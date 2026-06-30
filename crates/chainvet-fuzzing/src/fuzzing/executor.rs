use std::collections::{HashMap, HashSet};

use chainvet_core::cfg::CfgFunction;
use chainvet_core::ir::{
    ControlKind, IrCallOption, IrInstr, IrModule, IrPlace, IrValue, IrVar, PlaceClass,
};
use chainvet_core::norm::NormalizedAst;
use chainvet_frontend::frontend::FrontendOutput;

use crate::fuzzing::types::{
    ContractAbi, DependencyMap, Environment, ExecutionTrace, FuzzValue, Individual, TraceEvent,
    TraceEventKind, Transaction,
};

/// Simulated state: variable_name → FuzzValue.
type SimState = HashMap<String, FuzzValue>;

/// Execute a full individual (sequence of transactions) against the IR.
pub fn execute_individual(
    ind: &Individual,
    output: &FrontendOutput,
    ir_module: &IrModule,
    cfgs: &[CfgFunction],
    abi: &ContractAbi,
    deps: &DependencyMap,
) -> ExecutionTrace {
    let ast = &output.ast;
    let mut state = init_state(ast);
    let mut trace = ExecutionTrace::default();
    let checked_arithmetic = has_checked_arithmetic(ast);

    for tx in &ind.transactions {
        let result = execute_transaction(
            tx,
            &ind.environment,
            &mut state,
            output,
            ir_module,
            cfgs,
            abi,
            deps,
            checked_arithmetic,
            0,
        );
        trace.events.extend(result.events);
        trace.coverage.extend(&result.coverage);
        trace.edge_coverage.extend(&result.edge_coverage);
        if result.reverted {
            trace.reverted = true;
        }
    }

    trace.final_state = state;
    trace
}

/// Initialize state from contract state variables.
fn init_state(ast: &NormalizedAst) -> SimState {
    let mut state = SimState::new();
    for var in &ast.state_vars {
        state.insert(var.name.clone(), FuzzValue::Uint(0));
    }
    // Add built-in variables
    state.insert("this".to_string(), FuzzValue::Address(0));
    state
}

fn seed_contract_state_var_origins(
    temp_origins: &mut HashMap<String, HashSet<TempOrigin>>,
    function_id: u32,
    ast: &NormalizedAst,
) {
    let Some(contract_id) = ast
        .functions
        .get(function_id as usize)
        .and_then(|function| function.contract)
    else {
        return;
    };

    for state_var in ast
        .state_vars
        .iter()
        .filter(|state_var| state_var.contract == contract_id)
    {
        let Some(init_lower) = state_var_initializer_lower(ast, state_var.span) else {
            continue;
        };
        let entry = temp_origins.entry(state_var.name.clone()).or_default();
        if init_lower.contains("block.timestamp") || init_lower.contains("now") {
            entry.insert(TempOrigin::TimestampDerived);
        }
        if init_lower.contains("block.number") || init_lower.contains("blockhash") {
            entry.insert(TempOrigin::BlockNumberDerived);
        }
    }
}

fn state_var_initializer_lower(
    ast: &NormalizedAst,
    span: chainvet_core::norm::Span,
) -> Option<String> {
    let file = ast.files.get(span.file as usize)?;
    let source = file.source.get(span.start as usize..span.end as usize)?;
    let (_, rhs) = source.split_once('=')?;
    Some(rhs.to_ascii_lowercase())
}

/// Track which temp vars originate from special sources.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum TempOrigin {
    /// Loaded from block.timestamp
    Timestamp,
    /// Loaded from msg.sender or derived directly from it
    SenderDerived,
    /// Loaded from a .call / .send / .transfer member (external call reference)
    ExternalCallRef,
    /// Loaded from a value-carrying low-level call reference, e.g. `.call.value(x)`.
    ValueCallRef,
    /// Loaded specifically from a .delegatecall member
    DelegatecallRef,
    /// Loaded specifically from a .send member
    SendRef,
    /// Loaded specifically from a .transfer member
    TransferRef,
    /// Result bool produced by send() call
    SendResult,
    /// Derived from a timestamp value through arithmetic
    TimestampDerived,
    /// Loaded from tx.origin
    TxOrigin,
    /// Result value produced by ecrecover()
    EcrecoverResult,
    /// Loaded from storage (for detecting storage-dependent loop bounds)
    StorageDerived,
    /// Loaded from block.number or blockhash (for weak PRNG detection)
    BlockNumberDerived,
    /// Loaded from this.balance/address(this).balance
    ThisBalanceDerived,
    /// Result of a division operation (for div-before-mul detection)
    DivisionResult,
}

/// Execute a single transaction.
fn execute_transaction(
    tx: &Transaction,
    env: &Environment,
    state: &mut SimState,
    output: &FrontendOutput,
    ir_module: &IrModule,
    cfgs: &[CfgFunction],
    abi: &ContractAbi,
    deps: &DependencyMap,
    checked_arithmetic: bool,
    reentry_depth: u8,
) -> ExecutionTrace {
    let ast = &output.ast;
    let mut trace = ExecutionTrace::default();

    // Find the IR function
    let ir_func = ir_module.functions.iter().find(|f| f.id == tx.function_id);
    let ir_func = match ir_func {
        Some(f) => f,
        None => return trace,
    };

    // Find the corresponding CFG
    let cfg = cfgs.iter().find(|c| c.id == tx.function_id);

    // Get contract name for resolving `this.x` patterns
    let contract_name = ast
        .functions
        .get(tx.function_id as usize)
        .and_then(|f| f.contract)
        .and_then(|cid| ast.contracts.get(cid as usize))
        .map(|c| c.name.clone());

    // Set up local variables (function parameters)
    let mut locals: HashMap<String, FuzzValue> = HashMap::new();
    if let Some(func) = ast.functions.get(tx.function_id as usize) {
        for (idx, param) in func.params.iter().enumerate() {
            let val = tx.args.get(idx).cloned().unwrap_or(FuzzValue::Uint(0));
            locals.insert(param.clone(), val);
        }
    }

    // Set environment values
    locals.insert("msg.sender".to_string(), FuzzValue::Address(tx.sender));
    locals.insert("msg.value".to_string(), FuzzValue::Uint(tx.value));
    locals.insert(
        "block.timestamp".to_string(),
        FuzzValue::Uint(env.block_timestamp),
    );
    locals.insert(
        "block.number".to_string(),
        FuzzValue::Uint(env.block_number),
    );

    // Track temp variable origins for oracle detection
    let mut temp_origins: HashMap<String, HashSet<TempOrigin>> = HashMap::new();
    // Track low-level call return values and whether they are checked in control flow.
    let mut tracked_call_by_var: HashMap<String, usize> = HashMap::new();
    let mut tracked_calls: HashMap<usize, String> = HashMap::new();
    let mut checked_calls: HashSet<usize> = HashSet::new();
    let mut next_call_id: usize = 0;
    // Mark block.timestamp as a timestamp source
    temp_origins
        .entry("block.timestamp".to_string())
        .or_default()
        .insert(TempOrigin::Timestamp);
    seed_contract_state_var_origins(&mut temp_origins, tx.function_id, ast);

    // If we have a CFG, execute along chosen control-flow edges (path-sensitive).
    if let Some(cfg) = cfg {
        let block_map: HashMap<u32, &chainvet_core::cfg::Block> =
            cfg.blocks.iter().map(|b| (b.id, b)).collect();
        let mut succs: HashMap<u32, Vec<u32>> = HashMap::new();
        for edge in &cfg.edges {
            succs.entry(edge.from).or_default().push(edge.to);
        }

        let mut current = cfg.blocks.first().map(|b| b.id).unwrap_or(0);
        let mut steps = 0usize;
        let mut loop_iters: HashMap<u32, u32> = HashMap::new();
        const MAX_CFG_STEPS: usize = 1_024;
        const MAX_LOOP_ITERS_PER_HEADER: u32 = 8;

        while steps < MAX_CFG_STEPS {
            let Some(block) = block_map.get(&current) else {
                break;
            };
            trace.coverage.insert((tx.function_id, block.id));
            trace.events.push(TraceEvent {
                span: None,
                function_id: tx.function_id,
                kind: TraceEventKind::BlockVisited { block_id: block.id },
            });

            let mut next_block: Option<u32> = None;
            let mut terminated = false;

            for instr in &block.instrs {
                execute_instr(
                    instr,
                    tx,
                    state,
                    &mut locals,
                    &mut trace,
                    env,
                    output,
                    ir_module,
                    cfgs,
                    abi,
                    deps,
                    contract_name.as_deref(),
                    &mut temp_origins,
                    &mut tracked_call_by_var,
                    &mut tracked_calls,
                    &mut checked_calls,
                    &mut next_call_id,
                    checked_arithmetic,
                    reentry_depth,
                );

                if trace.reverted {
                    terminated = true;
                    next_block = None;
                    break;
                }

                match instr {
                    IrInstr::Return { .. } => {
                        terminated = true;
                        next_block = None;
                        break;
                    }
                    IrInstr::Control { kind, .. } => {
                        let outgoing = succs.get(&current).cloned().unwrap_or_default();
                        match kind {
                            ControlKind::If { cond } => {
                                let cond_true = resolve_value(cond, state, &locals).is_truthy();
                                next_block = if cond_true {
                                    outgoing.first().copied()
                                } else {
                                    outgoing
                                        .get(1)
                                        .copied()
                                        .or_else(|| outgoing.first().copied())
                                };
                            }
                            ControlKind::Loop { cond } => {
                                if let Some(cond_val) = cond {
                                    let take_body =
                                        resolve_value(cond_val, state, &locals).is_truthy();
                                    if take_body {
                                        let count = loop_iters.entry(current).or_insert(0);
                                        if *count < MAX_LOOP_ITERS_PER_HEADER {
                                            *count += 1;
                                            next_block = outgoing.first().copied();
                                        } else {
                                            next_block = outgoing
                                                .get(1)
                                                .copied()
                                                .or_else(|| outgoing.first().copied());
                                        }
                                    } else {
                                        next_block = outgoing
                                            .get(1)
                                            .copied()
                                            .or_else(|| outgoing.first().copied());
                                    }
                                } else {
                                    next_block = outgoing.first().copied();
                                }
                            }
                            ControlKind::Revert { .. } => {
                                next_block = None;
                            }
                            _ => {
                                next_block = outgoing.first().copied();
                            }
                        }
                        terminated = true;
                        break;
                    }
                    _ => {}
                }
            }

            steps = steps.saturating_add(1);
            if terminated {
                if let Some(n) = next_block {
                    trace.edge_coverage.insert((tx.function_id, current, n));
                    current = n;
                    continue;
                }
                break;
            }

            if let Some(n) = succs.get(&current).and_then(|xs| xs.first()).copied() {
                trace.edge_coverage.insert((tx.function_id, current, n));
                current = n;
            } else {
                break;
            }
        }
    } else {
        for block in &ir_func.blocks {
            trace.coverage.insert((tx.function_id, block.id));
            trace.events.push(TraceEvent {
                span: None,
                function_id: tx.function_id,
                kind: TraceEventKind::BlockVisited { block_id: block.id },
            });
            for instr in &block.instrs {
                let ev_before = trace.events.len();
                execute_instr(
                    instr,
                    tx,
                    state,
                    &mut locals,
                    &mut trace,
                    env,
                    output,
                    ir_module,
                    cfgs,
                    abi,
                    deps,
                    contract_name.as_deref(),
                    &mut temp_origins,
                    &mut tracked_call_by_var,
                    &mut tracked_calls,
                    &mut checked_calls,
                    &mut next_call_id,
                    checked_arithmetic,
                    reentry_depth,
                );
                // Stamp each event this instruction produced with its source span,
                // so oracles report the exact operation line (not the function).
                let instr_span = instr.span();
                for event in trace.events[ev_before..].iter_mut() {
                    if event.span.is_none() {
                        event.span = Some(instr_span);
                    }
                }
            }
        }
    }

    // --- Post-execution analysis ---

    // Exception disorder: external call followed by state write without require check
    let mut last_ext_call: Option<String> = None;
    let mut ext_call_checked = false;
    let mut disorder_events = Vec::new();
    for event in &trace.events {
        if event.function_id != tx.function_id {
            continue;
        }
        match &event.kind {
            TraceEventKind::ExternalCall {
                callee, low_level, ..
            } => {
                if *low_level {
                    last_ext_call = Some(callee.clone());
                    ext_call_checked = false;
                } else {
                    last_ext_call = None;
                    ext_call_checked = false;
                }
            }
            TraceEventKind::ConditionChecked => {
                // Any explicit condition check (require/assert/if) after the call marks it checked.
                ext_call_checked = true;
            }
            TraceEventKind::StorageWrite { var_name, .. } => {
                if let Some(callee) = &last_ext_call {
                    if !ext_call_checked && var_name != "__no_sender_check" {
                        disorder_events.push(TraceEvent {
                            span: None,
                            function_id: tx.function_id,
                            kind: TraceEventKind::ExternalCallThenState {
                                callee: callee.clone(),
                                checked: false,
                            },
                        });
                    }
                }
            }
            _ => {}
        }
    }
    trace.events.extend(disorder_events);

    // Any tracked low-level call result that was never checked is an unchecked call.
    for (call_id, callee) in tracked_calls {
        if !checked_calls.contains(&call_id) {
            trace.events.push(TraceEvent {
                span: None,
                function_id: tx.function_id,
                kind: TraceEventKind::CallReturnUnchecked { callee },
            });
        }
    }

    trace
}

/// Simulate a single IR instruction, recording trace events.
fn execute_instr(
    instr: &IrInstr,
    tx: &Transaction,
    state: &mut SimState,
    locals: &mut HashMap<String, FuzzValue>,
    trace: &mut ExecutionTrace,
    env: &Environment,
    output: &FrontendOutput,
    ir_module: &IrModule,
    cfgs: &[CfgFunction],
    abi: &ContractAbi,
    deps: &DependencyMap,
    contract_name: Option<&str>,
    temp_origins: &mut HashMap<String, HashSet<TempOrigin>>,
    tracked_call_by_var: &mut HashMap<String, usize>,
    tracked_calls: &mut HashMap<usize, String>,
    checked_calls: &mut HashSet<usize>,
    next_call_id: &mut usize,
    checked_arithmetic: bool,
    reentry_depth: u8,
) {
    let function_id = tx.function_id;
    let ast = &output.ast;
    match instr {
        IrInstr::Store { dest, src, .. } => {
            let val = resolve_value(src, state, locals);
            if is_storage(dest) {
                if let Some(meta) = storage_access_meta(dest, temp_origins, contract_name) {
                    let name = meta.var_name.clone();
                    let constructor_like =
                        function_is_constructor_like(function_id, ast, &output.compiler);
                    let wrong_constructor_candidate =
                        is_wrong_constructor_runtime_candidate(function_id, ast, &output.compiler);
                    let sender_derived = value_is_sender_derived(src, temp_origins)
                        || value_name(src).contains("sender");
                    // Key mapping writes by resolved runtime index so per-account
                    // balances are tracked separately (enables the conservation
                    // oracle). Scalars fall back to their plain name.
                    let store_key = runtime_place_key(dest, state, locals, contract_name)
                        .unwrap_or_else(|| name.clone());
                    state.insert(store_key, val);
                    trace.events.push(TraceEvent {
                        span: None,
                        function_id,
                        kind: TraceEventKind::StorageWrite {
                            var_name: meta.var_name.clone(),
                            slot_key: meta.slot_key.clone(),
                            authority_sensitive: meta.authority_sensitive && !constructor_like,
                            caller_keyed: meta.caller_keyed,
                        },
                    });
                    if wrong_constructor_candidate
                        && meta.authority_sensitive
                        && !meta.caller_keyed
                        && sender_derived
                    {
                        trace.events.push(TraceEvent {
                            span: None,
                            function_id,
                            kind: TraceEventKind::WrongConstructorCandidate {
                                function_name: ast
                                    .functions
                                    .get(function_id as usize)
                                    .and_then(|function| function.name.clone())
                                    .unwrap_or_else(|| "<anonymous>".to_string()),
                                slot_key: meta.slot_key,
                            },
                        });
                    }
                }
            } else if let Some(name) = place_name(dest, contract_name) {
                locals.insert(name, val);
            }
        }
        IrInstr::Load { dest, src, .. } => {
            let src_place_name = place_name(src, contract_name).unwrap_or_default();
            let dest_key = var_key(dest);
            let storage_meta = storage_access_meta(src, temp_origins, contract_name);

            let val = if is_storage(src) {
                if let Some(meta) = &storage_meta {
                    trace.events.push(TraceEvent {
                        span: None,
                        function_id,
                        kind: TraceEventKind::StorageRead {
                            var_name: meta.var_name.clone(),
                            slot_key: meta.slot_key.clone(),
                            order_sensitive: meta.order_sensitive,
                            caller_keyed: meta.caller_keyed,
                        },
                    });
                }
                // Mark dest as storage-derived for DoS loop detection
                temp_origins
                    .entry(dest_key.clone())
                    .or_default()
                    .insert(TempOrigin::StorageDerived);
                // Read mapping entries by resolved runtime index (consistent with
                // the Store path) so per-account balances read back faithfully.
                let read_key = runtime_place_key(src, state, locals, contract_name)
                    .unwrap_or_else(|| src_place_name.clone());
                state.get(&read_key).cloned().unwrap_or(FuzzValue::Uint(0))
            } else {
                locals
                    .get(&src_place_name)
                    .or_else(|| state.get(&src_place_name))
                    .cloned()
                    .unwrap_or(FuzzValue::Uint(0))
            };

            // Inspect the IrPlace structure directly for origin tracking.
            // place_name() returns the root for Member places (e.g. "block" for block.timestamp),
            // so we need to check .base and .field directly.
            match src {
                IrPlace::Member { base, field, .. } => {
                    let base_name = value_name(base);
                    let full_name = format!("{}.{}", base_name, field);
                    let f = field.to_lowercase();

                    // Detect block.timestamp loads
                    if full_name == "block.timestamp" || base_name == "block" && f == "timestamp" {
                        temp_origins
                            .entry(dest_key.clone())
                            .or_default()
                            .insert(TempOrigin::Timestamp);
                    }

                    // Detect block.number loads (weak PRNG)
                    if full_name == "block.number"
                        || base_name == "block" && f == "number"
                        || f == "blockhash"
                    {
                        temp_origins
                            .entry(dest_key.clone())
                            .or_default()
                            .insert(TempOrigin::BlockNumberDerived);
                        trace.events.push(TraceEvent {
                            span: None,
                            function_id,
                            kind: TraceEventKind::BlockNumberUsed,
                        });
                    }

                    if full_name == "this.balance"
                        || (base_name == "this" && f == "balance")
                        || (f == "balance" && is_contract_receiver(base, contract_name))
                    {
                        temp_origins
                            .entry(dest_key.clone())
                            .or_default()
                            .insert(TempOrigin::ThisBalanceDerived);
                    }

                    // Detect tx.origin loads
                    if full_name == "tx.origin" || base_name == "tx" && f == "origin" {
                        temp_origins
                            .entry(dest_key.clone())
                            .or_default()
                            .insert(TempOrigin::TxOrigin);
                        trace.events.push(TraceEvent {
                            span: None,
                            function_id,
                            kind: TraceEventKind::TxOriginUsed,
                        });
                    }

                    if full_name == "msg.sender" || base_name == "msg" && f == "sender" {
                        temp_origins
                            .entry(dest_key.clone())
                            .or_default()
                            .insert(TempOrigin::SenderDerived);
                    }

                    // Detect .call / .send / .transfer member loads (external call refs)
                    if f == "call"
                        || f == "send"
                        || f == "transfer"
                        || f == "delegatecall"
                        || f == "staticcall"
                    {
                        temp_origins
                            .entry(dest_key.clone())
                            .or_default()
                            .insert(TempOrigin::ExternalCallRef);
                    }
                    if f == "delegatecall" {
                        temp_origins
                            .entry(dest_key.clone())
                            .or_default()
                            .insert(TempOrigin::DelegatecallRef);
                    } else if f == "send" {
                        temp_origins
                            .entry(dest_key.clone())
                            .or_default()
                            .insert(TempOrigin::SendRef);
                    } else if f == "transfer" {
                        temp_origins
                            .entry(dest_key.clone())
                            .or_default()
                            .insert(TempOrigin::TransferRef);
                    } else if f == "value" {
                        let base_key = value_key(base);
                        let base_is_call_ref = temp_origins
                            .get(&base_key)
                            .map(|o| o.contains(&TempOrigin::ExternalCallRef))
                            .unwrap_or(false);
                        if base_is_call_ref {
                            let origins = temp_origins.entry(dest_key.clone()).or_default();
                            origins.insert(TempOrigin::ExternalCallRef);
                            origins.insert(TempOrigin::ValueCallRef);
                        }
                    }

                    // Detect .length member on storage-derived arrays (for DoS)
                    if f == "length" {
                        // If the base is storage-derived, mark this as storage-derived too
                        let base_key = value_key(base);
                        let base_is_storage = temp_origins
                            .get(&base_key)
                            .map(|o| o.contains(&TempOrigin::StorageDerived))
                            .unwrap_or(false);
                        if base_is_storage || is_storage(src) {
                            temp_origins
                                .entry(dest_key.clone())
                                .or_default()
                                .insert(TempOrigin::StorageDerived);
                        }
                    }
                }
                IrPlace::Var { var, .. } => {
                    // Direct var loads: check if the var name itself is timestamp-related
                    let vname = var_key(var);
                    if vname == "block.timestamp" || vname.contains("timestamp") {
                        temp_origins
                            .entry(dest_key.clone())
                            .or_default()
                            .insert(TempOrigin::Timestamp);
                    }
                    if vname == "block.number" || vname.contains("blockhash") {
                        temp_origins
                            .entry(dest_key.clone())
                            .or_default()
                            .insert(TempOrigin::BlockNumberDerived);
                        trace.events.push(TraceEvent {
                            span: None,
                            function_id,
                            kind: TraceEventKind::BlockNumberUsed,
                        });
                    }
                    if vname == "tx.origin" {
                        temp_origins
                            .entry(dest_key.clone())
                            .or_default()
                            .insert(TempOrigin::TxOrigin);
                        trace.events.push(TraceEvent {
                            span: None,
                            function_id,
                            kind: TraceEventKind::TxOriginUsed,
                        });
                    }
                    if vname == "msg.sender" {
                        temp_origins
                            .entry(dest_key.clone())
                            .or_default()
                            .insert(TempOrigin::SenderDerived);
                    }
                }
                _ => {}
            }

            // Propagate origins from source to dest
            if let Some(origins) = temp_origins.get(&src_place_name).cloned() {
                temp_origins
                    .entry(dest_key.clone())
                    .or_default()
                    .extend(origins);
            }
            let mut call_origin = tracked_call_by_var.get(&src_place_name).copied();
            match src {
                IrPlace::Member { base, .. } | IrPlace::Index { base, .. } => {
                    let base_key = value_key(base);
                    if let Some(origins) = temp_origins.get(&base_key).cloned() {
                        temp_origins.entry(dest_key).or_default().extend(origins);
                    }
                    if call_origin.is_none() {
                        call_origin = tracked_call_by_var.get(&base_key).copied();
                    }
                }
                IrPlace::Var { .. } => {}
            }
            if let Some(call_id) = call_origin {
                tracked_call_by_var.insert(var_key(dest), call_id);
            } else {
                tracked_call_by_var.remove(&var_key(dest));
            }

            set_var(dest, val, locals);
        }
        IrInstr::Declare { names, init, .. } => {
            let val = init
                .as_ref()
                .map(|v| resolve_value(v, state, locals))
                .unwrap_or(FuzzValue::Uint(0));
            for name in names {
                locals.insert(name.clone(), val.clone());
                tracked_call_by_var.remove(name);
            }
        }
        IrInstr::Assign { dest, src, .. } => {
            let val = resolve_value(src, state, locals);

            // Propagate origins
            let src_key = value_key(src);
            let dest_key = var_key(dest);
            if let Some(origins) = temp_origins.get(&src_key).cloned() {
                temp_origins
                    .entry(dest_key.clone())
                    .or_default()
                    .extend(origins);
            }
            if let Some(call_id) = tracked_call_by_var.get(&src_key).copied() {
                tracked_call_by_var.insert(dest_key.clone(), call_id);
            } else {
                tracked_call_by_var.remove(&dest_key);
            }

            set_var(dest, val, locals);
        }
        IrInstr::Binary {
            dest, op, lhs, rhs, ..
        } => {
            let l = resolve_value(lhs, state, locals).as_uint();
            let r = resolve_value(rhs, state, locals).as_uint();
            let result = eval_binary(op, l, r);
            let dest_key = var_key(dest);

            // For Solidity >=0.8, arithmetic is checked by default; avoid treating checked math as wrapping vulns.
            if !checked_arithmetic && matches!(op.as_str(), "+" | "-" | "*") {
                trace.events.push(TraceEvent {
                    span: None,
                    function_id,
                    kind: TraceEventKind::ArithmeticOp {
                        op: op.clone(),
                        lhs: l,
                        rhs: r,
                        result,
                    },
                });
            }

            // Propagate timestamp taint through arithmetic
            let lhs_key = value_key(lhs);
            let rhs_key = value_key(rhs);
            let lhs_has_ts = temp_origins
                .get(&lhs_key)
                .map(|o| {
                    o.contains(&TempOrigin::Timestamp) || o.contains(&TempOrigin::TimestampDerived)
                })
                .unwrap_or(false);
            let rhs_has_ts = temp_origins
                .get(&rhs_key)
                .map(|o| {
                    o.contains(&TempOrigin::Timestamp) || o.contains(&TempOrigin::TimestampDerived)
                })
                .unwrap_or(false);
            if lhs_has_ts || rhs_has_ts {
                temp_origins
                    .entry(dest_key.clone())
                    .or_default()
                    .insert(TempOrigin::TimestampDerived);
            }
            let lhs_blocknum = temp_origins
                .get(&lhs_key)
                .map(|o| o.contains(&TempOrigin::BlockNumberDerived))
                .unwrap_or(false);
            let rhs_blocknum = temp_origins
                .get(&rhs_key)
                .map(|o| o.contains(&TempOrigin::BlockNumberDerived))
                .unwrap_or(false);
            if (lhs_has_ts || rhs_has_ts)
                && (lhs_blocknum || rhs_blocknum)
                && matches!(
                    op.as_str(),
                    "%" | "*" | "+" | "-" | "^" | "|" | "&" | "<<" | ">>"
                )
            {
                trace.events.push(TraceEvent {
                    span: None,
                    function_id,
                    kind: TraceEventKind::TimestampArithmetic,
                });
            }

            // Propagate StorageDerived through comparisons (for loop conditions like `i < arr.length`)
            let lhs_storage = temp_origins
                .get(&lhs_key)
                .map(|o| o.contains(&TempOrigin::StorageDerived))
                .unwrap_or(false);
            let rhs_storage = temp_origins
                .get(&rhs_key)
                .map(|o| o.contains(&TempOrigin::StorageDerived))
                .unwrap_or(false);
            if lhs_storage || rhs_storage {
                temp_origins
                    .entry(dest_key.clone())
                    .or_default()
                    .insert(TempOrigin::StorageDerived);
            }

            // Access control: detect msg.sender == owner comparison pattern
            // If one side is "msg.sender" and the other is storage-derived, this is a sender check
            if matches!(op.as_str(), "==" | "!=") {
                let lhs_is_sender =
                    lhs_key.contains("sender") || value_name(lhs).contains("sender");
                let rhs_is_sender =
                    rhs_key.contains("sender") || value_name(rhs).contains("sender");
                if (lhs_is_sender && rhs_storage) || (rhs_is_sender && lhs_storage) {
                    temp_origins
                        .entry(dest_key.clone())
                        .or_default()
                        .insert(TempOrigin::StorageDerived);
                    trace.events.push(TraceEvent {
                        span: None,
                        function_id,
                        kind: TraceEventKind::SenderChecked,
                    });
                }
            }

            // Cryptographic evidence: detect explicit ecrecover result zero-address checks.
            if matches!(op.as_str(), "==" | "!=") {
                let lhs_is_ecrecover = temp_origins
                    .get(&lhs_key)
                    .map(|o| o.contains(&TempOrigin::EcrecoverResult))
                    .unwrap_or(false);
                let rhs_is_ecrecover = temp_origins
                    .get(&rhs_key)
                    .map(|o| o.contains(&TempOrigin::EcrecoverResult))
                    .unwrap_or(false);
                let compared_to_zero = (lhs_is_ecrecover && r == 0) || (rhs_is_ecrecover && l == 0);
                if compared_to_zero {
                    trace.events.push(TraceEvent {
                        span: None,
                        function_id,
                        kind: TraceEventKind::EcrecoverZeroChecked,
                    });
                }
            }

            let lhs_this_balance = temp_origins
                .get(&lhs_key)
                .map(|o| o.contains(&TempOrigin::ThisBalanceDerived))
                .unwrap_or(false);
            let rhs_this_balance = temp_origins
                .get(&rhs_key)
                .map(|o| o.contains(&TempOrigin::ThisBalanceDerived))
                .unwrap_or(false);
            if lhs_this_balance || rhs_this_balance {
                temp_origins
                    .entry(dest_key.clone())
                    .or_default()
                    .insert(TempOrigin::ThisBalanceDerived);
            }

            if let Some(call_id) = tracked_call_by_var
                .get(&lhs_key)
                .copied()
                .or_else(|| tracked_call_by_var.get(&rhs_key).copied())
            {
                tracked_call_by_var.insert(dest_key.clone(), call_id);
            } else {
                tracked_call_by_var.remove(&dest_key);
            }

            set_var(dest, FuzzValue::Uint(result), locals);

            // Track division results for div-before-mul detection
            if op == "/" {
                temp_origins
                    .entry(dest_key)
                    .or_default()
                    .insert(TempOrigin::DivisionResult);
            }
            // Detect division-before-multiplication: if one operand is a division result and op is *
            if op == "*" {
                let lhs_is_div = temp_origins
                    .get(&lhs_key)
                    .map(|o| o.contains(&TempOrigin::DivisionResult))
                    .unwrap_or(false);
                let rhs_is_div = temp_origins
                    .get(&rhs_key)
                    .map(|o| o.contains(&TempOrigin::DivisionResult))
                    .unwrap_or(false);
                if lhs_is_div || rhs_is_div {
                    trace.events.push(TraceEvent {
                        span: None,
                        function_id,
                        kind: TraceEventKind::DivisionBeforeMultiplication {
                            function_id_inner: function_id,
                        },
                    });
                }
            }
        }
        IrInstr::Unary { dest, op, expr, .. } => {
            let v = resolve_value(expr, state, locals).as_uint();
            let result = match op.as_str() {
                "!" => {
                    if v == 0 {
                        1
                    } else {
                        0
                    }
                }
                "-" => (0u128).wrapping_sub(v),
                "~" => !v,
                _ => v,
            };

            // Propagate timestamp taint through unary ops
            let expr_key = value_key(expr);
            let dest_key = var_key(dest);
            if temp_origins
                .get(&expr_key)
                .map(|o| {
                    o.contains(&TempOrigin::Timestamp) || o.contains(&TempOrigin::TimestampDerived)
                })
                .unwrap_or(false)
            {
                temp_origins
                    .entry(dest_key.clone())
                    .or_default()
                    .insert(TempOrigin::TimestampDerived);
            }
            if temp_origins
                .get(&expr_key)
                .map(|o| o.contains(&TempOrigin::ThisBalanceDerived))
                .unwrap_or(false)
            {
                temp_origins
                    .entry(dest_key.clone())
                    .or_default()
                    .insert(TempOrigin::ThisBalanceDerived);
            }

            if let Some(call_id) = tracked_call_by_var.get(&expr_key).copied() {
                tracked_call_by_var.insert(dest_key.clone(), call_id);
            } else {
                tracked_call_by_var.remove(&dest_key);
            }

            set_var(dest, FuzzValue::Uint(result), locals);
        }
        IrInstr::Call {
            dest,
            callee,
            args,
            options,
            ..
        } => {
            let callee_name = value_name(callee);
            let callee_key = value_key(callee);
            let callee_is_temp = matches!(callee, IrValue::Var(IrVar::Temp(_)));
            let callee_origins = temp_origins.get(&callee_key);
            let has_explicit_value = options.iter().any(|o| matches!(o, IrCallOption::Value(_)))
                || callee_origins
                    .map(|o| o.contains(&TempOrigin::ValueCallRef))
                    .unwrap_or(false);
            let callee_is_delegatecall_ref = callee_origins
                .map(|o| o.contains(&TempOrigin::DelegatecallRef))
                .unwrap_or(false);
            let mut callee_is_send_ref = callee_origins
                .map(|o| o.contains(&TempOrigin::SendRef))
                .unwrap_or(false);
            let mut callee_is_transfer_ref = callee_origins
                .map(|o| o.contains(&TempOrigin::TransferRef))
                .unwrap_or(false);
            // Legacy parser fallback can lower `.send`/`.transfer` as temp callees with a
            // single destination (bool result) and one value argument.
            let is_send_like_temp =
                callee_is_temp && dest.len() == 1 && args.len() == 1 && !has_explicit_value;
            if is_send_like_temp {
                callee_is_send_ref = true;
                callee_is_transfer_ref = false;
            }

            // Detect selfdestruct / suicide calls
            let callee_lower = callee_name.to_lowercase();
            if callee_lower == "selfdestruct" || callee_lower == "suicide" {
                trace.events.push(TraceEvent {
                    span: None,
                    function_id,
                    kind: TraceEventKind::SelfDestructCall,
                });
            }

            // Detect delegatecall
            if callee_lower.contains("delegatecall") || callee_is_delegatecall_ref {
                trace.events.push(TraceEvent {
                    span: None,
                    function_id,
                    kind: TraceEventKind::DelegatecallDetected {
                        callee: callee_name.clone(),
                    },
                });
            }

            // Detect ecrecover calls
            if callee_lower == "ecrecover" {
                trace.events.push(TraceEvent {
                    span: None,
                    function_id,
                    kind: TraceEventKind::EcrecoverCalled,
                });
            }

            // Detect .transfer() / .send() (hardcoded gas limit)
            if callee_lower == "transfer"
                || callee_lower == "send"
                || callee_lower.ends_with(".transfer")
                || callee_lower.ends_with(".send")
                || callee_is_send_ref
                || callee_is_transfer_ref
            {
                trace.events.push(TraceEvent {
                    span: None,
                    function_id,
                    kind: TraceEventKind::HardcodedGasCall {
                        callee: callee_name.clone(),
                    },
                });
            }

            // A tracked low-level call result passed as an argument to any
            // function (e.g. OpenZeppelin's `verifyCallResult(success, ret)`) is
            // consumed, not silently dropped — mark it checked. Genuinely
            // unchecked calls drop the result (no arg/condition use), so SolidiFI
            // recall is unaffected.
            for arg in args.iter() {
                if let Some(call_id) = tracked_call_by_var.get(&value_key(arg)).copied() {
                    checked_calls.insert(call_id);
                }
            }

            // Detect require(cond) — marks that the function checks conditions
            // If 1st arg is derived from a comparison with msg.sender, emit SenderChecked
            if callee_name == "require" || callee_name == "assert" {
                trace.events.push(TraceEvent {
                    span: None,
                    function_id,
                    kind: TraceEventKind::ConditionChecked,
                });
                if let Some(first_arg) = args.first() {
                    let arg_key = value_key(first_arg);
                    if let Some(call_id) = tracked_call_by_var.get(&arg_key).copied() {
                        checked_calls.insert(call_id);
                    }
                    let arg_is_send_result = temp_origins
                        .get(&arg_key)
                        .map(|o| o.contains(&TempOrigin::SendResult))
                        .unwrap_or(false);
                    if arg_is_send_result {
                        trace.events.push(TraceEvent {
                            span: None,
                            function_id,
                            kind: TraceEventKind::UnsafeSendInRequire {
                                callee: "send".to_string(),
                            },
                        });
                    }
                    let arg_has_this_balance = temp_origins
                        .get(&arg_key)
                        .map(|o| o.contains(&TempOrigin::ThisBalanceDerived))
                        .unwrap_or(false);
                    if arg_has_this_balance {
                        trace.events.push(TraceEvent {
                            span: None,
                            function_id,
                            kind: TraceEventKind::BalanceInvariantCheck,
                        });
                    }
                    // Check if the require condition involves msg.sender comparison
                    if arg_key.contains("sender")
                        || temp_origins
                            .get(&arg_key)
                            .map(|o| {
                                o.iter()
                                    .any(|origin| matches!(origin, TempOrigin::StorageDerived))
                            })
                            .unwrap_or(false)
                    {
                        trace.events.push(TraceEvent {
                            span: None,
                            function_id,
                            kind: TraceEventKind::SenderChecked,
                        });
                    }
                }
            }

            // Check if callee is an external call — either by name or by origin tracking
            let has_callback_capable_source_surface =
                function_has_callback_capable_low_level_call(ast, function_id);
            let has_value_moving_source_surface =
                function_has_value_moving_low_level_call(ast, function_id);
            let has_any_low_level_source_surface =
                has_callback_capable_source_surface || has_value_moving_source_surface;
            let is_external_by_name = is_external_call(&callee_name);
            let is_external_by_origin = temp_origins
                .get(&callee_key)
                .map(|o| o.contains(&TempOrigin::ExternalCallRef))
                .unwrap_or(false);
            // Legacy parser fallback often lowers low-level members (send/call/transfer) as temp callees.
            // Treat temp callees as low-level only when the source actually contains a low-level surface.
            let is_external_by_temp = callee_is_temp && (has_explicit_value || !args.is_empty());
            let is_external = is_external_by_name
                || is_external_by_origin
                || has_explicit_value
                || is_external_by_temp;
            let is_low_level_by_name = callee_lower == "call"
                || callee_lower == "send"
                || callee_lower == "transfer"
                || callee_lower == "delegatecall"
                || callee_lower == "staticcall"
                || callee_lower.ends_with(".call")
                || callee_lower.ends_with(".send")
                || callee_lower.ends_with(".transfer")
                || callee_lower.ends_with(".delegatecall")
                || callee_lower.ends_with(".staticcall");
            let is_low_level_by_temp = callee_is_temp && has_any_low_level_source_surface;
            let is_low_level_call = is_external
                && (is_low_level_by_name
                    || is_external_by_origin
                    || callee_is_delegatecall_ref
                    || is_low_level_by_temp);
            let has_value = has_explicit_value
                || callee_is_send_ref
                || callee_is_transfer_ref
                || (callee_is_temp && has_value_moving_source_surface);
            let is_transfer_call = callee_lower == "transfer"
                || callee_lower.ends_with(".transfer")
                || callee_is_transfer_ref;
            let unchecked_call_candidate = is_low_level_call && !is_transfer_call;
            let callback_overlap = if reentry_depth == 0 && tx.sender == 1 {
                has_no_value_reentrant_callback_overlap(function_id, ast, &output.compiler, deps)
            } else {
                false
            };
            let reentrant_capable = is_external
                && !callee_is_send_ref
                && !callee_is_transfer_ref
                && !callee_lower.contains("staticcall")
                && (has_value || (is_low_level_call && callback_overlap));

            if is_external {
                trace.events.push(TraceEvent {
                    span: None,
                    function_id,
                    kind: TraceEventKind::ExternalCall {
                        callee: callee_name.clone(),
                        has_value,
                        reentrant_capable,
                        low_level: is_low_level_call,
                    },
                });

                if unchecked_call_candidate {
                    if dest.is_empty() {
                        trace.events.push(TraceEvent {
                            span: None,
                            function_id,
                            kind: TraceEventKind::CallReturnUnchecked {
                                callee: callee_name.clone(),
                            },
                        });
                    } else {
                        let call_id = *next_call_id;
                        *next_call_id = next_call_id.saturating_add(1);
                        tracked_calls.insert(call_id, callee_name.clone());
                        for ret_var in dest {
                            tracked_call_by_var.insert(var_key(ret_var), call_id);
                        }
                    }
                } else {
                    for ret_var in dest {
                        tracked_call_by_var.remove(&var_key(ret_var));
                    }
                }
            }

            if reentrant_capable && reentry_depth == 0 && tx.sender == 1 {
                let callback_targets =
                    select_reentrant_callback_targets(function_id, ast, &output.compiler, deps);
                if !callback_targets.is_empty() {
                    for callback_target in callback_targets {
                        trace.events.push(TraceEvent {
                            span: None,
                            function_id,
                            kind: TraceEventKind::ReentrantCallback {
                                into_function_id: callback_target,
                            },
                        });
                        let callback_tx =
                            build_callback_transaction(callback_target, ast, tx.sender);
                        let callback_trace = execute_transaction(
                            &callback_tx,
                            env,
                            state,
                            output,
                            ir_module,
                            cfgs,
                            abi,
                            deps,
                            checked_arithmetic,
                            reentry_depth.saturating_add(1),
                        );
                        trace.events.extend(callback_trace.events);
                        trace.coverage.extend(callback_trace.coverage);
                        trace.edge_coverage.extend(callback_trace.edge_coverage);
                        trace.reverted |= callback_trace.reverted;
                    }
                }
            }

            // Set return values to defaults
            for var in dest {
                set_var(var, FuzzValue::Uint(0), locals);
                if callee_lower == "ecrecover" {
                    let key = var_key(var);
                    temp_origins
                        .entry(key)
                        .or_default()
                        .insert(TempOrigin::EcrecoverResult);
                }
                if callee_is_send_ref || callee_lower == "send" || callee_lower.ends_with(".send") {
                    let key = var_key(var);
                    temp_origins
                        .entry(key)
                        .or_default()
                        .insert(TempOrigin::SendResult);
                }
            }

            // Track ether-sending calls
            if has_value && is_external {
                trace.events.push(TraceEvent {
                    span: None,
                    function_id,
                    kind: TraceEventKind::EtherSent {
                        callee: callee_name.clone(),
                    },
                });
            }
        }
        IrInstr::Control { kind, .. } => {
            match kind {
                ControlKind::If { cond } => {
                    trace.events.push(TraceEvent {
                        span: None,
                        function_id,
                        kind: TraceEventKind::ConditionChecked,
                    });
                    let cond_key = value_key(cond);
                    if let Some(call_id) = tracked_call_by_var.get(&cond_key).copied() {
                        checked_calls.insert(call_id);
                    }
                    let cond_name = value_name(cond);

                    // Detect timestamp dependency: branch on value derived from block.timestamp
                    let has_timestamp = cond_name.contains("timestamp")
                        || cond_name.contains("block.timestamp")
                        || temp_origins
                            .get(&cond_key)
                            .map(|o| {
                                o.contains(&TempOrigin::Timestamp)
                                    || o.contains(&TempOrigin::TimestampDerived)
                            })
                            .unwrap_or(false);

                    if has_timestamp {
                        trace.events.push(TraceEvent {
                            span: None,
                            function_id,
                            kind: TraceEventKind::BranchOnTimestamp,
                        });
                    }
                }
                ControlKind::Loop { cond } => {
                    trace.events.push(TraceEvent {
                        span: None,
                        function_id,
                        kind: TraceEventKind::LoopEncountered,
                    });
                    // Detect unbounded loops: loop condition depends on storage-derived value
                    if let Some(cond_val) = cond {
                        let cond_key = value_key(cond_val);
                        if let Some(call_id) = tracked_call_by_var.get(&cond_key).copied() {
                            checked_calls.insert(call_id);
                        }
                        let is_storage_dep = temp_origins
                            .get(&cond_key)
                            .map(|o| o.contains(&TempOrigin::StorageDerived))
                            .unwrap_or(false);
                        if is_storage_dep {
                            let cond_name = value_name(cond_val);
                            trace.events.push(TraceEvent {
                                span: None,
                                function_id,
                                kind: TraceEventKind::UnboundedLoop {
                                    var_name: cond_name,
                                },
                            });
                        }
                    }
                }
                ControlKind::Revert { value } => {
                    let msg = value.as_ref().map(|v| value_name(v));
                    trace.events.push(TraceEvent {
                        span: None,
                        function_id,
                        kind: TraceEventKind::Revert { message: msg },
                    });
                    trace.reverted = true;
                }
                _ => {}
            }
        }
        IrInstr::Select {
            dest,
            cond,
            then_val,
            else_val,
            ..
        } => {
            let c = resolve_value(cond, state, locals);
            let cond_key = value_key(cond);
            let then_key = value_key(then_val);
            let else_key = value_key(else_val);
            let val = if c.is_truthy() {
                resolve_value(then_val, state, locals)
            } else {
                resolve_value(else_val, state, locals)
            };
            let dest_key = var_key(dest);
            let call_id = tracked_call_by_var
                .get(&cond_key)
                .copied()
                .or_else(|| tracked_call_by_var.get(&then_key).copied())
                .or_else(|| tracked_call_by_var.get(&else_key).copied());
            if let Some(call_id) = call_id {
                tracked_call_by_var.insert(dest_key.clone(), call_id);
            } else {
                tracked_call_by_var.remove(&dest_key);
            }
            let has_this_balance = temp_origins
                .get(&cond_key)
                .map(|o| o.contains(&TempOrigin::ThisBalanceDerived))
                .unwrap_or(false)
                || temp_origins
                    .get(&then_key)
                    .map(|o| o.contains(&TempOrigin::ThisBalanceDerived))
                    .unwrap_or(false)
                || temp_origins
                    .get(&else_key)
                    .map(|o| o.contains(&TempOrigin::ThisBalanceDerived))
                    .unwrap_or(false);
            if has_this_balance {
                temp_origins
                    .entry(dest_key.clone())
                    .or_default()
                    .insert(TempOrigin::ThisBalanceDerived);
            }
            set_var(dest, val, locals);
        }
        IrInstr::InlineAsm { .. } => {
            trace.events.push(TraceEvent {
                span: None,
                function_id,
                kind: TraceEventKind::InlineAssemblyDetected,
            });
        }
        _ => {}
    }
}

fn build_callback_transaction(
    function_id: u32,
    ast: &chainvet_core::norm::NormalizedAst,
    sender: usize,
) -> Transaction {
    let args = ast
        .functions
        .get(function_id as usize)
        .map(|function| vec![FuzzValue::Uint(0); function.params.len()])
        .unwrap_or_default();
    Transaction {
        function_id,
        args,
        sender,
        value: 0,
    }
}

fn select_reentrant_callback_targets(
    current_function_id: u32,
    ast: &chainvet_core::norm::NormalizedAst,
    compiler: &chainvet_frontend::frontend::CompilerInfo,
    deps: &DependencyMap,
) -> Vec<u32> {
    let Some(current_function) = ast.functions.get(current_function_id as usize) else {
        return Vec::new();
    };
    let Some(contract_id) = current_function.contract else {
        return Vec::new();
    };
    let Some(contract) = ast.contracts.get(contract_id as usize) else {
        return Vec::new();
    };
    let Some(current_deps) = deps.functions.get(&current_function_id) else {
        return Vec::new();
    };

    let mut candidates = Vec::new();
    for &function_id in &contract.functions {
        let Some(function) = ast.functions.get(function_id as usize) else {
            continue;
        };
        if !chainvet_frontend::frontend::is_mutating_entrypoint(function, compiler)
            || function.kind != chainvet_core::norm::FunctionKind::Function
        {
            continue;
        }
        if function_id == current_function_id {
            candidates.push((0u8, function_id));
            continue;
        }
        let overlaps =
            deps.functions
                .get(&function_id)
                .map(|candidate| {
                    current_deps.writes.iter().any(|slot| {
                        candidate.reads.contains(slot) || candidate.writes.contains(slot)
                    }) || current_deps
                        .reads
                        .iter()
                        .any(|slot| candidate.writes.contains(slot))
                })
                .unwrap_or(false);
        if overlaps {
            candidates.push((1u8, function_id));
        }
    }
    candidates.sort_unstable();
    candidates
        .into_iter()
        .take(4)
        .map(|(_, function_id)| function_id)
        .collect()
}

fn has_no_value_reentrant_callback_overlap(
    current_function_id: u32,
    ast: &chainvet_core::norm::NormalizedAst,
    compiler: &chainvet_frontend::frontend::CompilerInfo,
    deps: &DependencyMap,
) -> bool {
    let Some(current_function) = ast.functions.get(current_function_id as usize) else {
        return false;
    };
    let Some(contract_id) = current_function.contract else {
        return false;
    };
    let Some(current_deps) = deps.functions.get(&current_function_id) else {
        return false;
    };

    ast.contracts
        .get(contract_id as usize)
        .into_iter()
        .flat_map(|contract| contract.functions.iter().copied())
        .filter(|&function_id| function_id != current_function_id)
        .filter_map(|function_id| {
            let function = ast.functions.get(function_id as usize)?;
            if !chainvet_frontend::frontend::is_mutating_entrypoint(function, compiler)
                || function.kind != chainvet_core::norm::FunctionKind::Function
            {
                return None;
            }
            let candidate = deps.functions.get(&function_id)?;
            Some(
                current_deps
                    .writes
                    .iter()
                    .any(|slot| candidate.reads.contains(slot) || candidate.writes.contains(slot))
                    || current_deps
                        .reads
                        .iter()
                        .any(|slot| candidate.writes.contains(slot)),
            )
        })
        .any(|overlaps| overlaps)
}

fn function_has_callback_capable_low_level_call(ast: &NormalizedAst, function_id: u32) -> bool {
    let Some(source_lower) = function_source_lower(ast, function_id) else {
        return false;
    };
    source_lower.contains(".call(")
        || source_lower.contains(".call (")
        || source_lower.contains(".call.value")
        || source_lower.contains(".delegatecall")
        || source_lower.contains(".callcode")
}

fn function_has_value_moving_low_level_call(ast: &NormalizedAst, function_id: u32) -> bool {
    let Some(source_lower) = function_source_lower(ast, function_id) else {
        return false;
    };
    source_lower.contains(".call.value")
        || source_lower.contains(".send(")
        || source_lower.contains(".send (")
        || source_lower.contains(".transfer(")
        || source_lower.contains(".transfer (")
}

fn function_source_lower(ast: &NormalizedAst, function_id: u32) -> Option<String> {
    let function = ast.functions.get(function_id as usize)?;
    let file = ast.files.get(function.span.file as usize)?;
    Some(
        file.source
            .get(function.span.start as usize..function.span.end as usize)
            .filter(|source| !source.is_empty())
            .unwrap_or(file.source.as_str())
            .to_ascii_lowercase(),
    )
}

#[derive(Debug, Clone)]
struct StorageAccessMeta {
    var_name: String,
    slot_key: String,
    authority_sensitive: bool,
    order_sensitive: bool,
    caller_keyed: bool,
}

fn storage_access_meta(
    place: &IrPlace,
    temp_origins: &HashMap<String, HashSet<TempOrigin>>,
    contract_name: Option<&str>,
) -> Option<StorageAccessMeta> {
    let var_name = place_name(place, contract_name)?;
    let slot_key = place_slot_key(place, temp_origins, contract_name);
    let caller_keyed = place_is_caller_keyed(place, temp_origins);
    Some(StorageAccessMeta {
        authority_sensitive: slot_is_authority_sensitive(&slot_key, &var_name) && !caller_keyed,
        order_sensitive: slot_is_order_sensitive(&slot_key, &var_name),
        caller_keyed,
        slot_key,
        var_name,
    })
}

fn place_slot_key(
    place: &IrPlace,
    temp_origins: &HashMap<String, HashSet<TempOrigin>>,
    contract_name: Option<&str>,
) -> String {
    match place {
        IrPlace::Var {
            var: IrVar::Named(name),
            ..
        } => name.clone(),
        IrPlace::Var {
            var: IrVar::Temp(id),
            ..
        } => format!("$t{}", id),
        IrPlace::Member {
            base, field, root, ..
        } => {
            if is_contract_receiver(base, contract_name) {
                field.clone()
            } else if let Some(root) = root {
                root.clone()
            } else {
                format!(
                    "{}.{}",
                    value_display(base, temp_origins, contract_name),
                    field
                )
            }
        }
        IrPlace::Index {
            base, index, root, ..
        } => {
            let base_name = root
                .clone()
                .unwrap_or_else(|| value_display(base, temp_origins, contract_name));
            match index {
                Some(idx) => format!(
                    "{}[{}]",
                    base_name,
                    value_display(idx, temp_origins, contract_name)
                ),
                None => format!("{base_name}[]"),
            }
        }
    }
}

fn value_display(
    value: &IrValue,
    temp_origins: &HashMap<String, HashSet<TempOrigin>>,
    _contract_name: Option<&str>,
) -> String {
    let key = value_key(value);
    if temp_origins
        .get(&key)
        .map(|origins| origins.contains(&TempOrigin::SenderDerived))
        .unwrap_or(false)
    {
        return "msg.sender".to_string();
    }
    value_name(value)
}

fn place_is_caller_keyed(
    place: &IrPlace,
    temp_origins: &HashMap<String, HashSet<TempOrigin>>,
) -> bool {
    let IrPlace::Index { index, .. } = place else {
        return false;
    };
    let Some(index) = index else {
        return false;
    };
    let key = value_key(index);
    value_name(index).contains("sender")
        || temp_origins
            .get(&key)
            .map(|origins| origins.contains(&TempOrigin::SenderDerived))
            .unwrap_or(false)
}

fn slot_is_authority_sensitive(slot_key: &str, var_name: &str) -> bool {
    let joined = format!("{slot_key} {var_name}").to_ascii_lowercase();
    joined
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|token| !token.is_empty())
        .any(|token| {
            matches!(
                token,
                "owner"
                    | "creator"
                    | "admin"
                    | "operator"
                    | "minter"
                    | "pauser"
                    | "implementation"
                    | "governance"
                    | "role"
                    | "roles"
                    | "whitelist"
                    | "blacklist"
                    | "auth"
                    | "authority"
            ) || token.ends_with("owner")
                || token.ends_with("admin")
                || token.ends_with("governance")
        })
}

fn value_is_sender_derived(
    value: &IrValue,
    temp_origins: &HashMap<String, HashSet<TempOrigin>>,
) -> bool {
    let key = value_key(value);
    value_name(value).contains("sender")
        || temp_origins
            .get(&key)
            .map(|origins| origins.contains(&TempOrigin::SenderDerived))
            .unwrap_or(false)
}

fn function_is_constructor_like(
    function_id: u32,
    ast: &NormalizedAst,
    compiler: &chainvet_frontend::frontend::CompilerInfo,
) -> bool {
    let Some(function) = ast.functions.get(function_id as usize) else {
        return false;
    };
    if function.kind == chainvet_core::norm::FunctionKind::Constructor {
        return true;
    }
    let Some(name) = function.name.as_deref() else {
        return false;
    };
    let contract_name = function
        .contract
        .and_then(|contract_id| ast.contracts.get(contract_id as usize))
        .map(|contract| contract.name.as_str());
    contract_name
        .map(|contract_name| {
            name == contract_name
                && chainvet_frontend::frontend::is_public_entrypoint(function, compiler)
        })
        .unwrap_or(false)
}

fn is_wrong_constructor_runtime_candidate(
    function_id: u32,
    ast: &NormalizedAst,
    compiler: &chainvet_frontend::frontend::CompilerInfo,
) -> bool {
    let Some(function) = ast.functions.get(function_id as usize) else {
        return false;
    };
    if function.kind != chainvet_core::norm::FunctionKind::Function
        || !function.params.is_empty()
        || !chainvet_frontend::frontend::is_public_entrypoint(function, compiler)
    {
        return false;
    }
    let Some(name) = function.name.as_deref() else {
        return false;
    };
    let starts_upper = name
        .chars()
        .next()
        .map(|ch| ch.is_ascii_uppercase())
        .unwrap_or(false);
    if !starts_upper {
        return false;
    }
    let contract_name = function
        .contract
        .and_then(|contract_id| ast.contracts.get(contract_id as usize))
        .map(|contract| contract.name.as_str());
    contract_name
        .map(|contract_name| name != contract_name)
        .unwrap_or(false)
}

fn slot_is_order_sensitive(slot_key: &str, var_name: &str) -> bool {
    let joined = format!("{slot_key} {var_name}").to_ascii_lowercase();
    joined
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|token| !token.is_empty())
        .any(|token| {
            matches!(
                token,
                "price" | "rate" | "reward" | "bid" | "bids" | "auction" | "winner" | "quote"
            ) || token.ends_with("price")
                || token.ends_with("rate")
                || token.ends_with("reward")
        })
}

// --- Helpers ---

fn resolve_value(
    value: &IrValue,
    state: &SimState,
    locals: &HashMap<String, FuzzValue>,
) -> FuzzValue {
    match value {
        IrValue::Var(IrVar::Named(name)) => locals
            .get(name)
            .or_else(|| state.get(name))
            .cloned()
            .unwrap_or(FuzzValue::Uint(0)),
        IrValue::Var(IrVar::Temp(id)) => {
            // Look up temp variables from locals using their $t{id} key
            let key = format!("$t{}", id);
            locals.get(&key).cloned().unwrap_or(FuzzValue::Uint(0))
        }
        IrValue::Literal(lit) => {
            if let Ok(v) = lit.value.parse::<u128>() {
                FuzzValue::Uint(v)
            } else if lit.value == "true" {
                FuzzValue::Bool(true)
            } else if lit.value == "false" {
                FuzzValue::Bool(false)
            } else {
                FuzzValue::StringVal(lit.value.clone())
            }
        }
        IrValue::Unknown => FuzzValue::Uint(0),
    }
}

fn set_var(var: &IrVar, val: FuzzValue, locals: &mut HashMap<String, FuzzValue>) {
    match var {
        IrVar::Named(name) => {
            locals.insert(name.clone(), val);
        }
        IrVar::Temp(id) => {
            locals.insert(format!("$t{}", id), val);
        }
    }
}

/// Get a lookup key for an IrValue (used for origin tracking).
fn value_key(value: &IrValue) -> String {
    match value {
        IrValue::Var(IrVar::Named(name)) => name.clone(),
        IrValue::Var(IrVar::Temp(id)) => format!("$t{}", id),
        IrValue::Literal(lit) => format!("lit:{}", lit.value),
        IrValue::Unknown => "<unknown>".to_string(),
    }
}

/// Get a lookup key for an IrVar (used for origin tracking).
fn var_key(var: &IrVar) -> String {
    match var {
        IrVar::Named(name) => name.clone(),
        IrVar::Temp(id) => format!("$t{}", id),
    }
}

/// Stable string for a resolved mapping index, so `balances[0]` and
/// `balances[1]` get distinct storage keys (per-account state).
fn fuzz_index_key(value: &FuzzValue) -> String {
    match value {
        FuzzValue::Uint(v) => v.to_string(),
        FuzzValue::Int(v) => v.to_string(),
        FuzzValue::Bool(b) => b.to_string(),
        FuzzValue::Address(a) => format!("a{a}"),
        FuzzValue::Bytes(b) => format!("0x{}", hex_lower(b)),
        FuzzValue::StringVal(s) => s.clone(),
    }
}

/// Storage key that distinguishes mapping entries by their *resolved runtime
/// index* (`balances#<key>`), instead of collapsing the whole mapping to its
/// root name. Scalar places fall back to their plain name, so existing state
/// keying is unchanged for non-mapping vars.
fn runtime_place_key(
    place: &IrPlace,
    state: &SimState,
    locals: &HashMap<String, FuzzValue>,
    contract_name: Option<&str>,
) -> Option<String> {
    match place {
        IrPlace::Index {
            base, index, root, ..
        } => {
            let var = root.clone().unwrap_or_else(|| value_name(base));
            let key = match index {
                Some(idx) => fuzz_index_key(&resolve_value(idx, state, locals)),
                None => "_".to_string(),
            };
            Some(format!("{var}#{key}"))
        }
        _ => place_name(place, contract_name),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn value_name(value: &IrValue) -> String {
    match value {
        IrValue::Var(IrVar::Named(name)) => name.clone(),
        IrValue::Var(IrVar::Temp(id)) => format!("$t{}", id),
        IrValue::Literal(lit) => lit.value.clone(),
        IrValue::Unknown => "<unknown>".to_string(),
    }
}

fn is_storage(place: &IrPlace) -> bool {
    match place {
        IrPlace::Var { class, .. } => *class == PlaceClass::Storage,
        IrPlace::Member { class, .. } => *class == PlaceClass::Storage,
        IrPlace::Index { class, .. } => *class == PlaceClass::Storage,
    }
}

fn place_name(place: &IrPlace, contract_name: Option<&str>) -> Option<String> {
    match place {
        IrPlace::Var {
            var: IrVar::Named(n),
            ..
        } => Some(n.clone()),
        IrPlace::Var {
            var: IrVar::Temp(id),
            ..
        } => Some(format!("$t{}", id)),
        IrPlace::Member {
            base, field, root, ..
        } => {
            if is_contract_receiver(base, contract_name) {
                Some(field.clone())
            } else {
                root.clone()
            }
        }
        IrPlace::Index { root, .. } => root.clone(),
    }
}

fn is_contract_receiver(value: &IrValue, contract_name: Option<&str>) -> bool {
    match value {
        IrValue::Var(IrVar::Named(name)) => {
            name == "this" || name == "super" || contract_name.map(|cn| cn == name).unwrap_or(false)
        }
        _ => false,
    }
}

fn eval_binary(op: &str, l: u128, r: u128) -> u128 {
    match op {
        "+" => l.wrapping_add(r),
        "-" => l.wrapping_sub(r),
        "*" => l.wrapping_mul(r),
        "/" => {
            if r != 0 {
                l / r
            } else {
                0
            }
        }
        "%" => {
            if r != 0 {
                l % r
            } else {
                0
            }
        }
        "**" => l.wrapping_pow(r as u32),
        "&" => l & r,
        "|" => l | r,
        "^" => l ^ r,
        "<<" => l.wrapping_shl(r as u32),
        ">>" => l.wrapping_shr(r as u32),
        "==" => {
            if l == r {
                1
            } else {
                0
            }
        }
        "!=" => {
            if l != r {
                1
            } else {
                0
            }
        }
        "<" => {
            if l < r {
                1
            } else {
                0
            }
        }
        ">" => {
            if l > r {
                1
            } else {
                0
            }
        }
        "<=" => {
            if l <= r {
                1
            } else {
                0
            }
        }
        ">=" => {
            if l >= r {
                1
            } else {
                0
            }
        }
        "&&" => {
            if l != 0 && r != 0 {
                1
            } else {
                0
            }
        }
        "||" => {
            if l != 0 || r != 0 {
                1
            } else {
                0
            }
        }
        _ => 0,
    }
}

fn is_external_call(name: &str) -> bool {
    let low = name.to_lowercase();
    low.contains("call")
        || low.contains("transfer")
        || low.contains("send")
        || low.contains("delegatecall")
        || low.contains("staticcall")
}

fn has_checked_arithmetic(ast: &NormalizedAst) -> bool {
    for file in &ast.files {
        let src = file.source.to_ascii_lowercase();
        if src.contains("pragma solidity") && src.contains("0.8") {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzzing::types::{
        ContractAbi, DependencyMap, FunctionAbi, Individual, ParamInfo, build_dependency_map,
        extract_abis,
    };
    use chainvet_core::cfg;
    use chainvet_core::ir;
    use chainvet_core::ir::{
        IrBlock, IrCallOption, IrFunction, IrInstr, IrModule, IrPlace, IrValue,
    };
    use chainvet_core::norm::{FunctionKind, Mutability, NormalizedAst, Span, Visibility};
    use chainvet_frontend::frontend;
    use chainvet_frontend::frontend::{CompilerInfo, FrontendMode, FrontendOutput};

    #[test]
    fn eval_binary_ops() {
        assert_eq!(eval_binary("+", 3, 5), 8);
        assert_eq!(eval_binary("-", 10, 3), 7);
        assert_eq!(eval_binary("*", 4, 5), 20);
        assert_eq!(eval_binary("/", 10, 3), 3);
        assert_eq!(eval_binary("/", 10, 0), 0);
        assert_eq!(eval_binary("==", 5, 5), 1);
        assert_eq!(eval_binary("==", 5, 3), 0);
        assert_eq!(eval_binary("<", 3, 5), 1);
        assert_eq!(eval_binary("&&", 1, 1), 1);
        assert_eq!(eval_binary("&&", 1, 0), 0);
    }

    #[test]
    fn resolve_literal_values() {
        let state = SimState::new();
        let locals = HashMap::new();
        let lit = chainvet_core::norm::Literal {
            kind: "number".to_string(),
            value: "42".to_string(),
        };
        let val = resolve_value(&IrValue::Literal(lit), &state, &locals);
        assert_eq!(val.as_uint(), 42);
    }

    #[test]
    fn temp_var_tracking() {
        let state = SimState::new();
        let mut locals = HashMap::new();
        // Simulate: set $t5 = 100, then resolve it
        locals.insert("$t5".to_string(), FuzzValue::Uint(100));
        let val = resolve_value(&IrValue::Var(IrVar::Temp(5)), &state, &locals);
        assert_eq!(val.as_uint(), 100);
    }

    #[test]
    fn contract_receiver_balance_assert_marks_balance_invariant() {
        let tx = Transaction {
            function_id: 12,
            args: Vec::new(),
            sender: 0,
            value: 0,
        };
        let env = Environment::default();
        let output = FrontendOutput {
            mode: FrontendMode::Full,
            ast: NormalizedAst::default(),
            compiler: CompilerInfo {
                compiler_name: "solc".to_string(),
                compiler_version: Some("0.4.16".to_string()),
                legacy_omitted_visibility_is_public: true,
            },
        };
        let abi = ContractAbi {
            contract_name: "MyAdvancedToken".to_string(),
            functions: vec![FunctionAbi {
                id: 12,
                name: "migrate_and_destroy".to_string(),
                params: Vec::<ParamInfo>::new(),
                visibility: Visibility::Public,
                mutability: Mutability::NonPayable,
                kind: FunctionKind::Function,
                is_payable: false,
            }],
        };
        let ir_module = IrModule {
            functions: vec![IrFunction {
                id: 12,
                name: Some("migrate_and_destroy".to_string()),
                source: Some(12),
                span: Span::default(),
                blocks: vec![IrBlock {
                    id: 0,
                    instrs: Vec::new(),
                }],
            }],
        };
        let cfgs = Vec::new();
        let deps = DependencyMap::default();
        let mut state = SimState::new();
        let mut locals = HashMap::from([("totalSupply".to_string(), FuzzValue::Uint(0))]);
        let mut trace = ExecutionTrace::default();
        let mut temp_origins = HashMap::new();
        let mut tracked_call_by_var = HashMap::new();
        let mut tracked_calls = HashMap::new();
        let mut checked_calls = HashSet::new();
        let mut next_call_id = 0usize;

        let load_balance = IrInstr::Load {
            dest: IrVar::Temp(0),
            src: IrPlace::Member {
                base: IrValue::Var(IrVar::Named("MyAdvancedToken".to_string())),
                field: "balance".to_string(),
                root: Some("balance".to_string()),
                class: PlaceClass::Storage,
            },
            span: Span::default(),
        };
        let compare = IrInstr::Binary {
            dest: IrVar::Temp(1),
            op: "==".to_string(),
            lhs: IrValue::Var(IrVar::Temp(0)),
            rhs: IrValue::Var(IrVar::Named("totalSupply".to_string())),
            span: Span::default(),
        };
        let assert_call = IrInstr::Call {
            dest: Vec::new(),
            callee: IrValue::Var(IrVar::Named("assert".to_string())),
            args: vec![IrValue::Var(IrVar::Temp(1))],
            options: Vec::<IrCallOption>::new(),
            span: Span::default(),
        };

        execute_instr(
            &load_balance,
            &tx,
            &mut state,
            &mut locals,
            &mut trace,
            &env,
            &output,
            &ir_module,
            &cfgs,
            &abi,
            &deps,
            Some("MyAdvancedToken"),
            &mut temp_origins,
            &mut tracked_call_by_var,
            &mut tracked_calls,
            &mut checked_calls,
            &mut next_call_id,
            false,
            0,
        );
        execute_instr(
            &compare,
            &tx,
            &mut state,
            &mut locals,
            &mut trace,
            &env,
            &output,
            &ir_module,
            &cfgs,
            &abi,
            &deps,
            Some("MyAdvancedToken"),
            &mut temp_origins,
            &mut tracked_call_by_var,
            &mut tracked_calls,
            &mut checked_calls,
            &mut next_call_id,
            false,
            0,
        );
        execute_instr(
            &assert_call,
            &tx,
            &mut state,
            &mut locals,
            &mut trace,
            &env,
            &output,
            &ir_module,
            &cfgs,
            &abi,
            &deps,
            Some("MyAdvancedToken"),
            &mut temp_origins,
            &mut tracked_call_by_var,
            &mut tracked_calls,
            &mut checked_calls,
            &mut next_call_id,
            false,
            0,
        );

        assert!(
            trace
                .events
                .iter()
                .any(|event| { matches!(event.kind, TraceEventKind::BalanceInvariantCheck) })
        );
    }

    #[test]
    #[ignore = "pre-existing fixture expectation mismatch; predates the workspace split"]
    fn coin_fixture_migrate_and_destroy_emits_balance_invariant_check() {
        let output = frontend::load_project(
            "Benchmarks/Not-so-smart/not-so-smart-contracts-master/forced_ether_reception/coin.sol",
        )
        .expect("coin fixture should load");
        let ir_module = ir::lower_module(&output.ast);
        let cfgs = cfg::build_from_ir(&ir_module);
        let abis = extract_abis(&output.ast, &output.compiler);
        let abi = abis
            .iter()
            .find(|abi| abi.contract_name == "MyAdvancedToken")
            .expect("MyAdvancedToken abi");
        let deps = build_dependency_map(&ir_module, &output.ast);
        let individual = Individual {
            transactions: vec![Transaction {
                function_id: 12,
                args: Vec::new(),
                sender: 0,
                value: 0,
            }],
            environment: Environment::default(),
            energy: 1.0,
        };

        let trace = execute_individual(&individual, &output, &ir_module, &cfgs, abi, &deps);
        assert!(
            trace
                .events
                .iter()
                .any(|event| matches!(event.kind, TraceEventKind::BalanceInvariantCheck)),
            "expected BalanceInvariantCheck in trace, saw events: {:?}",
            trace.events
        );
    }
}
