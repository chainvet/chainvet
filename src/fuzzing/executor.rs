use std::collections::{HashMap, HashSet};

use crate::cfg::CfgFunction;
use crate::ir::{
    ControlKind, IrCallOption, IrInstr, IrModule, IrPlace, IrValue, IrVar, PlaceClass,
};
use crate::norm::NormalizedAst;

use crate::fuzzing::types::{
    ContractAbi, Environment, ExecutionTrace, FuzzValue, Individual, TraceEvent, TraceEventKind,
    Transaction,
};

/// Simulated state: variable_name → FuzzValue.
type SimState = HashMap<String, FuzzValue>;

/// Execute a full individual (sequence of transactions) against the IR.
pub fn execute_individual(
    ind: &Individual,
    ast: &NormalizedAst,
    ir_module: &IrModule,
    cfgs: &[CfgFunction],
    abi: &ContractAbi,
) -> ExecutionTrace {
    let mut state = init_state(ast);
    let mut trace = ExecutionTrace::default();

    for tx in &ind.transactions {
        let result =
            execute_transaction(tx, &ind.environment, &mut state, ast, ir_module, cfgs, abi);
        trace.events.extend(result.events);
        trace.coverage.extend(&result.coverage);
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

/// Track which temp vars originate from special sources.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum TempOrigin {
    /// Loaded from block.timestamp
    Timestamp,
    /// Loaded from a .call / .send / .transfer member (external call reference)
    ExternalCallRef,
    /// Derived from a timestamp value through arithmetic
    TimestampDerived,
    /// Loaded from tx.origin
    TxOrigin,
    /// Loaded from storage (for detecting storage-dependent loop bounds)
    StorageDerived,
    /// Loaded from block.number or blockhash (for weak PRNG detection)
    BlockNumberDerived,
    /// Result of a division operation (for div-before-mul detection)
    DivisionResult,
}

/// Execute a single transaction.
fn execute_transaction(
    tx: &Transaction,
    env: &Environment,
    state: &mut SimState,
    ast: &NormalizedAst,
    ir_module: &IrModule,
    cfgs: &[CfgFunction],
    _abi: &ContractAbi,
) -> ExecutionTrace {
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
    // Mark block.timestamp as a timestamp source
    temp_origins
        .entry("block.timestamp".to_string())
        .or_default()
        .insert(TempOrigin::Timestamp);

    // If we have a CFG, walk through blocks for coverage; otherwise walk IR blocks linearly.
    if let Some(cfg) = cfg {
        for block in &cfg.blocks {
            trace.coverage.insert((tx.function_id, block.id));
            trace.events.push(TraceEvent {
                function_id: tx.function_id,
                kind: TraceEventKind::BlockVisited { block_id: block.id },
            });

            for instr in &block.instrs {
                execute_instr(
                    instr,
                    tx.function_id,
                    state,
                    &mut locals,
                    &mut trace,
                    contract_name.as_deref(),
                    &mut temp_origins,
                );
            }
        }
    } else {
        for block in &ir_func.blocks {
            trace.coverage.insert((tx.function_id, block.id));
            trace.events.push(TraceEvent {
                function_id: tx.function_id,
                kind: TraceEventKind::BlockVisited { block_id: block.id },
            });
            for instr in &block.instrs {
                execute_instr(
                    instr,
                    tx.function_id,
                    state,
                    &mut locals,
                    &mut trace,
                    contract_name.as_deref(),
                    &mut temp_origins,
                );
            }
        }
    }

    // --- Post-execution analysis ---

    // Access control: check if any storage write happened without a sender check
    let has_sender_check = trace.events.iter().any(|e| {
        e.function_id == tx.function_id && matches!(e.kind, TraceEventKind::SenderChecked)
    });
    let has_storage_write = trace.events.iter().any(|e| {
        e.function_id == tx.function_id && matches!(e.kind, TraceEventKind::StorageWrite { .. })
    });
    if has_storage_write && !has_sender_check {
        trace.events.push(TraceEvent {
            function_id: tx.function_id,
            kind: TraceEventKind::StorageWrite {
                var_name: "__no_sender_check".to_string(),
            },
        });
    }

    // Exception disorder: external call followed by state write without require check
    let mut last_ext_call: Option<String> = None;
    let mut ext_call_checked = false;
    let mut disorder_events = Vec::new();
    for event in &trace.events {
        if event.function_id != tx.function_id {
            continue;
        }
        match &event.kind {
            TraceEventKind::ExternalCall { callee, .. } => {
                last_ext_call = Some(callee.clone());
                ext_call_checked = false;
            }
            TraceEventKind::Revert { .. } => {
                // A require() was hit — marks the call as checked
                ext_call_checked = true;
            }
            TraceEventKind::StorageWrite { var_name } => {
                if let Some(callee) = &last_ext_call {
                    if !ext_call_checked && var_name != "__no_sender_check" {
                        disorder_events.push(TraceEvent {
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

    trace
}

/// Simulate a single IR instruction, recording trace events.
fn execute_instr(
    instr: &IrInstr,
    function_id: u32,
    state: &mut SimState,
    locals: &mut HashMap<String, FuzzValue>,
    trace: &mut ExecutionTrace,
    contract_name: Option<&str>,
    temp_origins: &mut HashMap<String, HashSet<TempOrigin>>,
) {
    match instr {
        IrInstr::Store { dest, src, .. } => {
            let val = resolve_value(src, state, locals);
            if is_storage(dest) {
                if let Some(name) = place_name(dest, contract_name) {
                    state.insert(name.clone(), val);
                    trace.events.push(TraceEvent {
                        function_id,
                        kind: TraceEventKind::StorageWrite { var_name: name },
                    });
                }
            } else if let Some(name) = place_name(dest, contract_name) {
                locals.insert(name, val);
            }
        }
        IrInstr::Load { dest, src, .. } => {
            let src_place_name = place_name(src, contract_name).unwrap_or_default();
            let dest_key = var_key(dest);

            let val = if is_storage(src) {
                trace.events.push(TraceEvent {
                    function_id,
                    kind: TraceEventKind::StorageRead {
                        var_name: src_place_name.clone(),
                    },
                });
                // Mark dest as storage-derived for DoS loop detection
                temp_origins
                    .entry(dest_key.clone())
                    .or_default()
                    .insert(TempOrigin::StorageDerived);
                state
                    .get(&src_place_name)
                    .cloned()
                    .unwrap_or(FuzzValue::Uint(0))
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
                            function_id,
                            kind: TraceEventKind::BlockNumberUsed,
                        });
                    }

                    // Detect tx.origin loads
                    if full_name == "tx.origin" || base_name == "tx" && f == "origin" {
                        temp_origins
                            .entry(dest_key.clone())
                            .or_default()
                            .insert(TempOrigin::TxOrigin);
                        trace.events.push(TraceEvent {
                            function_id,
                            kind: TraceEventKind::TxOriginUsed,
                        });
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
                            function_id,
                            kind: TraceEventKind::TxOriginUsed,
                        });
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

            set_var(dest, val, locals);
        }
        IrInstr::Declare { names, init, .. } => {
            let val = init
                .as_ref()
                .map(|v| resolve_value(v, state, locals))
                .unwrap_or(FuzzValue::Uint(0));
            for name in names {
                locals.insert(name.clone(), val.clone());
            }
        }
        IrInstr::Assign { dest, src, .. } => {
            let val = resolve_value(src, state, locals);

            // Propagate origins
            let src_key = value_key(src);
            if let Some(origins) = temp_origins.get(&src_key).cloned() {
                let dest_key = var_key(dest);
                temp_origins.entry(dest_key).or_default().extend(origins);
            }

            set_var(dest, val, locals);
        }
        IrInstr::Binary {
            dest, op, lhs, rhs, ..
        } => {
            let l = resolve_value(lhs, state, locals).as_uint();
            let r = resolve_value(rhs, state, locals).as_uint();
            let result = eval_binary(op, l, r);

            // Track arithmetic for overflow detection
            if matches!(op.as_str(), "+" | "-" | "*") {
                trace.events.push(TraceEvent {
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
                let dest_key = var_key(dest);
                temp_origins
                    .entry(dest_key)
                    .or_default()
                    .insert(TempOrigin::TimestampDerived);
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
                let dest_key = var_key(dest);
                temp_origins
                    .entry(dest_key)
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
                    let dest_key = var_key(dest);
                    temp_origins
                        .entry(dest_key)
                        .or_default()
                        .insert(TempOrigin::StorageDerived);
                    trace.events.push(TraceEvent {
                        function_id,
                        kind: TraceEventKind::SenderChecked,
                    });
                }
            }

            set_var(dest, FuzzValue::Uint(result), locals);

            // Track division results for div-before-mul detection
            if op == "/" {
                let dest_key_dm = var_key(dest);
                temp_origins
                    .entry(dest_key_dm)
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
            if temp_origins
                .get(&expr_key)
                .map(|o| {
                    o.contains(&TempOrigin::Timestamp) || o.contains(&TempOrigin::TimestampDerived)
                })
                .unwrap_or(false)
            {
                let dest_key = var_key(dest);
                temp_origins
                    .entry(dest_key)
                    .or_default()
                    .insert(TempOrigin::TimestampDerived);
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
            let has_value = options.iter().any(|o| matches!(o, IrCallOption::Value(_)));

            // Detect selfdestruct / suicide calls
            let callee_lower = callee_name.to_lowercase();
            if callee_lower == "selfdestruct" || callee_lower == "suicide" {
                trace.events.push(TraceEvent {
                    function_id,
                    kind: TraceEventKind::SelfDestructCall,
                });
            }

            // Detect delegatecall
            if callee_lower.contains("delegatecall") {
                trace.events.push(TraceEvent {
                    function_id,
                    kind: TraceEventKind::DelegatecallDetected {
                        callee: callee_name.clone(),
                    },
                });
            }

            // Detect ecrecover calls
            if callee_lower == "ecrecover" {
                trace.events.push(TraceEvent {
                    function_id,
                    kind: TraceEventKind::EcrecoverCalled {
                        checked_zero: false,
                    },
                });
            }

            // Detect .transfer() / .send() (hardcoded gas limit)
            if callee_lower == "transfer"
                || callee_lower == "send"
                || callee_lower.ends_with(".transfer")
                || callee_lower.ends_with(".send")
            {
                trace.events.push(TraceEvent {
                    function_id,
                    kind: TraceEventKind::HardcodedGasCall {
                        callee: callee_name.clone(),
                    },
                });
            }

            // Detect require(cond) — marks that the function checks conditions
            // If 1st arg is derived from a comparison with msg.sender, emit SenderChecked
            if callee_name == "require" || callee_name == "assert" {
                if let Some(first_arg) = args.first() {
                    let arg_key = value_key(first_arg);
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
                            function_id,
                            kind: TraceEventKind::SenderChecked,
                        });
                    }
                }
            }

            // Check if callee is an external call — either by name or by origin tracking
            let is_external_by_name = is_external_call(&callee_name);
            let is_external_by_origin = temp_origins
                .get(&callee_key)
                .map(|o| o.contains(&TempOrigin::ExternalCallRef))
                .unwrap_or(false);
            let is_external = is_external_by_name || is_external_by_origin || has_value;

            if is_external {
                trace.events.push(TraceEvent {
                    function_id,
                    kind: TraceEventKind::ExternalCall {
                        callee: callee_name.clone(),
                        has_value,
                    },
                });

                // For unchecked call detection:
                if dest.is_empty() {
                    trace.events.push(TraceEvent {
                        function_id,
                        kind: TraceEventKind::CallReturnUnchecked {
                            callee: callee_name.clone(),
                        },
                    });
                }
            }

            // Set return values to defaults
            for var in dest {
                set_var(var, FuzzValue::Uint(0), locals);
            }

            // Track ether-sending calls
            if has_value && is_external {
                trace.events.push(TraceEvent {
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
                    let cond_key = value_key(cond);
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
                            function_id,
                            kind: TraceEventKind::BranchOnTimestamp,
                        });
                    }
                }
                ControlKind::Loop { cond } => {
                    // Detect unbounded loops: loop condition depends on storage-derived value
                    if let Some(cond_val) = cond {
                        let cond_key = value_key(cond_val);
                        let is_storage_dep = temp_origins
                            .get(&cond_key)
                            .map(|o| o.contains(&TempOrigin::StorageDerived))
                            .unwrap_or(false);
                        if is_storage_dep {
                            let cond_name = value_name(cond_val);
                            trace.events.push(TraceEvent {
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
            let val = if c.is_truthy() {
                resolve_value(then_val, state, locals)
            } else {
                resolve_value(else_val, state, locals)
            };
            set_var(dest, val, locals);
        }
        IrInstr::InlineAsm { .. } => {
            trace.events.push(TraceEvent {
                function_id,
                kind: TraceEventKind::InlineAssemblyDetected,
            });
        }
        _ => {}
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let lit = crate::norm::Literal {
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
}
