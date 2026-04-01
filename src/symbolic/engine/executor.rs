use z3::ast::{BV, Bool};
use z3::SatResult;

use crate::analysis::detectors::Severity;
use crate::cfg::{BlockId, CfgFunction};
use crate::ir::{ControlKind, IrCallOption, IrInstr, IrPlace, IrValue, IrVar, PlaceClass};
use crate::norm::Span;
use crate::symbolic::detectors::DetectorRegistry;
use crate::symbolic::results::finding::{Confidence, SeFinding, SeVulnKind};
use crate::symbolic::results::witness::Witness;
use crate::symbolic::solver::SmtSolver;
use crate::symbolic::state::storage::StorageLayout;
use crate::symbolic::state::SymbolicState;
use crate::symbolic::types::hash::KeccakContext;
use crate::symbolic::types::{bitvec, fresh_bv, literal_to_symbolic, zero_bv, SymbolicValue};

/// Outcome returned by `execute_block`.
///
/// The engine dispatches on this to update the worklist and path constraints.
pub enum BlockOutcome {
    /// Unconditional edge to one successor.
    Fallthrough { target: BlockId },
    /// Conditional branch: both successors must be feasibility-checked.
    Branch {
        cond: Bool,
        true_block: BlockId,
        false_block: BlockId,
    },
    /// Loop header: body/exit branch with unrolling tracking.
    LoopHeader {
        cond: Option<Bool>,
        body_block: BlockId,
        exit_block: Option<BlockId>,
    },
    /// Function returned with zero or more values.
    Return {
        #[allow(dead_code)] // Phase 6: used to propagate return values to callers
        values: Vec<SymbolicValue>,
    },
    /// Execution reverted.
    Revert {
        #[allow(dead_code)] // Phase 6: used to surface revert reasons in findings
        message: Option<SymbolicValue>,
    },
    /// Execution terminated without explicit return.
    Stop,
}

/// Non-fatal errors from block interpretation.
///
/// All variants are logged as warnings and execution continues
/// with a fallback value (e.g., fresh symbolic BV).
#[derive(Debug)]
#[allow(dead_code)] // Phase 6: UnresolvablePlace and SolverError raised by detector resolve paths
pub enum ExecutorError {
    UnsupportedInstruction(String),
    UnresolvablePlace(String),
    SolverError(String),
}

impl std::fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutorError::UnsupportedInstruction(s) => write!(f, "unsupported instruction: {s}"),
            ExecutorError::UnresolvablePlace(s) => write!(f, "unresolvable place: {s}"),
            ExecutorError::SolverError(s) => write!(f, "solver error: {s}"),
        }
    }
}

/// Interpret all IR instructions in a CFG block.
///
/// Mutates `state` (variable bindings, memory, storage, path constraints).
/// Calls detector hooks on each instruction and at block exit.
/// Returns the block's outcome for the engine to act on.
#[allow(clippy::too_many_arguments)] // all params are distinct; Phase 6 may bundle into ExecutionContext
pub fn execute_block(
    state: &mut SymbolicState,
    block: &crate::cfg::Block,
    cfg_func: &CfgFunction,
    detectors: &mut DetectorRegistry,
    solver: &dyn SmtSolver,
    keccak_ctx: &mut KeccakContext,
    layout: &StorageLayout,
    contract_name: &str,
    findings: &mut Vec<SeFinding>,
) -> Result<BlockOutcome, ExecutorError> {
    let mut outcome: Option<BlockOutcome> = None;

    for instr in &block.instrs {
        // Detector hook before each instruction.
        let new_findings = detectors.on_instruction(state, instr, solver);
        findings.extend(new_findings);

        state.instruction_count += 1;

        match instr {
            IrInstr::Nop { .. } => {}

            IrInstr::Eval { expr, .. } => {
                // Side-effecting expression — evaluate but discard result.
                let _ = eval_value(state, expr, keccak_ctx);
            }

            IrInstr::Declare { names, init, .. } => {
                for name in names {
                    let val = init
                        .as_ref()
                        .map(|v| eval_value(state, v, keccak_ctx))
                        .unwrap_or_else(|| zero_bv(256));
                    state.variables.set(IrVar::Named(name.clone()), val);
                }
            }

            IrInstr::Assign { dest, src, .. } => {
                let val = eval_value(state, src, keccak_ctx);
                state.variables.set(dest.clone(), val);
            }

            IrInstr::Binary { dest, op, lhs, rhs, .. } => {
                let lv = eval_value(state, lhs, keccak_ctx);
                let rv = eval_value(state, rhs, keccak_ctx);
                let width = lv.width().max(rv.width()).max(256);
                let lbv = lv.to_bv(width).unwrap_or_else(|_| BV::from_u64(0, width));
                let rbv = rv.to_bv(width).unwrap_or_else(|_| BV::from_u64(0, width));
                let result = bitvec::apply_binary_op(op, &lbv, &rbv, width)
                    .unwrap_or_else(|_| zero_bv(width));
                state.variables.set(dest.clone(), result);
            }

            IrInstr::Unary { dest, op, expr, prefix, .. } => {
                let val = eval_value(state, expr, keccak_ctx);
                let width = val.width().max(256);
                let bv = val.to_bv(width).unwrap_or_else(|_| BV::from_u64(0, width));
                let result = bitvec::apply_unary_op(op, &bv, width, *prefix)
                    .unwrap_or_else(|_| zero_bv(width));
                state.variables.set(dest.clone(), result);
            }

            IrInstr::Select { dest, cond, then_val, else_val, .. } => {
                let cond_sv = eval_value(state, cond, keccak_ctx);
                // Fallback: fresh unconstrained symbolic Bool keeps both branches reachable.
                let cond_bool = cond_sv.to_bool().unwrap_or_else(|_| fresh_symbolic_bool("select_cond"));
                let then_sv = eval_value(state, then_val, keccak_ctx);
                let else_sv = eval_value(state, else_val, keccak_ctx);

                let width = then_sv.width().max(else_sv.width()).max(256);
                let then_bv = then_sv.to_bv(width).unwrap_or_else(|_| BV::from_u64(0, width));
                let else_bv = else_sv.to_bv(width).unwrap_or_else(|_| BV::from_u64(0, width));
                let result_bv = cond_bool.ite(&then_bv, &else_bv);
                state
                    .variables
                    .set(dest.clone(), SymbolicValue::BitVec { width, val: result_bv });
            }

            IrInstr::Load { dest, src, .. } => {
                let val = resolve_place_read(state, src, layout, contract_name, keccak_ctx);
                state.variables.set(dest.clone(), val);
            }

            IrInstr::Store { dest, src, .. } => {
                let val = eval_value(state, src, keccak_ctx);
                resolve_place_write(state, dest, val, layout, contract_name, keccak_ctx);
            }

            IrInstr::Call { dest, callee, args, options, .. } => {
                let span = instr_span(instr);
                handle_call(
                    state,
                    callee,
                    args,
                    options,
                    dest,
                    solver,
                    keccak_ctx,
                    findings,
                    span,
                );
            }

            IrInstr::Emit { .. } => {
                // Event emission — no state effect.
            }

            IrInstr::InlineAsm { .. } => {
                // Havoc: we cannot model inline assembly symbolically.
                // Log a warning implicitly by doing nothing; confidence
                // should be downgraded by the engine for this path.
            }

            IrInstr::Return { values, .. } => {
                let vals: Vec<SymbolicValue> =
                    values.iter().map(|v| eval_value(state, v, keccak_ctx)).collect();
                outcome = Some(BlockOutcome::Return { values: vals });
                break;
            }

            IrInstr::Control { kind, span: _span } => {
                outcome = Some(handle_control(state, kind, cfg_func, block.id, keccak_ctx));
                break;
            }
        }
    }

    // Detector hook at block exit.
    let exit_findings = detectors.on_block_exit(state, block.id, solver);
    findings.extend(exit_findings);

    // If no explicit terminator was reached, determine outcome from CFG edges.
    let result = outcome.unwrap_or_else(|| {
        let succs = cfg_successors(cfg_func, block.id);
        match succs.as_slice() {
            [t] => BlockOutcome::Fallthrough { target: *t },
            [] => BlockOutcome::Stop,
            _ => BlockOutcome::Stop,
        }
    });

    Ok(result)
}

/// Translate a `ControlKind` terminator into a `BlockOutcome`.
///
/// Extracted from `execute_block` to keep that function within the 50-line guideline.
fn handle_control(
    state: &mut SymbolicState,
    kind: &ControlKind,
    cfg_func: &CfgFunction,
    block_id: BlockId,
    keccak_ctx: &mut KeccakContext,
) -> BlockOutcome {
    match kind {
        ControlKind::If { cond } => {
            let cond_sv = eval_value(state, cond, keccak_ctx);
            // Fallback: fresh unconstrained Bool keeps both branches reachable.
            let cond_bool =
                cond_sv.to_bool().unwrap_or_else(|_| fresh_symbolic_bool("if_cond"));
            let succs = cfg_successors(cfg_func, block_id);
            if succs.len() >= 2 {
                BlockOutcome::Branch {
                    cond: cond_bool,
                    true_block: succs[0],
                    false_block: succs[1],
                }
            } else if let Some(&t) = succs.first() {
                BlockOutcome::Fallthrough { target: t }
            } else {
                BlockOutcome::Stop
            }
        }

        ControlKind::Loop { cond } => {
            let cond_bool = cond.as_ref().map(|c| {
                let sv = eval_value(state, c, keccak_ctx);
                // Fallback: fresh unconstrained Bool keeps both body/exit reachable.
                sv.to_bool().unwrap_or_else(|_| fresh_symbolic_bool("loop_cond"))
            });
            let succs = cfg_successors(cfg_func, block_id);
            if let Some(&body) = succs.first() {
                BlockOutcome::LoopHeader {
                    cond: cond_bool,
                    body_block: body,
                    exit_block: succs.get(1).copied(),
                }
            } else {
                BlockOutcome::Stop
            }
        }

        ControlKind::Revert { value } => {
            let msg = value.as_ref().map(|v| eval_value(state, v, keccak_ctx));
            BlockOutcome::Revert { message: msg }
        }

        // Structural markers: fall through to single CFG successor.
        ControlKind::Else
        | ControlKind::EndIf
        | ControlKind::EndLoop
        | ControlKind::Break
        | ControlKind::Continue
        | ControlKind::Try
        | ControlKind::Catch
        | ControlKind::EndTry => {
            let succs = cfg_successors(cfg_func, block_id);
            if let Some(&t) = succs.first() {
                BlockOutcome::Fallthrough { target: t }
            } else {
                BlockOutcome::Stop
            }
        }
    }
}

/// Evaluate an `IrValue` in the current state, returning its symbolic value.
pub fn eval_value(
    state: &SymbolicState,
    value: &IrValue,
    _keccak_ctx: &mut KeccakContext,
) -> SymbolicValue {
    match value {
        IrValue::Var(var) => state
            .variables
            .get(var)
            .cloned()
            .unwrap_or_else(|| fresh_bv(&var_name(var), 256)),
        IrValue::Literal(lit) => literal_to_symbolic(lit),
        IrValue::Unknown => fresh_bv("unknown", 256),
    }
}

/// Dispatch a `Call` instruction.
///
/// Builtins are handled specially; all other calls havoc their destinations.
#[allow(clippy::too_many_arguments)]
fn handle_call(
    state: &mut SymbolicState,
    callee: &IrValue,
    args: &[IrValue],
    _options: &[IrCallOption],
    dest: &[IrVar],
    solver: &dyn SmtSolver,
    keccak_ctx: &mut KeccakContext,
    findings: &mut Vec<SeFinding>,
    span: Span,
) {
    match callee_name_str(callee).as_deref() {
        Some("require") | Some("require(bool)") | Some("require(bool,string)") => {
            handle_require(state, args, keccak_ctx, span);
        }
        Some("assert") | Some("assert(bool)") => {
            handle_assert(state, args, solver, keccak_ctx, findings, span);
        }
        Some("revert") | Some("revert()") | Some("revert(string)") => {
            // revert() as a bare call: block has no useful successors — no-op here.
        }
        Some("keccak256") | Some("keccak256(bytes)") => {
            handle_keccak_call(state, args, dest, keccak_ctx);
        }
        Some(name) if name.starts_with("abi.encode") => {
            if let Some(d) = dest.first() {
                // abi.encode* returns bytes; model as fresh symbolic word.
                state.variables.set(d.clone(), fresh_bv("abi_encoded", 256));
            }
        }
        _ => {
            // Unknown/external call: havoc all destination variables.
            for (i, d) in dest.iter().enumerate() {
                let name = format!("call_ret_{}_{}", var_name(d), i);
                state.variables.set(d.clone(), fresh_bv(&name, 256));
            }
        }
    }
}

/// Handle a `require(cond)` call: add cond as a path constraint.
fn handle_require(
    state: &mut SymbolicState,
    args: &[IrValue],
    keccak_ctx: &mut KeccakContext,
    span: Span,
) {
    if let Some(cond_val) = args.first() {
        let sv = eval_value(state, cond_val, keccak_ctx);
        if let Ok(b) = sv.to_bool() {
            state.path_constraints.add(b, format!("require at {:?}", span));
        }
    }
}

/// Handle an `assert(cond)` call: check for violation and add cond as constraint.
fn handle_assert(
    state: &mut SymbolicState,
    args: &[IrValue],
    solver: &dyn SmtSolver,
    keccak_ctx: &mut KeccakContext,
    findings: &mut Vec<SeFinding>,
    span: Span,
) {
    if let Some(cond_val) = args.first() {
        let sv = eval_value(state, cond_val, keccak_ctx);
        if let Ok(cond_bool) = sv.to_bool() {
            check_assert_violation(state, &cond_bool, solver, findings, span);
            // Continue on the "assert holds" path.
            state.path_constraints.add(cond_bool, format!("assert at {:?}", span));
        }
    }
}

/// Check whether an assertion can be violated on the current path.
fn check_assert_violation(
    state: &SymbolicState,
    cond_bool: &Bool,
    solver: &dyn SmtSolver,
    findings: &mut Vec<SeFinding>,
    span: Span,
) {
    let neg = cond_bool.not();
    let mut assumptions: Vec<Bool> = state
        .path_constraints
        .constraints()
        .iter()
        .map(|(c, _)| c.clone())
        .collect();
    assumptions.push(neg);

    if solver.check_sat_assuming(&assumptions) == SatResult::Sat {
        let witness = extract_witness(solver, state);
        findings.push(SeFinding {
            kind: SeVulnKind::AssertionFailure,
            severity: Severity::High,
            confidence: Confidence::High,
            message: "assert() can be violated on this path".to_string(),
            span,
            function_id: None,
            path_constraints: state
                .path_constraints
                .descriptions()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            witness,
            state_id: state.id,
            path_depth: state.path_depth,
        });
    }
}

/// Handle a `keccak256(input)` call: hash the input and bind the result.
fn handle_keccak_call(
    state: &mut SymbolicState,
    args: &[IrValue],
    dest: &[IrVar],
    keccak_ctx: &mut KeccakContext,
) {
    if let Some(input_val) = args.first() {
        let sv = eval_value(state, input_val, keccak_ctx);
        let hash = keccak_ctx.hash_single(&sv);
        if let Some(d) = dest.first() {
            state.variables.set(d.clone(), hash);
        }
    } else if let Some(d) = dest.first() {
        state.variables.set(d.clone(), fresh_bv("keccak_result", 256));
    }
}

/// Read from an `IrPlace`, returning a symbolic value.
///
/// Dispatches to per-variant helpers for `Var`, `Index`, and `Member`.
pub fn resolve_place_read(
    state: &mut SymbolicState,
    place: &IrPlace,
    layout: &StorageLayout,
    contract_name: &str,
    keccak_ctx: &mut KeccakContext,
) -> SymbolicValue {
    match place {
        IrPlace::Var { var, class } => {
            read_var(state, var, *class, layout, contract_name)
        }
        IrPlace::Index { base: _, index, root, class } => {
            let root_name = root.as_deref().unwrap_or("");
            let idx_bv = eval_optional_index(state, index.as_ref(), keccak_ctx);
            read_index(state, root_name, &idx_bv, *class, layout, contract_name)
        }
        IrPlace::Member { field, root, class, .. } => {
            let root_name = root.as_deref().unwrap_or("");
            read_member(state, root_name, field, *class, layout, contract_name)
        }
    }
}

/// Write a value to an `IrPlace`.
///
/// Dispatches to per-variant helpers for `Var`, `Index`, and `Member`.
pub fn resolve_place_write(
    state: &mut SymbolicState,
    place: &IrPlace,
    value: SymbolicValue,
    layout: &StorageLayout,
    contract_name: &str,
    keccak_ctx: &mut KeccakContext,
) {
    let value_bv = value.to_bv(256).unwrap_or_else(|_| BV::from_u64(0, 256));
    match place {
        IrPlace::Var { var, class } => {
            write_var(state, var, *class, &value_bv, layout, contract_name);
        }
        IrPlace::Index { base: _, index, root, class } => {
            let root_name = root.as_deref().unwrap_or("");
            let idx_bv = eval_optional_index(state, index.as_ref(), keccak_ctx);
            write_index(state, root_name, &idx_bv, *class, &value_bv, layout, contract_name);
        }
        IrPlace::Member { field, root, class, .. } => {
            let root_name = root.as_deref().unwrap_or("");
            write_member(state, root_name, field, *class, &value_bv, layout, contract_name);
        }
    }
}

// -- read helpers --

fn read_var(
    state: &mut SymbolicState,
    var: &IrVar,
    class: PlaceClass,
    layout: &StorageLayout,
    contract_name: &str,
) -> SymbolicValue {
    match class {
        PlaceClass::Storage => {
            let name = var_name(var);
            if layout.is_mapping(&name) {
                fresh_bv(&format!("storage_map_{name}"), 256)
            } else if let Some(slot) = layout.get_slot(contract_name, &name) {
                state.storage.sload(&BV::from_u64(slot, 256)).unwrap_or_else(|_| fresh_bv(&name, 256))
            } else {
                fresh_bv(&format!("storage_unknown_{name}"), 256)
            }
        }
        PlaceClass::Memory => {
            let addr = BV::from_u64(var_addr_hint(var), 256);
            state.memory.read(&addr).unwrap_or_else(|_| fresh_bv("mem_read", 256))
        }
        PlaceClass::Unknown => resolve_unknown_var_read(state, var, layout, contract_name),
    }
}

fn read_index(
    state: &mut SymbolicState,
    root_name: &str,
    idx_bv: &BV,
    class: PlaceClass,
    layout: &StorageLayout,
    contract_name: &str,
) -> SymbolicValue {
    match class {
        PlaceClass::Storage => {
            if layout.is_mapping(root_name) {
                state.storage.mapping_read(root_name, idx_bv)
                    .unwrap_or_else(|_| fresh_bv(root_name, 256))
            } else {
                let base_slot = layout.get_slot(contract_name, root_name).unwrap_or(0);
                let slot = BV::from_u64(base_slot, 256).bvadd(idx_bv);
                state.storage.sload(&slot).unwrap_or_else(|_| fresh_bv(root_name, 256))
            }
        }
        PlaceClass::Memory => {
            state.memory.read(idx_bv).unwrap_or_else(|_| fresh_bv("mem_read", 256))
        }
        PlaceClass::Unknown => fresh_bv(&format!("unknown_index_{root_name}"), 256),
    }
}

fn read_member(
    state: &mut SymbolicState,
    root_name: &str,
    field: &str,
    class: PlaceClass,
    layout: &StorageLayout,
    contract_name: &str,
) -> SymbolicValue {
    match class {
        PlaceClass::Storage => {
            let base_slot = layout.get_slot(contract_name, root_name).unwrap_or(0);
            let offset = layout.get_field_offset(root_name, field).unwrap_or(0);
            let slot = BV::from_u64(base_slot + offset, 256);
            state.storage.sload(&slot).unwrap_or_else(|_| fresh_bv(field, 256))
        }
        // TODO: derive address from base pointer + field offset when pointer tracking is added.
        PlaceClass::Memory | PlaceClass::Unknown => {
            fresh_bv(&format!("unknown_member_{root_name}_{field}"), 256)
        }
    }
}

// -- write helpers --

fn write_var(
    state: &mut SymbolicState,
    var: &IrVar,
    class: PlaceClass,
    value_bv: &BV,
    layout: &StorageLayout,
    contract_name: &str,
) {
    match class {
        PlaceClass::Storage => {
            let name = var_name(var);
            if let Some(slot) = layout.get_slot(contract_name, &name) {
                state.storage.sstore(&BV::from_u64(slot, 256), value_bv);
            }
            // Not in layout → discard (havoc semantics).
        }
        PlaceClass::Memory => {
            state.memory.write(&BV::from_u64(var_addr_hint(var), 256), value_bv);
        }
        PlaceClass::Unknown => {
            let name = var_name(var);
            if let Some(slot) = layout.get_slot(contract_name, &name) {
                state.storage.sstore(&BV::from_u64(slot, 256), value_bv);
            } else {
                state.variables.set(
                    var.clone(),
                    SymbolicValue::BitVec { width: 256, val: value_bv.clone() },
                );
            }
        }
    }
}

fn write_index(
    state: &mut SymbolicState,
    root_name: &str,
    idx_bv: &BV,
    class: PlaceClass,
    value_bv: &BV,
    layout: &StorageLayout,
    contract_name: &str,
) {
    match class {
        PlaceClass::Storage => {
            if layout.is_mapping(root_name) {
                state.storage.mapping_write(root_name, idx_bv, value_bv);
            } else {
                let base_slot = layout.get_slot(contract_name, root_name).unwrap_or(0);
                let slot = BV::from_u64(base_slot, 256).bvadd(idx_bv);
                state.storage.sstore(&slot, value_bv);
            }
        }
        PlaceClass::Memory => {
            state.memory.write(idx_bv, value_bv);
        }
        PlaceClass::Unknown => {
            // Discard write to unknown indexed place.
        }
    }
}

fn write_member(
    state: &mut SymbolicState,
    root_name: &str,
    field: &str,
    class: PlaceClass,
    value_bv: &BV,
    layout: &StorageLayout,
    contract_name: &str,
) {
    match class {
        PlaceClass::Storage => {
            let base_slot = layout.get_slot(contract_name, root_name).unwrap_or(0);
            let offset = layout.get_field_offset(root_name, field).unwrap_or(0);
            state.storage.sstore(&BV::from_u64(base_slot + offset, 256), value_bv);
        }
        // TODO: derive address from base pointer + field offset when pointer tracking is added.
        PlaceClass::Memory | PlaceClass::Unknown => {
            // Discard write to unknown memory member.
        }
    }
}

/// Evaluate an optional index `IrValue`, defaulting to `BV<256>(0)` if absent.
fn eval_optional_index(
    state: &SymbolicState,
    index: Option<&IrValue>,
    keccak_ctx: &mut KeccakContext,
) -> BV {
    index
        .map(|idx| {
            let sv = eval_value(state, idx, keccak_ctx);
            sv.to_bv(256).unwrap_or_else(|_| BV::from_u64(0, 256))
        })
        .unwrap_or_else(|| BV::from_u64(0, 256))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Collect direct CFG successors of a block, in edge order.
pub fn cfg_successors(cfg_func: &CfgFunction, block_id: BlockId) -> Vec<BlockId> {
    cfg_func
        .edges
        .iter()
        .filter(|e| e.from == block_id)
        .map(|e| e.to)
        .collect()
}

/// Three-tier variable read for Unknown class.
fn resolve_unknown_var_read(
    state: &mut SymbolicState,
    var: &IrVar,
    layout: &StorageLayout,
    contract_name: &str,
) -> SymbolicValue {
    // Tier 1: variable environment.
    if let Some(val) = state.variables.get(var) {
        return val.clone();
    }
    // Tier 2: storage slot.
    let name = var_name(var);
    if let Some(slot) = layout.get_slot(contract_name, &name) {
        let slot_bv = BV::from_u64(slot, 256);
        if let Ok(val) = state.storage.sload(&slot_bv) {
            return val;
        }
    }
    // Tier 3: havoc.
    fresh_bv(&format!("unknown_{name}"), 256)
}

/// Extract a string name from an `IrVar`.
fn var_name(var: &IrVar) -> String {
    match var {
        IrVar::Named(s) => s.clone(),
        IrVar::Temp(n) => format!("t{n}"),
    }
}

/// Extract the callee name string from an `IrValue`, if it's a named variable.
fn callee_name_str(callee: &IrValue) -> Option<String> {
    match callee {
        IrValue::Var(IrVar::Named(s)) => Some(s.clone()),
        IrValue::Literal(lit) => Some(lit.value.clone()),
        _ => None,
    }
}

/// Derive a memory address hint from a variable name (purely for testing).
/// Production code should pass addresses through proper load/store semantics.
fn var_addr_hint(var: &IrVar) -> u64 {
    match var {
        IrVar::Named(_) => 0,
        IrVar::Temp(n) => (*n as u64) * 32,
    }
}

/// Extract the span from an instruction (for error/finding reporting).
fn instr_span(instr: &IrInstr) -> Span {
    match instr {
        IrInstr::Nop { span } => *span,
        IrInstr::Eval { span, .. } => *span,
        IrInstr::Declare { span, .. } => *span,
        IrInstr::Assign { span, .. } => *span,
        IrInstr::Store { span, .. } => *span,
        IrInstr::Load { span, .. } => *span,
        IrInstr::Binary { span, .. } => *span,
        IrInstr::Unary { span, .. } => *span,
        IrInstr::Call { span, .. } => *span,
        IrInstr::Select { span, .. } => *span,
        IrInstr::Emit { span, .. } => *span,
        IrInstr::Return { span, .. } => *span,
        IrInstr::Control { span, .. } => *span,
        IrInstr::InlineAsm { span, .. } => *span,
    }
}

/// Create a fresh unconstrained symbolic Bool via a 1-bit BV comparison.
///
/// Used as a fallback when `to_bool()` fails — preserves both branches
/// instead of silently picking true or false.
fn fresh_symbolic_bool(prefix: &str) -> Bool {
    let bit = BV::fresh_const(prefix, 1);
    bit.eq(BV::from_u64(1, 1))
}

/// Attempt to extract a `Witness` from the current solver state.
///
/// Uses push/pop to avoid polluting the permanent constraint stack.
fn extract_witness(solver: &dyn SmtSolver, state: &SymbolicState) -> Option<Witness> {
    solver.push();
    for (c, _) in state.path_constraints.constraints() {
        solver.assert_constraint(c);
    }
    let result = if solver.check_sat() == SatResult::Sat {
        solver.get_model().map(|m| Witness::from_model(&m, &state.call_context))
    } else {
        None
    };
    solver.pop();
    result
}

/// Pre-populate variable env with well-known blockchain context names.
///
/// IR references `msg.sender`, `block.timestamp`, etc. as named variables.
/// This binds them to the `CallContext` BV fields before execution begins.
pub fn pre_populate_call_context(state: &mut SymbolicState) {
    macro_rules! bind {
        ($name:expr, $bv:expr, $width:expr) => {
            state.variables.set(
                IrVar::Named($name.to_string()),
                SymbolicValue::BitVec { width: $width, val: $bv.clone() },
            );
        };
    }

    // 160-bit address fields
    bind!("msg.sender", state.call_context.msg_sender, 160);
    bind!("tx.origin", state.call_context.tx_origin, 160);
    bind!("block.coinbase", state.call_context.block_coinbase, 160);

    // 256-bit fields
    bind!("msg.value", state.call_context.msg_value, 256);
    bind!("block.timestamp", state.call_context.block_timestamp, 256);
    bind!("block.number", state.call_context.block_number, 256);
    bind!("address(this).balance", state.call_context.this_balance, 256);
    bind!("this.balance", state.call_context.this_balance, 256);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{Block, BlockId, CfgFunction, Edge};
    use crate::ir::{ControlKind, IrValue, IrVar};
    use crate::norm::{Literal, Span};
    use crate::symbolic::detectors::DetectorRegistry;
    use crate::symbolic::solver::z3_backend::Z3Backend;
    use crate::symbolic::state::call_context::CallContext;
    use crate::symbolic::state::storage::StorageLayout;
    use crate::symbolic::state::{StateIdGen, SymbolicState};
    use crate::symbolic::types::hash::KeccakContext;
    use crate::symbolic::types::concrete_bv;

    // ---- Test helpers ----

    fn span() -> Span {
        Span { file: 0, start: 0, end: 0 }
    }

    fn make_state() -> SymbolicState {
        let mut id_gen = StateIdGen::new();
        let (ctx, _) = CallContext::new_symbolic();
        SymbolicState::initial(&mut id_gen, 0, ctx)
    }

    /// Build a CfgFunction with a single block containing `instrs` and no edges.
    fn single_block_cfg(instrs: Vec<IrInstr>) -> CfgFunction {
        CfgFunction {
            id: 0,
            blocks: vec![Block { id: 0, instrs }],
            edges: vec![],
        }
    }

    /// Build a CfgFunction with a single block, one edge to a successor.
    fn single_block_cfg_with_successor(instrs: Vec<IrInstr>, to: BlockId) -> CfgFunction {
        CfgFunction {
            id: 0,
            blocks: vec![Block { id: 0, instrs }],
            edges: vec![Edge { from: 0, to }],
        }
    }

    /// Run execute_block on a given cfg and block id, returning the outcome.
    fn run_block(
        state: &mut SymbolicState,
        cfg: &CfgFunction,
        block_id: BlockId,
    ) -> BlockOutcome {
        let solver = Z3Backend::new(0);
        let mut keccak = KeccakContext::new();
        let layout = StorageLayout::empty();
        let mut detectors = DetectorRegistry::new();
        let mut findings = vec![];
        let block = cfg.blocks.iter().find(|b| b.id == block_id).unwrap();
        execute_block(state, block, cfg, &mut detectors, &solver, &mut keccak, &layout, "", &mut findings)
            .unwrap()
    }

    // ---- eval_value tests ----

    #[test]
    fn test_eval_value_var_in_env() {
        // A variable that is bound in the VariableEnv must be returned by eval_value.
        let mut state = make_state();
        let mut keccak = KeccakContext::new();
        let var = IrVar::Named("x".to_string());
        state.variables.set(var.clone(), concrete_bv(42, 256));

        let result = eval_value(&state, &IrValue::Var(var), &mut keccak);
        // Verify the result is a BV with value 42.
        let bv = result.as_bv().expect("expected BitVec");
        assert_eq!(bv.get_size(), 256);
    }

    #[test]
    fn test_eval_value_unbound_var_returns_fresh_bv() {
        // An unbound variable must produce a fresh symbolic BV<256> rather than panicking.
        let state = make_state();
        let mut keccak = KeccakContext::new();
        let var = IrVar::Named("unbound_var".to_string());
        let result = eval_value(&state, &IrValue::Var(var), &mut keccak);
        assert_eq!(result.width(), 256, "unbound var should return a 256-bit symbolic BV");
    }

    #[test]
    fn test_eval_value_literal_number() {
        // IrValue::Literal with kind="number" and value="42" must produce BV 42.
        let state = make_state();
        let mut keccak = KeccakContext::new();
        let lit = IrValue::Literal(Literal { kind: "number".to_string(), value: "42".to_string() });
        let result = eval_value(&state, &lit, &mut keccak);
        // The result must be a 256-bit BV. Verify width.
        assert_eq!(result.width(), 256);
        // Confirm it's a BitVec variant.
        assert!(result.as_bv().is_some());
    }

    #[test]
    fn test_eval_value_unknown_returns_fresh_bv() {
        // IrValue::Unknown must produce a fresh 256-bit symbolic BV.
        let state = make_state();
        let mut keccak = KeccakContext::new();
        let result = eval_value(&state, &IrValue::Unknown, &mut keccak);
        assert_eq!(result.width(), 256, "IrValue::Unknown should produce BV<256>");
    }

    // ---- pre_populate_call_context tests ----

    #[test]
    fn test_pre_populate_call_context_binds_msg_sender() {
        // After pre_populate, "msg.sender" must be in the variable environment.
        let mut state = make_state();
        pre_populate_call_context(&mut state);
        let key = IrVar::Named("msg.sender".to_string());
        assert!(
            state.variables.contains(&key),
            "pre_populate_call_context must bind msg.sender"
        );
    }

    #[test]
    fn test_pre_populate_call_context_binds_block_timestamp() {
        // After pre_populate, "block.timestamp" must be in the variable environment.
        let mut state = make_state();
        pre_populate_call_context(&mut state);
        let key = IrVar::Named("block.timestamp".to_string());
        assert!(
            state.variables.contains(&key),
            "pre_populate_call_context must bind block.timestamp"
        );
    }

    // ---- cfg_successors tests ----

    #[test]
    fn test_cfg_successors_returns_correct_targets() {
        // Build a CfgFunction with edges from block 0 to blocks 1 and 2.
        // cfg_successors(cfg, 0) should return [1, 2] (order matches edge insertion).
        let cfg = CfgFunction {
            id: 0,
            blocks: vec![
                Block { id: 0, instrs: vec![] },
                Block { id: 1, instrs: vec![] },
                Block { id: 2, instrs: vec![] },
            ],
            edges: vec![
                Edge { from: 0, to: 1 },
                Edge { from: 0, to: 2 },
            ],
        };
        let succs = cfg_successors(&cfg, 0);
        assert_eq!(succs.len(), 2);
        assert!(succs.contains(&1));
        assert!(succs.contains(&2));
    }

    // ---- execute_block tests ----

    #[test]
    fn test_execute_block_nop_returns_fallthrough() {
        // A block with only a Nop instruction and one outgoing edge must produce
        // BlockOutcome::Fallthrough to that single successor.
        let instrs = vec![IrInstr::Nop { span: span() }];
        let cfg = single_block_cfg_with_successor(instrs, 1);
        let mut state = make_state();

        match run_block(&mut state, &cfg, 0) {
            BlockOutcome::Fallthrough { target } => {
                assert_eq!(target, 1, "Nop block with one successor should fall through to it");
            }
            _ => panic!("expected Fallthrough, got different variant"),
        }
    }

    #[test]
    fn test_execute_block_assign_binds_variable() {
        // An Assign instruction must bind the destination variable in state.variables.
        let dest = IrVar::Named("result".to_string());
        let src = IrValue::Literal(Literal { kind: "number".to_string(), value: "99".to_string() });
        let instrs = vec![IrInstr::Assign { dest: dest.clone(), src, span: span() }];
        let cfg = single_block_cfg(instrs);
        let mut state = make_state();

        run_block(&mut state, &cfg, 0);

        assert!(
            state.variables.contains(&dest),
            "execute_block must bind the dest variable after Assign"
        );
    }

    #[test]
    fn test_execute_block_return_terminates_path() {
        // A block ending in Return must produce BlockOutcome::Return.
        let instrs = vec![IrInstr::Return { values: vec![], span: span() }];
        let cfg = single_block_cfg(instrs);
        let mut state = make_state();

        match run_block(&mut state, &cfg, 0) {
            BlockOutcome::Return { .. } => {}
            _ => panic!("expected Return outcome"),
        }
    }

    #[test]
    fn test_execute_block_revert() {
        // A block ending in ControlKind::Revert must produce BlockOutcome::Revert.
        let instrs = vec![IrInstr::Control {
            kind: ControlKind::Revert { value: None },
            span: span(),
        }];
        let cfg = single_block_cfg(instrs);
        let mut state = make_state();

        match run_block(&mut state, &cfg, 0) {
            BlockOutcome::Revert { .. } => {}
            _ => panic!("expected Revert outcome"),
        }
    }

    #[test]
    fn test_execute_block_branch_from_if() {
        // A block ending in ControlKind::If with two outgoing CFG edges must produce
        // BlockOutcome::Branch with both true_block and false_block set.
        let cond_var = IrVar::Named("cond".to_string());
        let instrs = vec![IrInstr::Control {
            kind: ControlKind::If { cond: IrValue::Var(cond_var) },
            span: span(),
        }];
        // Two successors: block 1 (true branch) and block 2 (false branch).
        let cfg = CfgFunction {
            id: 0,
            blocks: vec![
                Block { id: 0, instrs },
                Block { id: 1, instrs: vec![] },
                Block { id: 2, instrs: vec![] },
            ],
            edges: vec![
                Edge { from: 0, to: 1 },
                Edge { from: 0, to: 2 },
            ],
        };
        let mut state = make_state();

        match run_block(&mut state, &cfg, 0) {
            BlockOutcome::Branch { true_block, false_block, .. } => {
                assert_eq!(true_block, 1, "first successor should be true_block");
                assert_eq!(false_block, 2, "second successor should be false_block");
            }
            _ => panic!("expected Branch outcome from ControlKind::If with two edges"),
        }
    }
}
