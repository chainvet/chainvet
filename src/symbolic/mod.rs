// Symbolic Execution Engine
// Consumes IR/CFG/SSA from M3 to perform path exploration and constraint solving.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use serde::Serialize;
use z3::{
    SatResult, Solver,
    ast::{Bool, Int},
};

use crate::frontend::FrontendOutput;
use crate::ir::{ControlKind, IrInstr, IrPlace, IrValue, IrVar, PlaceClass};
use crate::norm::Span;
use crate::report::OutputFormat;
use crate::util::error::{Error, Result};
use crate::cfg;

#[derive(Clone)]
struct State {
    block_id: u32,
    env: HashMap<String, Int>,
    storage: HashMap<String, Int>,
    path_constraints: Vec<Bool>,
    fresh_id: u64,
    external_call_pc: Option<usize>,
    trace: Vec<usize>,
    expr_env: HashMap<String, String>,
    branch_triggers: Vec<String>,
}

#[derive(Clone)]
enum TerminationKind {
    Return,
    Revert,
    Fallthrough,
}

#[derive(Clone)]
struct TerminalState {
    kind: TerminationKind,
    values: Vec<Int>,
    path_constraints: Vec<Bool>,
}

#[derive(Debug, Clone, Serialize)]
struct FunctionSymbolicReport {
    id: u32,
    name: Option<String>,
    instructions: usize,
    explored_states: usize,
    reachable_returns: usize,
    reachable_reverts: usize,
    reachable_fallthroughs: usize,
    terminal_paths: usize,
    pruned_branches: usize,
    dead_ends: usize,
    max_worklist: usize,
    vulnerability_count: usize,
    truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
struct SymbolicReport {
    files: usize,
    functions: usize,
    instructions: usize,
    explored_states: usize,
    reachable_returns: usize,
    reachable_reverts: usize,
    reachable_fallthroughs: usize,
    terminal_paths: usize,
    pruned_branches: usize,
    dead_ends: usize,
    max_worklist: usize,
    vulnerability_count: usize,
    truncated_functions: usize,
    by_function: Vec<FunctionSymbolicReport>,
    vulnerabilities: Vec<VulnerabilityFinding>,
}

#[derive(Debug, Clone, Default)]
struct EngineStats {
    instructions: usize,
    explored_states: usize,
    reachable_returns: usize,
    reachable_reverts: usize,
    reachable_fallthroughs: usize,
    terminal_paths: usize,
    pruned_branches: usize,
    dead_ends: usize,
    max_worklist: usize,
    vulnerabilities: Vec<LocalVulnerability>,
    truncated: bool,
}

#[derive(Debug, Clone)]
struct LocalVulnerability {
    kind: VulnerabilityKind,
    pc: usize,
    instruction: String,
    trace: Vec<usize>,
    trigger: Option<String>,
    branch_triggers: Vec<String>,
    span: Option<Span>,
    path_constraints: Vec<String>,
    message: String,
    model: Option<String>,
}

#[derive(Debug, Clone)]
enum VulnerabilityKind {
    Underflow,
    Reentrancy,
}

impl VulnerabilityKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Underflow => "underflow",
            Self::Reentrancy => "reentrancy",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct VulnerabilityFinding {
    kind: String,
    function_id: u32,
    function_name: Option<String>,
    pc: usize,
    instruction: String,
    trace: Vec<usize>,
    trigger: Option<String>,
    branch_triggers: Vec<String>,
    location: Option<FindingLocation>,
    path_constraints: Vec<String>,
    message: String,
    model: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct FindingLocation {
    file: String,
    start: u32,
    end: u32,
    snippet: Option<String>,
}

impl State {
    fn new() -> Self {
        Self {
            block_id: 0,
            env: HashMap::new(),
            storage: HashMap::new(),
            path_constraints: Vec::new(),
            fresh_id: 0,
            external_call_pc: None,
            trace: Vec::new(),
            expr_env: HashMap::new(),
            branch_triggers: Vec::new(),
        }
    }

    fn fresh_symbol(&mut self, prefix: &str) -> Int {
        let id = self.fresh_id;
        self.fresh_id = self.fresh_id.saturating_add(1);
        Int::new_const(format!("{prefix}_{id}"))
    }

    fn lookup_var(&mut self, var: &IrVar) -> Int {
        let name = var_key(var);
        if let Some(value) = self.env.get(&name) {
            return value.clone();
        }
        let sym = self.fresh_symbol(&name);
        self.env.insert(name, sym.clone());
        sym
    }

    fn eval_value(&mut self, value: &IrValue) -> Int {
        match value {
            IrValue::Literal(lit) => Int::from_i64(stable_literal_value(lit.value.as_str())),
            IrValue::Var(var) => self.lookup_var(var),
            IrValue::Unknown => self.fresh_symbol("unknown"),
        }
    }

    fn eval_bool(&mut self, value: &IrValue) -> Bool {
        self.eval_value(value).eq(Int::from_i64(0)).not()
    }

    fn set_var(&mut self, var: &IrVar, value: Int) {
        self.env.insert(var_key(var), value);
    }

    fn value_expr(&self, value: &IrValue) -> String {
        match value {
            IrValue::Literal(lit) => lit.value.clone(),
            IrValue::Unknown => "unknown".to_string(),
            IrValue::Var(var) => {
                let key = var_key(var);
                self.expr_env.get(&key).cloned().unwrap_or(key)
            }
        }
    }

    fn read_place(&mut self, place: &IrPlace) -> Int {
        match place {
            IrPlace::Var { var, .. } => self.lookup_var(var),
            _ => {
                let key = place_key(place);
                if let Some(value) = self.storage.get(&key) {
                    return value.clone();
                }
                let sym = self.fresh_symbol("storage");
                self.storage.insert(key, sym.clone());
                sym
            }
        }
    }

    fn write_place(&mut self, place: &IrPlace, value: Int) {
        match place {
            IrPlace::Var { var, .. } => self.set_var(var, value),
            _ => {
                self.storage.insert(place_key(place), value);
            }
        }
    }
}

const MAX_ENGINE_STEPS: usize = 200_000;
const MAX_TRACE_LEN: usize = 128;

pub fn run(output: &FrontendOutput, format: OutputFormat) -> Result<()> {
    let ir_module = crate::ir::lower_module(&output.ast);
    let cfgs = cfg::build_from_ir(&ir_module);
    let mut by_function = Vec::new();

    let mut instructions = 0usize;
    let mut explored_states = 0usize;
    let mut reachable_returns = 0usize;
    let mut reachable_reverts = 0usize;
    let mut reachable_fallthroughs = 0usize;
    let mut terminal_paths = 0usize;
    let mut pruned_branches = 0usize;
    let mut dead_ends = 0usize;
    let mut max_worklist = 0usize;
    let mut vulnerabilities: Vec<VulnerabilityFinding> = Vec::new();
    let mut truncated_functions = 0usize;

    for function in &ir_module.functions {
        let Some(cfg_fn) = cfgs.iter().find(|cfg_fn| cfg_fn.id == function.id) else {
            continue;
        };

        let stats = engine(cfg_fn);
        instructions += stats.instructions;
        explored_states += stats.explored_states;
        reachable_returns += stats.reachable_returns;
        reachable_reverts += stats.reachable_reverts;
        reachable_fallthroughs += stats.reachable_fallthroughs;
        terminal_paths += stats.terminal_paths;
        pruned_branches += stats.pruned_branches;
        dead_ends += stats.dead_ends;
        max_worklist = max_worklist.max(stats.max_worklist);
        if stats.truncated {
            truncated_functions += 1;
        }
        let function_vulnerability_count = stats.vulnerabilities.len();
        for vuln in stats.vulnerabilities {
            vulnerabilities.push(VulnerabilityFinding {
                kind: vuln.kind.as_str().to_string(),
                function_id: function.id,
                function_name: function.name.clone(),
                pc: vuln.pc,
                instruction: vuln.instruction,
                trace: vuln.trace,
                trigger: vuln.trigger,
                branch_triggers: vuln.branch_triggers,
                location: vuln
                    .span
                    .as_ref()
                    .and_then(|span| build_location(span, output)),
                path_constraints: vuln.path_constraints,
                message: vuln.message,
                model: vuln.model,
            });
        }

        by_function.push(FunctionSymbolicReport {
            id: function.id,
            name: function.name.clone(),
            instructions: stats.instructions,
            explored_states: stats.explored_states,
            reachable_returns: stats.reachable_returns,
            reachable_reverts: stats.reachable_reverts,
            reachable_fallthroughs: stats.reachable_fallthroughs,
            terminal_paths: stats.terminal_paths,
            pruned_branches: stats.pruned_branches,
            dead_ends: stats.dead_ends,
            max_worklist: stats.max_worklist,
            vulnerability_count: function_vulnerability_count,
            truncated: stats.truncated,
        });
    }

    let report = SymbolicReport {
        files: output.ast.files.len(),
        functions: ir_module.functions.len(),
        instructions,
        explored_states,
        reachable_returns,
        reachable_reverts,
        reachable_fallthroughs,
        terminal_paths,
        pruned_branches,
        dead_ends,
        max_worklist,
        vulnerability_count: vulnerabilities.len(),
        truncated_functions,
        by_function,
        vulnerabilities,
    };

    match format {
        OutputFormat::Text => {
            println!(
                "symbolic: files={}, functions={}, instructions={}, explored_states={}, terminal_paths={}, returns={}, reverts={}, fallthroughs={}, pruned_branches={}, dead_ends={}, max_worklist={}, vulnerabilities={}, truncated_functions={}",
                report.files,
                report.functions,
                report.instructions,
                report.explored_states,
                report.terminal_paths,
                report.reachable_returns,
                report.reachable_reverts,
                report.reachable_fallthroughs,
                report.pruned_branches,
                report.dead_ends,
                report.max_worklist,
                report.vulnerability_count,
                report.truncated_functions
            );
            for entry in &report.by_function {
                println!(
                    "  fn {} ({}) -> instructions={}, states={}, terminals={}, returns={}, reverts={}, fallthroughs={}, pruned={}, dead_ends={}, max_worklist={}, vulns={}, truncated={}",
                    entry.id,
                    entry.name.as_deref().unwrap_or("<anonymous>"),
                    entry.instructions,
                    entry.explored_states,
                    entry.terminal_paths,
                    entry.reachable_returns,
                    entry.reachable_reverts,
                    entry.reachable_fallthroughs,
                    entry.pruned_branches,
                    entry.dead_ends,
                    entry.max_worklist,
                    entry.vulnerability_count,
                    entry.truncated
                );
            }
            if report.vulnerabilities.is_empty() {
                println!("vulnerabilities found: none");
            } else {
                println!("vulnerabilities found (detailed):");
                for (idx, vuln) in report.vulnerabilities.iter().enumerate() {
                    println!(
                        "  {}. kind={}, fn {} ({}), pc={}",
                        idx + 1,
                        vuln.kind,
                        vuln.function_id,
                        vuln.function_name.as_deref().unwrap_or("<anonymous>"),
                        vuln.pc
                    );
                    println!("     message: {}", vuln.message);
                    if let Some(trigger) = &vuln.trigger {
                        println!("     trigger: {}", trigger);
                    }
                    if let Some(location) = &vuln.location {
                        println!(
                            "     location: {}:{}-{}",
                            location.file, location.start, location.end
                        );
                        if let Some(snippet) = &location.snippet {
                            println!("     snippet: {}", snippet);
                        }
                    }
                    println!("     instruction: {}", vuln.instruction);
                    println!("     trace: {}", format_trace(&vuln.trace));
                    if !vuln.branch_triggers.is_empty() {
                        println!("     branch_triggers:");
                        for trigger in &vuln.branch_triggers {
                            println!("       - {}", trigger);
                        }
                    }
                    if vuln.path_constraints.is_empty() {
                        println!("     path_constraints: <none>");
                    } else {
                        println!("     path_constraints_count: {}", vuln.path_constraints.len());
                        for (idx, c) in vuln.path_constraints.iter().enumerate() {
                            println!("     constraint[{}]: {}", idx, c);
                        }
                    }
                    if let Some(model) = &vuln.model {
                        println!("     model: {}", truncate(model, 240));
                    }
                }
            }
        }
        OutputFormat::Json => {
            let payload = serde_json::to_string_pretty(&report)
                .map_err(|err| Error::msg(format!("failed to encode symbolic JSON report: {err}")))?;
            println!("{payload}");
        }
    }

    Ok(())
}

fn engine(cfg_fn: &cfg::CfgFunction) -> EngineStats {
    let instructions = cfg_fn.blocks.iter().map(|b| b.instrs.len()).sum::<usize>();
    if instructions == 0 {
        return EngineStats {
            instructions,
            ..EngineStats::default()
        };
    }

    let block_map = cfg_fn
        .blocks
        .iter()
        .map(|b| (b.id, b))
        .collect::<HashMap<_, _>>();
    let mut succs: HashMap<u32, Vec<u32>> = HashMap::new();
    for edge in &cfg_fn.edges {
        succs.entry(edge.from).or_default().push(edge.to);
    }
    let mut instr_positions: HashMap<(u32, usize), usize> = HashMap::new();
    let mut flat_pc = 0usize;
    for block in &cfg_fn.blocks {
        for idx in 0..block.instrs.len() {
            instr_positions.insert((block.id, idx), flat_pc);
            flat_pc += 1;
        }
    }

    let entry_block = cfg_fn.blocks.first().map(|b| b.id).unwrap_or(0);
    let mut worklist = vec![State {
        block_id: entry_block,
        ..State::new()
    }];
    let mut max_worklist = 1usize;
    let mut terminal_states: Vec<TerminalState> = Vec::new();
    let mut explored_states = 0usize;
    let mut pruned_branches = 0usize;
    let mut dead_ends = 0usize;
    let mut vulnerabilities = Vec::new();
    let mut seen_reentrancy_edges: HashSet<(usize, usize)> = HashSet::new();
    let mut truncated = false;

    while let Some(mut state) = worklist.pop() {
        explored_states += 1;
        if explored_states >= MAX_ENGINE_STEPS {
            truncated = true;
            break;
        }

        let Some(block) = block_map.get(&state.block_id) else {
            dead_ends += 1;
            continue;
        };
        let mut block_terminated = false;

        for (instr_index, instr) in block.instrs.iter().enumerate() {
            let current_pc = *instr_positions
                .get(&(state.block_id, instr_index))
                .unwrap_or(&usize::MAX);
            if state.trace.len() < MAX_TRACE_LEN {
                state.trace.push(current_pc);
            }

            match instr {
                IrInstr::Nop { .. } | IrInstr::InlineAsm { .. } => {}
                IrInstr::Eval { expr, .. } | IrInstr::Emit { expr, .. } => {
                    let _ = state.eval_value(expr);
                }
                IrInstr::Declare { names, init, .. } => {
                    let value = init.as_ref().map(|v| state.eval_value(v));
                    for name in names {
                        let assigned = value.clone().unwrap_or_else(|| state.fresh_symbol(name));
                        state.env.insert(name.clone(), assigned);
                        let expr = init
                            .as_ref()
                            .map(|v| state.value_expr(v))
                            .unwrap_or_else(|| name.clone());
                        state.expr_env.insert(name.clone(), expr);
                    }
                }
                IrInstr::Assign { dest, src, .. } => {
                    let value = state.eval_value(src);
                    state.set_var(dest, value);
                    state.expr_env.insert(var_key(dest), state.value_expr(src));
                }
                IrInstr::Store { dest, src, .. } => {
                    let value = state.eval_value(src);
                    if is_storage_place(dest) {
                        if let Some(call_pc) = state.external_call_pc {
                            if seen_reentrancy_edges.insert((call_pc, current_pc)) {
                                vulnerabilities.push(LocalVulnerability {
                                    kind: VulnerabilityKind::Reentrancy,
                                    pc: current_pc,
                                    instruction: format!("{instr:?}"),
                                    trace: state.trace.clone(),
                                    trigger: state.branch_triggers.last().cloned(),
                                    branch_triggers: state.branch_triggers.clone(),
                                    span: Some(instr_span(instr)),
                                    path_constraints: constraints_to_strings(&state.path_constraints),
                                    message: format!(
                                        "storage write after external call (call_pc={call_pc}, store_pc={current_pc})"
                                    ),
                                    model: None,
                                });
                            }
                        }
                    }
                    state.write_place(dest, value);
                }
                IrInstr::Load { dest, src, .. } => {
                    let value = state.read_place(src);
                    state.set_var(dest, value);
                    state
                        .expr_env
                        .insert(var_key(dest), format!("load({})", place_key(src)));
                }
                IrInstr::Binary {
                    dest, op, lhs, rhs, ..
                } => {
                    if let Some(folded) = try_eval_binary_literals(op, lhs, rhs) {
                        state.set_var(dest, folded);
                        continue;
                    }
                    let lhs_v = state.eval_value(lhs);
                    let rhs_v = state.eval_value(rhs);
                    if op == "-" {
                        if let Some(model) = check_underflow(&state.path_constraints, &lhs_v, &rhs_v)
                        {
                            vulnerabilities.push(LocalVulnerability {
                                kind: VulnerabilityKind::Underflow,
                                pc: current_pc,
                                instruction: format!("{instr:?}"),
                                trace: state.trace.clone(),
                                trigger: state.branch_triggers.last().cloned(),
                                branch_triggers: state.branch_triggers.clone(),
                                span: Some(instr_span(instr)),
                                path_constraints: constraints_to_strings(&state.path_constraints),
                                message: "potential arithmetic underflow: rhs > lhs is satisfiable"
                                    .to_string(),
                                model: Some(model),
                            });
                        }
                    }
                    let out = eval_binary(op, lhs_v, rhs_v);
                    state.set_var(dest, out);
                    let expr = format!("({} {} {})", state.value_expr(lhs), op, state.value_expr(rhs));
                    state.expr_env.insert(var_key(dest), expr);
                }
                IrInstr::Unary { dest, op, expr, .. } => {
                    let in_v = state.eval_value(expr);
                    let out = eval_unary(op, in_v);
                    state.set_var(dest, out);
                    state
                        .expr_env
                        .insert(var_key(dest), format!("({}{})", op, state.value_expr(expr)));
                }
                IrInstr::Call { dest, .. } => {
                    for var in dest {
                        let value = state.fresh_symbol("call_ret");
                        state.set_var(var, value);
                        state.expr_env.insert(var_key(var), "call_ret".to_string());
                    }
                    if state.external_call_pc.is_none() {
                        state.external_call_pc = Some(current_pc);
                    }
                }
                IrInstr::Select {
                    dest,
                    cond,
                    then_val,
                    else_val,
                    ..
                } => {
                    let cond_v = state.eval_bool(cond);
                    let then_v = state.eval_value(then_val);
                    let else_v = state.eval_value(else_val);
                    let selected = cond_v.ite(&then_v, &else_v);
                    state.set_var(dest, selected);
                    state.expr_env.insert(
                        var_key(dest),
                        format!(
                            "({} ? {} : {})",
                            state.value_expr(cond),
                            state.value_expr(then_val),
                            state.value_expr(else_val)
                        ),
                    );
                }
                IrInstr::Return { values, .. } => {
                    if is_feasible(&state.path_constraints) {
                        let ret_values = values
                            .iter()
                            .map(|value| state.eval_value(value))
                            .collect::<Vec<_>>();
                        terminal_states.push(TerminalState {
                            kind: TerminationKind::Return,
                            values: ret_values,
                            path_constraints: state.path_constraints.clone(),
                        });
                    }
                    block_terminated = true;
                    break;
                }
                IrInstr::Control { kind, .. } => {
                    let outgoing = succs.get(&state.block_id).cloned().unwrap_or_default();
                    match kind {
                        ControlKind::If { cond } => {
                            let cond_expr = state.eval_bool(cond);
                            let cond_text = state.value_expr(cond);

                            if let Some(true_block) = outgoing.first().copied() {
                                let mut true_state = state.clone();
                                true_state.path_constraints.push(cond_expr.clone());
                                true_state
                                    .branch_triggers
                                    .push(format!("{cond_text} == true"));
                                true_state.block_id = true_block;
                                if is_feasible(&true_state.path_constraints) {
                                    worklist.push(true_state);
                                    max_worklist = max_worklist.max(worklist.len());
                                } else {
                                    pruned_branches += 1;
                                }
                            } else {
                                dead_ends += 1;
                            }

                            if let Some(false_block) = outgoing.get(1).copied() {
                                let mut false_state = state.clone();
                                false_state.path_constraints.push(cond_expr.not());
                                false_state
                                    .branch_triggers
                                    .push(format!("{cond_text} == false"));
                                false_state.block_id = false_block;
                                if is_feasible(&false_state.path_constraints) {
                                    worklist.push(false_state);
                                    max_worklist = max_worklist.max(worklist.len());
                                } else {
                                    pruned_branches += 1;
                                }
                            } else {
                                dead_ends += 1;
                            }
                        }
                        ControlKind::Loop { cond } => {
                            if let Some(cond) = cond {
                                let cond_expr = state.eval_bool(cond);
                                let cond_text = state.value_expr(cond);
                                if let Some(body_block) = outgoing.first().copied() {
                                    let mut body_state = state.clone();
                                    body_state.path_constraints.push(cond_expr.clone());
                                    body_state
                                        .branch_triggers
                                        .push(format!("loop({cond_text}) == true"));
                                    body_state.block_id = body_block;
                                    if is_feasible(&body_state.path_constraints) {
                                        worklist.push(body_state);
                                        max_worklist = max_worklist.max(worklist.len());
                                    } else {
                                        pruned_branches += 1;
                                    }
                                } else {
                                    dead_ends += 1;
                                }
                                if let Some(exit_block) = outgoing.get(1).copied() {
                                    let mut exit_state = state.clone();
                                    exit_state.path_constraints.push(cond_expr.not());
                                    exit_state
                                        .branch_triggers
                                        .push(format!("loop({cond_text}) == false"));
                                    exit_state.block_id = exit_block;
                                    if is_feasible(&exit_state.path_constraints) {
                                        worklist.push(exit_state);
                                        max_worklist = max_worklist.max(worklist.len());
                                    } else {
                                        pruned_branches += 1;
                                    }
                                } else {
                                    dead_ends += 1;
                                }
                            } else if let Some(next_block) = outgoing.first().copied() {
                                let mut next_state = state.clone();
                                next_state.block_id = next_block;
                                worklist.push(next_state);
                                max_worklist = max_worklist.max(worklist.len());
                            } else {
                                dead_ends += 1;
                            }
                        }
                        ControlKind::Revert { value } => {
                            if is_feasible(&state.path_constraints) {
                                let revert_values = value
                                    .as_ref()
                                    .map(|v| vec![state.eval_value(v)])
                                    .unwrap_or_default();
                                terminal_states.push(TerminalState {
                                    kind: TerminationKind::Revert,
                                    values: revert_values,
                                    path_constraints: state.path_constraints.clone(),
                                });
                            }
                        }
                        _ => {
                            if outgoing.is_empty() {
                                dead_ends += 1;
                            } else {
                                for next_block in outgoing {
                                    let mut next_state = state.clone();
                                    next_state.block_id = next_block;
                                    worklist.push(next_state);
                                    max_worklist = max_worklist.max(worklist.len());
                                }
                            }
                        }
                    }
                    block_terminated = true;
                    break;
                }
            }
        }

        if block_terminated {
            continue;
        }

        let outgoing = succs.get(&state.block_id).cloned().unwrap_or_default();
        if outgoing.is_empty() {
            terminal_states.push(TerminalState {
                kind: TerminationKind::Fallthrough,
                values: Vec::new(),
                path_constraints: state.path_constraints.clone(),
            });
        } else {
            for next_block in outgoing {
                let mut next_state = state.clone();
                next_state.block_id = next_block;
                worklist.push(next_state);
                max_worklist = max_worklist.max(worklist.len());
            }
        }
    }

    let reachable_returns = terminal_states
        .iter()
        .filter(|state| matches!(state.kind, TerminationKind::Return))
        .count();
    let reachable_reverts = terminal_states
        .iter()
        .filter(|state| matches!(state.kind, TerminationKind::Revert))
        .count();
    let reachable_fallthroughs = terminal_states
        .iter()
        .filter(|state| matches!(state.kind, TerminationKind::Fallthrough))
        .count();
    let terminal_paths = terminal_states.len();

    EngineStats {
        instructions,
        explored_states,
        reachable_returns,
        reachable_reverts,
        reachable_fallthroughs,
        terminal_paths,
        pruned_branches,
        dead_ends,
        max_worklist,
        vulnerabilities,
        truncated,
    }
}

fn var_key(var: &IrVar) -> String {
    match var {
        IrVar::Named(name) => name.clone(),
        IrVar::Temp(id) => format!("tmp_{id}"),
    }
}

fn place_key(place: &IrPlace) -> String {
    format!("{place:?}")
}

fn stable_literal_value(raw: &str) -> i64 {
    let normalized = normalize_literal(raw);
    if normalized.eq_ignore_ascii_case("true") {
        return 1;
    }
    if normalized.eq_ignore_ascii_case("false") {
        return 0;
    }
    if let Some(hex) = normalized.strip_prefix("0x") {
        if let Ok(value) = u64::from_str_radix(hex, 16) {
            return value as i64;
        }
    }
    if let Ok(value) = normalized.parse::<i64>() {
        return value;
    }

    // Fallback for large/unsupported literal encodings: stable pseudo-concrete value
    // keeps equal literals equal and different literals usually different.
    stable_fnv1a64(normalized.as_bytes()) as i64
}

fn normalize_literal(raw: &str) -> String {
    let trimmed = raw.trim();
    for prefix in ["number(", "address(", "int(", "uint("] {
        if let Some(inner) = trimmed.strip_prefix(prefix).and_then(|s| s.strip_suffix(')')) {
            return inner.trim().to_string();
        }
    }
    trimmed.to_string()
}

fn stable_fnv1a64(bytes: &[u8]) -> u64 {
    struct Fnv64(u64);
    impl Hasher for Fnv64 {
        fn finish(&self) -> u64 {
            self.0
        }
        fn write(&mut self, bytes: &[u8]) {
            const OFFSET: u64 = 0xcbf29ce484222325;
            const PRIME: u64 = 0x100000001b3;
            if self.0 == 0 {
                self.0 = OFFSET;
            }
            for b in bytes {
                self.0 ^= *b as u64;
                self.0 = self.0.wrapping_mul(PRIME);
            }
        }
    }

    let mut hasher = Fnv64(0);
    bytes.hash(&mut hasher);
    hasher.finish()
}

fn try_eval_binary_literals(op: &str, lhs: &IrValue, rhs: &IrValue) -> Option<Int> {
    let (IrValue::Literal(lhs_lit), IrValue::Literal(rhs_lit)) = (lhs, rhs) else {
        return None;
    };

    let lhs_key = literal_key(lhs_lit);
    let rhs_key = literal_key(rhs_lit);
    match op {
        "==" => Some(Int::from_i64((lhs_key == rhs_key) as i64)),
        "!=" => Some(Int::from_i64((lhs_key != rhs_key) as i64)),
        _ => None,
    }
}

fn literal_key(lit: &crate::norm::Literal) -> String {
    format!("{}:{}", lit.kind.to_ascii_lowercase(), lit.value)
}

fn bool_to_int(condition: Bool) -> Int {
    condition.ite(&Int::from_i64(1), &Int::from_i64(0))
}

fn eval_binary(op: &str, lhs: Int, rhs: Int) -> Int {
    match op {
        "+" => Int::add(&[lhs, rhs]),
        "-" => Int::sub(&[lhs, rhs]),
        "*" => Int::mul(&[lhs, rhs]),
        "/" => lhs.div(rhs),
        "%" => lhs.modulo(rhs),
        "==" => bool_to_int(lhs.eq(rhs)),
        "!=" => bool_to_int(lhs.eq(rhs).not()),
        ">" => bool_to_int(lhs.gt(rhs)),
        ">=" => bool_to_int(lhs.ge(rhs)),
        "<" => bool_to_int(lhs.lt(rhs)),
        "<=" => bool_to_int(lhs.le(rhs)),
        "&&" => {
            let lhs_truth = lhs.eq(Int::from_i64(0)).not();
            let rhs_truth = rhs.eq(Int::from_i64(0)).not();
            bool_to_int(Bool::and(&[&lhs_truth, &rhs_truth]))
        }
        "||" => {
            let lhs_truth = lhs.eq(Int::from_i64(0)).not();
            let rhs_truth = rhs.eq(Int::from_i64(0)).not();
            bool_to_int(Bool::or(&[&lhs_truth, &rhs_truth]))
        }
        _ => Int::new_const(format!("bin_{op}")),
    }
}

fn eval_unary(op: &str, expr: Int) -> Int {
    match op {
        "+" => expr,
        "-" => expr.unary_minus(),
        "!" => bool_to_int(expr.eq(Int::from_i64(0))),
        _ => Int::new_const(format!("un_{op}")),
    }
}

fn is_feasible(path_constraints: &[Bool]) -> bool {
    let solver = Solver::new();
    for constraint in path_constraints {
        solver.assert(constraint);
    }
    matches!(solver.check(), SatResult::Sat)
}

fn check_underflow(path_constraints: &[Bool], lhs: &Int, rhs: &Int) -> Option<String> {
    let solver = Solver::new();
    for constraint in path_constraints {
        solver.assert(constraint);
    }
    solver.assert(rhs.gt(lhs.clone()));
    if matches!(solver.check(), SatResult::Sat) {
        return solver.get_model().map(|model| model.to_string());
    }
    None
}

fn constraints_to_strings(path_constraints: &[Bool]) -> Vec<String> {
    path_constraints.iter().map(|c| c.to_string()).collect()
}

fn format_trace(trace: &[usize]) -> String {
    if trace.is_empty() {
        return "<empty>".to_string();
    }
    trace
        .iter()
        .map(|pc| pc.to_string())
        .collect::<Vec<_>>()
        .join(" -> ")
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        return s.to_string();
    }
    let mut out = String::new();
    for c in s.chars().take(max_len) {
        out.push(c);
    }
    out.push_str(" ...");
    out
}

fn instr_span(instr: &IrInstr) -> Span {
    match instr {
        IrInstr::Nop { span }
        | IrInstr::Eval { span, .. }
        | IrInstr::Declare { span, .. }
        | IrInstr::Assign { span, .. }
        | IrInstr::Store { span, .. }
        | IrInstr::Load { span, .. }
        | IrInstr::Binary { span, .. }
        | IrInstr::Unary { span, .. }
        | IrInstr::Call { span, .. }
        | IrInstr::Select { span, .. }
        | IrInstr::Emit { span, .. }
        | IrInstr::Return { span, .. }
        | IrInstr::Control { span, .. }
        | IrInstr::InlineAsm { span, .. } => *span,
    }
}

fn build_location(span: &Span, output: &FrontendOutput) -> Option<FindingLocation> {
    let file = output.ast.files.get(span.file as usize)?;
    let start = span.start as usize;
    let end = span.end as usize;
    let snippet = file
        .source
        .get(start..end)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| truncate(s, 120));
    Some(FindingLocation {
        file: file.path.clone(),
        start: span.start,
        end: span.end,
        snippet,
    })
}

fn is_storage_place(place: &IrPlace) -> bool {
    match place {
        IrPlace::Var { class, .. } => matches!(class, PlaceClass::Storage),
        IrPlace::Member { class, .. } => matches!(class, PlaceClass::Storage),
        IrPlace::Index { class, .. } => matches!(class, PlaceClass::Storage),
    }
}