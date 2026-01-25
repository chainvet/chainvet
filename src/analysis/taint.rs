use std::collections::{HashMap, HashSet, VecDeque};

use crate::analysis::{ResolvedCallGraph, ResolvedTarget};
use crate::cfg::{Block, CfgFunction};
use crate::ir::{IrCallOption, IrInstr, IrPlace, IrValue, IrVar};
use crate::norm::{CallOption, ExprKind, Function, NormalizedAst, StmtKind};

#[derive(Debug, Clone)]
pub struct TaintSummary {
    pub function_id: u32,
    pub tainted_vars: Vec<String>,
    pub tainted_calls: Vec<u32>,
    pub uses_source: bool,
}

#[derive(Debug, Clone)]
pub struct TaintPropagation {
    pub source_functions: usize,
    pub tainted_functions: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BitSet {
    words: Vec<u64>,
}

impl BitSet {
    fn new(size: usize) -> Self {
        let words = (size + 63) / 64;
        Self {
            words: vec![0; words],
        }
    }

    fn set(&mut self, idx: usize) {
        let word = idx / 64;
        let bit = idx % 64;
        if word < self.words.len() {
            self.words[word] |= 1u64 << bit;
        }
    }

    fn clear(&mut self, idx: usize) {
        let word = idx / 64;
        let bit = idx % 64;
        if word < self.words.len() {
            self.words[word] &= !(1u64 << bit);
        }
    }

    fn contains(&self, idx: usize) -> bool {
        let word = idx / 64;
        let bit = idx % 64;
        if word >= self.words.len() {
            return false;
        }
        (self.words[word] & (1u64 << bit)) != 0
    }

    fn union_from(&mut self, other: &BitSet) -> bool {
        let mut changed = false;
        let len = self.words.len().min(other.words.len());
        for idx in 0..len {
            let before = self.words[idx];
            let value = before | other.words[idx];
            if value != before {
                self.words[idx] = value;
                changed = true;
            }
        }
        changed
    }
}

struct NameIndex {
    names: Vec<String>,
    map: HashMap<String, usize>,
}

impl NameIndex {
    fn new() -> Self {
        Self {
            names: Vec::new(),
            map: HashMap::new(),
        }
    }

    fn add(&mut self, name: &str) {
        if self.map.contains_key(name) {
            return;
        }
        let idx = self.names.len();
        self.names.push(name.to_string());
        self.map.insert(name.to_string(), idx);
    }

    fn idx(&self, name: &str) -> Option<usize> {
        self.map.get(name).copied()
    }
}

pub fn analyze(ast: &NormalizedAst, cfgs: &[CfgFunction]) -> Vec<TaintSummary> {
    let mut summaries = Vec::new();
    for cfg in cfgs {
        let Some(func) = ast.functions.get(cfg.id as usize) else {
            continue;
        };
        let summary = analyze_function(ast, cfg, func);
        summaries.push(summary);
    }
    summaries
}

pub fn propagate_function_taint(
    function_count: usize,
    summaries: &[TaintSummary],
    resolved: &ResolvedCallGraph,
) -> TaintPropagation {
    let mut tainted = vec![false; function_count];
    let mut queue = VecDeque::new();
    let mut source_functions = 0;

    for summary in summaries {
        let idx = summary.function_id as usize;
        if idx >= function_count {
            continue;
        }
        if summary.uses_source {
            if !tainted[idx] {
                tainted[idx] = true;
                queue.push_back(idx);
            }
            source_functions += 1;
        }
    }

    let mut callers = vec![Vec::new(); function_count];
    for edge in &resolved.edges {
        if let ResolvedTarget::Function(callee) = edge.target {
            let callee_idx = callee as usize;
            let caller_idx = edge.from as usize;
            if callee_idx < function_count && caller_idx < function_count {
                callers[callee_idx].push(caller_idx);
            }
        }
    }

    while let Some(callee_idx) = queue.pop_front() {
        for caller_idx in &callers[callee_idx] {
            if !tainted[*caller_idx] {
                tainted[*caller_idx] = true;
                queue.push_back(*caller_idx);
            }
        }
    }

    let tainted_functions = tainted.into_iter().filter(|value| *value).count();
    TaintPropagation {
        source_functions,
        tainted_functions,
    }
}

fn analyze_function(ast: &NormalizedAst, cfg: &CfgFunction, func: &Function) -> TaintSummary {
    let mut names = NameIndex::new();
    if let Some(body) = func.body {
        collect_names(ast, body, &mut names);
    }
    let contract_name = func
        .contract
        .and_then(|id| ast.contracts.get(id as usize))
        .map(|contract| contract.name.clone());
    if let Some(contract_id) = func.contract {
        for var in &ast.state_vars {
            if var.contract == contract_id {
                names.add(&var.name);
            }
        }
    }

    let mut tainted_calls = HashSet::new();
    let mut temp_taint: HashMap<u32, bool> = HashMap::new();
    if names.names.is_empty() || cfg.blocks.is_empty() {
        return TaintSummary {
            function_id: func.id,
            tainted_vars: Vec::new(),
            tainted_calls: Vec::new(),
            uses_source: false,
        };
    }

    let (preds, succs) = build_edges(cfg);
    let mut out_sets = vec![BitSet::new(names.names.len()); cfg.blocks.len()];
    let mut worklist: VecDeque<usize> = (0..cfg.blocks.len()).collect();
    let mut uses_source = false;

    while let Some(block_idx) = worklist.pop_front() {
        let mut in_set = BitSet::new(names.names.len());
        for pred in &preds[block_idx] {
            in_set.union_from(&out_sets[*pred]);
        }

        let mut out_set = in_set.clone();
        apply_block(
            &names,
            contract_name.as_deref(),
            &cfg.blocks[block_idx],
            &mut out_set,
            &mut temp_taint,
            &mut tainted_calls,
            &mut uses_source,
        );

        if out_set != out_sets[block_idx] {
            out_sets[block_idx] = out_set;
            for succ in &succs[block_idx] {
                worklist.push_back(*succ);
            }
        }
    }

    let mut final_set = BitSet::new(names.names.len());
    for out in &out_sets {
        final_set.union_from(out);
    }
    let mut tainted_vars = Vec::new();
    for (idx, name) in names.names.iter().enumerate() {
        if final_set.contains(idx) {
            tainted_vars.push(name.clone());
        }
    }

    let mut tainted_calls: Vec<u32> = tainted_calls.into_iter().collect();
    tainted_calls.sort_unstable();
    TaintSummary {
        function_id: func.id,
        tainted_vars,
        tainted_calls,
        uses_source,
    }
}

fn build_edges(cfg: &CfgFunction) -> (Vec<Vec<usize>>, Vec<Vec<usize>>) {
    let mut id_to_index = HashMap::new();
    for (idx, block) in cfg.blocks.iter().enumerate() {
        id_to_index.insert(block.id, idx);
    }

    let mut preds = vec![Vec::new(); cfg.blocks.len()];
    let mut succs = vec![Vec::new(); cfg.blocks.len()];
    for edge in &cfg.edges {
        let (Some(&from), Some(&to)) = (
            id_to_index.get(&edge.from),
            id_to_index.get(&edge.to),
        ) else {
            continue;
        };
        preds[to].push(from);
        succs[from].push(to);
    }
    (preds, succs)
}

fn collect_names(ast: &NormalizedAst, stmt_id: u32, names: &mut NameIndex) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else {
        return;
    };
    match &stmt.kind {
        StmtKind::Block(children) => {
            for child in children {
                collect_names(ast, *child, names);
            }
        }
        StmtKind::Expr(expr) => collect_expr_names(ast, *expr, names),
        StmtKind::Return(expr) => {
            if let Some(expr) = expr {
                collect_expr_names(ast, *expr, names);
            }
        }
        StmtKind::If {
            cond,
            then_id,
            else_id,
        } => {
            collect_expr_names(ast, *cond, names);
            collect_names(ast, *then_id, names);
            if let Some(else_id) = else_id {
                collect_names(ast, *else_id, names);
            }
        }
        StmtKind::While { cond, body } => {
            collect_expr_names(ast, *cond, names);
            collect_names(ast, *body, names);
        }
        StmtKind::DoWhile { body, cond } => {
            collect_names(ast, *body, names);
            collect_expr_names(ast, *cond, names);
        }
        StmtKind::For {
            init,
            cond,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_names(ast, *init, names);
            }
            if let Some(cond) = cond {
                collect_expr_names(ast, *cond, names);
            }
            if let Some(step) = step {
                collect_expr_names(ast, *step, names);
            }
            collect_names(ast, *body, names);
        }
        StmtKind::Emit(expr) => collect_expr_names(ast, *expr, names),
        StmtKind::Revert(expr) => {
            if let Some(expr) = expr {
                collect_expr_names(ast, *expr, names);
            }
        }
        StmtKind::VarDecl { names: vars, init } => {
            for name in vars {
                names.add(name);
            }
            if let Some(expr) = init {
                collect_expr_names(ast, *expr, names);
            }
        }
        StmtKind::Try { call, clauses } => {
            collect_expr_names(ast, *call, names);
            for clause in clauses {
                collect_names(ast, clause.body, names);
            }
        }
        StmtKind::InlineAsm { .. } => {}
        StmtKind::Break | StmtKind::Continue => {}
    }
}

fn collect_expr_names(ast: &NormalizedAst, expr_id: u32, names: &mut NameIndex) {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return;
    };
    match &expr.kind {
        ExprKind::Ident(name) => names.add(name),
        ExprKind::Member { base, .. } => collect_expr_names(ast, *base, names),
        ExprKind::Index { base, index } => {
            collect_expr_names(ast, *base, names);
            if let Some(index) = index {
                collect_expr_names(ast, *index, names);
            }
        }
        ExprKind::Call { callee, args } => {
            collect_expr_names(ast, *callee, names);
            for arg in args {
                collect_expr_names(ast, *arg, names);
            }
        }
        ExprKind::CallOptions { callee, options } => {
            collect_expr_names(ast, *callee, names);
            for option in options {
                match option {
                    CallOption::Value(expr)
                    | CallOption::Gas(expr)
                    | CallOption::Salt(expr) => collect_expr_names(ast, *expr, names),
                }
            }
        }
        ExprKind::Binary { lhs, rhs, .. } => {
            collect_expr_names(ast, *lhs, names);
            collect_expr_names(ast, *rhs, names);
        }
        ExprKind::Unary { expr, .. } => collect_expr_names(ast, *expr, names),
        ExprKind::Assign { lhs, rhs, .. } => {
            collect_expr_names(ast, *lhs, names);
            collect_expr_names(ast, *rhs, names);
        }
        ExprKind::Tuple(entries) => {
            for entry in entries {
                collect_expr_names(ast, *entry, names);
            }
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            collect_expr_names(ast, *cond, names);
            collect_expr_names(ast, *then_expr, names);
            collect_expr_names(ast, *else_expr, names);
        }
        ExprKind::Literal(_)
        | ExprKind::New { .. }
        | ExprKind::Unknown => {}
    }
}

fn apply_block(
    names: &NameIndex,
    contract_name: Option<&str>,
    block: &Block,
    state: &mut BitSet,
    temp_taint: &mut HashMap<u32, bool>,
    tainted_calls: &mut HashSet<u32>,
    uses_source: &mut bool,
) {
    temp_taint.clear();
    for (instr_index, instr) in block.instrs.iter().enumerate() {
        match instr {
            IrInstr::Declare { names: vars, init, .. } => {
                let tainted = init
                    .as_ref()
                    .map(|value| {
                        value_taint(value, names, contract_name, state, temp_taint, uses_source)
                    })
                    .unwrap_or(false);
                for name in vars {
                    if let Some(idx) = names.idx(name) {
                        if tainted {
                            state.set(idx);
                        } else {
                            state.clear(idx);
                        }
                    }
                }
            }
            IrInstr::Assign { dest, src, .. } => {
                let tainted = value_taint(src, names, contract_name, state, temp_taint, uses_source);
                set_var_taint(dest, tainted, names, state, temp_taint);
            }
            IrInstr::Store { dest, src, .. } => {
                let tainted = value_taint(src, names, contract_name, state, temp_taint, uses_source);
                set_place_taint(
                    dest,
                    tainted,
                    names,
                    contract_name,
                    state,
                    temp_taint,
                );
            }
            IrInstr::Load { dest, src, .. } => {
                let tainted = place_taint(src, names, contract_name, state, temp_taint, uses_source);
                set_var_taint(dest, tainted, names, state, temp_taint);
            }
            IrInstr::Binary { dest, lhs, rhs, .. } => {
                let mut tainted =
                    value_taint(lhs, names, contract_name, state, temp_taint, uses_source);
                if value_taint(rhs, names, contract_name, state, temp_taint, uses_source) {
                    tainted = true;
                }
                set_var_taint(dest, tainted, names, state, temp_taint);
            }
            IrInstr::Unary { dest, expr, .. } => {
                let tainted =
                    value_taint(expr, names, contract_name, state, temp_taint, uses_source);
                set_var_taint(dest, tainted, names, state, temp_taint);
            }
            IrInstr::Select {
                dest,
                cond,
                then_val,
                else_val,
                ..
            } => {
                let mut tainted =
                    value_taint(cond, names, contract_name, state, temp_taint, uses_source);
                if value_taint(then_val, names, contract_name, state, temp_taint, uses_source) {
                    tainted = true;
                }
                if value_taint(else_val, names, contract_name, state, temp_taint, uses_source) {
                    tainted = true;
                }
                set_var_taint(dest, tainted, names, state, temp_taint);
            }
            IrInstr::Call {
                dest,
                callee,
                args,
                options,
                ..
            } => {
                let mut tainted =
                    value_taint(callee, names, contract_name, state, temp_taint, uses_source);
                for arg in args {
                    if value_taint(arg, names, contract_name, state, temp_taint, uses_source) {
                        tainted = true;
                    }
                }
                for option in options {
                    if call_option_taint(
                        option,
                        names,
                        contract_name,
                        state,
                        temp_taint,
                        uses_source,
                    ) {
                        tainted = true;
                    }
                }
                for var in dest {
                    set_var_taint(var, tainted, names, state, temp_taint);
                }
                if tainted {
                    tainted_calls.insert(call_site_id(block.id, instr_index));
                }
            }
            IrInstr::Emit { expr, .. } | IrInstr::Eval { expr, .. } => {
                value_taint(expr, names, contract_name, state, temp_taint, uses_source);
            }
            IrInstr::Return { values, .. } => {
                for expr in values {
                    value_taint(expr, names, contract_name, state, temp_taint, uses_source);
                }
            }
            IrInstr::Control { kind, .. } => match kind {
                crate::ir::ControlKind::If { cond } => {
                    value_taint(cond, names, contract_name, state, temp_taint, uses_source);
                }
                crate::ir::ControlKind::Loop { cond } => {
                    if let Some(cond) = cond {
                        value_taint(cond, names, contract_name, state, temp_taint, uses_source);
                    }
                }
                crate::ir::ControlKind::Revert { value } => {
                    if let Some(value) = value {
                        value_taint(value, names, contract_name, state, temp_taint, uses_source);
                    }
                }
                _ => {}
            },
            IrInstr::Nop { .. } | IrInstr::InlineAsm { .. } => {}
        }
    }
}

fn call_site_id(block_id: u32, instr_index: usize) -> u32 {
    block_id
        .wrapping_mul(1315423911)
        .wrapping_add(instr_index as u32)
}

fn call_option_taint(
    option: &IrCallOption,
    names: &NameIndex,
    contract_name: Option<&str>,
    state: &mut BitSet,
    temp_taint: &mut HashMap<u32, bool>,
    uses_source: &mut bool,
) -> bool {
    match option {
        IrCallOption::Value(value)
        | IrCallOption::Gas(value)
        | IrCallOption::Salt(value) => {
            value_taint(value, names, contract_name, state, temp_taint, uses_source)
        }
    }
}

fn value_taint(
    value: &IrValue,
    names: &NameIndex,
    contract_name: Option<&str>,
    state: &mut BitSet,
    temp_taint: &mut HashMap<u32, bool>,
    uses_source: &mut bool,
) -> bool {
    let _ = contract_name;
    if is_taint_source_value(value) {
        *uses_source = true;
        return true;
    }
    match value {
        IrValue::Literal(_) | IrValue::Unknown => false,
        IrValue::Var(IrVar::Named(name)) => names.idx(name).map(|idx| state.contains(idx)).unwrap_or(false),
        IrValue::Var(IrVar::Temp(id)) => temp_taint.get(id).copied().unwrap_or(false),
    }
}

fn place_taint(
    place: &IrPlace,
    names: &NameIndex,
    contract_name: Option<&str>,
    state: &mut BitSet,
    temp_taint: &mut HashMap<u32, bool>,
    uses_source: &mut bool,
) -> bool {
    if is_taint_source_place(place) {
        *uses_source = true;
        return true;
    }
    if let Some(name) = assign_target_name(place, contract_name) {
        if let Some(idx) = names.idx(&name) {
            return state.contains(idx);
        }
    }
    match place {
        IrPlace::Var {
            var: IrVar::Temp(id),
            ..
        } => temp_taint.get(id).copied().unwrap_or(false),
        IrPlace::Var {
            var: IrVar::Named(name),
            ..
        } => names
            .idx(name)
            .map(|idx| state.contains(idx))
            .unwrap_or(false),
        IrPlace::Member { base, .. } => {
            value_taint(base, names, contract_name, state, temp_taint, uses_source)
        }
        IrPlace::Index { base, index, .. } => {
            let mut tainted =
                value_taint(base, names, contract_name, state, temp_taint, uses_source);
            if let Some(index) = index {
                if value_taint(index, names, contract_name, state, temp_taint, uses_source) {
                    tainted = true;
                }
            }
            tainted
        }
    }
}

fn set_var_taint(
    var: &IrVar,
    tainted: bool,
    names: &NameIndex,
    state: &mut BitSet,
    temp_taint: &mut HashMap<u32, bool>,
) {
    match var {
        IrVar::Named(name) => {
            if let Some(idx) = names.idx(name) {
                if tainted {
                    state.set(idx);
                } else {
                    state.clear(idx);
                }
            }
        }
        IrVar::Temp(id) => {
            if tainted {
                temp_taint.insert(*id, true);
            } else {
                temp_taint.remove(id);
            }
        }
    }
}

fn set_place_taint(
    place: &IrPlace,
    tainted: bool,
    names: &NameIndex,
    contract_name: Option<&str>,
    state: &mut BitSet,
    temp_taint: &mut HashMap<u32, bool>,
) {
    match place {
        IrPlace::Var { var, .. } => set_var_taint(var, tainted, names, state, temp_taint),
        _ => {
            if let Some(name) = assign_target_name(place, contract_name) {
                if let Some(idx) = names.idx(&name) {
                    if tainted {
                        state.set(idx);
                    } else {
                        state.clear(idx);
                    }
                }
            }
        }
    }
}

fn assign_target_name(place: &IrPlace, contract_name: Option<&str>) -> Option<String> {
    match place {
        IrPlace::Var {
            var: IrVar::Named(name),
            ..
        } => Some(name.clone()),
        IrPlace::Var {
            var: IrVar::Temp(_),
            ..
        } => None,
        IrPlace::Member {
            base, field, root, ..
        } => {
            if is_contract_receiver_value(base, contract_name) {
                Some(field.clone())
            } else {
                root.clone().or_else(|| var_name_from_value(base))
            }
        }
        IrPlace::Index { root, .. } => root.clone(),
    }
}

fn var_name_from_value(value: &IrValue) -> Option<String> {
    match value {
        IrValue::Var(IrVar::Named(name)) => Some(name.clone()),
        _ => None,
    }
}

fn is_contract_receiver_value(value: &IrValue, contract_name: Option<&str>) -> bool {
    match value {
        IrValue::Var(IrVar::Named(name)) => {
            if name == "this" || name == "super" {
                return true;
            }
            contract_name.map(|value| value == name).unwrap_or(false)
        }
        _ => false,
    }
}

fn is_taint_source_value(value: &IrValue) -> bool {
    if let IrValue::Var(IrVar::Named(name)) = value {
        let parts: Vec<&str> = name.split('.').collect();
        if parts.len() == 2 {
            return is_source_names(&[parts[0].to_string(), parts[1].to_string()]);
        }
    }
    false
}

fn is_taint_source_place(place: &IrPlace) -> bool {
    match place {
        IrPlace::Member { base, field, .. } => match base {
            IrValue::Var(IrVar::Named(name)) => is_source_names(&[name.clone(), field.clone()]),
            _ => false,
        },
        _ => false,
    }
}

fn is_source_names(names: &[String]) -> bool {
    if names.len() != 2 {
        return false;
    }
    let base = names[0].as_str();
    let field = names[1].as_str();
    matches!(
        (base, field),
        ("tx", "origin")
            | ("tx", "gasprice")
            | ("msg", "sender")
            | ("msg", "value")
            | ("msg", "data")
            | ("msg", "sig")
    )
}
