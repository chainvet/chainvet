use std::collections::{HashMap, HashSet, VecDeque};

use crate::cfg::CfgFunction;
use crate::ir::{IrCallOption, IrInstr, IrPlace, IrValue, IrVar};
use crate::norm::{Function, NormalizedAst};

pub type DefId = u32;
pub type UseId = u32;

#[derive(Debug, Clone)]
pub struct SsaFunction {
    pub id: u32,
    pub blocks: Vec<SsaBlock>,
    pub defs: Vec<SsaDef>,
    pub uses: Vec<SsaUse>,
}

#[derive(Debug, Clone)]
pub struct SsaBlock {
    pub id: u32,
    pub preds: Vec<u32>,
    pub succs: Vec<u32>,
    pub phis: Vec<PhiNode>,
    pub instrs: Vec<SsaInstr>,
}

#[derive(Debug, Clone)]
pub struct SsaInstr {
    pub instr: IrInstr,
    pub def_ids: Vec<DefId>,
    pub use_ids: Vec<UseId>,
}

#[derive(Debug, Clone)]
pub struct PhiNode {
    pub var: String,
    pub version: u32,
    pub def_id: DefId,
    pub sources: Vec<Option<DefId>>,
}

#[derive(Debug, Clone)]
pub struct SsaDef {
    pub id: DefId,
    pub var: String,
    pub version: u32,
    pub block: u32,
    pub instr_index: Option<usize>,
    pub is_phi: bool,
    pub uses: Vec<UseId>,
}

#[derive(Debug, Clone)]
pub struct SsaUse {
    pub id: UseId,
    pub var: String,
    pub version: u32,
    pub block: u32,
    pub instr_index: Option<usize>,
    pub expr: Option<u32>,
    pub def: Option<DefId>,
}

pub fn build_ssa(ast: &NormalizedAst, cfgs: &[CfgFunction]) -> Vec<SsaFunction> {
    let mut out = Vec::new();
    for cfg in cfgs {
        let Some(func) = ast.functions.get(cfg.id as usize) else {
            continue;
        };
        out.push(build_function(ast, func, cfg));
    }
    out
}

fn build_function(ast: &NormalizedAst, func: &Function, cfg: &CfgFunction) -> SsaFunction {
    let block_count = cfg.blocks.len();
    let mut blocks = Vec::with_capacity(block_count);
    let (preds, succs) = build_block_edges(cfg);
    let contract_name = func
        .contract
        .and_then(|id| ast.contracts.get(id as usize))
        .map(|contract| contract.name.clone());

    for (idx, block) in cfg.blocks.iter().enumerate() {
        blocks.push(SsaBlock {
            id: block.id,
            preds: preds[idx].iter().map(|idx| cfg.blocks[*idx].id).collect(),
            succs: succs[idx].iter().map(|idx| cfg.blocks[*idx].id).collect(),
            phis: Vec::new(),
            instrs: block
                .instrs
                .iter()
                .cloned()
                .map(|instr| SsaInstr {
                    instr,
                    def_ids: Vec::new(),
                    use_ids: Vec::new(),
                })
                .collect(),
        });
    }

    let mut var_index = VarIndex::new();
    collect_vars(cfg, contract_name.as_deref(), &mut var_index);
    let def_sets = compute_def_sets(cfg, contract_name.as_deref(), &var_index);
    let reachable = compute_reachable(&succs);
    let dom = compute_dominators(&preds, &reachable);
    let idom = compute_idom(&dom, &reachable);
    let df = compute_dominance_frontier(&succs, &idom);
    insert_phi_nodes(&mut blocks, &def_sets, &df, &var_index);
    let mut defs = Vec::new();
    let mut uses = Vec::new();
    rename_variables(
        cfg,
        &mut blocks,
        contract_name.as_deref(),
        &var_index,
        &idom,
        &mut defs,
        &mut uses,
    );

    SsaFunction {
        id: func.id,
        blocks,
        defs,
        uses,
    }
}

fn build_block_edges(cfg: &CfgFunction) -> (Vec<Vec<usize>>, Vec<Vec<usize>>) {
    let mut id_to_index = HashMap::new();
    for (idx, block) in cfg.blocks.iter().enumerate() {
        id_to_index.insert(block.id, idx);
    }

    let mut preds = vec![Vec::new(); cfg.blocks.len()];
    let mut succs = vec![Vec::new(); cfg.blocks.len()];
    for edge in &cfg.edges {
        let (Some(&from), Some(&to)) = (id_to_index.get(&edge.from), id_to_index.get(&edge.to))
        else {
            continue;
        };
        preds[to].push(from);
        succs[from].push(to);
    }
    (preds, succs)
}

struct VarIndex {
    names: Vec<String>,
    map: HashMap<String, usize>,
}

impl VarIndex {
    fn new() -> Self {
        Self {
            names: Vec::new(),
            map: HashMap::new(),
        }
    }

    fn add(&mut self, name: &str) -> usize {
        if let Some(idx) = self.map.get(name) {
            return *idx;
        }
        let idx = self.names.len();
        self.names.push(name.to_string());
        self.map.insert(name.to_string(), idx);
        idx
    }

    fn get(&self, name: &str) -> Option<usize> {
        self.map.get(name).copied()
    }
}

fn collect_vars(cfg: &CfgFunction, contract_name: Option<&str>, vars: &mut VarIndex) {
    for block in &cfg.blocks {
        for instr in &block.instrs {
            match instr {
                IrInstr::Declare { names, init, .. } => {
                    for name in names {
                        vars.add(name);
                    }
                    if let Some(value) = init {
                        collect_value_names(value, vars);
                    }
                }
                IrInstr::Assign { dest, src, .. } => {
                    add_var_name(dest, vars);
                    collect_value_names(src, vars);
                }
                IrInstr::Store { dest, src, .. } => {
                    collect_place_names(dest, contract_name, vars);
                    collect_value_names(src, vars);
                }
                IrInstr::Load { dest, src, .. } => {
                    add_var_name(dest, vars);
                    collect_place_names(src, contract_name, vars);
                }
                IrInstr::Binary { dest, lhs, rhs, .. } => {
                    add_var_name(dest, vars);
                    collect_value_names(lhs, vars);
                    collect_value_names(rhs, vars);
                }
                IrInstr::Unary { dest, expr, .. } => {
                    add_var_name(dest, vars);
                    collect_value_names(expr, vars);
                }
                IrInstr::Call {
                    dest,
                    callee,
                    args,
                    options,
                    ..
                } => {
                    for var in dest {
                        add_var_name(var, vars);
                    }
                    collect_value_names(callee, vars);
                    for arg in args {
                        collect_value_names(arg, vars);
                    }
                    for option in options {
                        collect_call_option_names(option, vars);
                    }
                }
                IrInstr::Select {
                    dest,
                    cond,
                    then_val,
                    else_val,
                    ..
                } => {
                    add_var_name(dest, vars);
                    collect_value_names(cond, vars);
                    collect_value_names(then_val, vars);
                    collect_value_names(else_val, vars);
                }
                IrInstr::Emit { expr, .. } | IrInstr::Eval { expr, .. } => {
                    collect_value_names(expr, vars);
                }
                IrInstr::Return { values, .. } => {
                    for expr in values {
                        collect_value_names(expr, vars);
                    }
                }
                IrInstr::Control { kind, .. } => match kind {
                    crate::ir::ControlKind::If { cond } => {
                        collect_value_names(cond, vars);
                    }
                    crate::ir::ControlKind::Loop { cond } => {
                        if let Some(cond) = cond {
                            collect_value_names(cond, vars);
                        }
                    }
                    crate::ir::ControlKind::Revert { value } => {
                        if let Some(expr) = value {
                            collect_value_names(expr, vars);
                        }
                    }
                    _ => {}
                },
                IrInstr::Nop { .. } | IrInstr::InlineAsm { .. } => {}
            }
        }
    }
}

fn add_var_name(var: &IrVar, vars: &mut VarIndex) {
    if let IrVar::Named(name) = var {
        vars.add(name);
    }
}

fn collect_value_names(value: &IrValue, vars: &mut VarIndex) {
    if let IrValue::Var(IrVar::Named(name)) = value {
        vars.add(name);
    }
}

fn collect_place_names(place: &IrPlace, contract_name: Option<&str>, vars: &mut VarIndex) {
    match place {
        IrPlace::Var { var, .. } => add_var_name(var, vars),
        IrPlace::Member {
            base, field, root, ..
        } => {
            if is_contract_receiver_value(base, contract_name) {
                vars.add(field);
            } else if let Some(root) = root {
                vars.add(root);
            }
            collect_value_names(base, vars);
        }
        IrPlace::Index {
            base, index, root, ..
        } => {
            if let Some(root) = root {
                vars.add(root);
            }
            collect_value_names(base, vars);
            if let Some(index) = index {
                collect_value_names(index, vars);
            }
        }
    }
}

fn collect_call_option_names(option: &IrCallOption, vars: &mut VarIndex) {
    match option {
        IrCallOption::Value(value) | IrCallOption::Gas(value) | IrCallOption::Salt(value) => {
            collect_value_names(value, vars);
        }
    }
}

fn compute_def_sets(
    cfg: &CfgFunction,
    contract_name: Option<&str>,
    vars: &VarIndex,
) -> Vec<HashSet<usize>> {
    let mut def_sets = vec![HashSet::new(); cfg.blocks.len()];
    for (idx, block) in cfg.blocks.iter().enumerate() {
        for instr in &block.instrs {
            let mut defs = Vec::new();
            match instr {
                IrInstr::Declare { names, .. } => {
                    defs.extend(names.iter().cloned());
                }
                IrInstr::Assign { dest, .. } => {
                    if let IrVar::Named(name) = dest {
                        defs.push(name.clone());
                    }
                }
                IrInstr::Store { dest, .. } => {
                    defs.extend(defs_from_place(dest, contract_name));
                }
                IrInstr::Load { dest, .. }
                | IrInstr::Binary { dest, .. }
                | IrInstr::Unary { dest, .. }
                | IrInstr::Select { dest, .. } => {
                    if let IrVar::Named(name) = dest {
                        defs.push(name.clone());
                    }
                }
                IrInstr::Call { dest, .. } => {
                    for var in dest {
                        if let IrVar::Named(name) = var {
                            defs.push(name.clone());
                        }
                    }
                }
                IrInstr::Emit { .. }
                | IrInstr::Eval { .. }
                | IrInstr::Return { .. }
                | IrInstr::Control { .. }
                | IrInstr::Nop { .. }
                | IrInstr::InlineAsm { .. } => {}
            }

            for name in defs {
                if let Some(var_idx) = vars.get(&name) {
                    def_sets[idx].insert(var_idx);
                }
            }
        }
    }
    def_sets
}

fn compute_reachable(succs: &[Vec<usize>]) -> Vec<bool> {
    let n = succs.len();
    let mut reachable = vec![false; n];
    if n == 0 {
        return reachable;
    }
    let mut queue = VecDeque::new();
    reachable[0] = true;
    queue.push_back(0);
    while let Some(node) = queue.pop_front() {
        for succ in &succs[node] {
            if !reachable[*succ] {
                reachable[*succ] = true;
                queue.push_back(*succ);
            }
        }
    }
    reachable
}

fn compute_dominators(preds: &[Vec<usize>], reachable: &[bool]) -> Vec<HashSet<usize>> {
    let n = preds.len();
    let mut dom = vec![HashSet::new(); n];
    if n == 0 {
        return dom;
    }
    for idx in 0..n {
        if !reachable[idx] {
            dom[idx].insert(idx);
            continue;
        }
        if idx == 0 {
            dom[idx].insert(0);
        } else {
            for node in 0..n {
                if reachable[node] {
                    dom[idx].insert(node);
                }
            }
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for idx in 1..n {
            if !reachable[idx] {
                continue;
            }
            let reachable_preds: Vec<usize> = preds[idx]
                .iter()
                .copied()
                .filter(|pred| reachable[*pred])
                .collect();
            if reachable_preds.is_empty() {
                let mut next = HashSet::new();
                next.insert(idx);
                if next != dom[idx] {
                    dom[idx] = next;
                    changed = true;
                }
                continue;
            }
            let mut next = dom[reachable_preds[0]].clone();
            for pred in &reachable_preds[1..] {
                next = next
                    .intersection(&dom[*pred])
                    .copied()
                    .collect::<HashSet<_>>();
            }
            next.insert(idx);
            if next != dom[idx] {
                dom[idx] = next;
                changed = true;
            }
        }
    }
    dom
}

fn compute_idom(dom: &[HashSet<usize>], reachable: &[bool]) -> Vec<Option<usize>> {
    let n = dom.len();
    let mut idom = vec![None; n];
    if n == 0 {
        return idom;
    }
    idom[0] = None;
    for idx in 1..n {
        if !reachable[idx] {
            idom[idx] = None;
            continue;
        }
        let candidates = dom[idx]
            .iter()
            .copied()
            .filter(|value| *value != idx)
            .collect::<Vec<_>>();
        let mut chosen = None;
        'outer: for &cand in &candidates {
            for &other in &candidates {
                if other == cand {
                    continue;
                }
                if !dom[cand].contains(&other) {
                    continue 'outer;
                }
            }
            chosen = Some(cand);
            break;
        }
        idom[idx] = chosen;
    }
    idom
}

fn compute_dominance_frontier(succs: &[Vec<usize>], idom: &[Option<usize>]) -> Vec<HashSet<usize>> {
    let n = succs.len();
    let mut df = vec![HashSet::new(); n];
    for b in 0..n {
        for succ in &succs[b] {
            if idom[*succ] != Some(b) {
                df[b].insert(*succ);
            }
        }
    }
    let children = build_dom_tree(idom);
    let order = postorder(&children, 0, n);
    for &b in &order {
        for child in &children[b] {
            for w in df[*child].clone() {
                if idom[w] != Some(b) {
                    df[b].insert(w);
                }
            }
        }
    }
    df
}

fn build_dom_tree(idom: &[Option<usize>]) -> Vec<Vec<usize>> {
    let mut children = vec![Vec::new(); idom.len()];
    for (idx, parent) in idom.iter().enumerate() {
        if let Some(parent) = parent {
            children[*parent].push(idx);
        }
    }
    children
}

fn postorder(children: &[Vec<usize>], root: usize, total: usize) -> Vec<usize> {
    let mut order = Vec::new();
    let mut visited = vec![false; total];
    fn dfs(node: usize, children: &[Vec<usize>], visited: &mut [bool], order: &mut Vec<usize>) {
        visited[node] = true;
        for child in &children[node] {
            if !visited[*child] {
                dfs(*child, children, visited, order);
            }
        }
        order.push(node);
    }
    if root < total {
        dfs(root, children, &mut visited, &mut order);
    }
    order
}

fn insert_phi_nodes(
    blocks: &mut [SsaBlock],
    def_sets: &[HashSet<usize>],
    df: &[HashSet<usize>],
    vars: &VarIndex,
) {
    let mut phi_vars = vec![HashSet::new(); blocks.len()];
    for (var_idx, _name) in vars.names.iter().enumerate() {
        let mut work = VecDeque::new();
        for (block_idx, defs) in def_sets.iter().enumerate() {
            if defs.contains(&var_idx) {
                work.push_back(block_idx);
            }
        }
        let mut has_phi = HashSet::new();
        while let Some(block_idx) = work.pop_front() {
            for join in &df[block_idx] {
                if has_phi.contains(join) {
                    continue;
                }
                if phi_vars[*join].insert(var_idx) {
                    blocks[*join].phis.push(PhiNode {
                        var: vars.names[var_idx].clone(),
                        version: 0,
                        def_id: 0,
                        sources: vec![None; blocks[*join].preds.len()],
                    });
                }
                has_phi.insert(*join);
                if !def_sets[*join].contains(&var_idx) {
                    work.push_back(*join);
                }
            }
        }
    }
}

fn rename_variables(
    cfg: &CfgFunction,
    blocks: &mut [SsaBlock],
    contract_name: Option<&str>,
    vars: &VarIndex,
    idom: &[Option<usize>],
    defs: &mut Vec<SsaDef>,
    uses: &mut Vec<SsaUse>,
) {
    let children = build_dom_tree(idom);
    let mut stacks: Vec<Vec<DefId>> = vec![Vec::new(); vars.names.len()];
    let mut next_version = vec![0u32; vars.names.len()];
    let mut block_by_id = HashMap::new();
    for (idx, block) in blocks.iter().enumerate() {
        block_by_id.insert(block.id, idx);
    }
    let mut pred_index = Vec::new();
    for block in blocks.iter() {
        let mut map = HashMap::new();
        for (idx, pred) in block.preds.iter().enumerate() {
            map.insert(*pred, idx);
        }
        pred_index.push(map);
    }

    fn new_def(
        defs: &mut Vec<SsaDef>,
        stacks: &mut [Vec<DefId>],
        next_version: &mut [u32],
        var_idx: usize,
        block: u32,
        instr_index: Option<usize>,
        is_phi: bool,
    ) -> DefId {
        let version = next_version[var_idx];
        next_version[var_idx] += 1;
        let id = defs.len() as DefId;
        defs.push(SsaDef {
            id,
            var: String::new(),
            version,
            block,
            instr_index,
            is_phi,
            uses: Vec::new(),
        });
        stacks[var_idx].push(id);
        id
    }

    fn current_def(stacks: &[Vec<DefId>], defs: &[SsaDef], var_idx: usize) -> Option<(DefId, u32)> {
        let def_id = stacks[var_idx].last().copied()?;
        let version = defs.get(def_id as usize).map(|def| def.version)?;
        Some((def_id, version))
    }

    fn visit(
        node: usize,
        blocks: &mut [SsaBlock],
        contract_name: Option<&str>,
        vars: &VarIndex,
        children: &[Vec<usize>],
        stacks: &mut [Vec<DefId>],
        next_version: &mut [u32],
        defs: &mut Vec<SsaDef>,
        uses: &mut Vec<SsaUse>,
        block_by_id: &HashMap<u32, usize>,
        pred_index: &[HashMap<u32, usize>],
    ) {
        let block_id = blocks[node].id;
        let mut pushed = Vec::new();

        for phi in &mut blocks[node].phis {
            let var_idx = vars.get(&phi.var).unwrap_or(0);
            let def_id = new_def(defs, stacks, next_version, var_idx, block_id, None, true);
            defs[def_id as usize].var = phi.var.clone();
            phi.version = defs[def_id as usize].version;
            phi.def_id = def_id;
            pushed.push(var_idx);
        }

        for (instr_index, instr) in blocks[node].instrs.iter_mut().enumerate() {
            let (use_names, def_names) = analyze_instr(&instr.instr, contract_name, vars);
            let mut instr_uses = Vec::new();
            for (name, expr) in use_names {
                if let Some(var_idx) = vars.get(&name) {
                    if let Some((def_id, version)) = current_def(stacks, defs, var_idx) {
                        let use_id = uses.len() as UseId;
                        uses.push(SsaUse {
                            id: use_id,
                            var: name.clone(),
                            version,
                            block: block_id,
                            instr_index: Some(instr_index),
                            expr,
                            def: Some(def_id),
                        });
                        defs[def_id as usize].uses.push(use_id);
                        instr_uses.push(use_id);
                    } else {
                        let use_id = uses.len() as UseId;
                        uses.push(SsaUse {
                            id: use_id,
                            var: name.clone(),
                            version: 0,
                            block: block_id,
                            instr_index: Some(instr_index),
                            expr,
                            def: None,
                        });
                        instr_uses.push(use_id);
                    }
                }
            }
            instr.use_ids = instr_uses;

            let mut instr_defs = Vec::new();
            for name in def_names {
                let Some(var_idx) = vars.get(&name) else {
                    continue;
                };
                let def_id = new_def(
                    defs,
                    stacks,
                    next_version,
                    var_idx,
                    block_id,
                    Some(instr_index),
                    false,
                );
                defs[def_id as usize].var = name.clone();
                instr_defs.push(def_id);
                pushed.push(var_idx);
            }
            instr.def_ids = instr_defs;
        }

        for succ in blocks[node].succs.clone() {
            let Some(succ_idx) = block_by_id.get(&succ) else {
                continue;
            };
            let Some(pred_pos) = pred_index[*succ_idx].get(&block_id) else {
                continue;
            };
            for phi in &mut blocks[*succ_idx].phis {
                let Some(var_idx) = vars.get(&phi.var) else {
                    continue;
                };
                if let Some((def_id, _version)) = current_def(stacks, defs, var_idx)
                    && *pred_pos < phi.sources.len()
                {
                    phi.sources[*pred_pos] = Some(def_id);
                }
            }
        }

        for child in &children[node] {
            visit(
                *child,
                blocks,
                contract_name,
                vars,
                children,
                stacks,
                next_version,
                defs,
                uses,
                block_by_id,
                pred_index,
            );
        }

        for var_idx in pushed.into_iter().rev() {
            stacks[var_idx].pop();
        }
    }

    if cfg.blocks.is_empty() {
        return;
    }
    visit(
        0,
        blocks,
        contract_name,
        vars,
        &children,
        &mut stacks,
        &mut next_version,
        defs,
        uses,
        &block_by_id,
        &pred_index,
    );
}

fn analyze_instr(
    instr: &IrInstr,
    contract_name: Option<&str>,
    vars: &VarIndex,
) -> (Vec<(String, Option<u32>)>, Vec<String>) {
    let mut uses = Vec::new();
    let mut defs = Vec::new();
    match instr {
        IrInstr::Declare { names, init, .. } => {
            if let Some(value) = init {
                collect_uses_value(value, &mut uses);
            }
            defs.extend(names.iter().cloned());
        }
        IrInstr::Assign { dest, src, .. } => {
            collect_uses_value(src, &mut uses);
            if let IrVar::Named(name) = dest {
                defs.push(name.clone());
            }
        }
        IrInstr::Store { dest, src, .. } => {
            collect_place_base_uses(dest, contract_name, &mut uses);
            collect_uses_value(src, &mut uses);
            defs.extend(defs_from_place(dest, contract_name));
        }
        IrInstr::Load { dest, src, .. } => {
            collect_place_read_uses(src, contract_name, &mut uses);
            if let IrVar::Named(name) = dest {
                defs.push(name.clone());
            }
        }
        IrInstr::Binary { dest, lhs, rhs, .. } => {
            collect_uses_value(lhs, &mut uses);
            collect_uses_value(rhs, &mut uses);
            if let IrVar::Named(name) = dest {
                defs.push(name.clone());
            }
        }
        IrInstr::Unary { dest, expr, .. } => {
            collect_uses_value(expr, &mut uses);
            if let IrVar::Named(name) = dest {
                defs.push(name.clone());
            }
        }
        IrInstr::Call {
            dest,
            callee,
            args,
            options,
            ..
        } => {
            collect_uses_value(callee, &mut uses);
            for arg in args {
                collect_uses_value(arg, &mut uses);
            }
            for option in options {
                collect_call_option_uses(option, &mut uses);
            }
            for var in dest {
                if let IrVar::Named(name) = var {
                    defs.push(name.clone());
                }
            }
        }
        IrInstr::Select {
            dest,
            cond,
            then_val,
            else_val,
            ..
        } => {
            collect_uses_value(cond, &mut uses);
            collect_uses_value(then_val, &mut uses);
            collect_uses_value(else_val, &mut uses);
            if let IrVar::Named(name) = dest {
                defs.push(name.clone());
            }
        }
        IrInstr::Emit { expr, .. } | IrInstr::Eval { expr, .. } => {
            collect_uses_value(expr, &mut uses);
        }
        IrInstr::Return { values, .. } => {
            for value in values {
                collect_uses_value(value, &mut uses);
            }
        }
        IrInstr::Control { kind, .. } => match kind {
            crate::ir::ControlKind::If { cond } => {
                collect_uses_value(cond, &mut uses);
            }
            crate::ir::ControlKind::Loop { cond } => {
                if let Some(cond) = cond {
                    collect_uses_value(cond, &mut uses);
                }
            }
            crate::ir::ControlKind::Revert { value } => {
                if let Some(value) = value {
                    collect_uses_value(value, &mut uses);
                }
            }
            _ => {}
        },
        IrInstr::Nop { .. } | IrInstr::InlineAsm { .. } => {}
    }

    let mut filtered = Vec::new();
    for (name, expr) in uses {
        if vars.get(&name).is_some() {
            filtered.push((name, expr));
        }
    }
    (filtered, defs)
}

fn defs_from_place(place: &IrPlace, contract_name: Option<&str>) -> Vec<String> {
    let mut names = Vec::new();
    match place {
        IrPlace::Var {
            var: IrVar::Named(name),
            ..
        } => names.push(name.clone()),
        IrPlace::Var {
            var: IrVar::Temp(_),
            ..
        } => {}
        IrPlace::Member {
            base, field, root, ..
        } => {
            if is_contract_receiver_value(base, contract_name) {
                names.push(field.clone());
            } else if let Some(root) = root {
                names.push(root.clone());
            }
        }
        IrPlace::Index { root, .. } => {
            if let Some(root) = root {
                names.push(root.clone());
            }
        }
    }
    names
}

fn collect_uses_value(value: &IrValue, uses: &mut Vec<(String, Option<u32>)>) {
    if let IrValue::Var(IrVar::Named(name)) = value {
        uses.push((name.clone(), None));
    }
}

fn collect_place_base_uses(
    place: &IrPlace,
    contract_name: Option<&str>,
    uses: &mut Vec<(String, Option<u32>)>,
) {
    match place {
        IrPlace::Var { .. } => {}
        IrPlace::Member { base, .. } => {
            if !is_contract_receiver_value(base, contract_name) {
                collect_uses_value(base, uses);
            }
        }
        IrPlace::Index { base, index, .. } => {
            if !is_contract_receiver_value(base, contract_name) {
                collect_uses_value(base, uses);
            }
            if let Some(index) = index {
                collect_uses_value(index, uses);
            }
        }
    }
}

fn collect_place_read_uses(
    place: &IrPlace,
    contract_name: Option<&str>,
    uses: &mut Vec<(String, Option<u32>)>,
) {
    match place {
        IrPlace::Var {
            var: IrVar::Named(name),
            ..
        } => uses.push((name.clone(), None)),
        IrPlace::Var {
            var: IrVar::Temp(_),
            ..
        } => {}
        IrPlace::Member {
            base, field, root, ..
        } => {
            if is_contract_receiver_value(base, contract_name) {
                uses.push((field.clone(), None));
            } else if let Some(root) = root {
                uses.push((root.clone(), None));
            }
            collect_uses_value(base, uses);
        }
        IrPlace::Index {
            base, index, root, ..
        } => {
            if let Some(root) = root {
                uses.push((root.clone(), None));
            }
            collect_uses_value(base, uses);
            if let Some(index) = index {
                collect_uses_value(index, uses);
            }
        }
    }
}

fn collect_call_option_uses(option: &IrCallOption, uses: &mut Vec<(String, Option<u32>)>) {
    match option {
        IrCallOption::Value(value) | IrCallOption::Gas(value) | IrCallOption::Salt(value) => {
            collect_uses_value(value, uses)
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::norm::{
        Expr, ExprKind, ExprMeta, Function, FunctionKind, Literal, Mutability, NormalizedAst,
        SourceFile, Span, Stmt, StmtKind, Visibility,
    };
    use crate::{cfg, ir};

    #[test]
    fn ssa_phi_on_if_else() {
        let mut ast = new_ast();

        let cond = ident(&mut ast, "cond");
        let lit_then = literal(&mut ast, "1");
        let assign_then = assign(&mut ast, "x", lit_then);
        let lit_else = literal(&mut ast, "2");
        let assign_else = assign(&mut ast, "x", lit_else);

        let then_stmt = push_stmt(&mut ast, StmtKind::Expr(assign_then));
        let else_stmt = push_stmt(&mut ast, StmtKind::Expr(assign_else));
        let if_stmt = push_stmt(
            &mut ast,
            StmtKind::If {
                cond,
                then_id: then_stmt,
                else_id: Some(else_stmt),
            },
        );
        let ret_expr = ident(&mut ast, "x");
        let ret_stmt = push_stmt(&mut ast, StmtKind::Return(Some(ret_expr)));
        let body = push_stmt(&mut ast, StmtKind::Block(vec![if_stmt, ret_stmt]));
        push_function(&mut ast, "foo", body);

        let ir_module = ir::lower_module(&ast);
        let cfgs = cfg::build_from_ir(&ir_module);
        let ssa = build_ssa(&ast, &cfgs);
        assert_eq!(ssa.len(), 1);

        let ssa_fn = &ssa[0];
        let phi_count: usize = ssa_fn.blocks.iter().map(|block| block.phis.len()).sum();
        assert_eq!(phi_count, 1);
        let mut phi_vars = Vec::new();
        for block in &ssa_fn.blocks {
            for phi in &block.phis {
                phi_vars.push(phi.var.clone());
            }
        }
        assert!(phi_vars.iter().any(|name| name == "x"));
        assert_eq!(ssa_fn.defs.len(), 3);
        assert_eq!(ssa_fn.uses.len(), 2);
    }

    #[test]
    fn ssa_def_use_linear() {
        let mut ast = new_ast();

        let lit_x = literal(&mut ast, "1");
        let assign_x = assign(&mut ast, "x", lit_x);
        let x_use = ident(&mut ast, "x");
        let assign_y = assign(&mut ast, "y", x_use);
        let stmt_x = push_stmt(&mut ast, StmtKind::Expr(assign_x));
        let stmt_y = push_stmt(&mut ast, StmtKind::Expr(assign_y));
        let ret_expr = ident(&mut ast, "y");
        let ret_stmt = push_stmt(&mut ast, StmtKind::Return(Some(ret_expr)));
        let body = push_stmt(&mut ast, StmtKind::Block(vec![stmt_x, stmt_y, ret_stmt]));
        push_function(&mut ast, "bar", body);

        let ir_module = ir::lower_module(&ast);
        let cfgs = cfg::build_from_ir(&ir_module);
        let ssa = build_ssa(&ast, &cfgs);
        assert_eq!(ssa.len(), 1);

        let ssa_fn = &ssa[0];
        let phi_count: usize = ssa_fn.blocks.iter().map(|block| block.phis.len()).sum();
        assert_eq!(phi_count, 0);
        assert_eq!(ssa_fn.defs.len(), 2);
        assert_eq!(ssa_fn.uses.len(), 2);

        let x_use = ssa_fn
            .uses
            .iter()
            .find(|entry| entry.var == "x")
            .expect("missing x use");
        let x_def = x_use.def.expect("x use missing def");
        assert_eq!(ssa_fn.defs[x_def as usize].var, "x");

        let y_use = ssa_fn
            .uses
            .iter()
            .find(|entry| entry.var == "y")
            .expect("missing y use");
        let y_def = y_use.def.expect("y use missing def");
        assert_eq!(ssa_fn.defs[y_def as usize].var, "y");
    }

    fn new_ast() -> NormalizedAst {
        NormalizedAst::from_sources(vec![SourceFile {
            id: 0,
            path: "test.sol".to_string(),
            source: String::new(),
        }])
    }

    fn span() -> Span {
        Span {
            file: 0,
            start: 0,
            end: 0,
        }
    }

    fn push_expr(ast: &mut NormalizedAst, kind: ExprKind) -> u32 {
        let id = ast.expressions.len() as u32;
        ast.expressions.push(Expr {
            kind,
            span: span(),
            meta: ExprMeta::default(),
        });
        id
    }

    fn push_stmt(ast: &mut NormalizedAst, kind: StmtKind) -> u32 {
        let id = ast.statements.len() as u32;
        ast.statements.push(Stmt { kind, span: span() });
        id
    }

    fn push_function(ast: &mut NormalizedAst, name: &str, body: u32) -> u32 {
        let id = ast.functions.len() as u32;
        ast.functions.push(Function {
            id,
            contract: None,
            name: Some(name.to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: Some(body),
            span: span(),
        });
        id
    }

    fn ident(ast: &mut NormalizedAst, name: &str) -> u32 {
        push_expr(ast, ExprKind::Ident(name.to_string()))
    }

    fn literal(ast: &mut NormalizedAst, value: &str) -> u32 {
        push_expr(
            ast,
            ExprKind::Literal(Literal {
                kind: "number".to_string(),
                value: value.to_string(),
            }),
        )
    }

    fn assign(ast: &mut NormalizedAst, name: &str, rhs: u32) -> u32 {
        let lhs = ident(ast, name);
        push_expr(
            ast,
            ExprKind::Assign {
                op: "=".to_string(),
                lhs,
                rhs,
            },
        )
    }
}
