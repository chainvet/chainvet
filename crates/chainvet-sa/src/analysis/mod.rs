use std::collections::HashMap;

pub mod detectors;
pub mod summary;
pub mod taint;

use chainvet_core::norm::{CallMeta, CallTarget, ExprKind, NormalizedAst, Span, StmtKind};

#[derive(Debug, Default)]
pub struct AnalysisFacts {
    pub findings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CallGraph {
    pub sites: Vec<CallSite>,
}

#[derive(Debug, Clone)]
pub struct CallSite {
    pub function: u32,
    pub expr: u32,
    pub span: Span,
    pub call: Option<CallMeta>,
}

#[derive(Debug, Clone)]
pub struct ResolvedCallGraph {
    pub edges: Vec<CallEdge>,
    pub outgoing: HashMap<u32, Vec<usize>>,
}

#[derive(Debug, Clone)]
pub struct CallEdge {
    pub from: u32,
    pub site: u32,
    pub span: Span,
    pub call: Option<CallMeta>,
    pub target: ResolvedTarget,
}

#[derive(Debug, Clone)]
pub enum ResolvedTarget {
    Function(u32),
    Ambiguous(Vec<u32>),
    External(String),
    Builtin(String),
    Unknown,
}

pub fn build_call_graph(ast: &NormalizedAst) -> CallGraph {
    let mut sites = Vec::new();
    for func in &ast.functions {
        if let Some(body) = func.body {
            walk_stmt(ast, body, func.id, &mut sites);
        }
    }
    CallGraph { sites }
}

pub fn resolve_call_graph(ast: &NormalizedAst, graph: &CallGraph) -> ResolvedCallGraph {
    let index = CallIndex::new(ast);
    let mut edges = Vec::new();
    for site in &graph.sites {
        let caller_contract = ast
            .functions
            .get(site.function as usize)
            .and_then(|func| func.contract);
        let target = match site.call.as_ref().map(|call| &call.target) {
            Some(target) => resolve_target(target, caller_contract, &index),
            None => ResolvedTarget::Unknown,
        };

        edges.push(CallEdge {
            from: site.function,
            site: site.expr,
            span: site.span,
            call: site.call.clone(),
            target,
        });
    }
    let outgoing = build_outgoing_index(&edges);
    ResolvedCallGraph { edges, outgoing }
}

fn walk_stmt(ast: &NormalizedAst, stmt_id: u32, function_id: u32, sites: &mut Vec<CallSite>) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else {
        return;
    };

    match &stmt.kind {
        StmtKind::Block(stmts) => {
            for child in stmts {
                walk_stmt(ast, *child, function_id, sites);
            }
        }
        StmtKind::Expr(expr) => walk_expr(ast, *expr, function_id, sites),
        StmtKind::Return(expr) => {
            if let Some(expr) = expr {
                walk_expr(ast, *expr, function_id, sites);
            }
        }
        StmtKind::If {
            cond,
            then_id,
            else_id,
        } => {
            walk_expr(ast, *cond, function_id, sites);
            walk_stmt(ast, *then_id, function_id, sites);
            if let Some(else_id) = else_id {
                walk_stmt(ast, *else_id, function_id, sites);
            }
        }
        StmtKind::While { cond, body } => {
            walk_expr(ast, *cond, function_id, sites);
            walk_stmt(ast, *body, function_id, sites);
        }
        StmtKind::DoWhile { body, cond } => {
            walk_stmt(ast, *body, function_id, sites);
            walk_expr(ast, *cond, function_id, sites);
        }
        StmtKind::For {
            init,
            cond,
            step,
            body,
        } => {
            if let Some(init) = init {
                walk_stmt(ast, *init, function_id, sites);
            }
            if let Some(cond) = cond {
                walk_expr(ast, *cond, function_id, sites);
            }
            if let Some(step) = step {
                walk_expr(ast, *step, function_id, sites);
            }
            walk_stmt(ast, *body, function_id, sites);
        }
        StmtKind::Emit(expr) => walk_expr(ast, *expr, function_id, sites),
        StmtKind::Revert(expr) => {
            if let Some(expr) = expr {
                walk_expr(ast, *expr, function_id, sites);
            }
        }
        StmtKind::VarDecl { init, .. } => {
            if let Some(expr) = init {
                walk_expr(ast, *expr, function_id, sites);
            }
        }
        StmtKind::Try { call, clauses } => {
            walk_expr(ast, *call, function_id, sites);
            for clause in clauses {
                walk_stmt(ast, clause.body, function_id, sites);
            }
        }
        StmtKind::InlineAsm { .. } => {}
        StmtKind::Break | StmtKind::Continue => {}
    }
}

fn walk_expr(ast: &NormalizedAst, expr_id: u32, function_id: u32, sites: &mut Vec<CallSite>) {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return;
    };

    match &expr.kind {
        ExprKind::Call { callee, args } => {
            sites.push(CallSite {
                function: function_id,
                expr: expr_id,
                span: expr.span,
                call: expr.meta.call.clone(),
            });
            walk_expr(ast, *callee, function_id, sites);
            for arg in args {
                walk_expr(ast, *arg, function_id, sites);
            }
        }
        ExprKind::CallOptions { callee, options } => {
            walk_expr(ast, *callee, function_id, sites);
            for option in options {
                match option {
                    chainvet_core::norm::CallOption::Value(expr)
                    | chainvet_core::norm::CallOption::Gas(expr)
                    | chainvet_core::norm::CallOption::Salt(expr) => {
                        walk_expr(ast, *expr, function_id, sites);
                    }
                }
            }
        }
        ExprKind::Member { base, .. } => walk_expr(ast, *base, function_id, sites),
        ExprKind::Index { base, index } => {
            walk_expr(ast, *base, function_id, sites);
            if let Some(index) = index {
                walk_expr(ast, *index, function_id, sites);
            }
        }
        ExprKind::Binary { lhs, rhs, .. } => {
            walk_expr(ast, *lhs, function_id, sites);
            walk_expr(ast, *rhs, function_id, sites);
        }
        ExprKind::Unary { expr, .. } => walk_expr(ast, *expr, function_id, sites),
        ExprKind::Assign { lhs, rhs, .. } => {
            walk_expr(ast, *lhs, function_id, sites);
            walk_expr(ast, *rhs, function_id, sites);
        }
        ExprKind::Tuple(entries) => {
            for entry in entries {
                walk_expr(ast, *entry, function_id, sites);
            }
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            walk_expr(ast, *cond, function_id, sites);
            walk_expr(ast, *then_expr, function_id, sites);
            walk_expr(ast, *else_expr, function_id, sites);
        }
        ExprKind::Literal(_) | ExprKind::Ident(_) | ExprKind::New { .. } | ExprKind::Unknown => {}
    }
}

struct CallIndex {
    by_name: HashMap<String, Vec<u32>>,
    by_contract: HashMap<u32, HashMap<String, Vec<u32>>>,
    contract_by_name: HashMap<String, Vec<u32>>,
}

impl CallIndex {
    fn new(ast: &NormalizedAst) -> Self {
        let mut by_name: HashMap<String, Vec<u32>> = HashMap::new();
        let mut by_contract: HashMap<u32, HashMap<String, Vec<u32>>> = HashMap::new();
        for func in &ast.functions {
            let Some(name) = func.name.as_ref() else {
                continue;
            };
            by_name.entry(name.clone()).or_default().push(func.id);
            if let Some(contract) = func.contract {
                by_contract
                    .entry(contract)
                    .or_default()
                    .entry(name.clone())
                    .or_default()
                    .push(func.id);
            }
        }

        let mut contract_by_name: HashMap<String, Vec<u32>> = HashMap::new();
        for contract in &ast.contracts {
            contract_by_name
                .entry(contract.name.clone())
                .or_default()
                .push(contract.id);
        }

        Self {
            by_name,
            by_contract,
            contract_by_name,
        }
    }
}

fn resolve_target(
    target: &CallTarget,
    caller_contract: Option<u32>,
    index: &CallIndex,
) -> ResolvedTarget {
    match target {
        CallTarget::Direct { name } => resolve_direct(name, caller_contract, index),
        CallTarget::Member { receiver, name } => {
            resolve_member(receiver, name, caller_contract, index)
        }
        CallTarget::Unknown => ResolvedTarget::Unknown,
    }
}

fn resolve_direct(name: &str, caller_contract: Option<u32>, index: &CallIndex) -> ResolvedTarget {
    if let Some(contract) = caller_contract
        && let Some(map) = index.by_contract.get(&contract)
        && let Some(ids) = map.get(name)
    {
        return pack_ids(ids);
    }
    if let Some(ids) = index.by_name.get(name) {
        return pack_ids(ids);
    }
    if is_builtin_direct_call(name) {
        return ResolvedTarget::Builtin(name.to_string());
    }
    ResolvedTarget::Unknown
}

fn resolve_member(
    receiver: &[String],
    name: &str,
    caller_contract: Option<u32>,
    index: &CallIndex,
) -> ResolvedTarget {
    if receiver.is_empty() {
        return ResolvedTarget::Unknown;
    }
    if let Some(last) = receiver.last()
        && (last == "this" || last == "super")
    {
        return resolve_direct(name, caller_contract, index);
    }

    if receiver.len() == 1 {
        let recv = &receiver[0];
        if let Some(contract_ids) = index.contract_by_name.get(recv) {
            let mut candidates = Vec::new();
            for contract_id in contract_ids {
                if let Some(map) = index.by_contract.get(contract_id)
                    && let Some(ids) = map.get(name)
                {
                    candidates.extend(ids);
                }
            }
            if !candidates.is_empty() {
                return pack_ids(&candidates);
            }
        }
    }

    ResolvedTarget::External(format!("{}.{}", receiver.join("."), name))
}

fn pack_ids(ids: &[u32]) -> ResolvedTarget {
    match ids.len() {
        0 => ResolvedTarget::Unknown,
        1 => ResolvedTarget::Function(ids[0]),
        _ => ResolvedTarget::Ambiguous(ids.to_vec()),
    }
}

fn is_builtin_direct_call(name: &str) -> bool {
    matches!(
        name,
        "require"
            | "assert"
            | "revert"
            | "selfdestruct"
            | "suicide"
            | "keccak256"
            | "sha256"
            | "ripemd160"
            | "ecrecover"
            | "addmod"
            | "mulmod"
            | "blockhash"
            | "gasleft"
            | "payable"
    ) || is_primitive_type_name(name)
}

fn is_primitive_type_name(name: &str) -> bool {
    if matches!(name, "address" | "bool" | "string" | "bytes" | "byte") {
        return true;
    }

    if let Some(bits) = name.strip_prefix("uint") {
        return bits.is_empty() || parse_bits(bits);
    }
    if let Some(bits) = name.strip_prefix("int") {
        return bits.is_empty() || parse_bits(bits);
    }
    if let Some(width) = name.strip_prefix("bytes")
        && let Ok(value) = width.parse::<u16>()
    {
        return (1..=32).contains(&value);
    }
    false
}

fn parse_bits(bits: &str) -> bool {
    let Ok(value) = bits.parse::<u16>() else {
        return false;
    };
    (8..=256).contains(&value) && value % 8 == 0
}

fn build_outgoing_index(edges: &[CallEdge]) -> HashMap<u32, Vec<usize>> {
    let mut index: HashMap<u32, Vec<usize>> = HashMap::new();
    for (idx, edge) in edges.iter().enumerate() {
        index.entry(edge.from).or_default().push(idx);
    }
    index
}
