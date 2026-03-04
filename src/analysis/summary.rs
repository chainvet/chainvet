use std::collections::HashSet;

use crate::analysis::{ResolvedCallGraph, ResolvedTarget};
use crate::norm::{CallMeta, CallTarget, ExprKind, NormalizedAst, StmtKind};

#[derive(Debug, Clone)]
pub struct FunctionSummary {
    pub function_id: u32,
    pub storage_writes: usize,
    pub external_calls: usize,
    pub low_level_calls: usize,
    pub unresolved_calls: usize,
}

pub fn summarize(ast: &NormalizedAst, resolved: &ResolvedCallGraph) -> Vec<FunctionSummary> {
    let mut summaries = Vec::with_capacity(ast.functions.len());
    for func in &ast.functions {
        summaries.push(FunctionSummary {
            function_id: func.id,
            storage_writes: 0,
            external_calls: 0,
            low_level_calls: 0,
            unresolved_calls: 0,
        });
    }

    let mut state_vars: Vec<HashSet<String>> = vec![HashSet::new(); ast.contracts.len()];
    for var in &ast.state_vars {
        if let Some(entry) = state_vars.get_mut(var.contract as usize) {
            entry.insert(var.name.clone());
        }
    }

    for func in &ast.functions {
        let Some(summary) = summaries.get_mut(func.id as usize) else {
            continue;
        };
        let contract_state = func.contract.and_then(|id| state_vars.get(id as usize));
        let contract_name = func
            .contract
            .and_then(|id| ast.contracts.get(id as usize))
            .map(|contract| contract.name.clone());
        if let Some(body) = func.body {
            walk_stmt_for_storage(ast, body, contract_state, contract_name.as_deref(), summary);
        }
    }

    for edge in &resolved.edges {
        let Some(summary) = summaries.get_mut(edge.from as usize) else {
            continue;
        };
        match &edge.target {
            ResolvedTarget::External(_) => summary.external_calls += 1,
            ResolvedTarget::Builtin(_) => {}
            ResolvedTarget::Ambiguous(_) | ResolvedTarget::Unknown => summary.unresolved_calls += 1,
            ResolvedTarget::Function(_) => {}
        }
        if let Some(call) = edge.call.as_ref() {
            if is_low_level_call(call) {
                summary.low_level_calls += 1;
            }
        }
    }

    summaries
}

fn walk_stmt_for_storage(
    ast: &NormalizedAst,
    stmt_id: u32,
    state_vars: Option<&HashSet<String>>,
    contract_name: Option<&str>,
    summary: &mut FunctionSummary,
) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else {
        return;
    };
    match &stmt.kind {
        StmtKind::Block(children) => {
            for child in children {
                walk_stmt_for_storage(ast, *child, state_vars, contract_name, summary);
            }
        }
        StmtKind::Expr(expr) => {
            walk_expr_for_storage(ast, *expr, state_vars, contract_name, summary);
        }
        StmtKind::Return(expr) => {
            if let Some(expr) = expr {
                walk_expr_for_storage(ast, *expr, state_vars, contract_name, summary);
            }
        }
        StmtKind::If {
            cond,
            then_id,
            else_id,
        } => {
            walk_expr_for_storage(ast, *cond, state_vars, contract_name, summary);
            walk_stmt_for_storage(ast, *then_id, state_vars, contract_name, summary);
            if let Some(else_id) = else_id {
                walk_stmt_for_storage(ast, *else_id, state_vars, contract_name, summary);
            }
        }
        StmtKind::While { cond, body } => {
            walk_expr_for_storage(ast, *cond, state_vars, contract_name, summary);
            walk_stmt_for_storage(ast, *body, state_vars, contract_name, summary);
        }
        StmtKind::DoWhile { body, cond } => {
            walk_stmt_for_storage(ast, *body, state_vars, contract_name, summary);
            walk_expr_for_storage(ast, *cond, state_vars, contract_name, summary);
        }
        StmtKind::For {
            init,
            cond,
            step,
            body,
        } => {
            if let Some(init) = init {
                walk_stmt_for_storage(ast, *init, state_vars, contract_name, summary);
            }
            if let Some(cond) = cond {
                walk_expr_for_storage(ast, *cond, state_vars, contract_name, summary);
            }
            if let Some(step) = step {
                walk_expr_for_storage(ast, *step, state_vars, contract_name, summary);
            }
            walk_stmt_for_storage(ast, *body, state_vars, contract_name, summary);
        }
        StmtKind::Emit(expr) => {
            walk_expr_for_storage(ast, *expr, state_vars, contract_name, summary);
        }
        StmtKind::Revert(expr) => {
            if let Some(expr) = expr {
                walk_expr_for_storage(ast, *expr, state_vars, contract_name, summary);
            }
        }
        StmtKind::VarDecl { init, .. } => {
            if let Some(expr) = init {
                walk_expr_for_storage(ast, *expr, state_vars, contract_name, summary);
            }
        }
        StmtKind::Try { call, clauses } => {
            walk_expr_for_storage(ast, *call, state_vars, contract_name, summary);
            for clause in clauses {
                walk_stmt_for_storage(ast, clause.body, state_vars, contract_name, summary);
            }
        }
        StmtKind::InlineAsm { .. } => {}
        StmtKind::Break | StmtKind::Continue => {}
    }
}

fn walk_expr_for_storage(
    ast: &NormalizedAst,
    expr_id: u32,
    state_vars: Option<&HashSet<String>>,
    contract_name: Option<&str>,
    summary: &mut FunctionSummary,
) {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return;
    };
    match &expr.kind {
        ExprKind::Assign { lhs, rhs, .. } => {
            if is_storage_lhs(ast, *lhs, state_vars, contract_name) {
                summary.storage_writes += 1;
            }
            walk_expr_for_storage(ast, *lhs, state_vars, contract_name, summary);
            walk_expr_for_storage(ast, *rhs, state_vars, contract_name, summary);
        }
        ExprKind::Call { callee, args } => {
            walk_expr_for_storage(ast, *callee, state_vars, contract_name, summary);
            for arg in args {
                walk_expr_for_storage(ast, *arg, state_vars, contract_name, summary);
            }
        }
        ExprKind::CallOptions { callee, options } => {
            walk_expr_for_storage(ast, *callee, state_vars, contract_name, summary);
            for option in options {
                let expr_id = match option {
                    crate::norm::CallOption::Value(expr)
                    | crate::norm::CallOption::Gas(expr)
                    | crate::norm::CallOption::Salt(expr) => expr,
                };
                walk_expr_for_storage(ast, *expr_id, state_vars, contract_name, summary);
            }
        }
        ExprKind::Member { base, .. } => {
            walk_expr_for_storage(ast, *base, state_vars, contract_name, summary);
        }
        ExprKind::Index { base, index } => {
            walk_expr_for_storage(ast, *base, state_vars, contract_name, summary);
            if let Some(index) = index {
                walk_expr_for_storage(ast, *index, state_vars, contract_name, summary);
            }
        }
        ExprKind::Binary { lhs, rhs, .. } => {
            walk_expr_for_storage(ast, *lhs, state_vars, contract_name, summary);
            walk_expr_for_storage(ast, *rhs, state_vars, contract_name, summary);
        }
        ExprKind::Unary { expr, .. } => {
            walk_expr_for_storage(ast, *expr, state_vars, contract_name, summary);
        }
        ExprKind::Tuple(entries) => {
            for entry in entries {
                walk_expr_for_storage(ast, *entry, state_vars, contract_name, summary);
            }
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            walk_expr_for_storage(ast, *cond, state_vars, contract_name, summary);
            walk_expr_for_storage(ast, *then_expr, state_vars, contract_name, summary);
            walk_expr_for_storage(ast, *else_expr, state_vars, contract_name, summary);
        }
        ExprKind::Literal(_) | ExprKind::Ident(_) | ExprKind::New { .. } | ExprKind::Unknown => {}
    }
}

fn is_storage_lhs(
    ast: &NormalizedAst,
    expr_id: u32,
    state_vars: Option<&HashSet<String>>,
    contract_name: Option<&str>,
) -> bool {
    let Some(state_vars) = state_vars else {
        return false;
    };
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };
    match &expr.kind {
        ExprKind::Ident(name) => state_vars.contains(name),
        ExprKind::Member { base, field } => {
            if state_vars.contains(field) && is_this_or_contract(ast, *base, contract_name) {
                return true;
            }
            is_storage_lhs(ast, *base, Some(state_vars), contract_name)
        }
        ExprKind::Index { base, .. } => is_storage_lhs(ast, *base, Some(state_vars), contract_name),
        _ => false,
    }
}

fn is_this_or_contract(ast: &NormalizedAst, expr_id: u32, contract_name: Option<&str>) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };
    match &expr.kind {
        ExprKind::Ident(name) => {
            if name == "this" || name == "super" {
                return true;
            }
            contract_name.map(|value| value == name).unwrap_or(false)
        }
        _ => false,
    }
}

fn is_low_level_call(call: &CallMeta) -> bool {
    let name = match &call.target {
        CallTarget::Direct { name } => name.as_str(),
        CallTarget::Member { name, .. } => name.as_str(),
        CallTarget::Unknown => return false,
    };
    matches!(
        name,
        "call" | "delegatecall" | "callcode" | "staticcall" | "send" | "transfer"
    )
}
