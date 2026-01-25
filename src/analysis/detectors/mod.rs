use crate::analysis::CallGraph;
use crate::norm::{ChainSegment, ExprKind, NormalizedAst, Span, StmtKind};

#[derive(Debug, Clone)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    pub message: String,
    pub span: Span,
    pub function: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    TxOrigin,
    Delegatecall,
    UncheckedCall,
    Selfdestruct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl FindingKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingKind::TxOrigin => "tx.origin",
            FindingKind::Delegatecall => "delegatecall",
            FindingKind::UncheckedCall => "unchecked-call",
            FindingKind::Selfdestruct => "selfdestruct",
        }
    }
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

pub fn run_detectors(ast: &NormalizedAst, call_graph: &CallGraph) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(detect_tx_origin(ast));
    findings.extend(detect_delegatecall(call_graph));
    findings.extend(detect_unchecked_low_level_calls(ast));
    findings.extend(detect_selfdestruct(call_graph));
    findings
}

fn detect_tx_origin(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    for func in &ast.functions {
        if let Some(body) = func.body {
            walk_stmt(ast, body, func.id, &mut findings);
        }
    }
    findings
}

fn walk_stmt(ast: &NormalizedAst, stmt_id: u32, function_id: u32, findings: &mut Vec<Finding>) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else {
        return;
    };

    match &stmt.kind {
        StmtKind::Block(stmts) => {
            for child in stmts {
                walk_stmt(ast, *child, function_id, findings);
            }
        }
        StmtKind::Expr(expr) => walk_expr(ast, *expr, function_id, findings),
        StmtKind::Return(expr) => {
            if let Some(expr) = expr {
                walk_expr(ast, *expr, function_id, findings);
            }
        }
        StmtKind::If {
            cond,
            then_id,
            else_id,
        } => {
            walk_expr(ast, *cond, function_id, findings);
            walk_stmt(ast, *then_id, function_id, findings);
            if let Some(else_id) = else_id {
                walk_stmt(ast, *else_id, function_id, findings);
            }
        }
        StmtKind::While { cond, body } => {
            walk_expr(ast, *cond, function_id, findings);
            walk_stmt(ast, *body, function_id, findings);
        }
        StmtKind::DoWhile { body, cond } => {
            walk_stmt(ast, *body, function_id, findings);
            walk_expr(ast, *cond, function_id, findings);
        }
        StmtKind::For {
            init,
            cond,
            step,
            body,
        } => {
            if let Some(init) = init {
                walk_stmt(ast, *init, function_id, findings);
            }
            if let Some(cond) = cond {
                walk_expr(ast, *cond, function_id, findings);
            }
            if let Some(step) = step {
                walk_expr(ast, *step, function_id, findings);
            }
            walk_stmt(ast, *body, function_id, findings);
        }
        StmtKind::Emit(expr) => walk_expr(ast, *expr, function_id, findings),
        StmtKind::Revert(expr) => {
            if let Some(expr) = expr {
                walk_expr(ast, *expr, function_id, findings);
            }
        }
        StmtKind::VarDecl { init, .. } => {
            if let Some(expr) = init {
                walk_expr(ast, *expr, function_id, findings);
            }
        }
        StmtKind::Try { call, clauses } => {
            walk_expr(ast, *call, function_id, findings);
            for clause in clauses {
                walk_stmt(ast, clause.body, function_id, findings);
            }
        }
        StmtKind::InlineAsm { .. } => {}
        StmtKind::Break | StmtKind::Continue => {}
    }
}

fn walk_expr(ast: &NormalizedAst, expr_id: u32, function_id: u32, findings: &mut Vec<Finding>) {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return;
    };

    if is_tx_origin(expr) {
        findings.push(Finding {
            kind: FindingKind::TxOrigin,
            severity: Severity::Medium,
            message: "use of tx.origin for authorization".to_string(),
            span: expr.span,
            function: Some(function_id),
        });
    }

    match &expr.kind {
        ExprKind::Call { callee, args } => {
            walk_expr(ast, *callee, function_id, findings);
            for arg in args {
                walk_expr(ast, *arg, function_id, findings);
            }
        }
        ExprKind::CallOptions { callee, options } => {
            walk_expr(ast, *callee, function_id, findings);
            for option in options {
                match option {
                    crate::norm::CallOption::Value(expr)
                    | crate::norm::CallOption::Gas(expr)
                    | crate::norm::CallOption::Salt(expr) => {
                        walk_expr(ast, *expr, function_id, findings);
                    }
                }
            }
        }
        ExprKind::Member { base, .. } => walk_expr(ast, *base, function_id, findings),
        ExprKind::Index { base, index } => {
            walk_expr(ast, *base, function_id, findings);
            if let Some(index) = index {
                walk_expr(ast, *index, function_id, findings);
            }
        }
        ExprKind::Binary { lhs, rhs, .. } => {
            walk_expr(ast, *lhs, function_id, findings);
            walk_expr(ast, *rhs, function_id, findings);
        }
        ExprKind::Unary { expr, .. } => walk_expr(ast, *expr, function_id, findings),
        ExprKind::Assign { lhs, rhs, .. } => {
            walk_expr(ast, *lhs, function_id, findings);
            walk_expr(ast, *rhs, function_id, findings);
        }
        ExprKind::Tuple(entries) => {
            for entry in entries {
                walk_expr(ast, *entry, function_id, findings);
            }
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            walk_expr(ast, *cond, function_id, findings);
            walk_expr(ast, *then_expr, function_id, findings);
            walk_expr(ast, *else_expr, function_id, findings);
        }
        ExprKind::Literal(_)
        | ExprKind::Ident(_)
        | ExprKind::New { .. }
        | ExprKind::Unknown => {}
    }
}

fn is_tx_origin(expr: &crate::norm::Expr) -> bool {
    let Some(chain) = expr.meta.chain.as_deref() else {
        return false;
    };
    if chain.len() != 2 {
        return false;
    }
    matches!(
        (&chain[0], &chain[1]),
        (ChainSegment::Ident(first), ChainSegment::Member(second))
            if first == "tx" && second == "origin"
    )
}

fn detect_delegatecall(call_graph: &CallGraph) -> Vec<Finding> {
    let mut findings = Vec::new();
    for site in &call_graph.sites {
        let Some(call) = site.call.as_ref() else {
            continue;
        };
        let name = match &call.target {
            crate::norm::CallTarget::Member { name, .. } => name.as_str(),
            _ => continue,
        };
        if name == "delegatecall" || name == "callcode" {
            findings.push(Finding {
                kind: FindingKind::Delegatecall,
                severity: Severity::High,
                message: format!("low-level call via {name}"),
                span: site.span,
                function: Some(site.function),
            });
        }
    }
    findings
}

fn detect_unchecked_low_level_calls(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    for func in &ast.functions {
        if let Some(body) = func.body {
            walk_stmt_for_unchecked(ast, body, func.id, &mut findings);
        }
    }
    findings
}

fn walk_stmt_for_unchecked(
    ast: &NormalizedAst,
    stmt_id: u32,
    function_id: u32,
    findings: &mut Vec<Finding>,
) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else {
        return;
    };

    match &stmt.kind {
        StmtKind::Block(stmts) => {
            for child in stmts {
                walk_stmt_for_unchecked(ast, *child, function_id, findings);
            }
        }
        StmtKind::Expr(expr_id) => {
            if let Some(name) = low_level_call_name(ast, *expr_id) {
                findings.push(Finding {
                    kind: FindingKind::UncheckedCall,
                    severity: Severity::Medium,
                    message: format!("unchecked low-level call via {name}"),
                    span: stmt.span,
                    function: Some(function_id),
                });
            }
        }
        StmtKind::If {
            then_id,
            else_id,
            ..
        } => {
            walk_stmt_for_unchecked(ast, *then_id, function_id, findings);
            if let Some(else_id) = else_id {
                walk_stmt_for_unchecked(ast, *else_id, function_id, findings);
            }
        }
        StmtKind::While { body, .. } => {
            walk_stmt_for_unchecked(ast, *body, function_id, findings);
        }
        StmtKind::DoWhile { body, .. } => {
            walk_stmt_for_unchecked(ast, *body, function_id, findings);
        }
        StmtKind::For { init, body, .. } => {
            if let Some(init) = init {
                walk_stmt_for_unchecked(ast, *init, function_id, findings);
            }
            walk_stmt_for_unchecked(ast, *body, function_id, findings);
        }
        StmtKind::Try { clauses, .. } => {
            for clause in clauses {
                walk_stmt_for_unchecked(ast, clause.body, function_id, findings);
            }
        }
        StmtKind::Emit(_)
        | StmtKind::Return(_)
        | StmtKind::Revert(_)
        | StmtKind::VarDecl { .. }
        | StmtKind::InlineAsm { .. }
        | StmtKind::Break
        | StmtKind::Continue => {}
    }
}

fn low_level_call_name(ast: &NormalizedAst, expr_id: u32) -> Option<String> {
    let expr = ast.expressions.get(expr_id as usize)?;
    let call = expr.meta.call.as_ref()?;
    let name = match &call.target {
        crate::norm::CallTarget::Member { name, .. } => name.as_str(),
        crate::norm::CallTarget::Direct { name } => name.as_str(),
        crate::norm::CallTarget::Unknown => return None,
    };

    match name {
        "call" | "delegatecall" | "callcode" | "staticcall" | "send" => {
            Some(name.to_string())
        }
        _ => None,
    }
}

fn detect_selfdestruct(call_graph: &CallGraph) -> Vec<Finding> {
    let mut findings = Vec::new();
    for site in &call_graph.sites {
        let Some(call) = site.call.as_ref() else {
            continue;
        };
        let name = match &call.target {
            crate::norm::CallTarget::Direct { name } => name.as_str(),
            _ => continue,
        };
        if name == "selfdestruct" || name == "suicide" {
            findings.push(Finding {
                kind: FindingKind::Selfdestruct,
                severity: Severity::High,
                message: format!("use of {name}"),
                span: site.span,
                function: Some(site.function),
            });
        }
    }
    findings
}
