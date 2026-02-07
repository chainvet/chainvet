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
    TimestampDependency,
    Shadowing,
    Reentrancy,
    TaintedCall,
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
            FindingKind::TimestampDependency => "timestamp-dependency",
            FindingKind::Shadowing => "shadowing",
            FindingKind::Reentrancy => "reentrancy",
            FindingKind::TaintedCall => "tainted-call",
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

use crate::analysis::taint::TaintSummary;

pub fn run_detectors(ast: &NormalizedAst, call_graph: &CallGraph, taint_summaries: &[TaintSummary]) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(detect_tx_origin(ast));
    findings.extend(detect_delegatecall(call_graph));
    findings.extend(detect_unchecked_low_level_calls(ast));
    findings.extend(detect_selfdestruct(call_graph));
    findings.extend(detect_timestamp_dependency(ast));
    findings.extend(detect_shadowing(ast));
    findings.extend(detect_reentrancy(ast));
    findings.extend(detect_taint(ast, taint_summaries));
    findings
}

fn detect_taint(ast: &NormalizedAst, summaries: &[TaintSummary]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for summary in summaries {
        for span in &summary.tainted_calls {
            findings.push(Finding {
                kind: FindingKind::TaintedCall,
                severity: Severity::High,
                message: "call with tainted arguments".to_string(),
                span: *span,
                function: Some(summary.function_id),
            });
        }
    }
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

    if is_tx_origin(ast, expr) {
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

fn is_tx_origin(ast: &NormalizedAst, expr: &crate::norm::Expr) -> bool {
    // Check chain
    if let Some(chain) = expr.meta.chain.as_deref() {
        if chain.len() == 2 {
            if let (ChainSegment::Ident(first), ChainSegment::Member(second)) = (&chain[0], &chain[1]) {
                if first == "tx" && second == "origin" {
                    return true;
                }
            }
        }
    }
    
    // Check Member access struct
    if let ExprKind::Member { base, field } = &expr.kind {
        if field == "origin" {
             if let Some(base_expr) = ast.expressions.get(*base as usize) {
                if let ExprKind::Ident(base_name) = &base_expr.kind {
                    if base_name == "tx" {
                        return true;
                    }
                }
            }
        }
    }
    
    false
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

fn detect_timestamp_dependency(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    for func in &ast.functions {
        if let Some(body) = func.body {
            check_timestamp_in_stmt(ast, body, func.id, &mut findings);
        }
    }
    findings
}

fn check_timestamp_in_stmt(
    ast: &NormalizedAst,
    stmt_id: u32,
    function_id: u32,
    findings: &mut Vec<Finding>,
) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else {
        return;
    };

    match &stmt.kind {
        StmtKind::If { cond, then_id, else_id } => {
            if contains_timestamp(ast, *cond) {
                findings.push(Finding {
                    kind: FindingKind::TimestampDependency,
                    severity: Severity::Low,
                    message: "use of block.timestamp or now in conditional".to_string(),
                    span: stmt.span,
                    function: Some(function_id),
                });
            }
            check_timestamp_in_stmt(ast, *then_id, function_id, findings);
            if let Some(else_id) = else_id {
                check_timestamp_in_stmt(ast, *else_id, function_id, findings);
            }
        }
        StmtKind::While { cond, body } => {
            if contains_timestamp(ast, *cond) {
                findings.push(Finding {
                    kind: FindingKind::TimestampDependency,
                    severity: Severity::Low,
                    message: "use of block.timestamp or now in loop condition".to_string(),
                    span: stmt.span,
                    function: Some(function_id),
                });
            }
            check_timestamp_in_stmt(ast, *body, function_id, findings);
        }
        StmtKind::Expr(expr_id) => {
            if contains_timestamp(ast, *expr_id) {
                findings.push(Finding {
                    kind: FindingKind::TimestampDependency,
                    severity: Severity::Low,
                    message: "use of block.timestamp or now in expression statement".to_string(),
                    span: stmt.span,
                    function: Some(function_id),
                });
            }
        }
        StmtKind::VarDecl { init: Some(init_id), .. } => {
             if contains_timestamp(ast, *init_id) {
                findings.push(Finding {
                    kind: FindingKind::TimestampDependency,
                    severity: Severity::Low,
                    message: "assignment of block.timestamp or now".to_string(),
                    span: stmt.span,
                    function: Some(function_id),
                });
            }
        }
        StmtKind::Block(stmts) => {
            for child in stmts {
                check_timestamp_in_stmt(ast, *child, function_id, findings);
            }
        }
        _ => {}
    }
}



fn detect_shadowing(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    
    for func in &ast.functions {
        if let Some(body) = func.body {
            let mut local_vars = std::collections::HashSet::new();
            
            // Add function parameters to scope
            for param_name in &func.params {
                local_vars.insert(param_name.clone());
            }
            
            // Check for shadowing in function body
            check_shadowing_in_stmt(ast, body, func.id, func.contract, &mut local_vars, &mut findings);
        }
    }
    
    findings
}

fn check_shadowing_in_stmt(
    ast: &NormalizedAst,
    stmt_id: u32,
    function_id: u32,
    contract_id: Option<u32>,
    local_vars: &mut std::collections::HashSet<String>,
    findings: &mut Vec<Finding>,
) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else {
        return;
    };

    match &stmt.kind {
        StmtKind::VarDecl { names, .. } => {
            for name in names {
                // Check if shadows local variable
                if local_vars.contains(name) {
                    findings.push(Finding {
                        kind: FindingKind::Shadowing,
                        severity: Severity::Medium,
                        message: format!("variable '{name}' shadows existing local variable"),
                        span: stmt.span,
                        function: Some(function_id),
                    });
                }
                
                // Check if shadows state variable
                if let Some(cid) = contract_id {
                    for state_var in &ast.state_vars {
                        if state_var.contract == cid && state_var.name == *name {
                            findings.push(Finding {
                                kind: FindingKind::Shadowing,
                                severity: Severity::Medium,
                                message: format!("variable '{name}' shadows state variable"),
                                span: stmt.span,
                                function: Some(function_id),
                            });
                        }
                    }
                }
                
                local_vars.insert(name.clone());
            }
        }
        StmtKind::Block(stmts) => {
            for child in stmts {
                check_shadowing_in_stmt(ast, *child, function_id, contract_id, local_vars, findings);
            }
        }
        StmtKind::If { then_id, else_id, .. } => {
            check_shadowing_in_stmt(ast, *then_id, function_id, contract_id, local_vars, findings);
            if let Some(else_id) = else_id {
                check_shadowing_in_stmt(ast, *else_id, function_id, contract_id, local_vars, findings);
            }
        }
        StmtKind::While { body, .. } | StmtKind::DoWhile { body, .. } => {
            check_shadowing_in_stmt(ast, *body, function_id, contract_id, local_vars, findings);
        }
        StmtKind::For { init, body, .. } => {
            if let Some(init) = init {
                check_shadowing_in_stmt(ast, *init, function_id, contract_id, local_vars, findings);
            }
            check_shadowing_in_stmt(ast, *body, function_id, contract_id, local_vars, findings);
        }
        _ => {}
    }
}

fn detect_reentrancy(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    
    for func in &ast.functions {
        if let Some(body) = func.body {
            check_reentrancy_in_stmt(ast, body, func.id, &mut findings);
        }
    }
    
    findings
}

fn check_reentrancy_in_stmt(
    ast: &NormalizedAst,
    stmt_id: u32,
    function_id: u32,
    findings: &mut Vec<Finding>,
) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else {
        return;
    };

    if let StmtKind::Block(stmts) = &stmt.kind {
        // Look for pattern: external call followed by state update
        for i in 0..stmts.len() {
            let stmt_id = stmts[i];
            let Some(current_stmt) = ast.statements.get(stmt_id as usize) else {
                continue;
            };
            
            // Check if this statement contains an external call
            if contains_external_call(ast, current_stmt) {
                // Look ahead for state updates within next 5 statements
                for j in (i + 1)..stmts.len().min(i + 6) {
                    let next_stmt_id = stmts[j];
                    let Some(next_stmt) = ast.statements.get(next_stmt_id as usize) else {
                        continue;
                    };
                    
                    if contains_state_update(ast, next_stmt) {
                        findings.push(Finding {
                            kind: FindingKind::Reentrancy,
                            severity: Severity::High,
                            message: "potential reentrancy: state update after external call".to_string(),
                            span: current_stmt.span,
                            function: Some(function_id),
                        });
                        break;
                    }
                }
            }
            
            // Recursively check nested blocks
            check_reentrancy_in_stmt(ast, stmt_id, function_id, findings);
        }
    } else {
        // Check other statement types that might contain blocks
        match &stmt.kind {
            StmtKind::If { then_id, else_id, .. } => {
                check_reentrancy_in_stmt(ast, *then_id, function_id, findings);
                if let Some(else_id) = else_id {
                    check_reentrancy_in_stmt(ast, *else_id, function_id, findings);
                }
            }
            StmtKind::While { body, .. } | StmtKind::DoWhile { body, .. } => {
                check_reentrancy_in_stmt(ast, *body, function_id, findings);
            }
            StmtKind::For { body, .. } => {
                check_reentrancy_in_stmt(ast, *body, function_id, findings);
            }
            _ => {}
        }
    }
}

fn contains_timestamp(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };

    // Check for "now" identifier
    if let ExprKind::Ident(name) = &expr.kind {
        if name == "now" {
            return true;
        }
    }

    // Check for block.timestamp via Chain
    if let Some(chain) = expr.meta.chain.as_deref() {
        if chain.len() == 2 {
            if let (ChainSegment::Ident(base), ChainSegment::Member(member)) = (&chain[0], &chain[1]) {
                if base == "block" && member == "timestamp" {
                    return true;
                }
            }
        }
    }
    
    // Check for block.timestamp via Member access
    if let ExprKind::Member { base, field } = &expr.kind {
        if field == "timestamp" {
            if let Some(base_expr) = ast.expressions.get(*base as usize) {
                if let ExprKind::Ident(base_name) = &base_expr.kind {
                    if base_name == "block" {
                        return true;
                    }
                }
            }
        }
    }

    // Recursively check sub-expressions
    match &expr.kind {
        ExprKind::Binary { lhs, rhs, .. } => {
            contains_timestamp(ast, *lhs) || contains_timestamp(ast, *rhs)
        }
        ExprKind::Unary { expr, .. } => contains_timestamp(ast, *expr),
        ExprKind::Member { base, .. } => contains_timestamp(ast, *base),
        ExprKind::Tuple(entries) => entries.iter().any(|e| contains_timestamp(ast, *e)),
        ExprKind::Call { callee, args } => {
            contains_timestamp(ast, *callee) || args.iter().any(|arg| contains_timestamp(ast, *arg))
        }
        ExprKind::CallOptions { callee, options } => {
            contains_timestamp(ast, *callee) || options.iter().any(|opt| match opt {
                crate::norm::CallOption::Value(e) | crate::norm::CallOption::Gas(e) | crate::norm::CallOption::Salt(e) => contains_timestamp(ast, *e),
            })
        }
        ExprKind::Assign { lhs, rhs, .. } => {
            contains_timestamp(ast, *lhs) || contains_timestamp(ast, *rhs)
        }
        ExprKind::Index { base, index } => {
            contains_timestamp(ast, *base) || index.map_or(false, |i| contains_timestamp(ast, i))
        }
        ExprKind::Conditional { cond, then_expr, else_expr } => {
            contains_timestamp(ast, *cond) || contains_timestamp(ast, *then_expr) || contains_timestamp(ast, *else_expr)
        }
        _ => false,
    }
}

fn contains_external_call(ast: &NormalizedAst, stmt: &crate::norm::Stmt) -> bool {
    match &stmt.kind {
        StmtKind::Expr(expr_id) => check_expr_for_call(ast, *expr_id),
        StmtKind::VarDecl { init: Some(expr_id), .. } => check_expr_for_call(ast, *expr_id),
        _ => false,
    }
}

fn check_expr_for_call(ast: &NormalizedAst, expr_id: u32) -> bool {
    if let Some(expr) = ast.expressions.get(expr_id as usize) {
        // Check for call with value option (e.g., .call{value: ...})
        if let ExprKind::CallOptions { options, .. } = &expr.kind {
            for opt in options {
                if matches!(opt, crate::norm::CallOption::Value(_)) {
                    return true;
                }
            }
        }
        
        // Check for low-level calls
        if let Some(call) = &expr.meta.call {
            if let crate::norm::CallTarget::Member { name, .. } = &call.target {
                if matches!(name.as_str(), "call" | "delegatecall" | "send") {
                    return true;
                }
            }
        }
    }
    false
}

fn contains_state_update(ast: &NormalizedAst, stmt: &crate::norm::Stmt) -> bool {
    match &stmt.kind {
        StmtKind::Expr(expr_id) => check_expr_for_state_update(ast, *expr_id),
        StmtKind::VarDecl { .. } => false,
        _ => false,
    }
}

fn check_expr_for_state_update(ast: &NormalizedAst, expr_id: u32) -> bool {
    if let Some(expr) = ast.expressions.get(expr_id as usize) {
        // Check for assignment expressions
        if matches!(&expr.kind, ExprKind::Assign { .. }) {
            return true;
        }
    }
    false
}
