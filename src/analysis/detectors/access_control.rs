//! Access Control detectors (AC-01 through AC-18)
//! 18 vulnerability detectors covering unchecked low-level calls,
//! arbitrary input issues, function permission problems, and more.

use crate::analysis::CallGraph;
use crate::analysis::taint::TaintSummary;
use crate::norm::{
    CallOption, CallTarget, ChainSegment, ExprKind, FunctionKind,
    NormalizedAst, Span, StmtKind, Visibility,
};

use super::{Finding, FindingKind, Severity};

// ── Constants ────────────────────────────────────────────────────────────────

/// Modifier names commonly associated with access control.
const AC_MODIFIERS: &[&str] = &[
    "onlyowner",
    "onlyadmin",
    "onlyrole",
    "onlyminter",
    "onlyoperator",
    "onlygovernance",
    "authorized",
    "auth",
    "whennotpaused",
    "initializer",
    "onlyproxy",
    "onlydelegatecall",
    "onlycontroller",
    "restricted",
    "onlyauthorized",
];

/// Parameter-name fragments that hint the value is an address.
const ADDR_PARAM_HINTS: &[&str] = &[
    "addr", "address", "to", "from", "sender", "recipient", "owner",
    "spender", "account", "beneficiary", "receiver", "target",
    "destination", "operator", "delegate",
];

// ── Entry point ──────────────────────────────────────────────────────────────

/// Run all 18 Access Control detectors and return their findings.
pub fn detect_all(
    ast: &NormalizedAst,
    call_graph: &CallGraph,
    _taint_summaries: &[TaintSummary],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(detect_arbitrary_transfer_from(ast));            // AC-01
    findings.extend(detect_arbitrary_calldata(ast));                  // AC-02
    findings.extend(detect_caller_not_checked(ast));                  // AC-03
    findings.extend(detect_contract_destructable(ast, call_graph));   // AC-04
    findings.extend(detect_dangerous_state_var_init(ast));            // AC-05
    findings.extend(detect_tx_origin(ast));                           // AC-06
    findings.extend(detect_default_visibility(ast));                  // AC-07
    findings.extend(detect_uninit_permission_check(ast));             // AC-08
    findings.extend(detect_permit_arbitrary_transfer_from(ast));      // AC-09
    findings.extend(detect_missing_sender_check_transfer_from(ast));  // AC-10
    findings.extend(detect_missing_input_validation(ast));            // AC-11
    findings.extend(detect_arbitrary_ether_send(ast));                // AC-12
    findings.extend(detect_unprotected_selfdestruct(ast, call_graph));// AC-13
    findings.extend(detect_unprotected_ether_withdrawal(ast));        // AC-14
    findings.extend(detect_unsafe_delegatecall(call_graph));          // AC-15
    findings.extend(detect_unused_return_value(ast));                 // AC-16
    findings.extend(detect_public_mint_burn(ast));                    // AC-17
    findings.extend(detect_arbitrary_storage_write(ast));             // AC-18

    findings
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helper utilities
// ═══════════════════════════════════════════════════════════════════════════════

/// Returns `true` if the function has a modifier whose name (case-insensitive)
/// matches one of the common access-control patterns.
fn has_access_control_modifier(func: &crate::norm::Function) -> bool {
    func.modifiers.iter().any(|m| {
        let lower = m.to_lowercase();
        AC_MODIFIERS.iter().any(|ac| lower.contains(ac))
    })
}

/// Returns `true` if the expression at `expr_id` is `msg.sender`.
fn is_msg_sender(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };
    // Chain metadata check
    if let Some(chain) = expr.meta.chain.as_deref() {
        if chain.len() == 2 {
            if let (ChainSegment::Ident(a), ChainSegment::Member(b)) = (&chain[0], &chain[1]) {
                if a == "msg" && b == "sender" {
                    return true;
                }
            }
        }
    }
    // Member expression check
    if let ExprKind::Member { base, field } = &expr.kind {
        if field == "sender" {
            if let Some(be) = ast.expressions.get(*base as usize) {
                if let ExprKind::Ident(n) = &be.kind {
                    if n == "msg" {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Returns `true` if the function body contains any reference to `msg.sender`.
fn body_contains_msg_sender(ast: &NormalizedAst, func: &crate::norm::Function) -> bool {
    let Some(body) = func.body else { return false };
    let mut found = false;
    for_each_expr_in_stmt(ast, body, &mut |eid, _| {
        if !found && is_msg_sender(ast, eid) {
            found = true;
        }
    });
    found
}

/// Returns `true` if the function body calls a method with the given name.
fn function_calls_method(ast: &NormalizedAst, func: &crate::norm::Function, method: &str) -> bool {
    let Some(body) = func.body else { return false };
    let mut found = false;
    for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
        if found { return; }
        if let Some(call) = &expr.meta.call {
            if call_target_name(call) == method {
                found = true;
            }
        }
    });
    found
}

/// Extract the simple name from a `CallMeta`.
fn call_target_name(call: &crate::norm::CallMeta) -> &str {
    match &call.target {
        CallTarget::Direct { name } => name.as_str(),
        CallTarget::Member { name, .. } => name.as_str(),
        CallTarget::Unknown => "",
    }
}

/// Get the source text for a given span.
fn get_source_at_span<'a>(ast: &'a NormalizedAst, span: &Span) -> Option<&'a str> {
    let file = ast.files.get(span.file as usize)?;
    let start = span.start as usize;
    let end = span.end as usize;
    if end <= file.source.len() && start <= end {
        Some(&file.source[start..end])
    } else {
        None
    }
}

/// Returns `true` if the parameter name looks like an address parameter.
fn is_address_param_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    ADDR_PARAM_HINTS.iter().any(|hint| lower.contains(hint))
}

/// Returns `true` if an expression tree references an identifier named `name`.
fn expr_references_ident(ast: &NormalizedAst, expr_id: u32, name: &str) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };
    match &expr.kind {
        ExprKind::Ident(n) => n == name,
        ExprKind::Binary { lhs, rhs, .. } => {
            expr_references_ident(ast, *lhs, name) || expr_references_ident(ast, *rhs, name)
        }
        ExprKind::Unary { expr, .. } => expr_references_ident(ast, *expr, name),
        ExprKind::Member { base, .. } => expr_references_ident(ast, *base, name),
        ExprKind::Call { callee, args } => {
            expr_references_ident(ast, *callee, name)
                || args.iter().any(|&a| expr_references_ident(ast, a, name))
        }
        ExprKind::Index { base, index } => {
            expr_references_ident(ast, *base, name)
                || index.map_or(false, |i| expr_references_ident(ast, i, name))
        }
        _ => false,
    }
}

/// Returns `true` when the function body contains a `require` / `assert` that
/// references the given parameter name (heuristic for zero-address validation).
fn has_validation_for_param(ast: &NormalizedAst, func: &crate::norm::Function, param: &str) -> bool {
    let Some(body) = func.body else { return false };
    let mut found = false;
    for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
        if found { return; }
        if let Some(call) = &expr.meta.call {
            let cn = call_target_name(call);
            if cn == "require" || cn == "assert" || cn == "revert" {
                if let ExprKind::Call { args, .. } = &expr.kind {
                    for &arg_id in args {
                        if expr_references_ident(ast, arg_id, param) {
                            found = true;
                            return;
                        }
                    }
                }
            }
        }
    });
    found
}

/// Returns `true` if the name looks like a mint or burn function.
fn is_mint_or_burn_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower == "mint" || lower == "burn"
        || lower.starts_with("mint") || lower.starts_with("burn")
        || lower.ends_with("mint") || lower.ends_with("burn")
        || lower.contains("_mint") || lower.contains("_burn")
}

// ── Generic AST walkers ──────────────────────────────────────────────────────

/// Walk every expression reachable from a statement tree.
fn for_each_expr_in_stmt(
    ast: &NormalizedAst,
    stmt_id: u32,
    cb: &mut impl FnMut(u32, &crate::norm::Expr),
) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else { return };

    match &stmt.kind {
        StmtKind::Block(stmts) => {
            for &s in stmts {
                for_each_expr_in_stmt(ast, s, cb);
            }
        }
        StmtKind::Expr(e) => for_each_expr(ast, *e, cb),
        StmtKind::Return(Some(e)) => for_each_expr(ast, *e, cb),
        StmtKind::If { cond, then_id, else_id } => {
            for_each_expr(ast, *cond, cb);
            for_each_expr_in_stmt(ast, *then_id, cb);
            if let Some(e) = else_id {
                for_each_expr_in_stmt(ast, *e, cb);
            }
        }
        StmtKind::While { cond, body } => {
            for_each_expr(ast, *cond, cb);
            for_each_expr_in_stmt(ast, *body, cb);
        }
        StmtKind::DoWhile { body, cond } => {
            for_each_expr_in_stmt(ast, *body, cb);
            for_each_expr(ast, *cond, cb);
        }
        StmtKind::For { init, cond, step, body } => {
            if let Some(s) = init { for_each_expr_in_stmt(ast, *s, cb); }
            if let Some(e) = cond { for_each_expr(ast, *e, cb); }
            if let Some(e) = step { for_each_expr(ast, *e, cb); }
            for_each_expr_in_stmt(ast, *body, cb);
        }
        StmtKind::Emit(e) => for_each_expr(ast, *e, cb),
        StmtKind::Revert(Some(e)) => for_each_expr(ast, *e, cb),
        StmtKind::VarDecl { init: Some(e), .. } => for_each_expr(ast, *e, cb),
        StmtKind::Try { call, clauses } => {
            for_each_expr(ast, *call, cb);
            for clause in clauses {
                for_each_expr_in_stmt(ast, clause.body, cb);
            }
        }
        _ => {}
    }
}

/// Walk every sub-expression under `expr_id`, calling `cb` for each.
fn for_each_expr(
    ast: &NormalizedAst,
    expr_id: u32,
    cb: &mut impl FnMut(u32, &crate::norm::Expr),
) {
    let Some(expr) = ast.expressions.get(expr_id as usize) else { return };
    cb(expr_id, expr);

    match &expr.kind {
        ExprKind::Call { callee, args } => {
            for_each_expr(ast, *callee, cb);
            for arg in args { for_each_expr(ast, *arg, cb); }
        }
        ExprKind::CallOptions { callee, options } => {
            for_each_expr(ast, *callee, cb);
            for opt in options {
                match opt {
                    CallOption::Value(e) | CallOption::Gas(e) | CallOption::Salt(e) => {
                        for_each_expr(ast, *e, cb);
                    }
                }
            }
        }
        ExprKind::Member { base, .. } => for_each_expr(ast, *base, cb),
        ExprKind::Index { base, index } => {
            for_each_expr(ast, *base, cb);
            if let Some(i) = index { for_each_expr(ast, *i, cb); }
        }
        ExprKind::Binary { lhs, rhs, .. } => {
            for_each_expr(ast, *lhs, cb);
            for_each_expr(ast, *rhs, cb);
        }
        ExprKind::Unary { expr, .. } => for_each_expr(ast, *expr, cb),
        ExprKind::Assign { lhs, rhs, .. } => {
            for_each_expr(ast, *lhs, cb);
            for_each_expr(ast, *rhs, cb);
        }
        ExprKind::Tuple(entries) => {
            for e in entries { for_each_expr(ast, *e, cb); }
        }
        ExprKind::Conditional { cond, then_expr, else_expr } => {
            for_each_expr(ast, *cond, cb);
            for_each_expr(ast, *then_expr, cb);
            for_each_expr(ast, *else_expr, cb);
        }
        ExprKind::Literal(_) | ExprKind::Ident(_) | ExprKind::New { .. } | ExprKind::Unknown => {}
    }
}

/// Walk every statement under `stmt_id`, calling `cb` for each.
fn for_each_stmt(
    ast: &NormalizedAst,
    stmt_id: u32,
    cb: &mut impl FnMut(u32, &crate::norm::Stmt),
) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else { return };
    cb(stmt_id, stmt);

    match &stmt.kind {
        StmtKind::Block(stmts) => {
            for &s in stmts { for_each_stmt(ast, s, cb); }
        }
        StmtKind::If { then_id, else_id, .. } => {
            for_each_stmt(ast, *then_id, cb);
            if let Some(e) = else_id { for_each_stmt(ast, *e, cb); }
        }
        StmtKind::While { body, .. } | StmtKind::DoWhile { body, .. } => {
            for_each_stmt(ast, *body, cb);
        }
        StmtKind::For { init, body, .. } => {
            if let Some(s) = init { for_each_stmt(ast, *s, cb); }
            for_each_stmt(ast, *body, cb);
        }
        StmtKind::Try { clauses, .. } => {
            for c in clauses { for_each_stmt(ast, c.body, cb); }
        }
        _ => {}
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Detectors AC-01 … AC-18
// ═══════════════════════════════════════════════════════════════════════════════

// ── AC-01  Arbitrary `from` in transferFrom() without msg.sender check ───────

fn detect_arbitrary_transfer_from(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    for func in &ast.functions {
        // If function already has an access-control modifier, skip
        if has_access_control_modifier(func) { continue; }
        // If function body contains msg.sender somewhere, skip
        let has_sender = body_contains_msg_sender(ast, func);
        if has_sender { continue; }

        let Some(body) = func.body else { continue };

        for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
            if let Some(call) = &expr.meta.call {
                if call_target_name(call) == "transferFrom" {
                    if let ExprKind::Call { args, .. } = &expr.kind {
                        if let Some(&from_arg) = args.first() {
                            if !is_msg_sender(ast, from_arg) {
                                findings.push(Finding {
                                    kind: FindingKind::ArbitraryTransferFrom,
                                    severity: Severity::High,
                                    message: "transferFrom() called with arbitrary `from` \
                                            without msg.sender check or access control modifier"
                                        .into(),
                                    span: expr.span,
                                    function: Some(func.id),
                                });
                            }
                        }
                    }
                }
            }
        });
    }
    findings
}

// ── AC-02  Call to Arbitrary Addresses with Unchecked Calldata ────────────────

fn detect_arbitrary_calldata(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    for func in &ast.functions {
        let Some(body) = func.body else { continue };
        let params: std::collections::HashSet<&str> =
            func.params.iter().map(|s| s.as_str()).collect();
        if params.is_empty() { continue; }

        for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
            if let Some(call) = &expr.meta.call {
                if let CallTarget::Member { name, receiver } = &call.target {
                    if matches!(name.as_str(), "call" | "delegatecall" | "staticcall") {
                        if receiver.iter().any(|r| params.contains(r.as_str())) {
                            findings.push(Finding {
                                kind: FindingKind::ArbitraryCalldata,
                                severity: Severity::High,
                                message: "low-level call to address from function parameter \
                                        with unchecked calldata"
                                    .into(),
                                span: expr.span,
                                function: Some(func.id),
                            });
                        }
                    }
                }
            }
        });
    }
    findings
}

// ── AC-03  Caller Not Checked (extcodesize bypass in constructor) ────────────

fn detect_caller_not_checked(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        for_each_stmt(ast, body, &mut |_sid, stmt| {
            if let StmtKind::InlineAsm { .. } = &stmt.kind {
                if let Some(source) = get_source_at_span(ast, &stmt.span) {
                    let lower = source.to_lowercase();
                    if lower.contains("extcodesize")
                        && (lower.contains("caller") || lower.contains("msg.sender"))
                    {
                        findings.push(Finding {
                            kind: FindingKind::CallerNotChecked,
                            severity: Severity::Medium,
                            message: "extcodesize check on caller can be bypassed when \
                                    called from a constructor"
                                .into(),
                            span: stmt.span,
                            function: Some(func.id),
                        });
                    }
                }
            }
        });
    }
    findings
}

// ── AC-04  Contract Could be Destructed ──────────────────────────────────────

fn detect_contract_destructable(ast: &NormalizedAst, call_graph: &CallGraph) -> Vec<Finding> {
    let mut findings = Vec::new();
    for site in &call_graph.sites {
        let Some(call) = site.call.as_ref() else { continue };
        let name = match &call.target {
            CallTarget::Direct { name } => name.as_str(),
            _ => continue,
        };
        if name != "selfdestruct" && name != "suicide" { continue; }

        // Only flag when the function HAS access control (AC-13 handles unprotected)
        if let Some(func) = ast.functions.get(site.function as usize) {
            if has_access_control_modifier(func) {
                findings.push(Finding {
                    kind: FindingKind::ContractDestructable,
                    severity: Severity::Medium,
                    message: format!(
                        "contract can be destroyed via {name} — even with access control \
                        this is a centralization risk"
                    ),
                    span: site.span,
                    function: Some(site.function),
                });
            }
        }
    }
    findings
}

// ── AC-05  Dangerous Immediate Initialization of State Variables ─────────────

fn detect_dangerous_state_var_init(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    for sv in &ast.state_vars {
        if sv.constant || sv.immutable { continue; }
        if let Some(source) = get_source_at_span(ast, &sv.span) {
            if let Some(eq_pos) = source.find('=') {
                let rhs = &source[eq_pos + 1..];
                let rhs_lower = rhs.to_lowercase();
                // Flag runtime-dependent values used in state-variable initializers
                if rhs_lower.contains("block.")
                    || rhs_lower.contains("msg.")
                    || rhs_lower.contains("tx.")
                    || rhs_lower.contains("now")
                    || rhs_lower.contains("gasleft")
                    || rhs_lower.contains("blockhash")
                {
                    findings.push(Finding {
                        kind: FindingKind::DangerousStateVarInit,
                        severity: Severity::Medium,
                        message: format!(
                            "state variable '{}' initialized with runtime-dependent value",
                            sv.name
                        ),
                        span: sv.span,
                        function: None,
                    });
                }
            }
        }
    }
    findings
}

// ── AC-06  Dangerous Usage of `tx.origin` ────────────────────────────────────

fn detect_tx_origin(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    for func in &ast.functions {
        if let Some(body) = func.body {
            walk_for_tx_origin(ast, body, func.id, &mut findings);
        }
    }
    findings
}

fn walk_for_tx_origin(
    ast: &NormalizedAst,
    stmt_id: u32,
    function_id: u32,
    findings: &mut Vec<Finding>,
) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else { return };

    match &stmt.kind {
        StmtKind::Block(stmts) => {
            for child in stmts {
                walk_for_tx_origin(ast, *child, function_id, findings);
            }
        }
        StmtKind::Expr(expr) => walk_expr_for_tx_origin(ast, *expr, function_id, findings),
        StmtKind::Return(expr) => {
            if let Some(expr) = expr {
                walk_expr_for_tx_origin(ast, *expr, function_id, findings);
            }
        }
        StmtKind::If { cond, then_id, else_id } => {
            walk_expr_for_tx_origin(ast, *cond, function_id, findings);
            walk_for_tx_origin(ast, *then_id, function_id, findings);
            if let Some(else_id) = else_id {
                walk_for_tx_origin(ast, *else_id, function_id, findings);
            }
        }
        StmtKind::While { cond, body } => {
            walk_expr_for_tx_origin(ast, *cond, function_id, findings);
            walk_for_tx_origin(ast, *body, function_id, findings);
        }
        StmtKind::DoWhile { body, cond } => {
            walk_for_tx_origin(ast, *body, function_id, findings);
            walk_expr_for_tx_origin(ast, *cond, function_id, findings);
        }
        StmtKind::For { init, cond, step, body } => {
            if let Some(init) = init { walk_for_tx_origin(ast, *init, function_id, findings); }
            if let Some(cond) = cond { walk_expr_for_tx_origin(ast, *cond, function_id, findings); }
            if let Some(step) = step { walk_expr_for_tx_origin(ast, *step, function_id, findings); }
            walk_for_tx_origin(ast, *body, function_id, findings);
        }
        StmtKind::Emit(expr) => walk_expr_for_tx_origin(ast, *expr, function_id, findings),
        StmtKind::Revert(expr) => {
            if let Some(expr) = expr { walk_expr_for_tx_origin(ast, *expr, function_id, findings); }
        }
        StmtKind::VarDecl { init, .. } => {
            if let Some(expr) = init { walk_expr_for_tx_origin(ast, *expr, function_id, findings); }
        }
        StmtKind::Try { call, clauses } => {
            walk_expr_for_tx_origin(ast, *call, function_id, findings);
            for clause in clauses {
                walk_for_tx_origin(ast, clause.body, function_id, findings);
            }
        }
        StmtKind::InlineAsm { .. } | StmtKind::Break | StmtKind::Continue => {}
    }
}

fn walk_expr_for_tx_origin(
    ast: &NormalizedAst,
    expr_id: u32,
    function_id: u32,
    findings: &mut Vec<Finding>,
) {
    let Some(expr) = ast.expressions.get(expr_id as usize) else { return };

    if is_tx_origin(ast, expr) {
        findings.push(Finding {
            kind: FindingKind::TxOrigin,
            severity: Severity::Medium,
            message: "use of tx.origin for authorization".into(),
            span: expr.span,
            function: Some(function_id),
        });
    }

    match &expr.kind {
        ExprKind::Call { callee, args } => {
            walk_expr_for_tx_origin(ast, *callee, function_id, findings);
            for arg in args { walk_expr_for_tx_origin(ast, *arg, function_id, findings); }
        }
        ExprKind::CallOptions { callee, options } => {
            walk_expr_for_tx_origin(ast, *callee, function_id, findings);
            for option in options {
                match option {
                    CallOption::Value(e) | CallOption::Gas(e) | CallOption::Salt(e) => {
                        walk_expr_for_tx_origin(ast, *e, function_id, findings);
                    }
                }
            }
        }
        ExprKind::Member { base, .. } => walk_expr_for_tx_origin(ast, *base, function_id, findings),
        ExprKind::Index { base, index } => {
            walk_expr_for_tx_origin(ast, *base, function_id, findings);
            if let Some(index) = index { walk_expr_for_tx_origin(ast, *index, function_id, findings); }
        }
        ExprKind::Binary { lhs, rhs, .. } => {
            walk_expr_for_tx_origin(ast, *lhs, function_id, findings);
            walk_expr_for_tx_origin(ast, *rhs, function_id, findings);
        }
        ExprKind::Unary { expr, .. } => walk_expr_for_tx_origin(ast, *expr, function_id, findings),
        ExprKind::Assign { lhs, rhs, .. } => {
            walk_expr_for_tx_origin(ast, *lhs, function_id, findings);
            walk_expr_for_tx_origin(ast, *rhs, function_id, findings);
        }
        ExprKind::Tuple(entries) => {
            for entry in entries { walk_expr_for_tx_origin(ast, *entry, function_id, findings); }
        }
        ExprKind::Conditional { cond, then_expr, else_expr } => {
            walk_expr_for_tx_origin(ast, *cond, function_id, findings);
            walk_expr_for_tx_origin(ast, *then_expr, function_id, findings);
            walk_expr_for_tx_origin(ast, *else_expr, function_id, findings);
        }
        ExprKind::Literal(_) | ExprKind::Ident(_) | ExprKind::New { .. } | ExprKind::Unknown => {}
    }
}

fn is_tx_origin(ast: &NormalizedAst, expr: &crate::norm::Expr) -> bool {
    if let Some(chain) = expr.meta.chain.as_deref() {
        if chain.len() == 2 {
            if let (ChainSegment::Ident(a), ChainSegment::Member(b)) = (&chain[0], &chain[1]) {
                if a == "tx" && b == "origin" {
                    return true;
                }
            }
        }
    }
    if let ExprKind::Member { base, field } = &expr.kind {
        if field == "origin" {
            if let Some(be) = ast.expressions.get(*base as usize) {
                if let ExprKind::Ident(n) = &be.kind {
                    if n == "tx" { return true; }
                }
            }
        }
    }
    false
}

// ── AC-07  Default Function Visibility ───────────────────────────────────────

fn detect_default_visibility(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    for func in &ast.functions {
        // Only regular functions – constructors / fallback / receive have special rules
        if !matches!(func.kind, FunctionKind::Function) { continue; }

        if func.visibility == Visibility::Unknown {
            findings.push(Finding {
                kind: FindingKind::DefaultVisibility,
                severity: Severity::Medium,
                message: format!(
                    "function '{}' has no explicit visibility — defaults to public",
                    func.name.as_deref().unwrap_or("<unnamed>")
                ),
                span: func.span,
                function: Some(func.id),
            });
        }
    }
    findings
}

// ── AC-08  Initializing Method without Permission Check ──────────────────────

fn detect_uninit_permission_check(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    for func in &ast.functions {
        let name = func.name.as_deref().unwrap_or("").to_lowercase();
        let is_initializer = name == "initialize"
            || name == "init"
            || name == "initialise"
            || name.starts_with("initialize_")
            || name.starts_with("init_");

        if !is_initializer { continue; }
        if has_access_control_modifier(func) { continue; }

        // Also skip if function checks msg.sender in body
        if body_contains_msg_sender(ast, func) { continue; }

        findings.push(Finding {
            kind: FindingKind::UninitializedPermissionCheck,
            severity: Severity::High,
            message: format!(
                "initialization function '{}' lacks access control modifier or msg.sender check",
                func.name.as_deref().unwrap_or("<unnamed>")
            ),
            span: func.span,
            function: Some(func.id),
        });
    }
    findings
}

// ── AC-09  Method permit() Used for Arbitrary `from` in transferFrom() ───────

fn detect_permit_arbitrary_transfer_from(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    for func in &ast.functions {
        // Only care about functions that call both permit() and transferFrom()
        if !function_calls_method(ast, func, "permit") { continue; }

        let Some(body) = func.body else { continue };

        for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
            if let Some(call) = &expr.meta.call {
                if call_target_name(call) == "transferFrom" {
                    if let ExprKind::Call { args, .. } = &expr.kind {
                        if let Some(&from_arg) = args.first() {
                            if !is_msg_sender(ast, from_arg) {
                                findings.push(Finding {
                                    kind: FindingKind::PermitArbitraryTransferFrom,
                                    severity: Severity::High,
                                    message: "permit() used with transferFrom() where `from` \
                                            is not msg.sender — if token lacks permit support, \
                                            fallback may silently succeed"
                                        .into(),
                                    span: expr.span,
                                    function: Some(func.id),
                                });
                            }
                        }
                    }
                }
            }
        });
    }
    findings
}

// ── AC-10  Missing `msg.sender` Check for transferFrom() ─────────────────────

fn detect_missing_sender_check_transfer_from(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
            if let Some(call) = &expr.meta.call {
                if call_target_name(call) == "transferFrom" {
                    if let ExprKind::Call { args, .. } = &expr.kind {
                        if let Some(&from_arg) = args.first() {
                            if !is_msg_sender(ast, from_arg) {
                                findings.push(Finding {
                                    kind: FindingKind::MissingSenderCheckTransferFrom,
                                    severity: Severity::High,
                                    message: "transferFrom() called without msg.sender as `from` \
                                            parameter — may allow unauthorized token transfer"
                                        .into(),
                                    span: expr.span,
                                    function: Some(func.id),
                                });
                            }
                        }
                    }
                }
            }
        });
    }
    findings
}

// ── AC-11  Missing Input Validation ──────────────────────────────────────────

fn detect_missing_input_validation(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    for func in &ast.functions {
        // Only check externally callable functions
        if !matches!(func.visibility, Visibility::Public | Visibility::External) {
            continue;
        }

        for param in &func.params {
            if is_address_param_name(param) {
                if !has_validation_for_param(ast, func, param) {
                    findings.push(Finding {
                        kind: FindingKind::MissingInputValidation,
                        severity: Severity::Medium,
                        message: format!(
                            "parameter '{}' in function '{}' may lack zero-address validation",
                            param,
                            func.name.as_deref().unwrap_or("<unnamed>")
                        ),
                        span: func.span,
                        function: Some(func.id),
                    });
                }
            }
        }
    }
    findings
}

// ── AC-12  Sending Ether to Arbitrary Destinations ───────────────────────────

fn detect_arbitrary_ether_send(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    for func in &ast.functions {
        let Some(body) = func.body else { continue };
        let params: std::collections::HashSet<&str> =
            func.params.iter().map(|s| s.as_str()).collect();
        if params.is_empty() { continue; }

        for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
            if let Some(call) = &expr.meta.call {
                if let CallTarget::Member { name, receiver } = &call.target {
                    let is_ether_send = match name.as_str() {
                        "transfer" | "send" => true,
                        "call" => call.options.iter().any(|o| matches!(o, CallOption::Value(_))),
                        _ => false,
                    };
                    if is_ether_send
                        && receiver.iter().any(|r| params.contains(r.as_str()))
                    {
                        findings.push(Finding {
                            kind: FindingKind::ArbitraryEtherSend,
                            severity: Severity::High,
                            message: "ether sent to address derived from function parameter \
                                    — destination should be validated"
                                .into(),
                            span: expr.span,
                            function: Some(func.id),
                        });
                    }
                }
            }
        });
    }
    findings
}

// ── AC-13  Unprotected Contract Destruction ──────────────────────────────────

fn detect_unprotected_selfdestruct(ast: &NormalizedAst, call_graph: &CallGraph) -> Vec<Finding> {
    let mut findings = Vec::new();
    for site in &call_graph.sites {
        let Some(call) = site.call.as_ref() else { continue };
        let name = match &call.target {
            CallTarget::Direct { name } => name.as_str(),
            _ => continue,
        };
        if name != "selfdestruct" && name != "suicide" { continue; }

        if let Some(func) = ast.functions.get(site.function as usize) {
            if !has_access_control_modifier(func) {
                findings.push(Finding {
                    kind: FindingKind::UnprotectedSelfdestruct,
                    severity: Severity::High,
                    message: format!(
                        "unprotected {name} — no access control modifier on containing function"
                    ),
                    span: site.span,
                    function: Some(site.function),
                });
            }
        }
    }
    findings
}

// ── AC-14  Unprotected Ether Withdrawal ──────────────────────────────────────

fn detect_unprotected_ether_withdrawal(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    for func in &ast.functions {
        if !matches!(func.kind, FunctionKind::Function) { continue; }
        if has_access_control_modifier(func) { continue; }
        if matches!(func.visibility, Visibility::Internal | Visibility::Private) { continue; }

        let Some(body) = func.body else { continue };
        let mut sends_ether = false;

        for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
            if sends_ether { return; }
            if let Some(call) = &expr.meta.call {
                if let CallTarget::Member { name, .. } = &call.target {
                    match name.as_str() {
                        "transfer" | "send" => { sends_ether = true; }
                        "call" => {
                            if call.options.iter().any(|o| matches!(o, CallOption::Value(_))) {
                                sends_ether = true;
                            }
                        }
                        _ => {}
                    }
                }
            }
        });

        if sends_ether {
            findings.push(Finding {
                kind: FindingKind::UnprotectedEtherWithdrawal,
                severity: Severity::High,
                message: format!(
                    "function '{}' can send ether without access control",
                    func.name.as_deref().unwrap_or("<unnamed>")
                ),
                span: func.span,
                function: Some(func.id),
            });
        }
    }
    findings
}

// ── AC-15  Unsafe Delegatecall ───────────────────────────────────────────────

fn detect_unsafe_delegatecall(call_graph: &CallGraph) -> Vec<Finding> {
    let mut findings = Vec::new();
    for site in &call_graph.sites {
        let Some(call) = site.call.as_ref() else { continue };
        let name = match &call.target {
            CallTarget::Member { name, .. } => name.as_str(),
            _ => continue,
        };
        if name == "delegatecall" || name == "callcode" {
            findings.push(Finding {
                kind: FindingKind::UnsafeDelegatecall,
                severity: Severity::High,
                message: format!("unsafe low-level {name} — executes code in caller's context"),
                span: site.span,
                function: Some(site.function),
            });
        }
    }
    findings
}

// ── AC-16  Unused Return Value ───────────────────────────────────────────────

fn detect_unused_return_value(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    for func in &ast.functions {
        if let Some(body) = func.body {
            walk_for_unchecked(ast, body, func.id, &mut findings);
        }
    }
    findings
}

fn walk_for_unchecked(
    ast: &NormalizedAst,
    stmt_id: u32,
    function_id: u32,
    findings: &mut Vec<Finding>,
) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else { return };

    match &stmt.kind {
        StmtKind::Block(stmts) => {
            for child in stmts {
                walk_for_unchecked(ast, *child, function_id, findings);
            }
        }
        StmtKind::Expr(expr_id) => {
            if let Some(name) = low_level_call_name(ast, *expr_id) {
                findings.push(Finding {
                    kind: FindingKind::UnusedReturnValue,
                    severity: Severity::Medium,
                    message: format!("return value of low-level {name} is not checked"),
                    span: stmt.span,
                    function: Some(function_id),
                });
            }
        }
        StmtKind::If { then_id, else_id, .. } => {
            walk_for_unchecked(ast, *then_id, function_id, findings);
            if let Some(else_id) = else_id {
                walk_for_unchecked(ast, *else_id, function_id, findings);
            }
        }
        StmtKind::While { body, .. } | StmtKind::DoWhile { body, .. } => {
            walk_for_unchecked(ast, *body, function_id, findings);
        }
        StmtKind::For { init, body, .. } => {
            if let Some(init) = init {
                walk_for_unchecked(ast, *init, function_id, findings);
            }
            walk_for_unchecked(ast, *body, function_id, findings);
        }
        StmtKind::Try { clauses, .. } => {
            for clause in clauses {
                walk_for_unchecked(ast, clause.body, function_id, findings);
            }
        }
        _ => {}
    }
}

fn low_level_call_name(ast: &NormalizedAst, expr_id: u32) -> Option<String> {
    let expr = ast.expressions.get(expr_id as usize)?;
    let call = expr.meta.call.as_ref()?;
    let name = match &call.target {
        CallTarget::Member { name, .. } => name.as_str(),
        CallTarget::Direct { name } => name.as_str(),
        CallTarget::Unknown => return None,
    };
    match name {
        "call" | "delegatecall" | "callcode" | "staticcall" | "send" => Some(name.to_string()),
        _ => None,
    }
}

// ── AC-17  Usage of public mint or burn ──────────────────────────────────────

fn detect_public_mint_burn(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    for func in &ast.functions {
        let name = func.name.as_deref().unwrap_or("");
        if !is_mint_or_burn_name(name) { continue; }

        // Only flag public / external functions without access control
        if !matches!(func.visibility, Visibility::Public | Visibility::External | Visibility::Unknown) {
            continue;
        }
        if has_access_control_modifier(func) { continue; }

        findings.push(Finding {
            kind: FindingKind::PublicMintBurn,
            severity: Severity::High,
            message: format!(
                "public function '{}' allows anyone to mint / burn tokens",
                name
            ),
            span: func.span,
            function: Some(func.id),
        });
    }
    findings
}

// ── AC-18  Write to Arbitrary Storage Location ───────────────────────────────

fn detect_arbitrary_storage_write(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();
    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        for_each_stmt(ast, body, &mut |_sid, stmt| {
            if let StmtKind::InlineAsm { .. } = &stmt.kind {
                if let Some(source) = get_source_at_span(ast, &stmt.span) {
                    let lower = source.to_lowercase();
                    if lower.contains("sstore") {
                        findings.push(Finding {
                            kind: FindingKind::ArbitraryStorageWrite,
                            severity: Severity::High,
                            message: "inline assembly uses sstore — may write to \
                                    arbitrary storage location"
                                .into(),
                            span: stmt.span,
                            function: Some(func.id),
                        });
                    }
                }
            }
        });
    }
    findings
}
