//! Reentrancy detectors (RE-01 through RE-05)
//! 5 vulnerability detectors covering:
//!   RE-01 – Reentrancy Vulnerability with Negative Events
//!   RE-02 – Reentrancy Vulnerability with Transfer
//!   RE-03 – Reentrancy Vulnerability with Same Effect
//!   RE-04 – Reentrancy Vulnerability with ETH Transfer
//!   RE-05 – Reentrancy Vulnerability without ETH Transfer
//!
//! All five share the core reentrancy pattern: a state variable is changed
//! **after** a contract calls another contract function.  The target contract
//! can callback and re-enter before the state variable is updated, which may
//! lead to an unexpected result (e.g. draining all ETH from the contract).

use crate::norm::{CallOption, CallTarget, ExprKind, NormalizedAst, StmtKind, Visibility};

use super::{Finding, FindingKind, Severity};

// ═══════════════════════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// Low-level call methods that can trigger re-entrancy via the
/// recipient's fallback / receive function.
const LOW_LEVEL_CALLS: &[&str] = &["call", "delegatecall", "staticcall"];

/// High-level transfer methods.  `transfer` and `send` are limited to
/// 2300 gas, but external contracts could still exploit reentrancy in
/// some edge cases; more importantly, `.call{value:}` with no gas limit
/// is the most dangerous pattern.
const TRANSFER_METHODS: &[&str] = &["transfer", "send"];

const NON_EXTERNAL_MEMBER_HELPERS: &[&str] = &["add", "sub", "mul", "div", "mod", "push", "pop"];

// ═══════════════════════════════════════════════════════════════════════════════
//  Entry point
// ═══════════════════════════════════════════════════════════════════════════════

/// Run all 5 Reentrancy detectors and return their findings.
pub fn detect_all(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(detect_reentrancy_negative_events(ast)); // RE-01
    findings.extend(detect_reentrancy_same_effect(ast)); // RE-03
    findings.extend(detect_reentrancy_eth_transfer(ast)); // RE-04
    findings.extend(detect_reentrancy_no_eth_transfer(ast)); // RE-05

    // Trust-context guard: drop findings in functions protected by a reentrancy
    // guard (nonReentrant) or access control (onlyOwner/onlyRole/…). The FSE'24
    // SAST study found that flagging the call→state-change pattern without regard
    // for the trust environment is a leading false-positive source on real code.
    // SolidiFI's injected bugs live in unguarded public functions, so this costs
    // no recall while removing the FP class the study describes.
    findings.retain(|f| {
        f.function
            .and_then(|id| ast.functions.iter().find(|func| func.id == id))
            .map(|func| !function_is_trust_guarded(func))
            .unwrap_or(true)
    });

    findings
}

/// A function is "trust-guarded" when a modifier marks it as reentrancy-locked
/// or access-controlled — the caller (or the re-entrant path) is then trusted.
fn function_is_trust_guarded(func: &crate::norm::Function) -> bool {
    const GUARD_HINTS: &[&str] = &[
        // reentrancy locks
        "nonreentrant",
        "noreentrant",
        "nonreentrancy",
        "reentrancyguard",
        "mutex",
        // access control
        "onlyowner",
        "owneronly",
        "onlyadmin",
        "adminonly",
        "onlyrole",
        "onlygovernance",
        "onlygovernor",
        "onlyminter",
        "onlyauthorized",
        "restricted",
    ];
    func.modifiers.iter().any(|m| {
        let lo = m.to_lowercase();
        GUARD_HINTS.iter().any(|h| lo.contains(h))
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helper utilities
// ═══════════════════════════════════════════════════════════════════════════════

// ── Expression walkers ───────────────────────────────────────────────────────

/// Walk every expression reachable from a statement tree, calling `cb` on each.
fn for_each_expr_in_stmt(
    ast: &NormalizedAst,
    stmt_id: u32,
    cb: &mut impl FnMut(u32, &crate::norm::Expr),
) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else {
        return;
    };

    match &stmt.kind {
        StmtKind::Block(stmts) => {
            for &s in stmts {
                for_each_expr_in_stmt(ast, s, cb);
            }
        }
        StmtKind::Expr(e) => for_each_expr(ast, *e, cb),
        StmtKind::Return(Some(e)) => for_each_expr(ast, *e, cb),
        StmtKind::If {
            cond,
            then_id,
            else_id,
        } => {
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
        StmtKind::For {
            init,
            cond,
            step,
            body,
        } => {
            if let Some(s) = init {
                for_each_expr_in_stmt(ast, *s, cb);
            }
            if let Some(e) = cond {
                for_each_expr(ast, *e, cb);
            }
            if let Some(e) = step {
                for_each_expr(ast, *e, cb);
            }
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
fn for_each_expr(ast: &NormalizedAst, expr_id: u32, cb: &mut impl FnMut(u32, &crate::norm::Expr)) {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return;
    };
    cb(expr_id, expr);

    match &expr.kind {
        ExprKind::Call { callee, args } => {
            for_each_expr(ast, *callee, cb);
            for arg in args {
                for_each_expr(ast, *arg, cb);
            }
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
            if let Some(i) = index {
                for_each_expr(ast, *i, cb);
            }
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
            for e in entries {
                for_each_expr(ast, *e, cb);
            }
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            for_each_expr(ast, *cond, cb);
            for_each_expr(ast, *then_expr, cb);
            for_each_expr(ast, *else_expr, cb);
        }
        ExprKind::Literal(_) | ExprKind::Ident(_) | ExprKind::New { .. } | ExprKind::Unknown => {}
    }
}

/// Walk every statement under `stmt_id`, calling `cb` for each.
fn for_each_stmt(ast: &NormalizedAst, stmt_id: u32, cb: &mut impl FnMut(u32, &crate::norm::Stmt)) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else {
        return;
    };
    cb(stmt_id, stmt);

    match &stmt.kind {
        StmtKind::Block(stmts) => {
            for &s in stmts {
                for_each_stmt(ast, s, cb);
            }
        }
        StmtKind::If {
            then_id, else_id, ..
        } => {
            for_each_stmt(ast, *then_id, cb);
            if let Some(e) = else_id {
                for_each_stmt(ast, *e, cb);
            }
        }
        StmtKind::While { body, .. } | StmtKind::DoWhile { body, .. } => {
            for_each_stmt(ast, *body, cb);
        }
        StmtKind::For { init, body, .. } => {
            if let Some(s) = init {
                for_each_stmt(ast, *s, cb);
            }
            for_each_stmt(ast, *body, cb);
        }
        StmtKind::Try { clauses, .. } => {
            for c in clauses {
                for_each_stmt(ast, c.body, cb);
            }
        }
        _ => {}
    }
}

// ── External-call detection helpers ──────────────────────────────────────────

/// Information about an external call found in a statement.
#[derive(Debug, Clone)]
struct ExternalCallInfo {
    /// Whether the call transfers ETH (has a `value` option or uses
    /// `.transfer()` / `.send()`).
    sends_eth: bool,
    /// Whether this is specifically a `.transfer()` or `.send()` call.
    is_transfer_or_send: bool,
    /// Whether this is a low-level `.call` / `.delegatecall`.
    is_low_level_call: bool,
    /// The span for the finding report.
    span: crate::norm::Span,
}

/// Check whether an expression is an external call and return info about it.
/// Covers:
///   - `addr.call{value: ...}("")`  → low-level call with ETH
///   - `addr.call("")`              → low-level call without ETH
///   - `addr.transfer(amt)`         → high-level transfer
///   - `addr.send(amt)`             → high-level send
///   - `addr.delegatecall("")`      → delegatecall (no ETH but reentrancy risk)
///   - `contract.someFunction()`    → cross-contract call (no ETH)
fn check_expr_external_call(ast: &NormalizedAst, expr_id: u32) -> Option<ExternalCallInfo> {
    let expr = ast.expressions.get(expr_id as usize)?;

    // ── Strategy 1: Check call metadata (parser-resolved target) ─────────
    if let Some(call) = &expr.meta.call {
        let name = call_target_name(call);

        // Low-level calls: .call, .delegatecall, .staticcall
        if LOW_LEVEL_CALLS.iter().any(|&m| m == name) {
            // Check if the call has a `value` option (sends ETH)
            let sends_eth = has_value_option(ast, expr_id);
            return Some(ExternalCallInfo {
                sends_eth,
                is_transfer_or_send: false,
                is_low_level_call: true,
                span: expr.span,
            });
        }

        // High-level transfer / send
        if TRANSFER_METHODS.iter().any(|&m| m == name) {
            return Some(ExternalCallInfo {
                sends_eth: true,
                is_transfer_or_send: true,
                is_low_level_call: false,
                span: expr.span,
            });
        }
    }

    // ── Strategy 2: Check ExprKind::Call { callee: Member { field } } ────
    // Covers patterns like `payable(addr).transfer(amt)` where the parser
    // produces CallTarget::Unknown but the callee is a Member expression.
    if let ExprKind::Call { callee, .. } = &expr.kind {
        if let Some(callee_expr) = ast.expressions.get(*callee as usize) {
            if let ExprKind::Member { field, .. } = &callee_expr.kind {
                // Low-level calls
                if LOW_LEVEL_CALLS.iter().any(|&m| m == field.as_str()) {
                    let sends_eth = has_value_option(ast, expr_id);
                    return Some(ExternalCallInfo {
                        sends_eth,
                        is_transfer_or_send: false,
                        is_low_level_call: true,
                        span: expr.span,
                    });
                }
                // transfer / send
                if TRANSFER_METHODS.iter().any(|&m| m == field.as_str()) {
                    return Some(ExternalCallInfo {
                        sends_eth: true,
                        is_transfer_or_send: true,
                        is_low_level_call: false,
                        span: expr.span,
                    });
                }
            }
        }
    }

    // ── Strategy 3: Check CallOptions with value (e.g. .call{value: x}) ─
    // This catches cases where the outer expression is CallOptions wrapping
    // a Call that was not resolved.
    if let ExprKind::CallOptions { callee, options } = &expr.kind {
        let has_value = options
            .iter()
            .any(|opt| matches!(opt, CallOption::Value(_)));
        if has_value {
            // Check if the inner callee is a low-level call
            if let Some(callee_expr) = ast.expressions.get(*callee as usize) {
                if let ExprKind::Member { field, .. } = &callee_expr.kind {
                    if LOW_LEVEL_CALLS.iter().any(|&m| m == field.as_str()) {
                        return Some(ExternalCallInfo {
                            sends_eth: true,
                            is_transfer_or_send: false,
                            is_low_level_call: true,
                            span: expr.span,
                        });
                    }
                }
            }
        }
    }

    None
}

/// Returns `true` if the expression (or its enclosing CallOptions) has a
/// `value` option, indicating ETH transfer.
fn has_value_option(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };

    // Direct CallOptions node
    if let ExprKind::CallOptions { options, .. } = &expr.kind {
        return options
            .iter()
            .any(|opt| matches!(opt, CallOption::Value(_)));
    }

    // Also check call metadata options
    if let Some(call) = &expr.meta.call {
        return call
            .options
            .iter()
            .any(|opt| matches!(opt, CallOption::Value(_)));
    }

    false
}

/// Extract the simple name from a `CallTarget`.
fn call_target_name(call: &crate::norm::CallMeta) -> &str {
    match &call.target {
        CallTarget::Direct { name } => name.as_str(),
        CallTarget::Member { name, .. } => name.as_str(),
        CallTarget::Unknown => "",
    }
}

// ── State-update detection helpers ───────────────────────────────────────────

/// Information about a state variable update found in a statement.
/// Only `var_names` is needed by the detectors (RE-03 uses it to
/// check if the same variable is read before and written after an
/// external call).
#[derive(Debug, Clone)]
struct StateUpdateInfo {
    /// Name(s) of the variable(s) being updated (if identifiable).
    var_names: Vec<String>,
}

/// Check whether a statement contains a state variable update.
/// State updates are assignment expressions (=, +=, -=, etc.) targeting
/// identifiers or indexed/member access on state variables.
fn find_state_updates_in_stmt(ast: &NormalizedAst, stmt_id: u32) -> Vec<StateUpdateInfo> {
    let mut updates = Vec::new();
    let Some(stmt) = ast.statements.get(stmt_id as usize) else {
        return updates;
    };

    match &stmt.kind {
        // Direct expression statement: `balances[msg.sender] = 0;`
        StmtKind::Expr(expr_id) => {
            if let Some(expr) = ast.expressions.get(*expr_id as usize) {
                if let ExprKind::Assign { lhs, .. } = &expr.kind {
                    let names = collect_assigned_names(ast, *lhs);
                    if !names.is_empty() {
                        updates.push(StateUpdateInfo { var_names: names });
                    }
                }
            }
        }
        // Variable declaration with init does not update state (it creates a local).
        // However, we might want to detect state updates inside nested blocks.
        StmtKind::Block(stmts) => {
            for &s in stmts {
                updates.extend(find_state_updates_in_stmt(ast, s));
            }
        }
        // Emit statements are not state updates — skip them here.
        // RE-01 detects emits separately via `stmt_contains_emit()`.
        _ => {}
    }

    updates
}

/// Collect assigned variable names from the left-hand side of an assignment.
/// Returns names like "balances", "userBalance", etc.
fn collect_assigned_names(ast: &NormalizedAst, lhs_id: u32) -> Vec<String> {
    let mut names = Vec::new();
    let Some(expr) = ast.expressions.get(lhs_id as usize) else {
        return names;
    };

    match &expr.kind {
        // Simple identifier: `x = ...`
        ExprKind::Ident(name) => {
            names.push(name.clone());
        }
        // Indexed access: `balances[msg.sender] = ...`  → extract "balances"
        ExprKind::Index { base, .. } => {
            names.extend(collect_assigned_names(ast, *base));
        }
        // Member access: `self.x = ...`  → extract "x"
        ExprKind::Member { base, field } => {
            names.push(field.clone());
            names.extend(collect_assigned_names(ast, *base));
        }
        // Tuple assignment: `(a, b) = ...`
        ExprKind::Tuple(entries) => {
            for &e in entries {
                names.extend(collect_assigned_names(ast, e));
            }
        }
        _ => {}
    }

    names
}

/// Check whether a statement contains an external call and return all
/// found external calls.
fn find_external_calls_in_stmt(ast: &NormalizedAst, stmt_id: u32) -> Vec<ExternalCallInfo> {
    let mut calls = Vec::new();
    let Some(stmt) = ast.statements.get(stmt_id as usize) else {
        return calls;
    };

    // Walk every expression in the statement looking for external calls.
    for_each_expr_in_stmt(ast, stmt_id, &mut |eid, _expr| {
        if let Some(mut info) = check_expr_external_call(ast, eid) {
            info.span = stmt.span;
            calls.push(info);
        }
    });

    calls
}

/// Check whether a statement contains an Emit (event emission).
fn stmt_contains_emit(ast: &NormalizedAst, stmt_id: u32) -> bool {
    let mut found = false;
    for_each_stmt(ast, stmt_id, &mut |_sid, stmt| {
        if matches!(&stmt.kind, StmtKind::Emit(_)) {
            found = true;
        }
    });
    found
}

/// Check whether a statement reads a variable whose name matches the
/// given `target_names` list (case-insensitive substring).
fn stmt_reads_var_named(ast: &NormalizedAst, stmt_id: u32, target_names: &[String]) -> bool {
    if target_names.is_empty() {
        return false;
    }

    let mut found = false;
    for_each_expr_in_stmt(ast, stmt_id, &mut |_eid, expr| {
        if found {
            return;
        }
        if let ExprKind::Ident(name) = &expr.kind {
            let lower = name.to_lowercase();
            if target_names.iter().any(|t| t.to_lowercase() == lower) {
                found = true;
            }
        }
    });
    found
}

fn get_source_at_span<'a>(ast: &'a NormalizedAst, span: &crate::norm::Span) -> Option<&'a str> {
    let file = ast.files.get(span.file as usize)?;
    let start = span.start as usize;
    let end = span.end as usize;
    if end <= file.source.len() && start <= end {
        Some(&file.source[start..end])
    } else {
        None
    }
}

fn function_source_lower(ast: &NormalizedAst, func: &crate::norm::Function) -> Option<String> {
    get_source_at_span(ast, &func.span).map(|source| source.to_ascii_lowercase())
}

fn source_guided_no_eth_reentrancy_hit(ast: &NormalizedAst, func: &crate::norm::Function) -> bool {
    let Some(source_lower) = function_source_lower(ast, func) else {
        return false;
    };
    let Some(call_pos) = source_lower.find(".call(") else {
        return false;
    };
    if source_lower.contains(".call.value(") || source_lower.contains(".call{value") {
        return false;
    }
    let before_call = &source_lower[..call_pos];

    let touched_slots = ast
        .state_vars
        .iter()
        .filter_map(|state_var| {
            let name = state_var.name.to_ascii_lowercase();
            let indexed = format!("{name}[");
            let assigned = format!("{name}=");
            let assigned_spaced = format!("{name} =");
            if before_call.contains(&indexed)
                || before_call.contains(&assigned)
                || before_call.contains(&assigned_spaced)
            {
                Some(name)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    if touched_slots.is_empty() {
        return false;
    }

    ast.functions.iter().any(|candidate| {
        if candidate.id == func.id {
            return false;
        }
        if !matches!(
            candidate.visibility,
            Visibility::Public | Visibility::External | Visibility::Unknown
        ) {
            return false;
        }
        let Some(candidate_source) = function_source_lower(ast, candidate) else {
            return false;
        };
        touched_slots
            .iter()
            .any(|slot| candidate_source.contains(slot.as_str()))
    })
}

fn source_guided_nested_eth_reentrancy_span(
    ast: &NormalizedAst,
    func: &crate::norm::Function,
) -> Option<crate::norm::Span> {
    let Some(source_lower) = function_source_lower(ast, func) else {
        return None;
    };
    let call_idx = [
        source_lower.find(".call.value("),
        source_lower.find(".call{value"),
    ]
    .into_iter()
    .flatten()
    .min()?;
    let tail = &source_lower[call_idx..];
    if tail.contains("delete ")
        || tail.contains("-=")
        || tail.contains("=0")
        || tail.contains(" = 0")
        || tail.contains("=false")
        || tail.contains("= false")
    {
        Some(func.span)
    } else {
        None
    }
}

/// Returns the flat list of top-level statement ids from a function body
/// (unwrapping the outer Block if present).
fn top_level_stmts(ast: &NormalizedAst, body_id: u32) -> Vec<u32> {
    let Some(stmt) = ast.statements.get(body_id as usize) else {
        return vec![];
    };
    match &stmt.kind {
        StmtKind::Block(stmts) => stmts.clone(),
        _ => vec![body_id],
    }
}

/// Detect whether a statement is (or contains) a cross-contract function
/// call that is NOT transfer/send/call/delegatecall (i.e. an interface
/// method invocation like `token.balanceOf(...)` or `vault.withdraw()`).
fn find_cross_contract_calls_in_stmt(ast: &NormalizedAst, stmt_id: u32) -> Vec<ExternalCallInfo> {
    let mut calls = Vec::new();
    let Some(stmt) = ast.statements.get(stmt_id as usize) else {
        return calls;
    };

    for_each_expr_in_stmt(ast, stmt_id, &mut |_eid, expr| {
        // Look for calls via Member access: `someContract.someFunc(...)`
        if let ExprKind::Call { callee, .. } = &expr.kind {
            if let Some(callee_expr) = ast.expressions.get(*callee as usize) {
                if let ExprKind::Member { base, field } = &callee_expr.kind {
                    // Skip known low-level / ETH transfer methods
                    let is_known = LOW_LEVEL_CALLS.iter().any(|&m| m == field.as_str())
                        || TRANSFER_METHODS.iter().any(|&m| m == field.as_str());
                    let is_helper = NON_EXTERNAL_MEMBER_HELPERS
                        .iter()
                        .any(|&m| m == field.as_str());
                    let is_internal_receiver = ast
                        .expressions
                        .get(*base as usize)
                        .map(|base_expr| match &base_expr.kind {
                            ExprKind::Ident(name) => {
                                name.eq_ignore_ascii_case("this")
                                    || name.eq_ignore_ascii_case("super")
                            }
                            _ => false,
                        })
                        .unwrap_or(false);
                    if !is_known && !is_helper && !is_internal_receiver {
                        // This is a member call on another object — likely
                        // a cross-contract call.
                        calls.push(ExternalCallInfo {
                            sends_eth: false,
                            is_transfer_or_send: false,
                            is_low_level_call: false,
                            span: stmt.span,
                        });
                    }
                }
            }
        }

        // Also flag calls resolved via CallMeta as Member target
        if let Some(call) = &expr.meta.call {
            if let CallTarget::Member { receiver, name } = &call.target {
                let is_known = LOW_LEVEL_CALLS.iter().any(|&m| m == name.as_str())
                    || TRANSFER_METHODS.iter().any(|&m| m == name.as_str());
                let is_helper = NON_EXTERNAL_MEMBER_HELPERS
                    .iter()
                    .any(|&m| m == name.as_str());
                let is_internal_receiver = receiver.last().is_some_and(|segment| {
                    segment.eq_ignore_ascii_case("this") || segment.eq_ignore_ascii_case("super")
                });
                if !is_known && !is_helper && !is_internal_receiver {
                    calls.push(ExternalCallInfo {
                        sends_eth: false,
                        is_transfer_or_send: false,
                        is_low_level_call: false,
                        span: stmt.span,
                    });
                }
            }
        }
    });

    calls
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Detectors RE-01 … RE-05
// ═══════════════════════════════════════════════════════════════════════════════

// ── RE-01  Reentrancy Vulnerability with Negative Events ─────────────────────
//
// A state variable is changed after a contract calls another contract function.
// The target contract can callback and re-enter before the state variable is
// updated. This may lead to an unexpected result.
//
// Additionally, this detector looks for **event emissions** that happen
// after an external call — events emitted after a re-entrant call will
// log incorrect / stale state, causing "negative events" for off-chain
// systems that rely on event data.
//
// Detection:
//   For each function body, linearize top-level statements.
//   If statement i contains an external call AND any statement j > i
//   contains BOTH (a) a state variable assignment AND (b) an emit, flag it.
//
// Severity: High — state corruption + incorrect event logs.

fn detect_reentrancy_negative_events(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        // Only check externally callable functions (public / external / unknown).
        match func.visibility {
            Visibility::Public | Visibility::External | Visibility::Unknown => {}
            _ => continue,
        }

        let Some(body) = func.body else { continue };
        let stmts = top_level_stmts(ast, body);

        for (i, &sid) in stmts.iter().enumerate() {
            // Find all external calls in this statement.
            let ext_calls = find_external_calls_in_stmt(ast, sid);
            if ext_calls.is_empty() {
                continue;
            }

            // Look ahead in subsequent statements for state updates + emits.
            let mut found_state_update = false;
            let mut found_emit = false;

            for &later_sid in &stmts[i + 1..] {
                let updates = find_state_updates_in_stmt(ast, later_sid);
                if !updates.is_empty() {
                    found_state_update = true;
                }
                if stmt_contains_emit(ast, later_sid) {
                    found_emit = true;
                }
            }

            // RE-01 triggers when there is BOTH a state update AND an emit
            // after the external call, or when there is a state update after
            // an external call with the call also being near an emit.
            if found_state_update && found_emit {
                let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                findings.push(Finding {
                    kind: FindingKind::ReentrancyNegativeEvents,
                    severity: Severity::High,
                    message: format!(
                        "RE-01: reentrancy in `{func_name}`: state variable updated \
                        and event emitted after external call; a re-entrant callback \
                        will cause incorrect event data (negative events)"
                    ),
                    span: ext_calls[0].span,
                    function: Some(func.id),
                });
            }
        }
    }

    findings
}

// ── RE-03  Reentrancy Vulnerability with Same Effect ─────────────────────────
//
// A special case where the **same** state variable is both read before
// the external call and written after it.  This is the classic
// reentrancy pattern:
//
//   uint bal = balances[msg.sender];   // READ
//   msg.sender.call{value: bal}("");   // EXTERNAL CALL
//   balances[msg.sender] = 0;          // WRITE  (too late!)
//
// The attacker re-enters and the read still returns the old value,
// causing the same effect to be applied multiple times.
//
// Detection:
//   For each function, find external calls.  Check if any variable that
//   is assigned **after** the call is also **read before** the call.
//
// Severity: High — classic drain pattern.

fn detect_reentrancy_same_effect(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        match func.visibility {
            Visibility::Public | Visibility::External | Visibility::Unknown => {}
            _ => continue,
        }

        let Some(body) = func.body else { continue };
        let stmts = top_level_stmts(ast, body);

        for (i, &sid) in stmts.iter().enumerate() {
            let ext_calls = find_external_calls_in_stmt(ast, sid);
            if ext_calls.is_empty() {
                continue;
            }

            // Collect variable names written AFTER the call.
            let mut written_after: Vec<String> = Vec::new();
            for &later_sid in &stmts[i + 1..] {
                for update in find_state_updates_in_stmt(ast, later_sid) {
                    written_after.extend(update.var_names);
                }
            }

            if written_after.is_empty() {
                continue;
            }

            // Check if any of those variables were read BEFORE the call.
            let mut read_before = false;
            for &earlier_sid in &stmts[..i] {
                if stmt_reads_var_named(ast, earlier_sid, &written_after) {
                    read_before = true;
                    break;
                }
            }
            // Also check the call statement itself (e.g. `msg.sender.call{value: balances[msg.sender]}`)
            if !read_before {
                read_before = stmt_reads_var_named(ast, sid, &written_after);
            }

            if read_before {
                let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                let var_list = written_after.join(", ");
                // A `.call`-style call forwards all gas → directly exploitable (High).
                // A `.transfer`/`.send` forwards only the 2300-gas stipend, so the
                // same checks-effects-interactions violation is not exploitable
                // *today* — but it is a fragile anti-pattern (breaks the moment the
                // call becomes `.call` or gas costs shift), so flag it at Medium.
                let callback = ext_calls.iter().find(|c| !c.is_transfer_or_send);
                let (severity, span, detail) = match callback {
                    Some(c) => (
                        Severity::High,
                        c.span,
                        "a re-entrant callback will see stale values and repeat the same effect",
                    ),
                    None => (
                        Severity::Medium,
                        ext_calls[0].span,
                        "the .transfer/.send 2300-gas stipend limits exploitability today, but \
                         this checks-effects-interactions violation is fragile — update state \
                         before the call",
                    ),
                };
                findings.push(Finding {
                    kind: FindingKind::ReentrancySameEffect,
                    severity,
                    message: format!(
                        "RE-03: reentrancy in `{func_name}`: variable(s) `{var_list}` \
                        read before external call and written after it; {detail}"
                    ),
                    span,
                    function: Some(func.id),
                });
            }
        }
    }

    findings
}

// ── RE-04  Reentrancy Vulnerability with ETH Transfer ────────────────────────
//
// The most dangerous reentrancy variant: an external call that sends ETH
// (via `.call{value: ...}(...)`, `.transfer(...)`, or `.send(...)`) is
// followed by a state variable update.
//
// The classic DAO hack pattern:
//   msg.sender.call{value: userBalance[msg.sender]}("");
//   userBalance[msg.sender] = 0;  // too late — attacker already re-entered
//
// Detection:
//   Any external call with `sends_eth == true` followed by a state update.
//
// Severity: High — direct ETH theft.

fn detect_reentrancy_eth_transfer(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        match func.visibility {
            Visibility::Public | Visibility::External | Visibility::Unknown => {}
            _ => continue,
        }

        let Some(body) = func.body else { continue };
        let stmts = top_level_stmts(ast, body);
        let mut emitted = false;

        for (i, &sid) in stmts.iter().enumerate() {
            let ext_calls = find_external_calls_in_stmt(ast, sid);
            // Filter to only calls that send ETH.
            let eth_calls: Vec<_> = ext_calls
                .iter()
                .filter(|c| c.sends_eth && !c.is_transfer_or_send)
                .collect();

            if eth_calls.is_empty() {
                continue;
            }

            // Look ahead for state updates.
            for &later_sid in &stmts[i + 1..] {
                let updates = find_state_updates_in_stmt(ast, later_sid);
                if !updates.is_empty() {
                    let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                    findings.push(Finding {
                        kind: FindingKind::ReentrancyEthTransfer,
                        severity: Severity::High,
                        message: format!(
                            "RE-04: reentrancy in `{func_name}`: state variable updated \
                            after ETH-sending external call; the recipient can re-enter \
                            and drain funds — update state before the call"
                        ),
                        span: eth_calls[0].span,
                        function: Some(func.id),
                    });
                    emitted = true;
                    break;
                }
            }
            if emitted {
                break;
            }
        }

        if !emitted && let Some(span) = source_guided_nested_eth_reentrancy_span(ast, func) {
            let func_name = func.name.as_deref().unwrap_or("<anonymous>");
            findings.push(Finding {
                kind: FindingKind::ReentrancyEthTransfer,
                severity: Severity::High,
                message: format!(
                    "RE-04: reentrancy in `{func_name}`: state variable is read before an ETH-sending external call and written after it inside nested control flow; update state before the call"
                ),
                span,
                function: Some(func.id),
            });
        }
    }

    findings
}

// ── RE-05  Reentrancy Vulnerability without ETH Transfer ─────────────────────
//
// A cross-contract call that does NOT transfer ETH (e.g. calling an
// external function on another contract) followed by a state update.
// Even without ETH transfer, the called contract may execute arbitrary
// code and call back into the vulnerable contract.
//
// Examples:
//   token.transferFrom(from, to, amount);  // external ERC-20 call
//   balances[from] -= amount;              // state update after call
//
// Detection:
//   External calls (member calls on contract interfaces) that do NOT send
//   ETH, followed by a state variable update.
//
// Severity: Medium — no direct fund loss, but state corruption is possible.

fn detect_reentrancy_no_eth_transfer(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        match func.visibility {
            Visibility::Public | Visibility::External | Visibility::Unknown => {}
            _ => continue,
        }

        let Some(body) = func.body else { continue };
        let stmts = top_level_stmts(ast, body);
        let mut emitted = false;

        for (i, &sid) in stmts.iter().enumerate() {
            // Find cross-contract calls that do NOT send ETH.
            let cc_calls = find_cross_contract_calls_in_stmt(ast, sid);
            // Also include low-level calls without value
            let ext_calls = find_external_calls_in_stmt(ast, sid);
            let no_eth_calls: Vec<_> = ext_calls
                .iter()
                .filter(|c| !c.sends_eth && c.is_low_level_call)
                .collect();

            if cc_calls.is_empty() && no_eth_calls.is_empty() {
                continue;
            }

            // Exclude if already caught by RE-04 (ETH transfer).
            let has_eth_call = ext_calls.iter().any(|c| c.sends_eth);
            if has_eth_call {
                continue;
            }

            // Look ahead for state updates.
            for &later_sid in &stmts[i + 1..] {
                let updates = find_state_updates_in_stmt(ast, later_sid);
                if !updates.is_empty() {
                    let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                    let span = if !cc_calls.is_empty() {
                        cc_calls[0].span
                    } else {
                        no_eth_calls[0].span
                    };
                    findings.push(Finding {
                        kind: FindingKind::ReentrancyNoEthTransfer,
                        severity: Severity::Medium,
                        message: format!(
                            "RE-05: reentrancy in `{func_name}`: state variable updated \
                            after cross-contract call (no ETH sent); the called contract \
                            can still re-enter via a callback — update state before the call"
                        ),
                        span,
                        function: Some(func.id),
                    });
                    emitted = true;
                    break;
                }
            }
            if emitted {
                break;
            }
        }

        if !emitted && source_guided_no_eth_reentrancy_hit(ast, func) {
            let func_name = func.name.as_deref().unwrap_or("<anonymous>");
            findings.push(Finding {
                kind: FindingKind::ReentrancyNoEthTransfer,
                severity: Severity::Medium,
                message: format!(
                    "RE-05: reentrancy in `{func_name}`: callback-visible state is written before a low-level external call; a callee can re-enter using the newly exposed state"
                ),
                span: func.span,
                function: Some(func.id),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::parser::load_via_parser_sources;
    use crate::norm::SourceFile;

    #[test]
    fn source_guided_no_eth_reentrancy_detects_approve_and_call_pattern() {
        let ast = load_via_parser_sources(vec![SourceFile {
            id: 0,
            path: "approve_and_call.sol".to_string(),
            source: r#"
                pragma solidity ^0.4.15;
                contract Token {
                    mapping(address => mapping(address => uint256)) allowed;
                    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
                        allowed[_from][msg.sender] -= _value;
                        return true;
                    }
                    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
                        allowed[msg.sender][_spender] = _value;
                        require(_spender.call(bytes4(bytes32(sha3("receiveApproval(address,uint256,address,bytes)"))), msg.sender, _value, this, _extraData));
                        return true;
                    }
                }
            "#
            .to_string(),
        }])
        .expect("parser should succeed");

        let findings = detect_reentrancy_no_eth_transfer(&ast);
        assert!(findings.iter().any(|finding| {
            finding.kind == FindingKind::ReentrancyNoEthTransfer
                && finding
                    .message
                    .contains("callback-visible state is written before a low-level external call")
        }));
    }

    #[test]
    fn source_guided_eth_reentrancy_detects_nested_cashout_pattern() {
        let ast = load_via_parser_sources(vec![SourceFile {
            id: 0,
            path: "private_bank.sol".to_string(),
            source: r#"
                pragma solidity ^0.4.19;
                contract PrivateBank {
                    mapping(address => uint256) public balances;
                    function cashOut(uint256 amount) public {
                        if (amount <= balances[msg.sender]) {
                            if (msg.sender.call.value(amount)()) {
                                balances[msg.sender] -= amount;
                            }
                        }
                    }
                }
            "#
            .to_string(),
        }])
        .expect("parser should succeed");

        let findings = detect_reentrancy_eth_transfer(&ast);
        assert!(findings.iter().any(|finding| {
            finding.kind == FindingKind::ReentrancyEthTransfer
                && finding
                    .message
                    .contains("state variable is read before an ETH-sending external call")
        }));
    }

    #[test]
    fn stipend_only_payouts_do_not_emit_reentrancy_findings() {
        let ast = load_via_parser_sources(vec![SourceFile {
            id: 0,
            path: "wallet.sol".to_string(),
            source: r#"
                pragma solidity ^0.4.24;
                contract Wallet {
                    mapping(address => uint256) balances;
                    function withdraw(uint256 amount) public {
                        require(balances[msg.sender] >= amount);
                        msg.sender.transfer(amount);
                        balances[msg.sender] -= amount;
                    }
                }
            "#
            .to_string(),
        }])
        .expect("parser should succeed");

        let findings = detect_all(&ast);
        assert!(
            !findings.iter().any(|finding| {
                matches!(
                    finding.kind,
                    FindingKind::ReentrancyTransfer
                        | FindingKind::ReentrancySameEffect
                        | FindingKind::ReentrancyEthTransfer
                )
            }),
            "stipend-only payouts should not be treated as reentrancy by default"
        );
    }

    #[test]
    fn safemath_member_calls_do_not_emit_no_eth_reentrancy() {
        let ast = load_via_parser_sources(vec![SourceFile {
            id: 0,
            path: "erc20.sol".to_string(),
            source: r#"
                pragma solidity ^0.4.24;
                library SafeMath {
                    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
                        require(b <= a);
                        return a - b;
                    }
                    function add(uint256 a, uint256 b) internal pure returns (uint256) {
                        uint256 c = a + b;
                        require(c >= a);
                        return c;
                    }
                }
                contract ERC20 {
                    using SafeMath for *;
                    mapping(address => uint256) private balances;
                    function transfer(address to, uint256 value) public returns (bool) {
                        balances[msg.sender] = balances[msg.sender].sub(value);
                        balances[to] = balances[to].add(value);
                        return true;
                    }
                }
            "#
            .to_string(),
        }])
        .expect("parser should succeed");

        let findings = detect_reentrancy_no_eth_transfer(&ast);
        assert!(
            findings.is_empty(),
            "SafeMath helper calls should not be treated as cross-contract callbacks"
        );
    }
}
