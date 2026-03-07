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

use crate::norm::{
    CallOption, CallTarget, ExprKind, NormalizedAst, StmtKind, Visibility,
};

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



// ═══════════════════════════════════════════════════════════════════════════════
//  Entry point
// ═══════════════════════════════════════════════════════════════════════════════

/// Run all 5 Reentrancy detectors and return their findings.
pub fn detect_all(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(detect_reentrancy_negative_events(ast));     // RE-01
    findings.extend(detect_reentrancy_transfer(ast));            // RE-02
    findings.extend(detect_reentrancy_same_effect(ast));         // RE-03
    findings.extend(detect_reentrancy_eth_transfer(ast));        // RE-04
    findings.extend(detect_reentrancy_no_eth_transfer(ast));     // RE-05

    findings
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
    let Some(stmt) = ast.statements.get(stmt_id as usize) else { return };

    match &stmt.kind {
        StmtKind::Block(stmts) => {
            for &s in stmts { for_each_expr_in_stmt(ast, s, cb); }
        }
        StmtKind::Expr(e) => for_each_expr(ast, *e, cb),
        StmtKind::Return(Some(e)) => for_each_expr(ast, *e, cb),
        StmtKind::If { cond, then_id, else_id } => {
            for_each_expr(ast, *cond, cb);
            for_each_expr_in_stmt(ast, *then_id, cb);
            if let Some(e) = else_id { for_each_expr_in_stmt(ast, *e, cb); }
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
            for clause in clauses { for_each_expr_in_stmt(ast, clause.body, cb); }
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
        let has_value = options.iter().any(|opt| matches!(opt, CallOption::Value(_)));
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
    let Some(expr) = ast.expressions.get(expr_id as usize) else { return false };

    // Direct CallOptions node
    if let ExprKind::CallOptions { options, .. } = &expr.kind {
        return options.iter().any(|opt| matches!(opt, CallOption::Value(_)));
    }

    // Also check call metadata options
    if let Some(call) = &expr.meta.call {
        return call.options.iter().any(|opt| matches!(opt, CallOption::Value(_)));
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
    let Some(stmt) = ast.statements.get(stmt_id as usize) else { return updates };

    match &stmt.kind {
        // Direct expression statement: `balances[msg.sender] = 0;`
        StmtKind::Expr(expr_id) => {
            if let Some(expr) = ast.expressions.get(*expr_id as usize) {
                if let ExprKind::Assign { lhs, .. } = &expr.kind {
                    let names = collect_assigned_names(ast, *lhs);
                    if !names.is_empty() {
                        updates.push(StateUpdateInfo {
                            var_names: names,
                        });
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
    let Some(expr) = ast.expressions.get(lhs_id as usize) else { return names };

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
    let Some(stmt) = ast.statements.get(stmt_id as usize) else { return calls };

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
    if target_names.is_empty() { return false; }

    let mut found = false;
    for_each_expr_in_stmt(ast, stmt_id, &mut |_eid, expr| {
        if found { return; }
        if let ExprKind::Ident(name) = &expr.kind {
            let lower = name.to_lowercase();
            if target_names.iter().any(|t| t.to_lowercase() == lower) {
                found = true;
            }
        }
    });
    found
}

/// Returns the flat list of top-level statement ids from a function body
/// (unwrapping the outer Block if present).
fn top_level_stmts(ast: &NormalizedAst, body_id: u32) -> Vec<u32> {
    let Some(stmt) = ast.statements.get(body_id as usize) else { return vec![] };
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
    let Some(stmt) = ast.statements.get(stmt_id as usize) else { return calls };

    for_each_expr_in_stmt(ast, stmt_id, &mut |_eid, expr| {
        // Look for calls via Member access: `someContract.someFunc(...)`
        if let ExprKind::Call { callee, .. } = &expr.kind {
            if let Some(callee_expr) = ast.expressions.get(*callee as usize) {
                if let ExprKind::Member { field, .. } = &callee_expr.kind {
                    // Skip known low-level / ETH transfer methods
                    let is_known = LOW_LEVEL_CALLS.iter().any(|&m| m == field.as_str())
                        || TRANSFER_METHODS.iter().any(|&m| m == field.as_str());
                    if !is_known {
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
            if let CallTarget::Member { name, .. } = &call.target {
                let is_known = LOW_LEVEL_CALLS.iter().any(|&m| m == name.as_str())
                    || TRANSFER_METHODS.iter().any(|&m| m == name.as_str());
                if !is_known {
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
            if ext_calls.is_empty() { continue; }

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

// ── RE-02  Reentrancy Vulnerability with Transfer ────────────────────────────
//
// Specifically targets the `.transfer()` and `.send()` pattern.
// While these are limited to 2300 gas (making reentrancy harder since
// EIP-2929 / Istanbul), older compilers and certain patterns can still
// be exploited.  State updates after `.transfer()` / `.send()` are
// flagged.
//
// Detection:
//   Scan for `.transfer(...)` or `.send(...)` calls followed by state
//   variable assignments in subsequent statements.
//
// Severity: Medium — 2300 gas limits reduce risk but do not eliminate it.

fn detect_reentrancy_transfer(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        match func.visibility {
            Visibility::Public | Visibility::External | Visibility::Unknown => {}
            _ => continue,
        }

        let Some(body) = func.body else { continue };
        let stmts = top_level_stmts(ast, body);

        for (i, &sid) in stmts.iter().enumerate() {
            // Find external calls that are specifically transfer / send.
            let ext_calls = find_external_calls_in_stmt(ast, sid);
            let transfer_calls: Vec<_> = ext_calls
                .iter()
                .filter(|c| c.is_transfer_or_send)
                .collect();

            if transfer_calls.is_empty() { continue; }

            // Look ahead for state updates.
            for &later_sid in &stmts[i + 1..] {
                let updates = find_state_updates_in_stmt(ast, later_sid);
                if !updates.is_empty() {
                    let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                    findings.push(Finding {
                        kind: FindingKind::ReentrancyTransfer,
                        severity: Severity::Medium,
                        message: format!(
                            "RE-02: reentrancy in `{func_name}`: state variable updated \
                            after `.transfer()` / `.send()` call; update state \
                            **before** transferring to follow checks-effects-interactions"
                        ),
                        span: transfer_calls[0].span,
                        function: Some(func.id),
                    });
                    break; // one finding per call site
                }
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
            if ext_calls.is_empty() { continue; }

            // Collect variable names written AFTER the call.
            let mut written_after: Vec<String> = Vec::new();
            for &later_sid in &stmts[i + 1..] {
                for update in find_state_updates_in_stmt(ast, later_sid) {
                    written_after.extend(update.var_names);
                }
            }

            if written_after.is_empty() { continue; }

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
                findings.push(Finding {
                    kind: FindingKind::ReentrancySameEffect,
                    severity: Severity::High,
                    message: format!(
                        "RE-03: reentrancy in `{func_name}`: variable(s) `{var_list}` \
                        read before external call and written after it; a re-entrant \
                        callback will see stale values and repeat the same effect"
                    ),
                    span: ext_calls[0].span,
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

        for (i, &sid) in stmts.iter().enumerate() {
            let ext_calls = find_external_calls_in_stmt(ast, sid);
            // Filter to only calls that send ETH.
            let eth_calls: Vec<_> = ext_calls
                .iter()
                .filter(|c| c.sends_eth)
                .collect();

            if eth_calls.is_empty() { continue; }

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
                    break;
                }
            }
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

        for (i, &sid) in stmts.iter().enumerate() {
            // Find cross-contract calls that do NOT send ETH.
            let cc_calls = find_cross_contract_calls_in_stmt(ast, sid);
            // Also include low-level calls without value
            let ext_calls = find_external_calls_in_stmt(ast, sid);
            let no_eth_calls: Vec<_> = ext_calls
                .iter()
                .filter(|c| !c.sends_eth && c.is_low_level_call)
                .collect();

            if cc_calls.is_empty() && no_eth_calls.is_empty() { continue; }

            // Exclude if already caught by RE-04 (ETH transfer).
            let has_eth_call = ext_calls.iter().any(|c| c.sends_eth);
            if has_eth_call { continue; }

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
                    break;
                }
            }
        }
    }

    findings
}
