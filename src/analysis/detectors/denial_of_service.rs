//! Denial of Service detectors (DS-01 through DS-06)
//! 6 vulnerability detectors covering:
//!   DS-01 – `transfer()` and `send()` with Hardcoded Gas Amount (2300 gas)
//!   DS-02 – Contract Could Lock Ether (payable without withdrawal)
//!   DS-03 – DoS with Block Gas Limit (unbounded loops over dynamic arrays)
//!   DS-04 – DoS with Failed Call (external calls inside loops / push pattern)
//!   DS-05 – Force Sending Ether with `this.balance` check in require()/assert()
//!   DS-06 – Unsafe `send()` in `require()` Condition
//!
//! # Background
//!
//! Denial of Service (DoS) vulnerabilities in smart contracts arise when
//! an attacker (or unforeseen circumstances) can prevent legitimate users
//! from interacting with the contract.  Unlike traditional DoS attacks
//! that overwhelm servers with traffic, blockchain DoS exploits the
//! deterministic, gas-metered execution model of the EVM to lock funds,
//! exhaust gas limits, or permanently brick contract logic.
//!
//! These detectors identify common Solidity patterns that can lead to
//! DoS conditions, ranging from hardcoded gas assumptions that break
//! after EVM hard-forks to unbounded loops that exceed block gas limits.

use crate::norm::{
    CallOption, CallTarget, ChainSegment, ContractKind, ExprKind, FunctionKind, Mutability,
    NormalizedAst, Span, StmtKind,
};

use super::{Finding, FindingKind, Severity};

// ═══════════════════════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// Method names that forward a hardcoded 2300 gas stipend.
/// After EIP-1884 (Istanbul hard fork), the SLOAD instruction cost
/// increased, potentially causing these calls to fail unexpectedly.
const HARDCODED_GAS_METHODS: &[&str] = &["transfer", "send"];

/// Method names that perform external value transfers.
/// Used by DS-04 to detect external calls inside loops.
const EXTERNAL_CALL_METHODS: &[&str] =
    &["transfer", "transferFrom", "send", "call", "delegatecall"];

/// Function name fragments that typically represent a withdrawal pattern.
/// If a contract contains ANY function whose name matches these hints,
/// it is considered to have withdrawal capability (for DS-02).
const WITHDRAW_HINTS: &[&str] = &[
    "withdraw",
    "withdrawal",
    "pull",
    "claim",
    "redeem",
    "cashout",
    "payout",
    "sweep",
];

// ═══════════════════════════════════════════════════════════════════════════════
//  Entry point
// ═══════════════════════════════════════════════════════════════════════════════

/// Run all 6 Denial of Service detectors and return their findings.
pub fn detect_all(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(detect_hardcoded_gas_transfer(ast)); // DS-01
    findings.extend(detect_locked_ether(ast)); // DS-02
    findings.extend(detect_dos_block_gas_limit(ast)); // DS-03
    findings.extend(detect_dos_with_failed_call(ast)); // DS-04
    findings.extend(detect_force_ether_balance_check(ast)); // DS-05
    findings.extend(detect_unsafe_send_in_require(ast)); // DS-06

    findings
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helper utilities
// ═══════════════════════════════════════════════════════════════════════════════

// ── Expression walkers ───────────────────────────────────────────────────────

/// Walk every expression reachable from a statement tree, calling `cb` on each.
/// This is the same walker pattern used in block_manipulation.rs; reproduced
/// here so that this module is self-contained.
fn for_each_expr_in_stmt(
    ast: &NormalizedAst,
    stmt_id: u32,
    cb: &mut impl FnMut(u32, &crate::norm::Expr),
) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else {
        return;
    };

    match &stmt.kind {
        // Recurse into each child of a block.
        StmtKind::Block(stmts) => {
            for &s in stmts {
                for_each_expr_in_stmt(ast, s, cb);
            }
        }
        // Expression statement — walk the expression.
        StmtKind::Expr(e) => for_each_expr(ast, *e, cb),
        // Return with a value — walk the return expression.
        StmtKind::Return(Some(e)) => for_each_expr(ast, *e, cb),
        // If — walk condition, then branch, and optional else branch.
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
        // While — walk condition and body.
        StmtKind::While { cond, body } => {
            for_each_expr(ast, *cond, cb);
            for_each_expr_in_stmt(ast, *body, cb);
        }
        // Do-while — walk body then condition.
        StmtKind::DoWhile { body, cond } => {
            for_each_expr_in_stmt(ast, *body, cb);
            for_each_expr(ast, *cond, cb);
        }
        // For — walk init, condition, step, and body.
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
        // Emit — walk the emitted expression.
        StmtKind::Emit(e) => for_each_expr(ast, *e, cb),
        // Revert with expression.
        StmtKind::Revert(Some(e)) => for_each_expr(ast, *e, cb),
        // Variable declaration with initializer.
        StmtKind::VarDecl { init: Some(e), .. } => for_each_expr(ast, *e, cb),
        // Try-catch: walk the call and each clause's body.
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

// ── Detection helpers ────────────────────────────────────────────────────────

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

fn function_source_lower(ast: &NormalizedAst, func: &crate::norm::Function) -> Option<String> {
    get_source_at_span(ast, &func.span).map(|source| source.to_ascii_lowercase())
}

fn source_contains_loop(lower: &str) -> bool {
    ["for(", "for (", "while(", "while (", "do {"]
        .iter()
        .any(|pattern| lower.contains(pattern))
}

fn source_contains_external_payout(lower: &str) -> bool {
    [
        ".transfer(",
        ".send(",
        ".call(",
        ".call.value(",
        ".delegatecall(",
    ]
    .iter()
    .any(|pattern| lower.contains(pattern))
}

fn source_contains_failed_refund_guard(lower: &str) -> bool {
    lower
        .lines()
        .any(|line| line.contains("require(") && source_contains_external_payout(line))
}

/// Returns `true` if the expression is a call to `.transfer()` or `.send()`.
/// These two methods forward exactly 2300 gas, which may not be enough
/// after gas-cost changes in EVM hard forks (e.g. EIP-1884).
///
/// Checks two strategies:
///   1. CallMeta with a Member target named "transfer" or "send".
///   2. AST `ExprKind::Call { callee: Member { field: "transfer"|"send" } }`.
fn is_hardcoded_gas_call(ast: &NormalizedAst, expr: &crate::norm::Expr) -> bool {
    // Strategy 1: Check call metadata resolved by the normalizer.
    if let Some(call) = &expr.meta.call {
        let name = match &call.target {
            CallTarget::Direct { name } => name.as_str(),
            CallTarget::Member { name, .. } => name.as_str(),
            CallTarget::Unknown => "",
        };
        if HARDCODED_GAS_METHODS.iter().any(|&m| m == name) {
            return true;
        }
    }

    // Strategy 2: Inspect the callee expression directly for Member access.
    // Covers patterns like `payable(addr).transfer(amt)` where the parser
    // produces CallTarget::Unknown but the callee field is visible.
    if let ExprKind::Call { callee, .. } = &expr.kind {
        if let Some(callee_expr) = ast.expressions.get(*callee as usize) {
            if let ExprKind::Member { field, .. } = &callee_expr.kind {
                if HARDCODED_GAS_METHODS.iter().any(|&m| m == field.as_str()) {
                    return true;
                }
            }
        }
    }

    false
}

/// Returns `true` if the expression is a call to an external transfer method.
/// Used by DS-04 to detect external calls inside loops.
fn is_external_call(ast: &NormalizedAst, expr: &crate::norm::Expr) -> bool {
    // Strategy 1: CallMeta
    if let Some(call) = &expr.meta.call {
        let name = match &call.target {
            CallTarget::Direct { name } => name.as_str(),
            CallTarget::Member { name, .. } => name.as_str(),
            CallTarget::Unknown => "",
        };
        if EXTERNAL_CALL_METHODS.iter().any(|&m| m == name) {
            return true;
        }
    }

    // Strategy 2: Member field name on the callee.
    if let ExprKind::Call { callee, .. } = &expr.kind {
        if let Some(callee_expr) = ast.expressions.get(*callee as usize) {
            if let ExprKind::Member { field, .. } = &callee_expr.kind {
                if EXTERNAL_CALL_METHODS.iter().any(|&m| m == field.as_str()) {
                    return true;
                }
            }
        }
    }

    // Strategy 3: CallOptions with a `value` option (low-level `.call{value: ...}`).
    if let ExprKind::CallOptions { options, .. } = &expr.kind {
        for opt in options {
            if matches!(opt, CallOption::Value(_)) {
                return true;
            }
        }
    }

    false
}

/// Returns `true` if the expression is a call to `selfdestruct(...)`.
/// Checks both the call metadata and the callee identifier.
fn is_selfdestruct_call(ast: &NormalizedAst, expr: &crate::norm::Expr) -> bool {
    // Strategy 1: CallMeta with Direct target named "selfdestruct" or "suicide".
    if let Some(call) = &expr.meta.call {
        if let CallTarget::Direct { name } = &call.target {
            if name == "selfdestruct" || name == "suicide" {
                return true;
            }
        }
    }

    // Strategy 2: Call whose callee is an Ident("selfdestruct") or Ident("suicide").
    if let ExprKind::Call { callee, .. } = &expr.kind {
        if let Some(callee_expr) = ast.expressions.get(*callee as usize) {
            if let ExprKind::Ident(name) = &callee_expr.kind {
                if name == "selfdestruct" || name == "suicide" {
                    return true;
                }
            }
        }
    }

    false
}

/// Returns `true` if the expression contains a reference to `this.balance`
/// or `address(this).balance`.
///
/// Patterns detected:
///   1. Chain metadata: [Ident("this"), Member("balance")]
///   2. Member AST: `this.balance`
///   3. Chain metadata: [Ident("address"), Call, Member("balance")] with
///      argument `this` — representing `address(this).balance`.
///   4. Member AST chain: `address(this).balance`.
fn contains_this_balance(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };

    // --- Pattern 1: Chain metadata [this, balance] ---
    if let Some(chain) = expr.meta.chain.as_deref() {
        if chain.len() == 2 {
            if let (ChainSegment::Ident(base), ChainSegment::Member(member)) =
                (&chain[0], &chain[1])
            {
                if base == "this" && member == "balance" {
                    return true;
                }
            }
        }
        // Also check for address(this).balance chain: [address, Call, balance]
        if chain.len() >= 3 {
            if let ChainSegment::Member(last) = &chain[chain.len() - 1] {
                if last == "balance" {
                    if let ChainSegment::Ident(first) = &chain[0] {
                        if first == "address" {
                            return true;
                        }
                    }
                }
            }
        }
    }

    // --- Pattern 2: Member AST node  `.balance` on `this` ---
    if let ExprKind::Member { base, field } = &expr.kind {
        if field == "balance" {
            if let Some(base_expr) = ast.expressions.get(*base as usize) {
                // Direct `this.balance`
                if let ExprKind::Ident(name) = &base_expr.kind {
                    if name == "this" {
                        return true;
                    }
                }
                // `address(this).balance` — base is Call(address, [this])
                if let ExprKind::Call { callee, args } = &base_expr.kind {
                    if let Some(callee_expr) = ast.expressions.get(*callee as usize) {
                        if let ExprKind::Ident(name) = &callee_expr.kind {
                            if name == "address" && args.len() == 1 {
                                if let Some(arg) = ast.expressions.get(args[0] as usize) {
                                    if let ExprKind::Ident(arg_name) = &arg.kind {
                                        if arg_name == "this" {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Recurse into sub-expressions.
    recurse_contains(ast, expr, contains_this_balance)
}

/// Returns `true` if the expression is or contains a call to `require(...)`.
fn is_require_or_assert_call(expr: &crate::norm::Expr) -> bool {
    if let Some(call) = &expr.meta.call {
        if let CallTarget::Direct { name } = &call.target {
            if name == "require" || name == "assert" {
                return true;
            }
        }
    }
    false
}

/// Returns `true` if the expression is a call to `require(...)`.
fn is_require_call(expr: &crate::norm::Expr) -> bool {
    if let Some(call) = &expr.meta.call {
        if let CallTarget::Direct { name } = &call.target {
            if name == "require" {
                return true;
            }
        }
    }
    false
}

/// Returns `true` if the expression contains a `.send(...)` call anywhere
/// within its sub-expression tree.
fn contains_send_call(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };

    // Check call metadata for "send".
    if let Some(call) = &expr.meta.call {
        let name = match &call.target {
            CallTarget::Direct { name } => name.as_str(),
            CallTarget::Member { name, .. } => name.as_str(),
            CallTarget::Unknown => "",
        };
        if name == "send" {
            return true;
        }
    }

    // Check Member field on callee.
    if let ExprKind::Call { callee, .. } = &expr.kind {
        if let Some(callee_expr) = ast.expressions.get(*callee as usize) {
            if let ExprKind::Member { field, .. } = &callee_expr.kind {
                if field == "send" {
                    return true;
                }
            }
        }
    }

    // Recurse into sub-expressions.
    recurse_contains(ast, expr, contains_send_call)
}

/// Returns `true` if a statement is inside a loop (for / while / do-while).
/// This checks whether the statement `stmt_id` resides within a loop body
/// by walking upward through the parsed AST structure.
///
/// Since we do not have parent pointers, we instead use a different approach:
/// we walk into loop bodies and check whether they contain external calls.
fn stmt_body_contains_external_call(ast: &NormalizedAst, body_id: u32) -> bool {
    let mut found = false;
    for_each_expr_in_stmt(ast, body_id, &mut |_eid, expr| {
        if !found && is_external_call(ast, expr) {
            found = true;
        }
    });
    found
}

/// Returns `true` if the expression's loop condition references `.length`
/// on an identifier (suggesting an unbounded dynamic array iteration).
///
/// Common patterns:
///   `i < arr.length`
///   `i < users.length`
fn cond_uses_dynamic_length(ast: &NormalizedAst, cond_id: u32) -> bool {
    let mut found = false;
    for_each_expr(ast, cond_id, &mut |_eid, expr| {
        if found {
            return;
        }
        // Look for `.length` member access.
        if let ExprKind::Member { field, .. } = &expr.kind {
            if field == "length" {
                found = true;
            }
        }
    });
    found
}

/// Returns `true` if the loop body contains a `.push(...)` call on an array,
/// meaning the array grows inside the loop → potential unbounded gas usage.
fn body_contains_push(ast: &NormalizedAst, body_id: u32) -> bool {
    let mut found = false;
    for_each_expr_in_stmt(ast, body_id, &mut |_eid, expr| {
        if found {
            return;
        }
        // Check call metadata for "push".
        if let Some(call) = &expr.meta.call {
            let name = match &call.target {
                CallTarget::Direct { name } => name.as_str(),
                CallTarget::Member { name, .. } => name.as_str(),
                CallTarget::Unknown => "",
            };
            if name == "push" {
                found = true;
                return;
            }
        }
        // Check Member field on callee.
        if let ExprKind::Call { callee, .. } = &expr.kind {
            if let Some(callee_expr) = ast.expressions.get(*callee as usize) {
                if let ExprKind::Member { field, .. } = &callee_expr.kind {
                    if field == "push" {
                        found = true;
                    }
                }
            }
        }
    });
    found
}

/// Generic recursive descent into sub-expressions.
/// `pred` is the specific predicate that checks a single expression node.
fn recurse_contains(
    ast: &NormalizedAst,
    expr: &crate::norm::Expr,
    pred: fn(&NormalizedAst, u32) -> bool,
) -> bool {
    match &expr.kind {
        ExprKind::Binary { lhs, rhs, .. } => pred(ast, *lhs) || pred(ast, *rhs),
        ExprKind::Unary { expr, .. } => pred(ast, *expr),
        ExprKind::Member { base, .. } => pred(ast, *base),
        ExprKind::Tuple(entries) => entries.iter().any(|&e| pred(ast, e)),
        ExprKind::Call { callee, args } => pred(ast, *callee) || args.iter().any(|&a| pred(ast, a)),
        ExprKind::CallOptions { callee, options } => {
            pred(ast, *callee)
                || options.iter().any(|opt| match opt {
                    CallOption::Value(e) | CallOption::Gas(e) | CallOption::Salt(e) => {
                        pred(ast, *e)
                    }
                })
        }
        ExprKind::Assign { lhs, rhs, .. } => pred(ast, *lhs) || pred(ast, *rhs),
        ExprKind::Index { base, index } => {
            pred(ast, *base) || index.map_or(false, |i| pred(ast, i))
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => pred(ast, *cond) || pred(ast, *then_expr) || pred(ast, *else_expr),
        _ => false,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Detectors DS-01 … DS-06
// ═══════════════════════════════════════════════════════════════════════════════

// ── DS-01  `transfer()` and `send()` with Hardcoded Gas Amount ──────────────
//
// The `transfer()` and `send()` functions forward a fixed amount of 2300
// gas.  Historically, these were recommended to guard against reentrancy.
// However, the gas cost of EVM instructions may change significantly
// during hard forks (e.g. EIP-1884 increased SLOAD cost), breaking
// deployed contracts that rely on the 2300 gas assumption.
//
// Detection:
//   Walk every function body and flag any call to `.transfer(...)` or
//   `.send(...)`.
//
// Severity: Low — the contract still works on most chains today, but
// relying on 2300 gas is fragile against future hard forks.

fn detect_hardcoded_gas_transfer(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        // Walk every expression in the function body looking for
        // `.transfer(...)` or `.send(...)` calls.
        for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
            if is_hardcoded_gas_call(ast, expr) {
                // Determine which method was used for the message.
                let method_name = detected_method_name(ast, expr);
                findings.push(Finding {
                    kind: FindingKind::HardcodedGasTransfer,
                    severity: Severity::Low,
                    message: format!(
                        "DS-01: `{method_name}()` forwards a fixed 2300 gas stipend; \
                        EVM gas costs may change in hard forks (e.g. EIP-1884), \
                        potentially causing this call to fail — consider using \
                        `.call{{value: ...}}(\"\")` with a reentrancy guard instead"
                    ),
                    span: expr.span,
                    function: Some(func.id),
                });
            }
        });
    }

    findings
}

/// Extract the method name ("transfer" or "send") from a detected
/// hardcoded-gas call expression, for use in diagnostic messages.
fn detected_method_name(ast: &NormalizedAst, expr: &crate::norm::Expr) -> &'static str {
    // Check call metadata first.
    if let Some(call) = &expr.meta.call {
        let name = match &call.target {
            CallTarget::Direct { name } => name.as_str(),
            CallTarget::Member { name, .. } => name.as_str(),
            CallTarget::Unknown => "",
        };
        if name == "transfer" {
            return "transfer";
        }
        if name == "send" {
            return "send";
        }
    }

    // Fall back to callee Member field.
    if let ExprKind::Call { callee, .. } = &expr.kind {
        if let Some(callee_expr) = ast.expressions.get(*callee as usize) {
            if let ExprKind::Member { field, .. } = &callee_expr.kind {
                if field == "transfer" {
                    return "transfer";
                }
                if field == "send" {
                    return "send";
                }
            }
        }
    }

    "transfer/send"
}

// ── DS-02  Contract Could Lock Ether ────────────────────────────────────────
//
// A contract that can receive Ether (via a `payable` function, `receive`,
// or `fallback`) but has no mechanism to withdraw it will trap funds
// permanently.  This is a critical DoS vulnerability — once Ether is
// sent to the contract, it can never be recovered.
//
// Detection:
//   1. For each contract, check if it has at least one `payable` function
//      (including `receive()` and `fallback()`).
//   2. Check if the contract has any function whose name suggests a
//      withdrawal capability, OR any function body that contains a
//      `.transfer(...)`, `.send(...)`, or `.call{value: ...}(...)` call.
//   3. If the contract can receive Ether but has no withdrawal path →
//      report DS-02.
//
// Severity: High — locked Ether is permanently lost.

fn detect_locked_ether(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for contract in &ast.contracts {
        // Skip interfaces and libraries — they cannot hold Ether directly.
        if matches!(
            contract.kind,
            ContractKind::Interface | ContractKind::Library
        ) {
            continue;
        }

        // --- Step 1: Can this contract receive Ether? ---
        // A contract can receive Ether if it has:
        //   - A `receive()` function
        //   - A `fallback()` function that is payable
        //   - Any `payable` function (constructor, regular function, etc.)
        let mut can_receive_ether = false;

        for &func_id in &contract.functions {
            let Some(func) = ast.functions.get(func_id as usize) else {
                continue;
            };

            // `receive()` is always payable by definition.
            if matches!(func.kind, FunctionKind::Receive) {
                can_receive_ether = true;
                break;
            }
            // `fallback()` that is payable.
            if matches!(func.kind, FunctionKind::Fallback)
                && matches!(func.mutability, Mutability::Payable)
            {
                can_receive_ether = true;
                break;
            }
            // Any other function that is payable.
            if matches!(func.mutability, Mutability::Payable) {
                can_receive_ether = true;
                break;
            }
        }

        if !can_receive_ether {
            continue; // Contract cannot receive Ether → no risk.
        }

        // --- Step 2: Can this contract send Ether out? ---
        // Check if any function:
        //   a) Has a name hinting at withdrawal, OR
        //   b) Contains a `.transfer(...)`, `.send(...)`, `.call{value: ...}`
        //      or `selfdestruct(...)` call.
        let mut can_send_ether = false;

        for &func_id in &contract.functions {
            let Some(func) = ast.functions.get(func_id as usize) else {
                continue;
            };

            // Check function name for withdrawal hints.
            if let Some(ref name) = func.name {
                let lower = name.to_lowercase();
                if WITHDRAW_HINTS.iter().any(|hint| lower.contains(hint)) {
                    can_send_ether = true;
                    break;
                }
            }

            if function_source_lower(ast, func)
                .as_deref()
                .map(source_contains_external_payout)
                .unwrap_or(false)
            {
                can_send_ether = true;
                break;
            }

            // Check function body for outgoing Ether calls.
            if let Some(body) = func.body {
                for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
                    if can_send_ether {
                        return;
                    }

                    // .transfer(), .send(), .call{value:}, selfdestruct()
                    if is_external_call(ast, expr) || is_selfdestruct_call(ast, expr) {
                        can_send_ether = true;
                    }
                });

                if can_send_ether {
                    break;
                }
            }
        }

        // --- Step 3: Report if Ether can come in but never go out ---
        if !can_send_ether {
            findings.push(Finding {
                kind: FindingKind::LockedEther,
                severity: Severity::High,
                message: format!(
                    "DS-02: contract `{}` has `payable` function(s) but no withdrawal \
                    mechanism — Ether sent to this contract will be permanently locked",
                    contract.name
                ),
                span: contract.span,
                function: None,
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

    fn parse(source: &str) -> NormalizedAst {
        load_via_parser_sources(vec![SourceFile {
            id: 0,
            path: "test.sol".to_string(),
            source: source.to_string(),
        }])
        .expect("parser should succeed")
    }

    #[test]
    fn call_value_withdraw_is_not_locked_ether() {
        let ast = parse(
            r#"
            pragma solidity ^0.4.24;
            contract Bank {
                mapping(address => uint256) public balances;
                function deposit() public payable {
                    balances[msg.sender] += msg.value;
                }
                function collect(uint256 amount) public payable {
                    if (balances[msg.sender] >= amount) {
                        msg.sender.call.value(amount)();
                    }
                }
            }
            "#,
        );

        let findings = detect_locked_ether(&ast);
        assert!(
            findings.is_empty(),
            "old-style .call.value(...)() withdrawals should count as Ether exit paths"
        );
    }

    #[test]
    fn payable_contract_without_exit_is_locked_ether() {
        let ast = parse(
            r#"
            pragma solidity ^0.4.24;
            contract PiggyBank {
                function deposit() public payable {}
            }
            "#,
        );

        let findings = detect_locked_ether(&ast);
        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == FindingKind::LockedEther)
        );
    }
}

// ── DS-03  DoS with Block Gas Limit ─────────────────────────────────────────
//
// When the iteration count of a loop depends on a dynamically sized array
// (e.g. `for (uint i = 0; i < users.length; i++)`), and the array can
// grow without bound, the total gas consumed by the loop may eventually
// exceed the block gas limit.  This would make the function permanently
// uncallable — a DoS condition.
//
// Detection:
//   Walk every function body looking for `for` and `while` loops whose
//   condition references `.length` (a dynamic array size).  If such a
//   loop is found, also check whether the loop body or any function in
//   the contract pushes to an array (`.push(...)`), confirming that the
//   array can grow.
//
// Severity: Medium — the DoS manifests only when the array grows large,
// but once it does, the function is bricked with no recovery path.

fn detect_dos_block_gas_limit(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        let Some(body) = func.body else { continue };
        let source_lower = function_source_lower(ast, func);
        let baseline = findings.len();

        // Walk all statements looking for loops.
        for_each_stmt(ast, body, &mut |_sid, stmt| {
            match &stmt.kind {
                // `for (...; i < arr.length; ...)` — condition uses `.length`.
                StmtKind::For {
                    cond: Some(cond),
                    body: loop_body,
                    ..
                } => {
                    if cond_uses_dynamic_length(ast, *cond) {
                        let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                        findings.push(Finding {
                            kind: FindingKind::DosBlockGasLimit,
                            severity: Severity::Medium,
                            message: format!(
                                "DS-03: `for` loop in `{func_name}` iterates over a \
                                dynamically-sized array (`.length`); if the array grows \
                                without bound, this function may exceed the block gas \
                                limit and become permanently uncallable"
                            ),
                            span: stmt.span,
                            function: Some(func.id),
                        });
                    }
                    // Also flag if loop body itself pushes to an array
                    // (the array grows inside the loop → quadratic gas).
                    if body_contains_push(ast, *loop_body) {
                        let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                        findings.push(Finding {
                            kind: FindingKind::DosBlockGasLimit,
                            severity: Severity::Medium,
                            message: format!(
                                "DS-03: loop in `{func_name}` uses `.push()` inside the \
                                loop body, causing the iterated array to grow and \
                                potentially exceed the block gas limit"
                            ),
                            span: stmt.span,
                            function: Some(func.id),
                        });
                    }
                }
                // `while (i < arr.length)` — same pattern.
                StmtKind::While {
                    cond,
                    body: loop_body,
                } => {
                    if cond_uses_dynamic_length(ast, *cond) {
                        let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                        findings.push(Finding {
                            kind: FindingKind::DosBlockGasLimit,
                            severity: Severity::Medium,
                            message: format!(
                                "DS-03: `while` loop in `{func_name}` iterates over a \
                                dynamically-sized array (`.length`); if the array grows \
                                without bound, this function may exceed the block gas \
                                limit and become permanently uncallable"
                            ),
                            span: stmt.span,
                            function: Some(func.id),
                        });
                    }
                    if body_contains_push(ast, *loop_body) {
                        let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                        findings.push(Finding {
                            kind: FindingKind::DosBlockGasLimit,
                            severity: Severity::Medium,
                            message: format!(
                                "DS-03: loop in `{func_name}` uses `.push()` inside the \
                                loop body, causing the iterated array to grow and \
                                potentially exceed the block gas limit"
                            ),
                            span: stmt.span,
                            function: Some(func.id),
                        });
                    }
                }
                _ => {}
            }
        });

        if findings.len() == baseline {
            if let Some(source_lower) = source_lower.as_deref() {
                let dynamic_bound = source_lower.contains(".length")
                    || source_lower.contains("msg.gas")
                    || source_lower.contains("gasleft(");
                if source_contains_loop(source_lower) && dynamic_bound {
                    findings.push(Finding {
                        kind: FindingKind::DosBlockGasLimit,
                        severity: Severity::Medium,
                        message: format!(
                            "DS-03: loop in `{}` depends on dynamic bounds (`.length`/gas), which can make the function exceed the block gas limit",
                            func.name.as_deref().unwrap_or("<anonymous>")
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

// ── DS-04  DoS with Failed Call ─────────────────────────────────────────────
//
// External calls can fail accidentally or deliberately.  When an external
// call is made inside a loop, a single failing call causes the entire
// transaction to revert, blocking all subsequent iterations.  This is the
// classic "push over pull" anti-pattern — it is safer to let recipients
// withdraw funds themselves than to push payments to them in a loop.
//
// Detection:
//   Walk every function body looking for `for`, `while`, and `do-while`
//   loops.  If the loop body contains an external call (`.transfer()`,
//   `.send()`, `.call{value: ...}`, `.delegatecall()`), report DS-04.
//
// Severity: High — a single malicious or accidentally failing recipient
// can permanently block the entire distribution / payout logic.

fn detect_dos_with_failed_call(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        let Some(body) = func.body else { continue };
        let source_lower = function_source_lower(ast, func);
        let baseline = findings.len();

        // Walk all statements looking for loops containing external calls.
        for_each_stmt(ast, body, &mut |_sid, stmt| {
            match &stmt.kind {
                // `for (...; ...; ...) { ... externalCall ... }`
                StmtKind::For {
                    body: loop_body, ..
                } => {
                    if stmt_body_contains_external_call(ast, *loop_body) {
                        let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                        findings.push(Finding {
                            kind: FindingKind::DosWithFailedCall,
                            severity: Severity::High,
                            message: format!(
                                "DS-04: external call inside `for` loop in `{func_name}`; \
                                if any single call fails the entire transaction reverts, \
                                blocking all subsequent recipients — use a pull-payment \
                                (withdrawal) pattern instead"
                            ),
                            span: stmt.span,
                            function: Some(func.id),
                        });
                    }
                }
                // `while (...) { ... externalCall ... }`
                StmtKind::While {
                    body: loop_body, ..
                } => {
                    if stmt_body_contains_external_call(ast, *loop_body) {
                        let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                        findings.push(Finding {
                            kind: FindingKind::DosWithFailedCall,
                            severity: Severity::High,
                            message: format!(
                                "DS-04: external call inside `while` loop in `{func_name}`; \
                                if any single call fails the entire transaction reverts — \
                                use a pull-payment (withdrawal) pattern instead"
                            ),
                            span: stmt.span,
                            function: Some(func.id),
                        });
                    }
                }
                // `do { ... externalCall ... } while (...)`
                StmtKind::DoWhile {
                    body: loop_body, ..
                } => {
                    if stmt_body_contains_external_call(ast, *loop_body) {
                        let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                        findings.push(Finding {
                            kind: FindingKind::DosWithFailedCall,
                            severity: Severity::High,
                            message: format!(
                                "DS-04: external call inside `do-while` loop in `{func_name}`; \
                                if any single call fails the entire transaction reverts — \
                                use a pull-payment (withdrawal) pattern instead"
                            ),
                            span: stmt.span,
                            function: Some(func.id),
                        });
                    }
                }
                _ => {}
            }
        });

        if findings.len() == baseline {
            if let Some(source_lower) = source_lower.as_deref() {
                if source_contains_loop(source_lower)
                    && source_contains_external_payout(source_lower)
                {
                    findings.push(Finding {
                        kind: FindingKind::DosWithFailedCall,
                        severity: Severity::High,
                        message: format!(
                            "DS-04: loop in `{}` performs external payouts; a single reverting recipient can block progress",
                            func.name.as_deref().unwrap_or("<anonymous>")
                        ),
                        span: func.span,
                        function: Some(func.id),
                    });
                }
            }
        }

        if let Some(source_lower) = source_lower.as_deref() {
            if source_contains_failed_refund_guard(source_lower) {
                findings.push(Finding {
                    kind: FindingKind::DosWithFailedCall,
                    severity: Severity::High,
                    message: format!(
                        "DS-04: `{}` uses a required push payment (`require(...send/transfer/call...)`); a reverting recipient can DoS the function",
                        func.name.as_deref().unwrap_or("<anonymous>")
                    ),
                    span: func.span,
                    function: Some(func.id),
                });
            }
        }
    }

    findings
}

// ── DS-05  Force Sending Ether with `this.balance` Check ────────────────────
//
// An attacker can force-send Ether to any contract using `selfdestruct`
// (the recipient cannot refuse the payment).  If the contract uses
// `require(address(this).balance == ...)` or
// `assert(address(this).balance == ...)`, the attacker can manipulate
// the contract's balance and cause these checks to always fail,
// permanently bricking the contract logic.
//
// Detection:
//   For each function:
//     1. Check if the function body contains a `selfdestruct(...)` call.
//        (This indicates the *attack vector* — the function can force Ether
//        into another contract.)
//     2. Check if the function body contains `require(...)` or `assert(...)`
//        where the condition references `this.balance` or
//        `address(this).balance`.
//     3. If EITHER condition is met, flag it.  (DS-05 can be triggered by
//        *having* the vulnerable check, regardless of selfdestruct.)
//        However, when BOTH are present in the same contract, the risk is
//        elevated.
//
// Severity: High — the contract can be permanently DoS'd.

fn detect_force_ether_balance_check(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        // Walk every expression looking for require/assert that references
        // `this.balance` or `address(this).balance`.
        for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
            // Is this a `require(...)` or `assert(...)` call?
            if !is_require_or_assert_call(expr) {
                return;
            }

            // Check if ANY argument to require/assert contains `this.balance`.
            if let ExprKind::Call { args, .. } = &expr.kind {
                for &arg in args {
                    if contains_this_balance(ast, arg) {
                        let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                        findings.push(Finding {
                            kind: FindingKind::ForceEtherBalanceCheck,
                            severity: Severity::High,
                            message: format!(
                                "DS-05: `require()` / `assert()` in `{func_name}` \
                                checks `address(this).balance`; an attacker can \
                                force-send Ether via `selfdestruct` to manipulate \
                                the balance and cause this check to always fail, \
                                permanently bricking the contract"
                            ),
                            span: expr.span,
                            function: Some(func.id),
                        });
                        return; // one finding per require/assert call
                    }
                }
            }
        });
    }

    findings
}

// ── DS-06  Unsafe `send()` in `require()` Condition ─────────────────────────
//
// Using `.send(...)` inside a `require(...)` is dangerous because
// `.send()` returns `false` on failure (e.g. the recipient is a contract
// with a reverting fallback).  If `.send()` returns `false`, the
// `require(...)` reverts the entire transaction.  A malicious recipient
// can deliberately cause `.send()` to fail (by consuming all gas in
// their fallback), thereby causing the caller's transaction to always
// revert — a DoS attack.
//
// Detection:
//   Walk every function body looking for `require(...)` calls whose
//   arguments contain a `.send(...)` call.
//
// Severity: High — a malicious recipient can permanently block the
// function by always returning `false` from `.send()`.

fn detect_unsafe_send_in_require(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        // Walk every expression looking for require(...send...) patterns.
        for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
            // Is this a `require(...)` call?
            if !is_require_call(expr) {
                return;
            }

            // Check if any argument to require(...) contains a `.send()` call.
            if let ExprKind::Call { args, .. } = &expr.kind {
                for &arg in args {
                    if contains_send_call(ast, arg) {
                        let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                        findings.push(Finding {
                            kind: FindingKind::UnsafeSendInRequire,
                            severity: Severity::High,
                            message: format!(
                                "DS-06: `.send()` used inside `require()` in \
                                `{func_name}`; if the recipient's fallback reverts \
                                or consumes all gas, `.send()` returns `false` and \
                                `require()` reverts the entire transaction — a \
                                malicious recipient can permanently block this function"
                            ),
                            span: expr.span,
                            function: Some(func.id),
                        });
                        return; // one finding per require call
                    }
                }
            }
        });
    }

    findings
}
