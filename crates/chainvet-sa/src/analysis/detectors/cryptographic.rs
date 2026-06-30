//! Cryptographic detectors (CR-01 through CR-02)
//! 2 vulnerability detectors covering:
//!   CR-01 – Lack of Proper Signature Verification
//!   CR-02 – Signature Malleability
//!
//! # Background
//!
//! Many smart-contract systems allow users to sign messages off-chain and
//! submit them on-chain for verification.  The EVM pre-compiled contract
//! `ecrecover` recovers a signer address from a hash and a (v, r, s)
//! signature tuple.  Two classes of vulnerability arise from its misuse:
//!
//!   1. **Lack of Proper Signature Verification (CR-01)** – the contract
//!      calls `ecrecover` but never checks whether the returned address
//!      is `address(0)` (which `ecrecover` returns on failure) or whether
//!      it matches the expected signer.  Alternatively, the contract
//!      relies on `msg.sender` to infer signature validity, which is
//!      unsafe when proxies relay transactions.
//!
//!   2. **Signature Malleability (CR-02)** – ECDSA signatures are
//!      inherently malleable: given a valid (v, r, s), anyone can
//!      compute a *different* (v', r, s') that is also valid for the
//!      same message.  The standard fix is to require `s` to be in the
//!      lower half-order (as enforced by OpenZeppelin's `ECDSA.recover`).
//!      Using raw `ecrecover` without this check exposes the contract
//!      to replay / double-spend attacks when the signature is used as
//!      a unique identifier (e.g. as a mapping key or nonce guard).

use chainvet_core::norm::{
    CallOption, CallTarget, ChainSegment, ExprKind, NormalizedAst, StmtKind, Visibility,
};

use super::{Finding, FindingKind, Severity};

// ═══════════════════════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// Names of well-known safe wrappers around `ecrecover` that already
/// enforce the `s`-value lower-half-order check internally.
/// If the contract uses one of these, we do NOT flag CR-02.
const SAFE_RECOVER_WRAPPERS: &[&str] = &[
    "recover",       // OpenZeppelin ECDSA.recover
    "tryRecover",    // OpenZeppelin ECDSA.tryRecover
    "recoverSigner", // common custom wrapper name
];

// ═══════════════════════════════════════════════════════════════════════════════
//  Entry point
// ═══════════════════════════════════════════════════════════════════════════════

/// Run all 2 Cryptographic detectors and return their findings.
pub fn detect_all(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(detect_lack_of_signature_verification(ast)); // CR-01
    findings.extend(detect_signature_malleability(ast)); // CR-02

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
    cb: &mut impl FnMut(u32, &chainvet_core::norm::Expr),
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
fn for_each_expr(
    ast: &NormalizedAst,
    expr_id: u32,
    cb: &mut impl FnMut(u32, &chainvet_core::norm::Expr),
) {
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
fn for_each_stmt(
    ast: &NormalizedAst,
    stmt_id: u32,
    cb: &mut impl FnMut(u32, &chainvet_core::norm::Stmt),
) {
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

// ── Ecrecover detection helpers ─────────────────────────────────────────────

/// Returns `true` if the expression is a call to the built-in `ecrecover`.
/// Checks both the call metadata and the callee identifier by name.
fn is_ecrecover_call(ast: &NormalizedAst, expr: &chainvet_core::norm::Expr) -> bool {
    // Strategy 1: Check call metadata resolved by the normalizer.
    // The normalizer populates `expr.meta.call` with a `CallTarget::Direct`
    // when it can resolve the callee to a known function name.
    if let Some(call) = &expr.meta.call {
        if let CallTarget::Direct { name } = &call.target {
            if name == "ecrecover" {
                return true;
            }
        }
    }

    // Strategy 2: For cases where the normalizer produced `CallTarget::Unknown`,
    // fall back to inspecting the callee expression node directly.
    // `ExprKind::Call { callee, .. }` where callee is `Ident("ecrecover")`.
    if let ExprKind::Call { callee, .. } = &expr.kind {
        if let Some(callee_expr) = ast.expressions.get(*callee as usize) {
            if let ExprKind::Ident(name) = &callee_expr.kind {
                if name == "ecrecover" {
                    return true;
                }
            }
        }
    }

    false
}

/// Returns `true` if `expr_id` (or any sub-expression) contains a call to
/// `ecrecover`.  Used to check whether a larger expression tree involves
/// signature recovery.
fn contains_ecrecover_call(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };

    // Check this node itself.
    if is_ecrecover_call(ast, expr) {
        return true;
    }

    // Recurse into sub-expressions.
    match &expr.kind {
        ExprKind::Call { callee, args } => {
            contains_ecrecover_call(ast, *callee)
                || args.iter().any(|&a| contains_ecrecover_call(ast, a))
        }
        ExprKind::CallOptions { callee, options } => {
            contains_ecrecover_call(ast, *callee)
                || options.iter().any(|opt| match opt {
                    CallOption::Value(e) | CallOption::Gas(e) | CallOption::Salt(e) => {
                        contains_ecrecover_call(ast, *e)
                    }
                })
        }
        ExprKind::Binary { lhs, rhs, .. } => {
            contains_ecrecover_call(ast, *lhs) || contains_ecrecover_call(ast, *rhs)
        }
        ExprKind::Unary { expr, .. } => contains_ecrecover_call(ast, *expr),
        ExprKind::Member { base, .. } => contains_ecrecover_call(ast, *base),
        ExprKind::Assign { lhs, rhs, .. } => {
            contains_ecrecover_call(ast, *lhs) || contains_ecrecover_call(ast, *rhs)
        }
        ExprKind::Tuple(entries) => entries.iter().any(|&e| contains_ecrecover_call(ast, e)),
        ExprKind::Index { base, index } => {
            contains_ecrecover_call(ast, *base)
                || index.map_or(false, |i| contains_ecrecover_call(ast, i))
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            contains_ecrecover_call(ast, *cond)
                || contains_ecrecover_call(ast, *then_expr)
                || contains_ecrecover_call(ast, *else_expr)
        }
        _ => false,
    }
}

/// Returns `true` if the expression is a reference to `address(0)` or
/// the literal `0x0000000000000000000000000000000000000000`.
/// These are the zero-address constants that a well-written contract
/// compares the `ecrecover` result against.
fn is_zero_address(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };

    // Pattern 1: `address(0)` — a type-cast call whose argument is literal 0.
    //   ExprKind::Call { callee: Ident("address"), args: [Literal("0")] }
    if let ExprKind::Call { callee, args } = &expr.kind {
        if let Some(callee_expr) = ast.expressions.get(*callee as usize) {
            if let ExprKind::Ident(name) = &callee_expr.kind {
                if name == "address" && args.len() == 1 {
                    if let Some(arg_expr) = ast.expressions.get(args[0] as usize) {
                        if let ExprKind::Literal(lit) = &arg_expr.kind {
                            if lit.value == "0" {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    // Pattern 2: Literal zero address `0x0000000000000000000000000000000000000000`.
    if let ExprKind::Literal(lit) = &expr.kind {
        let v = lit.value.trim();
        if v == "0x0000000000000000000000000000000000000000" || v == "0x0" || v == "0" {
            return true;
        }
    }

    false
}

/// Collect the names of local variables that are assigned the return
/// value of `ecrecover(...)`.  Common patterns:
///   - `address signer = ecrecover(hash, v, r, s);`  (VarDecl)
///   - `signer = ecrecover(hash, v, r, s);`           (Assign)
///
/// Returns a set of variable name strings.
fn collect_ecrecover_result_vars(ast: &NormalizedAst, body: u32) -> Vec<String> {
    let mut vars = Vec::new();

    for_each_stmt(ast, body, &mut |_sid, stmt| {
        // VarDecl:  `address signer = ecrecover(...);`
        if let StmtKind::VarDecl {
            names,
            init: Some(init),
        } = &stmt.kind
        {
            if contains_ecrecover_call(ast, *init) {
                for name in names {
                    vars.push(name.clone());
                }
            }
        }
    });

    // Also check assignments:  `signer = ecrecover(...);`
    for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
        if let ExprKind::Assign { lhs, rhs, .. } = &expr.kind {
            if contains_ecrecover_call(ast, *rhs) {
                if let Some(lhs_expr) = ast.expressions.get(*lhs as usize) {
                    if let ExprKind::Ident(name) = &lhs_expr.kind {
                        vars.push(name.clone());
                    }
                }
            }
        }
    });

    vars
}

/// Returns `true` if `expr_id` is an identifier whose name is in `var_names`.
fn expr_is_one_of(ast: &NormalizedAst, expr_id: u32, var_names: &[String]) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };
    if let ExprKind::Ident(name) = &expr.kind {
        return var_names.iter().any(|v| v == name);
    }
    false
}

/// Returns `true` if the function body contains an expression that
/// compares the result of `ecrecover` against `address(0)`.
///
/// The common real-world pattern stores ecrecover's result in a local
/// variable first:
///   `address signer = ecrecover(hash, v, r, s);`
///   `require(signer != address(0), "invalid");`
///
/// We therefore:
///   1. Collect variable names assigned from ecrecover.
///   2. Look for a comparison (== / !=) where one side is such a variable
///      (or a direct ecrecover call) and the other is address(0).
fn body_has_zero_address_check(ast: &NormalizedAst, body: u32) -> bool {
    let ecrecover_vars = collect_ecrecover_result_vars(ast, body);
    let mut found = false;

    for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
        if found {
            return;
        }

        if let ExprKind::Binary { op, lhs, rhs } = &expr.kind {
            if op == "!=" || op == "==" {
                // Check both orderings:
                //   ecrecoverVar != address(0)  OR  address(0) != ecrecoverVar
                //   ecrecover(...) != address(0)  (inline call variant)
                let lhs_is_ec = contains_ecrecover_call(ast, *lhs)
                    || expr_is_one_of(ast, *lhs, &ecrecover_vars);
                let rhs_is_ec = contains_ecrecover_call(ast, *rhs)
                    || expr_is_one_of(ast, *rhs, &ecrecover_vars);
                let lhs_zero = is_zero_address(ast, *lhs);
                let rhs_zero = is_zero_address(ast, *rhs);

                if (lhs_is_ec && rhs_zero) || (rhs_is_ec && lhs_zero) {
                    found = true;
                }
            }
            // Recurse into `&&` / `||` chains inside require() args.
            if op == "&&" || op == "||" {
                if body_expr_has_zero_check(ast, *lhs, &ecrecover_vars)
                    || body_expr_has_zero_check(ast, *rhs, &ecrecover_vars)
                {
                    found = true;
                }
            }
        }
    });

    found
}

/// Recursively checks if a single expression is (or contains) a comparison
/// of an ecrecover result variable against the zero address.
fn body_expr_has_zero_check(ast: &NormalizedAst, expr_id: u32, ec_vars: &[String]) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };

    if let ExprKind::Binary { op, lhs, rhs } = &expr.kind {
        if op == "!=" || op == "==" {
            let lhs_ec = contains_ecrecover_call(ast, *lhs) || expr_is_one_of(ast, *lhs, ec_vars);
            let rhs_ec = contains_ecrecover_call(ast, *rhs) || expr_is_one_of(ast, *rhs, ec_vars);
            let lhs_z = is_zero_address(ast, *lhs);
            let rhs_z = is_zero_address(ast, *rhs);
            if (lhs_ec && rhs_z) || (rhs_ec && lhs_z) {
                return true;
            }
        }
        if op == "&&" || op == "||" {
            return body_expr_has_zero_check(ast, *lhs, ec_vars)
                || body_expr_has_zero_check(ast, *rhs, ec_vars);
        }
    }

    false
}

/// Returns `true` if the function body contains a `require(msg.sender == ...)`
/// or `if (msg.sender == ...)` pattern that is NOT accompanied by a proper
/// `ecrecover` call.  This heuristic detects the anti-pattern of relying on
/// `msg.sender` as a substitute for cryptographic signature verification.
fn body_relies_on_msg_sender_for_sig(ast: &NormalizedAst, body: u32) -> bool {
    let mut has_msg_sender_check = false;
    let mut has_ecrecover = false;

    for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
        // Track whether the function uses ecrecover at all.
        if is_ecrecover_call(ast, expr) {
            has_ecrecover = true;
        }

        // Detect `msg.sender` used in a comparison (== or !=).
        if let ExprKind::Binary { op, lhs, rhs } = &expr.kind {
            if op == "==" || op == "!=" {
                if contains_msg_sender(ast, *lhs) || contains_msg_sender(ast, *rhs) {
                    has_msg_sender_check = true;
                }
            }
        }
    });

    // The anti-pattern is: the function checks msg.sender but never calls
    // ecrecover — implying it relies on msg.sender *instead of* verifying
    // a cryptographic signature.  (If the function also calls ecrecover,
    // the msg.sender check is likely an additional guard, which is fine.)
    //
    // However, we only flag this when the function also appears to deal
    // with signature-related parameters (has parameters named "sig",
    // "signature", "v", "r", "s", or "hash").
    has_msg_sender_check && !has_ecrecover
}

/// Returns `true` if the expression is or contains `msg.sender`.
fn contains_msg_sender(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };

    // Chain metadata: [Ident("msg"), Member("sender")]
    if let Some(chain) = expr.meta.chain.as_deref() {
        if chain.len() == 2 {
            if let (ChainSegment::Ident(base), ChainSegment::Member(member)) =
                (&chain[0], &chain[1])
            {
                if base == "msg" && member == "sender" {
                    return true;
                }
            }
        }
    }

    // AST Member node: msg.sender
    if let ExprKind::Member { base, field } = &expr.kind {
        if field == "sender" {
            if let Some(base_expr) = ast.expressions.get(*base as usize) {
                if let ExprKind::Ident(name) = &base_expr.kind {
                    if name == "msg" {
                        return true;
                    }
                }
            }
        }
    }

    // Recurse into sub-expressions.
    match &expr.kind {
        ExprKind::Binary { lhs, rhs, .. } => {
            contains_msg_sender(ast, *lhs) || contains_msg_sender(ast, *rhs)
        }
        ExprKind::Unary { expr, .. } => contains_msg_sender(ast, *expr),
        ExprKind::Member { base, .. } => contains_msg_sender(ast, *base),
        ExprKind::Call { callee, args } => {
            contains_msg_sender(ast, *callee) || args.iter().any(|&a| contains_msg_sender(ast, a))
        }
        ExprKind::Assign { lhs, rhs, .. } => {
            contains_msg_sender(ast, *lhs) || contains_msg_sender(ast, *rhs)
        }
        ExprKind::Tuple(entries) => entries.iter().any(|&e| contains_msg_sender(ast, e)),
        ExprKind::Index { base, index } => {
            contains_msg_sender(ast, *base) || index.map_or(false, |i| contains_msg_sender(ast, i))
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            contains_msg_sender(ast, *cond)
                || contains_msg_sender(ast, *then_expr)
                || contains_msg_sender(ast, *else_expr)
        }
        _ => false,
    }
}

/// Returns `true` if a function's parameter names suggest it handles
/// signature data.  We look for common parameter names associated with
/// ECDSA signatures.
fn function_has_signature_params(func: &chainvet_core::norm::Function) -> bool {
    // Common signature-related parameter name fragments.
    const SIG_HINTS: &[&str] = &["signature", "sig", "v", "r", "s", "hash", "digest"];

    // We need at least 2 matches among the short names (v, r, s) or at
    // least 1 match for the longer descriptive names.
    let mut short_matches = 0u32; // matches for "v", "r", "s"
    let mut long_match = false; // matches for "signature", "sig", "hash", "digest"

    for param in &func.params {
        let lower = param.to_lowercase();
        match lower.as_str() {
            "v" | "r" | "s" => short_matches += 1,
            _ => {
                if SIG_HINTS.iter().any(|hint| lower.contains(hint)) {
                    long_match = true;
                }
            }
        }
    }

    // Heuristic: at least 2 of v/r/s  OR  at least 1 "signature"/"hash"/…
    short_matches >= 2 || long_match
}

/// Returns `true` if the function body uses a safe ECDSA wrapper library
/// such as OpenZeppelin's `ECDSA.recover` or `ECDSA.tryRecover`.
/// When a safe wrapper is used, signature malleability is already handled.
fn body_uses_safe_recover(ast: &NormalizedAst, body: u32) -> bool {
    let mut found = false;

    for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
        if found {
            return;
        }

        // Strategy 1: CallMeta with a Member target whose name is "recover"
        // or "tryRecover" — typically `ECDSA.recover(hash, v, r, s)`.
        if let Some(call) = &expr.meta.call {
            let name = match &call.target {
                CallTarget::Direct { name } => name.as_str(),
                CallTarget::Member { name, .. } => name.as_str(),
                CallTarget::Unknown => "",
            };
            if SAFE_RECOVER_WRAPPERS.iter().any(|&w| w == name) {
                found = true;
                return;
            }
        }

        // Strategy 2: Callee is a Member expression whose `field` is a
        // safe wrapper name (covers cases where CallMeta is Unknown but
        // the AST can see `ECDSA.recover(...)`).
        if let ExprKind::Call { callee, .. } = &expr.kind {
            if let Some(callee_expr) = ast.expressions.get(*callee as usize) {
                if let ExprKind::Member { field, .. } = &callee_expr.kind {
                    if SAFE_RECOVER_WRAPPERS.iter().any(|&w| w == field.as_str()) {
                        found = true;
                        return;
                    }
                }
                // Also match direct `recover(...)` calls (possible via
                // `using ECDSA for bytes32`).
                if let ExprKind::Ident(name) = &callee_expr.kind {
                    if SAFE_RECOVER_WRAPPERS.iter().any(|&w| w == name.as_str()) {
                        found = true;
                        return;
                    }
                }
            }
        }
    });

    found
}

/// Returns `true` if the function body contains a comparison of the `s`
/// parameter against the secp256k1 half-order upper bound.  This is the
/// manual fix for signature malleability.
///
/// Detected pattern:
///   `require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0)`
///
/// We heuristically look for any comparison (`<=`, `<`, `>=`, `>`) where
/// one side is an identifier named "s" and the other is a literal whose
/// hex value starts with `0x7FFFFFFF`.
fn body_has_s_value_check(ast: &NormalizedAst, body: u32) -> bool {
    let mut found = false;

    for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
        if found {
            return;
        }

        if let ExprKind::Binary { op, lhs, rhs } = &expr.kind {
            // Only look at ordering comparisons.
            if matches!(op.as_str(), "<=" | "<" | ">=" | ">") {
                let lhs_is_s = expr_is_s_ident(ast, *lhs);
                let rhs_is_s = expr_is_s_ident(ast, *rhs);
                let lhs_bound = expr_is_s_upper_bound(ast, *lhs);
                let rhs_bound = expr_is_s_upper_bound(ast, *rhs);

                if (lhs_is_s && rhs_bound) || (rhs_is_s && lhs_bound) {
                    found = true;
                }
            }
        }
    });

    found
}

/// Returns `true` if the expression resolves to an identifier named `s`
/// (possibly cast, e.g. `uint256(s)`).
fn expr_is_s_ident(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };

    // Direct identifier: `s`
    if let ExprKind::Ident(name) = &expr.kind {
        if name == "s" {
            return true;
        }
    }

    // Type-cast: `uint256(s)` — the normalizer represents this as a Call
    // whose callee is the type name and the single arg is the value.
    if let ExprKind::Call { args, .. } = &expr.kind {
        if args.len() == 1 {
            return expr_is_s_ident(ast, args[0]);
        }
    }

    false
}

/// Returns `true` if the expression is a literal whose value starts with
/// the known secp256k1 half-order upper-bound prefix.
fn expr_is_s_upper_bound(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };

    if let ExprKind::Literal(lit) = &expr.kind {
        // Normalize: strip optional `0x` / `0X`, then check the remaining
        // hex digits start with "7FFFFFFF" (case-insensitive).
        let v = lit.value.trim();
        let hex_part = v
            .strip_prefix("0x")
            .or_else(|| v.strip_prefix("0X"))
            .unwrap_or(v);
        if hex_part.to_ascii_uppercase().starts_with("7FFFFFFF") {
            return true;
        }
    }

    false
}

// ── Checking if `ecrecover` result is compared to an expected signer ────────

/// Returns `true` if the function body contains a comparison (== or !=)
/// of the ecrecover result against a variable / parameter / state variable
/// that is NOT address(0).  This proves the contract actually validates
/// the recovered signer.
///
/// Handles both inline `ecrecover(...) == expectedSigner` and the common
/// idiom where the result is stored in a local variable first:
///   `address recovered = ecrecover(...);`
///   `require(recovered == trustedSigner);`
fn body_validates_recovered_signer(ast: &NormalizedAst, body: u32) -> bool {
    let ecrecover_vars = collect_ecrecover_result_vars(ast, body);
    let mut found = false;

    for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
        if found {
            return;
        }

        if let ExprKind::Binary { op, lhs, rhs } = &expr.kind {
            if op == "==" || op == "!=" {
                let lhs_ec = contains_ecrecover_call(ast, *lhs)
                    || expr_is_one_of(ast, *lhs, &ecrecover_vars);
                let rhs_ec = contains_ecrecover_call(ast, *rhs)
                    || expr_is_one_of(ast, *rhs, &ecrecover_vars);

                if lhs_ec || rhs_ec {
                    // The other side must NOT be address(0) — that's the
                    // zero-check handled separately.
                    let other_side = if lhs_ec { *rhs } else { *lhs };
                    if !is_zero_address(ast, other_side) {
                        found = true;
                    }
                }
            }
        }
    });

    found
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Detectors CR-01 … CR-02
// ═══════════════════════════════════════════════════════════════════════════════

// ── CR-01  Lack of Proper Signature Verification ────────────────────────────
//
// Smart contracts that process signed messages must verify authenticity
// using `ecrecover`.  Two sub-patterns are considered vulnerable:
//
//   A. The contract calls `ecrecover` but never compares the returned
//      address against `address(0)` (failure case) AND never compares
//      it against an expected signer address.  An attacker can pass
//      arbitrary (v, r, s) values that cause `ecrecover` to return
//      `address(0)`, and if the contract does not check for this, the
//      recovered address is accepted unconditionally.
//
//   B. The contract has signature-related parameters (v, r, s, hash,
//      signature…) but relies on `msg.sender` for authentication
//      instead of calling `ecrecover`.  Since transactions can be
//      relayed through proxies or meta-transaction forwarders,
//      `msg.sender` does not reliably identify the original signer.
//
// Detection:
//   For each function:
//     1. Check whether it calls `ecrecover`.
//        1a. If yes, check whether the returned value is compared to
//            `address(0)` or to an expected signer variable.
//            If neither comparison exists → report CR-01 sub-pattern A.
//     2. If the function has signature-related parameters but does NOT
//        call `ecrecover` and instead checks `msg.sender` → report
//        CR-01 sub-pattern B.
//
// Severity: High — missing signature verification can let anyone
// impersonate a valid signer.

fn detect_lack_of_signature_verification(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        // ------------------------------------------------------------------
        // Sub-pattern A:  ecrecover called but result not validated.
        // ------------------------------------------------------------------
        let mut uses_ecrecover = false;

        for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
            if is_ecrecover_call(ast, expr) {
                uses_ecrecover = true;
            }
        });

        if uses_ecrecover {
            let has_zero_check = body_has_zero_address_check(ast, body);
            let has_signer_check = body_validates_recovered_signer(ast, body);

            if !has_zero_check && !has_signer_check {
                // The function calls ecrecover but never validates the
                // returned address — neither against address(0) nor
                // against an expected signer.
                let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                findings.push(Finding {
                    kind: FindingKind::LackOfSignatureVerification,
                    severity: Severity::High,
                    message: format!(
                        "CR-01: function `{func_name}` calls `ecrecover` but does not \
                        check the returned address against `address(0)` or an expected \
                        signer; an invalid signature will return `address(0)` and may \
                        bypass authentication"
                    ),
                    span: func.span,
                    function: Some(func.id),
                });
            }
        }

        // ------------------------------------------------------------------
        // Sub-pattern B:  Signature params present but msg.sender used
        //                 instead of ecrecover.
        // ------------------------------------------------------------------
        if !uses_ecrecover && function_has_signature_params(func) {
            // Only publicly callable functions are relevant.
            match func.visibility {
                Visibility::Public | Visibility::External | Visibility::Unknown => {}
                _ => continue,
            }

            if body_relies_on_msg_sender_for_sig(ast, body) {
                let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                findings.push(Finding {
                    kind: FindingKind::LackOfSignatureVerification,
                    severity: Severity::High,
                    message: format!(
                        "CR-01: function `{func_name}` has signature-related parameters \
                        but relies on `msg.sender` for authentication instead of \
                        `ecrecover`; proxies or meta-transaction forwarders can spoof \
                        the sender"
                    ),
                    span: func.span,
                    function: Some(func.id),
                });
            }
        }
    }

    findings
}

// ── CR-02  Signature Malleability ───────────────────────────────────────────
//
// ECDSA signatures have an inherent malleability property: for any valid
// signature (v, r, s), the tuple (v ^ 1, r, secp256k1_N - s) is also a
// valid signature for the same message.  If the contract uses the raw
// signature bytes as a unique identifier (e.g. as a mapping key to
// prevent replay), an attacker can create a second valid signature and
// replay the action.
//
// The standard mitigation is to enforce that `s` is in the lower half
// of the secp256k1 order:
//
//   require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0);
//
// OpenZeppelin's `ECDSA.recover` handles this automatically.
//
// Detection:
//   For each function that calls `ecrecover` directly:
//     1. Check if the function also uses a safe wrapper (ECDSA.recover).
//        If so → skip (safe).
//     2. Check if the function contains the `s`-value upper-bound comparison.
//        If so → skip (manually mitigated).
//     3. Otherwise → report CR-02.
//
// Severity: Medium — exploitable only when the raw signature is used as
// a unique key, but the pattern is common enough to warrant a warning.

fn detect_signature_malleability(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        // Step 1: Does this function call `ecrecover` directly?
        let mut uses_ecrecover = false;
        for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
            if is_ecrecover_call(ast, expr) {
                uses_ecrecover = true;
            }
        });

        if !uses_ecrecover {
            continue; // No ecrecover → nothing to flag for malleability.
        }

        // Step 2: Does the function use a safe ECDSA wrapper?
        if body_uses_safe_recover(ast, body) {
            continue; // Safe wrapper handles the s-value check internally.
        }

        // Step 3: Does the function manually check the s-value bound?
        if body_has_s_value_check(ast, body) {
            continue; // Developer has manually mitigated malleability.
        }

        // Neither safe wrapper nor manual check → flag the function.
        let func_name = func.name.as_deref().unwrap_or("<anonymous>");
        findings.push(Finding {
            kind: FindingKind::SignatureMalleability,
            severity: Severity::Medium,
            message: format!(
                "CR-02: function `{func_name}` calls `ecrecover` directly without \
                enforcing the `s`-value lower half-order constraint; ECDSA signatures are \
                malleable — use OpenZeppelin's `ECDSA.recover` or add \
                `require(uint256(s) <= 0x7FFF…1B20A0)` to prevent replay attacks"
            ),
            span: func.span,
            function: Some(func.id),
        });
    }

    findings
}
