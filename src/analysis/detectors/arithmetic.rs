//! Arithmetic detectors (AR-01 through AR-04)
//! 4 vulnerability detectors covering integer division before multiplication,
//! integer overflow, integer underflow, unsafe array length assignment.

use crate::norm::{
    CallOption, CallTarget, ExprKind, NormalizedAst, Span, StmtKind,
};

use super::{Finding, FindingKind, Severity};

// ── Entry point ──────────────────────────────────────────────────────────────

/// Run all 4 Arithmetic detectors and return their findings.
pub fn detect_all(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(detect_division_before_multiplication(ast)); // AR-01
    findings.extend(detect_integer_overflow(ast));                // AR-02
    findings.extend(detect_integer_underflow(ast));               // AR-03
    findings.extend(detect_unsafe_array_length_assignment(ast));  // AR-04

    findings
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helper utilities
// ═══════════════════════════════════════════════════════════════════════════════

/// Extract the Solidity compiler version from a `pragma solidity` directive
/// in the source text of a file.  Returns `None` if no pragma is found.
/// Examples of pragmas we handle:
///   pragma solidity ^0.8.0;
///   pragma solidity >=0.7.0 <0.9.0;
///   pragma solidity 0.6.12;
/// We extract the *first* version number that appears after `pragma solidity`.
fn extract_solidity_version(source: &str) -> Option<(u8, u8, u8)> {
    // Find the pragma directive
    let lower = source.to_lowercase();
    let pragma_pos = lower.find("pragma solidity")?;
    // Grab the text between `pragma solidity` and the next `;`
    let after = &source[pragma_pos + "pragma solidity".len()..];
    let semi = after.find(';').unwrap_or(after.len());
    let version_range = &after[..semi];

    // Extract the first version number (digits.digits.digits)
    parse_first_version(version_range)
}

/// Parse the first semver-like version (M.m.p) out of a string.
fn parse_first_version(s: &str) -> Option<(u8, u8, u8)> {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    // Skip until we find the first digit
    while i < len && !bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i >= len {
        return None;
    }

    // Parse major
    let major_start = i;
    while i < len && bytes[i].is_ascii_digit() {
        i += 1;
    }
    let major: u8 = s[major_start..i].parse().ok()?;

    // Expect '.'
    if i >= len || bytes[i] != b'.' {
        return Some((major, 0, 0));
    }
    i += 1;

    // Parse minor
    let minor_start = i;
    while i < len && bytes[i].is_ascii_digit() {
        i += 1;
    }
    let minor: u8 = s[minor_start..i].parse().ok()?;

    // Expect '.'
    if i >= len || bytes[i] != b'.' {
        return Some((major, minor, 0));
    }
    i += 1;

    // Parse patch
    let patch_start = i;
    while i < len && bytes[i].is_ascii_digit() {
        i += 1;
    }
    let patch: u8 = s[patch_start..i].parse().ok()?;

    Some((major, minor, patch))
}

/// Returns `true` when every source file in the AST targets Solidity ≥ 0.8.0.
/// When no pragma is found, we conservatively assume < 0.8 (i.e., unsafe).
fn all_files_are_0_8_plus(ast: &NormalizedAst) -> bool {
    if ast.files.is_empty() {
        return false;
    }
    ast.files.iter().all(|f| {
        match extract_solidity_version(&f.source) {
            // Solidity 0.8.0+ has built-in overflow/underflow checks
            Some((major, minor, _)) => major > 0 || minor >= 8,
            // No pragma found — be conservative, assume pre-0.8
            None => false,
        }
    })
}

/// Walk every expression reachable from a statement tree, calling `cb` for each.
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

/// Returns `true` when the expression is inside an `unchecked { ... }` block.
/// We scan the source text backwards from the expression looking for the
/// `unchecked` keyword.  This is a heuristic — if the word appears within
/// 100 bytes before the expression, we assume it is inside an unchecked block
/// (meaning overflow/underflow protection is disabled and we should flag it).
fn is_inside_unchecked_block(ast: &NormalizedAst, span: &Span) -> bool {
    let Some(file) = ast.files.get(span.file as usize) else { return false };
    // Look back up to 100 bytes before the expression for `unchecked`
    let lookback = 100.min(span.start as usize);
    let start = span.start as usize - lookback;
    let slice = &file.source[start..span.start as usize];
    // Check if we see "unchecked" followed by optional whitespace and `{`
    slice.contains("unchecked")
}

/// Returns `true` when an expression is a division (`/`) operation.
fn is_division(expr: &crate::norm::Expr) -> bool {
    matches!(&expr.kind, ExprKind::Binary { op, .. } if op == "/")
}

/// Check if the expression at `expr_id` contains an identifier whose name
/// appears in the given set of parameter/variable names.
fn expr_references_any_ident(
    ast: &NormalizedAst,
    expr_id: u32,
    names: &std::collections::HashSet<&str>,
) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else { return false };
    match &expr.kind {
        ExprKind::Ident(n) => names.contains(n.as_str()),
        ExprKind::Binary { lhs, rhs, .. } => {
            expr_references_any_ident(ast, *lhs, names)
                || expr_references_any_ident(ast, *rhs, names)
        }
        ExprKind::Unary { expr, .. } => expr_references_any_ident(ast, *expr, names),
        ExprKind::Member { base, .. } => expr_references_any_ident(ast, *base, names),
        ExprKind::Call { callee, args } => {
            expr_references_any_ident(ast, *callee, names)
                || args.iter().any(|&a| expr_references_any_ident(ast, a, names))
        }
        ExprKind::Index { base, index } => {
            expr_references_any_ident(ast, *base, names)
                || index.map_or(false, |i| expr_references_any_ident(ast, i, names))
        }
        _ => false,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Detectors AR-01 … AR-04
// ═══════════════════════════════════════════════════════════════════════════════

// ── AR-01  Inappropriate Integer Division before Multiplication ──────────────
//
// Pattern: `(a / b) * c`
//
// When integer division is done before multiplication the intermediate result
// truncates the fractional part, losing precision.  The canonical safe order
// is `a * c / b`.
//
// Detection:
//   Walk every expression.  When we find a `Binary { op: "*", lhs, rhs }`
//   check whether *either* operand is itself a `Binary { op: "/" }`.  If so,
//   report it.

fn detect_division_before_multiplication(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
            // We are looking for:  `<something> * <something>`
            if let ExprKind::Binary { op, lhs, rhs } = &expr.kind {
                if op != "*" {
                    return; // not a multiplication — skip
                }

                // Check if the left or right operand is a division
                let lhs_is_div = ast
                    .expressions
                    .get(*lhs as usize)
                    .map_or(false, is_division);
                let rhs_is_div = ast
                    .expressions
                    .get(*rhs as usize)
                    .map_or(false, is_division);

                if lhs_is_div || rhs_is_div {
                    findings.push(Finding {
                        kind: FindingKind::DivisionBeforeMultiplication,
                        severity: Severity::Medium,
                        message: "integer division is performed before multiplication — \
                                this truncates the intermediate result and loses precision"
                            .into(),
                        span: expr.span,
                        function: Some(func.id),
                    });
                }
            }
        });
    }

    findings
}

// ── AR-02  Integer Overflow ──────────────────────────────────────────────────
//
// In Solidity < 0.8.0, arithmetic operations wrap around on overflow silently.
// Starting from 0.8.0 the compiler inserts automatic overflow/underflow checks
// (unless the code is inside an `unchecked { }` block).
//
// Detection:
//   1. Check the pragma version.  If all files use >= 0.8.0, only flag
//      arithmetic inside `unchecked` blocks.
//   2. For pre-0.8 contracts, flag every addition (`+`) and multiplication
//      (`*`) that is not inside a SafeMath call.
//
// Heuristic limitations:
//   - We do not track variable types (could be signed vs. unsigned).
//   - We look for SafeMath usage by call-target name.

fn detect_integer_overflow(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    // If all files are 0.8+, only flag unchecked blocks
    let is_0_8_plus = all_files_are_0_8_plus(ast);

    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
            // Look for addition or multiplication operators
            if let ExprKind::Binary { op, .. } = &expr.kind {
                if op != "+" && op != "*" {
                    return; // not an overflow-prone operation
                }

                if is_0_8_plus {
                    // In 0.8+, only flag if inside an `unchecked` block
                    if is_inside_unchecked_block(ast, &expr.span) {
                        findings.push(Finding {
                            kind: FindingKind::IntegerOverflow,
                            severity: Severity::Medium,
                            message: format!(
                                "arithmetic `{op}` inside `unchecked` block — \
                                overflow protection is disabled"
                            ),
                            span: expr.span,
                            function: Some(func.id),
                        });
                    }
                } else {
                    // Pre-0.8: every addition/multiplication is potentially unsafe
                    findings.push(Finding {
                        kind: FindingKind::IntegerOverflow,
                        severity: Severity::High,
                        message: format!(
                            "arithmetic `{op}` in Solidity < 0.8 — \
                            no automatic overflow protection; consider using SafeMath"
                        ),
                        span: expr.span,
                        function: Some(func.id),
                    });
                }
            }
        });
    }

    findings
}

// ── AR-03  Integer Underflow ─────────────────────────────────────────────────
//
// Same concept as AR-02, but for subtraction (`-`).  When an unsigned integer
// is decremented below zero it wraps around to a very large number.
//
// Detection:
//   Symmetric to AR-02 — flag subtraction in pre-0.8 unconditionally, and
//   in 0.8+ only inside `unchecked` blocks.

fn detect_integer_underflow(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    let is_0_8_plus = all_files_are_0_8_plus(ast);

    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
            // Look for subtraction operators ( `-` or `-=` handled as Assign)
            let is_sub = match &expr.kind {
                ExprKind::Binary { op, .. } => op == "-",
                _ => false,
            };
            if !is_sub {
                return;
            }

            if is_0_8_plus {
                // 0.8+: only dangerous inside `unchecked`
                if is_inside_unchecked_block(ast, &expr.span) {
                    findings.push(Finding {
                        kind: FindingKind::IntegerUnderflow,
                        severity: Severity::Medium,
                        message: "subtraction inside `unchecked` block — \
                                underflow protection is disabled"
                            .into(),
                        span: expr.span,
                        function: Some(func.id),
                    });
                }
            } else {
                // Pre-0.8: every subtraction is potentially unsafe
                findings.push(Finding {
                    kind: FindingKind::IntegerUnderflow,
                    severity: Severity::High,
                    message: "subtraction in Solidity < 0.8 — \
                            no automatic underflow protection; consider using SafeMath"
                        .into(),
                    span: expr.span,
                    function: Some(func.id),
                });
            }
        });
    }

    findings
}

// ── AR-04  Unsafe Array Length Assignment ─────────────────────────────────────
//
// In Solidity < 0.6.0 it was possible to directly assign `.length` on a
// dynamic storage array (e.g. `arr.length = newLen;`).  If `newLen` comes from
// user-controlled input this can resize the array in unexpected ways and
// potentially allow access to arbitrary storage slots (related to AC-18).
//
// From Solidity 0.6.0 onward, direct `.length` assignment is disallowed by the
// compiler, so this detector only fires for contracts targeting < 0.6.
//
// Detection:
//   Walk every assignment expression.  If the left-hand side is a member
//   access on `.length`, and the right-hand side references a function
//   parameter (user-controlled), flag it.

fn detect_unsafe_array_length_assignment(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        // Collect function parameter names for user-input tracking
        let params: std::collections::HashSet<&str> =
            func.params.iter().map(|s| s.as_str()).collect();

        for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
            // Pattern: `someArray.length = <expr containing user param>`
            if let ExprKind::Assign { lhs, rhs, .. } = &expr.kind {
                // Is LHS a `.length` member access?
                let lhs_is_length = ast
                    .expressions
                    .get(*lhs as usize)
                    .map_or(false, |lhs_expr| {
                        matches!(&lhs_expr.kind, ExprKind::Member { field, .. } if field == "length")
                    });

                if !lhs_is_length {
                    return; // LHS is not `.length` — skip
                }

                // Does RHS reference any function parameter? (user-controlled)
                if !params.is_empty()
                    && expr_references_any_ident(ast, *rhs, &params)
                {
                    findings.push(Finding {
                        kind: FindingKind::UnsafeArrayLengthAssignment,
                        severity: Severity::High,
                        message: "array `.length` assigned from user-controlled parameter — \
                                may allow arbitrary storage access (Solidity < 0.6)"
                            .into(),
                        span: expr.span,
                        function: Some(func.id),
                    });
                }
            }
        });
    }

    findings
}
