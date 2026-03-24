//! Block Manipulation detectors (BM-01 through BM-03)
//! 3 vulnerability detectors covering:
//!   BM-01 – Dangerous usage of `block.timestamp`
//!   BM-02 – Transaction Order Dependency (TOD / front-running)
//!   BM-03 – Weak PRNG (pseudorandom number generator)

use crate::norm::{
    CallOption, CallTarget, ChainSegment, ExprKind, NormalizedAst, Span, StmtKind, Visibility,
};

use super::{Finding, FindingKind, Severity};

// ═══════════════════════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// Function names that are commonly used to transfer value or tokens.
/// These are the "sensitive" calls that become dangerous when their
/// execution order can be influenced by miners (TOD / front-running).
const TRANSFER_METHODS: &[&str] = &[
    "transfer",
    "transferFrom",
    "send",
    "call",
    "delegatecall",
    "approve",
    "safeTransferFrom",
];

/// State-variable name fragments that typically hold a price, rate, or
/// balance – values whose on-chain ordering matters.
const ORDER_SENSITIVE_VAR_HINTS: &[&str] = &[
    "price",
    "rate",
    "reward",
    "allowance",
    "allowances",
    "allow",
    "allowed",
    "approval",
    "approved",
    "nonce",
    "bid",
    "bids",
    "auction",
    "quote",
];

// ═══════════════════════════════════════════════════════════════════════════════
//  Entry point
// ═══════════════════════════════════════════════════════════════════════════════

/// Run all 3 Block Manipulation detectors and return their findings.
pub fn detect_all(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(detect_dangerous_timestamp(ast)); // BM-01
    findings.extend(detect_transaction_order_dependency(ast)); // BM-02
    findings.extend(detect_weak_prng(ast)); // BM-03

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
    fn price_based_transfer_still_emits_tod() {
        let ast = parse(
            r#"
            pragma solidity ^0.4.24;
            contract Sale {
                uint public price;
                function buy() public payable {
                    require(msg.value >= price);
                    msg.sender.transfer(price);
                }
            }
            "#,
        );

        let findings = detect_transaction_order_dependency(&ast);
        assert!(
            findings
                .iter()
                .any(|finding| { finding.kind == FindingKind::TransactionOrderDependency })
        );
    }

    #[test]
    fn balance_based_withdraw_does_not_emit_tod() {
        let ast = parse(
            r#"
            pragma solidity ^0.4.24;
            contract Wallet {
                mapping(address => uint256) balances;
                function withdraw(uint256 amount) public {
                    require(amount <= balances[msg.sender]);
                    msg.sender.transfer(amount);
                    balances[msg.sender] -= amount;
                }
            }
            "#,
        );

        let findings = detect_transaction_order_dependency(&ast);
        assert!(
            findings.is_empty(),
            "ordinary balance accounting should not be treated as transaction-order dependency"
        );
    }

    #[test]
    fn timestamp_return_comparison_emits_bm01() {
        let ast = parse(
            r#"
            pragma solidity ^0.4.24;
            contract TimedCrowdsale {
                function isSaleFinished() public view returns (bool) {
                    return block.timestamp >= 1546300800;
                }
            }
            "#,
        );

        let findings = detect_dangerous_timestamp(&ast);
        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == FindingKind::DangerousBlockTimestamp)
        );
    }

    #[test]
    fn logging_timestamp_assignment_does_not_emit_bm01() {
        let ast = parse(
            r#"
            pragma solidity ^0.4.24;
            contract Logger {
                struct Message { uint time; }
                Message lastMsg;
                function addMessage() public {
                    lastMsg.time = now;
                }
            }
            "#,
        );

        let findings = detect_dangerous_timestamp(&ast);
        assert!(
            findings.is_empty(),
            "plain bookkeeping assignments from `now` should not emit timestamp dependency"
        );
    }

    #[test]
    fn migrate_named_function_does_not_trip_rate_hint() {
        let ast = parse(
            r#"
            pragma solidity ^0.4.24;
            contract Wallet {
                address creator;
                constructor() public { creator = msg.sender; }
                function migrateTo(address to) public {
                    require(creator == msg.sender);
                    to.transfer(address(this).balance);
                }
            }
            "#,
        );

        let findings = detect_transaction_order_dependency(&ast);
        assert!(
            findings.is_empty(),
            "identifier substring matches like `migrateTo` should not trigger TOD hints"
        );
    }
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

// ── Block-value detection helpers ────────────────────────────────────────────

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

fn source_identifier_tokens(lower: &str) -> impl Iterator<Item = &str> {
    lower
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|token| !token.is_empty())
}

fn source_contains_transfer_call(lower: &str) -> bool {
    [
        ".transfer(",
        ".transferfrom(",
        ".send(",
        ".call(",
        ".approve(",
        ".safetransferfrom(",
        ".delegatecall(",
    ]
    .iter()
    .any(|pattern| lower.contains(pattern))
}

fn source_contains_order_sensitive_hint(lower: &str) -> bool {
    source_identifier_tokens(lower)
        .any(|token| ORDER_SENSITIVE_VAR_HINTS.iter().any(|hint| token == *hint))
}

/// Returns `true` if `expr_id` is (or contains) `block.timestamp` or `now`.
/// Checks three representations that the normalizer may produce:
///   1. Chain metadata `[Ident("block"), Member("timestamp")]`
///   2. `ExprKind::Member { base: Ident("block"), field: "timestamp" }`
///   3. `ExprKind::Ident("now")` (pre-0.7 alias for `block.timestamp`)
fn contains_timestamp(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };

    // Direct `now` keyword
    if let ExprKind::Ident(name) = &expr.kind {
        if name == "now" {
            return true;
        }
    }

    // Chain metadata: block.timestamp
    if let Some(chain) = expr.meta.chain.as_deref() {
        if chain.len() == 2 {
            if let (ChainSegment::Ident(base), ChainSegment::Member(member)) =
                (&chain[0], &chain[1])
            {
                if base == "block" && member == "timestamp" {
                    return true;
                }
            }
        }
    }

    // Member AST node: block.timestamp
    if let ExprKind::Member { base, field } = &expr.kind {
        if field == "timestamp" {
            if let Some(base_expr) = ast.expressions.get(*base as usize) {
                if let ExprKind::Ident(name) = &base_expr.kind {
                    if name == "block" {
                        return true;
                    }
                }
            }
        }
    }

    // Recurse into sub-expressions
    recurse_contains(ast, expr, contains_timestamp)
}

/// Returns `true` if `expr_id` is (or contains) `block.difficulty`
/// (also known as `block.prevrandao` since The Merge, but still miner-
/// influenceable on PoW chains and predictable on PoS chains).
fn contains_block_difficulty(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };

    // Chain metadata: block.difficulty OR block.prevrandao
    if let Some(chain) = expr.meta.chain.as_deref() {
        if chain.len() == 2 {
            if let (ChainSegment::Ident(base), ChainSegment::Member(member)) =
                (&chain[0], &chain[1])
            {
                if base == "block" && (member == "difficulty" || member == "prevrandao") {
                    return true;
                }
            }
        }
    }

    // Member AST node: block.difficulty | block.prevrandao
    if let ExprKind::Member { base, field } = &expr.kind {
        if field == "difficulty" || field == "prevrandao" {
            if let Some(base_expr) = ast.expressions.get(*base as usize) {
                if let ExprKind::Ident(name) = &base_expr.kind {
                    if name == "block" {
                        return true;
                    }
                }
            }
        }
    }

    recurse_contains(ast, expr, contains_block_difficulty)
}

/// Returns `true` if `expr_id` is (or contains) a call to `blockhash(...)`.
fn contains_blockhash(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };

    // Direct call: blockhash(number)
    if let Some(call) = &expr.meta.call {
        if let CallTarget::Direct { name } = &call.target {
            if name == "blockhash" {
                return true;
            }
        }
    }
    // Ident node named "blockhash" (callee before Call resolution)
    if let ExprKind::Ident(name) = &expr.kind {
        if name == "blockhash" {
            return true;
        }
    }

    recurse_contains(ast, expr, contains_blockhash)
}

/// Returns `true` if the expression contains `block.number`.
fn contains_block_number(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };

    // Chain metadata: block.number
    if let Some(chain) = expr.meta.chain.as_deref() {
        if chain.len() == 2 {
            if let (ChainSegment::Ident(base), ChainSegment::Member(member)) =
                (&chain[0], &chain[1])
            {
                if base == "block" && member == "number" {
                    return true;
                }
            }
        }
    }

    // Member AST node: block.number
    if let ExprKind::Member { base, field } = &expr.kind {
        if field == "number" {
            if let Some(base_expr) = ast.expressions.get(*base as usize) {
                if let ExprKind::Ident(name) = &base_expr.kind {
                    if name == "block" {
                        return true;
                    }
                }
            }
        }
    }

    recurse_contains(ast, expr, contains_block_number)
}

/// Returns `true` if the expression contains **any** miner-influenceable
/// block value: `block.timestamp`, `now`, `block.difficulty`,
/// `block.prevrandao`, `blockhash(...)`, or `block.number`.
fn contains_any_block_value(ast: &NormalizedAst, expr_id: u32) -> bool {
    contains_timestamp(ast, expr_id)
        || contains_block_difficulty(ast, expr_id)
        || contains_blockhash(ast, expr_id)
        || contains_block_number(ast, expr_id)
}

/// Generic recursive descent into sub-expressions.
/// `pred` is the specific predicate that checks a *single* expression.
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

/// Extract the simple name from a `CallTarget`.
fn call_target_name(call: &crate::norm::CallMeta) -> &str {
    match &call.target {
        CallTarget::Direct { name } => name.as_str(),
        CallTarget::Member { name, .. } => name.as_str(),
        CallTarget::Unknown => "",
    }
}

/// Returns `true` when an expression tree contains a call to one of the
/// value-transfer methods listed in `TRANSFER_METHODS`.
fn expr_contains_transfer_call(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };

    // Strategy 1: Check call metadata (works when parser resolves target)
    if let Some(call) = &expr.meta.call {
        let name = call_target_name(call);
        if TRANSFER_METHODS.iter().any(|&m| m == name) {
            return true;
        }
    }

    // Strategy 2: Check `ExprKind::Call { callee: Member { field }, .. }`
    // This covers cases like `payable(addr).transfer(amt)` where the parser
    // produces CallTarget::Unknown but the callee is a Member expression
    // whose `field` is the actual method name.
    if let ExprKind::Call { callee, .. } = &expr.kind {
        if let Some(callee_expr) = ast.expressions.get(*callee as usize) {
            if let ExprKind::Member { field, .. } = &callee_expr.kind {
                if TRANSFER_METHODS.iter().any(|&m| m == field.as_str()) {
                    return true;
                }
            }
        }
    }

    match &expr.kind {
        ExprKind::Call { callee, args } => {
            expr_contains_transfer_call(ast, *callee)
                || args.iter().any(|&a| expr_contains_transfer_call(ast, a))
        }
        ExprKind::CallOptions { callee, options } => {
            expr_contains_transfer_call(ast, *callee)
                || options.iter().any(|opt| match opt {
                    CallOption::Value(e) | CallOption::Gas(e) | CallOption::Salt(e) => {
                        expr_contains_transfer_call(ast, *e)
                    }
                })
        }
        ExprKind::Binary { lhs, rhs, .. } => {
            expr_contains_transfer_call(ast, *lhs) || expr_contains_transfer_call(ast, *rhs)
        }
        ExprKind::Unary { expr, .. } => expr_contains_transfer_call(ast, *expr),
        ExprKind::Member { base, .. } => expr_contains_transfer_call(ast, *base),
        ExprKind::Assign { lhs, rhs, .. } => {
            expr_contains_transfer_call(ast, *lhs) || expr_contains_transfer_call(ast, *rhs)
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            expr_contains_transfer_call(ast, *cond)
                || expr_contains_transfer_call(ast, *then_expr)
                || expr_contains_transfer_call(ast, *else_expr)
        }
        _ => false,
    }
}

/// Returns `true` if an expression contains an identifier whose lowercase
/// name matches one of the `ORDER_SENSITIVE_VAR_HINTS` fragments.
fn expr_references_order_sensitive_var(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };

    if let ExprKind::Ident(name) = &expr.kind {
        let lower = name.to_lowercase();
        if ORDER_SENSITIVE_VAR_HINTS.iter().any(|h| lower.contains(h)) {
            return true;
        }
    }

    match &expr.kind {
        ExprKind::Binary { lhs, rhs, .. } => {
            expr_references_order_sensitive_var(ast, *lhs)
                || expr_references_order_sensitive_var(ast, *rhs)
        }
        ExprKind::Unary { expr, .. } => expr_references_order_sensitive_var(ast, *expr),
        ExprKind::Member { base, .. } => expr_references_order_sensitive_var(ast, *base),
        ExprKind::Call { callee, args } => {
            expr_references_order_sensitive_var(ast, *callee)
                || args
                    .iter()
                    .any(|&a| expr_references_order_sensitive_var(ast, a))
        }
        ExprKind::Assign { lhs, rhs, .. } => {
            expr_references_order_sensitive_var(ast, *lhs)
                || expr_references_order_sensitive_var(ast, *rhs)
        }
        _ => false,
    }
}

/// Returns `true` when a statement (or any of its children) contains a
/// call to one of the transfer methods.
fn stmt_contains_transfer(ast: &NormalizedAst, stmt_id: u32) -> bool {
    let mut found = false;
    for_each_expr_in_stmt(ast, stmt_id, &mut |eid, _expr| {
        if !found && expr_contains_transfer_call(ast, eid) {
            found = true;
        }
    });
    found
}

/// Describe which block-value source was found (for human-readable messages).
fn block_value_label(ast: &NormalizedAst, expr_id: u32) -> &'static str {
    if contains_timestamp(ast, expr_id) {
        return "block.timestamp / now";
    }
    if contains_block_difficulty(ast, expr_id) {
        return "block.difficulty / prevrandao";
    }
    if contains_blockhash(ast, expr_id) {
        return "blockhash()";
    }
    if contains_block_number(ast, expr_id) {
        return "block.number";
    }
    "block value"
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Detectors BM-01 … BM-03
// ═══════════════════════════════════════════════════════════════════════════════

// ── BM-01  Dangerous Usage of `block.timestamp` ─────────────────────────────
//
// `block.timestamp` (and its pre-0.7 alias `now`) can be slightly
// manipulated by miners (within the ~15-second tolerance).  Using it in
// conditionals, comparisons, or for access-control decisions is risky.
//
// Detection:
//   1. Walk every function body.
//   2. For each `if` / `while` / `for` condition, check whether the
//      condition expression contains `block.timestamp` or `now`.
//   3. Also flag boolean-ish return expressions like
//      `return block.timestamp >= SOME_DEADLINE`.
//   4. Flag any use of `block.timestamp` as an argument passed to another
//      function call (the callee might rely on it for logic).
//
// Severity: Low — the manipulation window is small, but the risk exists.

fn is_decision_like_expr(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };
    match &expr.kind {
        ExprKind::Binary { op, .. } => {
            matches!(
                op.as_str(),
                ">" | "<" | ">=" | "<=" | "==" | "!=" | "&&" | "||"
            )
        }
        ExprKind::Unary { op, .. } => op == "!",
        ExprKind::Conditional { .. } => true,
        _ => false,
    }
}

fn detect_dangerous_timestamp(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        // --- 1. Check conditionals (if / while / for conditions) ----------
        for_each_stmt(ast, body, &mut |_sid, stmt| {
            match &stmt.kind {
                // if (block.timestamp ...)
                StmtKind::If { cond, .. } => {
                    if contains_timestamp(ast, *cond) {
                        findings.push(Finding {
                            kind: FindingKind::DangerousBlockTimestamp,
                            severity: Severity::Low,
                            message: "dangerous use of `block.timestamp` / `now` in if-condition; \
                                miners can manipulate this value within ~15 seconds"
                                .into(),
                            span: stmt.span,
                            function: Some(func.id),
                        });
                    }
                }
                // while (block.timestamp ...)
                StmtKind::While { cond, .. } => {
                    if contains_timestamp(ast, *cond) {
                        findings.push(Finding {
                            kind: FindingKind::DangerousBlockTimestamp,
                            severity: Severity::Low,
                            message:
                                "dangerous use of `block.timestamp` / `now` in while-condition; \
                                miners can manipulate this value within ~15 seconds"
                                    .into(),
                            span: stmt.span,
                            function: Some(func.id),
                        });
                    }
                }
                // for (...; block.timestamp < ...; ...)
                StmtKind::For {
                    cond: Some(cond), ..
                } => {
                    if contains_timestamp(ast, *cond) {
                        findings.push(Finding {
                            kind: FindingKind::DangerousBlockTimestamp,
                            severity: Severity::Low,
                            message:
                                "dangerous use of `block.timestamp` / `now` in for-condition; \
                                miners can manipulate this value within ~15 seconds"
                                    .into(),
                            span: stmt.span,
                            function: Some(func.id),
                        });
                    }
                }
                _ => {}
            }
        });

        // --- 2. Check direct boolean-ish returns -------------------------
        for_each_stmt(ast, body, &mut |_sid, stmt| {
            if let StmtKind::Return(Some(expr_id)) = &stmt.kind
                && contains_timestamp(ast, *expr_id)
                && is_decision_like_expr(ast, *expr_id)
            {
                findings.push(Finding {
                    kind: FindingKind::DangerousBlockTimestamp,
                    severity: Severity::Low,
                    message: "`block.timestamp` / `now` used in returned decision logic; \
                        callers may rely on this miner-manipulable value"
                        .into(),
                    span: stmt.span,
                    function: Some(func.id),
                });
            }
        });

        // --- 3. Check `block.timestamp` passed as a call argument ---------
        for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
            if let ExprKind::Call { args, .. } = &expr.kind {
                for &arg in args {
                    if contains_timestamp(ast, arg) {
                        findings.push(Finding {
                            kind: FindingKind::DangerousBlockTimestamp,
                            severity: Severity::Low,
                            message: "`block.timestamp` / `now` passed as function argument; \
                                the called function may make decisions based on this \
                                miner-manipulable value"
                                .into(),
                            span: expr.span,
                            function: Some(func.id),
                        });
                        break; // one finding per call is enough
                    }
                }
            }
        });
    }

    findings
}

// ── BM-02  Transaction Order Dependency (TOD / Front-Running) ────────────────
//
// In the blockchain system, miners select which transactions to include
// in a block based on gas price.  The order in which transactions are
// finalized is therefore *not* the order of submission.  A "Transaction
// Order Dependency" (TOD) vulnerability exists when the result of a
// function depends on the order of execution relative to other
// transactions (e.g. reading a price from storage, then transferring
// value based on that price, without a commit-reveal scheme).
//
// Detection heuristic (static approximation):
//   For each public / external function:
//     1. Check whether the function body reads a state variable whose
//        name hints at an order-sensitive value (price, rate, reward, …).
//     2. Check whether the function body also performs a transfer /
//        send / call (value movement).
//     3. If both are true, flag the function — its outcome depends on
//        the order in which state-modifying transactions execute.
//
// Severity: Medium — front-running can cause direct financial loss.

fn detect_transaction_order_dependency(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        // Only flag externally callable functions (public / external).
        // Internal / private helpers are only dangerous if their callers
        // are public, but that would require inter-procedural analysis;
        // we keep it simple and match the function's own visibility.
        // Note: Visibility::Unknown defaults to public in Solidity, so
        // we include it to be conservative.
        match func.visibility {
            Visibility::Public | Visibility::External | Visibility::Unknown => {}
            _ => continue,
        }

        let Some(body) = func.body else { continue };
        let source_lower = function_source_lower(ast, func);

        // --- Step 1:  Does the body reference an order-sensitive var? ------
        let mut reads_sensitive = false;
        for_each_expr_in_stmt(ast, body, &mut |eid, _expr| {
            if !reads_sensitive && expr_references_order_sensitive_var(ast, eid) {
                reads_sensitive = true;
            }
        });
        if !reads_sensitive {
            if let Some(source_lower) = source_lower.as_deref() {
                reads_sensitive = source_contains_order_sensitive_hint(source_lower);
            }
        }

        // --- Step 2:  Does the body contain a value-transfer call? ---------
        let has_transfer = stmt_contains_transfer(ast, body)
            || source_lower
                .as_deref()
                .map(source_contains_transfer_call)
                .unwrap_or(false);

        if !reads_sensitive {
            continue;
        }
        if !has_transfer {
            continue;
        }

        // --- Step 3:  Both conditions met → report TOD --------------------
        let func_name = func.name.as_deref().unwrap_or("<anonymous>");

        findings.push(Finding {
            kind: FindingKind::TransactionOrderDependency,
            severity: Severity::Medium,
            message: format!(
                "function `{func_name}` reads an order-sensitive state variable \
                and performs a value transfer; its outcome depends on transaction \
                ordering (front-running / TOD risk)"
            ),
            span: func.span,
            function: Some(func.id),
        });
    }

    findings
}

// ── BM-03  Weak PRNG (Pseudorandom Number Generator) ────────────────────────
//
// `block.timestamp`, `now`, `block.difficulty` (`block.prevrandao`),
// `blockhash(...)`, and `block.number` are all either directly
// manipulable by miners or predictable.  Using any of them — alone or
// combined — as the source of randomness is insecure.
//
// Common dangerous patterns:
//   uint random = uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));
//   uint random = block.timestamp % 10;
//   uint random = uint(blockhash(block.number - 1));
//
// Detection:
//   Walk every expression in the function body.  If an arithmetic
//   operation (%, *, +, ^) or a hashing call (keccak256 / sha3 / sha256)
//   has **any** miner-influenceable block value among its operands,
//   report the finding.
//
// Severity: High — predictable randomness can be exploited by miners
// or observers to rig lotteries, token distributions, auctions, etc.

fn detect_weak_prng(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
            match &expr.kind {
                // Pattern A:  block_value % n  /  block_value * n  /  etc.
                // Any arithmetic binary operation whose operands include a
                // miner-influenceable block variable.
                ExprKind::Binary { op, lhs, rhs } => {
                    // Restrict to arithmetic / bitwise ops commonly used in
                    // PRNG constructions: %, *, +, -, ^, |, &, **, <<, >>
                    if !matches!(
                        op.as_str(),
                        "%" | "*" | "+" | "-" | "^" | "|" | "&" | "**" | "<<" | ">>"
                    ) {
                        return;
                    }

                    let lhs_block = contains_any_block_value(ast, *lhs);
                    let rhs_block = contains_any_block_value(ast, *rhs);

                    if lhs_block || rhs_block {
                        let label = if lhs_block {
                            block_value_label(ast, *lhs)
                        } else {
                            block_value_label(ast, *rhs)
                        };
                        findings.push(Finding {
                            kind: FindingKind::WeakPrng,
                            severity: Severity::High,
                            message: format!(
                                "weak PRNG: `{label}` used in arithmetic expression; \
                                miners can influence block values — do not use them \
                                as a source of randomness"
                            ),
                            span: expr.span,
                            function: Some(func.id),
                        });
                    }
                }

                // Pattern B:  keccak256(abi.encodePacked(block.timestamp, ...))
                // A hashing call whose arguments contain a block value.
                ExprKind::Call { callee: _, args } => {
                    if let Some(call) = &expr.meta.call {
                        let name = call_target_name(call);
                        // Common hash functions used to "mix" block values
                        if matches!(name, "keccak256" | "sha256" | "sha3" | "ripemd160") {
                            for &arg in args {
                                if contains_any_block_value(ast, arg) {
                                    let label = block_value_label(ast, arg);
                                    findings.push(Finding {
                                        kind: FindingKind::WeakPrng,
                                        severity: Severity::High,
                                        message: format!(
                                            "weak PRNG: `{label}` passed to `{name}()` \
                                            for randomness; miners can influence block \
                                            values — use Chainlink VRF or similar oracle"
                                        ),
                                        span: expr.span,
                                        function: Some(func.id),
                                    });
                                    break; // one finding per call
                                }
                            }
                        }
                    }
                }

                _ => {}
            }
        });
    }

    findings
}
