//! Storage & Memory detectors (SM-01 through SM-07)
//! 7 vulnerability detectors covering:
//!   SM-01 – Arbitrary Function Jump via Inline Assembly
//!   SM-02 – Bytes Variables Risk (`msg.data` ABI encoding)
//!   SM-03 – Dangerous Usage of `msg.value` inside a Loop
//!   SM-04 – Error-prone Assembly Usage
//!   SM-05 – Memory Manipulation (assembly mstore/mload)
//!   SM-06 – Modifying Storage Array by Value
//!   SM-07 – Payable Functions using `delegatecall` inside a Loop

use chainvet_core::norm::{
    CallOption, CallTarget, ChainSegment, ExprKind, Mutability, NormalizedAst, StmtKind,
};

use super::{Finding, FindingKind, Severity};

// ═══════════════════════════════════════════════════════════════════════════════
//  Entry point
// ═══════════════════════════════════════════════════════════════════════════════

/// Run all 7 Storage & Memory detectors and return their findings.
pub fn detect_all(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(detect_arbitrary_function_jump(ast)); // SM-01
    findings.extend(detect_bytes_variables_risk(ast)); // SM-02
    findings.extend(detect_msg_value_in_loop(ast)); // SM-03
    findings.extend(detect_error_prone_assembly(ast)); // SM-04
    findings.extend(detect_memory_manipulation(ast)); // SM-05
    findings.extend(detect_storage_array_by_value(ast)); // SM-06
    findings.extend(detect_delegatecall_in_loop(ast)); // SM-07

    findings
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helper utilities  (expression & statement walkers)
// ═══════════════════════════════════════════════════════════════════════════════

// ── Expression walkers ───────────────────────────────────────────────────────

/// Walk every expression reachable from a statement tree, calling `cb` on each.
fn for_each_expr_in_stmt(
    ast: &NormalizedAst,
    stmt_id: u32,
    cb: &mut impl FnMut(u32, &chainvet_core::norm::Expr),
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

// ── Expression-level predicates ──────────────────────────────────────────────

/// Returns `true` if `expr_id` is (or contains) `msg.value`.
/// Checks two representations:
///   1. Chain metadata `[Ident("msg"), Member("value")]`
///   2. `ExprKind::Member { base: Ident("msg"), field: "value" }`
fn contains_msg_value(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };

    // Chain metadata: msg.value
    if let Some(chain) = expr.meta.chain.as_deref() {
        if chain.len() == 2 {
            if let (ChainSegment::Ident(base), ChainSegment::Member(member)) =
                (&chain[0], &chain[1])
            {
                if base == "msg" && member == "value" {
                    return true;
                }
            }
        }
    }

    // Member AST node: msg.value
    if let ExprKind::Member { base, field } = &expr.kind {
        if field == "value" {
            if let Some(base_expr) = ast.expressions.get(*base as usize) {
                if let ExprKind::Ident(name) = &base_expr.kind {
                    if name == "msg" {
                        return true;
                    }
                }
            }
        }
    }

    // Recurse into sub-expressions
    recurse_contains(ast, expr, contains_msg_value)
}

/// Returns `true` if `expr_id` is (or contains) `msg.data`.
/// Checks both chain metadata and Member AST node representations.
fn contains_msg_data(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };

    // Chain metadata: msg.data
    if let Some(chain) = expr.meta.chain.as_deref() {
        if chain.len() == 2 {
            if let (ChainSegment::Ident(base), ChainSegment::Member(member)) =
                (&chain[0], &chain[1])
            {
                if base == "msg" && member == "data" {
                    return true;
                }
            }
        }
    }

    // Member AST node: msg.data
    if let ExprKind::Member { base, field } = &expr.kind {
        if field == "data" {
            if let Some(base_expr) = ast.expressions.get(*base as usize) {
                if let ExprKind::Ident(name) = &base_expr.kind {
                    if name == "msg" {
                        return true;
                    }
                }
            }
        }
    }

    recurse_contains(ast, expr, contains_msg_data)
}

/// Returns `true` if `expr_id` contains a call to `delegatecall`.
/// Checks:
///   1. CallMeta with target name == "delegatecall"
///   2. ExprKind::Member with field == "delegatecall" (callee of a Call)
fn contains_delegatecall(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };

    // Strategy 1: CallMeta target name
    if let Some(call) = &expr.meta.call {
        let name = call_target_name(call);
        if name == "delegatecall" {
            return true;
        }
    }

    // Strategy 2: Call whose callee is a Member { field: "delegatecall" }
    if let ExprKind::Call { callee, .. } = &expr.kind {
        if let Some(callee_expr) = ast.expressions.get(*callee as usize) {
            if let ExprKind::Member { field, .. } = &callee_expr.kind {
                if field == "delegatecall" {
                    return true;
                }
            }
        }
    }

    recurse_contains(ast, expr, contains_delegatecall)
}

/// Generic recursive descent into sub-expressions.
/// `pred` is the specific predicate that checks a *single* expression.
fn recurse_contains(
    ast: &NormalizedAst,
    expr: &chainvet_core::norm::Expr,
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
fn call_target_name(call: &chainvet_core::norm::CallMeta) -> &str {
    match &call.target {
        CallTarget::Direct { name } => name.as_str(),
        CallTarget::Member { name, .. } => name.as_str(),
        CallTarget::Unknown => "",
    }
}

// ── Loop-body helpers ────────────────────────────────────────────────────────

/// Collect all statement ids that form the body of a loop (while, dowhile, for).
/// Returns `true` if `stmt_id` is inside a loop body and calls `cb` for each
/// expression inside that loop body.
fn for_each_expr_in_loop_bodies(
    ast: &NormalizedAst,
    stmt_id: u32,
    cb: &mut impl FnMut(u32, &chainvet_core::norm::Expr, &chainvet_core::norm::Span),
) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else {
        return;
    };

    match &stmt.kind {
        // For loops: walk the body and look for expressions
        StmtKind::For { body, .. } => {
            for_each_expr_in_stmt(ast, *body, &mut |eid, expr| {
                cb(eid, expr, &stmt.span);
            });
            // Also recurse to find nested loops inside the body
            for_each_nested_loops(ast, *body, cb);
        }
        // While loops
        StmtKind::While { body, .. } => {
            for_each_expr_in_stmt(ast, *body, &mut |eid, expr| {
                cb(eid, expr, &stmt.span);
            });
            for_each_nested_loops(ast, *body, cb);
        }
        // Do-while loops
        StmtKind::DoWhile { body, .. } => {
            for_each_expr_in_stmt(ast, *body, &mut |eid, expr| {
                cb(eid, expr, &stmt.span);
            });
            for_each_nested_loops(ast, *body, cb);
        }
        // Block: recurse into children to find loops
        StmtKind::Block(stmts) => {
            for &s in stmts {
                for_each_expr_in_loop_bodies(ast, s, cb);
            }
        }
        // If: recurse into branches to find loops
        StmtKind::If {
            then_id, else_id, ..
        } => {
            for_each_expr_in_loop_bodies(ast, *then_id, cb);
            if let Some(e) = else_id {
                for_each_expr_in_loop_bodies(ast, *e, cb);
            }
        }
        // Try: recurse into clauses
        StmtKind::Try { clauses, .. } => {
            for clause in clauses {
                for_each_expr_in_loop_bodies(ast, clause.body, cb);
            }
        }
        _ => {}
    }
}

/// Recurse into the body of a loop to find nested loops.
fn for_each_nested_loops(
    ast: &NormalizedAst,
    stmt_id: u32,
    cb: &mut impl FnMut(u32, &chainvet_core::norm::Expr, &chainvet_core::norm::Span),
) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else {
        return;
    };
    match &stmt.kind {
        StmtKind::Block(stmts) => {
            for &s in stmts {
                for_each_expr_in_loop_bodies(ast, s, cb);
            }
        }
        StmtKind::If {
            then_id, else_id, ..
        } => {
            for_each_expr_in_loop_bodies(ast, *then_id, cb);
            if let Some(e) = else_id {
                for_each_expr_in_loop_bodies(ast, *e, cb);
            }
        }
        StmtKind::For { .. } | StmtKind::While { .. } | StmtKind::DoWhile { .. } => {
            // Found a nested loop — process it
            for_each_expr_in_loop_bodies(ast, stmt_id, cb);
        }
        _ => {}
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Detectors SM-01 … SM-07
// ═══════════════════════════════════════════════════════════════════════════════

// ── SM-01  Arbitrary Function Jump via Inline Assembly ───────────────────────
//
// Inline assembly can modify the logic of `memory` function-type
// variables by overwriting the corresponding memory, causing unexpected
// behaviour.  Any function containing inline assembly that also uses
// function-type parameters or variables is risky because the assembly
// can alter the function pointer stored in memory.
//
// Detection:
//   Walk every function body.  If the body contains an `InlineAsm`
//   statement, flag it — inline assembly can arbitrarily modify
//   memory including function pointers.
//
// Severity: High — an attacker could redirect control flow.

fn detect_arbitrary_function_jump(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        // Track whether we found inline assembly in this function
        let mut has_asm = false;
        let mut asm_span = None;

        // Walk all statements looking for InlineAsm nodes
        for_each_stmt(ast, body, &mut |_sid, stmt| {
            if let StmtKind::InlineAsm { .. } = &stmt.kind {
                has_asm = true;
                asm_span = Some(stmt.span);
            }
        });

        // If found, also check whether the function has memory/function-type
        // parameters. We flag inline assembly that could manipulate memory
        // function-type variables. Since we can't precisely determine the
        // type of parameters from NormalizedAst alone, we flag every
        // InlineAsm as a potential arbitrary jump risk.
        if has_asm {
            let func_name = func.name.as_deref().unwrap_or("<anonymous>");
            findings.push(Finding {
                kind: FindingKind::ArbitraryFunctionJump,
                severity: Severity::High,
                message: format!(
                    "function `{func_name}` uses inline assembly, which can modify \
                    memory-based function pointers and cause arbitrary function jumps; \
                    this may lead to redirected control flow"
                ),
                span: asm_span.unwrap_or(func.span),
                function: Some(func.id),
            });
        }
    }

    findings
}

// ── SM-02  Bytes Variables Risk ──────────────────────────────────────────────
//
// `msg.data` is ABI-encoded.  If the data is too long or short but
// still passes validation, bytes of an ABI-encoded variable will be
// padded or truncated at the low-order bytes.  Different `msg.data`
// payloads may therefore produce the same value when assigned.
//
// Detection:
//   Walk every function body.  If any expression references `msg.data`,
//   flag it — the raw calldata may produce unexpected byte values
//   after ABI decoding.
//
// Severity: Medium — can lead to silent data corruption / collisions.

fn detect_bytes_variables_risk(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        for_each_expr_in_stmt(ast, body, &mut |eid, _expr| {
            if contains_msg_data(ast, eid) {
                let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                findings.push(Finding {
                    kind: FindingKind::BytesVariablesRisk,
                    severity: Severity::Medium,
                    message: format!(
                        "function `{func_name}` uses `msg.data`; ABI encoding may \
                        pad or truncate low-order bytes, so different calldata \
                        payloads can produce the same decoded value"
                    ),
                    span: _expr.span,
                    function: Some(func.id),
                });
            }
        });
    }

    findings
}

// ── SM-03  Dangerous Usage of `msg.value` inside a Loop ─────────────────────
//
// When `msg.value` is used inside a loop, the same value is credited
// on every iteration rather than being split. This leads to double-
// (or multi-) counting of the ETH sent in a single transaction.
//
// Example:
//   for (uint i = 0; i < receivers.length; i++) {
//       balances[receivers[i]] += msg.value;   // same msg.value each time!
//   }
//
// Detection:
//   1. Walk every function body.
//   2. For each loop (for / while / do-while), check whether the loop
//      body contains `msg.value`.
//   3. Flag if found — the value is re-used on each iteration.
//
// Severity: High — direct financial loss (ETH credited N times).

fn detect_msg_value_in_loop(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        // Walk the function body and for each loop, check the loop body
        // for msg.value references.
        for_each_expr_in_loop_bodies(ast, body, &mut |eid, _expr, loop_span| {
            if contains_msg_value(ast, eid) {
                let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                findings.push(Finding {
                    kind: FindingKind::MsgValueInLoop,
                    severity: Severity::High,
                    message: format!(
                        "function `{func_name}` uses `msg.value` inside a loop; \
                        the same `msg.value` is credited on every iteration, \
                        leading to double-counting of Ether sent"
                    ),
                    span: *loop_span,
                    function: Some(func.id),
                });
            }
        });
    }

    // Deduplicate: only keep one finding per (function, loop_span) pair
    findings.dedup_by(|a, b| a.function == b.function && a.span == b.span);

    findings
}

// ── SM-04  Error-prone Assembly Usage ────────────────────────────────────────
//
// The use of inline assembly is error-prone and should be avoided.
// It bypasses Solidity's safety checks (overflow, access control, etc.)
// and makes the code harder to audit and maintain.
//
// Detection:
//   Walk every function body.  If any `InlineAsm` statement is found,
//   flag it as a low-severity warning.
//
// Severity: Low — informational warning about risky patterns.

fn detect_error_prone_assembly(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        for_each_stmt(ast, body, &mut |_sid, stmt| {
            if let StmtKind::InlineAsm { language } = &stmt.kind {
                let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                let lang_info = language
                    .as_deref()
                    .map(|l| format!(" (language: {l})"))
                    .unwrap_or_default();
                findings.push(Finding {
                    kind: FindingKind::ErrorProneAssembly,
                    severity: Severity::Low,
                    message: format!(
                        "function `{func_name}` uses inline assembly{lang_info}; \
                        assembly bypasses Solidity safety checks and is error-prone \
                        — use high-level Solidity constructs when possible"
                    ),
                    span: stmt.span,
                    function: Some(func.id),
                });
            }
        });
    }

    findings
}

// ── SM-05  Memory Manipulation ──────────────────────────────────────────────
//
// Memory manipulation vulnerabilities occur when a contract's memory-
// related operations are improperly handled via inline assembly.
// Using `mstore` / `mload` in assembly to directly modify state
// variables or function-type pointers can lead to unintended behavior.
//
// Detection:
//   Walk every function body.  If the function contains both:
//     (a) an `InlineAsm` statement, AND
//     (b) a state-variable assignment (Assign with an Ident that
//         matches a contract state variable)
//   then flag it — the assembly may be directly manipulating memory
//   to modify contract state in unsafe ways.
//
//   Also flag any inline assembly in a function that declares
//   memory arrays (via `new`), since assembly could overwrite them.
//
// Severity: High — can corrupt contract state.

fn detect_memory_manipulation(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Collect all state-variable names for fast lookup
    let state_var_names: std::collections::HashSet<String> =
        ast.state_vars.iter().map(|sv| sv.name.clone()).collect();

    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        // Check 1: Does the function contain InlineAsm?
        let mut has_asm = false;
        let mut asm_span = None;

        for_each_stmt(ast, body, &mut |_sid, stmt| {
            if let StmtKind::InlineAsm { .. } = &stmt.kind {
                has_asm = true;
                if asm_span.is_none() {
                    asm_span = Some(stmt.span);
                }
            }
        });

        if !has_asm {
            continue;
        }

        // Check 2: Does the function body reference a state variable
        // or create memory arrays?
        let mut references_state = false;
        let mut has_memory_array = false;

        for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
            // Check for state-variable references
            if let ExprKind::Ident(name) = &expr.kind {
                if state_var_names.contains(name) {
                    references_state = true;
                }
            }
            // Check for memory array creation: `new uint[](n)`
            if let ExprKind::New { .. } = &expr.kind {
                has_memory_array = true;
            }
        });

        if references_state || has_memory_array {
            let func_name = func.name.as_deref().unwrap_or("<anonymous>");
            let detail = if references_state && has_memory_array {
                "references state variables and creates memory arrays"
            } else if references_state {
                "references state variables"
            } else {
                "creates memory arrays"
            };
            findings.push(Finding {
                kind: FindingKind::MemoryManipulation,
                severity: Severity::High,
                message: format!(
                    "function `{func_name}` uses inline assembly and {detail}; \
                    assembly `mstore`/`mload` can improperly modify memory or \
                    storage, leading to unintended state changes or security risks"
                ),
                span: asm_span.unwrap_or(func.span),
                function: Some(func.id),
            });
        }
    }

    findings
}

// ── SM-06  Modifying Storage Array by Value ─────────────────────────────────
//
// When arrays are passed to a function that expects a reference to
// a storage array, they should be tested to ensure the expected result.
// Usually, `memory` is used in function parameters, and assignment to
// storage variables should be made inside the function body.
//
// If a function parameter is declared as `memory` for an array type,
// and the body assigns it to a storage variable (or vice versa), the
// developer may get unexpected results because `memory` arrays are
// copies, not references.
//
// Detection:
//   Walk every function.  If a function parameter name contains
//   array-like hints AND the body assigns *to* a state variable using
//   that parameter (or assigns *from* a state variable into a local),
//   flag it as a potential storage-array-by-value issue.
//
// Severity: Medium — silent logic bugs; modifications to the copy
// are not reflected in storage.

fn detect_storage_array_by_value(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Collect all state-variable names for lookup
    let state_var_names: std::collections::HashSet<String> =
        ast.state_vars.iter().map(|sv| sv.name.clone()).collect();

    for func in &ast.functions {
        let Some(body) = func.body else { continue };

        // Get function parameter names
        let param_names: std::collections::HashSet<&str> =
            func.params.iter().map(|p| p.as_str()).collect();

        if param_names.is_empty() {
            continue;
        }

        // Walk the body looking for assignments where:
        //  - LHS is a state variable and RHS references a parameter, OR
        //  - LHS references a parameter and RHS is a state variable
        // This heuristic catches patterns where array data flows between
        // memory (parameters) and storage.
        for_each_expr_in_stmt(ast, body, &mut |_eid, expr| {
            if let ExprKind::Assign { lhs, rhs, .. } = &expr.kind {
                let lhs_is_state = is_state_var_ref(ast, *lhs, &state_var_names);
                let rhs_is_param = is_param_ref(ast, *rhs, &param_names);
                let lhs_is_param = is_param_ref(ast, *lhs, &param_names);
                let rhs_is_state = is_state_var_ref(ast, *rhs, &state_var_names);

                // Pattern: stateVar = paramArray  (memory copy into storage)
                if lhs_is_state && rhs_is_param {
                    let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                    findings.push(Finding {
                        kind: FindingKind::StorageArrayByValue,
                        severity: Severity::Medium,
                        message: format!(
                            "function `{func_name}` assigns a memory parameter to a \
                            storage variable; modifications to the memory copy will \
                            not be reflected in storage — ensure this is intentional"
                        ),
                        span: expr.span,
                        function: Some(func.id),
                    });
                }

                // Pattern: localVar = stateArray  (storage → memory copy)
                if lhs_is_param && rhs_is_state {
                    let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                    findings.push(Finding {
                        kind: FindingKind::StorageArrayByValue,
                        severity: Severity::Medium,
                        message: format!(
                            "function `{func_name}` assigns a storage variable to a \
                            memory parameter; the parameter holds a copy, not a \
                            reference — changes to it will not modify storage"
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

/// Check if an expression is a direct reference to a state variable.
fn is_state_var_ref(
    ast: &NormalizedAst,
    expr_id: u32,
    state_var_names: &std::collections::HashSet<String>,
) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };
    if let ExprKind::Ident(name) = &expr.kind {
        return state_var_names.contains(name);
    }
    // Also check indexed access: stateVar[i]
    if let ExprKind::Index { base, .. } = &expr.kind {
        return is_state_var_ref(ast, *base, state_var_names);
    }
    false
}

/// Check if an expression is a direct reference to a function parameter.
fn is_param_ref(
    ast: &NormalizedAst,
    expr_id: u32,
    param_names: &std::collections::HashSet<&str>,
) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };
    if let ExprKind::Ident(name) = &expr.kind {
        return param_names.contains(name.as_str());
    }
    // Also check indexed access: param[i]
    if let ExprKind::Index { base, .. } = &expr.kind {
        return is_param_ref(ast, *base, param_names);
    }
    false
}

// ── SM-07  Payable Functions using `delegatecall` inside a Loop ─────────────
//
// When `delegatecall` is used in a payable function inside a loop,
// `msg.value` is forwarded to each delegatecall.  The same Ether
// amount is therefore "spent" on every iteration, allowing the balance
// to be credited multiple times even though only one payment was made.
//
// Example:
//   function bad(address[] memory receivers) public payable {
//       for (uint i = 0; i < receivers.length; i++) {
//           address(this).delegatecall(
//               abi.encodeWithSignature("addBalance(address)", receivers[i])
//           );
//       }
//   }
//
// Detection:
//   1. Find all payable functions.
//   2. For each payable function, walk the body looking for loops.
//   3. If a loop body contains a `delegatecall`, flag the function.
//
// Severity: High — direct financial loss (Ether credited N times).

fn detect_delegatecall_in_loop(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        // Only check payable functions — non-payable functions cannot
        // receive Ether, so msg.value is 0 and the risk is mitigated.
        if func.mutability != Mutability::Payable {
            continue;
        }

        let Some(body) = func.body else { continue };

        // Walk the function body and for each loop expression, check
        // whether it contains delegatecall.
        let mut found = false;
        for_each_expr_in_loop_bodies(ast, body, &mut |eid, _expr, loop_span| {
            if !found && contains_delegatecall(ast, eid) {
                let func_name = func.name.as_deref().unwrap_or("<anonymous>");
                findings.push(Finding {
                    kind: FindingKind::DelegatecallInLoop,
                    severity: Severity::High,
                    message: format!(
                        "payable function `{func_name}` uses `delegatecall` inside \
                        a loop; `msg.value` is forwarded on every iteration, so the \
                        same Ether amount is credited multiple times"
                    ),
                    span: *loop_span,
                    function: Some(func.id),
                });
                found = true;
            }
        });
    }

    findings
}
