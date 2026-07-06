//! Miscellaneous detectors (MI-01, MI-02)
//! 2 detectors covering:
//!   MI-01 – Variable shadowing
//!   MI-02 – Tainted call arguments (from taint analysis)

use std::collections::HashSet;

use crate::analysis::taint::TaintSummary;
use chainvet_core::norm::{CallTarget, ExprKind, NormalizedAst, Span, StmtKind};

use super::{Confidence, Finding, FindingKind, Severity};

const NON_EXTERNAL_MEMBER_HELPERS: &[&str] = &["add", "sub", "mul", "div", "mod", "push", "pop"];

// ═══════════════════════════════════════════════════════════════════════════════
//  Entry point
// ═══════════════════════════════════════════════════════════════════════════════

/// Run all Miscellaneous detectors and return their findings.
pub fn detect_all(ast: &NormalizedAst, taint_summaries: &[TaintSummary]) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(detect_shadowing(ast)); // MI-01
    findings.extend(detect_taint(ast, taint_summaries)); // MI-02

    findings
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MI-01 – Variable shadowing
// ═══════════════════════════════════════════════════════════════════════════════

fn detect_shadowing(ast: &NormalizedAst) -> Vec<Finding> {
    let mut findings = Vec::new();

    for func in &ast.functions {
        if let Some(body) = func.body {
            let mut local_vars = HashSet::new();
            let state_var_names = func.contract.map(|cid| {
                ast.state_vars
                    .iter()
                    .filter(|sv| sv.contract == cid)
                    .map(|sv| sv.name.as_str())
                    .collect::<HashSet<_>>()
            });

            // Add function parameters to scope
            for param_name in &func.params {
                // Parameter shadows state variable with the same name.
                if state_var_names
                    .as_ref()
                    .map(|names| names.contains(param_name.as_str()))
                    .unwrap_or(false)
                {
                    findings.push(Finding {
                        kind: FindingKind::Shadowing,
                        confidence_override: None,
                        severity: Severity::Medium,
                        message: format!(
                            "parameter '{param_name}' shadows state variable with the same name"
                        ),
                        span: func.span,
                        function: Some(func.id),
                    });
                }
                local_vars.insert(param_name.clone());
            }

            // Check for shadowing in function body
            check_shadowing_in_stmt(
                ast,
                body,
                func.id,
                func.contract,
                &mut local_vars,
                &mut findings,
            );
        }
    }

    findings
}

fn check_shadowing_in_stmt(
    ast: &NormalizedAst,
    stmt_id: u32,
    function_id: u32,
    contract_id: Option<u32>,
    local_vars: &mut HashSet<String>,
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
                        confidence_override: None,
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
                                confidence_override: None,
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
                check_shadowing_in_stmt(
                    ast,
                    *child,
                    function_id,
                    contract_id,
                    local_vars,
                    findings,
                );
            }
        }
        StmtKind::If {
            then_id, else_id, ..
        } => {
            check_shadowing_in_stmt(
                ast,
                *then_id,
                function_id,
                contract_id,
                local_vars,
                findings,
            );
            if let Some(else_id) = else_id {
                check_shadowing_in_stmt(
                    ast,
                    *else_id,
                    function_id,
                    contract_id,
                    local_vars,
                    findings,
                );
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

// ═══════════════════════════════════════════════════════════════════════════════
//  MI-02 – Tainted call arguments
// ═══════════════════════════════════════════════════════════════════════════════

/// Decide whether a tainted call is worth surfacing and, if so, how confident
/// we are that it is a true positive. `None` drops the finding; `Some(conf)`
/// surfaces it. Confidence is derived from the sink: arbitrary-code /
/// arbitrary-external-call sinks (`delegatecall`/`call`) reached by
/// attacker-controlled data are the strongest signal, value transfers and
/// static calls are mid, and calls whose target we cannot resolve are weak.
fn classify_tainted_call(ast: &NormalizedAst, span: Span, uses_source: bool) -> Option<Confidence> {
    // A tainted call wrapped in an `emit` is an event emission, not an
    // external sink — never surface it.
    if ast.statements.iter().any(|stmt| match stmt.kind {
        StmtKind::Emit(_) => {
            stmt.span.file == span.file
                && stmt.span.start <= span.start
                && stmt.span.end >= span.end
        }
        _ => false,
    }) {
        return None;
    }

    let Some(expr) = ast
        .expressions
        .iter()
        .find(|expr| expr.span == span && matches!(expr.kind, ExprKind::Call { .. }))
    else {
        // Couldn't resolve the call expression — surface conservatively.
        return Some(Confidence::Low);
    };

    match expr.meta.call.as_ref().map(|call| &call.target) {
        Some(CallTarget::Direct { .. }) => None,
        Some(CallTarget::Member { name, receiver }) => {
            let is_helper = NON_EXTERNAL_MEMBER_HELPERS.contains(&name.as_str());
            let is_internal_receiver = receiver.last().is_some_and(|segment| {
                segment.eq_ignore_ascii_case("this") || segment.eq_ignore_ascii_case("super")
            });
            if is_helper || is_internal_receiver {
                return None;
            }
            sink_confidence(name.as_str(), uses_source)
        }
        // Unresolved target that still reaches a call: risky but unconfirmed.
        Some(CallTarget::Unknown) | None => Some(Confidence::Low),
    }
}

/// Confidence for a tainted member call given its sink method, or `None` when
/// the method is not a risky external sink (so the call is not surfaced).
/// `uses_source` marks taint that originates from attacker-controlled input,
/// which raises confidence on the arbitrary-execution sinks.
fn sink_confidence(name: &str, uses_source: bool) -> Option<Confidence> {
    match name {
        // Arbitrary code execution / arbitrary external call with tainted data.
        "delegatecall" | "call" => Some(if uses_source {
            Confidence::High
        } else {
            Confidence::Medium
        }),
        // Value transfer or read-only call with a tainted target/amount.
        "staticcall" | "send" | "transfer" => Some(Confidence::Medium),
        // Not in RISKY_EXTERNAL_MEMBER_CALLS — do not surface.
        _ => None,
    }
}

fn detect_taint(ast: &NormalizedAst, summaries: &[TaintSummary]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for summary in summaries {
        for span in &summary.tainted_calls {
            let Some(confidence) = classify_tainted_call(ast, *span, summary.uses_source) else {
                continue;
            };
            findings.push(Finding {
                kind: FindingKind::TaintedCall,
                confidence_override: Some(confidence),
                severity: Severity::High,
                message: "call with tainted arguments".to_string(),
                span: *span,
                function: Some(summary.function_id),
            });
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use chainvet_core::norm::SourceFile;
    use chainvet_frontend::frontend::parser::load_via_parser_sources;

    fn parse(source: &str) -> NormalizedAst {
        load_via_parser_sources(vec![SourceFile {
            id: 0,
            path: "test.sol".to_string(),
            source: source.to_string(),
        }])
        .expect("parser should succeed")
    }

    fn substring_span(source: &str, needle: &str) -> Span {
        let start = source.find(needle).expect("needle should exist") as u32;
        Span {
            file: 0,
            start,
            end: start + needle.len() as u32,
        }
    }

    #[test]
    fn emit_event_call_is_not_surfaced_as_tainted_call() {
        let source = r#"
            pragma solidity ^0.4.24;
            contract ERC20 {
                event Approval(address indexed owner, address indexed spender, uint256 value);
                function approve(address spender, uint256 value) public returns (bool) {
                    emit Approval(msg.sender, spender, value);
                    return true;
                }
            }
        "#;
        let ast = parse(source);
        let summaries = vec![TaintSummary {
            function_id: 0,
            tainted_vars: Vec::new(),
            tainted_calls: vec![substring_span(
                source,
                "Approval(msg.sender, spender, value)",
            )],
            uses_source: true,
        }];

        let findings = detect_taint(&ast, &summaries);
        assert!(
            findings.is_empty(),
            "event emissions should not surface as tainted external calls"
        );
    }

    #[test]
    fn external_member_call_still_surfaces_as_tainted_call() {
        let source = r#"
            pragma solidity ^0.4.24;
            contract Vault {
                function run(address target, bytes data) public {
                    target.call(data);
                }
            }
        "#;
        let ast = parse(source);
        let summaries = vec![TaintSummary {
            function_id: 0,
            tainted_vars: Vec::new(),
            tainted_calls: vec![substring_span(source, "target.call(data)")],
            uses_source: true,
        }];

        let findings = detect_taint(&ast, &summaries);
        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == FindingKind::TaintedCall),
            "external member calls should still surface as tainted-call findings"
        );
    }

    #[test]
    fn benign_logging_member_call_is_not_surfaced_as_tainted_call() {
        let source = r#"
            pragma solidity ^0.4.24;
            contract Logger {
                function AddMessage(address who, uint256 value, string data) public {}
            }
            contract Vault {
                Logger log;
                function deposit() public payable {
                    log.AddMessage(msg.sender, msg.value, "Put");
                }
            }
        "#;
        let ast = parse(source);
        let summaries = vec![TaintSummary {
            function_id: 1,
            tainted_vars: Vec::new(),
            tainted_calls: vec![substring_span(
                source,
                "log.AddMessage(msg.sender, msg.value, \"Put\")",
            )],
            uses_source: true,
        }];

        let findings = detect_taint(&ast, &summaries);
        assert!(
            findings.is_empty(),
            "benign helper/logging calls should not surface as tainted-call findings"
        );
    }
}
