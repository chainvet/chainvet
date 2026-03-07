//! Miscellaneous detectors (MI-01, MI-02)
//! 2 detectors covering:
//!   MI-01 – Variable shadowing
//!   MI-02 – Tainted call arguments (from taint analysis)

use std::collections::HashSet;

use crate::analysis::taint::TaintSummary;
use crate::norm::{NormalizedAst, StmtKind};

use super::{Finding, FindingKind, Severity};

// ═══════════════════════════════════════════════════════════════════════════════
//  Entry point
// ═══════════════════════════════════════════════════════════════════════════════

/// Run all Miscellaneous detectors and return their findings.
pub fn detect_all(ast: &NormalizedAst, taint_summaries: &[TaintSummary]) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(detect_shadowing(ast));                   // MI-01
    findings.extend(detect_taint(ast, taint_summaries));      // MI-02

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

            // Add function parameters to scope
            for param_name in &func.params {
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

fn detect_taint(_ast: &NormalizedAst, summaries: &[TaintSummary]) -> Vec<Finding> {
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
