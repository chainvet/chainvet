use std::collections::HashSet;

use crate::analysis::detectors::Severity;
use crate::cfg::BlockId;
use crate::ir::{IrInstr, IrValue, IrVar};
use crate::norm::Span;
use crate::symbolic::detectors::Detector;
use crate::symbolic::results::finding::{Confidence, SeFinding, SeVulnKind};
use crate::symbolic::solver::SmtSolver;
use crate::symbolic::state::SymbolicState;

/// Detects cryptographic vulnerabilities.
///
/// Covers:
/// - `MissingSignatureVerification` — `ecrecover` result not checked against zero
/// - `SignatureMalleability` — `ecrecover` `s` parameter not bounded to lower half
pub struct CryptographicDetector {
    /// Variables holding `ecrecover` return values.
    ecrecover_results: HashSet<IrVar>,
    /// Variables that were zero-checked (used in an `== 0` comparison).
    zero_checked: HashSet<IrVar>,
}

impl CryptographicDetector {
    pub fn new() -> Self {
        Self {
            ecrecover_results: HashSet::new(),
            zero_checked: HashSet::new(),
        }
    }
}

impl Detector for CryptographicDetector {
    fn id(&self) -> &'static str {
        "cryptographic"
    }

    fn name(&self) -> &'static str {
        "Cryptographic Detector"
    }

    fn on_instruction(
        &mut self,
        state: &SymbolicState,
        instr: &IrInstr,
        _solver: &dyn SmtSolver,
    ) -> Vec<SeFinding> {
        match instr {
            // Track ecrecover calls.
            IrInstr::Call { dest, callee, span, .. }
                if is_ecrecover(callee) =>
            {
                let mut findings = Vec::new();

                // SignatureMalleability: if ecrecover is called, the `s` parameter
                // (conventionally args[3]) is rarely validated against secp256k1n/2.
                // We emit a low-confidence pattern finding on every ecrecover call.
                findings.push(make_finding(
                    SeVulnKind::SignatureMalleability,
                    Severity::Medium,
                    Confidence::Low,
                    "ecrecover does not check that `s` is in the lower half of the curve; \
                     signature can be malleated to a different valid form",
                    span.clone(),
                    state,
                ));

                // Record the result variable for zero-check tracking.
                for v in dest {
                    self.ecrecover_results.insert(v.clone());
                }

                findings
            }

            // Binary comparison: detect `ecrecover_result == 0` (proper zero-check).
            IrInstr::Binary { op, lhs, rhs, .. }
                if op == "==" || op == "!=" =>
            {
                let is_zero = |v: &IrValue| {
                    matches!(v, IrValue::Literal(lit) if lit.value == "0")
                };

                let checked_var = if is_zero(rhs) {
                    as_var(lhs)
                } else if is_zero(lhs) {
                    as_var(rhs)
                } else {
                    None
                };

                if let Some(v) = checked_var {
                    if self.ecrecover_results.contains(v) {
                        self.zero_checked.insert(v.clone());
                    }
                }
                vec![]
            }

            // At function return: any ecrecover result not zero-checked is a finding.
            IrInstr::Return { span, .. } => {
                let mut findings = Vec::new();
                for v in &self.ecrecover_results {
                    if !self.zero_checked.contains(v) {
                        findings.push(make_finding(
                            SeVulnKind::MissingSignatureVerification,
                            Severity::High,
                            Confidence::Low,
                            "ecrecover return value not checked for address(0); \
                             invalid signatures may be silently accepted",
                            span.clone(),
                            state,
                        ));
                    }
                }
                findings
            }

            _ => vec![],
        }
    }

    fn on_block_exit(
        &mut self,
        _state: &SymbolicState,
        _block_id: BlockId,
        _solver: &dyn SmtSolver,
    ) -> Vec<SeFinding> {
        vec![]
    }

    fn reset(&mut self) {
        self.ecrecover_results.clear();
        self.zero_checked.clear();
    }
}

fn is_ecrecover(callee: &IrValue) -> bool {
    matches!(
        callee,
        IrValue::Var(IrVar::Named(n)) if n == "ecrecover"
    )
}

fn as_var(val: &IrValue) -> Option<&IrVar> {
    match val {
        IrValue::Var(v) => Some(v),
        _ => None,
    }
}

fn make_finding(
    kind: SeVulnKind,
    severity: Severity,
    confidence: Confidence,
    message: &str,
    span: Span,
    state: &SymbolicState,
) -> SeFinding {
    SeFinding {
        kind,
        severity,
        confidence,
        message: message.to_string(),
        span,
        function_id: None,
        path_constraints: state
            .path_constraints
            .descriptions()
            .iter()
            .map(|s| s.to_string())
            .collect(),
        witness: None,
        state_id: state.id,
        path_depth: state.path_depth,
    }
}
