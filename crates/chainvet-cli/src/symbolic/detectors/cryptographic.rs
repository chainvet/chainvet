use std::collections::HashSet;

use crate::analysis::detectors::Severity;
use chainvet_core::cfg::BlockId;
use chainvet_core::ir::{IrInstr, IrValue, IrVar};
use crate::symbolic::detectors::{make_finding, Detector};
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
                // Record the result variable for zero-check tracking.
                for v in dest {
                    self.ecrecover_results.insert(v.clone());
                }

                // SignatureMalleability: if ecrecover is called, the `s` parameter
                // (conventionally args[3]) is rarely validated against secp256k1n/2.
                // We emit a low-confidence pattern finding on every ecrecover call.
                vec![make_finding(
                    SeVulnKind::SignatureMalleability,
                    Severity::Medium,
                    Confidence::Low,
                    "ecrecover does not check that `s` is in the lower half of the curve; \
                     signature can be malleated to a different valid form",
                    *span,
                    state,
                    None,
                )]
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

                if let Some(v) = checked_var
                    && self.ecrecover_results.contains(v)
                {
                    self.zero_checked.insert(v.clone());
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
                            *span,
                            state,
                            None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use chainvet_core::ir::{IrInstr, IrValue, IrVar};
    use chainvet_core::norm::{Literal, Span};
    use crate::symbolic::results::finding::SeVulnKind;
    use crate::symbolic::solver::z3_backend::Z3Backend;
    use crate::symbolic::state::call_context::CallContext;
    use crate::symbolic::state::{StateIdGen, SymbolicState};

    fn span() -> Span {
        Span { file: 0, start: 0, end: 0 }
    }

    fn make_state_and_solver() -> (SymbolicState, Z3Backend) {
        let mut id_gen = StateIdGen::new();
        let (call_ctx, _) = CallContext::new_symbolic();
        let state = SymbolicState::initial(&mut id_gen, 0, call_ctx);
        (state, Z3Backend::new(0))
    }

    fn ecrecover_instr() -> IrInstr {
        IrInstr::Call {
            dest: vec![IrVar::Temp(0)],
            callee: IrValue::Var(IrVar::Named("ecrecover".to_string())),
            args: vec![],
            options: vec![],
            span: span(),
        }
    }

    fn return_instr() -> IrInstr {
        IrInstr::Return { values: vec![], span: span() }
    }

    fn zero_check_instr() -> IrInstr {
        // Binary{op:"==", lhs:Var(Temp(0)), rhs:Literal{value:"0"}} — zero-check of ecrecover result.
        IrInstr::Binary {
            dest: IrVar::Temp(1),
            op: "==".to_string(),
            lhs: IrValue::Var(IrVar::Temp(0)),
            rhs: IrValue::Literal(Literal {
                kind: "number".to_string(),
                value: "0".to_string(),
            }),
            span: span(),
        }
    }

    #[test]
    fn test_nop_no_findings() {
        // Nop should produce no cryptographic findings.
        let (state, solver) = make_state_and_solver();
        let mut det = CryptographicDetector::new();
        let findings = det.on_instruction(&state, &IrInstr::Nop { span: span() }, &solver);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_ecrecover_emits_signature_malleability() {
        // Every ecrecover call should emit SignatureMalleability (low-confidence pattern).
        let (state, solver) = make_state_and_solver();
        let mut det = CryptographicDetector::new();
        let findings = det.on_instruction(&state, &ecrecover_instr(), &solver);
        assert!(
            findings.iter().any(|f| f.kind == SeVulnKind::SignatureMalleability),
            "ecrecover should always emit SignatureMalleability"
        );
    }

    #[test]
    fn test_ecrecover_without_zero_check_emits_missing_sig_verification_at_return() {
        // ecrecover result not zero-checked, then Return → MissingSignatureVerification.
        let (state, solver) = make_state_and_solver();
        let mut det = CryptographicDetector::new();

        det.on_instruction(&state, &ecrecover_instr(), &solver);
        let findings = det.on_instruction(&state, &return_instr(), &solver);
        assert!(
            findings.iter().any(|f| f.kind == SeVulnKind::MissingSignatureVerification),
            "ecrecover result not checked before return should emit MissingSignatureVerification"
        );
    }

    #[test]
    fn test_ecrecover_with_zero_check_no_missing_sig_finding() {
        // ecrecover result zero-checked before return → no MissingSignatureVerification.
        // (SignatureMalleability may still fire.)
        let (state, solver) = make_state_and_solver();
        let mut det = CryptographicDetector::new();

        det.on_instruction(&state, &ecrecover_instr(), &solver);
        det.on_instruction(&state, &zero_check_instr(), &solver);
        let findings = det.on_instruction(&state, &return_instr(), &solver);
        assert!(
            !findings.iter().any(|f| f.kind == SeVulnKind::MissingSignatureVerification),
            "zero-checked ecrecover should not emit MissingSignatureVerification"
        );
    }

    #[test]
    fn test_reset_clears_state() {
        // After reset, a prior ecrecover result should be forgotten; Return won't emit missing sig.
        let (state, solver) = make_state_and_solver();
        let mut det = CryptographicDetector::new();

        det.on_instruction(&state, &ecrecover_instr(), &solver);
        det.reset();
        let findings = det.on_instruction(&state, &return_instr(), &solver);
        assert!(
            !findings.iter().any(|f| f.kind == SeVulnKind::MissingSignatureVerification),
            "reset should clear ecrecover_results set"
        );
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

