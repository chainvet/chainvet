use crate::analysis::detectors::Severity;
use crate::cfg::BlockId;
use crate::ir::{ControlKind, IrInstr, IrPlace, IrValue, IrVar};
use crate::norm::Span;
use crate::symbolic::detectors::Detector;
use crate::symbolic::results::finding::{Confidence, SeFinding, SeVulnKind};
use crate::symbolic::solver::SmtSolver;
use crate::symbolic::state::SymbolicState;

/// Detects Denial of Service vulnerabilities.
///
/// Covers:
/// - `UncheckedCall` — return value of `call`/`send` ignored
/// - `HardcodedGasAmount` — `transfer`/`send` with hardcoded 2300 gas
/// - `ForceSendEther` — contract balance used in `require`/`assert`
/// - `DosFailedCall` — single external call failure blocks entire function
/// - `UnsafeSendInRequire` — `send()` result inside `require()`
/// - `DosBlockGasLimit` — loop over unbounded storage array
pub struct DosDetector {
    /// Variable holding `address(this).balance` or `this.balance`.
    balance_var: Option<IrVar>,
    /// Destination variable of the most recent external call, and whether it was `send`.
    last_external_call: Option<(IrVar, bool)>,
}

impl DosDetector {
    pub fn new() -> Self {
        Self {
            balance_var: None,
            last_external_call: None,
        }
    }

    fn is_send(callee: &IrValue) -> bool {
        matches!(callee, IrValue::Var(IrVar::Named(n)) if n == "send")
    }

    fn is_send_or_call(callee: &IrValue) -> bool {
        matches!(
            callee,
            IrValue::Var(IrVar::Named(n)) if n == "call" || n == "send"
        )
    }

    fn is_transfer_or_send(callee: &IrValue) -> bool {
        matches!(
            callee,
            IrValue::Var(IrVar::Named(n)) if n == "transfer" || n == "send"
        )
    }

    fn is_require_or_assert(callee: &IrValue) -> bool {
        matches!(
            callee,
            IrValue::Var(IrVar::Named(n)) if n == "require" || n == "assert"
        )
    }

    fn is_balance_name(name: &str) -> bool {
        name == "this.balance"
            || name == "address(this).balance"
            || name == "balance"
    }
}

impl Detector for DosDetector {
    fn id(&self) -> &'static str {
        "dos"
    }

    fn on_instruction(
        &mut self,
        state: &SymbolicState,
        instr: &IrInstr,
        _solver: &dyn SmtSolver,
    ) -> Vec<SeFinding> {
        match instr {
            // Track balance loads for ForceSendEther.
            IrInstr::Load { dest, src, .. } => {
                if let IrPlace::Var {
                    var: IrVar::Named(n),
                    ..
                } = src
                    && Self::is_balance_name(n)
                {
                    self.balance_var = Some(dest.clone());
                }
                vec![]
            }

            IrInstr::Call {
                dest,
                callee,
                args,
                options,
                span,
            } => {
                let mut findings = Vec::new();

                // UncheckedCall: call/send with no destination variable (return value dropped).
                if Self::is_send_or_call(callee) && dest.is_empty() {
                    findings.push(make_finding(
                        SeVulnKind::UncheckedCall,
                        Severity::Medium,
                        Confidence::Low,
                        "Return value of call/send ignored; failed calls silently pass",
                        *span,
                        state,
                    ));
                }

                // HardcodedGasAmount: transfer/send always forwards exactly 2300 gas.
                if Self::is_transfer_or_send(callee) {
                    findings.push(make_finding(
                        SeVulnKind::HardcodedGasAmount,
                        Severity::Low,
                        Confidence::Low,
                        "transfer/send forwards hardcoded 2300 gas; may break if callee gas costs change",
                        *span,
                        state,
                    ));
                }

                // Track external call result for downstream require/assert check.
                if !dest.is_empty() && !options.is_empty() {
                    self.last_external_call = Some((dest[0].clone(), Self::is_send(callee)));
                }

                // DosFailedCall / UnsafeSendInRequire: require wrapping an external call result.
                if Self::is_require_or_assert(callee)
                    && let Some(IrValue::Var(v)) = args.first()
                    && let Some((ref last_var, is_send)) = self.last_external_call
                    && v == last_var
                {
                    let (kind, msg) = if is_send {
                        (SeVulnKind::UnsafeSendInRequire,
                         "send() result used directly in require(); reverts entire tx on failure")
                    } else {
                        (SeVulnKind::DosFailedCall,
                         "External call result used in require(); a failing callee permanently blocks this function")
                    };
                    findings.push(make_finding(kind, Severity::Medium, Confidence::Low, msg, *span, state));
                }

                // ForceSendEther: require/assert referencing contract balance.
                if Self::is_require_or_assert(callee) {
                    for arg in args {
                        if let IrValue::Var(v) = arg
                            && self.balance_var.as_ref() == Some(v)
                        {
                            findings.push(make_finding(
                                SeVulnKind::ForceSendEther,
                                Severity::Medium,
                                Confidence::Low,
                                "Contract balance used in require/assert; selfdestruct can force ETH and break invariant",
                                *span,
                                state,
                            ));
                        }
                    }
                }

                findings
            }

            // DosFailedCall: check if the last external call result feeds into require.
            // Also DosBlockGasLimit: loop over storage.
            IrInstr::Control {
                kind: ControlKind::Loop { .. },
                span,
            } => {
                vec![make_finding(
                    SeVulnKind::DosBlockGasLimit,
                    Severity::Medium,
                    Confidence::Low,
                    "Loop may iterate over an unbounded storage array, hitting block gas limit",
                    *span,
                    state,
                )]
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
        self.balance_var = None;
        self.last_external_call = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ControlKind, IrInstr, IrPlace, IrValue, IrVar, PlaceClass};
    use crate::norm::Span;
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

    #[test]
    fn test_nop_no_findings() {
        // Nop should produce no DoS findings.
        let (state, solver) = make_state_and_solver();
        let mut det = DosDetector::new();
        let findings = det.on_instruction(&state, &IrInstr::Nop { span: span() }, &solver);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_unchecked_call_emits_finding() {
        // Call to "call" with empty dest should emit UncheckedCall.
        let (state, solver) = make_state_and_solver();
        let mut det = DosDetector::new();
        let instr = IrInstr::Call {
            dest: vec![],
            callee: IrValue::Var(IrVar::Named("call".to_string())),
            args: vec![],
            options: vec![],
            span: span(),
        };
        let findings = det.on_instruction(&state, &instr, &solver);
        assert!(
            findings.iter().any(|f| f.kind == SeVulnKind::UncheckedCall),
            "call with empty dest should emit UncheckedCall"
        );
    }

    #[test]
    fn test_transfer_emits_hardcoded_gas() {
        // Call to "transfer" should emit HardcodedGasAmount.
        let (state, solver) = make_state_and_solver();
        let mut det = DosDetector::new();
        let instr = IrInstr::Call {
            dest: vec![],
            callee: IrValue::Var(IrVar::Named("transfer".to_string())),
            args: vec![IrValue::Var(IrVar::Temp(0))],
            options: vec![],
            span: span(),
        };
        let findings = det.on_instruction(&state, &instr, &solver);
        assert!(
            findings.iter().any(|f| f.kind == SeVulnKind::HardcodedGasAmount),
            "transfer should emit HardcodedGasAmount"
        );
    }

    #[test]
    fn test_send_emits_hardcoded_gas() {
        // Call to "send" should emit HardcodedGasAmount.
        let (state, solver) = make_state_and_solver();
        let mut det = DosDetector::new();
        let instr = IrInstr::Call {
            dest: vec![IrVar::Temp(0)],
            callee: IrValue::Var(IrVar::Named("send".to_string())),
            args: vec![IrValue::Var(IrVar::Temp(1))],
            options: vec![],
            span: span(),
        };
        let findings = det.on_instruction(&state, &instr, &solver);
        assert!(
            findings.iter().any(|f| f.kind == SeVulnKind::HardcodedGasAmount),
            "send should emit HardcodedGasAmount"
        );
    }

    #[test]
    fn test_loop_emits_dos_block_gas_limit() {
        // Control{Loop} should emit DosBlockGasLimit.
        let (state, solver) = make_state_and_solver();
        let mut det = DosDetector::new();
        let instr = IrInstr::Control {
            kind: ControlKind::Loop { cond: None },
            span: span(),
        };
        let findings = det.on_instruction(&state, &instr, &solver);
        assert_eq!(findings.len(), 1, "loop should emit DosBlockGasLimit");
        assert_eq!(findings[0].kind, SeVulnKind::DosBlockGasLimit);
    }

    #[test]
    fn test_balance_in_require_emits_force_send() {
        // Load balance into Temp(0), then require(Temp(0)) → ForceSendEther.
        let (state, solver) = make_state_and_solver();
        let mut det = DosDetector::new();

        let load_instr = IrInstr::Load {
            dest: IrVar::Temp(0),
            src: IrPlace::Var {
                var: IrVar::Named("balance".to_string()),
                class: PlaceClass::Unknown,
            },
            span: span(),
        };
        det.on_instruction(&state, &load_instr, &solver);

        let require_instr = IrInstr::Call {
            dest: vec![],
            callee: IrValue::Var(IrVar::Named("require".to_string())),
            args: vec![IrValue::Var(IrVar::Temp(0))],
            options: vec![],
            span: span(),
        };
        let findings = det.on_instruction(&state, &require_instr, &solver);
        assert!(
            findings.iter().any(|f| f.kind == SeVulnKind::ForceSendEther),
            "balance in require should emit ForceSendEther"
        );
    }

    #[test]
    fn test_reset_clears_state() {
        // After reset, a balance loaded before reset should not trigger ForceSendEther.
        let (state, solver) = make_state_and_solver();
        let mut det = DosDetector::new();

        let load_instr = IrInstr::Load {
            dest: IrVar::Temp(0),
            src: IrPlace::Var {
                var: IrVar::Named("balance".to_string()),
                class: PlaceClass::Unknown,
            },
            span: span(),
        };
        det.on_instruction(&state, &load_instr, &solver);
        det.reset();

        let require_instr = IrInstr::Call {
            dest: vec![],
            callee: IrValue::Var(IrVar::Named("require".to_string())),
            args: vec![IrValue::Var(IrVar::Temp(0))],
            options: vec![],
            span: span(),
        };
        let findings = det.on_instruction(&state, &require_instr, &solver);
        assert!(
            !findings.iter().any(|f| f.kind == SeVulnKind::ForceSendEther),
            "reset should clear balance_var tracking"
        );
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
