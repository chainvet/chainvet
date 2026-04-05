use z3::SatResult;
use z3::ast::Bool;

use crate::analysis::detectors::Severity;
use crate::cfg::BlockId;
use crate::ir::{
    ControlKind, IrCallOption, IrInstr, IrPlace, IrValue, IrVar, PlaceClass,
};
use crate::norm::Span;
use crate::symbolic::detectors::Detector;
use crate::symbolic::results::finding::{Confidence, SeFinding, SeVulnKind};
use crate::symbolic::results::witness::Witness;
use crate::symbolic::solver::SmtSolver;
use crate::symbolic::state::SymbolicState;

/// Detects access control vulnerabilities.
///
/// Covers:
/// - `TxOriginAuth` — use of `tx.origin` for authentication
/// - `UnprotectedSelfdestruct` — selfdestruct reachable without sender restriction
/// - `UnprotectedEtherWithdrawal` — ETH transfer without sender check
/// - `ArbitraryStorageWrite` — storage write at user-controlled index
/// - `AccessControlMissing` — general missing sender guard pattern
pub struct AccessControlDetector {
    /// Set when `tx.origin` or `tx_origin` was loaded.
    tx_origin_loaded: bool,
    /// Set when `msg.sender`, `owner`, or `onlyOwner` appears in path constraints or branch cond.
    has_sender_check: bool,
}

impl AccessControlDetector {
    pub fn new() -> Self {
        Self {
            tx_origin_loaded: false,
            has_sender_check: false,
        }
    }

    fn has_sender_restriction(state: &SymbolicState) -> bool {
        state.path_constraints.descriptions().iter().any(|d| {
            d.contains("msg.sender")
                || d.contains("msg_sender")
                || d.contains("owner")
                || d.contains("onlyOwner")
        })
    }
}

impl Detector for AccessControlDetector {
    fn id(&self) -> &'static str {
        "access-control"
    }

    fn on_instruction(
        &mut self,
        state: &SymbolicState,
        instr: &IrInstr,
        solver: &dyn SmtSolver,
    ) -> Vec<SeFinding> {
        match instr {
            // Track tx.origin loads.
            IrInstr::Load { src, .. } => {
                if let IrPlace::Var {
                    var: IrVar::Named(n),
                    ..
                } = src
                {
                    let name = n.as_str();
                    if name == "tx.origin" || name == "tx_origin" {
                        self.tx_origin_loaded = true;
                    }
                    if name == "msg.sender" || name == "msg_sender" {
                        self.has_sender_check = true;
                    }
                }
                vec![]
            }

            // Track sender-check via conditional instructions.
            IrInstr::Control {
                kind: ControlKind::If { cond },
                span,
            } => {
                let cond_str = format!("{cond:?}");
                if cond_str.contains("msg.sender") || cond_str.contains("msg_sender") {
                    self.has_sender_check = true;
                }

                // tx.origin authentication: loaded and used as auth condition without msg.sender.
                if self.tx_origin_loaded && !Self::has_sender_restriction(state) {
                    self.tx_origin_loaded = false;
                    return vec![make_finding(
                        SeVulnKind::TxOriginAuth,
                        Severity::Medium,
                        Confidence::Medium,
                        "tx.origin used for authentication; use msg.sender instead",
                        *span,
                        state,
                    )];
                }
                self.tx_origin_loaded = false;
                vec![]
            }

            // Call to selfdestruct/suicide without sender restriction.
            IrInstr::Call { callee, span, .. }
                if is_selfdestruct(callee) =>
            {
                if !Self::has_sender_restriction(state) {
                    return check_reachable_and_emit(
                        state,
                        solver,
                        SeVulnKind::UnprotectedSelfdestruct,
                        Severity::High,
                        Confidence::High,
                        "selfdestruct reachable without sender restriction",
                        *span,
                    );
                }
                vec![]
            }

            // ETH-transferring call without sender check.
            IrInstr::Call {
                callee,
                options,
                span,
                ..
            } if has_value_option(options) => {
                let mut findings = Vec::new();

                // UnprotectedEtherWithdrawal: ETH sent to potentially user-controlled recipient.
                if !Self::has_sender_restriction(state) && is_user_controlled_recipient(callee) {
                    findings.extend(check_reachable_and_emit(
                        state,
                        solver,
                        SeVulnKind::UnprotectedEtherWithdrawal,
                        Severity::High,
                        Confidence::Medium,
                        "ETH transfer to user-controlled address without access control",
                        *span,
                    ));
                }

                // AccessControlMissing: general ETH-sending call without any sender guard.
                if !self.has_sender_check && !Self::has_sender_restriction(state) {
                    findings.push(make_finding(
                        SeVulnKind::AccessControlMissing,
                        Severity::High,
                        Confidence::Low,
                        "ETH-sending call without msg.sender check",
                        *span,
                        state,
                    ));
                }

                findings
            }

            // Storage write at symbolic index → possibly arbitrary storage write.
            IrInstr::Store { dest, span, .. } => {
                if let IrPlace::Index {
                    index: Some(idx),
                    class: PlaceClass::Storage,
                    ..
                } = dest
                    && is_user_controlled_value(idx)
                {
                    return check_reachable_and_emit(
                        state,
                        solver,
                        SeVulnKind::ArbitraryStorageWrite,
                        Severity::High,
                        Confidence::Medium,
                        "Storage write at user-controlled index may overwrite arbitrary slots",
                        *span,
                    );
                }
                vec![]
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
        self.tx_origin_loaded = false;
        self.has_sender_check = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ControlKind, IrCallOption, IrInstr, IrPlace, IrValue, IrVar, PlaceClass};
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
        // A Nop instruction should produce no access control findings.
        let (state, solver) = make_state_and_solver();
        let mut det = AccessControlDetector::new();
        let findings = det.on_instruction(&state, &IrInstr::Nop { span: span() }, &solver);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_selfdestruct_without_sender_check_emits_finding() {
        // A selfdestruct call with empty path constraints should emit UnprotectedSelfdestruct.
        let (state, solver) = make_state_and_solver();
        let mut det = AccessControlDetector::new();
        let instr = IrInstr::Call {
            dest: vec![],
            callee: IrValue::Var(IrVar::Named("selfdestruct".to_string())),
            args: vec![IrValue::Var(IrVar::Temp(0))],
            options: vec![],
            span: span(),
        };
        let findings = det.on_instruction(&state, &instr, &solver);
        assert_eq!(findings.len(), 1, "selfdestruct without sender check should emit finding");
        assert_eq!(findings[0].kind, SeVulnKind::UnprotectedSelfdestruct);
    }

    #[test]
    fn test_load_tx_origin_then_if_emits_tx_origin_auth() {
        // Load tx.origin followed by a Control{If} should emit TxOriginAuth.
        let (state, solver) = make_state_and_solver();
        let mut det = AccessControlDetector::new();

        let load_instr = IrInstr::Load {
            dest: IrVar::Temp(0),
            src: IrPlace::Var {
                var: IrVar::Named("tx.origin".to_string()),
                class: PlaceClass::Unknown,
            },
            span: span(),
        };
        det.on_instruction(&state, &load_instr, &solver);

        let if_instr = IrInstr::Control {
            kind: ControlKind::If {
                cond: IrValue::Var(IrVar::Temp(0)),
            },
            span: span(),
        };
        let findings = det.on_instruction(&state, &if_instr, &solver);
        assert_eq!(findings.len(), 1, "tx.origin load then branch should emit TxOriginAuth");
        assert_eq!(findings[0].kind, SeVulnKind::TxOriginAuth);
    }

    #[test]
    fn test_eth_transfer_without_sender_emits_access_control_missing() {
        // An ETH-transferring call with no msg.sender check should emit AccessControlMissing.
        let (state, solver) = make_state_and_solver();
        let mut det = AccessControlDetector::new();
        let instr = IrInstr::Call {
            dest: vec![],
            callee: IrValue::Var(IrVar::Named("recipient".to_string())),
            args: vec![],
            options: vec![IrCallOption::Value(IrValue::Var(IrVar::Temp(0)))],
            span: span(),
        };
        let findings = det.on_instruction(&state, &instr, &solver);
        assert!(
            findings.iter().any(|f| f.kind == SeVulnKind::AccessControlMissing),
            "ETH transfer without sender check should emit AccessControlMissing"
        );
    }

    #[test]
    fn test_arbitrary_storage_write_emits_finding() {
        // Store to Index{class:Storage, index:Some(Var(Temp))} should emit ArbitraryStorageWrite.
        let (state, solver) = make_state_and_solver();
        let mut det = AccessControlDetector::new();
        let instr = IrInstr::Store {
            dest: IrPlace::Index {
                base: IrValue::Var(IrVar::Named("s".to_string())),
                index: Some(IrValue::Var(IrVar::Temp(1))),
                root: None,
                class: PlaceClass::Storage,
            },
            src: IrValue::Var(IrVar::Temp(0)),
            span: span(),
        };
        let findings = det.on_instruction(&state, &instr, &solver);
        assert_eq!(findings.len(), 1, "user-controlled storage index should emit ArbitraryStorageWrite");
        assert_eq!(findings[0].kind, SeVulnKind::ArbitraryStorageWrite);
    }

    #[test]
    fn test_reset_clears_flags() {
        // After reset, loading tx.origin and then a branch should not emit TxOriginAuth.
        let (state, solver) = make_state_and_solver();
        let mut det = AccessControlDetector::new();

        let load_instr = IrInstr::Load {
            dest: IrVar::Temp(0),
            src: IrPlace::Var {
                var: IrVar::Named("tx.origin".to_string()),
                class: PlaceClass::Unknown,
            },
            span: span(),
        };
        det.on_instruction(&state, &load_instr, &solver);
        det.reset();

        let if_instr = IrInstr::Control {
            kind: ControlKind::If {
                cond: IrValue::Var(IrVar::Temp(0)),
            },
            span: span(),
        };
        let findings = det.on_instruction(&state, &if_instr, &solver);
        assert!(
            !findings.iter().any(|f| f.kind == SeVulnKind::TxOriginAuth),
            "reset should clear tx_origin_loaded flag"
        );
    }

    #[test]
    fn test_msg_sender_load_sets_has_sender_check() {
        // Loading msg.sender sets has_sender_check, so subsequent ETH call won't emit
        // AccessControlMissing.
        let (state, solver) = make_state_and_solver();
        let mut det = AccessControlDetector::new();

        let load_instr = IrInstr::Load {
            dest: IrVar::Temp(0),
            src: IrPlace::Var {
                var: IrVar::Named("msg.sender".to_string()),
                class: PlaceClass::Unknown,
            },
            span: span(),
        };
        det.on_instruction(&state, &load_instr, &solver);

        let call_instr = IrInstr::Call {
            dest: vec![],
            callee: IrValue::Var(IrVar::Named("recipient".to_string())),
            args: vec![],
            options: vec![IrCallOption::Value(IrValue::Var(IrVar::Temp(0)))],
            span: span(),
        };
        let findings = det.on_instruction(&state, &call_instr, &solver);
        assert!(
            !findings.iter().any(|f| f.kind == SeVulnKind::AccessControlMissing),
            "after loading msg.sender, AccessControlMissing should not be emitted"
        );
    }
}

fn is_selfdestruct(callee: &IrValue) -> bool {
    matches!(
        callee,
        IrValue::Var(IrVar::Named(n)) if n == "selfdestruct" || n == "suicide"
    )
}

fn has_value_option(options: &[IrCallOption]) -> bool {
    options
        .iter()
        .any(|o| matches!(o, IrCallOption::Value(_)))
}

/// Returns true if the callee is not a known constant (not `this`, not a literal).
fn is_user_controlled_recipient(callee: &IrValue) -> bool {
    match callee {
        IrValue::Var(IrVar::Named(n)) => {
            n != "this" && n != "address(this)"
        }
        IrValue::Var(IrVar::Temp(_)) => true,
        IrValue::Unknown => true,
        IrValue::Literal(_) => false,
    }
}

/// Returns true if an IrValue is symbolic (not a literal constant).
fn is_user_controlled_value(val: &IrValue) -> bool {
    !matches!(val, IrValue::Literal(_))
}

fn path_bools(state: &SymbolicState) -> Vec<Bool> {
    state
        .path_constraints
        .constraints()
        .iter()
        .map(|(c, _)| c.clone())
        .collect()
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

/// Confirm path reachability via SAT before emitting a finding.
fn check_reachable_and_emit(
    state: &SymbolicState,
    solver: &dyn SmtSolver,
    kind: SeVulnKind,
    severity: Severity,
    confidence: Confidence,
    message: &str,
    span: Span,
) -> Vec<SeFinding> {
    let assumptions = path_bools(state);
    match solver.check_sat_assuming(&assumptions) {
        SatResult::Sat => {
            let witness = solver
                .get_model()
                .map(|m| Witness::from_model(&m, &state.call_context));
            vec![SeFinding {
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
                witness,
                state_id: state.id,
                path_depth: state.path_depth,
            }]
        }
        _ => vec![],
    }
}
