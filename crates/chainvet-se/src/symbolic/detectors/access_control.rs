use z3::SatResult;
use z3::ast::Bool;

use crate::symbolic::detectors::{
    CalleeTracker, Detector, make_finding, place_matches, value_has_origin,
};
use crate::symbolic::results::finding::{Confidence, SeFinding, SeVulnKind};
use crate::symbolic::results::witness::Witness;
use crate::symbolic::solver::SmtSolver;
use crate::symbolic::state::{SymbolicState, ValueOrigin};
use chainvet_core::cfg::BlockId;
use chainvet_core::ir::{ControlKind, IrCallOption, IrInstr, IrPlace, IrValue, IrVar, PlaceClass};
use chainvet_core::norm::Span;
use chainvet_sa::analysis::detectors::Severity;

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
    /// Tracks member-load chains for resolving Temp callees.
    tracker: CalleeTracker,
}

impl Default for AccessControlDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AccessControlDetector {
    pub fn new() -> Self {
        Self {
            tx_origin_loaded: false,
            has_sender_check: false,
            tracker: CalleeTracker::new(),
        }
    }

    fn has_sender_restriction(state: &SymbolicState) -> bool {
        // Use the engine-tracked flag first (set by require/if on sender-related vars).
        if state.sender_checked {
            return true;
        }
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
            IrInstr::Load { dest, src, .. } => self.handle_load(dest, src),
            IrInstr::Control {
                kind: ControlKind::If { cond },
                span,
            } => self.handle_control_if(cond, *span, state),
            IrInstr::Call { callee, span, .. } if is_selfdestruct(callee) => {
                self.handle_selfdestruct(state, solver, *span)
            }
            IrInstr::Call {
                callee,
                options,
                span,
                ..
            } if has_value_option(options)
                || self.tracker.chain_contains_field(callee, &["value"]) =>
            {
                self.handle_eth_transfer(callee, state, solver, *span)
            }
            IrInstr::Store { dest, span, .. } => Self::handle_store(dest, state, solver, *span),
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
        self.tracker.reset();
    }
}

impl AccessControlDetector {
    fn handle_load(&mut self, dest: &IrVar, src: &IrPlace) -> Vec<SeFinding> {
        self.tracker.track_load(dest, src);
        if place_matches(src, "tx", "origin") {
            self.tx_origin_loaded = true;
        }
        if place_matches(src, "msg", "sender") {
            self.has_sender_check = true;
        }
        vec![]
    }

    fn handle_control_if(
        &mut self,
        cond: &IrValue,
        span: Span,
        state: &SymbolicState,
    ) -> Vec<SeFinding> {
        let cond_str = format!("{cond:?}");
        if cond_str.contains("msg.sender") || cond_str.contains("msg_sender") {
            self.has_sender_check = true;
        }
        let origin_tainted = value_has_origin(state, cond, ValueOrigin::TxOrigin);
        if (self.tx_origin_loaded || origin_tainted) && !Self::has_sender_restriction(state) {
            self.tx_origin_loaded = false;
            return vec![make_finding(
                SeVulnKind::TxOriginAuth,
                Severity::Medium,
                Confidence::Medium,
                "tx.origin used for authentication; use msg.sender instead",
                span,
                state,
                None,
            )];
        }
        self.tx_origin_loaded = false;
        vec![]
    }

    fn handle_selfdestruct(
        &self,
        state: &SymbolicState,
        solver: &dyn SmtSolver,
        span: Span,
    ) -> Vec<SeFinding> {
        if !Self::has_sender_restriction(state) {
            return check_reachable_and_emit(
                state,
                solver,
                SeVulnKind::UnprotectedSelfdestruct,
                Severity::High,
                Confidence::High,
                "selfdestruct reachable without sender restriction",
                span,
            );
        }
        vec![]
    }

    fn handle_eth_transfer(
        &self,
        callee: &IrValue,
        state: &SymbolicState,
        solver: &dyn SmtSolver,
        span: Span,
    ) -> Vec<SeFinding> {
        let mut findings = Vec::new();
        if !Self::has_sender_restriction(state) && is_user_controlled_recipient(callee) {
            findings.extend(check_reachable_and_emit(
                state,
                solver,
                SeVulnKind::UnprotectedEtherWithdrawal,
                Severity::High,
                Confidence::Medium,
                "ETH transfer to user-controlled address without access control",
                span,
            ));
        }
        if !self.has_sender_check && !Self::has_sender_restriction(state) {
            findings.push(make_finding(
                SeVulnKind::AccessControlMissing,
                Severity::High,
                Confidence::Low,
                "ETH-sending call without msg.sender check",
                span,
                state,
                None,
            ));
        }
        findings
    }

    fn handle_store(
        dest: &IrPlace,
        state: &SymbolicState,
        solver: &dyn SmtSolver,
        span: Span,
    ) -> Vec<SeFinding> {
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
                span,
            );
        }
        vec![]
    }
}

fn is_selfdestruct(callee: &IrValue) -> bool {
    matches!(
        callee,
        IrValue::Var(IrVar::Named(n)) if n == "selfdestruct" || n == "suicide"
    )
}

fn has_value_option(options: &[IrCallOption]) -> bool {
    options.iter().any(|o| matches!(o, IrCallOption::Value(_)))
}

/// Returns true if the callee is not a known constant (not `this`, not a literal).
fn is_user_controlled_recipient(callee: &IrValue) -> bool {
    match callee {
        IrValue::Var(IrVar::Named(n)) => n != "this" && n != "address(this)",
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
            let witness = solver.get_model().map(|m| {
                let mut w = Witness::from_model(&m, &state.call_context);
                w.populate_variables(&m, &state.variables);
                w
            });
            vec![make_finding(
                kind, severity, confidence, message, span, state, witness,
            )]
        }
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbolic::results::finding::SeVulnKind;
    use crate::symbolic::solver::z3_backend::Z3Backend;
    use crate::symbolic::state::call_context::CallContext;
    use crate::symbolic::state::{StateIdGen, SymbolicState};
    use chainvet_core::ir::{
        ControlKind, IrCallOption, IrInstr, IrPlace, IrValue, IrVar, PlaceClass,
    };
    use chainvet_core::norm::Span;

    fn span() -> Span {
        Span {
            file: 0,
            start: 0,
            end: 0,
        }
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
        assert_eq!(
            findings.len(),
            1,
            "selfdestruct without sender check should emit finding"
        );
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
        assert_eq!(
            findings.len(),
            1,
            "tx.origin load then branch should emit TxOriginAuth"
        );
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
            findings
                .iter()
                .any(|f| f.kind == SeVulnKind::AccessControlMissing),
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
        assert_eq!(
            findings.len(),
            1,
            "user-controlled storage index should emit ArbitraryStorageWrite"
        );
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
            !findings
                .iter()
                .any(|f| f.kind == SeVulnKind::AccessControlMissing),
            "after loading msg.sender, AccessControlMissing should not be emitted"
        );
    }

    #[test]
    fn test_tx_origin_as_member_place_emits_tx_origin_auth() {
        // Simulates the actual IR for `tx.origin` as a Member place:
        //   Load Temp(0) <- Member{base:Named("tx"), field:"origin", root:Some("tx")}
        //   Control{If{cond:Var(Temp(0))}}
        // Should emit TxOriginAuth.
        let (state, solver) = make_state_and_solver();
        let mut det = AccessControlDetector::new();

        det.on_instruction(
            &state,
            &IrInstr::Load {
                dest: IrVar::Temp(0),
                src: IrPlace::Member {
                    base: IrValue::Var(IrVar::Named("tx".to_string())),
                    field: "origin".to_string(),
                    root: Some("tx".to_string()),
                    class: PlaceClass::Unknown,
                },
                span: span(),
            },
            &solver,
        );

        let findings = det.on_instruction(
            &state,
            &IrInstr::Control {
                kind: ControlKind::If {
                    cond: IrValue::Var(IrVar::Temp(0)),
                },
                span: span(),
            },
            &solver,
        );
        assert_eq!(
            findings.len(),
            1,
            "tx.origin as Member place followed by If should emit TxOriginAuth"
        );
        assert_eq!(findings[0].kind, SeVulnKind::TxOriginAuth);
    }
}
