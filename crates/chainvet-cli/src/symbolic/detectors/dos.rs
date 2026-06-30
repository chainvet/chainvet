use crate::analysis::detectors::Severity;
use chainvet_core::cfg::BlockId;
use chainvet_core::ir::{ControlKind, IrInstr, IrPlace, IrValue, IrVar};
use chainvet_core::norm::Span;
use crate::symbolic::detectors::{make_finding, place_matches, CalleeTracker, Detector};
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
    /// Tracks member-load chains for resolving Temp callees.
    tracker: CalleeTracker,
}

impl DosDetector {
    pub fn new() -> Self {
        Self {
            balance_var: None,
            last_external_call: None,
            tracker: CalleeTracker::new(),
        }
    }

    fn is_send(&self, callee: &IrValue) -> bool {
        self.tracker.chain_contains_field(callee, &["send"])
    }

    fn is_send_or_call(&self, callee: &IrValue) -> bool {
        self.tracker
            .chain_contains_field(callee, &["call", "send"])
    }

    fn is_transfer_or_send(&self, callee: &IrValue) -> bool {
        self.tracker
            .chain_contains_field(callee, &["transfer", "send"])
    }

    fn is_require_or_assert(callee: &IrValue) -> bool {
        matches!(
            callee,
            IrValue::Var(IrVar::Named(n)) if n == "require" || n == "assert"
        )
    }

    fn is_balance_place(place: &IrPlace) -> bool {
        place_matches(place, "this", "balance")
            || place_matches(place, "address(this)", "balance")
            || matches!(
                place,
                IrPlace::Var { var: IrVar::Named(n), .. }
                    if n == "balance" || n == "this.balance" || n == "address(this).balance"
            )
            // IR also uses root="balance" for this.balance
            || matches!(
                place,
                IrPlace::Member { field, root: Some(r), .. }
                    if field == "balance" && r == "balance"
            )
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
            IrInstr::Load { dest, src, .. } => self.handle_load(dest, src),
            IrInstr::Call {
                dest,
                callee,
                args,
                span,
                ..
            } => self.handle_call(dest, callee, args, *span, state),
            IrInstr::Control {
                kind: ControlKind::Loop { .. },
                span,
            } => {
                // Boost confidence when engine has confirmed we're inside a loop
                // that reads from storage (unbounded iteration over storage array).
                let confidence = if state.inside_loop && !state.storage_reads.is_empty() {
                    Confidence::Medium
                } else {
                    Confidence::Low
                };
                vec![make_finding(
                    SeVulnKind::DosBlockGasLimit,
                    Severity::Medium,
                    confidence,
                    "Loop may iterate over an unbounded storage array, hitting block gas limit",
                    *span,
                    state,
                    None,
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
        self.tracker.reset();
    }
}

impl DosDetector {
    fn handle_load(&mut self, dest: &IrVar, src: &IrPlace) -> Vec<SeFinding> {
        self.tracker.track_load(dest, src);
        if Self::is_balance_place(src) {
            self.balance_var = Some(dest.clone());
        }
        vec![]
    }

    fn handle_call(
        &mut self,
        dest: &[IrVar],
        callee: &IrValue,
        args: &[IrValue],
        span: Span,
        state: &SymbolicState,
    ) -> Vec<SeFinding> {
        let mut findings = Vec::new();

        if self.is_send_or_call(callee) && dest.is_empty() {
            findings.push(make_finding(
                SeVulnKind::UncheckedCall,
                Severity::Medium,
                Confidence::Low,
                "Return value of call/send ignored; failed calls silently pass",
                span,
                state,
                None,
            ));
        }

        if self.is_transfer_or_send(callee) {
            findings.push(make_finding(
                SeVulnKind::HardcodedGasAmount,
                Severity::Low,
                Confidence::Low,
                "transfer/send forwards hardcoded 2300 gas; may break if callee gas costs change",
                span,
                state,
                None,
            ));
        }

        // Track external call result for downstream require/assert check.
        if !dest.is_empty()
            && (self.is_send_or_call(callee)
                || self
                    .tracker
                    .chain_contains_field(callee, &["call", "send", "transfer"]))
        {
            self.last_external_call = Some((dest[0].clone(), self.is_send(callee)));
        }

        self.check_require_patterns(callee, args, span, state, &mut findings);
        findings
    }

    fn check_require_patterns(
        &self,
        callee: &IrValue,
        args: &[IrValue],
        span: Span,
        state: &SymbolicState,
        findings: &mut Vec<SeFinding>,
    ) {
        if !Self::is_require_or_assert(callee) {
            return;
        }

        // DosFailedCall / UnsafeSendInRequire.
        if let Some(IrValue::Var(v)) = args.first()
            && let Some((ref last_var, is_send)) = self.last_external_call
            && v == last_var
        {
            let (kind, msg) = if is_send {
                (
                    SeVulnKind::UnsafeSendInRequire,
                    "send() result used directly in require(); reverts entire tx on failure",
                )
            } else {
                (
                    SeVulnKind::DosFailedCall,
                    "External call result used in require(); a failing callee permanently blocks this function",
                )
            };
            findings.push(make_finding(
                kind,
                Severity::Medium,
                Confidence::Low,
                msg,
                span,
                state,
                None,
            ));
        }

        // ForceSendEther: require/assert referencing contract balance.
        for arg in args {
            if let IrValue::Var(v) = arg
                && self.balance_var.as_ref() == Some(v)
            {
                findings.push(make_finding(
                    SeVulnKind::ForceSendEther,
                    Severity::Medium,
                    Confidence::Low,
                    "Contract balance used in require/assert; selfdestruct can force ETH and break invariant",
                    span,
                    state,
                    None,
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chainvet_core::ir::{ControlKind, IrInstr, IrPlace, IrValue, IrVar, PlaceClass};
    use chainvet_core::norm::Span;
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

    #[test]
    fn test_send_via_member_chain_unchecked_call() {
        // Simulates the actual IR for `winner.send(amount)` via member chain:
        //   Load Temp(2) <- Member{base:Named("winner"), field:"send"}
        //   Call callee:Var(Temp(2)), dest:[] (return value dropped)
        // Should emit UncheckedCall.
        let (state, solver) = make_state_and_solver();
        let mut det = DosDetector::new();

        // Load winner.send -> Temp(2)
        det.on_instruction(
            &state,
            &IrInstr::Load {
                dest: IrVar::Temp(2),
                src: IrPlace::Member {
                    base: IrValue::Var(IrVar::Named("winner".to_string())),
                    field: "send".to_string(),
                    root: Some("winner".to_string()),
                    class: PlaceClass::Unknown,
                },
                span: span(),
            },
            &solver,
        );

        // Call Temp(2) with empty dest -> UncheckedCall
        let findings = det.on_instruction(
            &state,
            &IrInstr::Call {
                dest: vec![],
                callee: IrValue::Var(IrVar::Temp(2)),
                args: vec![IrValue::Var(IrVar::Temp(0))],
                options: vec![],
                span: span(),
            },
            &solver,
        );
        assert!(
            findings.iter().any(|f| f.kind == SeVulnKind::UncheckedCall),
            "send via member chain with empty dest should emit UncheckedCall"
        );
        // send also triggers HardcodedGasAmount
        assert!(
            findings.iter().any(|f| f.kind == SeVulnKind::HardcodedGasAmount),
            "send via member chain should also emit HardcodedGasAmount"
        );
    }
}

