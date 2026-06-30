use crate::analysis::detectors::Severity;
use chainvet_core::cfg::BlockId;
use chainvet_core::ir::{IrCallOption, IrInstr, IrValue, IrVar};
use crate::symbolic::detectors::{make_finding, CalleeTracker, Detector};
use crate::symbolic::results::finding::{Confidence, SeFinding, SeVulnKind};
use crate::symbolic::solver::SmtSolver;
use crate::symbolic::state::SymbolicState;

/// Detects delegatecall-related vulnerabilities.
///
/// Covers:
/// - `UnsafeDelegatecall` — delegatecall to user-controlled address
/// - `PayableDelegatecallInLoop` — payable delegatecall inside a loop
pub struct DelegatecallDetector {
    tracker: CalleeTracker,
}

impl DelegatecallDetector {
    pub fn new() -> Self {
        Self {
            tracker: CalleeTracker::new(),
        }
    }
}

impl Detector for DelegatecallDetector {
    fn id(&self) -> &'static str {
        "delegatecall"
    }

    fn on_instruction(
        &mut self,
        state: &SymbolicState,
        instr: &IrInstr,
        _solver: &dyn SmtSolver,
    ) -> Vec<SeFinding> {
        // Track member loads for callee resolution.
        if let IrInstr::Load { dest, src, .. } = instr {
            self.tracker.track_load(dest, src);
        }

        let IrInstr::Call {
            callee,
            options,
            args,
            span,
            ..
        } = instr
        else {
            return vec![];
        };

        if !self.tracker.chain_contains_field(callee, &["delegatecall"]) {
            return vec![];
        }

        let mut findings = Vec::new();

        // UnsafeDelegatecall: delegatecall to a potentially user-controlled target.
        // The first argument is the target address for low-level `address.delegatecall(...)`.
        // For Solidity `delegatecall`, the callee itself IS the address.
        let target = if args.is_empty() { callee } else { &args[0] };
        if is_user_controlled(target) {
            findings.push(make_finding(
                SeVulnKind::UnsafeDelegatecall,
                Severity::High,
                Confidence::Medium,
                "delegatecall to user-controlled address can execute arbitrary code",
                *span,
                state,
                None,
            ));
        }

        // PayableDelegatecallInLoop: delegatecall with ETH value inside a loop body.
        // path_depth > 0 serves as a proxy for being inside a loop or deep branch.
        let has_value = options
            .iter()
            .any(|o| matches!(o, IrCallOption::Value(_)));
        if has_value && state.path_depth > 0 {
            findings.push(make_finding(
                SeVulnKind::PayableDelegatecallInLoop,
                Severity::High,
                Confidence::Medium,
                "delegatecall with ETH value inside a loop can drain contract balance",
                *span,
                state,
                None,
            ));
        }

        findings
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
        self.tracker.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chainvet_core::ir::{IrCallOption, IrInstr, IrValue, IrVar};
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
        // Nop should produce no delegatecall findings.
        let (state, solver) = make_state_and_solver();
        let mut det = DelegatecallDetector::new();
        let findings = det.on_instruction(&state, &IrInstr::Nop { span: span() }, &solver);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_non_delegatecall_no_findings() {
        // A regular "call" (not delegatecall) should produce no findings.
        let (state, solver) = make_state_and_solver();
        let mut det = DelegatecallDetector::new();
        let instr = IrInstr::Call {
            dest: vec![],
            callee: IrValue::Var(IrVar::Named("call".to_string())),
            args: vec![IrValue::Var(IrVar::Temp(0))],
            options: vec![],
            span: span(),
        };
        let findings = det.on_instruction(&state, &instr, &solver);
        assert!(findings.is_empty(), "non-delegatecall should produce no findings");
    }

    #[test]
    fn test_delegatecall_to_temp_var_emits_unsafe() {
        // delegatecall where first arg is a Temp var (user-controlled) → UnsafeDelegatecall.
        let (state, solver) = make_state_and_solver();
        let mut det = DelegatecallDetector::new();
        let instr = IrInstr::Call {
            dest: vec![],
            callee: IrValue::Var(IrVar::Named("delegatecall".to_string())),
            args: vec![IrValue::Var(IrVar::Temp(0))],
            options: vec![],
            span: span(),
        };
        let findings = det.on_instruction(&state, &instr, &solver);
        assert_eq!(findings.len(), 1, "delegatecall to temp var should emit UnsafeDelegatecall");
        assert_eq!(findings[0].kind, SeVulnKind::UnsafeDelegatecall);
    }

    #[test]
    fn test_delegatecall_with_value_in_loop_emits_payable_delegatecall() {
        // delegatecall with a Value option at path_depth=1 should emit PayableDelegatecallInLoop.
        let (mut state, solver) = make_state_and_solver();
        state.path_depth = 1;
        let mut det = DelegatecallDetector::new();
        let instr = IrInstr::Call {
            dest: vec![],
            callee: IrValue::Var(IrVar::Named("delegatecall".to_string())),
            args: vec![IrValue::Var(IrVar::Temp(0))],
            options: vec![IrCallOption::Value(IrValue::Var(IrVar::Temp(1)))],
            span: span(),
        };
        let findings = det.on_instruction(&state, &instr, &solver);
        assert!(
            findings.iter().any(|f| f.kind == SeVulnKind::PayableDelegatecallInLoop),
            "delegatecall with value at path_depth>0 should emit PayableDelegatecallInLoop"
        );
    }

    #[test]
    fn test_delegatecall_with_value_at_depth_zero_no_payable_finding() {
        // At path_depth=0, delegatecall with value should NOT emit PayableDelegatecallInLoop.
        let (mut state, solver) = make_state_and_solver();
        state.path_depth = 0;
        let mut det = DelegatecallDetector::new();
        let instr = IrInstr::Call {
            dest: vec![],
            callee: IrValue::Var(IrVar::Named("delegatecall".to_string())),
            args: vec![IrValue::Var(IrVar::Temp(0))],
            options: vec![IrCallOption::Value(IrValue::Var(IrVar::Temp(1)))],
            span: span(),
        };
        let findings = det.on_instruction(&state, &instr, &solver);
        assert!(
            !findings.iter().any(|f| f.kind == SeVulnKind::PayableDelegatecallInLoop),
            "path_depth=0 should not emit PayableDelegatecallInLoop"
        );
    }

    #[test]
    fn test_reset_is_noop() {
        // DelegatecallDetector is stateless; reset() should not panic.
        let mut det = DelegatecallDetector::new();
        det.reset(); // must not panic
    }

    #[test]
    fn test_delegatecall_via_member_chain_emits_unsafe() {
        // Simulates the actual IR for `lib.delegatecall(data)` via member chain:
        //   Load Temp(0) <- Member{base:Named("lib"), field:"delegatecall", root:Some("lib")}
        //   Call callee:Var(Temp(0)), args:[Var(Temp(1))]
        // Should emit UnsafeDelegatecall (Temp(1) is user-controlled).
        use chainvet_core::ir::IrPlace;
        use chainvet_core::ir::PlaceClass;

        let (state, solver) = make_state_and_solver();
        let mut det = DelegatecallDetector::new();

        // Load lib.delegatecall -> Temp(0)
        det.on_instruction(
            &state,
            &IrInstr::Load {
                dest: IrVar::Temp(0),
                src: IrPlace::Member {
                    base: IrValue::Var(IrVar::Named("lib".to_string())),
                    field: "delegatecall".to_string(),
                    root: Some("lib".to_string()),
                    class: PlaceClass::Unknown,
                },
                span: span(),
            },
            &solver,
        );

        // Call Temp(0) with Temp(1) as argument
        let findings = det.on_instruction(
            &state,
            &IrInstr::Call {
                dest: vec![],
                callee: IrValue::Var(IrVar::Temp(0)),
                args: vec![IrValue::Var(IrVar::Temp(1))],
                options: vec![],
                span: span(),
            },
            &solver,
        );
        assert_eq!(
            findings.len(),
            1,
            "delegatecall via member chain should emit UnsafeDelegatecall"
        );
        assert_eq!(findings[0].kind, SeVulnKind::UnsafeDelegatecall);
    }
}

/// Returns true if a value is not a known constant.
fn is_user_controlled(val: &IrValue) -> bool {
    match val {
        IrValue::Var(IrVar::Named(n)) => n != "this" && n != "address(this)",
        IrValue::Var(IrVar::Temp(_)) | IrValue::Unknown => true,
        IrValue::Literal(_) => false,
    }
}

