use std::collections::HashMap;

use crate::analysis::detectors::Severity;
use crate::cfg::BlockId;
use crate::ir::{IrCallOption, IrInstr, IrPlace, IrValue, PlaceClass};
use crate::symbolic::detectors::{make_finding, CalleeTracker, Detector};
use crate::symbolic::results::finding::{Confidence, SeFinding, SeVulnKind};
use crate::symbolic::solver::SmtSolver;
use crate::symbolic::state::{StateId, SymbolicState};

/// Detects reentrancy vulnerabilities by tracking CEI (Checks-Effects-Interactions) violations.
///
/// Covers all 5 taxonomy patterns:
/// - Reentrancy with Negative Events
/// - Reentrancy with Transfer
/// - Reentrancy with Same Effect
/// - Reentrancy with ETH Transfer
/// - Reentrancy without ETH Transfer
pub struct ReentrancyDetector {
    /// Per-state: the most recent external call seen on that state's path.
    call_seen: HashMap<StateId, ExternalCallInfo>,
    /// Parent state ID map for ancestor traversal across forks.
    parent_map: HashMap<StateId, StateId>,
    /// Tracks member-load chains for resolving Temp callees.
    tracker: CalleeTracker,
}

struct ExternalCallInfo {
    sends_eth: bool,
    /// `state.instruction_count` at the call site.
    call_instruction_count: u32,
}

impl ReentrancyDetector {
    pub fn new() -> Self {
        Self {
            call_seen: HashMap::new(),
            parent_map: HashMap::new(),
            tracker: CalleeTracker::new(),
        }
    }

    /// Walk ancestor chain to find the nearest external call on this path.
    fn find_ancestor_call(&self, state: &SymbolicState) -> Option<&ExternalCallInfo> {
        let mut id = state.id;
        for _ in 0..1000 {
            if let Some(info) = self.call_seen.get(&id) {
                return Some(info);
            }
            match self.parent_map.get(&id) {
                Some(&parent) if parent != 0 => id = parent,
                _ => return None,
            }
        }
        None
    }

    /// Returns true if this call is an external call.
    ///
    /// Checks three signals (in order):
    /// 1. `options` is non-empty (carries `value` or `gas`)
    /// 2. Callee is a Named external call builtin
    /// 3. Callee is a Temp loaded from a `.call`/`.send`/etc. member chain
    fn is_external_call(&self, callee: &IrValue, options: &[IrCallOption]) -> bool {
        if !options.is_empty() {
            return true;
        }
        self.tracker
            .chain_contains_field(callee, &["call", "send", "delegatecall", "staticcall"])
    }

    /// Returns true if the call sends ETH.
    ///
    /// Checks both `IrCallOption::Value` and `.value()` in the member chain
    /// (the IR may represent `.call.value(amt)()` as a member load, not an option).
    fn sends_eth(&self, callee: &IrValue, options: &[IrCallOption]) -> bool {
        options
            .iter()
            .any(|o| matches!(o, IrCallOption::Value(_)))
            || self.tracker.chain_contains_field(callee, &["value"])
    }
}

impl Detector for ReentrancyDetector {
    fn id(&self) -> &'static str {
        "reentrancy"
    }

    fn on_instruction(
        &mut self,
        state: &SymbolicState,
        instr: &IrInstr,
        _solver: &dyn SmtSolver,
    ) -> Vec<SeFinding> {
        // Maintain parent map for ancestor traversal.
        self.parent_map.entry(state.id).or_insert(state.parent_id);

        // Track member loads for callee resolution.
        if let IrInstr::Load { dest, src, .. } = instr {
            self.tracker.track_load(dest, src);
        }

        match instr {
            // External call seen — record it for CEI checking.
            IrInstr::Call {
                callee,
                options,
                ..
            } if self.is_external_call(callee, options) => {
                self.call_seen.insert(
                    state.id,
                    ExternalCallInfo {
                        sends_eth: self.sends_eth(callee, options),
                        call_instruction_count: state.instruction_count,
                    },
                );
                vec![]
            }

            // Storage write after an external call → CEI violation.
            IrInstr::Store {
                dest,
                span,
                ..
            } if is_storage_place(dest) => {
                if let Some(info) = self.find_ancestor_call(state)
                    && state.instruction_count > info.call_instruction_count
                {
                    // Sender-guarded reentrancy is lower risk (attacker must own the
                    // authorized address), but still a CEI violation.
                    let guarded = state.sender_checked;
                    let severity = if guarded {
                        Severity::Medium
                    } else if info.sends_eth {
                        Severity::High
                    } else {
                        Severity::Medium
                    };
                    let confidence = if info.sends_eth && !guarded {
                        Confidence::High
                    } else {
                        Confidence::Medium
                    };
                    let msg = if guarded {
                        "Reentrancy: state written after external call (sender-guarded, lower risk)"
                    } else {
                        "Reentrancy: state written after external call violates CEI pattern"
                    };
                    return vec![make_finding(
                        SeVulnKind::Reentrancy,
                        severity,
                        confidence,
                        msg,
                        *span,
                        state,
                        None,
                    )];
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
        self.call_seen.clear();
        self.parent_map.clear();
        self.tracker.reset();
    }
}

fn is_storage_place(place: &IrPlace) -> bool {
    match place {
        IrPlace::Var { class, .. } => *class == PlaceClass::Storage,
        IrPlace::Member { class, .. } => *class == PlaceClass::Storage,
        IrPlace::Index { class, .. } => *class == PlaceClass::Storage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{IrCallOption, IrInstr, IrPlace, IrValue, IrVar, PlaceClass};
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

    fn external_call_instr() -> IrInstr {
        // A Call with a Value option is treated as an external call.
        IrInstr::Call {
            dest: vec![],
            callee: IrValue::Var(IrVar::Named("call".to_string())),
            args: vec![],
            options: vec![IrCallOption::Value(IrValue::Var(IrVar::Temp(0)))],
            span: span(),
        }
    }

    fn storage_write_instr() -> IrInstr {
        IrInstr::Store {
            dest: IrPlace::Var {
                var: IrVar::Named("balance".to_string()),
                class: PlaceClass::Storage,
            },
            src: IrValue::Var(IrVar::Temp(1)),
            span: span(),
        }
    }

    fn memory_write_instr() -> IrInstr {
        IrInstr::Store {
            dest: IrPlace::Var {
                var: IrVar::Named("local".to_string()),
                class: PlaceClass::Memory,
            },
            src: IrValue::Var(IrVar::Temp(1)),
            span: span(),
        }
    }

    #[test]
    fn test_no_findings_on_nop() {
        // A Nop instruction should never trigger reentrancy detector findings.
        let (state, solver) = make_state_and_solver();
        let mut det = ReentrancyDetector::new();
        let findings = det.on_instruction(&state, &IrInstr::Nop { span: span() }, &solver);
        assert!(findings.is_empty(), "Nop should produce no findings");
    }

    #[test]
    fn test_external_call_does_not_immediately_emit() {
        // An external call (with Value option) records state but emits no finding itself.
        let (state, solver) = make_state_and_solver();
        let mut det = ReentrancyDetector::new();
        let findings = det.on_instruction(&state, &external_call_instr(), &solver);
        assert!(findings.is_empty(), "external call alone should not emit a finding");
    }

    #[test]
    fn test_storage_write_after_external_call_emits_reentrancy() {
        // External call followed by storage write with higher instruction_count → Reentrancy.
        let (mut state, solver) = make_state_and_solver();
        let mut det = ReentrancyDetector::new();

        // Process the external call at instruction_count=0.
        state.instruction_count = 0;
        det.on_instruction(&state, &external_call_instr(), &solver);

        // Increment instruction_count to simulate instructions after the call.
        state.instruction_count = 1;
        let findings = det.on_instruction(&state, &storage_write_instr(), &solver);
        assert_eq!(findings.len(), 1, "storage write after external call should emit Reentrancy");
        assert_eq!(findings[0].kind, SeVulnKind::Reentrancy);
    }

    #[test]
    fn test_storage_write_before_call_no_finding() {
        // Storage write at instruction_count=0, then call records count=1 → write came before call.
        // We test this by doing the write first without any prior call recorded.
        let (mut state, solver) = make_state_and_solver();
        let mut det = ReentrancyDetector::new();

        // Storage write with no prior external call → no reentrancy.
        state.instruction_count = 0;
        let findings = det.on_instruction(&state, &storage_write_instr(), &solver);
        assert!(findings.is_empty(), "storage write with no prior call should not emit finding");
    }

    #[test]
    fn test_non_external_call_no_tracking() {
        // A call to "require" with no options is not an external call → no tracking.
        let (mut state, solver) = make_state_and_solver();
        let mut det = ReentrancyDetector::new();

        let require_call = IrInstr::Call {
            dest: vec![],
            callee: IrValue::Var(IrVar::Named("require".to_string())),
            args: vec![IrValue::Var(IrVar::Temp(0))],
            options: vec![],
            span: span(),
        };
        state.instruction_count = 0;
        det.on_instruction(&state, &require_call, &solver);

        // Storage write after a non-external call should not trigger reentrancy.
        state.instruction_count = 1;
        let findings = det.on_instruction(&state, &storage_write_instr(), &solver);
        assert!(findings.is_empty(), "require call should not be tracked as external call");
    }

    #[test]
    fn test_reset_clears_state() {
        // After reset, a storage write following a prior external call should not emit.
        let (mut state, solver) = make_state_and_solver();
        let mut det = ReentrancyDetector::new();

        state.instruction_count = 0;
        det.on_instruction(&state, &external_call_instr(), &solver);
        det.reset();

        state.instruction_count = 1;
        let findings = det.on_instruction(&state, &storage_write_instr(), &solver);
        assert!(findings.is_empty(), "reset should clear external call tracking");
    }

    #[test]
    fn test_non_storage_write_no_finding() {
        // A write to Memory (not Storage) after an external call should not trigger reentrancy.
        let (mut state, solver) = make_state_and_solver();
        let mut det = ReentrancyDetector::new();

        state.instruction_count = 0;
        det.on_instruction(&state, &external_call_instr(), &solver);

        state.instruction_count = 1;
        let findings = det.on_instruction(&state, &memory_write_instr(), &solver);
        assert!(findings.is_empty(), "memory write should not trigger reentrancy");
    }

    #[test]
    fn test_reentrancy_via_member_chain_call_value() {
        // Simulates the actual IR shape for `msg.sender.call.value(amount)()`:
        //   Load Temp(3) <- Member{base:Named("msg"), field:"sender"}
        //   Load Temp(4) <- Member{base:Var(Temp(3)), field:"call"}
        //   Load Temp(5) <- Member{base:Var(Temp(4)), field:"value"}
        //   Call callee:Var(Temp(5))
        //   Store to storage  (should trigger Reentrancy)
        let (mut state, solver) = make_state_and_solver();
        let mut det = ReentrancyDetector::new();

        // Load msg.sender -> Temp(3)
        state.instruction_count = 0;
        det.on_instruction(
            &state,
            &IrInstr::Load {
                dest: IrVar::Temp(3),
                src: IrPlace::Member {
                    base: IrValue::Var(IrVar::Named("msg".to_string())),
                    field: "sender".to_string(),
                    root: Some("msg".to_string()),
                    class: PlaceClass::Unknown,
                },
                span: span(),
            },
            &solver,
        );

        // Load Temp(3).call -> Temp(4)
        state.instruction_count = 1;
        det.on_instruction(
            &state,
            &IrInstr::Load {
                dest: IrVar::Temp(4),
                src: IrPlace::Member {
                    base: IrValue::Var(IrVar::Temp(3)),
                    field: "call".to_string(),
                    root: Some("msg".to_string()),
                    class: PlaceClass::Unknown,
                },
                span: span(),
            },
            &solver,
        );

        // Load Temp(4).value -> Temp(5)
        state.instruction_count = 2;
        det.on_instruction(
            &state,
            &IrInstr::Load {
                dest: IrVar::Temp(5),
                src: IrPlace::Member {
                    base: IrValue::Var(IrVar::Temp(4)),
                    field: "value".to_string(),
                    root: Some("msg".to_string()),
                    class: PlaceClass::Unknown,
                },
                span: span(),
            },
            &solver,
        );

        // Call Temp(5) — external call via member chain (contains "call" and "value")
        state.instruction_count = 3;
        let findings = det.on_instruction(
            &state,
            &IrInstr::Call {
                dest: vec![],
                callee: IrValue::Var(IrVar::Temp(5)),
                args: vec![IrValue::Var(IrVar::Temp(0))],
                options: vec![],
                span: span(),
            },
            &solver,
        );
        assert!(findings.is_empty(), "external call alone should not emit finding");

        // Storage write after the call -> should trigger Reentrancy
        state.instruction_count = 4;
        let findings = det.on_instruction(&state, &storage_write_instr(), &solver);
        assert_eq!(
            findings.len(),
            1,
            "storage write after member-chain external call should emit Reentrancy"
        );
        assert_eq!(findings[0].kind, SeVulnKind::Reentrancy);
        // The call sends ETH (chain contains "value"), so severity should be High.
        assert_eq!(findings[0].severity, Severity::High);
    }
}
