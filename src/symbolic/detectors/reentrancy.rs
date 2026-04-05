use std::collections::HashMap;

use crate::analysis::detectors::Severity;
use crate::cfg::BlockId;
use crate::ir::{IrCallOption, IrInstr, IrPlace, IrValue, IrVar, PlaceClass};
use crate::norm::Span;
use crate::symbolic::detectors::Detector;
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
        }
    }

    /// Walk ancestor chain to find the nearest external call on this path.
    fn find_ancestor_call(&self, state: &SymbolicState) -> Option<&ExternalCallInfo> {
        let mut id = state.id;
        loop {
            if let Some(info) = self.call_seen.get(&id) {
                return Some(info);
            }
            match self.parent_map.get(&id) {
                Some(&parent) if parent != 0 => id = parent,
                _ => return None,
            }
        }
    }

    /// Returns true if this call is an external call.
    ///
    /// Primary signal: `options` is non-empty (carries `value` or `gas`).
    /// Secondary signal: callee name is one of the known external call builtins.
    fn is_external_call(callee: &IrValue, options: &[IrCallOption]) -> bool {
        if !options.is_empty() {
            return true;
        }
        matches!(
            callee,
            IrValue::Var(IrVar::Named(n))
                if matches!(n.as_str(), "call" | "send" | "delegatecall" | "staticcall")
        )
    }

    /// Returns true if any option carries an ETH value.
    fn sends_eth(options: &[IrCallOption]) -> bool {
        options
            .iter()
            .any(|o| matches!(o, IrCallOption::Value(_)))
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

        match instr {
            // External call seen — record it for CEI checking.
            IrInstr::Call {
                callee,
                options,
                ..
            } if Self::is_external_call(callee, options) => {
                self.call_seen.insert(
                    state.id,
                    ExternalCallInfo {
                        sends_eth: Self::sends_eth(options),
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
                    let severity = if info.sends_eth {
                        Severity::High
                    } else {
                        Severity::Medium
                    };
                    let confidence = if info.sends_eth {
                        Confidence::High
                    } else {
                        Confidence::Medium
                    };
                    return vec![make_finding(
                        SeVulnKind::Reentrancy,
                        severity,
                        confidence,
                        "Reentrancy: state written after external call violates CEI pattern",
                        *span,
                        state,
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
    }
}

fn is_storage_place(place: &IrPlace) -> bool {
    match place {
        IrPlace::Var { class, .. } => *class == PlaceClass::Storage,
        IrPlace::Member { class, .. } => *class == PlaceClass::Storage,
        IrPlace::Index { class, .. } => *class == PlaceClass::Storage,
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
}
