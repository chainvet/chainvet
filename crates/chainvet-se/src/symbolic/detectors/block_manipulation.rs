use std::collections::HashSet;

use chainvet_sa::analysis::detectors::Severity;
use chainvet_core::cfg::BlockId;
use chainvet_core::ir::{ControlKind, IrInstr, IrPlace, IrVar, IrValue};
use crate::symbolic::detectors::{make_finding, place_matches, value_has_origin, Detector};
use crate::symbolic::results::finding::{Confidence, SeFinding, SeVulnKind};
use crate::symbolic::solver::SmtSolver;
use crate::symbolic::state::{SymbolicState, ValueOrigin};

/// Detects block-environment manipulation vulnerabilities.
///
/// Covers:
/// - `TimestampDependency` — branch condition depends on `block.timestamp`
/// - `WeakPRNG` — randomness derived from block variables
pub struct BlockManipulationDetector {
    /// Variables that hold a `block.timestamp` value.
    timestamp_vars: HashSet<IrVar>,
    /// Variables that hold other block environment values (number, difficulty, etc.).
    block_vars: HashSet<IrVar>,
    /// Variables derived from block vars via `%` or `&` (PRNG patterns).
    prng_vars: HashSet<IrVar>,
}

impl BlockManipulationDetector {
    pub fn new() -> Self {
        Self {
            timestamp_vars: HashSet::new(),
            block_vars: HashSet::new(),
            prng_vars: HashSet::new(),
        }
    }

    fn is_timestamp_place(place: &IrPlace) -> bool {
        place_matches(place, "block", "timestamp")
            || matches!(
                place,
                IrPlace::Var { var: IrVar::Named(n), .. }
                    if n == "now"
            )
    }

    fn is_block_entropy_place(place: &IrPlace) -> bool {
        place_matches(place, "block", "number")
            || place_matches(place, "block", "difficulty")
            || place_matches(place, "block", "prevrandao")
            || matches!(
                place,
                IrPlace::Var { var: IrVar::Named(n), .. }
                    if n == "blockhash"
            )
    }

    fn value_in_set(val: &IrValue, set: &HashSet<IrVar>) -> bool {
        matches!(val, IrValue::Var(v) if set.contains(v))
    }
}

impl Detector for BlockManipulationDetector {
    fn id(&self) -> &'static str {
        "block-manipulation"
    }

    fn on_instruction(
        &mut self,
        state: &SymbolicState,
        instr: &IrInstr,
        _solver: &dyn SmtSolver,
    ) -> Vec<SeFinding> {
        match instr {
            // Track loads of block environment variables.
            IrInstr::Load { dest, src, .. } => {
                // Match both IrPlace::Var{Named("block.timestamp")} and
                // IrPlace::Member{root:"block", field:"timestamp"} forms.
                if Self::is_timestamp_place(src) {
                    self.timestamp_vars.insert(dest.clone());
                } else if Self::is_block_entropy_place(src) {
                    self.block_vars.insert(dest.clone());
                }
                vec![]
            }

            // Arithmetic on block vars propagates the taint.
            IrInstr::Binary {
                dest,
                op,
                lhs,
                rhs,
                ..
            } => {
                let lhs_is_block = Self::value_in_set(lhs, &self.block_vars)
                    || Self::value_in_set(lhs, &self.timestamp_vars);
                let rhs_is_block = Self::value_in_set(rhs, &self.block_vars)
                    || Self::value_in_set(rhs, &self.timestamp_vars);

                if (lhs_is_block || rhs_is_block) && matches!(op.as_str(), "%" | "&") {
                    self.prng_vars.insert(dest.clone());
                }
                vec![]
            }

            // Conditional branches using timestamp or PRNG vars.
            IrInstr::Control {
                kind: ControlKind::If { cond },
                span,
            } => {
                let mut findings = Vec::new();

                if Self::value_in_set(cond, &self.timestamp_vars)
                    || value_has_origin(state, cond, ValueOrigin::Timestamp)
                {
                    // Higher confidence when the path also reads order-sensitive storage
                    // (e.g., using timestamp to gate a storage-dependent decision).
                    let confidence = if state.saw_order_sensitive_storage_read {
                        Confidence::Medium
                    } else {
                        Confidence::Low
                    };
                    findings.push(make_finding(
                        SeVulnKind::TimestampDependency,
                        Severity::Low,
                        confidence,
                        "Branch condition depends on block.timestamp; miners can manipulate this value",
                        *span,
                        state,
                        None,
                    ));
                }

                if Self::value_in_set(cond, &self.prng_vars)
                    || value_has_origin(state, cond, ValueOrigin::BlockNumber)
                {
                    findings.push(make_finding(
                        SeVulnKind::WeakPRNG,
                        Severity::High,
                        Confidence::Low,
                        "Randomness derived from block variables is predictable and miner-manipulable",
                        *span,
                        state,
                        None,
                    ));
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
        self.timestamp_vars.clear();
        self.block_vars.clear();
        self.prng_vars.clear();
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

    fn load_named(dest: IrVar, name: &str) -> IrInstr {
        IrInstr::Load {
            dest,
            src: IrPlace::Var {
                var: IrVar::Named(name.to_string()),
                class: PlaceClass::Unknown,
            },
            span: span(),
        }
    }

    fn if_cond(var: IrVar) -> IrInstr {
        IrInstr::Control {
            kind: ControlKind::If { cond: IrValue::Var(var) },
            span: span(),
        }
    }

    #[test]
    fn test_nop_no_findings() {
        // Nop should produce no block manipulation findings.
        let (state, solver) = make_state_and_solver();
        let mut det = BlockManipulationDetector::new();
        let findings = det.on_instruction(&state, &IrInstr::Nop { span: span() }, &solver);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_load_timestamp_then_if_emits_timestamp_dependency() {
        // Load block.timestamp into Temp(0), then Control{If{cond:Temp(0)}} → TimestampDependency.
        let (state, solver) = make_state_and_solver();
        let mut det = BlockManipulationDetector::new();

        det.on_instruction(&state, &load_named(IrVar::Temp(0), "block.timestamp"), &solver);
        let findings = det.on_instruction(&state, &if_cond(IrVar::Temp(0)), &solver);
        assert_eq!(findings.len(), 1, "timestamp used in branch should emit TimestampDependency");
        assert_eq!(findings[0].kind, SeVulnKind::TimestampDependency);
    }

    #[test]
    fn test_load_block_var_modulo_then_if_emits_weak_prng() {
        // Load block.number, compute % to get prng_var, use in If → WeakPRNG.
        let (state, solver) = make_state_and_solver();
        let mut det = BlockManipulationDetector::new();

        // Load block.number into Temp(0).
        det.on_instruction(&state, &load_named(IrVar::Temp(0), "block.number"), &solver);

        // Binary{op:"%", dest:Temp(1), lhs:Temp(0), ...} → prng_vars gets Temp(1).
        let modulo_instr = IrInstr::Binary {
            dest: IrVar::Temp(1),
            op: "%".to_string(),
            lhs: IrValue::Var(IrVar::Temp(0)),
            rhs: IrValue::Var(IrVar::Named("n".to_string())),
            span: span(),
        };
        det.on_instruction(&state, &modulo_instr, &solver);

        let findings = det.on_instruction(&state, &if_cond(IrVar::Temp(1)), &solver);
        assert!(
            findings.iter().any(|f| f.kind == SeVulnKind::WeakPRNG),
            "block.number % n used in branch should emit WeakPRNG"
        );
    }

    #[test]
    fn test_non_block_load_no_tracking() {
        // Loading a non-block variable and using it in a branch should not produce findings.
        let (state, solver) = make_state_and_solver();
        let mut det = BlockManipulationDetector::new();

        det.on_instruction(&state, &load_named(IrVar::Temp(0), "some_random_var"), &solver);
        let findings = det.on_instruction(&state, &if_cond(IrVar::Temp(0)), &solver);
        assert!(findings.is_empty(), "non-block variable in branch should not produce findings");
    }

    #[test]
    fn test_reset_clears_sets() {
        // After reset, timestamp loaded before reset should no longer trigger TimestampDependency.
        let (state, solver) = make_state_and_solver();
        let mut det = BlockManipulationDetector::new();

        det.on_instruction(&state, &load_named(IrVar::Temp(0), "block.timestamp"), &solver);
        det.reset();

        let findings = det.on_instruction(&state, &if_cond(IrVar::Temp(0)), &solver);
        assert!(
            !findings.iter().any(|f| f.kind == SeVulnKind::TimestampDependency),
            "reset should clear timestamp_vars set"
        );
    }

    #[test]
    fn test_block_timestamp_as_member_place_emits_timestamp_dependency() {
        // Simulates the actual IR for `block.timestamp` as a Member place:
        //   Load Temp(0) <- Member{base:Named("block"), field:"timestamp", root:Some("block")}
        //   Control{If{cond:Var(Temp(0))}}
        // Should emit TimestampDependency.
        let (state, solver) = make_state_and_solver();
        let mut det = BlockManipulationDetector::new();

        det.on_instruction(
            &state,
            &IrInstr::Load {
                dest: IrVar::Temp(0),
                src: IrPlace::Member {
                    base: IrValue::Var(IrVar::Named("block".to_string())),
                    field: "timestamp".to_string(),
                    root: Some("block".to_string()),
                    class: PlaceClass::Unknown,
                },
                span: span(),
            },
            &solver,
        );

        let findings = det.on_instruction(&state, &if_cond(IrVar::Temp(0)), &solver);
        assert_eq!(
            findings.len(),
            1,
            "block.timestamp as Member place in branch should emit TimestampDependency"
        );
        assert_eq!(findings[0].kind, SeVulnKind::TimestampDependency);
    }
}

