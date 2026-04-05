use std::collections::HashSet;

use crate::analysis::detectors::Severity;
use crate::cfg::BlockId;
use crate::ir::{ControlKind, IrInstr, IrPlace, IrVar, IrValue};
use crate::norm::Span;
use crate::symbolic::detectors::Detector;
use crate::symbolic::results::finding::{Confidence, SeFinding, SeVulnKind};
use crate::symbolic::solver::SmtSolver;
use crate::symbolic::state::SymbolicState;

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

    fn is_timestamp_name(name: &str) -> bool {
        name == "block.timestamp"
            || name == "block_timestamp"
            || name == "now"
    }

    fn is_block_entropy_name(name: &str) -> bool {
        name == "block.number"
            || name == "block_number"
            || name == "block.difficulty"
            || name == "block.prevrandao"
            || name == "blockhash"
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
                if let IrPlace::Var {
                    var: IrVar::Named(n),
                    ..
                } = src
                {
                    if Self::is_timestamp_name(n) {
                        self.timestamp_vars.insert(dest.clone());
                    } else if Self::is_block_entropy_name(n) {
                        self.block_vars.insert(dest.clone());
                    }
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

                if Self::value_in_set(cond, &self.timestamp_vars) {
                    findings.push(make_finding(
                        SeVulnKind::TimestampDependency,
                        Severity::Low,
                        Confidence::Low,
                        "Branch condition depends on block.timestamp; miners can manipulate this value",
                        *span,
                        state,
                    ));
                }

                if Self::value_in_set(cond, &self.prng_vars) {
                    findings.push(make_finding(
                        SeVulnKind::WeakPRNG,
                        Severity::High,
                        Confidence::Low,
                        "Randomness derived from block variables is predictable and miner-manipulable",
                        *span,
                        state,
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
