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

    fn name(&self) -> &'static str {
        "Block Manipulation Detector"
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
                        span.clone(),
                        state,
                    ));
                }

                if Self::value_in_set(cond, &self.prng_vars) {
                    findings.push(make_finding(
                        SeVulnKind::WeakPRNG,
                        Severity::High,
                        Confidence::Low,
                        "Randomness derived from block variables is predictable and miner-manipulable",
                        span.clone(),
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
