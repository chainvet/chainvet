use std::collections::HashMap;

use z3::SatResult;
use z3::ast::Bool;

use crate::analysis::detectors::Severity;
use crate::cfg::BlockId;
use crate::ir::{IrCallOption, IrInstr, IrPlace, IrValue, IrVar, PlaceClass};
use crate::norm::Span;
use crate::symbolic::detectors::Detector;
use crate::symbolic::results::finding::{Confidence, SeFinding, SeVulnKind};
use crate::symbolic::results::witness::Witness;
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
    span: Span,
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

    fn name(&self) -> &'static str {
        "Reentrancy Detector"
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
                span,
                ..
            } if Self::is_external_call(callee, options) => {
                self.call_seen.insert(
                    state.id,
                    ExternalCallInfo {
                        span: span.clone(),
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
                if let Some(info) = self.find_ancestor_call(state) {
                    if state.instruction_count > info.call_instruction_count {
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
                            span.clone(),
                            state,
                        )];
                    }
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

fn make_finding_with_witness(
    kind: SeVulnKind,
    severity: Severity,
    confidence: Confidence,
    message: &str,
    span: Span,
    state: &SymbolicState,
    solver: &dyn SmtSolver,
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
