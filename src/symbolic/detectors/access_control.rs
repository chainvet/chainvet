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

    fn name(&self) -> &'static str {
        "Access Control Detector"
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
                        span.clone(),
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
                        span.clone(),
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
                        span.clone(),
                    ));
                }

                // AccessControlMissing: general ETH-sending call without any sender guard.
                if !self.has_sender_check && !Self::has_sender_restriction(state) {
                    findings.push(make_finding(
                        SeVulnKind::AccessControlMissing,
                        Severity::High,
                        Confidence::Low,
                        "ETH-sending call without msg.sender check",
                        span.clone(),
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
                {
                    if is_user_controlled_value(idx) {
                        return check_reachable_and_emit(
                            state,
                            solver,
                            SeVulnKind::ArbitraryStorageWrite,
                            Severity::High,
                            Confidence::Medium,
                            "Storage write at user-controlled index may overwrite arbitrary slots",
                            span.clone(),
                        );
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
        self.tx_origin_loaded = false;
        self.has_sender_check = false;
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
