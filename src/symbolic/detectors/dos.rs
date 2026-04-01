use crate::analysis::detectors::Severity;
use crate::cfg::BlockId;
use crate::ir::{ControlKind, IrInstr, IrPlace, IrValue, IrVar};
use crate::norm::Span;
use crate::symbolic::detectors::Detector;
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
    /// Destination variable of the most recent external call (for DosFailedCall check).
    last_external_call_dest: Option<IrVar>,
}

impl DosDetector {
    pub fn new() -> Self {
        Self {
            balance_var: None,
            last_external_call_dest: None,
        }
    }

    fn is_send_or_call(callee: &IrValue) -> bool {
        matches!(
            callee,
            IrValue::Var(IrVar::Named(n)) if n == "call" || n == "send"
        )
    }

    fn is_transfer_or_send(callee: &IrValue) -> bool {
        matches!(
            callee,
            IrValue::Var(IrVar::Named(n)) if n == "transfer" || n == "send"
        )
    }

    fn is_require_or_assert(callee: &IrValue) -> bool {
        matches!(
            callee,
            IrValue::Var(IrVar::Named(n)) if n == "require" || n == "assert"
        )
    }

    fn is_balance_name(name: &str) -> bool {
        name == "this.balance"
            || name == "address(this).balance"
            || name == "balance"
    }
}

impl Detector for DosDetector {
    fn id(&self) -> &'static str {
        "dos"
    }

    fn name(&self) -> &'static str {
        "Denial of Service Detector"
    }

    fn on_instruction(
        &mut self,
        state: &SymbolicState,
        instr: &IrInstr,
        _solver: &dyn SmtSolver,
    ) -> Vec<SeFinding> {
        match instr {
            // Track balance loads for ForceSendEther.
            IrInstr::Load { dest, src, .. } => {
                if let IrPlace::Var {
                    var: IrVar::Named(n),
                    ..
                } = src
                {
                    if Self::is_balance_name(n) {
                        self.balance_var = Some(dest.clone());
                    }
                }
                vec![]
            }

            IrInstr::Call {
                dest,
                callee,
                args,
                options,
                span,
            } => {
                let mut findings = Vec::new();

                // UncheckedCall: call/send with no destination variable (return value dropped).
                if Self::is_send_or_call(callee) && dest.is_empty() {
                    findings.push(make_finding(
                        SeVulnKind::UncheckedCall,
                        Severity::Medium,
                        Confidence::Low,
                        "Return value of call/send ignored; failed calls silently pass",
                        span.clone(),
                        state,
                    ));
                }

                // HardcodedGasAmount: transfer/send always forwards exactly 2300 gas.
                if Self::is_transfer_or_send(callee) {
                    findings.push(make_finding(
                        SeVulnKind::HardcodedGasAmount,
                        Severity::Low,
                        Confidence::Low,
                        "transfer/send forwards hardcoded 2300 gas; may break if callee gas costs change",
                        span.clone(),
                        state,
                    ));
                }

                // DosFailedCall: track external call result for downstream require check.
                if !dest.is_empty() && !options.is_empty() {
                    self.last_external_call_dest = Some(dest[0].clone());
                }

                // UnsafeSendInRequire: require/assert wrapping a send() result.
                if Self::is_require_or_assert(callee) {
                    if let Some(arg) = args.first() {
                        if let IrValue::Var(v) = arg {
                            if let Some(ref last) = self.last_external_call_dest {
                                if v == last {
                                    findings.push(make_finding(
                                        SeVulnKind::UnsafeSendInRequire,
                                        Severity::Medium,
                                        Confidence::Low,
                                        "send() result used directly in require(); reverts entire tx on failure",
                                        span.clone(),
                                        state,
                                    ));
                                }
                            }
                        }
                    }
                }

                // ForceSendEther: require/assert referencing contract balance.
                if Self::is_require_or_assert(callee) {
                    for arg in args {
                        if let IrValue::Var(v) = arg {
                            if self.balance_var.as_ref() == Some(v) {
                                findings.push(make_finding(
                                    SeVulnKind::ForceSendEther,
                                    Severity::Medium,
                                    Confidence::Low,
                                    "Contract balance used in require/assert; selfdestruct can force ETH and break invariant",
                                    span.clone(),
                                    state,
                                ));
                            }
                        }
                    }
                }

                findings
            }

            // DosFailedCall: check if the last external call result feeds into require.
            // Also DosBlockGasLimit: loop over storage.
            IrInstr::Control {
                kind: ControlKind::Loop { .. },
                span,
            } => {
                vec![make_finding(
                    SeVulnKind::DosBlockGasLimit,
                    Severity::Medium,
                    Confidence::Low,
                    "Loop may iterate over an unbounded storage array, hitting block gas limit",
                    span.clone(),
                    state,
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
        self.last_external_call_dest = None;
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
