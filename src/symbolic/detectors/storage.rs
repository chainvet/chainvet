use crate::analysis::detectors::Severity;
use crate::cfg::BlockId;
use crate::ir::{IrInstr, IrPlace, IrVar};
use crate::norm::Span;
use crate::symbolic::detectors::Detector;
use crate::symbolic::results::finding::{Confidence, SeFinding, SeVulnKind};
use crate::symbolic::solver::SmtSolver;
use crate::symbolic::state::SymbolicState;

/// Detects storage and memory vulnerabilities.
///
/// Covers:
/// - `MsgValueInLoop` — `msg.value` accessed inside a loop/branch (path_depth > 0)
/// - `ArbitraryFunctionJump` — inline assembly may contain arbitrary jumps
/// - `UnsafeAssembly` — any inline assembly usage
pub struct StorageDetector;

impl Detector for StorageDetector {
    fn id(&self) -> &'static str {
        "storage"
    }

    fn name(&self) -> &'static str {
        "Storage and Memory Detector"
    }

    fn on_instruction(
        &mut self,
        state: &SymbolicState,
        instr: &IrInstr,
        _solver: &dyn SmtSolver,
    ) -> Vec<SeFinding> {
        match instr {
            // MsgValueInLoop: msg.value read inside a loop body.
            IrInstr::Load { src, span, .. } => {
                if let IrPlace::Var {
                    var: IrVar::Named(n),
                    ..
                } = src
                {
                    if (n == "msg.value" || n == "msg_value") && state.path_depth > 0 {
                        return vec![make_finding(
                            SeVulnKind::MsgValueInLoop,
                            Severity::Medium,
                            Confidence::Low,
                            "msg.value accessed inside a loop; each iteration may transfer ETH \
                             from the original call, leading to fund loss",
                            span.clone(),
                            state,
                        )];
                    }
                }
                vec![]
            }

            // ArbitraryFunctionJump and UnsafeAssembly: any inline assembly.
            IrInstr::InlineAsm { span, .. } => {
                vec![
                    make_finding(
                        SeVulnKind::UnsafeAssembly,
                        Severity::Medium,
                        Confidence::Low,
                        "Inline assembly bypasses Solidity safety checks; memory/storage may be \
                         manipulated in unexpected ways",
                        span.clone(),
                        state,
                    ),
                    make_finding(
                        SeVulnKind::ArbitraryFunctionJump,
                        Severity::Medium,
                        Confidence::Low,
                        "Inline assembly may contain arbitrary JUMP instructions; \
                         static analysis required for full verification",
                        span.clone(),
                        state,
                    ),
                ]
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

    fn reset(&mut self) {}
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
