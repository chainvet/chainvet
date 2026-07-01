use crate::symbolic::detectors::{Detector, make_finding, place_matches};
use crate::symbolic::results::finding::{Confidence, SeFinding, SeVulnKind};
use crate::symbolic::solver::SmtSolver;
use crate::symbolic::state::SymbolicState;
use chainvet_core::cfg::BlockId;
use chainvet_core::ir::IrInstr;
use chainvet_sa::analysis::detectors::Severity;

/// Detects storage and memory vulnerabilities.
///
/// Covers:
/// - `MsgValueInLoop` — `msg.value` accessed inside a loop/branch (path_depth > 0)
/// - `ArbitraryFunctionJump` — inline assembly may contain arbitrary jumps
/// - `UnsafeAssembly` — any inline assembly usage
pub struct StorageDetector;

impl Default for StorageDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Detector for StorageDetector {
    fn id(&self) -> &'static str {
        "storage"
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
                if place_matches(src, "msg", "value") && state.path_depth > 0 {
                    return vec![make_finding(
                        SeVulnKind::MsgValueInLoop,
                        Severity::Medium,
                        Confidence::Low,
                        "msg.value accessed inside a loop; each iteration may transfer ETH \
                         from the original call, leading to fund loss",
                        *span,
                        state,
                        None,
                    )];
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
                        *span,
                        state,
                        None,
                    ),
                    make_finding(
                        SeVulnKind::ArbitraryFunctionJump,
                        Severity::Medium,
                        Confidence::Low,
                        "Inline assembly may contain arbitrary JUMP instructions; \
                         static analysis required for full verification",
                        *span,
                        state,
                        None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbolic::results::finding::SeVulnKind;
    use crate::symbolic::solver::z3_backend::Z3Backend;
    use crate::symbolic::state::call_context::CallContext;
    use crate::symbolic::state::{StateIdGen, SymbolicState};
    use chainvet_core::ir::{IrInstr, IrPlace, IrVar, PlaceClass};
    use chainvet_core::norm::Span;

    fn span() -> Span {
        Span {
            file: 0,
            start: 0,
            end: 0,
        }
    }

    fn make_state_and_solver() -> (SymbolicState, Z3Backend) {
        let mut id_gen = StateIdGen::new();
        let (call_ctx, _) = CallContext::new_symbolic();
        let state = SymbolicState::initial(&mut id_gen, 0, call_ctx);
        (state, Z3Backend::new(0))
    }

    fn inline_asm_instr() -> IrInstr {
        IrInstr::InlineAsm {
            language: Some("assembly".to_string()),
            span: span(),
        }
    }

    fn msg_value_load_instr() -> IrInstr {
        IrInstr::Load {
            dest: IrVar::Temp(0),
            src: IrPlace::Var {
                var: IrVar::Named("msg.value".to_string()),
                class: PlaceClass::Unknown,
            },
            span: span(),
        }
    }

    #[test]
    fn test_nop_no_findings() {
        // Nop should produce no storage/memory findings.
        let (state, solver) = make_state_and_solver();
        let mut det = StorageDetector;
        let findings = det.on_instruction(&state, &IrInstr::Nop { span: span() }, &solver);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_msg_value_at_depth_zero_no_finding() {
        // Loading msg.value at path_depth=0 should not trigger MsgValueInLoop.
        let (mut state, solver) = make_state_and_solver();
        state.path_depth = 0;
        let mut det = StorageDetector;
        let findings = det.on_instruction(&state, &msg_value_load_instr(), &solver);
        assert!(
            findings.is_empty(),
            "msg.value at depth=0 should not trigger MsgValueInLoop"
        );
    }

    #[test]
    fn test_msg_value_in_loop_emits_finding() {
        // Loading msg.value at path_depth=1 (inside a loop) should emit MsgValueInLoop.
        let (mut state, solver) = make_state_and_solver();
        state.path_depth = 1;
        let mut det = StorageDetector;
        let findings = det.on_instruction(&state, &msg_value_load_instr(), &solver);
        assert_eq!(
            findings.len(),
            1,
            "msg.value inside loop should emit MsgValueInLoop"
        );
        assert_eq!(findings[0].kind, SeVulnKind::MsgValueInLoop);
    }

    #[test]
    fn test_inline_asm_emits_unsafe_assembly() {
        // InlineAsm should emit UnsafeAssembly.
        let (state, solver) = make_state_and_solver();
        let mut det = StorageDetector;
        let findings = det.on_instruction(&state, &inline_asm_instr(), &solver);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == SeVulnKind::UnsafeAssembly),
            "inline assembly should emit UnsafeAssembly"
        );
    }

    #[test]
    fn test_inline_asm_emits_arbitrary_function_jump() {
        // InlineAsm should also emit ArbitraryFunctionJump.
        let (state, solver) = make_state_and_solver();
        let mut det = StorageDetector;
        let findings = det.on_instruction(&state, &inline_asm_instr(), &solver);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == SeVulnKind::ArbitraryFunctionJump),
            "inline assembly should emit ArbitraryFunctionJump"
        );
    }

    #[test]
    fn test_inline_asm_emits_two_findings() {
        // A single InlineAsm instruction should produce exactly two findings (UnsafeAssembly + ArbitraryFunctionJump).
        let (state, solver) = make_state_and_solver();
        let mut det = StorageDetector;
        let findings = det.on_instruction(&state, &inline_asm_instr(), &solver);
        assert_eq!(
            findings.len(),
            2,
            "InlineAsm should produce exactly two findings"
        );
    }

    #[test]
    fn test_msg_value_as_member_place_in_loop_emits_finding() {
        // Simulates the actual IR for `msg.value` as a Member place at path_depth > 0:
        //   Load Temp(0) <- Member{base:Named("msg"), field:"value", root:Some("msg")}
        // At path_depth=1, should emit MsgValueInLoop.
        use chainvet_core::ir::IrValue;

        let (mut state, solver) = make_state_and_solver();
        state.path_depth = 1;
        let mut det = StorageDetector;

        let findings = det.on_instruction(
            &state,
            &IrInstr::Load {
                dest: IrVar::Temp(0),
                src: IrPlace::Member {
                    base: IrValue::Var(IrVar::Named("msg".to_string())),
                    field: "value".to_string(),
                    root: Some("msg".to_string()),
                    class: PlaceClass::Unknown,
                },
                span: span(),
            },
            &solver,
        );
        assert_eq!(
            findings.len(),
            1,
            "msg.value as Member place at path_depth=1 should emit MsgValueInLoop"
        );
        assert_eq!(findings[0].kind, SeVulnKind::MsgValueInLoop);
    }

    #[test]
    fn test_msg_value_as_member_place_at_depth_zero_no_finding() {
        // Same Member place form but at path_depth=0 should not emit.
        use chainvet_core::ir::IrValue;

        let (mut state, solver) = make_state_and_solver();
        state.path_depth = 0;
        let mut det = StorageDetector;

        let findings = det.on_instruction(
            &state,
            &IrInstr::Load {
                dest: IrVar::Temp(0),
                src: IrPlace::Member {
                    base: IrValue::Var(IrVar::Named("msg".to_string())),
                    field: "value".to_string(),
                    root: Some("msg".to_string()),
                    class: PlaceClass::Unknown,
                },
                span: span(),
            },
            &solver,
        );
        assert!(
            findings.is_empty(),
            "msg.value as Member at depth=0 should not emit MsgValueInLoop"
        );
    }
}
