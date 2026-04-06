use z3::ast::{BV, Bool};
use z3::SatResult;

use crate::analysis::detectors::Severity;
use crate::symbolic::solver::optimization::is_trivially_false;
use crate::cfg::BlockId;
use crate::ir::{IrInstr, IrPlace, IrValue, IrVar};
use crate::norm::Span;
use crate::symbolic::detectors::{make_finding, Detector};
use crate::symbolic::results::finding::{Confidence, SeFinding, SeVulnKind};
use crate::symbolic::results::witness::Witness;
use crate::symbolic::solver::SmtSolver;
use crate::symbolic::state::SymbolicState;
use crate::symbolic::types::literal_to_symbolic;

/// Detects arithmetic vulnerabilities: integer overflow/underflow,
/// division before multiplication, and unsafe array length assignment.
pub struct ArithmeticDetector {
    /// The destination variable of the most recent division instruction,
    /// used to detect the division-before-multiplication antipattern.
    last_div_dest: Option<IrVar>,
}

impl ArithmeticDetector {
    pub fn new() -> Self {
        Self {
            last_div_dest: None,
        }
    }
}

fn eval_to_bv(state: &SymbolicState, val: &IrValue) -> Option<BV> {
    match val {
        IrValue::Var(v) => state.variables.get(v)?.as_bv().cloned(),
        IrValue::Literal(lit) => literal_to_symbolic(lit).as_bv().cloned(),
        IrValue::Unknown => None,
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

impl Detector for ArithmeticDetector {
    fn id(&self) -> &'static str {
        "arithmetic"
    }

    fn on_instruction(
        &mut self,
        state: &SymbolicState,
        instr: &IrInstr,
        solver: &dyn SmtSolver,
    ) -> Vec<SeFinding> {
        match instr {
            IrInstr::Binary {
                dest,
                op,
                lhs,
                rhs,
                span,
            } => self.check_binary(state, solver, dest, op, lhs, rhs, span),

            IrInstr::Store { dest, span, .. } => {
                // Unsafe array length: direct write to a ".length" field.
                if let IrPlace::Member { field, .. } = dest
                    && field == "length"
                {
                    return vec![make_finding(
                        SeVulnKind::UnsafeArrayLength,
                        Severity::Medium,
                        Confidence::Low,
                        "Direct assignment to array length can corrupt storage",
                        *span,
                        state,
                        None,
                    )];
                }
                vec![]
            }

            _ => {
                // Any non-arithmetic instruction breaks the div-before-mul chain.
                self.last_div_dest = None;
                vec![]
            }
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
        self.last_div_dest = None;
    }
}

impl ArithmeticDetector {
    #[allow(clippy::too_many_arguments)]
    fn check_binary(
        &mut self,
        state: &SymbolicState,
        solver: &dyn SmtSolver,
        dest: &IrVar,
        op: &str,
        lhs: &IrValue,
        rhs: &IrValue,
        span: &Span,
    ) -> Vec<SeFinding> {
        match op {
            "/" => {
                self.last_div_dest = Some(dest.clone());
                vec![]
            }
            "*" => self.check_mul(state, solver, lhs, rhs, span),
            "+" => {
                self.last_div_dest = None;
                Self::check_add(state, solver, lhs, rhs, span)
            }
            "-" => {
                self.last_div_dest = None;
                Self::check_sub(state, solver, lhs, rhs, span)
            }
            _ => {
                self.last_div_dest = None;
                vec![]
            }
        }
    }

    fn check_mul(
        &mut self,
        state: &SymbolicState,
        solver: &dyn SmtSolver,
        lhs: &IrValue,
        rhs: &IrValue,
        span: &Span,
    ) -> Vec<SeFinding> {
        let div_finding = self.check_div_before_mul(state, lhs, rhs, span);
        self.last_div_dest = None;

        if let Some(f) = div_finding {
            return vec![f];
        }

        let (Some(lhs_bv), Some(rhs_bv)) = (eval_to_bv(state, lhs), eval_to_bv(state, rhs))
        else {
            return vec![];
        };
        let lhs_512 = lhs_bv.zero_ext(256);
        let rhs_512 = rhs_bv.zero_ext(256);
        let product_512 = lhs_512.bvmul(&rhs_512);
        let high = product_512.extract(511, 256);
        let overflow_cond = high.bvugt(BV::from_u64(0, 256));
        check_sat_and_emit(
            state,
            solver,
            overflow_cond,
            SeVulnKind::IntegerOverflow,
            Severity::High,
            Confidence::High,
            "Integer multiplication can overflow: product exceeds uint256 max",
            *span,
        )
    }

    fn check_add(
        state: &SymbolicState,
        solver: &dyn SmtSolver,
        lhs: &IrValue,
        rhs: &IrValue,
        span: &Span,
    ) -> Vec<SeFinding> {
        let (Some(lhs_bv), Some(rhs_bv)) = (eval_to_bv(state, lhs), eval_to_bv(state, rhs))
        else {
            return vec![];
        };
        let result_bv = lhs_bv.bvadd(&rhs_bv);
        let overflow_cond = result_bv.bvult(&lhs_bv);
        check_sat_and_emit(
            state,
            solver,
            overflow_cond,
            SeVulnKind::IntegerOverflow,
            Severity::High,
            Confidence::High,
            "Integer addition can overflow: result wraps around",
            *span,
        )
    }

    fn check_sub(
        state: &SymbolicState,
        solver: &dyn SmtSolver,
        lhs: &IrValue,
        rhs: &IrValue,
        span: &Span,
    ) -> Vec<SeFinding> {
        let (Some(lhs_bv), Some(rhs_bv)) = (eval_to_bv(state, lhs), eval_to_bv(state, rhs))
        else {
            return vec![];
        };
        let underflow_cond = lhs_bv.bvult(&rhs_bv);
        check_sat_and_emit(
            state,
            solver,
            underflow_cond,
            SeVulnKind::IntegerUnderflow,
            Severity::High,
            Confidence::High,
            "Integer subtraction can underflow: result wraps below zero",
            *span,
        )
    }

    fn check_div_before_mul(
        &self,
        state: &SymbolicState,
        lhs: &IrValue,
        rhs: &IrValue,
        span: &Span,
    ) -> Option<SeFinding> {
        let div_dest = self.last_div_dest.as_ref()?;
        let lhs_is_div_result = matches!(lhs, IrValue::Var(v) if v == div_dest);
        let rhs_is_div_result = matches!(rhs, IrValue::Var(v) if v == div_dest);
        if lhs_is_div_result || rhs_is_div_result {
            Some(make_finding(
                SeVulnKind::DivisionBeforeMultiplication,
                Severity::Medium,
                Confidence::Low,
                "Division before multiplication loses precision due to integer truncation",
                *span,
                state,
                None,
            ))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{IrInstr, IrPlace, IrValue, IrVar, PlaceClass};
    use crate::norm::{Span};
    use crate::symbolic::results::finding::SeVulnKind;
    use crate::symbolic::solver::z3_backend::Z3Backend;
    use crate::symbolic::state::call_context::CallContext;
    use crate::symbolic::state::{StateIdGen, SymbolicState};
    use crate::symbolic::types::SymbolicValue;
    use z3::ast::BV;

    fn span() -> Span {
        Span { file: 0, start: 0, end: 0 }
    }

    fn make_state_and_solver() -> (SymbolicState, Z3Backend) {
        let mut id_gen = StateIdGen::new();
        let (call_ctx, _) = CallContext::new_symbolic();
        let state = SymbolicState::initial(&mut id_gen, 0, call_ctx);
        (state, Z3Backend::new(0))
    }

    fn nop_instr() -> IrInstr {
        IrInstr::Nop { span: span() }
    }

    fn binary_instr(op: &str, dest: IrVar, lhs: IrValue, rhs: IrValue) -> IrInstr {
        IrInstr::Binary {
            dest,
            op: op.to_string(),
            lhs,
            rhs,
            span: span(),
        }
    }

    #[test]
    fn test_nop_returns_no_findings() {
        // A Nop instruction should never trigger any arithmetic detector findings.
        let (state, solver) = make_state_and_solver();
        let mut det = ArithmeticDetector::new();
        let findings = det.on_instruction(&state, &nop_instr(), &solver);
        assert!(findings.is_empty(), "Nop should produce no findings");
    }

    #[test]
    fn test_add_with_symbolic_operands_emits_overflow() {
        // Binary{op:"+"} with two unconstrained symbolic BVs can overflow → IntegerOverflow.
        let (mut state, solver) = make_state_and_solver();
        state.variables.set(
            IrVar::Named("a".to_string()),
            SymbolicValue::BitVec { width: 256, val: BV::new_const("a", 256) },
        );
        state.variables.set(
            IrVar::Named("b".to_string()),
            SymbolicValue::BitVec { width: 256, val: BV::new_const("b", 256) },
        );
        let instr = binary_instr(
            "+",
            IrVar::Temp(0),
            IrValue::Var(IrVar::Named("a".to_string())),
            IrValue::Var(IrVar::Named("b".to_string())),
        );
        let mut det = ArithmeticDetector::new();
        let findings = det.on_instruction(&state, &instr, &solver);
        assert_eq!(findings.len(), 1, "symbolic add should emit overflow finding");
        assert_eq!(findings[0].kind, SeVulnKind::IntegerOverflow);
    }

    #[test]
    fn test_add_with_concrete_zero_no_overflow() {
        // 0 + 0 = 0; overflow condition (result < lhs) is 0 < 0 = false → UNSAT → no finding.
        let (mut state, solver) = make_state_and_solver();
        state.variables.set(
            IrVar::Named("a".to_string()),
            SymbolicValue::BitVec { width: 256, val: BV::from_u64(0, 256) },
        );
        state.variables.set(
            IrVar::Named("b".to_string()),
            SymbolicValue::BitVec { width: 256, val: BV::from_u64(0, 256) },
        );
        let instr = binary_instr(
            "+",
            IrVar::Temp(0),
            IrValue::Var(IrVar::Named("a".to_string())),
            IrValue::Var(IrVar::Named("b".to_string())),
        );
        let mut det = ArithmeticDetector::new();
        let findings = det.on_instruction(&state, &instr, &solver);
        assert!(findings.is_empty(), "0 + 0 cannot overflow");
    }

    #[test]
    fn test_sub_with_symbolic_operands_emits_underflow() {
        // Binary{op:"-"} with unconstrained BVs: lhs < rhs is satisfiable → IntegerUnderflow.
        let (mut state, solver) = make_state_and_solver();
        state.variables.set(
            IrVar::Named("a".to_string()),
            SymbolicValue::BitVec { width: 256, val: BV::new_const("a_sub", 256) },
        );
        state.variables.set(
            IrVar::Named("b".to_string()),
            SymbolicValue::BitVec { width: 256, val: BV::new_const("b_sub", 256) },
        );
        let instr = binary_instr(
            "-",
            IrVar::Temp(0),
            IrValue::Var(IrVar::Named("a".to_string())),
            IrValue::Var(IrVar::Named("b".to_string())),
        );
        let mut det = ArithmeticDetector::new();
        let findings = det.on_instruction(&state, &instr, &solver);
        assert_eq!(findings.len(), 1, "symbolic sub should emit underflow finding");
        assert_eq!(findings[0].kind, SeVulnKind::IntegerUnderflow);
    }

    #[test]
    fn test_mul_with_symbolic_operands_emits_overflow() {
        // Binary{op:"*"} with unconstrained BVs can produce product > 2^256 → IntegerOverflow.
        let (mut state, solver) = make_state_and_solver();
        state.variables.set(
            IrVar::Named("a".to_string()),
            SymbolicValue::BitVec { width: 256, val: BV::new_const("a_mul", 256) },
        );
        state.variables.set(
            IrVar::Named("b".to_string()),
            SymbolicValue::BitVec { width: 256, val: BV::new_const("b_mul", 256) },
        );
        let instr = binary_instr(
            "*",
            IrVar::Temp(0),
            IrValue::Var(IrVar::Named("a".to_string())),
            IrValue::Var(IrVar::Named("b".to_string())),
        );
        let mut det = ArithmeticDetector::new();
        let findings = det.on_instruction(&state, &instr, &solver);
        assert_eq!(findings.len(), 1, "symbolic mul should emit overflow finding");
        assert_eq!(findings[0].kind, SeVulnKind::IntegerOverflow);
    }

    #[test]
    fn test_div_before_mul_detected() {
        // Sequence: Binary{op:"/"} → Binary{op:"*"} using division result → DivisionBeforeMultiplication.
        let (mut state, solver) = make_state_and_solver();
        state.variables.set(
            IrVar::Named("x".to_string()),
            SymbolicValue::BitVec { width: 256, val: BV::new_const("x_dbm", 256) },
        );
        state.variables.set(
            IrVar::Named("y".to_string()),
            SymbolicValue::BitVec { width: 256, val: BV::new_const("y_dbm", 256) },
        );
        let div_instr = binary_instr(
            "/",
            IrVar::Temp(1),
            IrValue::Var(IrVar::Named("x".to_string())),
            IrValue::Var(IrVar::Named("y".to_string())),
        );
        let mul_instr = binary_instr(
            "*",
            IrVar::Temp(2),
            IrValue::Var(IrVar::Temp(1)),   // uses division result
            IrValue::Var(IrVar::Named("y".to_string())),
        );
        let mut det = ArithmeticDetector::new();
        det.on_instruction(&state, &div_instr, &solver);
        let findings = det.on_instruction(&state, &mul_instr, &solver);
        // The DivisionBeforeMultiplication finding should be present.
        assert!(
            findings.iter().any(|f| f.kind == SeVulnKind::DivisionBeforeMultiplication),
            "div before mul should emit DivisionBeforeMultiplication"
        );
    }

    #[test]
    fn test_div_no_finding_without_mul() {
        // Binary{op:"/"} alone should not produce a finding (just records last_div_dest).
        let (mut state, solver) = make_state_and_solver();
        state.variables.set(
            IrVar::Named("x".to_string()),
            SymbolicValue::BitVec { width: 256, val: BV::new_const("x_div", 256) },
        );
        state.variables.set(
            IrVar::Named("y".to_string()),
            SymbolicValue::BitVec { width: 256, val: BV::new_const("y_div", 256) },
        );
        let instr = binary_instr(
            "/",
            IrVar::Temp(0),
            IrValue::Var(IrVar::Named("x".to_string())),
            IrValue::Var(IrVar::Named("y".to_string())),
        );
        let mut det = ArithmeticDetector::new();
        let findings = det.on_instruction(&state, &instr, &solver);
        assert!(findings.is_empty(), "division alone should not emit a finding");
    }

    #[test]
    fn test_store_to_length_field_emits_unsafe_array_length() {
        // Store to a Member place with field=="length" → UnsafeArrayLength.
        let (state, solver) = make_state_and_solver();
        let instr = IrInstr::Store {
            dest: IrPlace::Member {
                base: IrValue::Var(IrVar::Named("arr".to_string())),
                field: "length".to_string(),
                root: None,
                class: PlaceClass::Unknown,
            },
            src: IrValue::Var(IrVar::Temp(0)),
            span: span(),
        };
        let mut det = ArithmeticDetector::new();
        let findings = det.on_instruction(&state, &instr, &solver);
        assert_eq!(findings.len(), 1, "store to .length should emit UnsafeArrayLength");
        assert_eq!(findings[0].kind, SeVulnKind::UnsafeArrayLength);
    }

    #[test]
    fn test_reset_clears_last_div_dest() {
        // After div, reset() should clear last_div_dest so subsequent mul finds nothing.
        let (mut state, solver) = make_state_and_solver();
        state.variables.set(
            IrVar::Named("x".to_string()),
            SymbolicValue::BitVec { width: 256, val: BV::new_const("x_rst", 256) },
        );
        state.variables.set(
            IrVar::Named("y".to_string()),
            SymbolicValue::BitVec { width: 256, val: BV::new_const("y_rst", 256) },
        );
        let div_instr = binary_instr(
            "/",
            IrVar::Temp(1),
            IrValue::Var(IrVar::Named("x".to_string())),
            IrValue::Var(IrVar::Named("y".to_string())),
        );
        let mul_instr = binary_instr(
            "*",
            IrVar::Temp(2),
            IrValue::Var(IrVar::Temp(1)),
            IrValue::Var(IrVar::Named("y".to_string())),
        );
        let mut det = ArithmeticDetector::new();
        det.on_instruction(&state, &div_instr, &solver);
        det.reset();
        let findings = det.on_instruction(&state, &mul_instr, &solver);
        // After reset, div result should no longer be tracked → no DivisionBeforeMultiplication.
        assert!(
            !findings.iter().any(|f| f.kind == SeVulnKind::DivisionBeforeMultiplication),
            "reset should clear div-before-mul tracking"
        );
    }

    #[test]
    fn test_unknown_op_returns_no_findings() {
        // Binary{op:"%"} is not a tracked operation → should produce no findings.
        let (mut state, solver) = make_state_and_solver();
        state.variables.set(
            IrVar::Named("a".to_string()),
            SymbolicValue::BitVec { width: 256, val: BV::new_const("a_mod", 256) },
        );
        state.variables.set(
            IrVar::Named("b".to_string()),
            SymbolicValue::BitVec { width: 256, val: BV::new_const("b_mod", 256) },
        );
        let instr = binary_instr(
            "%",
            IrVar::Temp(0),
            IrValue::Var(IrVar::Named("a".to_string())),
            IrValue::Var(IrVar::Named("b".to_string())),
        );
        let mut det = ArithmeticDetector::new();
        let findings = det.on_instruction(&state, &instr, &solver);
        assert!(findings.is_empty(), "modulo op should not be detected as arithmetic vulnerability");
    }
}

/// Check SAT for `overflow_cond` under current path constraints.
///
/// Short-circuits when the overflow condition is trivially false
/// (e.g., both operands are concrete zeros), avoiding a solver call.
#[allow(clippy::too_many_arguments)]
fn check_sat_and_emit(
    state: &SymbolicState,
    solver: &dyn SmtSolver,
    overflow_cond: Bool,
    kind: SeVulnKind,
    severity: Severity,
    confidence: Confidence,
    message: &str,
    span: Span,
) -> Vec<SeFinding> {
    if is_trivially_false(&overflow_cond) {
        return vec![];
    }
    let mut assumptions = path_bools(state);
    assumptions.push(overflow_cond);
    match solver.check_sat_assuming(&assumptions) {
        SatResult::Sat => {
            let witness = solver
                .get_model()
                .map(|m| Witness::from_model(&m, &state.call_context));
            vec![make_finding(kind, severity, confidence, message, span, state, witness)]
        }
        // Unknown (timeout) or Unsat — not a confirmed finding.
        _ => vec![],
    }
}
