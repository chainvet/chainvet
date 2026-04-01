use z3::ast::{BV, Bool};
use z3::SatResult;

use crate::analysis::detectors::Severity;
use crate::cfg::BlockId;
use crate::ir::{IrInstr, IrPlace, IrValue, IrVar};
use crate::norm::Span;
use crate::symbolic::detectors::Detector;
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

fn make_finding(
    kind: SeVulnKind,
    severity: Severity,
    confidence: Confidence,
    message: &str,
    span: Span,
    state: &SymbolicState,
    witness: Option<Witness>,
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
        witness,
        state_id: state.id,
        path_depth: state.path_depth,
    }
}

impl Detector for ArithmeticDetector {
    fn id(&self) -> &'static str {
        "arithmetic"
    }

    fn name(&self) -> &'static str {
        "Arithmetic Vulnerability Detector"
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
                if let IrPlace::Member { field, .. } = dest {
                    if field == "length" {
                        return vec![make_finding(
                            SeVulnKind::UnsafeArrayLength,
                            Severity::Medium,
                            Confidence::Low,
                            "Direct assignment to array length can corrupt storage",
                            span.clone(),
                            state,
                            None,
                        )];
                    }
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
                // Track the result variable so the next `*` can detect div-before-mul.
                self.last_div_dest = Some(dest.clone());
                vec![]
            }

            "*" => {
                let div_finding = self.check_div_before_mul(state, lhs, rhs, span);

                // Always reset after seeing `*`.
                self.last_div_dest = None;

                if let Some(f) = div_finding {
                    return vec![f];
                }

                // Multiplication overflow check via BV512 zero-extension.
                let (Some(lhs_bv), Some(rhs_bv)) =
                    (eval_to_bv(state, lhs), eval_to_bv(state, rhs))
                else {
                    return vec![];
                };
                // Extend both operands from BV256 to BV512 to capture the full product.
                let lhs_512 = lhs_bv.zero_ext(256);
                let rhs_512 = rhs_bv.zero_ext(256);
                let product_512 = lhs_512.bvmul(&rhs_512);
                // High 256 bits nonzero ⟹ overflow.
                let high = product_512.extract(511, 256);
                let overflow_cond = high.bvugt(&BV::from_u64(0, 256));
                check_sat_and_emit(
                    state,
                    solver,
                    overflow_cond,
                    SeVulnKind::IntegerOverflow,
                    Severity::High,
                    Confidence::High,
                    "Integer multiplication can overflow: product exceeds uint256 max",
                    span.clone(),
                )
            }

            "+" => {
                self.last_div_dest = None;
                let (Some(lhs_bv), Some(rhs_bv)) =
                    (eval_to_bv(state, lhs), eval_to_bv(state, rhs))
                else {
                    return vec![];
                };
                // Unsigned addition overflow: wrapped result < lhs.
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
                    span.clone(),
                )
            }

            "-" => {
                self.last_div_dest = None;
                let (Some(lhs_bv), Some(rhs_bv)) =
                    (eval_to_bv(state, lhs), eval_to_bv(state, rhs))
                else {
                    return vec![];
                };
                // Unsigned subtraction underflow: lhs < rhs.
                let underflow_cond = lhs_bv.bvult(&rhs_bv);
                check_sat_and_emit(
                    state,
                    solver,
                    underflow_cond,
                    SeVulnKind::IntegerUnderflow,
                    Severity::High,
                    Confidence::High,
                    "Integer subtraction can underflow: result wraps below zero",
                    span.clone(),
                )
            }

            _ => {
                self.last_div_dest = None;
                vec![]
            }
        }
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
                span.clone(),
                state,
                None,
            ))
        } else {
            None
        }
    }
}

/// Check SAT for `overflow_cond` under current path constraints.
/// Returns a finding if SAT, with witness extracted from the model.
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
