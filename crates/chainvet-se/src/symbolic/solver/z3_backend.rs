use std::cell::Cell;

use z3::ast::Bool;
use z3::{Model, Params, SatResult, Solver};

use super::SmtSolver;

/// Z3 implementation of the `SmtSolver` trait.
///
/// Wraps `z3::Solver` with QF_ABV logic (quantifier-free arrays + bitvectors)
/// and configurable timeout. Tracks query count for diagnostics.
pub struct Z3Backend {
    solver: Solver,
    query_count: Cell<u64>,
}

impl Z3Backend {
    /// Create a new Z3 backend.
    ///
    /// - Tries QF_ABV logic first (optimal for EVM bitvector + array reasoning).
    ///   Falls back to the default logic if QF_ABV is unavailable.
    /// - Sets per-query timeout if `timeout_ms > 0`.
    /// - Enables `model.completion` so models assign values to all declared variables.
    pub fn new(timeout_ms: u32) -> Self {
        let solver = Solver::new_for_logic("QF_ABV").unwrap_or_default();

        let mut params = Params::new();
        params.set_bool("model.completion", true);
        if timeout_ms > 0 {
            params.set_u32("timeout", timeout_ms);
        }
        solver.set_params(&params);

        Z3Backend {
            solver,
            query_count: Cell::new(0),
        }
    }

    /// Number of `check_sat` / `check_sat_assuming` queries issued so far.
    #[allow(dead_code)] // Phase 6: used by detector telemetry / report stats
    pub fn query_count(&self) -> u64 {
        self.query_count.get()
    }
}

impl SmtSolver for Z3Backend {
    fn assert_constraint(&self, constraint: &Bool) {
        self.solver.assert(constraint);
    }

    fn check_sat(&self) -> SatResult {
        self.query_count.set(self.query_count.get() + 1);
        self.solver.check()
    }

    fn check_sat_assuming(&self, assumptions: &[Bool]) -> SatResult {
        self.query_count.set(self.query_count.get() + 1);
        self.solver.check_assumptions(assumptions)
    }

    fn get_model(&self) -> Option<Model> {
        self.solver.get_model()
    }

    fn push(&self) {
        self.solver.push();
    }

    fn pop(&self) {
        self.solver.pop(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::SatResult;
    use z3::ast::BV;

    // -- Construction tests --

    #[test]
    fn test_z3backend_new_with_zero_timeout() {
        // Creating a backend with timeout=0 should succeed and start with zero queries.
        let backend = Z3Backend::new(0);
        assert_eq!(backend.query_count(), 0);
    }

    #[test]
    fn test_z3backend_new_with_nonzero_timeout() {
        // Creating a backend with a positive timeout should succeed.
        let backend = Z3Backend::new(5000);
        assert_eq!(backend.query_count(), 0);
    }

    // -- Satisfiability tests --

    #[test]
    fn test_check_sat_unsatisfiable_contradictory_constraints() {
        // Assert x > 5 AND x < 3 on an 8-bit bitvector (unsigned).
        // These constraints are contradictory, so check_sat must return Unsat.
        let backend = Z3Backend::new(5000);
        let x = BV::new_const("x", 8);
        let five = BV::from_u64(5, 8);
        let three = BV::from_u64(3, 8);

        // x > 5 (unsigned)
        let gt_five = x.bvugt(&five);
        // x < 3 (unsigned)
        let lt_three = x.bvult(&three);

        backend.assert_constraint(&gt_five);
        backend.assert_constraint(&lt_three);

        assert_eq!(backend.check_sat(), SatResult::Unsat);
    }

    #[test]
    fn test_check_sat_satisfiable_with_model() {
        // Assert x > 5 AND x < 10 on an 8-bit unsigned bitvector.
        // The valid range is [6, 9]. check_sat must return Sat and
        // the model must assign x a value within that range.
        let backend = Z3Backend::new(5000);
        let x = BV::new_const("x", 8);
        let five = BV::from_u64(5, 8);
        let ten = BV::from_u64(10, 8);

        backend.assert_constraint(&x.bvugt(&five));
        backend.assert_constraint(&x.bvult(&ten));

        assert_eq!(backend.check_sat(), SatResult::Sat);

        let model = backend.get_model();
        assert!(model.is_some(), "model should be present after Sat result");
        let model = model.unwrap();

        let x_val = model.eval(&x, true).expect("x should be evaluable");
        let x_u64 = x_val.as_u64().expect("concrete 8-bit value fits in u64");
        assert!(
            (6..=9).contains(&x_u64),
            "expected x in [6, 9], got {x_u64}"
        );
    }

    #[test]
    fn test_check_sat_empty_constraints_is_sat() {
        // With no constraints, the solver should return Sat (trivially satisfiable).
        let backend = Z3Backend::new(5000);
        assert_eq!(backend.check_sat(), SatResult::Sat);
    }

    // -- check_sat_assuming tests --

    #[test]
    fn test_check_sat_assuming_contradictory_assumptions_then_sat_without() {
        // Assert x > 5. Then check_sat_assuming with x < 3 should be Unsat.
        // Afterwards, check_sat without assumptions should still be Sat
        // because assumptions are not permanently asserted.
        let backend = Z3Backend::new(5000);
        let x = BV::new_const("x", 8);
        let five = BV::from_u64(5, 8);
        let three = BV::from_u64(3, 8);

        backend.assert_constraint(&x.bvugt(&five));

        // Temporary contradictory assumption
        let assumption = x.bvult(&three);
        assert_eq!(
            backend.check_sat_assuming(&[assumption]),
            SatResult::Unsat,
            "contradictory assumption should yield Unsat"
        );

        // Without the assumption, the original constraint is satisfiable
        assert_eq!(
            backend.check_sat(),
            SatResult::Sat,
            "assumptions should not be permanent"
        );
    }

    #[test]
    fn test_check_sat_assuming_satisfiable_assumption() {
        // Assert x > 5, assume x < 20. Both hold for x in [6, 19].
        let backend = Z3Backend::new(5000);
        let x = BV::new_const("x", 8);

        backend.assert_constraint(&x.bvugt(&BV::from_u64(5, 8)));

        let assumption = x.bvult(&BV::from_u64(20, 8));
        assert_eq!(backend.check_sat_assuming(&[assumption]), SatResult::Sat);
    }

    // -- Push / Pop tests --

    #[test]
    fn test_push_pop_restores_satisfiability() {
        // Assert x > 5 (sat). Push scope, assert x < 3 (unsat), pop,
        // then check that the solver is sat again.
        let backend = Z3Backend::new(5000);
        let x = BV::new_const("x", 8);

        backend.assert_constraint(&x.bvugt(&BV::from_u64(5, 8)));
        assert_eq!(backend.check_sat(), SatResult::Sat);

        backend.push();
        backend.assert_constraint(&x.bvult(&BV::from_u64(3, 8)));
        assert_eq!(
            backend.check_sat(),
            SatResult::Unsat,
            "inner scope should be unsat"
        );

        backend.pop();
        assert_eq!(
            backend.check_sat(),
            SatResult::Sat,
            "after pop, only outer constraint should remain"
        );
    }

    #[test]
    fn test_nested_push_pop() {
        // Two levels of push/pop: verify each level restores correctly.
        let backend = Z3Backend::new(5000);
        let x = BV::new_const("x", 8);

        // Level 0: x > 10
        backend.assert_constraint(&x.bvugt(&BV::from_u64(10, 8)));
        assert_eq!(backend.check_sat(), SatResult::Sat);

        backend.push(); // Level 1
        // x < 20 narrows to [11, 19]
        backend.assert_constraint(&x.bvult(&BV::from_u64(20, 8)));
        assert_eq!(backend.check_sat(), SatResult::Sat);

        backend.push(); // Level 2
        // x < 5 contradicts x > 10
        backend.assert_constraint(&x.bvult(&BV::from_u64(5, 8)));
        assert_eq!(backend.check_sat(), SatResult::Unsat);

        backend.pop(); // Back to level 1
        assert_eq!(backend.check_sat(), SatResult::Sat);

        backend.pop(); // Back to level 0
        assert_eq!(backend.check_sat(), SatResult::Sat);
    }

    // -- Query count tests --

    #[test]
    fn test_query_count_increments_on_check_sat() {
        // Each call to check_sat should increment query_count by 1.
        let backend = Z3Backend::new(5000);
        assert_eq!(backend.query_count(), 0);

        backend.check_sat();
        assert_eq!(backend.query_count(), 1);

        backend.check_sat();
        assert_eq!(backend.query_count(), 2);
    }

    #[test]
    fn test_query_count_increments_on_check_sat_assuming() {
        // check_sat_assuming should also increment the query count.
        let backend = Z3Backend::new(5000);
        let t = Bool::from_bool(true);

        backend.check_sat_assuming(&[t]);
        assert_eq!(backend.query_count(), 1);
    }

    #[test]
    fn test_query_count_mixed_calls() {
        // Both check_sat and check_sat_assuming contribute to the same counter.
        let backend = Z3Backend::new(5000);
        let t = Bool::from_bool(true);

        backend.check_sat();
        backend.check_sat_assuming(&[t]);
        backend.check_sat();

        assert_eq!(backend.query_count(), 3);
    }

    // -- Model tests --

    #[test]
    fn test_get_model_returns_none_before_check() {
        // Before any check_sat call, get_model behavior depends on z3.
        // After an Unsat result, get_model should return None.
        let backend = Z3Backend::new(5000);
        let x = BV::new_const("x", 8);

        // Force unsat
        backend.assert_constraint(&x.bvugt(&BV::from_u64(5, 8)));
        backend.assert_constraint(&x.bvult(&BV::from_u64(3, 8)));
        backend.check_sat();

        assert!(
            backend.get_model().is_none(),
            "no model should exist after Unsat"
        );
    }

    #[test]
    fn test_get_model_evaluates_multiple_variables() {
        // With two variables constrained to specific values, the model
        // should evaluate both correctly.
        let backend = Z3Backend::new(5000);
        let x = BV::new_const("x", 8);
        let y = BV::new_const("y", 8);

        // x == 42
        backend.assert_constraint(&x.eq(&BV::from_u64(42, 8)));
        // y == 7
        backend.assert_constraint(&y.eq(&BV::from_u64(7, 8)));

        assert_eq!(backend.check_sat(), SatResult::Sat);
        let model = backend.get_model().unwrap();

        let x_val = model.eval(&x, true).unwrap().as_u64().unwrap();
        let y_val = model.eval(&y, true).unwrap().as_u64().unwrap();
        assert_eq!(x_val, 42);
        assert_eq!(y_val, 7);
    }
}
