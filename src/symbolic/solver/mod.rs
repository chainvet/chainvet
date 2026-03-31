pub mod optimization;
pub mod z3_backend;

use z3::ast::Bool;
use z3::{Model, SatResult};

/// Abstraction over an SMT solver.
///
/// The engine calls these methods without knowing the backend.
/// Named `SmtSolver` to avoid collision with `z3::Solver`.
/// This trait enables mock/recording wrappers for unit tests.
pub trait SmtSolver {
    /// Assert a boolean constraint into the current scope.
    fn assert_constraint(&self, constraint: &Bool);

    /// Check satisfiability of all asserted constraints.
    fn check_sat(&self) -> SatResult;

    /// Check satisfiability under temporary assumptions (not permanently asserted).
    /// Used at branch points to probe both true/false without push/pop overhead.
    fn check_sat_assuming(&self, assumptions: &[Bool]) -> SatResult;

    /// If the last `check_sat` / `check_sat_assuming` returned `Sat`, extract the model.
    fn get_model(&self) -> Option<Model>;

    /// Create a backtracking point.
    fn push(&self);

    /// Backtrack one level (undo all assertions since the last `push`).
    fn pop(&self);
}
