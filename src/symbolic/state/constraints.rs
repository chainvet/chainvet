use z3::ast::Bool;

/// Accumulated path constraints for one execution path.
///
/// Each constraint is a Z3 Bool paired with a human-readable description
/// of why it was added (e.g., "block 5: if-condition true branch").
/// Cloning is cheap: Bool values are Rc-based Z3 AST handles.
///
/// This is pure data — no solving logic. The engine is responsible for
/// feeding these constraints into the solver via push/assert_all/check/pop.
#[derive(Clone)]
pub struct PathConstraints {
    constraints: Vec<(Bool, String)>,
}

impl PathConstraints {
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
        }
    }

    /// Add a constraint with a human-readable description.
    pub fn add(&mut self, constraint: Bool, description: String) {
        self.constraints.push((constraint, description));
    }

    /// All accumulated (constraint, description) pairs.
    pub fn constraints(&self) -> &[(Bool, String)] {
        &self.constraints
    }

    /// Number of constraints.
    pub fn len(&self) -> usize {
        self.constraints.len()
    }

    /// Whether no constraints have been added.
    pub fn is_empty(&self) -> bool {
        self.constraints.is_empty()
    }

    /// Human-readable descriptions of all constraints (for reporting).
    pub fn descriptions(&self) -> Vec<&str> {
        self.constraints.iter().map(|(_, d)| d.as_str()).collect()
    }
}

impl Default for PathConstraints {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::ast::Bool;

    #[test]
    fn test_path_constraints_new_is_empty() {
        // A freshly created PathConstraints should have zero constraints.
        let pc = PathConstraints::new();
        assert!(pc.is_empty());
        assert_eq!(pc.len(), 0);
        assert!(pc.constraints().is_empty());
        assert!(pc.descriptions().is_empty());
    }

    #[test]
    fn test_path_constraints_add_increments_len() {
        // Adding a constraint should increase the length by one.
        let mut pc = PathConstraints::new();
        let b = Bool::from_bool(true);
        pc.add(b, "first constraint".into());
        assert_eq!(pc.len(), 1);
        assert!(!pc.is_empty());
    }

    #[test]
    fn test_path_constraints_add_multiple() {
        // Adding multiple constraints should accumulate in order.
        let mut pc = PathConstraints::new();
        pc.add(Bool::from_bool(true), "c1".into());
        pc.add(Bool::from_bool(false), "c2".into());
        pc.add(Bool::from_bool(true), "c3".into());
        assert_eq!(pc.len(), 3);
    }

    #[test]
    fn test_path_constraints_descriptions_returns_all_in_order() {
        // descriptions() should return the description strings in insertion order.
        let mut pc = PathConstraints::new();
        pc.add(Bool::from_bool(true), "block 0: entry".into());
        pc.add(Bool::from_bool(false), "block 1: if-true".into());
        let descs = pc.descriptions();
        assert_eq!(descs, vec!["block 0: entry", "block 1: if-true"]);
    }

    #[test]
    fn test_path_constraints_constraints_returns_pairs() {
        // constraints() should return (Bool, String) pairs matching what was added.
        let mut pc = PathConstraints::new();
        pc.add(Bool::from_bool(true), "desc".into());
        let pairs = pc.constraints();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].1, "desc");
    }

    #[test]
    fn test_path_constraints_clone_independence() {
        // Cloning PathConstraints should produce an independent copy:
        // adding to the original should not affect the clone.
        let mut original = PathConstraints::new();
        original.add(Bool::from_bool(true), "before clone".into());

        let cloned = original.clone();
        original.add(Bool::from_bool(false), "after clone".into());

        assert_eq!(original.len(), 2);
        assert_eq!(cloned.len(), 1, "clone should not see additions to original");
    }

    #[test]
    fn test_path_constraints_default_equals_new() {
        // Default trait impl should behave identically to new().
        let pc = PathConstraints::default();
        assert!(pc.is_empty());
        assert_eq!(pc.len(), 0);
    }
}
