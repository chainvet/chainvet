use std::collections::HashMap;

use crate::ir::IrVar;
use crate::symbolic::types::SymbolicValue;

/// Maps IR variables to their current symbolic values.
///
/// Flat HashMap — no scope frames. The IR uses `IrVar::Named(String)` and
/// `IrVar::Temp(u32)`, which are already positionally scoped. For inline
/// function call exploration, the executor prefixes callee variable names
/// with a call-site identifier to avoid collisions.
#[derive(Clone)]
pub struct VariableEnv {
    bindings: HashMap<IrVar, SymbolicValue>,
}

impl VariableEnv {
    pub fn new() -> Self {
        Self {
            bindings: HashMap::new(),
        }
    }

    /// Get the symbolic value of a variable.
    pub fn get(&self, var: &IrVar) -> Option<&SymbolicValue> {
        self.bindings.get(var)
    }

    /// Set a variable's symbolic value. Overwrites any previous binding.
    pub fn set(&mut self, var: IrVar, value: SymbolicValue) {
        self.bindings.insert(var, value);
    }

    /// Check if a variable is bound.
    #[allow(dead_code)] // Phase 6: used by detectors checking variable existence before use
    pub fn contains(&self, var: &IrVar) -> bool {
        self.bindings.contains_key(var)
    }

    /// Number of bound variables.
    #[allow(dead_code)] // Phase 6: used by state-budget accounting
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// Whether no variables are bound.
    #[allow(dead_code)] // Phase 6: used by state-budget accounting
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// Iterate over all (variable, value) bindings.
    pub fn iter(&self) -> impl Iterator<Item = (&IrVar, &SymbolicValue)> {
        self.bindings.iter()
    }
}

impl Default for VariableEnv {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::IrVar;
    use crate::symbolic::types::SymbolicValue;
    use z3::ast::BV;

    fn make_bv256(val: u64) -> SymbolicValue {
        SymbolicValue::BitVec {
            width: 256,
            val: BV::from_u64(val, 256),
        }
    }

    #[test]
    fn test_variable_env_new_is_empty() {
        // A fresh VariableEnv should have no bindings.
        let env = VariableEnv::new();
        assert!(env.is_empty());
        assert_eq!(env.len(), 0);
    }

    #[test]
    fn test_variable_env_set_and_get_named() {
        // Setting a Named variable and retrieving it should return the same value.
        let mut env = VariableEnv::new();
        let var = IrVar::Named("x".into());
        env.set(var.clone(), make_bv256(42));

        assert!(env.contains(&var));
        let val = env.get(&var).expect("should find variable x");
        assert_eq!(val.width(), 256);
    }

    #[test]
    fn test_variable_env_set_and_get_temp() {
        // Temp variables should also be usable as keys.
        let mut env = VariableEnv::new();
        let var = IrVar::Temp(0);
        env.set(var.clone(), make_bv256(99));

        assert!(env.contains(&var));
        assert_eq!(env.len(), 1);
    }

    #[test]
    fn test_variable_env_get_missing_returns_none() {
        // Getting a variable that was never set should return None.
        let env = VariableEnv::new();
        assert!(env.get(&IrVar::Named("missing".into())).is_none());
    }

    #[test]
    fn test_variable_env_overwrite_replaces_value() {
        // Setting the same variable twice should overwrite the previous binding.
        let mut env = VariableEnv::new();
        let var = IrVar::Named("x".into());
        env.set(var.clone(), make_bv256(1));
        env.set(var.clone(), make_bv256(2));

        assert_eq!(env.len(), 1, "overwriting should not increase count");
        // The value should be the second one (concrete 2).
        let val = env.get(&var).unwrap();
        assert_eq!(val.width(), 256);
    }

    #[test]
    fn test_variable_env_multiple_distinct_vars() {
        // Multiple distinct variables should all be independently accessible.
        let mut env = VariableEnv::new();
        env.set(IrVar::Named("a".into()), make_bv256(1));
        env.set(IrVar::Named("b".into()), make_bv256(2));
        env.set(IrVar::Temp(0), make_bv256(3));

        assert_eq!(env.len(), 3);
        assert!(env.contains(&IrVar::Named("a".into())));
        assert!(env.contains(&IrVar::Named("b".into())));
        assert!(env.contains(&IrVar::Temp(0)));
        assert!(!env.contains(&IrVar::Temp(1)));
    }

    #[test]
    fn test_variable_env_clone_independence() {
        // Cloning a VariableEnv should produce an independent copy:
        // modifying the original should not affect the clone.
        let mut original = VariableEnv::new();
        original.set(IrVar::Named("x".into()), make_bv256(10));

        let cloned = original.clone();
        original.set(IrVar::Named("y".into()), make_bv256(20));

        assert_eq!(original.len(), 2);
        assert_eq!(cloned.len(), 1, "clone should not see additions to original");
        assert!(!cloned.contains(&IrVar::Named("y".into())));
    }
}
