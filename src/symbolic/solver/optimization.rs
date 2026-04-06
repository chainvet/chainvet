// Constraint simplification utilities used by detectors for fast pruning.

use z3::ast::{Ast, Bool};

/// Simplify a Bool constraint using Z3's built-in simplifier.
#[allow(dead_code)]
pub fn simplify(constraint: &Bool) -> Bool {
    constraint.simplify()
}

/// Check if a constraint is trivially true (simplifies to `true`).
#[allow(dead_code)]
pub fn is_trivially_true(constraint: &Bool) -> bool {
    constraint.simplify().as_bool() == Some(true)
}

/// Check if a constraint is trivially false (simplifies to `false`).
pub fn is_trivially_false(constraint: &Bool) -> bool {
    constraint.simplify().as_bool() == Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::ast::BV;

    // -- is_trivially_true tests --

    #[test]
    fn test_is_trivially_true_on_literal_true() {
        // A concrete `true` boolean should be recognized as trivially true.
        let t = Bool::from_bool(true);
        assert!(is_trivially_true(&t));
    }

    #[test]
    fn test_is_trivially_true_on_literal_false() {
        // A concrete `false` boolean is not trivially true.
        let f = Bool::from_bool(false);
        assert!(!is_trivially_true(&f));
    }

    #[test]
    fn test_is_trivially_true_on_symbolic_bool() {
        // A fresh symbolic boolean has no fixed value, so it is not trivially true.
        let b = Bool::new_const("p");
        assert!(!is_trivially_true(&b));
    }

    #[test]
    fn test_is_trivially_true_on_tautology_or_p_not_p() {
        // p OR (NOT p) is always true. Z3's simplifier should reduce it.
        let p = Bool::new_const("p");
        let tautology = Bool::or(&[&p, &p.not()]);
        assert!(is_trivially_true(&tautology));
    }

    // -- is_trivially_false tests --

    #[test]
    fn test_is_trivially_false_on_literal_false() {
        // A concrete `false` boolean should be recognized as trivially false.
        let f = Bool::from_bool(false);
        assert!(is_trivially_false(&f));
    }

    #[test]
    fn test_is_trivially_false_on_literal_true() {
        // A concrete `true` boolean is not trivially false.
        let t = Bool::from_bool(true);
        assert!(!is_trivially_false(&t));
    }

    #[test]
    fn test_is_trivially_false_on_symbolic_bool() {
        // A fresh symbolic boolean is not trivially false.
        let b = Bool::new_const("q");
        assert!(!is_trivially_false(&b));
    }

    #[test]
    fn test_is_trivially_false_on_contradiction_and_p_not_p() {
        // p AND (NOT p) is always false. Z3's simplifier should reduce it.
        let p = Bool::new_const("p");
        let contradiction = Bool::and(&[&p, &p.not()]);
        assert!(is_trivially_false(&contradiction));
    }

    // -- simplify tests --

    #[test]
    fn test_simplify_bv_eq_self_yields_true() {
        // x == x should simplify to true for any bitvector x.
        let x = BV::new_const("x", 256);
        #[allow(clippy::eq_op)]
        let eq_self = x.clone().eq(x);
        let simplified = simplify(&eq_self);
        assert_eq!(
            simplified.as_bool(),
            Some(true),
            "x == x should simplify to true"
        );
    }

    #[test]
    fn test_simplify_concrete_true_stays_true() {
        // Simplifying a concrete true should still be true.
        let t = Bool::from_bool(true);
        let simplified = simplify(&t);
        assert_eq!(simplified.as_bool(), Some(true));
    }

    #[test]
    fn test_simplify_concrete_false_stays_false() {
        // Simplifying a concrete false should still be false.
        let f = Bool::from_bool(false);
        let simplified = simplify(&f);
        assert_eq!(simplified.as_bool(), Some(false));
    }

    #[test]
    fn test_simplify_double_negation() {
        // NOT(NOT(p)) should simplify to p. For a concrete true, this means true.
        let t = Bool::from_bool(true);
        let double_neg = t.not().not();
        let simplified = simplify(&double_neg);
        assert_eq!(simplified.as_bool(), Some(true));
    }

    #[test]
    fn test_simplify_symbolic_not_concrete() {
        // Simplifying a symbolic variable should not produce a concrete bool.
        let x = Bool::new_const("x");
        let simplified = simplify(&x);
        assert_eq!(
            simplified.as_bool(),
            None,
            "symbolic variable cannot be simplified to a concrete value"
        );
    }

    #[test]
    fn test_simplify_and_with_false() {
        // p AND false should simplify to false regardless of p.
        let p = Bool::new_const("p");
        let f = Bool::from_bool(false);
        let expr = Bool::and(&[&p, &f]);
        let simplified = simplify(&expr);
        assert_eq!(simplified.as_bool(), Some(false));
    }

    #[test]
    fn test_simplify_or_with_true() {
        // p OR true should simplify to true regardless of p.
        let p = Bool::new_const("p");
        let t = Bool::from_bool(true);
        let expr = Bool::or(&[&p, &t]);
        let simplified = simplify(&expr);
        assert_eq!(simplified.as_bool(), Some(true));
    }

    // -- Cross-function consistency tests --

    #[test]
    fn test_is_trivially_true_consistent_with_simplify() {
        // is_trivially_true should agree with simplify().as_bool() == Some(true).
        let p = Bool::new_const("p");
        let tautology = Bool::or(&[&p, &p.not()]);
        assert_eq!(
            is_trivially_true(&tautology),
            simplify(&tautology).as_bool() == Some(true)
        );
    }

    #[test]
    fn test_is_trivially_false_consistent_with_simplify() {
        // is_trivially_false should agree with simplify().as_bool() == Some(false).
        let p = Bool::new_const("p");
        let contradiction = Bool::and(&[&p, &p.not()]);
        assert_eq!(
            is_trivially_false(&contradiction),
            simplify(&contradiction).as_bool() == Some(false)
        );
    }
}
