use z3::ast::{BV, Bool};

use super::SymbolicValue;
use chainvet_core::util::error::{Error, Result};

/// Apply an IR binary operator to two BV operands.
///
/// Maps IR op strings ("+", "-", "==", etc.) to Z3 BV methods.
/// Returns `SymbolicValue::BitVec` for arithmetic/bitwise ops,
/// `SymbolicValue::Bool` for comparison/logical ops.
pub fn apply_binary_op(op: &str, lhs: &BV, rhs: &BV, width: u32) -> Result<SymbolicValue> {
    match op {
        // Arithmetic
        "+" => Ok(bv(lhs.bvadd(rhs), width)),
        "-" => Ok(bv(lhs.bvsub(rhs), width)),
        "*" => Ok(bv(lhs.bvmul(rhs), width)),
        "/" => Ok(bv(lhs.bvudiv(rhs), width)),
        "%" => Ok(bv(lhs.bvurem(rhs), width)),
        "**" => bv_exp(lhs, rhs, width),

        // Comparison (unsigned by default)
        "==" => Ok(boolean(lhs.eq(rhs))),
        "!=" => Ok(boolean(lhs.eq(rhs).not())),
        "<" => Ok(boolean(lhs.bvult(rhs))),
        ">" => Ok(boolean(lhs.bvugt(rhs))),
        "<=" => Ok(boolean(lhs.bvule(rhs))),
        ">=" => Ok(boolean(lhs.bvuge(rhs))),

        // Bitwise
        "&" => Ok(bv(lhs.bvand(rhs), width)),
        "|" => Ok(bv(lhs.bvor(rhs), width)),
        "^" => Ok(bv(lhs.bvxor(rhs), width)),
        "<<" => Ok(bv(lhs.bvshl(rhs), width)),
        ">>" => Ok(bv(lhs.bvlshr(rhs), width)),

        // Logical (coerce BV operands to Bool via != 0)
        "&&" => {
            let lb = lhs.eq(BV::from_u64(0, width)).not();
            let rb = rhs.eq(BV::from_u64(0, width)).not();
            Ok(boolean(Bool::and(&[&lb, &rb])))
        }
        "||" => {
            let lb = lhs.eq(BV::from_u64(0, width)).not();
            let rb = rhs.eq(BV::from_u64(0, width)).not();
            Ok(boolean(Bool::or(&[&lb, &rb])))
        }

        _ => Err(Error::msg(format!("unsupported binary operator: {op}"))),
    }
}

/// Apply an IR unary operator to a BV operand.
pub fn apply_unary_op(op: &str, operand: &BV, width: u32, prefix: bool) -> Result<SymbolicValue> {
    match (op, prefix) {
        ("!", _) => {
            let b = operand.eq(BV::from_u64(0, width)).not();
            Ok(boolean(b.not()))
        }
        ("-", true) => Ok(bv(operand.bvneg(), width)),
        ("~", _) => Ok(bv(operand.bvnot(), width)),
        ("++", _) => Ok(bv(operand.bvadd(BV::from_u64(1, width)), width)),
        ("--", _) => Ok(bv(operand.bvsub(BV::from_u64(1, width)), width)),
        _ => Err(Error::msg(format!("unsupported unary operator: {op}"))),
    }
}

/// Resize a BV to target_width by zero/sign extending or truncating.
pub fn bv_resize(val: &BV, target_width: u32, signed: bool) -> BV {
    let current = val.get_size();
    if current == target_width {
        val.clone()
    } else if current < target_width {
        let extra = target_width - current;
        if signed {
            val.sign_ext(extra)
        } else {
            val.zero_ext(extra)
        }
    } else {
        val.extract(target_width - 1, 0)
    }
}

/// BV exponentiation via repeated squaring.
///
/// Three cases:
/// - Both concrete: compute modular exponentiation directly as a concrete BV.
/// - Symbolic base, concrete exponent ≤ 256: repeated squaring with Z3 mul constraints.
/// - Symbolic exponent or exponent > 256: fresh unconstrained BV (sound overapproximation).
fn bv_exp(base: &BV, exp: &BV, width: u32) -> Result<SymbolicValue> {
    let concrete_exp = exp.as_u64();
    let concrete_base = base.as_u64();

    // Both concrete: compute directly via modular exponentiation
    if let (Some(b), Some(e)) = (concrete_base, concrete_exp) {
        let result = concrete_modpow(b as u128, e as u128, width);
        return Ok(bv(BV::from_u64(result, width), width));
    }

    // Symbolic base, concrete small exponent: repeated squaring with Z3 mul
    if let Some(e) = concrete_exp
        && e <= 256
    {
        let mut result = BV::from_u64(1, width);
        let mut b = base.clone();
        let mut e = e;
        while e > 0 {
            if e & 1 == 1 {
                result = result.bvmul(&b);
            }
            b = b.bvmul(&b);
            e >>= 1;
        }
        return Ok(bv(result, width));
    }

    // Symbolic or large exponent: overapproximate with fresh unconstrained variable
    Ok(SymbolicValue::BitVec {
        width,
        val: BV::fresh_const("exp_result", width),
    })
}

/// Compute (base ^ exp) mod 2^width using u128 arithmetic.
fn concrete_modpow(base: u128, exp: u128, width: u32) -> u64 {
    let modulus: u128 = if width >= 128 {
        // For widths >= 128, use u128::MAX as working modulus
        // (the BV itself enforces the true width)
        u128::MAX
    } else {
        1u128 << width
    };

    let mut result: u128 = 1;
    let mut b = base % modulus;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = result.wrapping_mul(b) % modulus;
        }
        b = b.wrapping_mul(b) % modulus;
        e >>= 1;
    }
    result as u64
}

fn bv(val: BV, width: u32) -> SymbolicValue {
    SymbolicValue::BitVec { width, val }
}

fn boolean(val: Bool) -> SymbolicValue {
    SymbolicValue::Bool { val }
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::ast::BV;
    use z3::{SatResult, Solver};

    /// Helper: verify a SymbolicValue::BitVec equals the expected concrete u64.
    fn assert_bv_val(sv: &SymbolicValue, expected: u64, width: u32) {
        let bv = sv.as_bv().expect("expected BitVec");
        let solver = Solver::new();
        solver.assert(&bv.eq(&BV::from_u64(expected, width)));
        assert_eq!(solver.check(), SatResult::Sat, "expected {expected}");
        // Uniqueness check
        let solver2 = Solver::new();
        solver2.assert(&bv.eq(&BV::from_u64(expected, width)).not());
        assert_eq!(solver2.check(), SatResult::Unsat);
    }

    /// Helper: verify a SymbolicValue::Bool equals expected.
    fn assert_bool_val(sv: &SymbolicValue, expected: bool) {
        let b = sv.as_bool().expect("expected Bool");
        let solver = Solver::new();
        if expected {
            // Check b is always true
            solver.assert(&b.not());
            assert_eq!(solver.check(), SatResult::Unsat);
        } else {
            // Check b is always false
            solver.assert(b);
            assert_eq!(solver.check(), SatResult::Unsat);
        }
    }

    // ==== apply_binary_op: arithmetic ====

    #[test]
    fn test_binary_add_basic() {
        // 3 + 5 == 8
        let lhs = BV::from_u64(3, 256);
        let rhs = BV::from_u64(5, 256);
        let result = apply_binary_op("+", &lhs, &rhs, 256).unwrap();
        assert_bv_val(&result, 8, 256);
    }

    #[test]
    fn test_binary_add_overflow_u8() {
        // 200 + 100 wraps around in 8-bit: (300 mod 256) = 44
        let lhs = BV::from_u64(200, 8);
        let rhs = BV::from_u64(100, 8);
        let result = apply_binary_op("+", &lhs, &rhs, 8).unwrap();
        assert_bv_val(&result, 44, 8);
    }

    #[test]
    fn test_binary_sub_basic() {
        let lhs = BV::from_u64(10, 256);
        let rhs = BV::from_u64(3, 256);
        let result = apply_binary_op("-", &lhs, &rhs, 256).unwrap();
        assert_bv_val(&result, 7, 256);
    }

    #[test]
    fn test_binary_sub_underflow_u8() {
        // 0 - 1 in 8 bits wraps to 255
        let lhs = BV::from_u64(0, 8);
        let rhs = BV::from_u64(1, 8);
        let result = apply_binary_op("-", &lhs, &rhs, 8).unwrap();
        assert_bv_val(&result, 255, 8);
    }

    #[test]
    fn test_binary_mul_basic() {
        let lhs = BV::from_u64(7, 256);
        let rhs = BV::from_u64(6, 256);
        let result = apply_binary_op("*", &lhs, &rhs, 256).unwrap();
        assert_bv_val(&result, 42, 256);
    }

    #[test]
    fn test_binary_mul_by_zero() {
        let lhs = BV::from_u64(12345, 256);
        let rhs = BV::from_u64(0, 256);
        let result = apply_binary_op("*", &lhs, &rhs, 256).unwrap();
        assert_bv_val(&result, 0, 256);
    }

    #[test]
    fn test_binary_div_basic() {
        // Unsigned division: 10 / 3 = 3
        let lhs = BV::from_u64(10, 256);
        let rhs = BV::from_u64(3, 256);
        let result = apply_binary_op("/", &lhs, &rhs, 256).unwrap();
        assert_bv_val(&result, 3, 256);
    }

    #[test]
    fn test_binary_mod_basic() {
        let lhs = BV::from_u64(10, 256);
        let rhs = BV::from_u64(3, 256);
        let result = apply_binary_op("%", &lhs, &rhs, 256).unwrap();
        assert_bv_val(&result, 1, 256);
    }

    // ==== apply_binary_op: comparison ====

    #[test]
    fn test_binary_eq_true() {
        let lhs = BV::from_u64(42, 256);
        let rhs = BV::from_u64(42, 256);
        let result = apply_binary_op("==", &lhs, &rhs, 256).unwrap();
        assert_bool_val(&result, true);
    }

    #[test]
    fn test_binary_eq_false() {
        let lhs = BV::from_u64(42, 256);
        let rhs = BV::from_u64(43, 256);
        let result = apply_binary_op("==", &lhs, &rhs, 256).unwrap();
        assert_bool_val(&result, false);
    }

    #[test]
    fn test_binary_neq() {
        let lhs = BV::from_u64(1, 256);
        let rhs = BV::from_u64(2, 256);
        let result = apply_binary_op("!=", &lhs, &rhs, 256).unwrap();
        assert_bool_val(&result, true);
    }

    #[test]
    fn test_binary_lt_unsigned() {
        // Unsigned less-than
        let lhs = BV::from_u64(5, 256);
        let rhs = BV::from_u64(10, 256);
        let result = apply_binary_op("<", &lhs, &rhs, 256).unwrap();
        assert_bool_val(&result, true);

        let result2 = apply_binary_op("<", &rhs, &lhs, 256).unwrap();
        assert_bool_val(&result2, false);
    }

    #[test]
    fn test_binary_gt_unsigned() {
        let lhs = BV::from_u64(10, 256);
        let rhs = BV::from_u64(5, 256);
        let result = apply_binary_op(">", &lhs, &rhs, 256).unwrap();
        assert_bool_val(&result, true);
    }

    #[test]
    fn test_binary_lte() {
        let a = BV::from_u64(5, 256);
        let b = BV::from_u64(5, 256);
        let result = apply_binary_op("<=", &a, &b, 256).unwrap();
        assert_bool_val(&result, true);
    }

    #[test]
    fn test_binary_gte() {
        let a = BV::from_u64(5, 256);
        let b = BV::from_u64(6, 256);
        let result = apply_binary_op(">=", &a, &b, 256).unwrap();
        assert_bool_val(&result, false);
    }

    // ==== apply_binary_op: bitwise ====

    #[test]
    fn test_binary_bitand() {
        // 0xFF & 0x0F = 0x0F
        let lhs = BV::from_u64(0xFF, 256);
        let rhs = BV::from_u64(0x0F, 256);
        let result = apply_binary_op("&", &lhs, &rhs, 256).unwrap();
        assert_bv_val(&result, 0x0F, 256);
    }

    #[test]
    fn test_binary_bitor() {
        let lhs = BV::from_u64(0xF0, 256);
        let rhs = BV::from_u64(0x0F, 256);
        let result = apply_binary_op("|", &lhs, &rhs, 256).unwrap();
        assert_bv_val(&result, 0xFF, 256);
    }

    #[test]
    fn test_binary_bitxor() {
        let lhs = BV::from_u64(0xFF, 256);
        let rhs = BV::from_u64(0x0F, 256);
        let result = apply_binary_op("^", &lhs, &rhs, 256).unwrap();
        assert_bv_val(&result, 0xF0, 256);
    }

    #[test]
    fn test_binary_shl() {
        // 1 << 8 = 256
        let lhs = BV::from_u64(1, 256);
        let rhs = BV::from_u64(8, 256);
        let result = apply_binary_op("<<", &lhs, &rhs, 256).unwrap();
        assert_bv_val(&result, 256, 256);
    }

    #[test]
    fn test_binary_shr() {
        // 256 >> 8 = 1
        let lhs = BV::from_u64(256, 256);
        let rhs = BV::from_u64(8, 256);
        let result = apply_binary_op(">>", &lhs, &rhs, 256).unwrap();
        assert_bv_val(&result, 1, 256);
    }

    // ==== apply_binary_op: logical ====

    #[test]
    fn test_binary_logical_and_both_nonzero() {
        // Both nonzero -> true
        let lhs = BV::from_u64(1, 256);
        let rhs = BV::from_u64(2, 256);
        let result = apply_binary_op("&&", &lhs, &rhs, 256).unwrap();
        assert_bool_val(&result, true);
    }

    #[test]
    fn test_binary_logical_and_one_zero() {
        let lhs = BV::from_u64(1, 256);
        let rhs = BV::from_u64(0, 256);
        let result = apply_binary_op("&&", &lhs, &rhs, 256).unwrap();
        assert_bool_val(&result, false);
    }

    #[test]
    fn test_binary_logical_or_one_nonzero() {
        let lhs = BV::from_u64(0, 256);
        let rhs = BV::from_u64(5, 256);
        let result = apply_binary_op("||", &lhs, &rhs, 256).unwrap();
        assert_bool_val(&result, true);
    }

    #[test]
    fn test_binary_logical_or_both_zero() {
        let lhs = BV::from_u64(0, 256);
        let rhs = BV::from_u64(0, 256);
        let result = apply_binary_op("||", &lhs, &rhs, 256).unwrap();
        assert_bool_val(&result, false);
    }

    // ==== apply_binary_op: unsupported ====

    #[test]
    fn test_binary_unsupported_op_returns_error() {
        let lhs = BV::from_u64(1, 256);
        let rhs = BV::from_u64(2, 256);
        assert!(apply_binary_op("???", &lhs, &rhs, 256).is_err());
    }

    // ==== apply_unary_op ====

    #[test]
    fn test_unary_logical_not_nonzero_is_false() {
        // !(nonzero) should be false
        let operand = BV::from_u64(42, 256);
        let result = apply_unary_op("!", &operand, 256, true).unwrap();
        assert_bool_val(&result, false);
    }

    #[test]
    fn test_unary_logical_not_zero_is_true() {
        // !(0) should be true
        let operand = BV::from_u64(0, 256);
        let result = apply_unary_op("!", &operand, 256, true).unwrap();
        assert_bool_val(&result, true);
    }

    #[test]
    fn test_unary_negate() {
        // -5 in 8-bit unsigned = 251 (256 - 5)
        let operand = BV::from_u64(5, 8);
        let result = apply_unary_op("-", &operand, 8, true).unwrap();
        assert_bv_val(&result, 251, 8);
    }

    #[test]
    fn test_unary_negate_zero() {
        let operand = BV::from_u64(0, 256);
        let result = apply_unary_op("-", &operand, 256, true).unwrap();
        assert_bv_val(&result, 0, 256);
    }

    #[test]
    fn test_unary_bitwise_not_8bit() {
        // ~0x0F in 8-bit = 0xF0 = 240
        let operand = BV::from_u64(0x0F, 8);
        let result = apply_unary_op("~", &operand, 8, true).unwrap();
        assert_bv_val(&result, 0xF0, 8);
    }

    #[test]
    fn test_unary_increment() {
        let operand = BV::from_u64(9, 256);
        let result = apply_unary_op("++", &operand, 256, true).unwrap();
        assert_bv_val(&result, 10, 256);
    }

    #[test]
    fn test_unary_increment_overflow_u8() {
        // 255 + 1 in 8-bit wraps to 0
        let operand = BV::from_u64(255, 8);
        let result = apply_unary_op("++", &operand, 8, true).unwrap();
        assert_bv_val(&result, 0, 8);
    }

    #[test]
    fn test_unary_decrement() {
        let operand = BV::from_u64(10, 256);
        let result = apply_unary_op("--", &operand, 256, true).unwrap();
        assert_bv_val(&result, 9, 256);
    }

    #[test]
    fn test_unary_decrement_underflow_u8() {
        // 0 - 1 in 8-bit wraps to 255
        let operand = BV::from_u64(0, 8);
        let result = apply_unary_op("--", &operand, 8, true).unwrap();
        assert_bv_val(&result, 255, 8);
    }

    #[test]
    fn test_unary_unsupported_op_returns_error() {
        let operand = BV::from_u64(1, 256);
        assert!(apply_unary_op("@", &operand, 256, true).is_err());
    }

    // ==== bv_resize ====

    #[test]
    fn test_bv_resize_same_width_is_noop() {
        let bv = BV::from_u64(42, 256);
        let resized = bv_resize(&bv, 256, false);
        assert_eq!(resized.get_size(), 256);
        let solver = Solver::new();
        solver.assert(&resized.eq(&BV::from_u64(42, 256)));
        assert_eq!(solver.check(), SatResult::Sat);
    }

    #[test]
    fn test_bv_resize_zero_extend_8_to_256() {
        let bv = BV::from_u64(200, 8);
        let resized = bv_resize(&bv, 256, false);
        assert_eq!(resized.get_size(), 256);
        let solver = Solver::new();
        solver.assert(&resized.eq(&BV::from_u64(200, 256)));
        assert_eq!(solver.check(), SatResult::Sat);
    }

    #[test]
    fn test_bv_resize_sign_extend_8_to_256() {
        // 0xFF as signed 8-bit is -1. Sign-extended to 256 bits should be all-ones.
        let bv = BV::from_u64(0xFF, 8);
        let resized = bv_resize(&bv, 256, true);
        assert_eq!(resized.get_size(), 256);
        let solver = Solver::new();
        // -1 in 256-bit two's complement
        solver.assert(&resized.eq(&BV::from_i64(-1, 256)));
        assert_eq!(solver.check(), SatResult::Sat);
    }

    #[test]
    fn test_bv_resize_truncate_256_to_8() {
        // 0x1FF (511) truncated to 8 bits = 0xFF (255)
        let bv = BV::from_u64(0x1FF, 256);
        let resized = bv_resize(&bv, 8, false);
        assert_eq!(resized.get_size(), 8);
        let solver = Solver::new();
        solver.assert(&resized.eq(&BV::from_u64(0xFF, 8)));
        assert_eq!(solver.check(), SatResult::Sat);
    }

    // ==== bv_exp ====

    #[test]
    fn test_exp_concrete_small() {
        // 2 ** 10 = 1024
        let base = BV::from_u64(2, 256);
        let exp = BV::from_u64(10, 256);
        let result = apply_binary_op("**", &base, &exp, 256).unwrap();
        assert_bv_val(&result, 1024, 256);
    }

    #[test]
    fn test_exp_zero_exponent() {
        // x ** 0 = 1 for any x
        let base = BV::from_u64(999, 256);
        let exp = BV::from_u64(0, 256);
        let result = apply_binary_op("**", &base, &exp, 256).unwrap();
        assert_bv_val(&result, 1, 256);
    }

    #[test]
    fn test_exp_zero_base_nonzero_exp() {
        // 0 ** 5 = 0
        let base = BV::from_u64(0, 256);
        let exp = BV::from_u64(5, 256);
        let result = apply_binary_op("**", &base, &exp, 256).unwrap();
        assert_bv_val(&result, 0, 256);
    }

    #[test]
    fn test_exp_one_base() {
        // 1 ** 100 = 1
        let base = BV::from_u64(1, 256);
        let exp = BV::from_u64(100, 256);
        let result = apply_binary_op("**", &base, &exp, 256).unwrap();
        assert_bv_val(&result, 1, 256);
    }

    #[test]
    fn test_exp_concrete_8bit_overflow() {
        // 3 ** 5 = 243, which fits in 8 bits
        let base = BV::from_u64(3, 8);
        let exp = BV::from_u64(5, 8);
        let result = apply_binary_op("**", &base, &exp, 8).unwrap();
        assert_bv_val(&result, 243, 8);
    }

    #[test]
    fn test_exp_concrete_8bit_wraps() {
        // 3 ** 6 = 729, mod 256 = 217
        let base = BV::from_u64(3, 8);
        let exp = BV::from_u64(6, 8);
        let result = apply_binary_op("**", &base, &exp, 8).unwrap();
        assert_bv_val(&result, 729u64 % 256, 8);
    }

    #[test]
    fn test_exp_symbolic_exponent_produces_fresh_var() {
        // When the exponent is symbolic, the result should be a fresh unconstrained BV.
        // We verify that the result is satisfiable for multiple values (unconstrained).
        let base = BV::from_u64(2, 256);
        let exp = BV::new_const("sym_exp", 256);
        let result = apply_binary_op("**", &base, &exp, 256).unwrap();
        assert_eq!(result.width(), 256);
        // The result should be unconstrained -- check that it can equal both 0 and 1
        let bv = result.as_bv().unwrap();
        let s1 = Solver::new();
        s1.assert(&bv.eq(&BV::from_u64(0, 256)));
        assert_eq!(s1.check(), SatResult::Sat);
        let s2 = Solver::new();
        s2.assert(&bv.eq(&BV::from_u64(1, 256)));
        assert_eq!(s2.check(), SatResult::Sat);
    }

    #[test]
    fn test_exp_symbolic_base_concrete_small_exp() {
        // Symbolic base with small concrete exponent uses repeated squaring.
        // x ** 2 should produce x * x, verifiable by the solver.
        let base = BV::new_const("x", 256);
        let exp = BV::from_u64(2, 256);
        let result = apply_binary_op("**", &base, &exp, 256).unwrap();
        let result_bv = result.as_bv().unwrap();

        // Verify: when x = 5, result should be 25
        let solver = Solver::new();
        solver.assert(&base.eq(&BV::from_u64(5, 256)));
        solver.assert(&result_bv.eq(&BV::from_u64(25, 256)));
        assert_eq!(solver.check(), SatResult::Sat);
    }

    // ==== proptest: bitvector arithmetic properties ====

    use proptest::prelude::*;

    proptest! {
        // Addition commutativity: a + b == b + a
        #[test]
        fn prop_add_commutative(a in 0u64..=u64::MAX, b in 0u64..=u64::MAX) {
            let bv_a = BV::from_u64(a, 64);
            let bv_b = BV::from_u64(b, 64);
            let ab = apply_binary_op("+", &bv_a, &bv_b, 64).unwrap();
            let ba = apply_binary_op("+", &bv_b, &bv_a, 64).unwrap();
            let solver = Solver::new();
            solver.assert(&ab.as_bv().unwrap().eq(ba.as_bv().unwrap()));
            prop_assert_eq!(solver.check(), SatResult::Sat);
        }

        // Multiplication commutativity: a * b == b * a
        #[test]
        fn prop_mul_commutative(a in 0u64..=u64::MAX, b in 0u64..=u64::MAX) {
            let bv_a = BV::from_u64(a, 64);
            let bv_b = BV::from_u64(b, 64);
            let ab = apply_binary_op("*", &bv_a, &bv_b, 64).unwrap();
            let ba = apply_binary_op("*", &bv_b, &bv_a, 64).unwrap();
            let solver = Solver::new();
            solver.assert(&ab.as_bv().unwrap().eq(ba.as_bv().unwrap()));
            prop_assert_eq!(solver.check(), SatResult::Sat);
        }

        // Additive identity: a + 0 == a
        #[test]
        fn prop_add_identity(a in 0u64..=u64::MAX) {
            let bv_a = BV::from_u64(a, 64);
            let bv_0 = BV::from_u64(0, 64);
            let result = apply_binary_op("+", &bv_a, &bv_0, 64).unwrap();
            let solver = Solver::new();
            solver.assert(&result.as_bv().unwrap().eq(&bv_a));
            prop_assert_eq!(solver.check(), SatResult::Sat);
        }

        // Multiplicative identity: a * 1 == a
        #[test]
        fn prop_mul_identity(a in 0u64..=u64::MAX) {
            let bv_a = BV::from_u64(a, 64);
            let bv_1 = BV::from_u64(1, 64);
            let result = apply_binary_op("*", &bv_a, &bv_1, 64).unwrap();
            let solver = Solver::new();
            solver.assert(&result.as_bv().unwrap().eq(&bv_a));
            prop_assert_eq!(solver.check(), SatResult::Sat);
        }

        // Overflow consistency: BV add matches Rust wrapping_add for 64-bit
        #[test]
        fn prop_add_matches_wrapping(a in 0u64..=u64::MAX, b in 0u64..=u64::MAX) {
            let expected = a.wrapping_add(b);
            let bv_a = BV::from_u64(a, 64);
            let bv_b = BV::from_u64(b, 64);
            let result = apply_binary_op("+", &bv_a, &bv_b, 64).unwrap();
            let solver = Solver::new();
            solver.assert(&result.as_bv().unwrap().eq(&BV::from_u64(expected, 64)));
            prop_assert_eq!(solver.check(), SatResult::Sat);
        }

        // Subtraction overflow consistency with Rust wrapping_sub
        #[test]
        fn prop_sub_matches_wrapping(a in 0u64..=u64::MAX, b in 0u64..=u64::MAX) {
            let expected = a.wrapping_sub(b);
            let bv_a = BV::from_u64(a, 64);
            let bv_b = BV::from_u64(b, 64);
            let result = apply_binary_op("-", &bv_a, &bv_b, 64).unwrap();
            let solver = Solver::new();
            solver.assert(&result.as_bv().unwrap().eq(&BV::from_u64(expected, 64)));
            prop_assert_eq!(solver.check(), SatResult::Sat);
        }

        // Mul overflow consistency with Rust wrapping_mul
        #[test]
        fn prop_mul_matches_wrapping(a in 0u64..=u64::MAX, b in 0u64..=u64::MAX) {
            let expected = a.wrapping_mul(b);
            let bv_a = BV::from_u64(a, 64);
            let bv_b = BV::from_u64(b, 64);
            let result = apply_binary_op("*", &bv_a, &bv_b, 64).unwrap();
            let solver = Solver::new();
            solver.assert(&result.as_bv().unwrap().eq(&BV::from_u64(expected, 64)));
            prop_assert_eq!(solver.check(), SatResult::Sat);
        }
    }
}
