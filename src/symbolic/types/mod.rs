pub mod bitvec;
pub mod hash;
pub mod symbolic_array;
pub mod symbolic_bytes;

use crate::norm::Literal;
use crate::util::error::{Error, Result};
use z3::ast::{Array, BV, Bool};

/// Core symbolic value type used throughout the SE engine.
///
/// All numeric EVM types map to `BitVec`, booleans to `Bool`,
/// mappings/storage to `SymArray`, and dynamic bytes/strings to `SymBytes`.
#[derive(Debug, Clone)]
pub enum SymbolicValue {
    BitVec { width: u32, val: BV },
    Bool { val: Bool },
    #[allow(dead_code)] // Phase 6: mapping/array storage type
    SymArray { key_width: u32, val_width: u32, val: Array },
    #[allow(dead_code)] // Phase 6: dynamic bytes/string type
    SymBytes {
        #[allow(dead_code)]
        len: BV,
        #[allow(dead_code)]
        content: Array,
    },
}

impl SymbolicValue {
    #[allow(dead_code)] // Phase 6: used by detectors inspecting mapping values
    pub fn as_bv(&self) -> Option<&BV> {
        match self {
            SymbolicValue::BitVec { val, .. } => Some(val),
            _ => None,
        }
    }

    #[allow(dead_code)] // Phase 6: used by detectors inspecting boolean conditions
    pub fn as_bool(&self) -> Option<&Bool> {
        match self {
            SymbolicValue::Bool { val } => Some(val),
            _ => None,
        }
    }

    #[allow(dead_code)] // Phase 6: used by detectors inspecting mapping arrays
    pub fn as_array(&self) -> Option<&Array> {
        match self {
            SymbolicValue::SymArray { val, .. } => Some(val),
            _ => None,
        }
    }

    /// Coerce to BV. BitVec returns (resized if needed). Bool returns `ite(b, 1, 0)`.
    /// Returns `Err` for SymArray/SymBytes.
    pub fn to_bv(&self, width: u32) -> Result<BV> {
        match self {
            SymbolicValue::BitVec { val, width: w } => {
                if *w == width {
                    Ok(val.clone())
                } else {
                    Ok(bitvec::bv_resize(val, width, false))
                }
            }
            SymbolicValue::Bool { val } => {
                Ok(val.ite(&BV::from_u64(1, width), &BV::from_u64(0, width)))
            }
            SymbolicValue::SymArray { .. } => {
                Err(Error::msg("cannot coerce SymArray to BV"))
            }
            SymbolicValue::SymBytes { .. } => {
                Err(Error::msg("cannot coerce SymBytes to BV"))
            }
        }
    }

    /// Coerce to Bool. Bool returns clone. BitVec returns `bv != 0`.
    /// Returns `Err` for SymArray/SymBytes.
    pub fn to_bool(&self) -> Result<Bool> {
        match self {
            SymbolicValue::Bool { val } => Ok(val.clone()),
            SymbolicValue::BitVec { val, width } => {
                Ok(val.eq(BV::from_u64(0, *width)).not())
            }
            SymbolicValue::SymArray { .. } => {
                Err(Error::msg("cannot coerce SymArray to Bool"))
            }
            SymbolicValue::SymBytes { .. } => {
                Err(Error::msg("cannot coerce SymBytes to Bool"))
            }
        }
    }

    /// Bit width of this value. For Bool returns 1, SymArray returns val_width,
    /// SymBytes returns 256.
    pub fn width(&self) -> u32 {
        match self {
            SymbolicValue::BitVec { width, .. } => *width,
            SymbolicValue::Bool { .. } => 1,
            SymbolicValue::SymArray { val_width, .. } => *val_width,
            SymbolicValue::SymBytes { .. } => 256,
        }
    }
}

/// Create a fresh named symbolic bitvector variable.
pub fn fresh_bv(name: &str, width: u32) -> SymbolicValue {
    SymbolicValue::BitVec {
        width,
        val: BV::new_const(name, width),
    }
}

/// Create a zero bitvector of given width.
pub fn zero_bv(width: u32) -> SymbolicValue {
    SymbolicValue::BitVec {
        width,
        val: BV::from_u64(0, width),
    }
}

/// Create a concrete bitvector from a u64 value.
#[allow(dead_code)] // Phase 6: used by detectors constructing concrete test values
pub fn concrete_bv(value: u64, width: u32) -> SymbolicValue {
    SymbolicValue::BitVec {
        width,
        val: BV::from_u64(value, width),
    }
}

/// Create a concrete boolean symbolic value.
#[allow(dead_code)] // Phase 6: used by detectors constructing concrete conditions
pub fn concrete_bool(value: bool) -> SymbolicValue {
    SymbolicValue::Bool {
        val: Bool::from_bool(value),
    }
}

/// Convert an IR `Literal` into a `SymbolicValue`.
///
/// Literal kinds from the frontend:
/// - `"number"` — decimal integer (default width 256)
/// - `"bool"` / `"boolean"` — `"true"` or `"false"`
/// - `"hex"` — hex string literal
/// - `"string"` — string literal (modeled as SymBytes)
/// - `"type"` — type name from `new` expressions (returns zero BV placeholder)
pub fn literal_to_symbolic(lit: &Literal) -> SymbolicValue {
    match lit.kind.as_str() {
        "number" => parse_number_literal(&lit.value),
        "bool" | "boolean" => {
            let b = lit.value == "true";
            SymbolicValue::Bool {
                val: Bool::from_bool(b),
            }
        }
        "hex" | "hexString" => parse_hex_literal(&lit.value),
        "string" => {
            let bytes = lit.value.as_bytes();
            let content_arr = symbolic_bytes::concrete_bytes_array(bytes);
            SymbolicValue::SymBytes {
                len: BV::from_u64(bytes.len() as u64, 256),
                content: content_arr,
            }
        }
        // Type names in `new` expressions or unknown literal kinds
        _ => zero_bv(256),
    }
}

/// Parse a decimal number string into a BV<256>.
fn parse_number_literal(value: &str) -> SymbolicValue {
    // Strip underscores (Solidity allows 1_000_000)
    let clean: String = value.chars().filter(|c| *c != '_').collect();

    // Try u64 first (most common case)
    if let Ok(n) = clean.parse::<u64>() {
        return SymbolicValue::BitVec {
            width: 256,
            val: BV::from_u64(n, 256),
        };
    }

    // Try i64 for negative numbers
    if let Ok(n) = clean.parse::<i64>() {
        return SymbolicValue::BitVec {
            width: 256,
            val: BV::from_i64(n, 256),
        };
    }

    // For values > u64, build from two 64-bit halves
    if let Ok(n) = clean.parse::<u128>() {
        let hi = (n >> 64) as u64;
        let lo = n as u64;
        let bv_hi = BV::from_u64(hi, 256);
        let bv_lo = BV::from_u64(lo, 256);
        let shifted = bv_hi.bvshl(BV::from_u64(64, 256));
        return SymbolicValue::BitVec {
            width: 256,
            val: shifted.bvor(&bv_lo),
        };
    }

    // Fallback for unparseable values
    zero_bv(256)
}

/// Parse a hex literal (e.g., "0xFF", "hex\"deadbeef\"") into a BV<256>.
fn parse_hex_literal(value: &str) -> SymbolicValue {
    let hex_str = value
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .trim_start_matches("hex\"")
        .trim_end_matches('"')
        .trim_start_matches("hex'")
        .trim_end_matches('\'');

    if hex_str.is_empty() {
        return zero_bv(256);
    }

    // Parse as u64 if small enough
    if hex_str.len() <= 16
        && let Ok(n) = u64::from_str_radix(hex_str, 16)
    {
        return SymbolicValue::BitVec {
            width: 256,
            val: BV::from_u64(n, 256),
        };
    }

    // For larger hex values, build from 64-bit chunks
    let padded = format!("{:0>64}", hex_str);
    let mut result = BV::from_u64(0, 256);
    for chunk_idx in 0..4 {
        let start = chunk_idx * 16;
        let chunk = &padded[start..start + 16];
        if let Ok(n) = u64::from_str_radix(chunk, 16) {
            let chunk_bv = BV::from_u64(n, 256);
            let shift_bits = ((3 - chunk_idx) * 64) as u64;
            if shift_bits > 0 {
                let shifted = chunk_bv.bvshl(BV::from_u64(shift_bits, 256));
                result = result.bvor(&shifted);
            } else {
                result = result.bvor(&chunk_bv);
            }
        }
    }

    SymbolicValue::BitVec {
        width: 256,
        val: result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::ast::BV;
    use z3::{SatResult, Solver};

    /// Helper: assert that a concrete BV has the expected u64 value.
    fn assert_bv_eq(sv: &SymbolicValue, expected: u64) {
        let bv = sv.as_bv().expect("expected BitVec variant");
        let solver = Solver::new();
        solver.assert(&bv.eq(&BV::from_u64(expected, bv.get_size())));
        assert_eq!(solver.check(), SatResult::Sat, "expected bv == {expected}");
        // Also check the negation is unsat to confirm uniqueness
        let solver2 = Solver::new();
        solver2.assert(&bv.eq(&BV::from_u64(expected, bv.get_size())).not());
        assert_eq!(
            solver2.check(),
            SatResult::Unsat,
            "bv should be exactly {expected}"
        );
    }

    /// Helper: assert that a concrete Bool has the expected boolean value.
    fn assert_bool_eq(sv: &SymbolicValue, expected: bool) {
        let b = sv.as_bool().expect("expected Bool variant");
        let solver = Solver::new();
        if expected {
            solver.assert(b);
        } else {
            solver.assert(&b.not());
        }
        assert_eq!(solver.check(), SatResult::Sat);
    }

    // ---- fresh_bv ----

    #[test]
    fn test_fresh_bv_creates_symbolic_bitvec_with_correct_width() {
        // A fresh BV should be unconstrained (symbolic) with the specified width.
        let sv = fresh_bv("x", 256);
        assert_eq!(sv.width(), 256);
        assert!(sv.as_bv().is_some());
    }

    #[test]
    fn test_fresh_bv_8bit_width() {
        let sv = fresh_bv("byte_val", 8);
        assert_eq!(sv.width(), 8);
        assert_eq!(sv.as_bv().unwrap().get_size(), 8);
    }

    // ---- zero_bv ----

    #[test]
    fn test_zero_bv_is_zero() {
        // zero_bv should produce a concrete BV with value 0.
        let sv = zero_bv(256);
        assert_bv_eq(&sv, 0);
    }

    #[test]
    fn test_zero_bv_8bit() {
        let sv = zero_bv(8);
        assert_eq!(sv.width(), 8);
        assert_bv_eq(&sv, 0);
    }

    // ---- concrete_bv ----

    #[test]
    fn test_concrete_bv_small_value() {
        let sv = concrete_bv(42, 256);
        assert_bv_eq(&sv, 42);
    }

    #[test]
    fn test_concrete_bv_max_u64() {
        let sv = concrete_bv(u64::MAX, 256);
        assert_bv_eq(&sv, u64::MAX);
    }

    #[test]
    fn test_concrete_bv_8bit_max() {
        // 255 is the max value for an 8-bit BV.
        let sv = concrete_bv(255, 8);
        assert_bv_eq(&sv, 255);
    }

    // ---- concrete_bool ----

    #[test]
    fn test_concrete_bool_true() {
        let sv = concrete_bool(true);
        assert_bool_eq(&sv, true);
        assert_eq!(sv.width(), 1);
    }

    #[test]
    fn test_concrete_bool_false() {
        let sv = concrete_bool(false);
        assert_bool_eq(&sv, false);
    }

    // ---- as_bv / as_bool / as_array ----

    #[test]
    fn test_as_bv_returns_none_for_bool() {
        let sv = concrete_bool(true);
        assert!(sv.as_bv().is_none());
    }

    #[test]
    fn test_as_bool_returns_none_for_bitvec() {
        let sv = concrete_bv(1, 256);
        assert!(sv.as_bool().is_none());
    }

    #[test]
    fn test_as_array_returns_none_for_bitvec() {
        let sv = concrete_bv(1, 256);
        assert!(sv.as_array().is_none());
    }

    // ---- to_bv ----

    #[test]
    fn test_to_bv_bitvec_same_width_is_identity() {
        // Converting a BV to the same width should return the same value.
        let sv = concrete_bv(99, 256);
        let bv = sv.to_bv(256).unwrap();
        let solver = Solver::new();
        solver.assert(&bv.eq(&BV::from_u64(99, 256)));
        assert_eq!(solver.check(), SatResult::Sat);
    }

    #[test]
    fn test_to_bv_bitvec_resize_narrow() {
        // Narrowing a 256-bit BV to 8 bits should truncate.
        let sv = concrete_bv(0x1FF, 256); // 511 in 256 bits
        let bv = sv.to_bv(8).unwrap();
        // Truncated to 8 bits: 0xFF = 255
        let solver = Solver::new();
        solver.assert(&bv.eq(&BV::from_u64(0xFF, 8)));
        assert_eq!(solver.check(), SatResult::Sat);
    }

    #[test]
    fn test_to_bv_bitvec_resize_widen() {
        // Widening an 8-bit BV to 256 bits should zero-extend.
        let sv = concrete_bv(200, 8);
        let bv = sv.to_bv(256).unwrap();
        let solver = Solver::new();
        solver.assert(&bv.eq(&BV::from_u64(200, 256)));
        assert_eq!(solver.check(), SatResult::Sat);
    }

    #[test]
    fn test_to_bv_bool_true_becomes_one() {
        // Bool true coerced to BV should become 1.
        let sv = concrete_bool(true);
        let bv = sv.to_bv(256).unwrap();
        let solver = Solver::new();
        solver.assert(&bv.eq(&BV::from_u64(1, 256)));
        assert_eq!(solver.check(), SatResult::Sat);
    }

    #[test]
    fn test_to_bv_bool_false_becomes_zero() {
        let sv = concrete_bool(false);
        let bv = sv.to_bv(256).unwrap();
        let solver = Solver::new();
        solver.assert(&bv.eq(&BV::from_u64(0, 256)));
        assert_eq!(solver.check(), SatResult::Sat);
    }

    #[test]
    fn test_to_bv_symarray_returns_error() {
        let sv = symbolic_array::new_symbolic_array("m", 256, 256);
        assert!(sv.to_bv(256).is_err());
    }

    // ---- to_bool ----

    #[test]
    fn test_to_bool_bool_is_identity() {
        let sv = concrete_bool(true);
        let b = sv.to_bool().unwrap();
        let solver = Solver::new();
        solver.assert(&b);
        assert_eq!(solver.check(), SatResult::Sat);
    }

    #[test]
    fn test_to_bool_nonzero_bv_is_true() {
        // A nonzero BV coerced to Bool should be true (bv != 0).
        let sv = concrete_bv(42, 256);
        let b = sv.to_bool().unwrap();
        let solver = Solver::new();
        solver.assert(&b);
        assert_eq!(solver.check(), SatResult::Sat);
    }

    #[test]
    fn test_to_bool_zero_bv_is_false() {
        // A zero BV coerced to Bool should be false.
        let sv = zero_bv(256);
        let b = sv.to_bool().unwrap();
        let solver = Solver::new();
        solver.assert(&b.not());
        assert_eq!(solver.check(), SatResult::Sat);
        // Also verify the bool is definitely false
        let solver2 = Solver::new();
        solver2.assert(&b);
        assert_eq!(solver2.check(), SatResult::Unsat);
    }

    #[test]
    fn test_to_bool_symarray_returns_error() {
        let sv = symbolic_array::new_symbolic_array("m", 256, 256);
        assert!(sv.to_bool().is_err());
    }

    // ---- width ----

    #[test]
    fn test_width_bitvec() {
        assert_eq!(concrete_bv(0, 8).width(), 8);
        assert_eq!(concrete_bv(0, 256).width(), 256);
    }

    #[test]
    fn test_width_bool_is_one() {
        assert_eq!(concrete_bool(true).width(), 1);
    }

    #[test]
    fn test_width_symarray_returns_val_width() {
        let sv = symbolic_array::new_symbolic_array("m", 256, 128);
        assert_eq!(sv.width(), 128);
    }

    // ---- literal_to_symbolic ----

    fn make_literal(kind: &str, value: &str) -> Literal {
        Literal {
            kind: kind.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn test_literal_to_symbolic_number_small() {
        // A small decimal number should become a BV<256> with that value.
        let sv = literal_to_symbolic(&make_literal("number", "42"));
        assert_eq!(sv.width(), 256);
        assert_bv_eq(&sv, 42);
    }

    #[test]
    fn test_literal_to_symbolic_number_with_underscores() {
        // Solidity allows underscores in number literals (e.g. 1_000_000).
        let sv = literal_to_symbolic(&make_literal("number", "1_000_000"));
        assert_bv_eq(&sv, 1_000_000);
    }

    #[test]
    fn test_literal_to_symbolic_number_zero() {
        let sv = literal_to_symbolic(&make_literal("number", "0"));
        assert_bv_eq(&sv, 0);
    }

    #[test]
    fn test_literal_to_symbolic_number_u64_max() {
        let sv = literal_to_symbolic(&make_literal("number", &u64::MAX.to_string()));
        assert_bv_eq(&sv, u64::MAX);
    }

    #[test]
    fn test_literal_to_symbolic_number_negative() {
        // Negative number should be parsed as i64 and stored as two's complement BV.
        let sv = literal_to_symbolic(&make_literal("number", "-1"));
        // -1 as i64 in two's complement 256-bit is a very large unsigned number.
        // Verify via solver that it equals the expected value.
        let bv = sv.as_bv().unwrap();
        let solver = Solver::new();
        // -1 in two's complement should have all bits set in the low 64 bits
        // and sign-extended to 256 bits via BV::from_i64
        solver.assert(&bv.eq(&BV::from_i64(-1, 256)));
        assert_eq!(solver.check(), SatResult::Sat);
    }

    #[test]
    fn test_literal_to_symbolic_number_large_u128() {
        // A number larger than u64::MAX but within u128 range.
        let big: u128 = (1u128 << 64) + 5;
        let sv = literal_to_symbolic(&make_literal("number", &big.to_string()));
        let bv = sv.as_bv().unwrap();
        // Verify the high bits: (1 << 64) + 5
        let solver = Solver::new();
        let hi_bv = BV::from_u64(1, 256);
        let lo_bv = BV::from_u64(5, 256);
        let expected = hi_bv.bvshl(&BV::from_u64(64, 256)).bvor(&lo_bv);
        solver.assert(&bv.eq(&expected));
        assert_eq!(solver.check(), SatResult::Sat);
    }

    #[test]
    fn test_literal_to_symbolic_bool_true() {
        let sv = literal_to_symbolic(&make_literal("bool", "true"));
        assert_bool_eq(&sv, true);
    }

    #[test]
    fn test_literal_to_symbolic_bool_false() {
        let sv = literal_to_symbolic(&make_literal("boolean", "false"));
        assert_bool_eq(&sv, false);
    }

    #[test]
    fn test_literal_to_symbolic_hex_small() {
        let sv = literal_to_symbolic(&make_literal("hex", "0xFF"));
        assert_bv_eq(&sv, 255);
    }

    #[test]
    fn test_literal_to_symbolic_hex_string_format() {
        // hex"deadbeef" format from Solidity.
        let sv = literal_to_symbolic(&make_literal("hexString", "hex\"deadbeef\""));
        assert_bv_eq(&sv, 0xdeadbeef);
    }

    #[test]
    fn test_literal_to_symbolic_hex_empty() {
        let sv = literal_to_symbolic(&make_literal("hex", "0x"));
        assert_bv_eq(&sv, 0);
    }

    #[test]
    fn test_literal_to_symbolic_string_produces_symbytes() {
        // A string literal should become SymBytes with the string's bytes.
        let sv = literal_to_symbolic(&make_literal("string", "hello"));
        match &sv {
            SymbolicValue::SymBytes { len, .. } => {
                let solver = Solver::new();
                solver.assert(&len.eq(&BV::from_u64(5, 256)));
                assert_eq!(solver.check(), SatResult::Sat);
            }
            other => panic!("expected SymBytes, got {:?}", other),
        }
    }

    #[test]
    fn test_literal_to_symbolic_unknown_kind_returns_zero_bv() {
        // Unknown literal kinds should fall through to zero_bv(256).
        let sv = literal_to_symbolic(&make_literal("type", "uint256"));
        assert_bv_eq(&sv, 0);
        assert_eq!(sv.width(), 256);
    }

    #[test]
    fn test_literal_to_symbolic_unparseable_number_returns_zero() {
        // A number value that can't be parsed should fall back to zero.
        let sv = literal_to_symbolic(&make_literal("number", "not_a_number"));
        assert_bv_eq(&sv, 0);
    }
}
