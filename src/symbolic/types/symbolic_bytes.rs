use z3::ast::{Array, BV, Bool};
use z3::Sort;

use super::SymbolicValue;

/// Create a fresh symbolic byte array with a symbolic length bounded by `max_bound`.
/// Returns `(SymbolicValue::SymBytes, bound_constraint)` where the constraint
/// enforces `len <= max_bound`.
pub fn new_symbolic_bytes(name: &str, max_bound: u32) -> (SymbolicValue, Bool) {
    let key_sort = Sort::bitvector(256);
    let val_sort = Sort::bitvector(8);
    let len = BV::new_const(format!("{name}_len"), 256);
    let content = Array::new_const(format!("{name}_data"), &key_sort, &val_sort);
    let bound = len.bvule(&BV::from_u64(max_bound as u64, 256));
    let sv = SymbolicValue::SymBytes {
        len,
        content,
    };
    (sv, bound)
}

/// Build a concrete byte array from raw bytes.
/// Returns a `z3::ast::Array` with each index storing the corresponding byte.
pub fn concrete_bytes_array(data: &[u8]) -> Array {
    let key_sort = Sort::bitvector(256);
    let zero_byte = BV::from_u64(0, 8);
    let mut arr = Array::const_array(&key_sort, &zero_byte);

    for (i, &byte) in data.iter().enumerate() {
        let idx = BV::from_u64(i as u64, 256);
        let val = BV::from_u64(byte as u64, 8);
        arr = arr.store(&idx, &val);
    }
    arr
}

/// Read a single byte from a SymBytes value at the given index.
/// Returns `SymbolicValue::BitVec { width: 8 }`.
pub fn bytes_read(content: &Array, index: &BV) -> SymbolicValue {
    let result = content.select(index);
    // Array<BV256, BV8> select always produces BV8
    match result.as_bv() {
        Some(bv) => SymbolicValue::BitVec { width: 8, val: bv },
        None => {
            // Defensive: should not happen for a well-formed BV8 array
            SymbolicValue::BitVec {
                width: 8,
                val: BV::fresh_const("bytes_read_fallback", 8),
            }
        }
    }
}

/// Concatenate two symbolic byte arrays.
/// The result has length `a_len + b_len`, and content where indices `[0, a_len)` come
/// from `a_content` and `[a_len, a_len + b_len)` come from `b_content`.
///
/// Since Z3 arrays can't directly express this conditional indexing, we model it
/// as a fresh array with constraints pushed via the returned constraint Bool.
pub fn bytes_concat(
    a_len: &BV,
    a_content: &Array,
    b_len: &BV,
    b_content: &Array,
) -> (BV, Array, Vec<Bool>) {
    let new_len = a_len.bvadd(b_len);

    // For symbolic concat, we create a fresh array and leave it underconstrained.
    // The engine should add per-index constraints if it needs to reason about
    // specific byte positions. This is a practical tradeoff: fully constraining
    // every index would require quantifiers.
    let key_sort = Sort::bitvector(256);
    let val_sort = Sort::bitvector(8);
    let result_arr = Array::fresh_const("concat_result", &key_sort, &val_sort);

    // No additional constraints for now — quantifier-free approximation.
    // The content is left as a fresh symbolic array. If the engine needs
    // precise reasoning about concatenated bytes, it should track the
    // components separately.
    let _ = (a_content, b_content); // acknowledge unused for now

    (new_len, result_arr, Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::ast::BV;
    use z3::{SatResult, Solver};

    // ---- new_symbolic_bytes ----

    #[test]
    fn test_new_symbolic_bytes_returns_symbytes_variant() {
        // new_symbolic_bytes should produce a SymBytes with a symbolic length
        // and a bound constraint on that length.
        let (sv, bound) = new_symbolic_bytes("data", 1024);
        match &sv {
            SymbolicValue::SymBytes { len, .. } => {
                // The length should be satisfiable at 0 (within bound).
                let solver = Solver::new();
                solver.assert(&bound);
                solver.assert(&len.eq(&BV::from_u64(0, 256)));
                assert_eq!(solver.check(), SatResult::Sat);
            }
            other => panic!("expected SymBytes, got {:?}", other),
        }
    }

    #[test]
    fn test_new_symbolic_bytes_length_respects_bound() {
        // The bound constraint should prevent length from exceeding max_bound.
        let (sv, bound) = new_symbolic_bytes("data", 100);
        match &sv {
            SymbolicValue::SymBytes { len, .. } => {
                // Length = 100 should be satisfiable (it's <= 100).
                let s1 = Solver::new();
                s1.assert(&bound);
                s1.assert(&len.eq(&BV::from_u64(100, 256)));
                assert_eq!(s1.check(), SatResult::Sat);

                // Length = 101 should be unsatisfiable with the bound.
                let s2 = Solver::new();
                s2.assert(&bound);
                s2.assert(&len.eq(&BV::from_u64(101, 256)));
                assert_eq!(s2.check(), SatResult::Unsat);
            }
            other => panic!("expected SymBytes, got {:?}", other),
        }
    }

    #[test]
    fn test_new_symbolic_bytes_width_is_256() {
        let (sv, _) = new_symbolic_bytes("data", 1024);
        assert_eq!(sv.width(), 256);
    }

    // ---- concrete_bytes_array ----

    #[test]
    fn test_concrete_bytes_array_empty() {
        // An empty byte array should return 0 at any index (default).
        let arr = concrete_bytes_array(&[]);
        let idx = BV::from_u64(0, 256);
        let read = arr.select(&idx);
        let bv = read.as_bv().unwrap();
        let solver = Solver::new();
        solver.assert(&bv.eq(&BV::from_u64(0, 8)));
        assert_eq!(solver.check(), SatResult::Sat);
    }

    #[test]
    fn test_concrete_bytes_array_stores_correct_bytes() {
        // Build array from [0x48, 0x65, 0x6C] ("Hel") and verify each byte.
        let data: &[u8] = &[0x48, 0x65, 0x6C];
        let arr = concrete_bytes_array(data);

        for (i, &expected_byte) in data.iter().enumerate() {
            let idx = BV::from_u64(i as u64, 256);
            let read = arr.select(&idx);
            let bv = read.as_bv().unwrap();
            let solver = Solver::new();
            solver.assert(&bv.eq(&BV::from_u64(expected_byte as u64, 8)));
            assert_eq!(
                solver.check(),
                SatResult::Sat,
                "byte at index {i} should be 0x{expected_byte:02X}"
            );
            // Uniqueness
            let solver2 = Solver::new();
            solver2.assert(&bv.eq(&BV::from_u64(expected_byte as u64, 8)).not());
            assert_eq!(solver2.check(), SatResult::Unsat);
        }
    }

    #[test]
    fn test_concrete_bytes_array_out_of_range_returns_zero() {
        // Reading past the stored bytes should return the default (0).
        let arr = concrete_bytes_array(&[0xAB, 0xCD]);
        let idx = BV::from_u64(99, 256);
        let read = arr.select(&idx);
        let bv = read.as_bv().unwrap();
        let solver = Solver::new();
        solver.assert(&bv.eq(&BV::from_u64(0, 8)));
        assert_eq!(solver.check(), SatResult::Sat);
        let solver2 = Solver::new();
        solver2.assert(&bv.eq(&BV::from_u64(0, 8)).not());
        assert_eq!(solver2.check(), SatResult::Unsat);
    }

    // ---- bytes_read ----

    #[test]
    fn test_bytes_read_returns_correct_byte() {
        // bytes_read is a wrapper around array select; verify it returns BV<8>.
        let arr = concrete_bytes_array(&[10, 20, 30]);
        let idx = BV::from_u64(1, 256);
        let result = bytes_read(&arr, &idx);
        assert_eq!(result.width(), 8);
        let bv = result.as_bv().unwrap();
        let solver = Solver::new();
        solver.assert(&bv.eq(&BV::from_u64(20, 8)));
        assert_eq!(solver.check(), SatResult::Sat);
        let solver2 = Solver::new();
        solver2.assert(&bv.eq(&BV::from_u64(20, 8)).not());
        assert_eq!(solver2.check(), SatResult::Unsat);
    }

    #[test]
    fn test_bytes_read_first_and_last_byte() {
        let data = &[0xFF, 0x00, 0x42];
        let arr = concrete_bytes_array(data);

        // First byte
        let first = bytes_read(&arr, &BV::from_u64(0, 256));
        let bv0 = first.as_bv().unwrap();
        let solver = Solver::new();
        solver.assert(&bv0.eq(&BV::from_u64(0xFF, 8)));
        assert_eq!(solver.check(), SatResult::Sat);

        // Last byte
        let last = bytes_read(&arr, &BV::from_u64(2, 256));
        let bv2 = last.as_bv().unwrap();
        let solver2 = Solver::new();
        solver2.assert(&bv2.eq(&BV::from_u64(0x42, 8)));
        assert_eq!(solver2.check(), SatResult::Sat);
    }

    #[test]
    fn test_bytes_read_from_symbolic_array_is_unconstrained() {
        // Reading from a fresh symbolic bytes array should be unconstrained.
        let (sv, _bound) = new_symbolic_bytes("data", 1024);
        match &sv {
            SymbolicValue::SymBytes { content, .. } => {
                let read = bytes_read(content, &BV::from_u64(0, 256));
                let bv = read.as_bv().unwrap();
                // Can be 0
                let s1 = Solver::new();
                s1.assert(&bv.eq(&BV::from_u64(0, 8)));
                assert_eq!(s1.check(), SatResult::Sat);
                // Can also be 0xFF
                let s2 = Solver::new();
                s2.assert(&bv.eq(&BV::from_u64(0xFF, 8)));
                assert_eq!(s2.check(), SatResult::Sat);
            }
            other => panic!("expected SymBytes, got {:?}", other),
        }
    }

    // ---- bytes_concat ----

    #[test]
    fn test_bytes_concat_length_is_sum() {
        // Concatenating two byte arrays should produce length = a_len + b_len.
        let a_len = BV::from_u64(5, 256);
        let b_len = BV::from_u64(3, 256);
        let a_arr = concrete_bytes_array(&[1, 2, 3, 4, 5]);
        let b_arr = concrete_bytes_array(&[6, 7, 8]);

        let (new_len, _result_arr, _constraints) =
            bytes_concat(&a_len, &a_arr, &b_len, &b_arr);

        let solver = Solver::new();
        solver.assert(&new_len.eq(&BV::from_u64(8, 256)));
        assert_eq!(solver.check(), SatResult::Sat);
        let solver2 = Solver::new();
        solver2.assert(&new_len.eq(&BV::from_u64(8, 256)).not());
        assert_eq!(solver2.check(), SatResult::Unsat);
    }

    #[test]
    fn test_bytes_concat_with_empty_first_array() {
        // Concatenating empty + [1,2,3] should have length 3.
        let a_len = BV::from_u64(0, 256);
        let b_len = BV::from_u64(3, 256);
        let a_arr = concrete_bytes_array(&[]);
        let b_arr = concrete_bytes_array(&[1, 2, 3]);

        let (new_len, _result_arr, constraints) =
            bytes_concat(&a_len, &a_arr, &b_len, &b_arr);

        assert!(constraints.is_empty(), "current implementation returns no constraints");

        let solver = Solver::new();
        solver.assert(&new_len.eq(&BV::from_u64(3, 256)));
        assert_eq!(solver.check(), SatResult::Sat);
    }

    #[test]
    fn test_bytes_concat_result_array_is_fresh_symbolic() {
        // The current implementation returns a fresh unconstrained array for the content.
        // Verify the result array can hold any value at index 0.
        let a_len = BV::from_u64(1, 256);
        let b_len = BV::from_u64(1, 256);
        let a_arr = concrete_bytes_array(&[0xAA]);
        let b_arr = concrete_bytes_array(&[0xBB]);

        let (_, result_arr, _) = bytes_concat(&a_len, &a_arr, &b_len, &b_arr);

        let read = result_arr.select(&BV::from_u64(0, 256));
        let bv = read.as_bv().unwrap();
        // Fresh array: any value is possible
        let s1 = Solver::new();
        s1.assert(&bv.eq(&BV::from_u64(0xAA, 8)));
        assert_eq!(s1.check(), SatResult::Sat);
        let s2 = Solver::new();
        s2.assert(&bv.eq(&BV::from_u64(0x00, 8)));
        assert_eq!(s2.check(), SatResult::Sat);
    }

    #[test]
    fn test_bytes_concat_symbolic_lengths() {
        // With symbolic lengths, the result length should be their sum.
        let a_len = BV::new_const("a_len", 256);
        let b_len = BV::new_const("b_len", 256);
        let a_arr = concrete_bytes_array(&[]);
        let b_arr = concrete_bytes_array(&[]);

        let (new_len, _, _) = bytes_concat(&a_len, &a_arr, &b_len, &b_arr);

        // If a_len = 10 and b_len = 20, new_len should be 30.
        let solver = Solver::new();
        solver.assert(&a_len.eq(&BV::from_u64(10, 256)));
        solver.assert(&b_len.eq(&BV::from_u64(20, 256)));
        solver.assert(&new_len.eq(&BV::from_u64(30, 256)));
        assert_eq!(solver.check(), SatResult::Sat);
    }
}
