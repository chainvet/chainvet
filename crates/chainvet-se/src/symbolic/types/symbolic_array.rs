// Array-theory helpers for mapping and storage access.

use z3::Sort;
use z3::ast::{Array, BV};

use super::SymbolicValue;
use chainvet_core::util::error::{Error, Result};

/// Create a fresh symbolic array (e.g., for a mapping `mapping(uint256 => uint256)`).
#[allow(dead_code)]
pub fn new_symbolic_array(name: &str, key_width: u32, val_width: u32) -> SymbolicValue {
    let key_sort = Sort::bitvector(key_width);
    let val_sort = Sort::bitvector(val_width);
    SymbolicValue::SymArray {
        key_width,
        val_width,
        val: Array::new_const(name, &key_sort, &val_sort),
    }
}

/// Create a constant array where every index maps to the given default value.
#[allow(dead_code)]
pub fn const_array(default_val: &BV, key_width: u32, val_width: u32) -> SymbolicValue {
    let key_sort = Sort::bitvector(key_width);
    SymbolicValue::SymArray {
        key_width,
        val_width,
        val: Array::const_array(&key_sort, default_val),
    }
}

/// Read a value from an array at the given index.
/// Returns `SymbolicValue::BitVec` with the array's value sort width.
pub fn array_select(arr: &Array, index: &BV, val_width: u32) -> Result<SymbolicValue> {
    let result = arr.select(index);
    result
        .as_bv()
        .map(|bv| SymbolicValue::BitVec {
            width: val_width,
            val: bv,
        })
        .ok_or_else(|| Error::msg("array select did not produce a BV"))
}

/// Write a value to an array at the given index.
/// Returns a new `SymbolicValue::SymArray` with the updated mapping.
#[allow(dead_code)]
pub fn array_store(
    arr: &Array,
    index: &BV,
    value: &BV,
    key_width: u32,
    val_width: u32,
) -> SymbolicValue {
    SymbolicValue::SymArray {
        key_width,
        val_width,
        val: arr.store(index, value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::ast::BV;
    use z3::{SatResult, Solver};

    // ---- new_symbolic_array ----

    #[test]
    fn test_new_symbolic_array_has_correct_widths() {
        // A fresh symbolic array should report the key and value widths we specified.
        let sv = new_symbolic_array("m", 256, 256);
        assert_eq!(sv.width(), 256); // width() returns val_width for SymArray
        match &sv {
            SymbolicValue::SymArray {
                key_width,
                val_width,
                ..
            } => {
                assert_eq!(*key_width, 256);
                assert_eq!(*val_width, 256);
            }
            other => panic!("expected SymArray, got {:?}", other),
        }
    }

    #[test]
    fn test_new_symbolic_array_different_widths() {
        // Mapping from uint160 (address) to uint8 (byte).
        let sv = new_symbolic_array("balances", 160, 8);
        match &sv {
            SymbolicValue::SymArray {
                key_width,
                val_width,
                ..
            } => {
                assert_eq!(*key_width, 160);
                assert_eq!(*val_width, 8);
            }
            other => panic!("expected SymArray, got {:?}", other),
        }
    }

    #[test]
    fn test_new_symbolic_array_as_array_succeeds() {
        let sv = new_symbolic_array("m", 256, 256);
        assert!(sv.as_array().is_some());
    }

    #[test]
    fn test_new_symbolic_array_as_bv_fails() {
        // A SymArray is not a BitVec.
        let sv = new_symbolic_array("m", 256, 256);
        assert!(sv.as_bv().is_none());
    }

    // ---- const_array ----

    #[test]
    fn test_const_array_all_indices_return_default() {
        // A constant array with default 0 should return 0 at any index.
        let default_val = BV::from_u64(0, 256);
        let sv = const_array(&default_val, 256, 256);
        let arr = sv.as_array().unwrap();

        // Read at an arbitrary index and verify it equals 0.
        let idx = BV::from_u64(42, 256);
        let read = array_select(arr, &idx, 256).unwrap();
        let bv = read.as_bv().unwrap();
        let solver = Solver::new();
        solver.assert(bv.eq(BV::from_u64(0, 256)));
        assert_eq!(solver.check(), SatResult::Sat);
        // Confirm uniqueness: it cannot be anything other than 0.
        let solver2 = Solver::new();
        solver2.assert(bv.eq(BV::from_u64(0, 256)).not());
        assert_eq!(solver2.check(), SatResult::Unsat);
    }

    #[test]
    fn test_const_array_nonzero_default() {
        // A constant array with default 99 should return 99 everywhere.
        let default_val = BV::from_u64(99, 256);
        let sv = const_array(&default_val, 256, 256);
        let arr = sv.as_array().unwrap();

        let idx = BV::from_u64(12345, 256);
        let read = array_select(arr, &idx, 256).unwrap();
        let bv = read.as_bv().unwrap();
        let solver = Solver::new();
        solver.assert(bv.eq(BV::from_u64(99, 256)));
        assert_eq!(solver.check(), SatResult::Sat);
    }

    // ---- array_store then array_select (write-then-read) ----

    #[test]
    fn test_store_then_select_same_index_returns_stored_value() {
        // Writing 42 at index 7, then reading index 7 should yield 42.
        let default_val = BV::from_u64(0, 256);
        let sv = const_array(&default_val, 256, 256);
        let arr = sv.as_array().unwrap();

        let idx = BV::from_u64(7, 256);
        let val = BV::from_u64(42, 256);
        let updated = array_store(arr, &idx, &val, 256, 256);
        let updated_arr = updated.as_array().unwrap();

        let read = array_select(updated_arr, &idx, 256).unwrap();
        let read_bv = read.as_bv().unwrap();
        let solver = Solver::new();
        solver.assert(read_bv.eq(BV::from_u64(42, 256)));
        assert_eq!(solver.check(), SatResult::Sat);
        // Uniqueness
        let solver2 = Solver::new();
        solver2.assert(read_bv.eq(BV::from_u64(42, 256)).not());
        assert_eq!(solver2.check(), SatResult::Unsat);
    }

    #[test]
    fn test_store_does_not_affect_other_indices() {
        // Writing at index 7 should not change the value at index 8.
        let default_val = BV::from_u64(0, 256);
        let sv = const_array(&default_val, 256, 256);
        let arr = sv.as_array().unwrap();

        let idx7 = BV::from_u64(7, 256);
        let val = BV::from_u64(42, 256);
        let updated = array_store(arr, &idx7, &val, 256, 256);
        let updated_arr = updated.as_array().unwrap();

        // Read at index 8 -- should still be the default (0).
        let idx8 = BV::from_u64(8, 256);
        let read = array_select(updated_arr, &idx8, 256).unwrap();
        let read_bv = read.as_bv().unwrap();
        let solver = Solver::new();
        solver.assert(read_bv.eq(BV::from_u64(0, 256)));
        assert_eq!(solver.check(), SatResult::Sat);
        let solver2 = Solver::new();
        solver2.assert(read_bv.eq(BV::from_u64(0, 256)).not());
        assert_eq!(solver2.check(), SatResult::Unsat);
    }

    #[test]
    fn test_overwrite_then_read_returns_latest_value() {
        // Writing 10 then 20 at the same index should yield 20.
        let default_val = BV::from_u64(0, 256);
        let sv = const_array(&default_val, 256, 256);
        let arr = sv.as_array().unwrap();

        let idx = BV::from_u64(5, 256);
        let first = array_store(arr, &idx, &BV::from_u64(10, 256), 256, 256);
        let second = array_store(
            first.as_array().unwrap(),
            &idx,
            &BV::from_u64(20, 256),
            256,
            256,
        );

        let read = array_select(second.as_array().unwrap(), &idx, 256).unwrap();
        let read_bv = read.as_bv().unwrap();
        let solver = Solver::new();
        solver.assert(read_bv.eq(BV::from_u64(20, 256)));
        assert_eq!(solver.check(), SatResult::Sat);
        let solver2 = Solver::new();
        solver2.assert(read_bv.eq(BV::from_u64(20, 256)).not());
        assert_eq!(solver2.check(), SatResult::Unsat);
    }

    #[test]
    fn test_symbolic_array_read_from_fresh_is_unconstrained() {
        // Reading from a fresh symbolic array at any index should be satisfiable
        // for multiple values (the value is unconstrained).
        let sv = new_symbolic_array("m", 256, 256);
        let arr = sv.as_array().unwrap();
        let idx = BV::from_u64(0, 256);
        let read = array_select(arr, &idx, 256).unwrap();
        let read_bv = read.as_bv().unwrap();

        // Should be able to equal 0
        let s1 = Solver::new();
        s1.assert(read_bv.eq(BV::from_u64(0, 256)));
        assert_eq!(s1.check(), SatResult::Sat);

        // Should also be able to equal 999
        let s2 = Solver::new();
        s2.assert(read_bv.eq(BV::from_u64(999, 256)));
        assert_eq!(s2.check(), SatResult::Sat);
    }

    #[test]
    fn test_array_select_returns_bitvec_with_correct_width() {
        let sv = new_symbolic_array("m", 256, 128);
        let arr = sv.as_array().unwrap();
        let idx = BV::from_u64(0, 256);
        let read = array_select(arr, &idx, 128).unwrap();
        assert_eq!(read.width(), 128);
    }

    #[test]
    fn test_multiple_distinct_keys_store_independently() {
        // Store different values at three distinct keys and verify each reads back correctly.
        let default_val = BV::from_u64(0, 256);
        let sv = const_array(&default_val, 256, 256);
        let arr = sv.as_array().unwrap();

        let k1 = BV::from_u64(1, 256);
        let k2 = BV::from_u64(2, 256);
        let k3 = BV::from_u64(3, 256);

        let a1 = array_store(arr, &k1, &BV::from_u64(100, 256), 256, 256);
        let a2 = array_store(
            a1.as_array().unwrap(),
            &k2,
            &BV::from_u64(200, 256),
            256,
            256,
        );
        let a3 = array_store(
            a2.as_array().unwrap(),
            &k3,
            &BV::from_u64(300, 256),
            256,
            256,
        );
        let final_arr = a3.as_array().unwrap();

        for (key, expected) in [(1u64, 100u64), (2, 200), (3, 300)] {
            let read = array_select(final_arr, &BV::from_u64(key, 256), 256).unwrap();
            let bv = read.as_bv().unwrap();
            let solver = Solver::new();
            solver.assert(bv.eq(BV::from_u64(expected, 256)));
            assert_eq!(
                solver.check(),
                SatResult::Sat,
                "key {key} should map to {expected}"
            );
            let solver2 = Solver::new();
            solver2.assert(bv.eq(BV::from_u64(expected, 256)).not());
            assert_eq!(
                solver2.check(),
                SatResult::Unsat,
                "key {key} should map uniquely to {expected}"
            );
        }
    }
}
