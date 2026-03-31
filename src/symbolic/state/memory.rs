use z3::ast::{Array, BV};
use z3::Sort;

use crate::symbolic::types::symbolic_array;
use crate::symbolic::types::SymbolicValue;
use crate::util::error::Result;

/// Word-addressed symbolic memory: `Array<BV256, BV256>`.
///
/// Models EVM call-local memory at word granularity. Each read/write operates
/// on a 256-bit word. Uninitialized memory reads return zero (Z3 Array default).
///
/// Word-addressed (not byte-addressed) because our IR is Solidity-level:
/// `Load`/`Store` with `IrPlace`, not raw `MLOAD`/`MSTORE` with byte offsets.
#[derive(Clone)]
pub struct SymbolicMemory {
    mem: Array,
}

const WORD_WIDTH: u32 = 256;

impl SymbolicMemory {
    /// Create a fresh memory initialized to all zeros.
    ///
    /// The `name` parameter labels the underlying Z3 array for debugging
    /// (e.g., `"mem_0"` for the initial state, `"mem_3"` for state ID 3).
    pub fn new(_name: &str) -> Self {
        let zero = BV::from_u64(0, WORD_WIDTH);
        let key_sort = Sort::bitvector(WORD_WIDTH);
        Self {
            mem: Array::const_array(&key_sort, &zero),
        }
    }

    /// Read a 256-bit word at the given symbolic address.
    pub fn read(&self, addr: &BV) -> Result<SymbolicValue> {
        symbolic_array::array_select(&self.mem, addr, WORD_WIDTH)
    }

    /// Write a 256-bit word at the given symbolic address.
    pub fn write(&mut self, addr: &BV, value: &BV) {
        self.mem = self.mem.store(addr, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::ast::BV;
    use z3::{SatResult, Solver};

    #[test]
    fn test_symbolic_memory_new_exists() {
        // Creating a new SymbolicMemory should not panic.
        let _mem = SymbolicMemory::new("test_mem");
    }

    #[test]
    fn test_symbolic_memory_read_uninitialized_is_zero() {
        // Reading from an address that was never written should return zero.
        // We verify this by asking Z3 whether the read value equals zero.
        let mem = SymbolicMemory::new("mem");
        let addr = BV::from_u64(100, WORD_WIDTH);
        let val = mem.read(&addr).expect("read should succeed");
        let bv = val.as_bv().expect("should be a BitVec");

        let zero = BV::from_u64(0, WORD_WIDTH);
        let solver = Solver::new_for_logic("QF_ABV").unwrap();
        // Assert that the read value is NOT zero; if unsatisfiable, then it must be zero.
        solver.assert(&bv.eq(&zero).not());
        assert_eq!(solver.check(), SatResult::Unsat, "uninitialized memory should read as zero");
    }

    #[test]
    fn test_symbolic_memory_write_then_read_same_address() {
        // Writing a value to an address and reading it back should return the same value.
        let mut mem = SymbolicMemory::new("mem");
        let addr = BV::from_u64(42, WORD_WIDTH);
        let written = BV::from_u64(0xDEAD, WORD_WIDTH);

        mem.write(&addr, &written);
        let read_val = mem.read(&addr).expect("read should succeed");
        let bv = read_val.as_bv().expect("should be a BitVec");

        let solver = Solver::new_for_logic("QF_ABV").unwrap();
        // Assert that the read value differs from the written value; should be unsat.
        solver.assert(&bv.eq(&written).not());
        assert_eq!(solver.check(), SatResult::Unsat, "read after write to same address should return written value");
    }

    #[test]
    fn test_symbolic_memory_write_does_not_affect_other_address() {
        // Writing to one address should not change the value at a different address.
        // The other address should still read as zero.
        let mut mem = SymbolicMemory::new("mem");
        let addr_a = BV::from_u64(1, WORD_WIDTH);
        let addr_b = BV::from_u64(2, WORD_WIDTH);
        let val = BV::from_u64(999, WORD_WIDTH);

        mem.write(&addr_a, &val);

        let read_b = mem.read(&addr_b).expect("read should succeed");
        let bv_b = read_b.as_bv().expect("should be a BitVec");

        let zero = BV::from_u64(0, WORD_WIDTH);
        let solver = Solver::new_for_logic("QF_ABV").unwrap();
        solver.assert(&bv_b.eq(&zero).not());
        assert_eq!(solver.check(), SatResult::Unsat, "unwritten address should still be zero");
    }

    #[test]
    fn test_symbolic_memory_overwrite_same_address() {
        // Writing twice to the same address should keep only the latest value.
        let mut mem = SymbolicMemory::new("mem");
        let addr = BV::from_u64(5, WORD_WIDTH);
        let first = BV::from_u64(100, WORD_WIDTH);
        let second = BV::from_u64(200, WORD_WIDTH);

        mem.write(&addr, &first);
        mem.write(&addr, &second);

        let read_val = mem.read(&addr).expect("read should succeed");
        let bv = read_val.as_bv().expect("should be a BitVec");

        let solver = Solver::new_for_logic("QF_ABV").unwrap();
        solver.assert(&bv.eq(&second).not());
        assert_eq!(solver.check(), SatResult::Unsat, "second write should overwrite the first");
    }

    #[test]
    fn test_symbolic_memory_symbolic_address_write_read() {
        // Writing with a symbolic address and reading with the same symbolic address
        // should return the written value.
        let mut mem = SymbolicMemory::new("mem");
        let addr = BV::new_const("sym_addr", WORD_WIDTH);
        let val = BV::from_u64(0xBEEF, WORD_WIDTH);

        mem.write(&addr, &val);
        let read_val = mem.read(&addr).expect("read should succeed");
        let bv = read_val.as_bv().expect("should be a BitVec");

        let solver = Solver::new_for_logic("QF_ABV").unwrap();
        solver.assert(&bv.eq(&val).not());
        assert_eq!(solver.check(), SatResult::Unsat, "symbolic addr write-read roundtrip should match");
    }

    #[test]
    fn test_symbolic_memory_read_returns_bitvec_width_256() {
        // The read result should always have width 256.
        let mem = SymbolicMemory::new("mem");
        let addr = BV::from_u64(0, WORD_WIDTH);
        let val = mem.read(&addr).expect("read should succeed");
        assert_eq!(val.width(), 256);
    }
}
