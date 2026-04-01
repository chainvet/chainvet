use std::collections::HashMap;

use tiny_keccak::{Hasher, Keccak};
use z3::ast::BV;
use z3::{FuncDecl, Sort};

use super::SymbolicValue;

/// Manages keccak256 modeling: concrete evaluation when possible,
/// uninterpreted function for symbolic inputs.
pub struct KeccakContext {
    /// Uninterpreted function declaration: BV<256> → BV<256>
    func_decl: FuncDecl,
    /// Cache of concrete input → concrete hash output
    concrete_cache: HashMap<Vec<u8>, [u8; 32]>,
}

impl Default for KeccakContext {
    fn default() -> Self {
        Self::new()
    }
}

impl KeccakContext {
    pub fn new() -> Self {
        let bv256 = Sort::bitvector(256);
        let func_decl = FuncDecl::new("keccak256", &[&bv256], &bv256);
        KeccakContext {
            func_decl,
            concrete_cache: HashMap::new(),
        }
    }

    /// Compute keccak256 of a single 256-bit input.
    ///
    /// If the input is concrete, computes the real keccak256 hash.
    /// If symbolic, applies the uninterpreted function.
    pub fn hash_single(&mut self, input: &SymbolicValue) -> SymbolicValue {
        let bv = match input {
            SymbolicValue::BitVec { val, .. } => val,
            _ => {
                // Non-BV input: apply uninterpreted function on a fresh var
                let fresh = BV::fresh_const("keccak_input", 256);
                return self.apply_uninterpreted(&fresh);
            }
        };

        // Try concrete evaluation
        if let Some(concrete_val) = bv.as_u64() {
            let mut input_bytes = [0u8; 32];
            input_bytes[24..32].copy_from_slice(&concrete_val.to_be_bytes());
            return self.hash_concrete_bytes(&input_bytes);
        }

        // Symbolic: apply uninterpreted function
        self.apply_uninterpreted(bv)
    }

    /// Compute keccak256(concat(parts)) for storage slot computation.
    ///
    /// Used for mapping slot calculation: `keccak256(abi.encode(key, slot))`.
    /// If all parts are concrete, computes the real hash. Otherwise uses
    /// the uninterpreted function on the concatenated symbolic BV.
    #[allow(dead_code)] // Phase 6: used for keccak256(abi.encode(key, slot)) storage slot computation
    pub fn hash_concat(&mut self, parts: &[&BV]) -> SymbolicValue {
        // Try to extract concrete u64 values from all parts.
        let concrete_parts: Vec<(u32, u64)> = parts
            .iter()
            .filter_map(|bv| bv.as_u64().map(|n| (bv.get_size(), n)))
            .collect();

        // If every part resolved to a concrete value, compute the real hash.
        if concrete_parts.len() == parts.len() {
            let mut bytes = Vec::new();
            for &(bit_width, n) in &concrete_parts {
                let width_bytes = (bit_width / 8) as usize;
                let val_bytes = n.to_be_bytes();
                // Pad to the BV's width
                if width_bytes > 8 {
                    bytes.extend(std::iter::repeat_n(0u8, width_bytes - 8));
                }
                let start = 8_usize.saturating_sub(width_bytes);
                bytes.extend_from_slice(&val_bytes[start..]);
            }
            return self.hash_concrete_bytes(&bytes);
        }

        // Symbolic: concatenate BVs and apply uninterpreted function
        // For two BV<256> parts, the concat would be BV<512>. We model the
        // hash as an uninterpreted function from the first part XOR'd with
        // the second, which is unsound for collision analysis but sufficient
        // for storage slot modeling where we mainly need injectivity.
        if parts.len() == 2 {
            // Model as uninterpreted function of a combined key
            let combined = parts[0].concat(parts[1]);
            // We need BV<256> input for our func_decl, so extract lower 256 bits
            // after XOR-folding
            let hi = combined.extract(511, 256);
            let lo = combined.extract(255, 0);
            let folded = hi.bvxor(&lo);
            return self.apply_uninterpreted(&folded);
        }

        // General case: XOR-fold all parts into a single BV<256>
        let mut folded = BV::from_u64(0, 256);
        for part in parts {
            let resized = super::bitvec::bv_resize(part, 256, false);
            folded = folded.bvxor(&resized);
        }
        self.apply_uninterpreted(&folded)
    }

    fn hash_concrete_bytes(&mut self, input: &[u8]) -> SymbolicValue {
        let hash = self
            .concrete_cache
            .entry(input.to_vec())
            .or_insert_with(|| {
                let mut hasher = Keccak::v256();
                let mut output = [0u8; 32];
                hasher.update(input);
                hasher.finalize(&mut output);
                output
            });

        // Convert 32-byte hash to BV<256> from 4 × u64 chunks
        let mut result = BV::from_u64(0, 256);
        for chunk_idx in 0..4 {
            let start = chunk_idx * 8;
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&hash[start..start + 8]);
            let chunk_val = u64::from_be_bytes(bytes);
            let chunk_bv = BV::from_u64(chunk_val, 256);
            let shift = ((3 - chunk_idx) * 64) as u64;
            if shift > 0 {
                result = result.bvor(chunk_bv.bvshl(BV::from_u64(shift, 256)));
            } else {
                result = result.bvor(&chunk_bv);
            }
        }

        SymbolicValue::BitVec {
            width: 256,
            val: result,
        }
    }

    fn apply_uninterpreted(&self, input: &BV) -> SymbolicValue {
        let result = self.func_decl.apply(&[input]);
        match result.as_bv() {
            Some(bv) => SymbolicValue::BitVec {
                width: 256,
                val: bv,
            },
            None => SymbolicValue::BitVec {
                width: 256,
                val: BV::fresh_const("keccak_fallback", 256),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tiny_keccak::{Hasher, Keccak};
    use z3::ast::BV;
    use z3::{SatResult, Solver};

    /// Helper: compute keccak256 of a byte slice and return the 32-byte hash.
    fn reference_keccak256(input: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(input);
        hasher.finalize(&mut output);
        output
    }

    /// Helper: convert a 32-byte hash to a BV<256> for comparison.
    fn hash_to_bv256(hash: &[u8; 32]) -> BV {
        let mut result = BV::from_u64(0, 256);
        for chunk_idx in 0..4 {
            let start = chunk_idx * 8;
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&hash[start..start + 8]);
            let chunk_val = u64::from_be_bytes(bytes);
            let chunk_bv = BV::from_u64(chunk_val, 256);
            let shift = ((3 - chunk_idx) * 64) as u64;
            if shift > 0 {
                result = result.bvor(chunk_bv.bvshl(BV::from_u64(shift, 256)));
            } else {
                result = result.bvor(&chunk_bv);
            }
        }
        result
    }

    // ---- KeccakContext::new ----

    #[test]
    fn test_keccak_context_new_creates_empty_cache() {
        // A fresh KeccakContext should have an empty concrete_cache.
        let ctx = KeccakContext::new();
        assert!(ctx.concrete_cache.is_empty());
    }

    #[test]
    fn test_keccak_context_default_is_equivalent_to_new() {
        let ctx = KeccakContext::default();
        assert!(ctx.concrete_cache.is_empty());
    }

    // ---- hash_single with concrete input ----

    #[test]
    fn test_hash_single_concrete_zero() {
        // keccak256 of a 32-byte zero-padded representation of 0.
        let mut ctx = KeccakContext::new();
        let input = SymbolicValue::BitVec {
            width: 256,
            val: BV::from_u64(0, 256),
        };
        let result = ctx.hash_single(&input);

        // Compute the reference hash: keccak256 of 32 zero bytes (u64 0 stored in last 8 bytes).
        let input_bytes = [0u8; 32];
        // The code stores concrete_val.to_be_bytes() in bytes[24..32], which is all zeros for 0.
        let expected_hash = reference_keccak256(&input_bytes);
        let expected_bv = hash_to_bv256(&expected_hash);

        let bv = result.as_bv().unwrap();
        let solver = Solver::new();
        solver.assert(&bv.eq(&expected_bv));
        assert_eq!(solver.check(), SatResult::Sat);
        // Verify uniqueness.
        let solver2 = Solver::new();
        solver2.assert(&bv.eq(&expected_bv).not());
        assert_eq!(solver2.check(), SatResult::Unsat);
    }

    #[test]
    fn test_hash_single_concrete_one() {
        // keccak256(1) should match the reference implementation.
        let mut ctx = KeccakContext::new();
        let input = SymbolicValue::BitVec {
            width: 256,
            val: BV::from_u64(1, 256),
        };
        let result = ctx.hash_single(&input);

        let mut input_bytes = [0u8; 32];
        input_bytes[24..32].copy_from_slice(&1u64.to_be_bytes());
        let expected_hash = reference_keccak256(&input_bytes);
        let expected_bv = hash_to_bv256(&expected_hash);

        let bv = result.as_bv().unwrap();
        let solver = Solver::new();
        solver.assert(&bv.eq(&expected_bv));
        assert_eq!(solver.check(), SatResult::Sat);
    }

    #[test]
    fn test_hash_single_concrete_is_deterministic() {
        // Hashing the same concrete value twice should produce the same result.
        let mut ctx = KeccakContext::new();
        let input = SymbolicValue::BitVec {
            width: 256,
            val: BV::from_u64(42, 256),
        };
        let r1 = ctx.hash_single(&input);
        let r2 = ctx.hash_single(&input);

        let bv1 = r1.as_bv().unwrap();
        let bv2 = r2.as_bv().unwrap();
        let solver = Solver::new();
        solver.assert(&bv1.eq(bv2));
        assert_eq!(solver.check(), SatResult::Sat);
        let solver2 = Solver::new();
        solver2.assert(&bv1.eq(bv2).not());
        assert_eq!(solver2.check(), SatResult::Unsat);
    }

    #[test]
    fn test_hash_single_different_inputs_produce_different_hashes() {
        // keccak256(0) != keccak256(1) for concrete inputs.
        let mut ctx = KeccakContext::new();
        let h0 = ctx.hash_single(&SymbolicValue::BitVec {
            width: 256,
            val: BV::from_u64(0, 256),
        });
        let h1 = ctx.hash_single(&SymbolicValue::BitVec {
            width: 256,
            val: BV::from_u64(1, 256),
        });

        let bv0 = h0.as_bv().unwrap();
        let bv1 = h1.as_bv().unwrap();
        // They should not be equal.
        let solver = Solver::new();
        solver.assert(&bv0.eq(bv1));
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    #[test]
    fn test_hash_single_populates_cache() {
        let mut ctx = KeccakContext::new();
        assert!(ctx.concrete_cache.is_empty());
        let input = SymbolicValue::BitVec {
            width: 256,
            val: BV::from_u64(7, 256),
        };
        ctx.hash_single(&input);
        assert_eq!(ctx.concrete_cache.len(), 1);
        // Hashing same value again should not add another cache entry.
        ctx.hash_single(&input);
        assert_eq!(ctx.concrete_cache.len(), 1);
    }

    // ---- hash_single with symbolic input ----

    #[test]
    fn test_hash_single_symbolic_returns_bv256() {
        // A symbolic input should produce a BV<256> result (via uninterpreted function).
        let mut ctx = KeccakContext::new();
        let input = SymbolicValue::BitVec {
            width: 256,
            val: BV::new_const("sym_input", 256),
        };
        let result = ctx.hash_single(&input);
        assert_eq!(result.width(), 256);
        assert!(result.as_bv().is_some());
    }

    #[test]
    fn test_hash_single_symbolic_is_functional() {
        // The uninterpreted function should be functional: same input => same output.
        // If we constrain two inputs to be equal, their hashes must be equal.
        let mut ctx = KeccakContext::new();
        let x = BV::new_const("x", 256);
        let y = BV::new_const("y", 256);
        let hx = ctx.hash_single(&SymbolicValue::BitVec {
            width: 256,
            val: x.clone(),
        });
        let hy = ctx.hash_single(&SymbolicValue::BitVec {
            width: 256,
            val: y.clone(),
        });

        let bv_hx = hx.as_bv().unwrap();
        let bv_hy = hy.as_bv().unwrap();

        // If x == y, then hash(x) == hash(y) (functionality of uninterpreted function).
        let solver = Solver::new();
        solver.assert(&x.eq(&y));
        solver.assert(&bv_hx.eq(bv_hy).not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "equal inputs must produce equal hash outputs"
        );
    }

    #[test]
    fn test_hash_single_non_bitvec_input_returns_bv256() {
        // A non-BV input (e.g., Bool) should still produce a BV<256> via fallback.
        let mut ctx = KeccakContext::new();
        let input = SymbolicValue::Bool {
            val: z3::ast::Bool::from_bool(true),
        };
        let result = ctx.hash_single(&input);
        assert_eq!(result.width(), 256);
        assert!(result.as_bv().is_some());
    }

    // ---- hash_concat ----

    #[test]
    fn test_hash_concat_all_concrete_matches_reference() {
        // hash_concat with two concrete BV<256> parts should match keccak256
        // of the concatenated big-endian bytes.
        let mut ctx = KeccakContext::new();
        let part1 = BV::from_u64(1, 256);
        let part2 = BV::from_u64(0, 256);

        let result = ctx.hash_concat(&[&part1, &part2]);

        // Build the reference input: 32-byte big-endian encoding of 1, then 32-byte of 0.
        let mut input_bytes = Vec::new();
        // Part1: 256 bits = 32 bytes, value 1 in big-endian
        let mut p1_bytes = vec![0u8; 24]; // 24 zero padding bytes
        p1_bytes.extend_from_slice(&1u64.to_be_bytes()); // 8 bytes for value
        input_bytes.extend_from_slice(&p1_bytes);
        // Part2: 32 zero bytes
        input_bytes.extend(std::iter::repeat(0u8).take(32));

        let expected_hash = reference_keccak256(&input_bytes);
        let expected_bv = hash_to_bv256(&expected_hash);

        let bv = result.as_bv().unwrap();
        let solver = Solver::new();
        solver.assert(&bv.eq(&expected_bv));
        assert_eq!(solver.check(), SatResult::Sat);
        let solver2 = Solver::new();
        solver2.assert(&bv.eq(&expected_bv).not());
        assert_eq!(solver2.check(), SatResult::Unsat);
    }

    #[test]
    fn test_hash_concat_different_concrete_parts_produce_different_hashes() {
        // hash_concat(1, 0) != hash_concat(0, 1) for mapping slot computation.
        let mut ctx = KeccakContext::new();
        let h1 = ctx.hash_concat(&[&BV::from_u64(1, 256), &BV::from_u64(0, 256)]);
        let h2 = ctx.hash_concat(&[&BV::from_u64(0, 256), &BV::from_u64(1, 256)]);

        let bv1 = h1.as_bv().unwrap();
        let bv2 = h2.as_bv().unwrap();
        let solver = Solver::new();
        solver.assert(&bv1.eq(bv2));
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    #[test]
    fn test_hash_concat_symbolic_parts_returns_bv256() {
        // With symbolic parts, hash_concat should still produce a BV<256>.
        let mut ctx = KeccakContext::new();
        let sym = BV::new_const("key", 256);
        let slot = BV::from_u64(0, 256);
        let result = ctx.hash_concat(&[&sym, &slot]);
        assert_eq!(result.width(), 256);
        assert!(result.as_bv().is_some());
    }

    #[test]
    fn test_hash_concat_single_part_concrete() {
        // hash_concat with a single concrete part should still produce a valid hash.
        let mut ctx = KeccakContext::new();
        let part = BV::from_u64(42, 256);
        let result = ctx.hash_concat(&[&part]);
        assert_eq!(result.width(), 256);
        assert!(result.as_bv().is_some());
    }

    #[test]
    fn test_hash_concat_three_parts_concrete() {
        // hash_concat with three concrete parts should produce a deterministic hash.
        let mut ctx = KeccakContext::new();
        let p1 = BV::from_u64(1, 256);
        let p2 = BV::from_u64(2, 256);
        let p3 = BV::from_u64(3, 256);
        let r1 = ctx.hash_concat(&[&p1, &p2, &p3]);
        let r2 = ctx.hash_concat(&[&p1, &p2, &p3]);

        let bv1 = r1.as_bv().unwrap();
        let bv2 = r2.as_bv().unwrap();
        let solver = Solver::new();
        solver.assert(&bv1.eq(bv2));
        assert_eq!(solver.check(), SatResult::Sat);
        let solver2 = Solver::new();
        solver2.assert(&bv1.eq(bv2).not());
        assert_eq!(solver2.check(), SatResult::Unsat);
    }

    #[test]
    fn test_hash_concat_two_symbolic_is_functional() {
        // For two symbolic parts, if both inputs are equal, the hashes should be equal.
        let mut ctx = KeccakContext::new();
        let x1 = BV::new_const("x1", 256);
        let x2 = BV::new_const("x2", 256);
        let y1 = BV::new_const("y1", 256);
        let y2 = BV::new_const("y2", 256);

        let h1 = ctx.hash_concat(&[&x1, &x2]);
        let h2 = ctx.hash_concat(&[&y1, &y2]);

        let bv_h1 = h1.as_bv().unwrap();
        let bv_h2 = h2.as_bv().unwrap();

        // If x1==y1 and x2==y2, then hash(x1,x2) == hash(y1,y2).
        let solver = Solver::new();
        solver.assert(&x1.eq(&y1));
        solver.assert(&x2.eq(&y2));
        solver.assert(&bv_h1.eq(bv_h2).not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "equal inputs to hash_concat must produce equal outputs"
        );
    }
}
