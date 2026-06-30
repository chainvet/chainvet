use serde::Serialize;
use z3::Model;
use z3::ast::BV;

use crate::symbolic::state::call_context::CallContext;
use crate::symbolic::state::variables::VariableEnv;
use chainvet_core::ir::IrVar;

/// Concrete counterexample extracted from a Z3 model.
///
/// Uses byte arrays instead of Z3 AST references so the witness
/// is safe to serialize, display, and pass to the fuzzer.
#[derive(Debug, Clone, Serialize)]
pub struct Witness {
    /// msg.sender as big-endian 20-byte address.
    pub msg_sender: [u8; 20],
    /// msg.value as big-endian 32-byte uint256.
    pub msg_value: [u8; 32],
    /// tx.origin as big-endian 20-byte address.
    pub tx_origin: [u8; 20],
    /// block.timestamp (bounded to u64 by initial constraints).
    pub block_timestamp: u64,
    /// block.number (bounded to u64 by initial constraints).
    pub block_number: u64,
    /// address(this).balance as big-endian 32-byte uint256.
    pub this_balance: [u8; 32],
    /// Additional named symbolic variables with their concrete values.
    pub variables: Vec<(String, Vec<u8>)>,
}

impl Witness {
    /// Extract concrete values from a Z3 model using the CallContext BVs.
    ///
    /// Requires `model.completion = true` on the solver so all variables
    /// receive a value even if unconstrained.
    pub fn from_model(model: &Model, call_ctx: &CallContext) -> Self {
        Self {
            msg_sender: eval_bv_fixed::<20>(model, &call_ctx.msg_sender),
            msg_value: eval_bv_fixed::<32>(model, &call_ctx.msg_value),
            tx_origin: eval_bv_fixed::<20>(model, &call_ctx.tx_origin),
            block_timestamp: eval_bv_u64(model, &call_ctx.block_timestamp),
            block_number: eval_bv_u64(model, &call_ctx.block_number),
            this_balance: eval_bv_fixed::<32>(model, &call_ctx.this_balance),
            variables: Vec::new(),
        }
    }

    /// Extract concrete values for all Named IR variables from the model
    /// and append them to `self.variables`. This allows the hybrid seeder
    /// to map witness values back to function parameter names.
    pub fn populate_variables(&mut self, model: &Model, variables: &VariableEnv) {
        for (var, sym_val) in variables.iter() {
            if let IrVar::Named(name) = var {
                if let Some(bv) = sym_val.as_bv() {
                    let byte_count = (bv.get_size() as usize + 7) / 8;
                    let bytes = eval_bv_bytes(model, bv, byte_count);
                    self.variables.push((name.clone(), bytes));
                }
            }
        }
    }
}

/// Evaluate a BV in the model and extract as a fixed-size big-endian byte array.
///
/// For BVs wider than 64 bits, extracts in 64-bit chunks from high to low.
fn eval_bv_fixed<const N: usize>(model: &Model, bv: &BV) -> [u8; N] {
    let bytes = eval_bv_bytes(model, bv, N);
    let mut result = [0u8; N];
    let len = bytes.len().min(N);
    // Right-align: pad with leading zeros if bytes is shorter than N.
    result[N - len..].copy_from_slice(&bytes[..len]);
    result
}

/// Evaluate a BV in the model and extract as u64.
///
/// Falls back to 0 if the model cannot evaluate the BV.
fn eval_bv_u64(model: &Model, bv: &BV) -> u64 {
    let evaluated = model.eval(bv, true);
    match evaluated {
        Some(concrete) => concrete.as_u64().unwrap_or(0),
        None => 0,
    }
}

/// Evaluate a BV in the model and extract as big-endian byte vector.
///
/// Strategy: for BVs ≤ 64 bits wide, use `as_u64()` directly.
/// For wider BVs, extract in 64-bit chunks from high bits to low bits,
/// evaluate each chunk, and concatenate big-endian.
pub fn eval_bv_bytes(model: &Model, bv: &BV, expected_bytes: usize) -> Vec<u8> {
    let evaluated = match model.eval(bv, true) {
        Some(concrete) => concrete,
        None => return vec![0u8; expected_bytes],
    };

    let bit_width = expected_bytes * 8;

    if bit_width <= 64 {
        let val = evaluated.as_u64().unwrap_or(0);
        return val.to_be_bytes()[8 - expected_bytes..].to_vec();
    }

    // Extract in 64-bit chunks, high to low.
    let full_chunks = bit_width / 64;
    let remainder_bits = bit_width % 64;
    let mut result = Vec::with_capacity(expected_bytes);

    // Handle partial high chunk if bit_width is not a multiple of 64.
    if remainder_bits > 0 {
        let high = (bit_width - 1) as u32;
        let low = (full_chunks * 64) as u32;
        let chunk = evaluated.extract(high, low);
        let chunk_val = model
            .eval(&chunk, true)
            .and_then(|c| c.as_u64())
            .unwrap_or(0);
        let chunk_bytes = remainder_bits.div_ceil(8);
        let be = chunk_val.to_be_bytes();
        result.extend_from_slice(&be[8 - chunk_bytes..]);
    }

    // Handle full 64-bit chunks from high to low.
    for i in (0..full_chunks).rev() {
        let high = ((i + 1) * 64 - 1) as u32;
        let low = (i * 64) as u32;
        let chunk = evaluated.extract(high, low);
        let chunk_val = model
            .eval(&chunk, true)
            .and_then(|c| c.as_u64())
            .unwrap_or(0);
        result.extend_from_slice(&chunk_val.to_be_bytes());
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Params, SatResult, Solver};

    /// Build a solver with model.completion=true and assert all initial constraints.
    fn make_solver_with_ctx(constraints: &[(z3::ast::Bool, String)]) -> Solver {
        let solver = Solver::new_for_logic("QF_ABV").unwrap_or_else(Solver::new);
        let mut params = Params::new();
        params.set_bool("model.completion", true);
        solver.set_params(&params);
        for (c, _) in constraints {
            solver.assert(c);
        }
        solver
    }

    #[test]
    fn test_witness_from_model_block_timestamp() {
        // Constrain block_timestamp to a specific known value and verify
        // that from_model() extracts that exact value.
        let (call_ctx, constraints) = CallContext::new_symbolic();
        let solver = make_solver_with_ctx(&constraints);

        let known_ts: u64 = 1_700_000_000;
        let ts_val = BV::from_u64(known_ts, 256);
        solver.assert(&call_ctx.block_timestamp.eq(&ts_val));

        assert_eq!(solver.check(), SatResult::Sat);
        let model = solver.get_model().unwrap();
        let witness = Witness::from_model(&model, &call_ctx);

        assert_eq!(
            witness.block_timestamp, known_ts,
            "block_timestamp should match the constrained value"
        );
    }

    #[test]
    fn test_witness_from_model_block_number() {
        // Constrain block_number to a known value and verify extraction.
        let (call_ctx, constraints) = CallContext::new_symbolic();
        let solver = make_solver_with_ctx(&constraints);

        let known_bn: u64 = 12_345;
        let bn_val = BV::from_u64(known_bn, 256);
        solver.assert(&call_ctx.block_number.eq(&bn_val));

        assert_eq!(solver.check(), SatResult::Sat);
        let model = solver.get_model().unwrap();
        let witness = Witness::from_model(&model, &call_ctx);

        assert_eq!(
            witness.block_number, known_bn,
            "block_number should match the constrained value"
        );
    }

    #[test]
    fn test_witness_from_model_msg_value_zero() {
        // Constrain msg_value to 0 and verify all 32 bytes of the extracted
        // value are zero (big-endian uint256 representation).
        let (call_ctx, constraints) = CallContext::new_symbolic();
        let solver = make_solver_with_ctx(&constraints);

        let zero_256 = BV::from_u64(0, 256);
        solver.assert(&call_ctx.msg_value.eq(&zero_256));

        assert_eq!(solver.check(), SatResult::Sat);
        let model = solver.get_model().unwrap();
        let witness = Witness::from_model(&model, &call_ctx);

        assert_eq!(
            witness.msg_value, [0u8; 32],
            "all 32 bytes of msg_value should be zero"
        );
    }

    #[test]
    fn test_witness_variables_is_empty() {
        // The variables field is always empty in from_model() — no named
        // symbolic variables are populated by from_model() itself.
        let (call_ctx, constraints) = CallContext::new_symbolic();
        let solver = make_solver_with_ctx(&constraints);

        assert_eq!(solver.check(), SatResult::Sat);
        let model = solver.get_model().unwrap();
        let witness = Witness::from_model(&model, &call_ctx);

        assert!(
            witness.variables.is_empty(),
            "variables should be empty — only filled by callers, not from_model()"
        );
    }

    #[test]
    fn test_witness_msg_sender_nonzero() {
        // The initial constraint asserts msg_sender != 0, so the extracted
        // msg_sender must have at least one non-zero byte in any valid model.
        let (call_ctx, constraints) = CallContext::new_symbolic();
        let solver = make_solver_with_ctx(&constraints);

        assert_eq!(solver.check(), SatResult::Sat);
        let model = solver.get_model().unwrap();
        let witness = Witness::from_model(&model, &call_ctx);

        let all_zero = witness.msg_sender.iter().all(|&b| b == 0);
        assert!(
            !all_zero,
            "msg_sender should have at least one non-zero byte (initial constraint: sender != 0)"
        );
    }
}
