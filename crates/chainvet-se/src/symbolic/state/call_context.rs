use z3::ast::{BV, Bool};

/// Symbolic blockchain environment for one call frame.
///
/// All fields are symbolic by default. Initial constraints bounding values
/// to realistic ranges are returned separately from `new_symbolic()` — the
/// engine is responsible for adding them to the state's `PathConstraints`.
#[derive(Clone)]
pub struct CallContext {
    /// `msg.sender`: `BV<160>` — caller address.
    pub msg_sender: BV,
    /// `msg.value`: `BV<256>` — Ether sent with the call.
    pub msg_value: BV,
    /// `tx.origin`: `BV<160>` — original external caller.
    pub tx_origin: BV,
    /// `block.timestamp`: `BV<256>`.
    pub block_timestamp: BV,
    /// `block.number`: `BV<256>`.
    pub block_number: BV,
    /// `block.coinbase`: `BV<160>`.
    pub block_coinbase: BV,
    /// `address(this)`: `BV<160>` — concrete address for the contract under analysis.
    #[allow(dead_code)] // Phase 6: used by detectors checking address(this) == msg.sender
    pub this_address: BV,
    /// `address(this).balance`: `BV<256>`.
    pub this_balance: BV,
}

impl CallContext {
    /// Create a fresh symbolic call context with realistic constraints.
    ///
    /// Returns `(context, initial_constraints)` where `initial_constraints`
    /// should be added to the state's `PathConstraints` by the engine.
    ///
    /// See `build_initial_constraints` for the full list of applied constraints.
    pub fn new_symbolic() -> (Self, Vec<(Bool, String)>) {
        let ctx = Self {
            msg_sender: BV::new_const("msg_sender", 160),
            msg_value: BV::new_const("msg_value", 256),
            tx_origin: BV::new_const("tx_origin", 160),
            block_timestamp: BV::new_const("block_timestamp", 256),
            block_number: BV::new_const("block_number", 256),
            block_coinbase: BV::new_const("block_coinbase", 160),
            this_address: BV::from_u64(0x1001, 160),
            this_balance: BV::new_const("this_balance", 256),
        };
        let constraints = ctx.build_initial_constraints();
        (ctx, constraints)
    }

    /// Build realistic constraints for a fresh symbolic call context.
    ///
    /// Constraints applied:
    /// - `msg_sender != 0` (address(0) is the burn address, not a real caller)
    /// - `tx_origin != 0` (same reasoning)
    /// - `block_timestamp > 0` and `<= u64::MAX` (realistic range)
    /// - `block_number > 0` and `<= u64::MAX` (realistic range)
    ///
    /// NOT constrained (by design):
    /// - `tx_origin == msg_sender` — independence is critical for
    ///   detecting `tx.origin` authentication bypass vulnerabilities.
    /// - `msg_value` — for non-payable functions, engine adds `msg_value == 0`.
    /// - `this_balance` — for payable functions, engine adds `this_balance >= msg_value`.
    fn build_initial_constraints(&self) -> Vec<(Bool, String)> {
        let zero_160 = BV::from_u64(0, 160);
        let zero_256 = BV::from_u64(0, 256);
        let max_u64 = BV::from_u64(u64::MAX, 256);

        vec![
            (
                self.msg_sender.eq(&zero_160).not(),
                "msg.sender is non-zero address".into(),
            ),
            (
                self.tx_origin.eq(&zero_160).not(),
                "tx.origin is non-zero address".into(),
            ),
            (
                self.block_timestamp.bvugt(&zero_256),
                "block.timestamp is positive".into(),
            ),
            (
                self.block_timestamp.bvule(&max_u64),
                "block.timestamp fits in u64".into(),
            ),
            (
                self.block_number.bvugt(&zero_256),
                "block.number is positive".into(),
            ),
            (
                self.block_number.bvule(&max_u64),
                "block.number fits in u64".into(),
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{SatResult, Solver};

    #[test]
    fn test_call_context_new_symbolic_returns_six_constraints() {
        // new_symbolic() should return exactly 6 initial constraints
        // (sender != 0, origin != 0, timestamp > 0, timestamp <= u64::MAX,
        //  block_number > 0, block_number <= u64::MAX).
        let (_ctx, constraints) = CallContext::new_symbolic();
        assert_eq!(constraints.len(), 6);
    }

    #[test]
    fn test_call_context_msg_sender_is_160_bits() {
        // msg_sender should be a 160-bit bitvector (Ethereum address width).
        let (ctx, _) = CallContext::new_symbolic();
        assert_eq!(ctx.msg_sender.get_size(), 160);
    }

    #[test]
    fn test_call_context_msg_value_is_256_bits() {
        // msg_value should be a 256-bit bitvector (EVM word size).
        let (ctx, _) = CallContext::new_symbolic();
        assert_eq!(ctx.msg_value.get_size(), 256);
    }

    #[test]
    fn test_call_context_tx_origin_is_160_bits() {
        let (ctx, _) = CallContext::new_symbolic();
        assert_eq!(ctx.tx_origin.get_size(), 160);
    }

    #[test]
    fn test_call_context_block_timestamp_is_256_bits() {
        let (ctx, _) = CallContext::new_symbolic();
        assert_eq!(ctx.block_timestamp.get_size(), 256);
    }

    #[test]
    fn test_call_context_block_number_is_256_bits() {
        let (ctx, _) = CallContext::new_symbolic();
        assert_eq!(ctx.block_number.get_size(), 256);
    }

    #[test]
    fn test_call_context_block_coinbase_is_160_bits() {
        let (ctx, _) = CallContext::new_symbolic();
        assert_eq!(ctx.block_coinbase.get_size(), 160);
    }

    #[test]
    fn test_call_context_this_address_is_concrete_160_bits() {
        // this_address should be a concrete 160-bit value (0x1001).
        let (ctx, _) = CallContext::new_symbolic();
        assert_eq!(ctx.this_address.get_size(), 160);
    }

    #[test]
    fn test_call_context_this_balance_is_256_bits() {
        let (ctx, _) = CallContext::new_symbolic();
        assert_eq!(ctx.this_balance.get_size(), 256);
    }

    #[test]
    fn test_call_context_constraints_are_satisfiable() {
        // The 6 initial constraints should be satisfiable together (not contradictory).
        let (_ctx, constraints) = CallContext::new_symbolic();
        let solver = Solver::new_for_logic("QF_ABV").unwrap();
        for (c, _desc) in &constraints {
            solver.assert(c);
        }
        assert_eq!(
            solver.check(),
            SatResult::Sat,
            "initial constraints should be satisfiable"
        );
    }

    #[test]
    fn test_call_context_msg_sender_nonzero_enforced() {
        // Under the initial constraints, msg_sender == 0 should be unsatisfiable.
        let (ctx, constraints) = CallContext::new_symbolic();
        let solver = Solver::new_for_logic("QF_ABV").unwrap();
        for (c, _) in &constraints {
            solver.assert(c);
        }
        let zero_160 = BV::from_u64(0, 160);
        solver.assert(ctx.msg_sender.eq(&zero_160));
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "msg_sender == 0 should be unsat with initial constraints"
        );
    }

    #[test]
    fn test_call_context_tx_origin_independent_from_msg_sender() {
        // tx_origin and msg_sender should be independent (not constrained to be equal).
        // So tx_origin != msg_sender should be satisfiable.
        let (ctx, constraints) = CallContext::new_symbolic();
        let solver = Solver::new_for_logic("QF_ABV").unwrap();
        for (c, _) in &constraints {
            solver.assert(c);
        }
        solver.assert(ctx.tx_origin.eq(&ctx.msg_sender).not());
        assert_eq!(
            solver.check(),
            SatResult::Sat,
            "tx_origin and msg_sender should be independent"
        );
    }

    #[test]
    fn test_call_context_constraint_descriptions_are_nonempty() {
        // Each constraint should have a non-empty human-readable description.
        let (_ctx, constraints) = CallContext::new_symbolic();
        for (_c, desc) in &constraints {
            assert!(
                !desc.is_empty(),
                "constraint description should not be empty"
            );
        }
    }
}
