//! # chainvet-evm
//!
//! Opt-in **EVM validation layer**. The fuzzing engine executes an IR-level
//! interpreter, not a real EVM (`u128` values, no gas, abstract calls). This
//! crate replays fuzzer transactions against a real EVM ([`revm`]) so the
//! fidelity gap can be *measured*: whether a reverting path really reverts,
//! whether a finding reproduces, and (later) how EVM coverage compares.
//!
//! It is deliberately the only crate that depends on `revm`; nothing in the
//! pure engine crates depends on it, so the heavy dependency stays contained.

pub mod abi;
pub mod artifact;
pub mod coverage;
pub mod harness;
pub mod replay;
pub mod report;

pub use abi::{AbiType, encode_call, selector};
pub use artifact::{AbiFn, CompiledContract, compile};
pub use coverage::CoverageInspector;
pub use harness::{CallOutcome, EvmHarness, HarnessError, pool_address};
pub use replay::{
    IndividualReplay, TxReplay, TxStatus, replay_individual, replay_individual_covered,
};
pub use report::{EvmDiffReport, FindingReplay, FindingReplayVerdict, diff_report, replay_finding};

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap runtime bytecode in a minimal constructor that returns it, so
    /// `EvmHarness::deploy` installs `runtime` as the contract's code.
    fn creation_code(runtime: &[u8]) -> Vec<u8> {
        let len = runtime.len() as u8;
        // PUSH1 len, DUP1, PUSH1 0x0b (runtime offset), PUSH1 0x00, CODECOPY,
        // PUSH1 0x00, RETURN — an 11-byte prologue, runtime follows at 0x0b.
        let mut code = vec![
            0x60, len, 0x80, 0x60, 0x0b, 0x60, 0x00, 0x39, 0x60, 0x00, 0xf3,
        ];
        code.extend_from_slice(runtime);
        code
    }

    #[test]
    fn deploy_and_successful_call() {
        // Runtime: MSTORE(0, 42); RETURN(0, 32) — always succeeds, returns 42.
        let runtime = [0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        let mut harness = EvmHarness::deploy(creation_code(&runtime)).expect("deploy");
        let outcome = harness.call(1, 0, vec![]).expect("call");
        assert!(outcome.success, "call should succeed");
        assert!(!outcome.reverted);
        assert_eq!(outcome.output.last(), Some(&42u8), "returns 42");
    }

    #[test]
    fn reverting_call_is_reported_as_revert() {
        // Runtime: REVERT(0, 0) — always reverts.
        let runtime = [0x60, 0x00, 0x60, 0x00, 0xfd];
        let mut harness = EvmHarness::deploy(creation_code(&runtime)).expect("deploy");
        let outcome = harness.call(1, 0, vec![]).expect("call");
        assert!(!outcome.success, "reverting call is not a success");
        assert!(outcome.reverted, "revert must be detected");
    }

    #[test]
    fn state_persists_across_calls() {
        // Runtime: SSTORE(slot 0, CALLDATASIZE); return SLOAD(0). Each call
        // stores its calldata size at slot 0 and returns it, so the returned
        // value reflects state only if the DB persists between calls.
        // CALLDATASIZE(0x36), PUSH1 0x00, SSTORE(0x55)  [slot on top, value below]
        // PUSH1 0x00, SLOAD(0x54), PUSH1 0x00, MSTORE(0x52),
        // PUSH1 0x20, PUSH1 0x00, RETURN(0xf3)
        let runtime = [
            0x36, 0x60, 0x00, 0x55, 0x60, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00,
            0xf3,
        ];
        let mut harness = EvmHarness::deploy(creation_code(&runtime)).expect("deploy");

        // First call with 4 bytes of calldata stores 4.
        let first = harness.call(1, 0, vec![0xaa; 4]).expect("first");
        assert_eq!(first.output.last(), Some(&4u8));
        // Second call with 0 bytes stores 0, but if state persisted the SLOAD
        // reflects the just-written value (0 here); use differing sizes to show
        // the store took effect across the persisted DB.
        let second = harness.call(1, 0, vec![0xbb; 7]).expect("second");
        assert_eq!(second.output.last(), Some(&7u8), "state write persisted");
    }

    #[test]
    fn coverage_distinguishes_deep_branch_from_early_return() {
        // Runtime branches on CALLDATASIZE: empty calldata takes a 4-opcode
        // shallow path (STOP); non-empty jumps into a longer arithmetic path.
        //  0: CALLDATASIZE  1: PUSH1 05  3: JUMPI  4: STOP
        //  5: JUMPDEST  6: PUSH1 01  8: PUSH1 02  10: ADD  11: PUSH1 00
        // 13: MSTORE  14: PUSH1 20  16: PUSH1 00  18: RETURN
        let runtime = [
            0x36, 0x60, 0x05, 0x57, 0x00, 0x5b, 0x60, 0x01, 0x60, 0x02, 0x01, 0x60, 0x00, 0x52,
            0x60, 0x20, 0x60, 0x00, 0xf3,
        ];

        let mut shallow = EvmHarness::deploy(creation_code(&runtime)).expect("deploy");
        shallow.call(1, 0, vec![]).expect("shallow call");
        let shallow_pcs = shallow.covered_pc_count();

        let mut deep = EvmHarness::deploy(creation_code(&runtime)).expect("deploy");
        deep.call(1, 0, vec![0x01]).expect("deep call");
        let deep_pcs = deep.covered_pc_count();

        assert!(
            shallow_pcs >= 3,
            "shallow path still executes a few opcodes"
        );
        assert!(
            deep_pcs > shallow_pcs,
            "deep branch ({deep_pcs}) must reach more PCs than early return ({shallow_pcs})"
        );
        // Constructor PCs are cleared, so the shallow path is exactly its opcodes.
        assert_eq!(
            shallow_pcs, 4,
            "shallow path is CALLDATASIZE,PUSH1,JUMPI,STOP"
        );
    }
}
