//! An EVM coverage inspector. Replaying a fuzzer input against the real EVM
//! tells us *whether* a call reverted; the inspector tells us *what it reached*.
//! It records the set of distinct program counters executed, which turns a bare
//! "reverted / did not revert" signal into "reached a deep branch" vs. "hit an
//! early `require` and bailed" — the distinction that makes an EVM-vs-IR
//! coverage delta meaningful.
//!
//! PCs are collected across every frame that runs, so with a single deployed
//! contract (the fuzzer target) the set is that contract's executed bytecode.

use std::collections::HashSet;

use revm::interpreter::interpreter_types::Jumps;
use revm::interpreter::{Interpreter, InterpreterTypes};
use revm::Inspector;

/// Accumulates the distinct program counters executed on the EVM. Held inside
/// the [`crate::harness::EvmHarness`]'s evm so coverage persists across a
/// transaction sequence; read back via the harness after replay.
#[derive(Debug, Default, Clone)]
pub struct CoverageInspector {
    pcs: HashSet<usize>,
}

impl CoverageInspector {
    pub fn new() -> Self {
        Self::default()
    }

    /// The set of distinct PCs executed so far.
    pub fn covered_pcs(&self) -> &HashSet<usize> {
        &self.pcs
    }

    /// Number of distinct PCs executed — the scalar EVM-coverage measure.
    pub fn unique_pc_count(&self) -> usize {
        self.pcs.len()
    }

    /// Forget everything recorded. Used to discard constructor-time PCs after
    /// deployment so reported coverage reflects only replayed calls.
    pub fn clear(&mut self) {
        self.pcs.clear();
    }
}

impl<CTX, INTR: InterpreterTypes> Inspector<CTX, INTR> for CoverageInspector {
    fn step(&mut self, interp: &mut Interpreter<INTR>, _context: &mut CTX) {
        self.pcs.insert(interp.bytecode.pc());
    }
}
