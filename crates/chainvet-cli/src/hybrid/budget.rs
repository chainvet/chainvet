//! Configurable budget for the hybrid orchestration loop.
//!
//! P1 hardcoded a starved budget (200 fuzz iters/epoch, max 3 SE assists, and a
//! 120 s wall-clock cap it never used). This carries P1's budget *shape* but with
//! realistic values: real fuzz throughput per epoch, SE depth/timeout matching the
//! linear P2 pass (96 / 30 s), and an assist policy gated by the remaining time
//! budget with a high safety cap rather than a hard count of 3. All values are
//! overridable from the CLI (see `main.rs`).

use std::collections::HashSet;

use chainvet_fuzzing::fuzzing::types::FuzzConfig;
use chainvet_se::symbolic::SymbolicOptions;

/// Fixed fuzz seed for reproducible hybrid runs and clean benchmark deltas.
pub const HYBRID_FUZZ_SEED: u64 = 0x5EED_C0DE_5EED_C0DE;

#[derive(Debug, Clone)]
pub struct HybridBudget {
    /// Maximum number of fuzz epochs in the control loop.
    pub max_epochs: u32,
    /// Wall-clock budget for fuzzing specifically (SE time does not count against
    /// it, so a long SE pass cannot starve the fuzzer).
    pub total_runtime_ms: u64,
    /// Hard overall wall-clock ceiling for the whole hybrid run. Checked between
    /// epochs and before each SE assist so no contract can run unbounded if the
    /// machine is under load (the per-call SE/fuzz timeouts handle the steady
    /// state; this bounds pathological accumulation).
    pub hard_cap_ms: u64,
    /// Upper bound on fuzz iterations per epoch (time may cut it short).
    pub fuzz_iters_per_epoch: usize,
    /// Per-epoch wall-clock cap for a fuzz slice.
    pub fuzz_epoch_ms: u64,

    /// Symbolic execution bounds for an on-stall assist (match P2's linear pass).
    pub se_max_depth: u32,
    pub se_timeout_ms: u64,
    pub se_max_states: usize,
    pub se_max_instructions: u32,
    pub se_max_loop_unrolling: u32,

    /// Safety cap on SE assists; the real gate is remaining `total_runtime_ms`.
    pub max_se_assists: u32,
    /// Consecutive low-progress epochs before the adaptive loop treats the
    /// contract as plateaued (1 = stop as soon as an epoch adds no new coverage;
    /// a genuinely-progressing contract keeps the counter at 0 and runs on).
    pub stall_epochs_threshold: u32,
    /// Minimum new-edge delta for an epoch to count as progress.
    pub min_coverage_delta: usize,

    /// Fixed fuzz seed (reproducible runs).
    pub fuzz_seed: u64,
}

impl Default for HybridBudget {
    fn default() -> Self {
        Self {
            max_epochs: 10,
            total_runtime_ms: 20_000,
            hard_cap_ms: 120_000,
            fuzz_iters_per_epoch: 6_000,
            fuzz_epoch_ms: 2_000,

            se_max_depth: 96,
            se_timeout_ms: 30_000,
            se_max_states: 2_000,
            se_max_instructions: 3_000,
            se_max_loop_unrolling: 2,

            max_se_assists: 6,
            stall_epochs_threshold: 1,
            min_coverage_delta: 1,

            fuzz_seed: HYBRID_FUZZ_SEED,
        }
    }
}

impl HybridBudget {
    /// SE options for an on-stall assist over the given target functions.
    pub fn symbolic_options(&self, target_function_ids: HashSet<u32>) -> SymbolicOptions {
        SymbolicOptions {
            target_function_ids: (!target_function_ids.is_empty()).then_some(target_function_ids),
            max_path_depth: Some(self.se_max_depth),
            max_instructions: Some(self.se_max_instructions),
            max_loop_unrolling: Some(self.se_max_loop_unrolling),
            max_states: Some(self.se_max_states),
            total_timeout_s: Some(self.se_timeout_ms.div_ceil(1000).max(1)),
        }
    }

    /// Base fuzz config for the session; per-epoch iteration/time bounds are
    /// passed to `run_slice`, so `max_iterations`/`max_duration_ms` here only
    /// matter for the legacy single-call path.
    pub fn fuzz_config(&self, seed_corpus: Vec<chainvet_fuzzing::fuzzing::types::Individual>) -> FuzzConfig {
        FuzzConfig {
            hybrid_mode: true,
            seed: Some(self.fuzz_seed),
            max_iterations: self.fuzz_iters_per_epoch,
            max_duration_ms: Some(self.fuzz_epoch_ms),
            seed_corpus,
            ..FuzzConfig::default()
        }
    }
}
