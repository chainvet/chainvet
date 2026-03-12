use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Budget {
    pub total_runtime_ms: u64,
    pub max_epochs: u32,
    pub fuzz_epoch_ms: u64,
    pub fuzz_iterations_per_epoch: usize,
    pub se_timeout_ms: u64,
    pub se_max_states: u64,
    pub se_max_depth: u32,
    pub max_se_assists: u32,
    pub max_seed_injection_per_assist: usize,
    pub stall_epochs_threshold: u32,
    pub min_coverage_delta: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            total_runtime_ms: 120_000,
            max_epochs: 12,
            fuzz_epoch_ms: 10_000,
            fuzz_iterations_per_epoch: 200,
            se_timeout_ms: 5_000,
            se_max_states: 5_000,
            se_max_depth: 32,
            max_se_assists: 3,
            max_seed_injection_per_assist: 8,
            stall_epochs_threshold: 2,
            min_coverage_delta: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzEpochBudget {
    pub epoch: u32,
    pub wallclock_ms: u64,
    pub max_iterations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeBudget {
    pub timeout_ms: u64,
    pub max_states: u64,
    pub max_depth: u32,
    pub max_new_seeds: usize,
}
