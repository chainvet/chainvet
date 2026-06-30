use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

use crate::symbolic::detectors::DetectorRegistry;
use crate::symbolic::state::SymbolicState;
use crate::symbolic::state::storage::StorageLayout;
use chainvet_core::cfg::BlockId;
use chainvet_core::norm::Span;

use super::explorer::ExplorationStrategyKind;

/// One entry in the worklist: a state to explore plus its scheduling metadata.
pub struct WorklistEntry {
    /// The symbolic state to explore.
    pub state: SymbolicState,
    /// Which CFG function this state belongs to.
    pub cfg_func_id: u32,
    /// The block we just came from (for future phi-node resolution).
    #[allow(dead_code)] // Phase 6: used by SSA phi-node resolver
    pub predecessor_block: Option<BlockId>,
    /// How many times each loop header has been entered on this path.
    /// Used for loop unrolling bound enforcement.
    pub loop_counts: HashMap<BlockId, u32>,
}

impl WorklistEntry {
    /// Fork this entry to a new target block, preserving loop counts.
    pub fn fork_to(&self, target: BlockId) -> Self {
        Self {
            state: self.state.clone(),
            cfg_func_id: self.cfg_func_id,
            predecessor_block: Some(self.state.current_block),
            loop_counts: self.loop_counts.clone(),
        }
        .with_block(target)
    }

    fn with_block(mut self, block: BlockId) -> Self {
        self.state.current_block = block;
        self
    }
}

/// Engine-wide configuration.
///
/// Built once by the caller and passed to `run_engine`. Detectors and
/// layout are shared across all states.
pub struct SeConfig {
    /// Maximum branch depth per path before a state is dropped.
    pub max_path_depth: u32,
    /// Maximum IR instructions executed per path.
    pub max_instructions: u32,
    /// Maximum number of times a loop header is visited on one path.
    pub max_loop_unrolling: u32,
    /// Maximum number of states on the worklist at any time.
    pub max_states: usize,
    /// Per-query solver timeout in milliseconds (0 = no timeout).
    pub solver_timeout_ms: u64,
    /// Total analysis wall-clock timeout in seconds (0 = no timeout).
    pub total_timeout_s: u64,
    /// Upper bound on symbolic byte array lengths.
    #[allow(dead_code)] // Phase 6: bounds SymBytes len in new_symbolic_bytes calls
    pub dynamic_bytes_bound: usize,
    /// Worklist ordering.
    pub exploration_strategy: ExplorationStrategyKind,
    /// Registered vulnerability detectors.
    pub detectors: DetectorRegistry,
    /// Storage slot layout derived from the NormalizedAst.
    /// Shared read-only — NOT cloned with state.
    pub storage_layout: Arc<StorageLayout>,
    /// Contract name used for storage slot lookup.
    /// Defaults to empty string (single-contract analysis).
    pub contract_name: String,
    /// Optional function-level targeting used by hybrid mode.
    pub target_function_ids: Option<HashSet<u32>>,
    /// Optional sink span preference used by hybrid mode.
    pub preferred_sink_span: Option<Span>,
}

impl Default for SeConfig {
    fn default() -> Self {
        Self {
            max_path_depth: 256,
            max_instructions: 10_000,
            max_loop_unrolling: 3,
            max_states: 10_000,
            solver_timeout_ms: 5_000,
            total_timeout_s: 300,
            dynamic_bytes_bound: 256,
            exploration_strategy: ExplorationStrategyKind::VulnerabilityDirected,
            detectors: DetectorRegistry::new(),
            storage_layout: Arc::new(StorageLayout::empty()),
            contract_name: String::new(),
            target_function_ids: None,
            preferred_sink_span: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbolic::state::call_context::CallContext;
    use crate::symbolic::state::{StateIdGen, SymbolicState};

    /// Build a minimal WorklistEntry at the given block_id.
    fn make_entry(block_id: BlockId) -> WorklistEntry {
        let mut id_gen = StateIdGen::new();
        let (call_ctx, _) = CallContext::new_symbolic();
        let state = SymbolicState::initial(&mut id_gen, block_id, call_ctx);
        WorklistEntry {
            state,
            cfg_func_id: 0,
            predecessor_block: None,
            loop_counts: HashMap::new(),
        }
    }

    // ---- SeConfig::default tests ----

    #[test]
    fn test_seconfig_default_values() {
        // SeConfig::default() must expose the expected sentinel values
        // that the engine relies on for path/loop/state budgets.
        let cfg = SeConfig::default();
        assert_eq!(cfg.max_path_depth, 256);
        assert_eq!(cfg.max_loop_unrolling, 3);
        assert_eq!(cfg.max_states, 10_000);
    }

    // ---- WorklistEntry::fork_to tests ----

    #[test]
    fn test_worklist_entry_fork_to_changes_current_block() {
        // fork_to(target) must set the forked state's current_block to target.
        let entry = make_entry(0);
        let forked = entry.fork_to(99);
        assert_eq!(
            forked.state.current_block, 99,
            "fork_to should set current_block to the target block id"
        );
    }

    #[test]
    fn test_worklist_entry_fork_to_sets_predecessor() {
        // fork_to records the original block as the predecessor for phi resolution.
        // The original entry's current_block is 5; the fork's predecessor should be Some(5).
        let entry = make_entry(5);
        let forked = entry.fork_to(10);
        assert_eq!(
            forked.predecessor_block,
            Some(5),
            "fork_to should set predecessor_block to the original current_block"
        );
    }

    #[test]
    fn test_worklist_entry_fork_to_preserves_loop_counts() {
        // Loop counts accumulated on the original entry must be carried over
        // to the fork so the engine correctly enforces loop unrolling bounds.
        let mut entry = make_entry(0);
        entry.loop_counts.insert(42, 2);
        entry.loop_counts.insert(7, 1);

        let forked = entry.fork_to(99);
        assert_eq!(
            forked.loop_counts.get(&42).copied(),
            Some(2),
            "fork_to should preserve loop count for header 42"
        );
        assert_eq!(
            forked.loop_counts.get(&7).copied(),
            Some(1),
            "fork_to should preserve loop count for header 7"
        );
    }
}
