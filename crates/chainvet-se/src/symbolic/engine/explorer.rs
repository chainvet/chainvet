use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, VecDeque};

use chainvet_core::cfg::CfgFunction;
use chainvet_core::ir::{ControlKind, IrInstr, IrValue, IrVar, PlaceClass};

use super::scheduler::WorklistEntry;

/// Worklist ordering strategy.
///
/// Owns the worklist data structure. The engine pushes and pops
/// `WorklistEntry` values through this interface, decoupled from the
/// concrete ordering chosen at configuration time.
pub trait ExplorationStrategy {
    /// Push a new state onto the worklist.
    fn push(&mut self, entry: WorklistEntry);

    /// Pop the next state to explore. Returns `None` when the worklist is empty.
    fn pop(&mut self) -> Option<WorklistEntry>;

    /// Whether the worklist is empty.
    #[allow(dead_code)] // Phase 6: used by priority/targeted scheduling strategies
    fn is_empty(&self) -> bool;

    /// Number of entries currently in the worklist.
    #[allow(dead_code)] // Phase 6: used by coverage-guided scheduling for budget tracking
    fn len(&self) -> usize;
}

/// Depth-first exploration: last-in, first-out (Vec stack).
///
/// Explores one path as deep as possible before backtracking.
/// Memory-efficient for deep paths; finds deep bugs quickly.
pub struct DfsStrategy {
    stack: Vec<WorklistEntry>,
}

impl DfsStrategy {
    pub fn new() -> Self {
        Self { stack: Vec::new() }
    }
}

impl Default for DfsStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl ExplorationStrategy for DfsStrategy {
    fn push(&mut self, entry: WorklistEntry) {
        self.stack.push(entry);
    }

    fn pop(&mut self) -> Option<WorklistEntry> {
        self.stack.pop()
    }

    fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    fn len(&self) -> usize {
        self.stack.len()
    }
}

/// Breadth-first exploration: first-in, first-out (VecDeque queue).
///
/// Explores all paths at depth N before moving to depth N+1.
/// Better coverage uniformity; higher memory usage for wide programs.
pub struct BfsStrategy {
    queue: VecDeque<WorklistEntry>,
}

impl BfsStrategy {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }
}

impl Default for BfsStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl ExplorationStrategy for BfsStrategy {
    fn push(&mut self, entry: WorklistEntry) {
        self.queue.push_back(entry);
    }

    fn pop(&mut self) -> Option<WorklistEntry> {
        self.queue.pop_front()
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn len(&self) -> usize {
        self.queue.len()
    }
}

/// Vulnerability-directed exploration: max-heap by block sink score.
///
/// Pre-computes a static "danger score" per CFG block based on the
/// instructions it contains (storage writes, external calls, selfdestruct).
/// Higher-scoring blocks are explored first, focusing the budget on
/// vulnerability-relevant paths.
pub struct VulnerabilityDirectedStrategy {
    heap: BinaryHeap<ScoredEntry>,
    sink_scores: HashMap<u32, i32>,
    insertion_counter: u64,
}

struct ScoredEntry {
    priority: i32,
    insertion_order: u64,
    entry: WorklistEntry,
}

impl Eq for ScoredEntry {}

impl PartialEq for ScoredEntry {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.insertion_order == other.insertion_order
    }
}

impl Ord for ScoredEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first; among ties, earlier insertion wins (lower counter).
        self.priority
            .cmp(&other.priority)
            .then_with(|| other.insertion_order.cmp(&self.insertion_order))
    }
}

impl PartialOrd for ScoredEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl VulnerabilityDirectedStrategy {
    pub fn new(cfgs: &[CfgFunction]) -> Self {
        Self {
            heap: BinaryHeap::new(),
            sink_scores: build_sink_scores(cfgs),
            insertion_counter: 0,
        }
    }

    fn score_for(&self, func_id: u32, block_id: u32) -> i32 {
        let key = sink_score_key(func_id, block_id);
        *self.sink_scores.get(&key).unwrap_or(&0)
    }
}

impl ExplorationStrategy for VulnerabilityDirectedStrategy {
    fn push(&mut self, entry: WorklistEntry) {
        let mut priority = self.score_for(entry.cfg_func_id, entry.state.current_block);

        // Dynamic bonuses based on runtime state properties.
        // Boost states that are "closer" to vulnerability patterns.
        if !entry.state.sender_checked {
            // Unguarded paths are more likely to contain access control vulns.
            priority += 2;
        }
        if entry.state.inside_loop {
            // Loop bodies are DoS-relevant and can multiply reentrancy impact.
            priority += 1;
        }
        if !entry.state.storage_reads.is_empty() {
            // Paths that read storage are more interesting for state-dependent vulns.
            priority += 1;
        }
        if entry.state.callback_frame.is_some() {
            // Callback simulation paths deserve higher priority — they're
            // specifically exploring reentrancy scenarios.
            priority += 3;
        }
        if !entry.state.pending_calls.is_empty() {
            // Unchecked call returns still pending — interesting for detection.
            priority += 2;
        }

        let insertion_order = self.insertion_counter;
        self.insertion_counter += 1;
        self.heap.push(ScoredEntry {
            priority,
            insertion_order,
            entry,
        });
    }

    fn pop(&mut self) -> Option<WorklistEntry> {
        self.heap.pop().map(|se| se.entry)
    }

    fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    fn len(&self) -> usize {
        self.heap.len()
    }
}

/// Compute a sink score key from function and block IDs.
fn sink_score_key(func_id: u32, block_id: u32) -> u32 {
    (func_id << 16) ^ block_id
}

/// Pre-compute static sink scores for all CFG blocks.
///
/// Blocks containing dangerous instructions (storage writes, external calls,
/// selfdestruct) receive higher scores.
pub fn build_sink_scores(cfgs: &[CfgFunction]) -> HashMap<u32, i32> {
    let mut scores = HashMap::new();
    for cfg_fn in cfgs {
        for block in &cfg_fn.blocks {
            let mut score = 0i32;
            for instr in &block.instrs {
                match instr {
                    IrInstr::Store { dest, .. } if place_is_storage(dest) => {
                        score += 4;
                    }
                    IrInstr::Call { callee, .. } => {
                        let name = callee_name_lower(callee);
                        if is_low_level_name(&name) {
                            score += 5;
                        }
                        if name.contains("delegatecall") {
                            score += 3;
                        }
                        if name == "selfdestruct" || name == "suicide" {
                            score += 4;
                        }
                        if name.contains("ecrecover") {
                            score += 2;
                        }
                    }
                    IrInstr::Control {
                        kind: ControlKind::If { .. } | ControlKind::Loop { .. },
                        ..
                    } => {
                        score += 1;
                    }
                    _ => {}
                }
            }
            if score > 0 {
                scores.insert(sink_score_key(cfg_fn.id, block.id), score);
            }
        }
    }
    scores
}

fn place_is_storage(place: &chainvet_core::ir::IrPlace) -> bool {
    match place {
        chainvet_core::ir::IrPlace::Var { class, .. }
        | chainvet_core::ir::IrPlace::Member { class, .. }
        | chainvet_core::ir::IrPlace::Index { class, .. } => *class == PlaceClass::Storage,
    }
}

fn callee_name_lower(callee: &IrValue) -> String {
    match callee {
        IrValue::Var(IrVar::Named(s)) => s.to_ascii_lowercase(),
        IrValue::Literal(lit) => lit.value.to_ascii_lowercase(),
        _ => String::new(),
    }
}

fn is_low_level_name(name: &str) -> bool {
    matches!(
        name,
        "call" | "send" | "transfer" | "delegatecall" | "staticcall"
    ) || name.ends_with(".call")
        || name.ends_with(".send")
        || name.ends_with(".transfer")
        || name.ends_with(".delegatecall")
        || name.ends_with(".staticcall")
}

/// Which exploration order to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplorationStrategyKind {
    #[allow(dead_code)]
    Dfs,
    #[allow(dead_code)]
    Bfs,
    VulnerabilityDirected,
}

/// Construct the chosen strategy as a boxed trait object.
///
/// `cfgs` is required for `VulnerabilityDirected` (pre-computes sink scores).
pub fn make_strategy(
    kind: ExplorationStrategyKind,
    cfgs: &[CfgFunction],
) -> Box<dyn ExplorationStrategy> {
    match kind {
        ExplorationStrategyKind::Dfs => Box::new(DfsStrategy::new()),
        ExplorationStrategyKind::Bfs => Box::new(BfsStrategy::new()),
        ExplorationStrategyKind::VulnerabilityDirected => {
            Box::new(VulnerabilityDirectedStrategy::new(cfgs))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbolic::engine::scheduler::WorklistEntry;
    use crate::symbolic::state::call_context::CallContext;
    use crate::symbolic::state::{StateIdGen, SymbolicState};
    use chainvet_core::cfg::BlockId;
    use std::collections::HashMap;

    /// Build a minimal WorklistEntry at the given block_id.
    /// Each call creates a fresh Z3 context via CallContext::new_symbolic(),
    /// so entries are independent and can be pushed individually.
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

    // ---- DfsStrategy tests ----

    #[test]
    fn test_dfs_empty_is_empty() {
        // A new DfsStrategy must start empty before any pushes.
        let dfs = DfsStrategy::new();
        assert!(dfs.is_empty());
        assert_eq!(dfs.len(), 0);
    }

    #[test]
    fn test_dfs_is_lifo() {
        // DFS uses a stack: entries come back in last-in, first-out order.
        // Push entries associated with block ids 10, 20, 30.
        // Expected pop order: 30, 20, 10.
        let mut dfs = DfsStrategy::new();
        dfs.push(make_entry(10));
        dfs.push(make_entry(20));
        dfs.push(make_entry(30));

        let first = dfs.pop().unwrap();
        let second = dfs.pop().unwrap();
        let third = dfs.pop().unwrap();

        assert_eq!(
            first.state.current_block, 30,
            "DFS: first pop should be last pushed"
        );
        assert_eq!(second.state.current_block, 20);
        assert_eq!(
            third.state.current_block, 10,
            "DFS: last pop should be first pushed"
        );
    }

    #[test]
    fn test_dfs_len_tracks_pushes_and_pops() {
        // len() must increase by 1 per push and decrease by 1 per pop.
        let mut dfs = DfsStrategy::new();
        assert_eq!(dfs.len(), 0);

        dfs.push(make_entry(1));
        assert_eq!(dfs.len(), 1);

        dfs.push(make_entry(2));
        assert_eq!(dfs.len(), 2);

        dfs.pop();
        assert_eq!(dfs.len(), 1);

        dfs.pop();
        assert_eq!(dfs.len(), 0);
        assert!(dfs.is_empty());
    }

    // ---- BfsStrategy tests ----

    #[test]
    fn test_bfs_empty_is_empty() {
        // A new BfsStrategy must start empty before any pushes.
        let bfs = BfsStrategy::new();
        assert!(bfs.is_empty());
        assert_eq!(bfs.len(), 0);
    }

    #[test]
    fn test_bfs_is_fifo() {
        // BFS uses a queue: entries come back in first-in, first-out order.
        // Push entries associated with block ids 10, 20, 30.
        // Expected pop order: 10, 20, 30.
        let mut bfs = BfsStrategy::new();
        bfs.push(make_entry(10));
        bfs.push(make_entry(20));
        bfs.push(make_entry(30));

        let first = bfs.pop().unwrap();
        let second = bfs.pop().unwrap();
        let third = bfs.pop().unwrap();

        assert_eq!(
            first.state.current_block, 10,
            "BFS: first pop should be first pushed"
        );
        assert_eq!(second.state.current_block, 20);
        assert_eq!(
            third.state.current_block, 30,
            "BFS: last pop should be last pushed"
        );
    }

    // ---- make_strategy tests ----

    #[test]
    fn test_make_strategy_dfs() {
        // make_strategy(Dfs) must produce LIFO behavior.
        let mut strategy = make_strategy(ExplorationStrategyKind::Dfs, &[]);
        strategy.push(make_entry(1));
        strategy.push(make_entry(2));

        // LIFO: second entry should come out first.
        let out = strategy.pop().unwrap();
        assert_eq!(
            out.state.current_block, 2,
            "make_strategy(Dfs) should be LIFO"
        );
    }

    #[test]
    fn test_make_strategy_bfs() {
        // make_strategy(Bfs) must produce FIFO behavior.
        let mut strategy = make_strategy(ExplorationStrategyKind::Bfs, &[]);
        strategy.push(make_entry(1));
        strategy.push(make_entry(2));

        // FIFO: first entry should come out first.
        let out = strategy.pop().unwrap();
        assert_eq!(
            out.state.current_block, 1,
            "make_strategy(Bfs) should be FIFO"
        );
    }
}
