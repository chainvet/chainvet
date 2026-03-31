use std::collections::VecDeque;

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
    fn is_empty(&self) -> bool;

    /// Number of entries currently in the worklist.
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

/// Which exploration order to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplorationStrategyKind {
    Dfs,
    Bfs,
}

/// Construct the chosen strategy as a boxed trait object.
pub fn make_strategy(kind: ExplorationStrategyKind) -> Box<dyn ExplorationStrategy> {
    match kind {
        ExplorationStrategyKind::Dfs => Box::new(DfsStrategy::new()),
        ExplorationStrategyKind::Bfs => Box::new(BfsStrategy::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::cfg::BlockId;
    use crate::symbolic::state::{StateIdGen, SymbolicState};
    use crate::symbolic::state::call_context::CallContext;
    use crate::symbolic::engine::scheduler::WorklistEntry;

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

        assert_eq!(first.state.current_block, 30, "DFS: first pop should be last pushed");
        assert_eq!(second.state.current_block, 20);
        assert_eq!(third.state.current_block, 10, "DFS: last pop should be first pushed");
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

        assert_eq!(first.state.current_block, 10, "BFS: first pop should be first pushed");
        assert_eq!(second.state.current_block, 20);
        assert_eq!(third.state.current_block, 30, "BFS: last pop should be last pushed");
    }

    // ---- make_strategy tests ----

    #[test]
    fn test_make_strategy_dfs() {
        // make_strategy(Dfs) must produce LIFO behavior.
        let mut strategy = make_strategy(ExplorationStrategyKind::Dfs);
        strategy.push(make_entry(1));
        strategy.push(make_entry(2));

        // LIFO: second entry should come out first.
        let out = strategy.pop().unwrap();
        assert_eq!(out.state.current_block, 2, "make_strategy(Dfs) should be LIFO");
    }

    #[test]
    fn test_make_strategy_bfs() {
        // make_strategy(Bfs) must produce FIFO behavior.
        let mut strategy = make_strategy(ExplorationStrategyKind::Bfs);
        strategy.push(make_entry(1));
        strategy.push(make_entry(2));

        // FIFO: first entry should come out first.
        let out = strategy.pop().unwrap();
        assert_eq!(out.state.current_block, 1, "make_strategy(Bfs) should be FIFO");
    }
}
