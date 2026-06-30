use std::collections::HashSet;

use serde::Serialize;

use chainvet_core::cfg::BlockId;
use chainvet_core::ir::IrFunctionId;

/// Mutable coverage accumulator passed to the engine during execution.
///
/// The engine calls `record_block` / `record_edge` / `record_function`
/// as side effects during exploration. The tracker never influences
/// worklist ordering — it is purely an output accumulator.
pub struct CoverageTracker {
    visited_blocks: HashSet<(IrFunctionId, BlockId)>,
    visited_edges: HashSet<(BlockId, BlockId)>,
    visited_functions: HashSet<IrFunctionId>,
    total_blocks: usize,
    total_functions: usize,
}

impl CoverageTracker {
    /// Create a new tracker with the given totals from the CFG/IR module.
    pub fn new(total_blocks: usize, total_functions: usize) -> Self {
        Self {
            visited_blocks: HashSet::new(),
            visited_edges: HashSet::new(),
            visited_functions: HashSet::new(),
            total_blocks,
            total_functions,
        }
    }

    /// Record that a block was visited during execution.
    pub fn record_block(&mut self, func_id: IrFunctionId, block_id: BlockId) {
        self.visited_blocks.insert((func_id, block_id));
    }

    /// Record that an edge was traversed during execution.
    pub fn record_edge(&mut self, from: BlockId, to: BlockId) {
        self.visited_edges.insert((from, to));
    }

    /// Record that a function was entered during execution.
    pub fn record_function(&mut self, func_id: IrFunctionId) {
        self.visited_functions.insert(func_id);
    }

    /// Produce an immutable coverage snapshot for reporting.
    pub fn report(&self) -> CoverageReport {
        let blocks_visited = self.visited_blocks.len();
        let functions_visited = self.visited_functions.len();

        let block_coverage_pct = if self.total_blocks > 0 {
            (blocks_visited as f64 / self.total_blocks as f64) * 100.0
        } else {
            0.0
        };

        let function_coverage_pct = if self.total_functions > 0 {
            (functions_visited as f64 / self.total_functions as f64) * 100.0
        } else {
            0.0
        };

        // Compute uncovered blocks by diffing against visited set.
        // Note: we don't have a full list of all (func, block) pairs here,
        // so uncovered_blocks is left empty — the engine should populate
        // total block info at a higher level if needed.
        CoverageReport {
            blocks_visited,
            blocks_total: self.total_blocks,
            block_coverage_pct,
            edges_visited: self.visited_edges.len(),
            functions_visited,
            functions_total: self.total_functions,
            function_coverage_pct,
        }
    }
}

/// Immutable coverage snapshot for reporting.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CoverageReport {
    pub blocks_visited: usize,
    pub blocks_total: usize,
    pub block_coverage_pct: f64,
    pub edges_visited: usize,
    pub functions_visited: usize,
    pub functions_total: usize,
    pub function_coverage_pct: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coverage_tracker_starts_empty() {
        // A newly created tracker should have zero visited blocks, edges, and functions.
        let tracker = CoverageTracker::new(10, 5);
        let report = tracker.report();
        assert_eq!(report.blocks_visited, 0);
        assert_eq!(report.edges_visited, 0);
        assert_eq!(report.functions_visited, 0);
    }

    #[test]
    fn test_record_block_increments_count() {
        // Recording 3 distinct (func_id, block_id) pairs should yield blocks_visited == 3.
        let mut tracker = CoverageTracker::new(10, 5);
        tracker.record_block(0, 1);
        tracker.record_block(0, 2);
        tracker.record_block(1, 1);
        assert_eq!(tracker.report().blocks_visited, 3);
    }

    #[test]
    fn test_record_block_deduplicates() {
        // Recording the same (func_id, block_id) pair twice should still count as 1.
        let mut tracker = CoverageTracker::new(10, 5);
        tracker.record_block(0, 1);
        tracker.record_block(0, 1);
        assert_eq!(tracker.report().blocks_visited, 1);
    }

    #[test]
    fn test_record_edge_increments_count() {
        // Recording distinct edges should increment edges_visited.
        let mut tracker = CoverageTracker::new(10, 5);
        tracker.record_edge(0, 1);
        tracker.record_edge(1, 2);
        tracker.record_edge(2, 3);
        assert_eq!(tracker.report().edges_visited, 3);
    }

    #[test]
    fn test_record_edge_deduplicates() {
        // Recording the same edge twice should still count as 1.
        let mut tracker = CoverageTracker::new(10, 5);
        tracker.record_edge(0, 1);
        tracker.record_edge(0, 1);
        assert_eq!(tracker.report().edges_visited, 1);
    }

    #[test]
    fn test_record_function_increments_count() {
        // Recording distinct function IDs should increment functions_visited.
        let mut tracker = CoverageTracker::new(10, 5);
        tracker.record_function(0);
        tracker.record_function(1);
        tracker.record_function(2);
        assert_eq!(tracker.report().functions_visited, 3);
    }

    #[test]
    fn test_report_50pct_block_coverage() {
        // With total_blocks=4 and 2 blocks visited, block_coverage_pct should be 50.0.
        let mut tracker = CoverageTracker::new(4, 4);
        tracker.record_block(0, 0);
        tracker.record_block(0, 1);
        let report = tracker.report();
        assert_eq!(report.blocks_visited, 2);
        assert_eq!(report.blocks_total, 4);
        assert!((report.block_coverage_pct - 50.0).abs() < 1e-9);
    }

    #[test]
    fn test_report_100pct_coverage() {
        // Recording all blocks and functions should yield 100.0 pct for each.
        let mut tracker = CoverageTracker::new(2, 2);
        tracker.record_block(0, 0);
        tracker.record_block(1, 0);
        tracker.record_function(0);
        tracker.record_function(1);
        let report = tracker.report();
        assert!((report.block_coverage_pct - 100.0).abs() < 1e-9);
        assert!((report.function_coverage_pct - 100.0).abs() < 1e-9);
    }

    #[test]
    fn test_report_zero_total_blocks_no_div_by_zero() {
        // When total_blocks == 0, block_coverage_pct must be 0.0, not a division panic.
        let tracker = CoverageTracker::new(0, 1);
        let report = tracker.report();
        assert_eq!(report.block_coverage_pct, 0.0);
    }

    #[test]
    fn test_report_zero_total_functions_no_div_by_zero() {
        // When total_functions == 0, function_coverage_pct must be 0.0, not a division panic.
        let tracker = CoverageTracker::new(1, 0);
        let report = tracker.report();
        assert_eq!(report.function_coverage_pct, 0.0);
    }
}
