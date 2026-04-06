pub mod executor;
pub mod explorer;
pub mod scheduler;

use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::Instant;

use z3::ast::Bool;
use z3::SatResult;

use crate::cfg::{BlockId, CfgFunction};
use crate::norm::NormalizedAst;
use crate::symbolic::detectors::DetectorRegistry;
use crate::symbolic::results::coverage::{CoverageReport, CoverageTracker};
use crate::symbolic::results::SeFinding;
use crate::symbolic::solver::SmtSolver;
use crate::symbolic::state::call_context::CallContext;
use crate::symbolic::state::storage::StorageLayout;
use crate::symbolic::state::{StateIdGen, SymbolicState};
use crate::symbolic::types::hash::KeccakContext;

use executor::{BlockOutcome, ExecutorError, execute_block, flush_pending_calls, pre_populate_call_context};
use explorer::{ExplorationStrategy, make_strategy};
use scheduler::{SeConfig, WorklistEntry};

/// Output produced by the engine for one analysis run.
pub struct EngineResult {
    pub findings: Vec<SeFinding>,
    pub coverage: CoverageReport,
    pub states_explored: usize,
}

/// Cache for solver feasibility probes.
///
/// Uses Z3 structural hashing of Bool AST nodes to fingerprint constraint sets.
/// Avoids redundant SAT queries when the same constraint combination is probed
/// multiple times (common with loop unrolling and diamond-shaped CFGs).
struct SolverCache {
    cache: RefCell<HashMap<u64, bool>>,
}

impl SolverCache {
    fn new() -> Self {
        Self {
            cache: RefCell::new(HashMap::new()),
        }
    }

    /// Compute a fingerprint for a set of Bool assumptions.
    fn fingerprint(assumptions: &[Bool]) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        assumptions.len().hash(&mut hasher);
        for a in assumptions {
            a.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Probe with caching: returns cached result or queries the solver.
    fn probe(&self, solver: &dyn SmtSolver, base: &[Bool], extra: &Bool) -> bool {
        let mut assumptions = base.to_vec();
        assumptions.push(extra.clone());
        let key = Self::fingerprint(&assumptions);

        if let Some(&result) = self.cache.borrow().get(&key) {
            return result;
        }

        let result = solver.check_sat_assuming(&assumptions) == SatResult::Sat;
        self.cache.borrow_mut().insert(key, result);
        result
    }
}

/// Shared immutable parameters threaded through the exploration loop.
struct RunContext<'a> {
    solver: &'a dyn SmtSolver,
    layout: &'a StorageLayout,
    contract_name: &'a str,
    #[allow(dead_code)] // Used by callback simulation (Item 1), arithmetic (Item 3), authority profiling (Item 5)
    ast: &'a NormalizedAst,
    #[allow(dead_code)] // Used by callback simulation (Item 1) for cross-function CFG lookup
    all_cfgs: &'a [CfgFunction],
    solver_cache: SolverCache,
    max_path_depth: u32,
    max_instructions: u32,
    max_loop_unrolling: u32,
    max_states: usize,
    total_timeout_s: u64,
    start_time: Instant,
}

/// Mutable outputs accumulated across all worklist entries.
struct RunAccumulators<'a> {
    coverage: &'a mut CoverageTracker,
    findings: &'a mut Vec<SeFinding>,
    keccak_ctx: &'a mut KeccakContext,
    states_explored: &'a mut usize,
}

/// Context passed to branch-fork helpers.
///
/// Groups the source block, coverage tracker, and worklist strategy so
/// that fork helpers stay within the seven-argument convention.
struct ForkSink<'a> {
    from_block: BlockId,
    coverage: &'a mut CoverageTracker,
    strategy: &'a mut dyn ExplorationStrategy,
}

/// Run symbolic execution over all CFG functions.
///
/// Exploration is driven by a configurable worklist strategy (DFS or BFS).
/// Each state is an independent snapshot of one execution path. The engine
/// forks states at conditional branches, applies path constraints, and
/// queries the solver for feasibility before exploring each fork.
pub fn run_engine(
    cfgs: &[CfgFunction],
    ast: &NormalizedAst,
    config: SeConfig,
    solver: &dyn SmtSolver,
) -> EngineResult {
    use std::collections::HashSet;

    let total_blocks: usize = cfgs.iter().map(|f| f.blocks.len()).sum();
    let mut coverage = CoverageTracker::new(total_blocks, cfgs.len());
    let mut findings: Vec<SeFinding> = Vec::new();
    let mut id_gen = StateIdGen::new();
    let mut keccak_ctx = KeccakContext::new();
    let mut states_explored: usize = 0;

    let SeConfig {
        max_path_depth, max_instructions, max_loop_unrolling,
        max_states, solver_timeout_ms: _, total_timeout_s,
        dynamic_bytes_bound: _, exploration_strategy,
        mut detectors, storage_layout, contract_name,
    } = config;

    let run_ctx = RunContext {
        solver,
        layout: &storage_layout,
        contract_name: &contract_name,
        ast,
        all_cfgs: cfgs,
        solver_cache: SolverCache::new(),
        max_path_depth, max_instructions, max_loop_unrolling,
        max_states, total_timeout_s, start_time: Instant::now(),
    };

    for cfg_func in cfgs {
        if cfg_func.blocks.is_empty() {
            continue;
        }
        detectors.reset_all();
        let mut acc = RunAccumulators {
            coverage: &mut coverage,
            findings: &mut findings,
            keccak_ctx: &mut keccak_ctx,
            states_explored: &mut states_explored,
        };
        explore_function(cfg_func, cfgs, &mut detectors, &mut id_gen, &mut acc, &run_ctx, exploration_strategy);
    }

    // Global dedup: keep first (highest-confidence) finding per (function, kind, span).
    let default_span = crate::norm::Span::default();
    let mut seen: HashSet<(u32, crate::symbolic::results::finding::SeVulnKind, crate::norm::Span)> = HashSet::new();
    findings.retain(|f| {
        // Don't dedup findings with fallback/zero spans — they'd all collide.
        if f.span == default_span {
            return true;
        }
        seen.insert((f.function_id.unwrap_or(0), f.kind, f.span))
    });

    EngineResult { findings, coverage: coverage.report(), states_explored }
}

/// Symbolically explore one CFG function to completion.
///
/// Creates the initial symbolic state, binds blockchain context names,
/// seeds the worklist, then drives the exploration loop.
fn explore_function(
    cfg_func: &CfgFunction,
    all_cfgs: &[CfgFunction],
    detectors: &mut DetectorRegistry,
    id_gen: &mut StateIdGen,
    acc: &mut RunAccumulators<'_>,
    run_ctx: &RunContext<'_>,
    exploration_strategy: explorer::ExplorationStrategyKind,
) {
    acc.coverage.record_function(cfg_func.id);
    let entry_block = cfg_func.blocks[0].id;
    let (call_ctx, init_constraints) = CallContext::new_symbolic();
    let mut initial_state = SymbolicState::initial(id_gen, entry_block, call_ctx);
    for (c, desc) in init_constraints {
        initial_state.path_constraints.add(c, desc);
    }
    pre_populate_call_context(&mut initial_state);
    let mut strategy = make_strategy(exploration_strategy, all_cfgs);
    strategy.push(WorklistEntry {
        state: initial_state,
        cfg_func_id: cfg_func.id,
        predecessor_block: None,
        loop_counts: std::collections::HashMap::new(),
    });
    let findings_start = acc.findings.len();
    run_worklist(&mut *strategy, cfg_func, all_cfgs, detectors, acc, run_ctx);
    // Stamp function_id on all findings emitted during this function's exploration.
    for f in acc.findings[findings_start..].iter_mut() {
        if f.function_id.is_none() {
            f.function_id = Some(cfg_func.id);
        }
    }
}

/// Drive the worklist for one function until it is empty or a limit is hit.
fn run_worklist(
    strategy: &mut dyn ExplorationStrategy,
    cfg_func: &CfgFunction,
    all_cfgs: &[CfgFunction],
    detectors: &mut DetectorRegistry,
    acc: &mut RunAccumulators<'_>,
    run_ctx: &RunContext<'_>,
) {
    while let Some(mut entry) = strategy.pop() {
        if run_ctx.total_timeout_s > 0
            && run_ctx.start_time.elapsed().as_secs() >= run_ctx.total_timeout_s
        {
            break;
        }
        if *acc.states_explored >= run_ctx.max_states { break; }
        if entry.state.path_depth >= run_ctx.max_path_depth { continue; }
        if entry.state.instruction_count >= run_ctx.max_instructions { continue; }

        *acc.states_explored += 1;

        // Look up the CFG for this entry's function (supports cross-function callbacks).
        let current_cfg = all_cfgs
            .iter()
            .find(|c| c.id == entry.cfg_func_id)
            .unwrap_or(cfg_func);
        acc.coverage.record_block(current_cfg.id, entry.state.current_block);

        let block = match current_cfg.blocks.iter().find(|b| b.id == entry.state.current_block) {
            Some(b) => b,
            None => continue,
        };

        let outcome = match execute_block(
            &mut entry.state, block, current_cfg, detectors,
            run_ctx.solver, acc.keccak_ctx, run_ctx.layout, run_ctx.contract_name, acc.findings,
        ) {
            Ok(o) => o,
            Err(ExecutorError::UnsupportedInstruction(msg)) => {
                eprintln!("[se] warning: {msg}");
                continue;
            }
            Err(e) => {
                eprintln!("[se] executor error: {e}");
                continue;
            }
        };

        // Flush unchecked low-level calls at terminal blocks.
        if matches!(outcome, BlockOutcome::Return { .. } | BlockOutcome::Revert { .. } | BlockOutcome::Stop) {
            let fallback_span = crate::norm::Span { file: 0, start: 0, end: 0 };
            flush_pending_calls(&mut entry.state, acc.findings, fallback_span);
        }

        // Callback simulation: if an external call was seen and we're not already
        // in a callback, fork a state that re-enters the function from the top
        // (simulating a re-entrant call into the fallback).
        if let Some(call_span) = entry.state.last_external_call_span.take() {
            let cb_depth = entry.state.callback_frame.as_ref().map_or(0, |f| f.depth);
            if cb_depth < 1 {
                let mut cb_state = entry.state.clone();
                cb_state.callback_frame = Some(crate::symbolic::state::CallbackFrame {
                    pre_call_storage: entry.state.storage.clone(),
                    call_span,
                    depth: cb_depth + 1,
                });
                cb_state.current_block = current_cfg.blocks[0].id;
                cb_state.path_depth += 1;
                strategy.push(WorklistEntry {
                    state: cb_state,
                    cfg_func_id: current_cfg.id,
                    predecessor_block: None,
                    loop_counts: std::collections::HashMap::new(),
                });
            }
        }

        let mut sink = ForkSink {
            from_block: block.id,
            coverage: &mut *acc.coverage,
            strategy: &mut *strategy,
        };
        dispatch_outcome(entry, outcome, run_ctx, &mut sink);
    }
}

/// Dispatch a `BlockOutcome` — push successor states onto the worklist.
fn dispatch_outcome(
    entry: WorklistEntry,
    outcome: BlockOutcome,
    run_ctx: &RunContext<'_>,
    sink: &mut ForkSink<'_>,
) {
    match outcome {
        BlockOutcome::Fallthrough { target } => {
            sink.coverage.record_edge(sink.from_block, target);
            let mut next = entry.fork_to(target);
            next.state.path_depth += 1;
            sink.strategy.push(next);
        }
        BlockOutcome::Branch { cond, true_block, false_block } => {
            handle_branch(&entry, cond, true_block, false_block, run_ctx, sink);
        }
        BlockOutcome::LoopHeader { cond, body_block, exit_block } => {
            handle_loop_header(
                entry, cond, body_block, exit_block,
                run_ctx, sink,
            );
        }
        BlockOutcome::Return { .. } | BlockOutcome::Revert { .. } | BlockOutcome::Stop => {}
    }
}

/// Probe both branch directions and push feasible forks.
fn handle_branch(
    entry: &WorklistEntry,
    cond: Bool,
    true_block: BlockId,
    false_block: BlockId,
    run_ctx: &RunContext<'_>,
    sink: &mut ForkSink<'_>,
) {
    let base = collect_base_constraints(&entry.state);
    if run_ctx.solver_cache.probe(run_ctx.solver, &base, &cond) {
        sink.coverage.record_edge(sink.from_block, true_block);
        let mut fork = entry.fork_to(true_block);
        fork.state.path_constraints.add(
            cond.clone(),
            format!("branch true → block {true_block}"),
        );
        fork.state.path_depth += 1;
        sink.strategy.push(fork);
    }
    if run_ctx.solver_cache.probe(run_ctx.solver, &base, &cond.not()) {
        sink.coverage.record_edge(sink.from_block, false_block);
        let mut fork = entry.fork_to(false_block);
        fork.state.path_constraints.add(
            cond.not(),
            format!("branch false → block {false_block}"),
        );
        fork.state.path_depth += 1;
        sink.strategy.push(fork);
    }
}

/// Enforce the loop unrolling bound and push the appropriate fork(s).
fn handle_loop_header(
    entry: WorklistEntry,
    cond: Option<Bool>,
    body_block: BlockId,
    exit_block: Option<BlockId>,
    run_ctx: &RunContext<'_>,
    sink: &mut ForkSink<'_>,
) {
    let loop_count = entry.loop_counts.get(&body_block).copied().unwrap_or(0);
    let base = collect_base_constraints(&entry.state);
    if loop_count >= run_ctx.max_loop_unrolling {
        push_loop_exit_fork(entry, &cond, exit_block, run_ctx, &base, sink);
    } else {
        push_loop_forks(entry, cond, body_block, exit_block, run_ctx, &base, sink);
    }
}

/// Push the exit fork when the loop unrolling bound has been reached.
fn push_loop_exit_fork(
    entry: WorklistEntry,
    cond: &Option<Bool>,
    exit_block: Option<BlockId>,
    run_ctx: &RunContext<'_>,
    base: &[Bool],
    sink: &mut ForkSink<'_>,
) {
    if let Some(exit) = exit_block {
        let exit_cond = cond.as_ref().map(|c| c.not());
        let feasible = match &exit_cond {
            Some(ec) => run_ctx.solver_cache.probe(run_ctx.solver, base, ec),
            None => true,
        };
        if feasible {
            sink.coverage.record_edge(sink.from_block, exit);
            let mut fork = entry.fork_to(exit);
            if let Some(ec) = exit_cond {
                fork.state.path_constraints.add(ec, format!("loop exit → block {exit}"));
            }
            fork.state.path_depth += 1;
            sink.strategy.push(fork);
        }
    }
}

/// Push body and exit forks when the loop is still within its unrolling bound.
fn push_loop_forks(
    entry: WorklistEntry,
    cond: Option<Bool>,
    body_block: BlockId,
    exit_block: Option<BlockId>,
    run_ctx: &RunContext<'_>,
    base: &[Bool],
    sink: &mut ForkSink<'_>,
) {
    let body_feasible = match &cond {
        Some(c) => run_ctx.solver_cache.probe(run_ctx.solver, base, c),
        None => true,
    };
    if body_feasible {
        sink.coverage.record_edge(sink.from_block, body_block);
        let mut fork = entry.fork_to(body_block);
        if let Some(c) = cond.clone() {
            fork.state.path_constraints.add(c, format!("loop body → block {body_block}"));
        }
        *fork.loop_counts.entry(body_block).or_insert(0) += 1;
        fork.state.path_depth += 1;
        fork.state.inside_loop = true;
        sink.strategy.push(fork);
    }
    if let Some(exit) = exit_block {
        let exit_feasible = match &cond {
            Some(c) => run_ctx.solver_cache.probe(run_ctx.solver, base, &c.not()),
            None => false,
        };
        if exit_feasible {
            sink.coverage.record_edge(sink.from_block, exit);
            let mut fork = entry.fork_to(exit);
            if let Some(c) = cond {
                fork.state.path_constraints.add(c.not(), format!("loop exit → block {exit}"));
            }
            fork.state.path_depth += 1;
            fork.state.inside_loop = false;
            sink.strategy.push(fork);
        }
    }
}

/// Collect current path constraints as a flat `Vec<Bool>` for SAT assumptions.
fn collect_base_constraints(state: &SymbolicState) -> Vec<Bool> {
    state.path_constraints.constraints().iter().map(|(c, _)| c.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{Block, CfgFunction, Edge};
    use crate::ir::{ControlKind, IrBlock, IrFunction, IrInstr, IrModule, IrValue, IrVar};
    use crate::norm::{NormalizedAst, Span};
    use crate::symbolic::solver::z3_backend::Z3Backend;
    use scheduler::SeConfig;

    fn span() -> Span {
        Span { file: 0, start: 0, end: 0 }
    }

    /// Build a CfgFunction from a flat list of IR instructions using the real CFG builder.
    fn cfg_from_instrs(instrs: Vec<IrInstr>) -> CfgFunction {
        let s = span();
        let module = IrModule {
            functions: vec![IrFunction {
                id: 0,
                name: None,
                source: None,
                span: s,
                blocks: vec![IrBlock { id: 0, instrs }],
            }],
        };
        let mut cfgs = crate::cfg::build_from_ir(&module);
        cfgs.remove(0)
    }

    /// Return a minimal NormalizedAst (empty).
    fn empty_ast() -> NormalizedAst {
        NormalizedAst::empty()
    }

    fn nop() -> IrInstr {
        IrInstr::Nop { span: span() }
    }

    /// Build a CfgFunction directly from pre-made blocks and edges (no IR lowering).
    fn make_cfg(id: u32, blocks: Vec<Block>, edges: Vec<Edge>) -> CfgFunction {
        CfgFunction { id, blocks, edges }
    }

    /// Return a Z3 solver with a 500 ms per-query timeout for branch-feasibility probing.
    fn default_solver() -> Z3Backend {
        Z3Backend::new(500)
    }

    // ---- run_engine tests ----

    #[test]
    fn test_run_engine_empty_cfgs_returns_no_findings() {
        // Passing an empty CFG slice must return 0 findings and 0 states explored.
        let solver = Z3Backend::new(0);
        let config = SeConfig::default();
        let ast = empty_ast();
        let result = run_engine(&[], &ast, config, &solver);
        assert!(result.findings.is_empty(), "no findings expected for empty CFGs");
        assert_eq!(result.states_explored, 0, "no states should be explored for empty CFGs");
    }

    #[test]
    fn test_run_engine_single_block_no_terminator() {
        // A single-block CFG with one Nop and no outgoing edges should explore exactly
        // 1 state (the entry block) and produce 0 findings (no detector registered).
        let instrs = vec![IrInstr::Nop { span: span() }];
        let cfg = cfg_from_instrs(instrs);

        let solver = Z3Backend::new(0);
        let config = SeConfig::default();
        let ast = empty_ast();
        let result = run_engine(&[cfg], &ast, config, &solver);

        assert_eq!(
            result.states_explored, 1,
            "single block with no successors should explore exactly 1 state"
        );
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_run_engine_linear_three_blocks() {
        // Three blocks in sequence: block 0 -> block 1 -> block 2 (no terminator on last block).
        // All three blocks must be visited (coverage.blocks_visited == 3).
        //
        // Build manually so we can control the exact edges.
        let nop = IrInstr::Nop { span: span() };
        let cfg = CfgFunction {
            id: 0,
            blocks: vec![
                Block { id: 0, instrs: vec![nop.clone()] },
                Block { id: 1, instrs: vec![nop.clone()] },
                Block { id: 2, instrs: vec![nop.clone()] },
            ],
            edges: vec![
                Edge { from: 0, to: 1 },
                Edge { from: 1, to: 2 },
            ],
        };

        let solver = Z3Backend::new(0);
        let config = SeConfig::default();
        let ast = empty_ast();
        let result = run_engine(&[cfg], &ast, config, &solver);

        assert_eq!(
            result.coverage.blocks_visited, 3,
            "all three blocks in a linear chain must be visited"
        );
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_run_engine_branch_explores_both_paths() {
        // A 3-block CFG: entry block (If) with two successors, true_block and false_block.
        // The engine must explore both branches so states_explored >= 2 and
        // coverage shows at least 2 distinct blocks visited (the entry + at least one branch).
        //
        // Build the If-block by hand: Control::If with two edges.
        let cond_var = IrVar::Named("cond".to_string());
        let if_instr = IrInstr::Control {
            kind: ControlKind::If { cond: IrValue::Var(cond_var) },
            span: span(),
        };
        let nop = IrInstr::Nop { span: span() };
        let cfg = CfgFunction {
            id: 0,
            blocks: vec![
                Block { id: 0, instrs: vec![if_instr] },
                Block { id: 1, instrs: vec![nop.clone()] }, // true branch
                Block { id: 2, instrs: vec![nop.clone()] }, // false branch
            ],
            edges: vec![
                Edge { from: 0, to: 1 },
                Edge { from: 0, to: 2 },
            ],
        };

        let solver = Z3Backend::new(0);
        let config = SeConfig::default();
        let ast = empty_ast();
        let result = run_engine(&[cfg], &ast, config, &solver);

        // Both branch blocks must be reachable when cond is symbolic (no forced value).
        assert!(
            result.states_explored >= 2,
            "both branches of an If with symbolic cond should be explored; got {}",
            result.states_explored
        );
        assert!(
            result.coverage.blocks_visited >= 2,
            "at least 2 blocks should be visited; got {}",
            result.coverage.blocks_visited
        );
    }

    // ---- limit-enforcement and structural tests ----

    #[test]
    fn test_infeasible_branch_is_pruned() {
        // When an If condition is the concrete literal `false`, the true-branch is
        // UNSAT and must be pruned. Only entry + false-branch block are explored.
        use crate::norm::Literal;
        let false_lit = IrValue::Literal(Literal {
            kind: "bool".to_string(),
            value: "false".to_string(),
        });
        let if_instr = IrInstr::Control {
            kind: ControlKind::If { cond: false_lit },
            span: span(),
        };
        let cfg = make_cfg(
            0,
            vec![
                Block { id: 0, instrs: vec![if_instr] },
                Block { id: 1, instrs: vec![nop()] }, // true-branch  — must be pruned
                Block { id: 2, instrs: vec![nop()] }, // false-branch — must be explored
            ],
            vec![
                Edge { from: 0, to: 1 },
                Edge { from: 0, to: 2 },
            ],
        );
        let result = run_engine(&[cfg], &empty_ast(), SeConfig::default(), &default_solver());
        assert_eq!(
            result.states_explored, 2,
            "only entry + false-branch should be explored; got {}",
            result.states_explored
        );
        assert_eq!(
            result.coverage.blocks_visited, 2,
            "entry + false-branch = 2 blocks visited; got {}",
            result.coverage.blocks_visited
        );
    }

    #[test]
    fn test_revert_block_terminates_path() {
        // A Revert terminator produces BlockOutcome::Revert, which the engine
        // discards without pushing successors. No findings are produced.
        let revert_instr = IrInstr::Control {
            kind: ControlKind::Revert { value: None },
            span: span(),
        };
        let cfg = make_cfg(
            0,
            vec![
                Block { id: 0, instrs: vec![nop()] },
                Block { id: 1, instrs: vec![revert_instr] },
            ],
            vec![Edge { from: 0, to: 1 }],
        );
        let result = run_engine(&[cfg], &empty_ast(), SeConfig::default(), &default_solver());
        assert_eq!(result.states_explored, 2, "entry + revert block = 2 states");
        assert!(result.findings.is_empty(), "no findings expected for a plain revert");
    }

    #[test]
    fn test_dfs_and_bfs_produce_same_coverage() {
        // Exploration order does not change reachability: DFS and BFS must visit
        // identical block and state counts on the same 3-block branch CFG.
        use crate::symbolic::engine::explorer::ExplorationStrategyKind;
        let build = || {
            let if_instr = IrInstr::Control {
                kind: ControlKind::If { cond: IrValue::Var(IrVar::Named("x".into())) },
                span: span(),
            };
            make_cfg(
                0,
                vec![
                    Block { id: 0, instrs: vec![if_instr] },
                    Block { id: 1, instrs: vec![nop()] },
                    Block { id: 2, instrs: vec![nop()] },
                ],
                vec![Edge { from: 0, to: 1 }, Edge { from: 0, to: 2 }],
            )
        };
        let ast = empty_ast();
        let dfs = run_engine(
            &[build()],
            &ast,
            SeConfig { exploration_strategy: ExplorationStrategyKind::Dfs, ..SeConfig::default() },
            &default_solver(),
        );
        let bfs = run_engine(
            &[build()],
            &ast,
            SeConfig { exploration_strategy: ExplorationStrategyKind::Bfs, ..SeConfig::default() },
            &default_solver(),
        );
        assert_eq!(dfs.coverage.blocks_visited, bfs.coverage.blocks_visited);
        assert_eq!(dfs.states_explored, bfs.states_explored);
    }

    #[test]
    fn test_max_path_depth_stops_deep_chains() {
        // An 8-block linear chain with max_path_depth=3 must stop after at most
        // 3 executed states (the check skips states at depth >= limit).
        let blocks: Vec<Block> = (0u32..8).map(|i| Block { id: i, instrs: vec![nop()] }).collect();
        let edges: Vec<Edge> = (0u32..7).map(|i| Edge { from: i, to: i + 1 }).collect();
        let cfg = make_cfg(0, blocks, edges);
        let config = SeConfig { max_path_depth: 3, ..SeConfig::default() };
        let result = run_engine(&[cfg], &empty_ast(), config, &default_solver());
        assert!(
            result.states_explored <= 3,
            "max_path_depth=3 should stop at ≤3 states; got {}",
            result.states_explored
        );
    }

    #[test]
    fn test_max_states_stops_explosion() {
        // A 3-level binary tree (7 blocks) with symbolic conditions. With
        // max_states=3 the engine must stop at or before 3 states_explored.
        let sym_if = || IrInstr::Control {
            kind: ControlKind::If { cond: IrValue::Var(IrVar::Named("x".into())) },
            span: span(),
        };
        let cfg = make_cfg(
            0,
            vec![
                Block { id: 0, instrs: vec![sym_if()] },
                Block { id: 1, instrs: vec![sym_if()] },
                Block { id: 2, instrs: vec![sym_if()] },
                Block { id: 3, instrs: vec![nop()] },
                Block { id: 4, instrs: vec![nop()] },
                Block { id: 5, instrs: vec![nop()] },
                Block { id: 6, instrs: vec![nop()] },
            ],
            vec![
                Edge { from: 0, to: 1 }, Edge { from: 0, to: 2 },
                Edge { from: 1, to: 3 }, Edge { from: 1, to: 4 },
                Edge { from: 2, to: 5 }, Edge { from: 2, to: 6 },
            ],
        );
        let config = SeConfig { max_states: 3, ..SeConfig::default() };
        let result = run_engine(&[cfg], &empty_ast(), config, &default_solver());
        assert!(
            result.states_explored <= 3,
            "max_states=3 should cap exploration at 3; got {}",
            result.states_explored
        );
    }

    #[test]
    fn test_max_loop_unrolling_prevents_infinite_loop() {
        // A Loop with cond: None would cycle forever without a bound.
        // With max_loop_unrolling=2 the engine must terminate.
        let loop_instr = IrInstr::Control {
            kind: ControlKind::Loop { cond: None },
            span: span(),
        };
        let cfg = make_cfg(
            0,
            vec![
                Block { id: 0, instrs: vec![loop_instr] },
                Block { id: 1, instrs: vec![nop()] }, // body  (first successor)
                Block { id: 2, instrs: vec![nop()] }, // exit  (second successor)
            ],
            vec![Edge { from: 0, to: 1 }, Edge { from: 0, to: 2 }],
        );
        let config = SeConfig { max_loop_unrolling: 2, ..SeConfig::default() };
        let result = run_engine(&[cfg], &empty_ast(), config, &default_solver());
        // Termination is proved by reaching this assertion at all.
        assert!(
            result.states_explored <= 5,
            "loop with max_loop_unrolling=2 must not run away; got {}",
            result.states_explored
        );
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_multi_function_cfgs_explored_independently() {
        // Two CFG functions, each with one entry block, must each be explored.
        let cfg0 = make_cfg(0, vec![Block { id: 0, instrs: vec![nop()] }], vec![]);
        let cfg1 = make_cfg(1, vec![Block { id: 0, instrs: vec![nop()] }], vec![]);
        let result = run_engine(&[cfg0, cfg1], &empty_ast(), SeConfig::default(), &default_solver());
        assert_eq!(result.states_explored, 2);
        assert_eq!(result.coverage.blocks_visited, 2);
        assert_eq!(result.coverage.functions_visited, 2);
    }

    #[test]
    fn test_coverage_percentage_nonzero_after_execution() {
        // After executing any block the block_coverage_pct must be positive.
        let if_instr = IrInstr::Control {
            kind: ControlKind::If { cond: IrValue::Var(IrVar::Named("x".into())) },
            span: span(),
        };
        let cfg = make_cfg(
            0,
            vec![
                Block { id: 0, instrs: vec![if_instr] },
                Block { id: 1, instrs: vec![nop()] },
                Block { id: 2, instrs: vec![nop()] },
            ],
            vec![Edge { from: 0, to: 1 }, Edge { from: 0, to: 2 }],
        );
        let result = run_engine(&[cfg], &empty_ast(), SeConfig::default(), &default_solver());
        assert!(result.coverage.block_coverage_pct > 0.0);
        assert!(result.coverage.blocks_visited >= 1);
    }

    #[test]
    fn test_dangling_edge_to_missing_block_does_not_panic() {
        // A Fallthrough edge pointing to a non-existent block must not panic.
        // The engine does `None => continue` on the missing-block lookup.
        let cfg = make_cfg(
            0,
            vec![Block { id: 0, instrs: vec![nop()] }],
            vec![Edge { from: 0, to: 99 }],
        );
        let result = run_engine(&[cfg], &empty_ast(), SeConfig::default(), &default_solver());
        // states_explored is incremented before the block-lookup check, so the
        // missing block 99 is counted before the None => continue fires: exactly 2.
        assert_eq!(result.states_explored, 2);
    }
}
