// TODO Phase 5: remove when run_engine is wired from symbolic/mod.rs::run()
#![allow(dead_code)]

pub mod executor;
pub mod explorer;
pub mod scheduler;

use std::time::Instant;

use z3::ast::Bool;
use z3::SatResult;

use crate::cfg::{BlockId, CfgFunction};
use crate::norm::NormalizedAst;
use crate::symbolic::results::coverage::{CoverageReport, CoverageTracker};
use crate::symbolic::results::SeFinding;
use crate::symbolic::solver::SmtSolver;
use crate::symbolic::state::call_context::CallContext;
use crate::symbolic::state::storage::StorageLayout;
use crate::symbolic::state::{StateIdGen, SymbolicState};
use crate::symbolic::types::hash::KeccakContext;

use executor::{BlockOutcome, ExecutorError, execute_block, pre_populate_call_context};
use explorer::make_strategy;
use scheduler::{SeConfig, WorklistEntry};

/// Output produced by the engine for one analysis run.
pub struct EngineResult {
    pub findings: Vec<SeFinding>,
    pub coverage: CoverageReport,
    pub states_explored: usize,
}

/// Run symbolic execution over all CFG functions.
///
/// Exploration is driven by a configurable worklist strategy (DFS or BFS).
/// Each state is an independent snapshot of one execution path. The engine
/// forks states at conditional branches, applies path constraints, and
/// queries the solver for feasibility before exploring each fork.
pub fn run_engine(
    cfgs: &[CfgFunction],
    _ast: &NormalizedAst,
    config: SeConfig,
    solver: &dyn SmtSolver,
) -> EngineResult {
    let total_blocks: usize = cfgs.iter().map(|f| f.blocks.len()).sum();
    let total_functions = cfgs.len();

    let mut coverage = CoverageTracker::new(total_blocks, total_functions);
    let mut all_findings: Vec<SeFinding> = Vec::new();
    let mut id_gen = StateIdGen::new();
    let mut keccak_ctx = KeccakContext::new();
    let mut states_explored: usize = 0;
    let start_time = Instant::now();

    // Unpack config — we need mutability for detectors.
    let SeConfig {
        max_path_depth,
        max_instructions,
        max_loop_unrolling,
        max_states,
        solver_timeout_ms: _,
        total_timeout_s,
        dynamic_bytes_bound: _,
        exploration_strategy,
        mut detectors,
        storage_layout,
        contract_name,
    } = config;

    let layout: &StorageLayout = &storage_layout;

    for cfg_func in cfgs {
        if cfg_func.blocks.is_empty() {
            continue;
        }

        detectors.reset_all();
        coverage.record_function(cfg_func.id);

        let entry_block = cfg_func.blocks[0].id;
        let (call_ctx, init_constraints) = CallContext::new_symbolic();
        let mut initial_state = SymbolicState::initial(&mut id_gen, entry_block, call_ctx);

        // Add CallContext initial constraints to PathConstraints.
        for (c, desc) in init_constraints {
            initial_state.path_constraints.add(c, desc);
        }

        // Bind well-known blockchain names in the variable environment.
        pre_populate_call_context(&mut initial_state);

        let mut strategy = make_strategy(exploration_strategy);
        strategy.push(WorklistEntry {
            state: initial_state,
            cfg_func_id: cfg_func.id,
            predecessor_block: None,
            loop_counts: std::collections::HashMap::new(),
        });

        while let Some(mut entry) = strategy.pop() {
            // ── Termination guards ──────────────────────────────────────────
            if total_timeout_s > 0
                && start_time.elapsed().as_secs() >= total_timeout_s
            {
                break;
            }
            // Cap total states processed, not just worklist size.
            if states_explored >= max_states {
                break;
            }
            if entry.state.path_depth >= max_path_depth {
                continue;
            }
            if entry.state.instruction_count >= max_instructions {
                continue;
            }

            states_explored += 1;
            coverage.record_block(cfg_func.id, entry.state.current_block);

            // ── Find the block in the CFG ────────────────────────────────
            let block = match cfg_func.blocks.iter().find(|b| b.id == entry.state.current_block) {
                Some(b) => b,
                None => continue, // stale block reference — skip
            };

            // ── Execute the block ────────────────────────────────────────
            let outcome = match execute_block(
                &mut entry.state,
                block,
                cfg_func,
                &mut detectors,
                solver,
                &mut keccak_ctx,
                layout,
                &contract_name,
                &mut all_findings,
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

            // ── Dispatch on block outcome ────────────────────────────────
            match outcome {
                BlockOutcome::Fallthrough { target } => {
                    coverage.record_edge(block.id, target);
                    let mut next = entry.fork_to(target);
                    next.state.path_depth += 1;
                    strategy.push(next);
                }

                BlockOutcome::Branch { cond, true_block, false_block } => {
                    handle_branch(
                        &entry, cond, true_block, false_block,
                        block.id, solver, &mut coverage, &mut *strategy,
                    );
                }

                BlockOutcome::LoopHeader { cond, body_block, exit_block } => {
                    handle_loop_header(
                        entry, cond, body_block, exit_block,
                        block.id, solver, &mut coverage, &mut *strategy,
                        max_loop_unrolling,
                    );
                }

                // Terminal outcomes — path ends.
                BlockOutcome::Return { .. } | BlockOutcome::Revert { .. } | BlockOutcome::Stop => {}
            }
        }
    }

    EngineResult {
        findings: all_findings,
        coverage: coverage.report(),
        states_explored,
    }
}

/// Handle a conditional branch outcome: probe feasibility and push forks.
#[allow(clippy::too_many_arguments)]
fn handle_branch(
    entry: &WorklistEntry,
    cond: Bool,
    true_block: BlockId,
    false_block: BlockId,
    from_block: BlockId,
    solver: &dyn SmtSolver,
    coverage: &mut CoverageTracker,
    strategy: &mut dyn explorer::ExplorationStrategy,
) {
    let base: Vec<Bool> = entry
        .state
        .path_constraints
        .constraints()
        .iter()
        .map(|(c, _)| c.clone())
        .collect();

    if probe_branch(solver, &base, &cond) {
        coverage.record_edge(from_block, true_block);
        let mut fork = entry.fork_to(true_block);
        fork.state.path_constraints.add(
            cond.clone(),
            format!("branch true → block {true_block}"),
        );
        fork.state.path_depth += 1;
        strategy.push(fork);
    }
    if probe_branch(solver, &base, &cond.not()) {
        coverage.record_edge(from_block, false_block);
        let mut fork = entry.fork_to(false_block);
        fork.state.path_constraints.add(
            cond.not(),
            format!("branch false → block {false_block}"),
        );
        fork.state.path_depth += 1;
        strategy.push(fork);
    }
}

/// Handle a loop-header outcome: enforce unrolling bound, push body and/or exit forks.
#[allow(clippy::too_many_arguments)]
fn handle_loop_header(
    entry: WorklistEntry,
    cond: Option<Bool>,
    body_block: BlockId,
    exit_block: Option<BlockId>,
    from_block: BlockId,
    solver: &dyn SmtSolver,
    coverage: &mut CoverageTracker,
    strategy: &mut dyn explorer::ExplorationStrategy,
    max_loop_unrolling: u32,
) {
    let loop_count = entry.loop_counts.get(&body_block).copied().unwrap_or(0);
    let base: Vec<Bool> = entry
        .state
        .path_constraints
        .constraints()
        .iter()
        .map(|(c, _)| c.clone())
        .collect();

    if loop_count >= max_loop_unrolling {
        // Bound hit: push only exit path.
        if let Some(exit) = exit_block {
            let exit_cond = cond.as_ref().map(|c| c.not());
            let feasible = match &exit_cond {
                Some(ec) => probe_branch(solver, &base, ec),
                None => true,
            };
            if feasible {
                coverage.record_edge(from_block, exit);
                let mut fork = entry.fork_to(exit);
                if let Some(ec) = exit_cond {
                    fork.state.path_constraints.add(ec, format!("loop exit → block {exit}"));
                }
                fork.state.path_depth += 1;
                strategy.push(fork);
            }
        }
        return;
    }

    // Under bound: push body and optionally exit.
    let body_feasible = match &cond {
        Some(c) => probe_branch(solver, &base, c),
        None => true,
    };
    if body_feasible {
        coverage.record_edge(from_block, body_block);
        let mut fork = entry.fork_to(body_block);
        if let Some(c) = cond.clone() {
            fork.state.path_constraints.add(c, format!("loop body → block {body_block}"));
        }
        *fork.loop_counts.entry(body_block).or_insert(0) += 1;
        fork.state.path_depth += 1;
        strategy.push(fork);
    }

    if let Some(exit) = exit_block {
        let exit_feasible = match &cond {
            Some(c) => probe_branch(solver, &base, &c.not()),
            None => false, // unconditional loop — no exit via condition
        };
        if exit_feasible {
            coverage.record_edge(from_block, exit);
            let mut fork = entry.fork_to(exit);
            if let Some(c) = cond {
                fork.state.path_constraints.add(c.not(), format!("loop exit → block {exit}"));
            }
            fork.state.path_depth += 1;
            strategy.push(fork);
        }
    }
}

/// Probe whether `extra` is satisfiable given the base path constraints.
///
/// Uses `check_sat_assuming` to avoid permanently asserting the probe condition.
fn probe_branch(solver: &dyn SmtSolver, base: &[Bool], extra: &Bool) -> bool {
    let mut assumptions = base.to_vec();
    assumptions.push(extra.clone());
    solver.check_sat_assuming(&assumptions) == SatResult::Sat
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{Block, BlockId, CfgFunction, Edge};
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
}
