use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::time::Instant;

use crate::cfg;
use crate::core::artifacts::{
    AssistEvent, CompilerInfo, ContractTarget, EpochResultArtifact, Finding, FrontierGoal,
    HybridReport, Seed, StallMetrics, StaticHints, TracePrefix, TxEnv, TxSeed,
};
use crate::core::budget::{Budget, FuzzEpochBudget, SeBudget};
use crate::core::engines::{
    EngineContext, EpochResult, FuzzAdapter, FuzzEngine, SEResult, StaticAdapter, StaticEngine,
    SymbolicAssistAdapter, SymbolicEngine,
};
use crate::core::queues::{
    FindingQueue, FrontierQueue, InMemoryFindingQueue, InMemoryFrontierQueue, InMemorySeedQueue,
    SeedQueue,
};
use crate::core::store::ArtifactStore;
use crate::core::triage::FindingTriage;
use crate::frontend::{self, FrontendMode};
use crate::fuzzing;
use crate::ir;
use crate::meta;
use crate::norm::{FunctionKind, Mutability};
use crate::util::error::Result;

const FRONTIER_MAX_ATTEMPTS_PER_GOAL: u32 = 3;
const FRONTIER_MAX_BACKOFF_EPOCHS: u32 = 8;

#[derive(Debug, Clone)]
pub struct HybridRunOutput {
    pub run_id: String,
    pub run_dir: String,
    pub report: HybridReport,
    pub findings: Vec<Finding>,
}

pub fn run_p1(input_path: &str, budget: Budget) -> Result<HybridRunOutput> {
    let scheduler = P1Scheduler {
        static_engine: StaticAdapter,
        fuzz_engine: FuzzAdapter,
        symbolic_engine: SymbolicAssistAdapter,
    };
    scheduler.run(input_path, budget)
}

pub struct P1Scheduler<S, F, SE> {
    pub static_engine: S,
    pub fuzz_engine: F,
    pub symbolic_engine: SE,
}

impl<S, F, SE> P1Scheduler<S, F, SE>
where
    S: StaticEngine,
    F: FuzzEngine,
    SE: SymbolicEngine,
{
    pub fn run(&self, input_path: &str, budget: Budget) -> Result<HybridRunOutput> {
        let output = frontend::load_project(input_path)?;
        self.run_with_output(input_path, output, budget)
    }

    fn run_with_output(
        &self,
        input_path: &str,
        output: crate::frontend::FrontendOutput,
        budget: Budget,
    ) -> Result<HybridRunOutput> {
        let start = Instant::now();
        let ir_module = ir::lower_module(&output.ast);
        let cfgs = cfg::build_from_ir(&ir_module);
        let fuzz_deps = fuzzing::types::build_dependency_map(&ir_module, &output.ast);
        let fuzz_abis = fuzzing::types::extract_abis(&output.ast, &output.compiler);

        let target = build_target(input_path, &output);
        let mut seed_queue = InMemorySeedQueue::default();
        let mut frontier_queue = InMemoryFrontierQueue::default();
        let mut finding_queue = InMemoryFindingQueue::default();
        let mut triage = FindingTriage::default();

        let mut coverage_history = Vec::new();
        let mut epoch_artifacts = Vec::new();
        let mut assists = Vec::new();
        let mut last_prefix: Option<TracePrefix> = None;
        let mut covered_blocks_global = HashSet::<(u32, u32)>::new();
        let mut covered_edges_global = HashSet::<(u32, u32, u32)>::new();

        let runs_root = Path::new("runs");
        std::fs::create_dir_all(runs_root)?;
        let store = ArtifactStore::create(runs_root)?;

        store.save_target(&target)?;

        let ctx = EngineContext {
            output: &output,
            ir_module: &ir_module,
            cfgs: &cfgs,
        };

        let static_hints = self.static_engine.analyze(&ctx)?;
        store.save_static_hints(&static_hints)?;

        let static_findings = self.static_engine.findings(&ctx)?;
        if !static_findings.is_empty() {
            let triage_res = triage.ingest(static_findings);
            if triage_res.inserted > 0 {
                // time-to-first-finding may be set to zero later when report is built.
            }
        }
        let meta_findings = meta::analyze(&output);
        let runtime_meta_promotions = meta::runtime_promotions(&meta_findings);
        if !runtime_meta_promotions.is_empty() {
            let triage_res = triage.ingest(runtime_meta_promotions);
            if triage_res.inserted > 0 {
                // time-to-first-finding may be set to zero later when report is built.
            }
        }
        if !meta_findings.is_empty() {
            let triage_res = triage.ingest(meta_findings);
            if triage_res.inserted > 0 {
                // time-to-first-finding may be set to zero later when report is built.
            }
        }

        let bootstrap = bootstrap_seeds(&output, &static_hints);
        seed_queue.push_many(bootstrap);
        store.save_seed_corpus(&seed_queue.snapshot())?;

        let mut stagnant_epochs = 0u32;
        let mut se_assists = 0usize;
        let mut injected_by_se = 0usize;
        let mut se_new_edges_from_injected = 0usize;
        let mut edge_rate_window = VecDeque::<f64>::new();
        let mut frontier_attempts = HashMap::<String, u32>::new();
        let mut frontier_backoff_until_epoch = HashMap::<String, u32>::new();
        let stall_window_size = budget.stall_epochs_threshold.max(1) as usize;
        let stall_edge_rate_epsilon = compute_stall_edge_rate_epsilon(&budget);
        let mut time_to_first_finding_ms = if triage.unique_count() > 0 {
            Some(0u128)
        } else {
            None
        };

        for epoch in 1..=budget.max_epochs {
            if start.elapsed().as_millis() as u64 >= budget.total_runtime_ms {
                break;
            }

            let seed_pool = seed_queue.snapshot();
            let fuzz_budget = FuzzEpochBudget {
                epoch,
                wallclock_ms: budget.fuzz_epoch_ms,
                max_iterations: budget.fuzz_iterations_per_epoch,
            };

            let epoch_result =
                self.fuzz_engine
                    .run_epoch(&ctx, &static_hints, &seed_pool, &fuzz_budget)?;

            process_epoch_result(
                &epoch_result,
                &mut covered_blocks_global,
                &mut covered_edges_global,
                &mut seed_queue,
                &mut frontier_queue,
                &mut finding_queue,
            );

            let findings = finding_queue.drain_all();
            if !findings.is_empty() {
                let triage_res = triage.ingest(findings);
                if triage_res.inserted > 0 && time_to_first_finding_ms.is_none() {
                    time_to_first_finding_ms = Some(start.elapsed().as_millis());
                }
            }

            if epoch_result.coverage.delta_edges < budget.min_coverage_delta as i64 {
                stagnant_epochs = stagnant_epochs.saturating_add(1);
            } else {
                stagnant_epochs = 0;
            }
            let stalled = update_stall_window(
                &mut edge_rate_window,
                epoch_result.stall.edge_rate,
                stall_window_size,
                stall_edge_rate_epsilon,
            );

            let unmet_priority_goal = has_unmet_sink_goal(&static_hints, &covered_blocks_global);

            if (stalled || unmet_priority_goal)
                && se_assists < budget.max_se_assists as usize
            {
                if let Some(mut goal) = select_frontier_goal_for_assist(
                    &mut frontier_queue,
                    epoch,
                    &mut frontier_attempts,
                    &mut frontier_backoff_until_epoch,
                    FRONTIER_MAX_ATTEMPTS_PER_GOAL,
                ) {
                    let goal_key = frontier_goal_key(&goal);
                    let attempt = frontier_attempts
                        .get(&goal_key)
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(1);
                    frontier_attempts.insert(goal_key.clone(), attempt);
                    goal.attempts = attempt;

                    let se_result = self.invoke_symbolic_assist(
                        &ctx,
                        &goal,
                        epoch_result.trace_prefix.as_ref().or(last_prefix.as_ref()),
                        &budget,
                    )?;

                    let (injectable_seeds, unlocked_edges) = filter_assist_seeds(
                        &ctx,
                        &fuzz_abis,
                        &fuzz_deps,
                        &goal,
                        epoch_result.trace_prefix.as_ref().or(last_prefix.as_ref()),
                        &covered_edges_global,
                        se_result.new_seeds,
                    );
                    let injected = injectable_seeds
                        .into_iter()
                        .take(budget.max_seed_injection_per_assist)
                        .collect::<Vec<_>>();
                    let injected_ids = injected.iter().map(|s| s.id.clone()).collect::<Vec<_>>();
                    let count_added = seed_queue.push_many(injected);
                    injected_by_se += count_added;
                    if count_added > 0 {
                        se_new_edges_from_injected =
                            se_new_edges_from_injected.saturating_add(unlocked_edges);
                    }
                    se_assists += 1;
                    let assist_success = count_added > 0 || !se_result.findings.is_empty();

                    if !se_result.findings.is_empty() {
                        let triage_res = triage.ingest(se_result.findings);
                        if triage_res.inserted > 0 && time_to_first_finding_ms.is_none() {
                            time_to_first_finding_ms = Some(start.elapsed().as_millis());
                        }
                    }

                    assists.push(AssistEvent {
                        epoch,
                        goal: goal.clone(),
                        injected_seed_ids: injected_ids,
                        solver: se_result.solver,
                    });

                    if assist_success {
                        frontier_attempts.remove(&goal_key);
                        frontier_backoff_until_epoch.remove(&goal_key);
                    } else if attempt < FRONTIER_MAX_ATTEMPTS_PER_GOAL {
                        let mut retry_goal = goal.clone();
                        retry_goal.priority = (retry_goal.priority * 0.9).max(0.1);
                        frontier_queue.push(retry_goal);
                        frontier_backoff_until_epoch
                            .insert(goal_key, epoch.saturating_add(assist_backoff_epochs(attempt)));
                    } else {
                        frontier_backoff_until_epoch.remove(&goal_key);
                    }
                }
            }

            if let Some(prefix) = &epoch_result.trace_prefix {
                last_prefix = Some(prefix.clone());
            }

            coverage_history.push(epoch_result.coverage.clone());
            epoch_artifacts.push(EpochResultArtifact {
                epoch,
                coverage: epoch_result.coverage.clone(),
                new_seed_ids: epoch_result
                    .new_seeds
                    .iter()
                    .map(|s| s.id.clone())
                    .collect(),
                findings: epoch_result.findings.clone(),
                frontier_goals: epoch_result.candidate_frontier_goals.clone(),
                stall: StallMetrics {
                    edge_rate: epoch_result.stall.edge_rate,
                    stagnant_epochs,
                    coverage_delta: epoch_result.coverage.delta_edges,
                },
                trace_prefix: epoch_result.trace_prefix.clone(),
            });

            store.save_seed_corpus(&seed_queue.snapshot())?;
            store.save_findings(&triage.unique_findings())?;
            store.save_coverage_history(&coverage_history)?;
            store.save_epochs(&epoch_artifacts)?;
            store.save_assists(&assists)?;
        }

        let findings = triage.unique_findings();
        let report = HybridReport {
            run_id: store.run_id().to_string(),
            runtime_ms: start.elapsed().as_millis(),
            total_epochs: coverage_history.len() as u32,
            coverage_curve: coverage_history,
            findings_total: triage.total_seen(),
            findings_unique: triage.unique_count(),
            runtime_findings_total: triage.total_seen_by_layer("runtime"),
            runtime_findings_unique: triage.unique_count_by_layer("runtime"),
            meta_findings_total: triage.total_seen_by_layer("meta"),
            meta_findings_unique: triage.unique_count_by_layer("meta"),
            se_assists,
            seeds_injected_by_se: injected_by_se,
            se_new_edges_from_injected,
            time_to_first_finding_ms,
        };

        store.save_report(&report)?;

        Ok(HybridRunOutput {
            run_id: store.run_id().to_string(),
            run_dir: store.run_dir().display().to_string(),
            report,
            findings,
        })
    }

    fn invoke_symbolic_assist(
        &self,
        ctx: &EngineContext<'_>,
        goal: &FrontierGoal,
        trace_prefix: Option<&TracePrefix>,
        budget: &Budget,
    ) -> Result<SEResult> {
        let se_budget = SeBudget {
            timeout_ms: budget.se_timeout_ms,
            max_states: budget.se_max_states,
            max_depth: budget.se_max_depth,
            max_new_seeds: budget.max_seed_injection_per_assist,
        };
        self.symbolic_engine
            .solve(ctx, goal, trace_prefix, &se_budget)
    }
}

fn process_epoch_result(
    epoch: &EpochResult,
    covered_blocks_global: &mut HashSet<(u32, u32)>,
    covered_edges_global: &mut HashSet<(u32, u32, u32)>,
    seed_queue: &mut impl SeedQueue,
    frontier_queue: &mut impl FrontierQueue,
    finding_queue: &mut impl FindingQueue,
) {
    covered_blocks_global.extend(epoch.covered_blocks.iter().copied());
    covered_edges_global.extend(epoch.covered_edges.iter().copied());
    seed_queue.push_many(epoch.new_seeds.clone());
    frontier_queue.push_many(epoch.candidate_frontier_goals.clone());
    finding_queue.push_many(epoch.findings.clone());
}

fn filter_assist_seeds(
    ctx: &EngineContext<'_>,
    abis: &[fuzzing::types::ContractAbi],
    deps: &fuzzing::types::DependencyMap,
    goal: &FrontierGoal,
    trace_prefix: Option<&TracePrefix>,
    covered_edges_global: &HashSet<(u32, u32, u32)>,
    seeds: Vec<Seed>,
) -> (Vec<Seed>, usize) {
    let mut accepted = Vec::new();
    let mut unlocked_edge_set: HashSet<(u32, u32, u32)> = HashSet::new();
    let baseline_distance = trace_prefix
        .and_then(|prefix| prefix.distance_hint)
        .unwrap_or(u32::MAX);

    for seed in seeds {
        let Some(ind) = seed_to_individual(&seed) else {
            continue;
        };
        let Some(abi) = abi_for_seed(abis, &seed) else {
            continue;
        };
        let trace = fuzzing::executor::execute_individual(
            &ind,
            ctx.output,
            ctx.ir_module,
            ctx.cfgs,
            abi,
            deps,
        );
        let newly_unlocked = trace
            .edge_coverage
            .iter()
            .filter(|edge| !covered_edges_global.contains(edge))
            .copied()
            .collect::<HashSet<_>>();
        let goal_distance = assist_goal_distance(goal, &trace);
        let improves_frontier = goal_distance < baseline_distance || goal_distance == 0;
        let unlocks_edges = !newly_unlocked.is_empty();
        if improves_frontier || unlocks_edges {
            accepted.push(seed);
            unlocked_edge_set.extend(newly_unlocked);
        }
    }

    (accepted, unlocked_edge_set.len())
}

fn assist_goal_distance(goal: &FrontierGoal, trace: &fuzzing::types::ExecutionTrace) -> u32 {
    if let (Some(from), Some(to)) = (goal.edge_from, goal.edge_to) {
        if trace
            .edge_coverage
            .contains(&(goal.function_id, from, to))
        {
            return 0;
        }
        if trace.coverage.contains(&(goal.function_id, to)) {
            return 1;
        }
        if trace.coverage.contains(&(goal.function_id, from)) {
            return 2;
        }
        return u32::MAX;
    }

    if let Some(block_id) = goal.block_id {
        if trace.coverage.contains(&(goal.function_id, block_id)) {
            return 0;
        }
        return u32::MAX;
    }

    u32::MAX
}

fn abi_for_seed<'a>(
    abis: &'a [fuzzing::types::ContractAbi],
    seed: &Seed,
) -> Option<&'a fuzzing::types::ContractAbi> {
    let function_ids = seed
        .txs
        .iter()
        .map(|tx| tx.function_id)
        .collect::<HashSet<_>>();
    abis.iter().find(|abi| {
        abi.functions
            .iter()
            .any(|function| function_ids.contains(&function.id))
    })
}

fn seed_to_individual(seed: &Seed) -> Option<fuzzing::types::Individual> {
    if seed.txs.is_empty() {
        return None;
    }
    let env = fuzzing::types::Environment {
        block_timestamp: seed
            .txs
            .first()
            .and_then(|tx| tx.env.block_timestamp)
            .unwrap_or(1_700_000_000),
        block_number: seed
            .txs
            .first()
            .and_then(|tx| tx.env.block_number)
            .unwrap_or(1_000_000),
        address_pool_size: 8,
    };
    let mut txs = Vec::with_capacity(seed.txs.len());
    for tx in &seed.txs {
        let args = tx
            .args
            .iter()
            .map(|arg| {
                arg.parse::<u128>()
                    .map(fuzzing::types::FuzzValue::Uint)
                    .unwrap_or(fuzzing::types::FuzzValue::Uint(0))
            })
            .collect::<Vec<_>>();
        txs.push(fuzzing::types::Transaction {
            function_id: tx.function_id,
            args,
            sender: tx.sender.parse::<usize>().unwrap_or(0),
            value: tx.value.parse::<u128>().unwrap_or(0),
        });
    }
    Some(fuzzing::types::Individual {
        transactions: txs,
        environment: env,
        energy: seed.score.max(0.1),
    })
}

fn has_unmet_sink_goal(hints: &StaticHints, covered: &HashSet<(u32, u32)>) -> bool {
    let covered_functions = covered.iter().map(|(f, _)| *f).collect::<HashSet<_>>();
    hints
        .sinks
        .iter()
        .filter(|sink| sink.function_id != u32::MAX)
        .any(|sink| !covered_functions.contains(&sink.function_id))
}

fn compute_stall_edge_rate_epsilon(budget: &Budget) -> f64 {
    if budget.fuzz_iterations_per_epoch == 0 {
        return 0.0;
    }
    (budget.min_coverage_delta as f64 / budget.fuzz_iterations_per_epoch as f64).max(0.0)
}

fn update_stall_window(
    edge_rate_window: &mut VecDeque<f64>,
    edge_rate: f64,
    window_size: usize,
    epsilon: f64,
) -> bool {
    if window_size == 0 {
        return false;
    }
    edge_rate_window.push_back(edge_rate.max(0.0));
    while edge_rate_window.len() > window_size {
        edge_rate_window.pop_front();
    }
    if edge_rate_window.len() < window_size {
        return false;
    }
    let avg = edge_rate_window.iter().sum::<f64>() / edge_rate_window.len() as f64;
    avg < epsilon
}

fn frontier_goal_key(goal: &FrontierGoal) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        goal.function_id,
        goal.block_id
            .map(|v| v.to_string())
            .unwrap_or_else(|| "none".to_string()),
        goal.edge_from
            .map(|v| v.to_string())
            .unwrap_or_else(|| "none".to_string()),
        goal.edge_to
            .map(|v| v.to_string())
            .unwrap_or_else(|| "none".to_string()),
        goal.sink_kind.as_deref().unwrap_or("none")
    )
}

fn assist_backoff_epochs(attempt: u32) -> u32 {
    let shift = attempt.saturating_sub(1).min(5);
    let delay = 1u32 << shift;
    delay.min(FRONTIER_MAX_BACKOFF_EPOCHS)
}

fn select_frontier_goal_for_assist(
    frontier_queue: &mut impl FrontierQueue,
    epoch: u32,
    attempts_by_goal: &mut HashMap<String, u32>,
    backoff_until_epoch: &mut HashMap<String, u32>,
    max_attempts: u32,
) -> Option<FrontierGoal> {
    let mut deferred = Vec::new();
    let mut selected = None;

    while let Some(goal) = frontier_queue.pop_highest_priority() {
        let key = frontier_goal_key(&goal);
        let attempts = attempts_by_goal.get(&key).copied().unwrap_or(0);
        if attempts >= max_attempts {
            backoff_until_epoch.remove(&key);
            continue;
        }

        if let Some(until) = backoff_until_epoch.get(&key).copied()
            && epoch < until
        {
            deferred.push(goal);
            continue;
        }

        selected = Some(goal);
        break;
    }

    if !deferred.is_empty() {
        frontier_queue.push_many(deferred);
    }

    selected
}

fn coverage_curve_stable(curve: &[crate::core::artifacts::CoverageSummary]) -> bool {
    if curve.is_empty() {
        return true;
    }
    let mut prev_edges = curve[0].covered_edges;
    for point in curve {
        if point.covered_edges > point.total_edges {
            return false;
        }
        if !(0.0..=100.0).contains(&point.coverage_pct) {
            return false;
        }
        if point.covered_edges < prev_edges {
            return false;
        }
        prev_edges = point.covered_edges;
    }
    true
}

fn report_quality_guard(report: &HybridReport, budget: &Budget) -> bool {
    if report.findings_unique > report.findings_total {
        return false;
    }
    if report.se_assists > budget.max_se_assists as usize {
        return false;
    }
    if report.total_epochs as usize != report.coverage_curve.len() {
        return false;
    }
    if let Some(last) = report.coverage_curve.last()
        && report.se_new_edges_from_injected > last.covered_edges
    {
        return false;
    }
    coverage_curve_stable(&report.coverage_curve)
}

fn build_target(input_path: &str, output: &crate::frontend::FrontendOutput) -> ContractTarget {
    let mode = match output.mode {
        FrontendMode::Full => "full",
        FrontendMode::Partial => "partial",
    }
    .to_string();

    ContractTarget {
        id: Path::new(input_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("target")
            .to_string(),
        input_path: input_path.to_string(),
        source_paths: output.ast.files.iter().map(|f| f.path.clone()).collect(),
        chain_id: None,
        address: None,
        abi: None,
        bytecode: None,
        compiler: CompilerInfo {
            frontend_mode: mode,
            compiler_name: output.compiler.compiler_name.clone(),
            compiler_version: output.compiler.compiler_version.clone(),
        },
    }
}

fn bootstrap_seeds(output: &crate::frontend::FrontendOutput, hints: &StaticHints) -> Vec<Seed> {
    let ast = &output.ast;
    let mut out = Vec::new();
    let owner_role = hints
        .address_roles
        .iter()
        .find(|role| role.role.eq_ignore_ascii_case("owner"));
    let attacker_role = hints
        .address_roles
        .iter()
        .find(|role| role.role.eq_ignore_ascii_case("attacker"));

    let owner_sender = owner_role
        .and_then(|role| role.indices.first())
        .copied()
        .unwrap_or(0)
        .to_string();
    let attacker_sender = attacker_role
        .and_then(|role| role.indices.first())
        .copied()
        .unwrap_or(1)
        .to_string();

    let owner_targets = owner_role
        .map(|role| role.target_functions.iter().copied().collect::<HashSet<_>>())
        .unwrap_or_default();

    for function in &ast.functions {
        let callable = match function.kind {
            FunctionKind::Function => {
                crate::frontend::is_public_entrypoint(function, &output.compiler)
            }
            FunctionKind::Fallback | FunctionKind::Receive => {
                function.mutability == Mutability::Payable && function.params.is_empty()
            }
            _ => false,
        };
        if !callable {
            continue;
        }

        let tx = TxSeed {
            function_id: function.id,
            selector: None,
            calldata: None,
            args: function
                .params
                .iter()
                .enumerate()
                .map(|(idx, _)| {
                    hints
                        .arg_domains
                        .iter()
                        .find(|domain| domain.function_id == function.id && domain.param_index == idx)
                        .and_then(|domain| domain.candidate_values.first().copied())
                        .unwrap_or(0)
                        .to_string()
                })
                .collect(),
            sender: if owner_targets.contains(&function.id) {
                owner_sender.clone()
            } else {
                "0".to_string()
            },
            value: if function.mutability == Mutability::Payable {
                "1".to_string()
            } else {
                "0".to_string()
            },
            env: TxEnv {
                block_timestamp: Some(1_700_000_000),
                block_number: Some(1_000_000),
            },
        };

        out.push(Seed {
            id: format!("bootstrap-fn-{}", function.id),
            txs: vec![tx],
            state_snapshot_id: None,
            score: 1.0,
        });
    }

    for hotspot in hints.hotspots.iter().take(8) {
        let function = ast.functions.get(hotspot.function_id as usize);
        let tx = TxSeed {
            function_id: hotspot.function_id,
            selector: None,
            calldata: None,
            args: function
                .map(|f| {
                    f.params
                        .iter()
                        .enumerate()
                        .map(|(idx, _)| {
                            hints
                                .arg_domains
                                .iter()
                                .find(|domain| {
                                    domain.function_id == hotspot.function_id
                                        && domain.param_index == idx
                                })
                                .and_then(|domain| {
                                    domain
                                        .candidate_values
                                        .get(1)
                                        .copied()
                                        .or_else(|| domain.candidate_values.first().copied())
                                })
                                .unwrap_or(1)
                                .to_string()
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_else(|| vec!["1".to_string(), "2".to_string()]),
            sender: if owner_targets.contains(&hotspot.function_id) {
                attacker_sender.clone()
            } else {
                owner_sender.clone()
            },
            value: if function
                .map(|f| f.mutability == Mutability::Payable)
                .unwrap_or(false)
            {
                "1000000000000000000".to_string()
            } else {
                "0".to_string()
            },
            env: TxEnv {
                block_timestamp: Some(1_700_000_100),
                block_number: Some(1_000_010),
            },
        };
        out.push(Seed {
            id: format!("bootstrap-hotspot-{}", hotspot.function_id),
            txs: vec![tx],
            state_snapshot_id: None,
            score: hotspot.score,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use crate::core::artifacts::{CoverageSummary, Finding, FindingLocation, TracePrefix};
    use crate::core::engines::{EpochResult, FuzzEngine, SEResult, StaticEngine, SymbolicEngine};
    use crate::frontend::{FrontendMode, FrontendOutput};
    use crate::norm::{
        Function, FunctionKind, Mutability, NormalizedAst, SourceFile, Span, Visibility,
    };
    use crate::util::error::Result;

    #[derive(Clone)]
    struct MockStaticEngine {
        hints: StaticHints,
        findings: Vec<Finding>,
    }

    impl MockStaticEngine {
        fn new() -> Self {
            Self {
                hints: StaticHints {
                    function_whitelist: vec![0],
                    ..StaticHints::default()
                },
                findings: Vec::new(),
            }
        }
    }

    impl StaticEngine for MockStaticEngine {
        fn analyze(&self, _ctx: &crate::core::engines::EngineContext<'_>) -> Result<StaticHints> {
            Ok(self.hints.clone())
        }

        fn findings(
            &self,
            _ctx: &crate::core::engines::EngineContext<'_>,
        ) -> Result<Vec<Finding>> {
            Ok(self.findings.clone())
        }
    }

    #[derive(Clone)]
    struct MockFuzzEngine {
        goal: FrontierGoal,
        epoch_calls: Rc<Cell<u32>>,
        emit_unique_finding: bool,
    }

    impl MockFuzzEngine {
        fn new(goal: FrontierGoal, emit_unique_finding: bool) -> Self {
            Self {
                goal,
                epoch_calls: Rc::new(Cell::new(0)),
                emit_unique_finding,
            }
        }
    }

    impl FuzzEngine for MockFuzzEngine {
        fn run_epoch(
            &self,
            _ctx: &crate::core::engines::EngineContext<'_>,
            _hints: &StaticHints,
            _seed_pool: &[Seed],
            budget: &FuzzEpochBudget,
        ) -> Result<EpochResult> {
            let call_idx = self.epoch_calls.get();
            self.epoch_calls.set(call_idx.saturating_add(1));
            let covered_edges = (call_idx as usize).saturating_add(1);
            let finding = if self.emit_unique_finding {
                vec![Finding {
                    engine: "fuzzing".to_string(),
                    finding_type: "reentrancy".to_string(),
                    severity: "high".to_string(),
                    message: format!("mock finding epoch {}", budget.epoch),
                    location: Some(FindingLocation {
                        file: Some("mock.sol".to_string()),
                        start: Some(1),
                        end: Some(2),
                        pc: None,
                        function_id: Some(0),
                        function_name: Some("f".to_string()),
                    }),
                    reproduction: None,
                    signature: format!("sig-{}", budget.epoch),
                    analysis_layer: "runtime".to_string(),
                    evidence_kind: "executor".to_string(),
                    metadata: BTreeMap::new(),
                }]
            } else {
                Vec::new()
            };
            Ok(EpochResult {
                coverage: CoverageSummary {
                    epoch: budget.epoch,
                    covered_edges,
                    total_edges: 16,
                    coverage_pct: (covered_edges as f64 / 16.0) * 100.0,
                    delta_edges: 0,
                    edge_rate: 0.0,
                },
                covered_blocks: vec![(0, call_idx)],
                covered_edges: vec![(0, call_idx, call_idx.saturating_add(1))],
                new_seeds: Vec::new(),
                findings: finding,
                stall: StallMetrics {
                    edge_rate: 0.0,
                    stagnant_epochs: 1,
                    coverage_delta: 0,
                },
                candidate_frontier_goals: vec![self.goal.clone()],
                trace_prefix: Some(TracePrefix {
                    id: format!("mock-prefix-{}", budget.epoch),
                    txs: Vec::new(),
                    last_function_id: Some(0),
                    covered_edges: vec![(9, 10)],
                    last_block: Some(10),
                    distance_hint: Some(1),
                    notes: vec!["mock".to_string()],
                }),
            })
        }
    }

    #[derive(Clone)]
    struct MockSymbolicSuccessEngine {
        attempts_seen: Rc<RefCell<Vec<u32>>>,
        calls: Rc<Cell<u32>>,
    }

    impl MockSymbolicSuccessEngine {
        fn new() -> Self {
            Self {
                attempts_seen: Rc::new(RefCell::new(Vec::new())),
                calls: Rc::new(Cell::new(0)),
            }
        }
    }

    impl SymbolicEngine for MockSymbolicSuccessEngine {
        fn solve(
            &self,
            _ctx: &crate::core::engines::EngineContext<'_>,
            goal: &FrontierGoal,
            _trace_prefix: Option<&TracePrefix>,
            _budget: &SeBudget,
        ) -> Result<SEResult> {
            self.attempts_seen.borrow_mut().push(goal.attempts);
            let call_idx = self.calls.get();
            self.calls.set(call_idx.saturating_add(1));
            Ok(SEResult {
                new_seeds: vec![Seed {
                    id: format!("se-ok-{call_idx}"),
                    txs: vec![TxSeed {
                        function_id: goal.function_id,
                        selector: None,
                        calldata: None,
                        args: vec![call_idx.to_string()],
                        sender: call_idx.to_string(),
                        value: "0".to_string(),
                        env: TxEnv::default(),
                    }],
                    state_snapshot_id: None,
                    score: goal.priority,
                }],
                findings: vec![Finding {
                    engine: "symbolic".to_string(),
                    finding_type: "reentrancy".to_string(),
                    severity: "high".to_string(),
                    message: format!("mock se finding {call_idx}"),
                    location: Some(FindingLocation {
                        file: Some("mock.sol".to_string()),
                        start: Some(1),
                        end: Some(2),
                        pc: None,
                        function_id: Some(goal.function_id),
                        function_name: Some("f".to_string()),
                    }),
                    reproduction: None,
                    signature: format!("se-sig-{call_idx}"),
                    analysis_layer: "runtime".to_string(),
                    evidence_kind: "solver".to_string(),
                    metadata: BTreeMap::new(),
                }],
                solver: crate::core::artifacts::SolverStats {
                    elapsed_ms: 1,
                    states_explored: 1,
                    max_depth_reached: 1,
                    satisfiable_paths: 1,
                },
            })
        }
    }

    #[derive(Clone)]
    struct MockSymbolicUnsolvedEngine {
        attempts_seen: Rc<RefCell<Vec<u32>>>,
    }

    impl MockSymbolicUnsolvedEngine {
        fn new() -> Self {
            Self {
                attempts_seen: Rc::new(RefCell::new(Vec::new())),
            }
        }
    }

    impl SymbolicEngine for MockSymbolicUnsolvedEngine {
        fn solve(
            &self,
            _ctx: &crate::core::engines::EngineContext<'_>,
            goal: &FrontierGoal,
            _trace_prefix: Option<&TracePrefix>,
            _budget: &SeBudget,
        ) -> Result<SEResult> {
            self.attempts_seen.borrow_mut().push(goal.attempts);
            Ok(SEResult {
                new_seeds: Vec::new(),
                findings: Vec::new(),
                solver: crate::core::artifacts::SolverStats {
                    elapsed_ms: 1,
                    states_explored: 1,
                    max_depth_reached: 1,
                    satisfiable_paths: 0,
                },
            })
        }
    }

    fn mock_frontend_output() -> FrontendOutput {
        let mut ast = NormalizedAst::default();
        ast.files.push(SourceFile {
            id: 0,
            path: "mock.sol".to_string(),
            source: "contract C {}".to_string(),
        });
        ast.functions.push(Function {
            id: 0,
            contract: None,
            name: Some("f".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span {
                file: 0,
                start: 0,
                end: 1,
            },
        });
        FrontendOutput {
            mode: FrontendMode::Partial,
            ast,
            compiler: crate::frontend::CompilerInfo {
                compiler_name: "test".to_string(),
                compiler_version: Some("0.8.0".to_string()),
                legacy_omitted_visibility_is_public: false,
            },
        }
    }

    fn test_budget(max_epochs: u32, max_se_assists: u32) -> Budget {
        Budget {
            total_runtime_ms: 5_000,
            max_epochs,
            fuzz_epoch_ms: 10,
            fuzz_iterations_per_epoch: 10,
            se_timeout_ms: 10,
            se_max_states: 100,
            se_max_depth: 4,
            max_se_assists,
            max_seed_injection_per_assist: 2,
            stall_epochs_threshold: 1,
            min_coverage_delta: 1,
        }
    }

    fn goal(id: &str, function_id: u32, priority: f64) -> FrontierGoal {
        FrontierGoal {
            id: id.to_string(),
            function_id,
            function_name: None,
            block_id: Some(0),
            edge_from: None,
            edge_to: None,
            sink_kind: Some("reentrancy".to_string()),
            reason: "test".to_string(),
            priority,
            attempts: 0,
        }
    }

    #[test]
    fn stall_window_uses_windowed_edge_rate() {
        let mut window = VecDeque::new();
        let window_size = 3usize;
        let epsilon = 0.01f64;

        assert!(!update_stall_window(&mut window, 0.02, window_size, epsilon));
        assert!(!update_stall_window(&mut window, 0.005, window_size, epsilon));
        assert!(update_stall_window(&mut window, 0.001, window_size, epsilon));
        assert!(!update_stall_window(&mut window, 0.2, window_size, epsilon));
    }

    #[test]
    fn frontier_selector_respects_backoff_and_attempt_budget() {
        let mut queue = InMemoryFrontierQueue::default();
        let g1 = goal("g1", 1, 10.0);
        let g2 = goal("g2", 2, 8.0);
        queue.push(g1.clone());
        queue.push(g2.clone());

        let mut attempts = HashMap::<String, u32>::new();
        let mut backoff = HashMap::<String, u32>::new();

        // g1 is in backoff until epoch 4, so selector should pick g2 at epoch 3.
        backoff.insert(frontier_goal_key(&g1), 4);
        let selected = select_frontier_goal_for_assist(&mut queue, 3, &mut attempts, &mut backoff, 3)
            .expect("expected eligible goal");
        assert_eq!(selected.id, "g2");

        // Exhaust g1 attempt budget; selector should drop it and return none.
        attempts.insert(frontier_goal_key(&g1), 3);
        let selected_none =
            select_frontier_goal_for_assist(&mut queue, 4, &mut attempts, &mut backoff, 3);
        assert!(selected_none.is_none());
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn assist_backoff_scales_with_attempts() {
        assert_eq!(assist_backoff_epochs(1), 1);
        assert_eq!(assist_backoff_epochs(2), 2);
        assert_eq!(assist_backoff_epochs(3), 4);
        assert_eq!(assist_backoff_epochs(4), 8);
        assert_eq!(assist_backoff_epochs(7), 8);
    }

    #[test]
    fn assist_loop_success_resets_attempts_and_records_findings() {
        let static_engine = MockStaticEngine::new();
        let fuzz_engine = MockFuzzEngine::new(goal("g-s", 0, 5.0), false);
        let symbolic_engine = MockSymbolicSuccessEngine::new();
        let attempts_seen = symbolic_engine.attempts_seen.clone();
        let scheduler = P1Scheduler {
            static_engine,
            fuzz_engine,
            symbolic_engine,
        };

        let budget = test_budget(4, 2);
        let output = mock_frontend_output();
        let run = scheduler
            .run_with_output("mock-success.sol", output, budget.clone())
            .expect("mock run should succeed");

        assert_eq!(run.report.se_assists, 2);
        assert!(run.report.findings_unique >= 1);
        assert_eq!(&*attempts_seen.borrow(), &[1, 1]);
        assert!(report_quality_guard(&run.report, &budget));
    }

    #[test]
    fn assist_loop_unsolved_applies_backoff_and_attempt_cap() {
        let static_engine = MockStaticEngine::new();
        let fuzz_engine = MockFuzzEngine::new(goal("g-u", 0, 5.0), false);
        let symbolic_engine = MockSymbolicUnsolvedEngine::new();
        let attempts_seen = symbolic_engine.attempts_seen.clone();
        let scheduler = P1Scheduler {
            static_engine,
            fuzz_engine,
            symbolic_engine,
        };

        let budget = test_budget(8, 10);
        let output = mock_frontend_output();
        let run = scheduler
            .run_with_output("mock-unsolved.sol", output, budget.clone())
            .expect("mock run should succeed");

        // capped by per-goal attempt budget with backoff schedule
        assert_eq!(run.report.se_assists, 3);
        assert_eq!(&*attempts_seen.borrow(), &[1, 2, 3]);
        assert_eq!(run.report.seeds_injected_by_se, 0);
        assert!(report_quality_guard(&run.report, &budget));
    }

    #[test]
    fn report_quality_guard_rejects_bad_metrics() {
        let mut report = HybridReport {
            run_id: "x".to_string(),
            runtime_ms: 1,
            total_epochs: 2,
            coverage_curve: vec![
                CoverageSummary {
                    epoch: 1,
                    covered_edges: 5,
                    total_edges: 10,
                    coverage_pct: 50.0,
                    delta_edges: 5,
                    edge_rate: 0.5,
                },
                CoverageSummary {
                    epoch: 2,
                    covered_edges: 6,
                    total_edges: 10,
                    coverage_pct: 60.0,
                    delta_edges: 1,
                    edge_rate: 0.1,
                },
            ],
            findings_total: 2,
            findings_unique: 2,
            runtime_findings_total: 2,
            runtime_findings_unique: 2,
            meta_findings_total: 0,
            meta_findings_unique: 0,
            se_assists: 1,
            seeds_injected_by_se: 1,
            se_new_edges_from_injected: 1,
            time_to_first_finding_ms: Some(1),
        };
        let budget = test_budget(2, 2);
        assert!(report_quality_guard(&report, &budget));

        report.findings_unique = 3;
        assert!(!report_quality_guard(&report, &budget));
        report.findings_unique = 2;

        report.se_assists = 3;
        assert!(!report_quality_guard(&report, &budget));
        report.se_assists = 1;

        report.coverage_curve[1].covered_edges = 4; // non-monotonic
        assert!(!report_quality_guard(&report, &budget));
    }
}
