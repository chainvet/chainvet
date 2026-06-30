use std::time::Instant;

use rand::Rng;
use serde::Serialize;
use sha2::{Digest, Sha256};

use chainvet_sa::analysis;
use chainvet_frontend::frontend::FrontendOutput;
use crate::fuzzing::executor;
use crate::fuzzing::generator;
use crate::fuzzing::mutator;
use crate::fuzzing::oracle;
use crate::fuzzing::scheduler::{self, CoverageMap};
use crate::fuzzing::types::{
    build_dependency_map, extract_abis, ContractAbi, Corpus, DependencyMap, Dictionary, FuzzConfig,
    FuzzFinding, FuzzFindingKind, FuzzHybridStats, FuzzReport, FuzzSeverity,
};
use chainvet_core::norm::{FunctionKind, Mutability, NormalizedAst, Span};
use crate::surfaced;
use chainvet_core::util::error::{Error, Result};
use crate::meta;
use chainvet_core::{cfg, ir};

/// Run the fuzzer on a parsed contract.
pub fn run(output: &FrontendOutput, config: &FuzzConfig) -> FuzzReport {
    let mut session = FuzzSession::new(output, config.clone());
    session.run_slice(&[], config.max_iterations, config.max_duration_ms);
    session.finalize()
}

/// Result of one fuzz slice, used by the hybrid orchestrator for stall detection.
#[derive(Debug, Clone, Default)]
pub struct SliceStats {
    pub edges_before: usize,
    pub edges_after: usize,
    pub delta_edges: usize,
    pub findings_total: usize,
    pub new_findings: usize,
}

/// Per-contract loop state carried across slices so coverage and the corpus
/// accumulate over epochs (enabling real cross-epoch stall detection).
struct ContractFuzzState {
    abi_index: usize,
    rng: rand::rngs::StdRng,
    stall_counter: usize,
    last_coverage_count: usize,
    iters_run: usize,
    initialized: bool,
    locked_ether_candidate: bool,
}

/// A persistent fuzzing session. One-time setup (IR/CFG/detectors/dictionary)
/// happens in `new`; `run_slice` runs a chunk of iterations continuing from the
/// carried corpus + coverage (optionally injecting SE-witness seeds first), and
/// `finalize` produces the report. `runner::run` == new + one slice + finalize,
/// so the standalone `--fuzzing` path is behavior-identical.
pub struct FuzzSession<'a> {
    output: &'a FrontendOutput,
    config: FuzzConfig,
    ir_module: ir::IrModule,
    cfgs: Vec<cfg::CfgFunction>,
    abis: Vec<ContractAbi>,
    deps: DependencyMap,
    dictionary: Dictionary,
    static_findings: Vec<analysis::detectors::Finding>,
    meta_findings: Vec<chainvet_core::artifacts::Finding>,
    tod_allowed: std::collections::HashSet<u32>,
    sig_mall_allowed: std::collections::HashSet<u32>,
    total_blocks: usize,
    no_targets: bool,
    start: Instant,
    corpus: Corpus,
    global_coverage: CoverageMap,
    all_findings: Vec<FuzzFinding>,
    /// Trace hashes of findings already seen, so a finding-bearing input is only
    /// force-added to the corpus when it triggers a *novel* finding (otherwise a
    /// constantly-firing oracle, e.g. tx-origin, would explode the corpus).
    seen_finding_hashes: std::collections::HashSet<String>,
    /// Concrete values observed during execution (storage values + mapping keys
    /// like a `proposalId`), fed back into the value pool so later transactions
    /// can use them as arguments — the standard fix for the stateful-fuzzing wall
    /// where `f(runtimeId)` reverts because the fuzzer can't guess `runtimeId`.
    harvested: std::collections::HashSet<u128>,
    contract_states: Vec<ContractFuzzState>,
    seeded_inputs_executed: usize,
}

impl<'a> FuzzSession<'a> {
    /// One-time setup: static pre-pass, IR/CFG, dictionary, per-contract state.
    pub fn new(output: &'a FrontendOutput, config: FuzzConfig) -> Self {
        let start = Instant::now();
        let ast = &output.ast;

        let ir_module = ir::lower_module(ast);
        let cfgs = cfg::build_from_ir(&ir_module);
        let abis = extract_abis(ast, &output.compiler);
        let deps = build_dependency_map(&ir_module, ast);
        let static_call_graph = analysis::build_call_graph(ast);
        let static_taint = analysis::taint::analyze(ast, &cfgs);
        let static_findings =
            analysis::detectors::run_detectors(ast, &static_call_graph, &static_taint);
        let meta_findings =
            meta::analyze_for_engine(output, meta::ConsumerEngine::Fuzzing, &static_findings);
        let (tod_allowed, sig_mall_allowed) = build_static_fp_guards(&static_findings);
        let locked_ether_candidates = build_locked_ether_candidates(ast, &ir_module);
        let dictionary = generator::extract_dictionary(&ir_module);
        let total_blocks: usize = cfgs.iter().map(|c| c.blocks.len()).sum();

        let no_targets = abis.is_empty() || abis.iter().all(|a| a.functions.is_empty());

        // Seed one persistent RNG per contract. Preserves the original per-call
        // seeding (loop rng = seed + 1) so the single-slice path is unchanged.
        let contract_states = abis
            .iter()
            .enumerate()
            .map(|(abi_index, abi)| {
                let rng = match config.seed {
                    Some(seed) => <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(
                        seed.wrapping_add(1),
                    ),
                    None => <rand::rngs::StdRng as rand::SeedableRng>::from_entropy(),
                };
                ContractFuzzState {
                    abi_index,
                    rng,
                    stall_counter: 0,
                    last_coverage_count: 0,
                    iters_run: 0,
                    initialized: false,
                    locked_ether_candidate: locked_ether_candidates
                        .get(&abi.contract_name)
                        .copied()
                        .unwrap_or(false),
                }
            })
            .collect();

        Self {
            output,
            config,
            ir_module,
            cfgs,
            abis,
            deps,
            dictionary,
            static_findings,
            meta_findings,
            tod_allowed,
            sig_mall_allowed,
            total_blocks,
            no_targets,
            start,
            corpus: Corpus::default(),
            global_coverage: CoverageMap::new(),
            all_findings: Vec::new(),
            seen_finding_hashes: std::collections::HashSet::new(),
            harvested: std::collections::HashSet::new(),
            contract_states,
            seeded_inputs_executed: 0,
        }
    }

    /// Total findings discovered so far (pre-finalize, undeduped).
    pub fn raw_findings_len(&self) -> usize {
        self.all_findings.len()
    }

    /// Function ids that have at least one covered block so far. Used by the
    /// hybrid orchestrator to detect which target functions are still unmet.
    pub fn covered_function_ids(&self) -> std::collections::HashSet<u32> {
        self.global_coverage
            .visited_set()
            .into_iter()
            .map(|(function_id, _block)| function_id)
            .collect()
    }

    /// Total distinct edges covered so far.
    pub fn covered_edges(&self) -> usize {
        self.global_coverage.count()
    }

    /// Run one slice: optionally inject `extra_seeds`, then run up to
    /// `max_iterations` per contract continuing from the carried state.
    /// Returns the coverage delta for stall detection.
    pub fn run_slice(
        &mut self,
        extra_seeds: &[crate::fuzzing::types::Individual],
        max_iterations: usize,
        max_duration_ms: Option<u64>,
    ) -> SliceStats {
        let slice_start = Instant::now();
        let edges_before = self.global_coverage.count();
        let findings_before = self.all_findings.len();

        if self.no_targets {
            return SliceStats {
                edges_before,
                edges_after: edges_before,
                delta_edges: 0,
                findings_total: self.all_findings.len(),
                new_findings: 0,
            };
        }

        for idx in 0..self.contract_states.len() {
            if let Some(ms) = max_duration_ms {
                if slice_start.elapsed().as_millis() as u64 >= ms {
                    break;
                }
            }
            let abi_index = self.contract_states[idx].abi_index;

            // First-touch initialization: generate + execute the initial
            // population (this is where config.seed_corpus is folded in).
            if !self.contract_states[idx].initialized {
                let population = generator::generate_initial_population_with_dict(
                    &self.abis[abi_index],
                    &self.deps,
                    &self.config,
                    Some(&self.dictionary),
                );
                self.seeded_inputs_executed +=
                    count_seeded_inputs_for_abi(&self.abis[abi_index], &self.config);
                let locked = self.contract_states[idx].locked_ether_candidate;
                for ind in &population {
                    self.execute_and_absorb(abi_index, ind, locked);
                }
                self.contract_states[idx].initialized = true;
            }

            // Inject SE-witness (or other) seeds applicable to this contract.
            let locked = self.contract_states[idx].locked_ether_candidate;
            for seed in extra_seeds {
                if seed.transactions.is_empty() {
                    continue;
                }
                let applicable = seed.transactions.iter().all(|tx| {
                    self.abis[abi_index]
                        .functions
                        .iter()
                        .any(|f| f.id == tx.function_id)
                });
                if applicable {
                    self.execute_and_absorb(abi_index, &seed.clone(), locked);
                }
            }

            self.run_contract_iterations(idx, max_iterations, &slice_start, max_duration_ms);
        }

        let edges_after = self.global_coverage.count();
        SliceStats {
            edges_before,
            edges_after,
            delta_edges: edges_after.saturating_sub(edges_before),
            findings_total: self.all_findings.len(),
            new_findings: self.all_findings.len().saturating_sub(findings_before),
        }
    }

    /// Execute one individual, run oracles, fold findings + coverage into state.
    fn execute_and_absorb(
        &mut self,
        abi_index: usize,
        ind: &crate::fuzzing::types::Individual,
        locked_ether_candidate: bool,
    ) {
        let trace = executor::execute_individual(
            ind,
            self.output,
            &self.ir_module,
            &self.cfgs,
            &self.abis[abi_index],
            &self.deps,
        );

        // Value feedback: harvest concrete runtime values (mapping keys like a
        // proposalId, and stored values) into the value pool so later txs can use
        // them as arguments. Capped to keep generation cheap.
        if self.dictionary.values.len() < 1024 {
            for (key, val) in &trace.final_state {
                if let Some(index) = key.split('#').nth(1) {
                    if let Ok(v) = index.parse::<u128>() {
                        if v != 0 && self.harvested.insert(v) {
                            self.dictionary.values.push(v);
                        }
                    }
                }
                let stored = val.as_uint();
                if stored != 0 && self.harvested.insert(stored) {
                    self.dictionary.values.push(stored);
                }
            }
        }

        let mut findings = oracle::check_all(&trace, &ind.transactions, Some(&self.output.ast));
        findings.retain(|finding| keep_locked_ether_finding(finding, locked_ether_candidate));

        // New-edge admission keeps the corpus bounded.
        let added =
            scheduler::update_corpus(&mut self.corpus, ind, &trace, &mut self.global_coverage);

        if !findings.is_empty() {
            // Report every finding (deduplicated at finalize), but only force-add
            // this input to the corpus when it triggered a *novel* finding hash —
            // otherwise an oracle that fires on most executions (e.g. tx-origin)
            // would explode the corpus the same way bucket-admission did.
            let mut novel_hashes = Vec::new();
            for finding in &findings {
                if self.seen_finding_hashes.insert(finding.trace_hash.clone()) {
                    novel_hashes.push(finding.trace_hash.clone());
                }
            }
            self.all_findings.extend(findings);
            if !added && !novel_hashes.is_empty() {
                self.corpus
                    .entries
                    .push(crate::fuzzing::types::CorpusEntry {
                        individual: ind.clone(),
                        coverage: trace.coverage.clone(),
                        finding_hashes: novel_hashes,
                    });
            }
        }
    }

    /// The core fuzz loop for one contract, continuing from carried state.
    fn run_contract_iterations(
        &mut self,
        state_idx: usize,
        max_iterations: usize,
        slice_start: &Instant,
        max_duration_ms: Option<u64>,
    ) {
        let abi_index = self.contract_states[state_idx].abi_index;
        for _ in 0..max_iterations {
            if let Some(ms) = max_duration_ms {
                if slice_start.elapsed().as_millis() as u64 >= ms {
                    break;
                }
            }

            let parent = {
                let st = &mut self.contract_states[state_idx];
                match scheduler::select_next(&self.corpus, &mut st.rng) {
                    Some(p) => p.clone(),
                    None => continue,
                }
            };

            let stall_counter = self.contract_states[state_idx].stall_counter;
            let havoc_only = stall_counter >= 100;
            let child = {
                let st = &mut self.contract_states[state_idx];
                if stall_counter >= 150 && st.rng.gen_bool(0.25) {
                    generator::generate_dependency_seed_with_dict(
                        &self.abis[abi_index],
                        &self.deps,
                        &self.config,
                        &mut st.rng,
                        Some(&self.dictionary),
                    )
                    .unwrap_or_else(|| parent.clone())
                } else if st.rng.gen_bool(0.2) && self.corpus.entries.len() >= 2 {
                    let other_idx = st.rng.gen_range(0..self.corpus.entries.len());
                    let other = &self.corpus.entries[other_idx].individual;
                    mutator::crossover(&parent, other, &mut st.rng)
                } else {
                    mutator::mutate_individual_guided_with_dict(
                        &parent,
                        &self.abis[abi_index],
                        &self.deps,
                        &mut st.rng,
                        Some(&self.dictionary),
                        havoc_only,
                    )
                }
            };

            let locked = self.contract_states[state_idx].locked_ether_candidate;
            self.execute_and_absorb(abi_index, &child, locked);

            let st = &mut self.contract_states[state_idx];
            let current_coverage = self.global_coverage.count();
            if current_coverage > st.last_coverage_count {
                st.stall_counter = 0;
                st.last_coverage_count = current_coverage;
            } else {
                st.stall_counter += 1;
            }

            let n = st.iters_run;
            st.iters_run += 1;
            if n % 50 == 0 {
                scheduler::assign_energy(&mut self.corpus, &self.global_coverage);
            }
            if n % 200 == 0 && n > 0 {
                scheduler::minimize_corpus(&mut self.corpus);
            }
        }
    }

    /// Produce the final report (post-processing identical to the old `run`).
    pub fn finalize(mut self) -> FuzzReport {
        let ast = &self.output.ast;
        if self.no_targets {
            return FuzzReport {
                iterations: 0,
                coverage_pct: 0.0,
                total_blocks: self.total_blocks,
                covered_blocks: 0,
                findings: Vec::new(),
                meta_findings: self.meta_findings,
                corpus_size: 0,
                corpus_zero_reason: Some(
                    "no contracts or functions available for fuzzing".to_string(),
                ),
                elapsed_ms: self.start.elapsed().as_millis(),
                hybrid_stats: self.config.hybrid_mode.then(|| FuzzHybridStats {
                    seeded_inputs_provided: self.config.seed_corpus.len(),
                    seeded_inputs_executed: 0,
                }),
            };
        }

        let mut all_findings = std::mem::take(&mut self.all_findings);
        all_findings.extend(detect_shadowing_findings(ast));
        all_findings.extend(detect_public_mint_burn_findings(ast, &self.output.compiler));
        all_findings =
            apply_static_fp_guards(all_findings, &self.tod_allowed, &self.sig_mall_allowed);
        all_findings.extend(inject_static_runtime_backstops(
            &all_findings,
            &self.static_findings,
            ast,
        ));
        all_findings.extend(promoted_runtime_meta_findings(&self.meta_findings));

        let findings = oracle::deduplicate(all_findings);
        let covered_blocks = self.global_coverage.count();
        let coverage_pct = if self.total_blocks > 0 {
            (covered_blocks as f64 / self.total_blocks as f64) * 100.0
        } else {
            0.0
        };

        FuzzReport {
            iterations: self.config.max_iterations,
            coverage_pct,
            total_blocks: self.total_blocks,
            covered_blocks,
            findings,
            meta_findings: self.meta_findings,
            corpus_size: self.corpus.entries.len(),
            corpus_zero_reason: zero_corpus_reason(&self.abis, &self.corpus),
            elapsed_ms: self.start.elapsed().as_millis(),
            hybrid_stats: self.config.hybrid_mode.then(|| FuzzHybridStats {
                seeded_inputs_provided: self.config.seed_corpus.len(),
                seeded_inputs_executed: self.seeded_inputs_executed,
            }),
        }
    }
}

fn zero_corpus_reason(abis: &[ContractAbi], corpus: &Corpus) -> Option<String> {
    if !corpus.entries.is_empty() {
        return None;
    }
    let contract_count = abis.len();
    let function_count = abis.iter().map(|abi| abi.functions.len()).sum::<usize>();
    let callable_count = abis
        .iter()
        .flat_map(|abi| abi.functions.iter())
        .filter(|func| func.is_fuzz_callable())
        .count();
    Some(format!(
        "no callable entrypoints generated (contracts={contract_count}, functions={function_count}, callable={callable_count})"
    ))
}

fn promoted_runtime_meta_findings(
    meta_findings: &[chainvet_core::artifacts::Finding],
) -> Vec<FuzzFinding> {
    crate::meta::runtime_promotions(meta_findings)
        .into_iter()
        .filter_map(|finding| {
            let kind = match finding.finding_type.as_str() {
                "shadowing" => FuzzFindingKind::Shadowing,
                _ => return None,
            };
            Some(FuzzFinding {
                span: None,
                kind,
                severity: match finding.severity.as_str() {
                    "high" => FuzzSeverity::High,
                    "medium" => FuzzSeverity::Medium,
                    _ => FuzzSeverity::Low,
                },
                message: format!(
                    "Runtime backstop from {}: {}",
                    finding.evidence_kind, finding.message
                ),
                tx_sequence: Vec::new(),
                trace_hash: hash_local_finding(
                    "runtime-meta-backstop",
                    format!(
                        "{}:{}",
                        finding.finding_type,
                        finding
                            .location
                            .as_ref()
                            .and_then(|location| location.file.as_deref())
                            .unwrap_or("<unknown>")
                    )
                    .as_str(),
                ),
            })
        })
        .collect()
}

fn detect_shadowing_findings(ast: &NormalizedAst) -> Vec<FuzzFinding> {
    let mut by_contract: std::collections::HashMap<u32, std::collections::HashSet<String>> =
        std::collections::HashMap::new();
    for state_var in &ast.state_vars {
        by_contract
            .entry(state_var.contract)
            .or_default()
            .insert(state_var.name.clone());
    }

    let mut findings = Vec::new();
    for function in &ast.functions {
        let Some(contract_id) = function.contract else {
            continue;
        };
        let Some(state_names) = by_contract.get(&contract_id) else {
            continue;
        };
        for param in &function.params {
            if state_names.contains(param) {
                let function_name = function
                    .name
                    .as_deref()
                    .filter(|name| !name.is_empty())
                    .unwrap_or("<anonymous>");
                let detail = format!("{}:{}", function.id, param);
                findings.push(FuzzFinding {
                    span: None,
                    kind: FuzzFindingKind::Shadowing,
                    severity: FuzzSeverity::Medium,
                    message: format!(
                        "Parameter '{}' in function '{}' shadows a state variable with the same name",
                        param, function_name
                    ),
                    tx_sequence: Vec::new(),
                    trace_hash: hash_local_finding("shadowing", &detail),
                });
            }
        }
    }

    findings
}

fn detect_public_mint_burn_findings(
    ast: &NormalizedAst,
    compiler: &chainvet_frontend::frontend::CompilerInfo,
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    for function in &ast.functions {
        let Some(name) = function.name.as_deref() else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if lower != "mint" && lower != "burn" {
            continue;
        }
        if !chainvet_frontend::frontend::is_public_entrypoint(function, compiler)
            || function.kind != FunctionKind::Function
        {
            continue;
        }
        let detail = format!("{}:{}", function.id, lower);
        findings.push(FuzzFinding {
            span: None,
            kind: FuzzFindingKind::PublicMintBurn,
            severity: FuzzSeverity::High,
            message: format!(
                "Public {} function '{}' may allow unauthorized supply manipulation",
                lower, name
            ),
            tx_sequence: Vec::new(),
            trace_hash: hash_local_finding("public-mint-burn", &detail),
        });
    }
    findings
}

fn hash_local_finding(kind: &str, detail: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update(detail.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn inject_static_runtime_backstops(
    runtime_findings: &[FuzzFinding],
    static_findings: &[analysis::detectors::Finding],
    ast: &NormalizedAst,
) -> Vec<FuzzFinding> {
    let runtime_reentrancy_fns = runtime_findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind,
                FuzzFindingKind::Reentrancy | FuzzFindingKind::ReentrancyHeuristic
            )
        })
        .filter_map(|finding| extract_function_id_from_message(finding.message.as_str()))
        .collect::<std::collections::HashSet<_>>();
    let runtime_access_like_fns = runtime_findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind,
                FuzzFindingKind::AccessControl | FuzzFindingKind::WrongConstructorName
            )
        })
        .filter_map(|finding| extract_function_id_from_message(finding.message.as_str()))
        .collect::<std::collections::HashSet<_>>();
    let runtime_dos_fns = runtime_findings
        .iter()
        .filter(|finding| finding.kind == FuzzFindingKind::DosWithFailedCall)
        .filter_map(|finding| extract_function_id_from_message(finding.message.as_str()))
        .collect::<std::collections::HashSet<_>>();
    let runtime_dos_block_gas_limit_fns = runtime_findings
        .iter()
        .filter(|finding| finding.kind == FuzzFindingKind::DosBlockGasLimit)
        .filter_map(|finding| extract_function_id_from_message(finding.message.as_str()))
        .collect::<std::collections::HashSet<_>>();
    let runtime_weak_prng_fns = runtime_findings
        .iter()
        .filter(|finding| finding.kind == FuzzFindingKind::WeakPRNG)
        .filter_map(|finding| extract_function_id_from_message(finding.message.as_str()))
        .collect::<std::collections::HashSet<_>>();
    let runtime_timestamp_dependency_fns = runtime_findings
        .iter()
        .filter(|finding| finding.kind == FuzzFindingKind::TimestampDependency)
        .filter_map(|finding| extract_function_id_from_message(finding.message.as_str()))
        .collect::<std::collections::HashSet<_>>();
    let runtime_locked_ether_fns = runtime_findings
        .iter()
        .filter(|finding| finding.kind == FuzzFindingKind::LockedEther)
        .filter_map(|finding| extract_function_id_from_message(finding.message.as_str()))
        .collect::<std::collections::HashSet<_>>();
    let runtime_unchecked_call_fns = runtime_findings
        .iter()
        .filter(|finding| finding.kind == FuzzFindingKind::UncheckedCall)
        .filter_map(|finding| extract_function_id_from_message(finding.message.as_str()))
        .collect::<std::collections::HashSet<_>>();

    let mut out = Vec::new();
    let mut injected = std::collections::HashSet::<(&'static str, u32)>::new();

    for finding in static_findings.iter().filter(|finding| {
        matches!(
            finding.kind,
            analysis::detectors::FindingKind::ReentrancyNegativeEvents
                | analysis::detectors::FindingKind::ReentrancyTransfer
                | analysis::detectors::FindingKind::ReentrancySameEffect
                | analysis::detectors::FindingKind::ReentrancyEthTransfer
                | analysis::detectors::FindingKind::ReentrancyNoEthTransfer
        )
    }) {
        let function_id = finding.function.unwrap_or(0);
        if runtime_reentrancy_fns.contains(&function_id)
            || function_uses_only_stipend_external_calls(ast, function_id)
            || function_is_checked_selector_low_level_wrapper(ast, function_id)
            || !injected.insert(("reentrancy", function_id))
        {
            continue;
        }
        let function_name = ast
            .functions
            .get(function_id as usize)
            .and_then(|f| f.name.as_deref())
            .unwrap_or("<unknown>");
        out.push(FuzzFinding {
                    span: None,
            kind: FuzzFindingKind::ReentrancyHeuristic,
            severity: FuzzSeverity::Low,
            message: format!(
                "Static-guided runtime backstop: function {} ('{}') has static reentrancy signal but runtime callback/store evidence was not captured",
                function_id, function_name
            ),
            tx_sequence: Vec::new(),
            trace_hash: hash_local_finding("runtime-backstop-reentrancy", &function_id.to_string()),
        });
    }

    for finding in static_findings
        .iter()
        .filter(|finding| finding.kind == analysis::detectors::FindingKind::DosWithFailedCall)
    {
        let function_id = finding.function.unwrap_or(0);
        if runtime_dos_fns.contains(&function_id)
            || !function_has_value_moving_low_level_call(ast, function_id)
            || function_is_checked_selector_low_level_wrapper(ast, function_id)
            || !injected.insert(("dos", function_id))
        {
            continue;
        }
        let function_name = ast
            .functions
            .get(function_id as usize)
            .and_then(|f| f.name.as_deref())
            .unwrap_or("<unknown>");
        out.push(FuzzFinding {
                    span: None,
            kind: FuzzFindingKind::DosWithFailedCall,
            severity: FuzzSeverity::Low,
            message: format!(
                "Static-guided runtime backstop: function {} ('{}') has static DoS-with-failed-call signal but runtime loop/call-failure evidence was not captured",
                function_id, function_name
            ),
            tx_sequence: Vec::new(),
            trace_hash: hash_local_finding("runtime-backstop-dos-with-failed-call", &function_id.to_string()),
        });
    }

    let dos_functions_with_backstop = out
        .iter()
        .filter(|finding| finding.kind == FuzzFindingKind::DosWithFailedCall)
        .filter_map(|finding| extract_function_id_from_message(finding.message.as_str()))
        .chain(runtime_dos_fns.iter().copied())
        .collect::<std::collections::HashSet<_>>();

    for finding in static_findings
        .iter()
        .filter(|finding| finding.kind == analysis::detectors::FindingKind::DosBlockGasLimit)
    {
        let function_id = finding.function.unwrap_or(0);
        if runtime_dos_block_gas_limit_fns.contains(&function_id)
            || !dos_functions_with_backstop.contains(&function_id)
            || !function_source_has_dynamic_gas_loop(ast, function_id)
            || !injected.insert(("dos-block-gas-limit", function_id))
        {
            continue;
        }
        let function_name = ast
            .functions
            .get(function_id as usize)
            .and_then(|f| f.name.as_deref())
            .unwrap_or("<unknown>");
        out.push(FuzzFinding {
                    span: None,
            kind: FuzzFindingKind::DosBlockGasLimit,
            severity: FuzzSeverity::Low,
            message: format!(
                "Static-guided runtime backstop: function {} ('{}') reached a loop/call DoS path and also has dynamic (`.length`/gas) loop bounds",
                function_id, function_name
            ),
            tx_sequence: Vec::new(),
            trace_hash: hash_local_finding(
                "runtime-backstop-dos-block-gas-limit",
                &function_id.to_string(),
            ),
        });
    }

    for finding in static_findings
        .iter()
        .filter(|finding| finding.kind == analysis::detectors::FindingKind::WeakPrng)
    {
        let function_id = finding.function.unwrap_or(0);
        let function_name = ast
            .functions
            .get(function_id as usize)
            .and_then(|f| f.name.as_deref())
            .unwrap_or("<unknown>");
        if !runtime_timestamp_dependency_fns.contains(&function_id)
            && function_uses_timestamp_seeded_prng(ast, function_id)
            && injected.insert(("timestamp-dependency", function_id))
        {
            out.push(FuzzFinding {
                    span: None,
                kind: FuzzFindingKind::TimestampDependency,
                severity: FuzzSeverity::Low,
                message: format!(
                    "Static-guided runtime backstop: function {} ('{}') mixes block-derived randomness with a state variable seeded from block.timestamp/now",
                    function_id, function_name
                ),
                tx_sequence: Vec::new(),
                trace_hash: hash_local_finding(
                    "runtime-backstop-timestamp-dependency",
                    &function_id.to_string(),
                ),
            });
        }
        if runtime_weak_prng_fns.contains(&function_id)
            || !injected.insert(("weak-prng", function_id))
        {
            continue;
        }
        out.push(FuzzFinding {
                    span: None,
            kind: FuzzFindingKind::WeakPRNG,
            severity: FuzzSeverity::Low,
            message: format!(
                "Static-guided runtime backstop: function {} ('{}') has static weak-PRNG signal but runtime block-number/blockhash execution evidence was not captured",
                function_id, function_name
            ),
            tx_sequence: Vec::new(),
            trace_hash: hash_local_finding("runtime-backstop-weak-prng", &function_id.to_string()),
        });
    }

    for finding in static_findings.iter().filter(|finding| {
        matches!(
            finding.kind,
            analysis::detectors::FindingKind::LockedEther
                | analysis::detectors::FindingKind::ForceEtherBalanceCheck
        )
    }) {
        let function_id = finding.function.unwrap_or(0);
        if runtime_locked_ether_fns.contains(&function_id)
            || !injected.insert(("locked-ether", function_id))
        {
            continue;
        }
        let function_name = ast
            .functions
            .get(function_id as usize)
            .and_then(|f| f.name.as_deref())
            .unwrap_or("<unknown>");
        out.push(FuzzFinding {
                    span: None,
            kind: FuzzFindingKind::LockedEther,
            severity: FuzzSeverity::Low,
            message: format!(
                "Static-guided runtime backstop: function {} ('{}') has static locked-Ether signal but runtime deposit/withdraw evidence was not captured",
                function_id, function_name
            ),
            tx_sequence: Vec::new(),
            trace_hash: hash_local_finding("runtime-backstop-locked-ether", &function_id.to_string()),
        });
    }

    for finding in static_findings
        .iter()
        .filter(|finding| finding.kind == analysis::detectors::FindingKind::UnusedReturnValue)
    {
        let function_id = finding.function.unwrap_or(0);
        if runtime_unchecked_call_fns.contains(&function_id)
            || function_is_checked_selector_low_level_wrapper(ast, function_id)
            || !injected.insert(("unchecked-call", function_id))
        {
            continue;
        }
        let function_name = ast
            .functions
            .get(function_id as usize)
            .and_then(|f| f.name.as_deref())
            .unwrap_or("<unknown>");
        out.push(FuzzFinding {
                    span: None,
            kind: FuzzFindingKind::UncheckedCall,
            severity: FuzzSeverity::Low,
            message: format!(
                "Static-guided runtime backstop: function {} ('{}') has static unchecked-call signal but runtime return-value tracking evidence was not captured",
                function_id, function_name
            ),
            tx_sequence: Vec::new(),
            trace_hash: hash_local_finding("runtime-backstop-unchecked-call", &function_id.to_string()),
        });
    }

    for finding in static_findings.iter().filter(|finding| {
        finding.kind == analysis::detectors::FindingKind::UninitializedPermissionCheck
    }) {
        let function_id = finding.function.unwrap_or(0);
        if runtime_access_like_fns.contains(&function_id)
            || !injected.insert(("access-control", function_id))
        {
            continue;
        }
        let function_name = ast
            .functions
            .get(function_id as usize)
            .and_then(|f| f.name.as_deref())
            .unwrap_or("<unknown>");
        out.push(FuzzFinding {
                    span: None,
            kind: FuzzFindingKind::AccessControl,
            severity: FuzzSeverity::Low,
            message: format!(
                "Static-guided runtime backstop: function {} ('{}') is publicly reinitializable or lacks a permission check on authority setup",
                function_id, function_name
            ),
            tx_sequence: Vec::new(),
            trace_hash: hash_local_finding(
                "runtime-backstop-access-control-init",
                &function_id.to_string(),
            ),
        });
    }

    out
}

fn build_static_fp_guards(
    findings: &[analysis::detectors::Finding],
) -> (
    std::collections::HashSet<u32>,
    std::collections::HashSet<u32>,
) {
    let mut tod_allowed = std::collections::HashSet::new();
    let mut sig_mall_allowed = std::collections::HashSet::new();
    for finding in findings {
        let Some(function_id) = finding.function else {
            continue;
        };
        match finding.kind {
            analysis::detectors::FindingKind::TransactionOrderDependency => {
                tod_allowed.insert(function_id);
            }
            analysis::detectors::FindingKind::SignatureMalleability => {
                sig_mall_allowed.insert(function_id);
            }
            _ => {}
        }
    }
    (tod_allowed, sig_mall_allowed)
}

fn apply_static_fp_guards(
    findings: Vec<FuzzFinding>,
    tod_allowed: &std::collections::HashSet<u32>,
    sig_mall_allowed: &std::collections::HashSet<u32>,
) -> Vec<FuzzFinding> {
    findings
        .into_iter()
        .filter(|finding| match finding.kind {
            FuzzFindingKind::TransactionOrderDependency => {
                extract_function_id_from_message(finding.message.as_str())
                    .map(|id| tod_allowed.contains(&id))
                    .unwrap_or(false)
            }
            FuzzFindingKind::SignatureMalleability => {
                extract_function_id_from_message(finding.message.as_str())
                    .map(|id| sig_mall_allowed.contains(&id))
                    .unwrap_or(false)
            }
            _ => true,
        })
        .collect()
}

fn extract_function_id_from_message(message: &str) -> Option<u32> {
    let tokens = message.split_whitespace().collect::<Vec<_>>();
    for window in tokens.windows(2) {
        if window[0] == "function" {
            if let Ok(id) = window[1]
                .trim_matches(|c: char| !c.is_ascii_digit())
                .parse::<u32>()
            {
                return Some(id);
            }
        }
    }
    None
}

fn function_source_has_dynamic_gas_loop(ast: &NormalizedAst, function_id: u32) -> bool {
    let Some(source_lower) = function_source_lower(ast, function_id) else {
        return false;
    };
    let has_loop = source_lower.contains("for(")
        || source_lower.contains("for (")
        || source_lower.contains("while(")
        || source_lower.contains("while (");
    let has_dynamic_bound = source_lower.contains(".length")
        || source_lower.contains("msg.gas")
        || source_lower.contains("gasleft(");
    has_loop && has_dynamic_bound
}

fn function_has_value_moving_low_level_call(ast: &NormalizedAst, function_id: u32) -> bool {
    let Some(source_lower) = function_source_lower(ast, function_id) else {
        return false;
    };
    source_lower.contains(".call.value")
        || source_lower.contains(".send(")
        || source_lower.contains(".send (")
        || source_lower.contains(".transfer(")
        || source_lower.contains(".transfer (")
}

fn function_is_checked_selector_low_level_wrapper(ast: &NormalizedAst, function_id: u32) -> bool {
    let Some(source_lower) = function_source_lower(ast, function_id) else {
        return false;
    };
    let has_checked_call = source_lower.contains("require(")
        || source_lower.contains("require (")
        || source_lower.contains("assert(")
        || source_lower.contains("assert (");
    let has_low_level_call = source_lower.contains(".call(")
        || source_lower.contains(".call (")
        || source_lower.contains(".call.value");
    let has_selector_payload = source_lower.contains("bytes4(sha3(")
        || source_lower.contains("bytes4(keccak256(")
        || source_lower.contains("abi.encodewithsignature(")
        || source_lower.contains("abi.encodewithselector(");
    has_checked_call && has_low_level_call && has_selector_payload
}

fn function_uses_only_stipend_external_calls(ast: &NormalizedAst, function_id: u32) -> bool {
    let Some(source_lower) = function_source_lower(ast, function_id) else {
        return false;
    };
    let has_stipend_call = source_lower.contains(".send(")
        || source_lower.contains(".send (")
        || source_lower.contains(".transfer(")
        || source_lower.contains(".transfer (");
    let has_callback_capable_call = source_lower.contains(".call(")
        || source_lower.contains(".call (")
        || source_lower.contains(".call.value")
        || source_lower.contains(".delegatecall")
        || source_lower.contains(".callcode");
    has_stipend_call && !has_callback_capable_call
}

fn function_uses_timestamp_seeded_prng(ast: &NormalizedAst, function_id: u32) -> bool {
    let Some(function) = ast_function_by_id(ast, function_id) else {
        return false;
    };
    let Some(contract_id) = function.contract else {
        return false;
    };
    let Some(source_lower) = function_source_lower(ast, function_id) else {
        return false;
    };
    let has_block_randomness = source_lower.contains("block.number")
        || source_lower.contains("blockhash(")
        || source_lower.contains("block.blockhash(");
    if !has_block_randomness {
        return false;
    }
    if source_lower.contains("block.timestamp") || source_lower.contains("now") {
        return true;
    }
    ast.state_vars
        .iter()
        .filter(|state_var| state_var.contract == contract_id)
        .filter_map(|state_var| {
            let init_lower = state_var_initializer_lower(ast, state_var.span)?;
            if init_lower.contains("block.timestamp") || init_lower.contains("now") {
                Some(state_var.name.to_ascii_lowercase())
            } else {
                None
            }
        })
        .any(|state_var_name| source_lower.contains(&state_var_name))
}

fn function_source_lower(ast: &NormalizedAst, function_id: u32) -> Option<String> {
    let function = ast_function_by_id(ast, function_id)?;
    let file = ast.files.get(function.span.file as usize)?;
    Some(
        file.source
            .get(function.span.start as usize..function.span.end as usize)
            .filter(|source| !source.is_empty())
            .unwrap_or(file.source.as_str())
            .to_ascii_lowercase(),
    )
}

fn ast_function_by_id(ast: &NormalizedAst, function_id: u32) -> Option<&chainvet_core::norm::Function> {
    ast.functions
        .iter()
        .find(|function| function.id == function_id)
}

fn state_var_initializer_lower(ast: &NormalizedAst, span: Span) -> Option<String> {
    let file = ast.files.get(span.file as usize)?;
    let source = file.source.get(span.start as usize..span.end as usize)?;
    let (_, rhs): (&str, &str) = source.split_once('=')?;
    Some(rhs.to_ascii_lowercase())
}

fn build_locked_ether_candidates(
    ast: &NormalizedAst,
    ir_module: &ir::IrModule,
) -> std::collections::HashMap<String, bool> {
    let mut has_payable_function: std::collections::HashMap<u32, bool> =
        std::collections::HashMap::new();
    let mut has_ether_send_path: std::collections::HashMap<u32, bool> =
        std::collections::HashMap::new();

    for function in &ast.functions {
        let Some(contract_id) = function.contract else {
            continue;
        };
        if function.kind == FunctionKind::Function && function.mutability == Mutability::Payable {
            has_payable_function.insert(contract_id, true);
        }
    }

    for function in &ir_module.functions {
        let Some(ast_fn) = ast.functions.get(function.id as usize) else {
            continue;
        };
        let Some(contract_id) = ast_fn.contract else {
            continue;
        };
        if ir_function_has_ether_send(function) {
            has_ether_send_path.insert(contract_id, true);
        }
    }

    let mut candidates = std::collections::HashMap::new();
    for contract in &ast.contracts {
        let payable = has_payable_function
            .get(&contract.id)
            .copied()
            .unwrap_or(false);
        let has_send = has_ether_send_path
            .get(&contract.id)
            .copied()
            .unwrap_or(false);
        candidates.insert(contract.name.clone(), payable && !has_send);
    }
    candidates
}

fn keep_locked_ether_finding(finding: &FuzzFinding, locked_ether_candidate: bool) -> bool {
    if finding.kind != FuzzFindingKind::LockedEther {
        return true;
    }
    locked_ether_candidate || finding.message.starts_with("Forced-Ether invariant risk:")
}

fn ir_function_has_ether_send(function: &ir::IrFunction) -> bool {
    function.blocks.iter().any(|block| {
        block.instrs.iter().any(|instr| {
            let ir::IrInstr::Call {
                callee, options, ..
            } = instr
            else {
                return false;
            };
            let callee_name = match callee {
                chainvet_core::ir::IrValue::Var(chainvet_core::ir::IrVar::Named(name)) => name.to_ascii_lowercase(),
                chainvet_core::ir::IrValue::Var(chainvet_core::ir::IrVar::Temp(id)) => format!("tmp_{id}"),
                chainvet_core::ir::IrValue::Literal(lit) => lit.value.to_ascii_lowercase(),
                chainvet_core::ir::IrValue::Unknown => String::new(),
            };
            let has_value = options
                .iter()
                .any(|opt| matches!(opt, chainvet_core::ir::IrCallOption::Value(_)));
            has_value
                || callee_name == "send"
                || callee_name == "transfer"
                || callee_name.ends_with(".send")
                || callee_name.ends_with(".transfer")
        })
    })
}

// `fuzz_contract` was absorbed into `FuzzSession::run_slice` /
// `run_contract_iterations` so the loop state (corpus, coverage, rng, stall
// counter) can persist across epochs for the hybrid orchestrator.

fn count_seeded_inputs_for_abi(abi: &ContractAbi, config: &FuzzConfig) -> usize {
    let abi_function_ids = abi
        .functions
        .iter()
        .map(|function| function.id)
        .collect::<std::collections::HashSet<_>>();
    config
        .seed_corpus
        .iter()
        .filter(|seed| {
            !seed.transactions.is_empty()
                && seed
                    .transactions
                    .iter()
                    .all(|tx| abi_function_ids.contains(&tx.function_id))
        })
        .count()
}

/// Print a text report of fuzz results, grouped by taxonomy category.
pub fn print_report(report: &FuzzReport) {
    let surfaced = surfaced::surface_findings(
        report.findings.iter().map(fuzz_runtime_candidate).collect(),
        report
            .meta_findings
            .iter()
            .map(fuzz_meta_candidate)
            .collect(),
    );
    println!("=== Fuzzing Report ===");
    println!(
        "iterations: {}, corpus: {}, time: {}ms",
        report.iterations, report.corpus_size, report.elapsed_ms
    );
    println!(
        "coverage: {}/{} blocks ({:.1}%)",
        report.covered_blocks, report.total_blocks, report.coverage_pct
    );
    if let Some(stats) = &report.hybrid_stats {
        println!(
            "hybrid_seeds: provided={}, executed={}",
            stats.seeded_inputs_provided, stats.seeded_inputs_executed
        );
    }
    if let Some(reason) = &report.corpus_zero_reason {
        println!("corpus_zero_reason: {reason}");
    }
    println!("runtime_findings: {}", surfaced.runtime_findings.len());
    println!("runtime_findings_raw: {}", report.findings.len());
    println!(
        "runtime_types_raw: {}",
        machine_count_field(&count_raw_fuzz_findings(&report.findings))
    );
    println!("meta_findings: {}", surfaced.meta_findings.len());
    println!("meta_findings_raw: {}", report.meta_findings.len());
    println!(
        "meta_types_raw: {}",
        machine_count_field(&count_raw_meta_findings(&report.meta_findings))
    );

    if surfaced.runtime_findings.is_empty() {
        println!("  (no vulnerabilities detected)");
    } else {
        let mut by_category: std::collections::BTreeMap<&str, Vec<&surfaced::SurfacedFinding>> =
            std::collections::BTreeMap::new();
        for finding in &surfaced.runtime_findings {
            by_category
                .entry(finding.category.as_str())
                .or_default()
                .push(finding);
        }

        for (category, findings) in &by_category {
            println!("\n  [{}] {} finding(s):", category, findings.len());
            for (idx, finding) in findings.iter().enumerate() {
                println!(
                    "    {}. [{}] [{}] [{}] {}",
                    idx + 1,
                    finding.kind,
                    finding.severity,
                    finding.confidence.as_deref().unwrap_or("unknown"),
                    finding.message
                );
                if let Some(function_id) = finding.function_id {
                    println!(
                        "       function: {} ({})",
                        function_id,
                        finding.function_name.as_deref().unwrap_or("<unknown>")
                    );
                }
                if let Some(file) = &finding.file {
                    println!(
                        "       location: {}:{}-{}",
                        file,
                        finding.start.unwrap_or(0),
                        finding.end.unwrap_or(0)
                    );
                }
            }
        }
    }

    if !surfaced.meta_findings.is_empty() {
        println!("\n  [Meta] {} finding(s):", surfaced.meta_findings.len());
        for (idx, finding) in surfaced.meta_findings.iter().enumerate() {
            println!(
                "    {}. kind={} severity={} evidence={} {}",
                idx + 1,
                finding.kind,
                finding.severity,
                finding.evidence_kind.as_deref().unwrap_or("meta"),
                finding.message
            );
            if let Some(file) = &finding.file {
                println!(
                    "       location: {}:{}-{}",
                    file,
                    finding.start.unwrap_or(0),
                    finding.end.unwrap_or(0)
                );
            }
        }
    }

    println!("=== End Report ===");
}

#[derive(Debug, Serialize)]
struct JsonFuzzTransaction {
    function_id: u32,
    sender: usize,
    value: u128,
    args: Vec<String>,
}

#[derive(Debug, Serialize)]
struct JsonFuzzFinding {
    kind: String,
    canonical_kind: String,
    category: String,
    severity: String,
    confidence: String,
    message: String,
    trace_hash: String,
    tx_sequence: Vec<JsonFuzzTransaction>,
}

#[derive(Debug, Serialize)]
struct JsonFuzzReport {
    iterations: usize,
    coverage_pct: f64,
    total_blocks: usize,
    covered_blocks: usize,
    corpus_size: usize,
    corpus_zero_reason: Option<String>,
    elapsed_ms: u128,
    hybrid_stats: Option<JsonFuzzHybridStats>,
    finding_count_raw: usize,
    suppressed_findings: usize,
    finding_counts: Vec<surfaced::SurfacedCount>,
    findings: Vec<surfaced::SurfacedFinding>,
    findings_raw: Vec<JsonFuzzFinding>,
    meta_finding_count_raw: usize,
    suppressed_meta_findings: usize,
    meta_finding_counts: Vec<surfaced::SurfacedCount>,
    meta_findings: Vec<surfaced::SurfacedFinding>,
    meta_findings_raw: Vec<chainvet_core::artifacts::Finding>,
}

#[derive(Debug, Serialize)]
struct JsonFuzzHybridStats {
    seeded_inputs_provided: usize,
    seeded_inputs_executed: usize,
}

pub fn print_report_json(report: &FuzzReport) -> Result<()> {
    let payload = serde_json::to_string_pretty(&json_report(report))
        .map_err(|err| Error::msg(format!("failed to encode fuzzing JSON report: {err}")))?;
    println!("{payload}");
    Ok(())
}

fn json_report(report: &FuzzReport) -> JsonFuzzReport {
    let surfaced = surfaced::surface_findings(
        report.findings.iter().map(fuzz_runtime_candidate).collect(),
        report
            .meta_findings
            .iter()
            .map(fuzz_meta_candidate)
            .collect(),
    );
    JsonFuzzReport {
        iterations: report.iterations,
        coverage_pct: report.coverage_pct,
        total_blocks: report.total_blocks,
        covered_blocks: report.covered_blocks,
        corpus_size: report.corpus_size,
        corpus_zero_reason: report.corpus_zero_reason.clone(),
        elapsed_ms: report.elapsed_ms,
        hybrid_stats: report
            .hybrid_stats
            .as_ref()
            .map(|stats| JsonFuzzHybridStats {
                seeded_inputs_provided: stats.seeded_inputs_provided,
                seeded_inputs_executed: stats.seeded_inputs_executed,
            }),
        finding_count_raw: report.findings.len(),
        suppressed_findings: surfaced.suppressed_runtime_findings,
        finding_counts: surfaced.runtime_finding_counts,
        findings: surfaced.runtime_findings,
        findings_raw: report
            .findings
            .iter()
            .map(|finding| JsonFuzzFinding {
                kind: finding.kind.as_str().to_string(),
                canonical_kind: finding.kind.canonical_str().to_string(),
                category: finding.kind.category().to_string(),
                severity: finding.severity.as_str().to_string(),
                confidence: finding.kind.confidence().as_str().to_string(),
                message: finding.message.clone(),
                trace_hash: finding.trace_hash.clone(),
                tx_sequence: finding
                    .tx_sequence
                    .iter()
                    .map(|tx| JsonFuzzTransaction {
                        function_id: tx.function_id,
                        sender: tx.sender,
                        value: tx.value,
                        args: tx
                            .args
                            .iter()
                            .map(|arg| arg.as_uint().to_string())
                            .collect(),
                    })
                    .collect(),
            })
            .collect(),
        meta_finding_count_raw: report.meta_findings.len(),
        suppressed_meta_findings: surfaced.suppressed_meta_findings,
        meta_finding_counts: surfaced.meta_finding_counts,
        meta_findings: surfaced.meta_findings,
        meta_findings_raw: report.meta_findings.clone(),
    }
}

fn fuzz_runtime_candidate(finding: &FuzzFinding) -> surfaced::FindingCandidate {
    surfaced::FindingCandidate {
        kind: finding.kind.as_str().to_string(),
        canonical_kind: finding.kind.canonical_str().to_string(),
        category: finding.kind.category().to_string(),
        severity: finding.severity.as_str().to_string(),
        confidence: Some(finding.kind.confidence().as_str().to_string()),
        message: finding.message.clone(),
        file: None,
        start: None,
        end: None,
        function_id: extract_function_id_from_message(finding.message.as_str()),
        function_name: None,
        analysis_layer: "runtime".to_string(),
        evidence_kind: Some("executor".to_string()),
    }
}

fn fuzz_meta_candidate(finding: &chainvet_core::artifacts::Finding) -> surfaced::FindingCandidate {
    surfaced::FindingCandidate {
        kind: finding.finding_type.clone(),
        canonical_kind: surfaced::canonicalize_kind(&finding.finding_type),
        category: finding
            .metadata
            .get("category")
            .cloned()
            .unwrap_or_else(|| {
                surfaced::default_category_for_kind(&finding.finding_type).to_string()
            }),
        severity: finding.severity.clone(),
        confidence: None,
        message: finding.message.clone(),
        file: finding
            .location
            .as_ref()
            .and_then(|location| location.file.clone()),
        start: finding
            .location
            .as_ref()
            .and_then(|location| location.start),
        end: finding.location.as_ref().and_then(|location| location.end),
        function_id: finding
            .location
            .as_ref()
            .and_then(|location| location.function_id),
        function_name: finding
            .location
            .as_ref()
            .and_then(|location| location.function_name.clone()),
        analysis_layer: "meta".to_string(),
        evidence_kind: Some(finding.evidence_kind.clone()),
    }
}

fn count_raw_fuzz_findings(findings: &[FuzzFinding]) -> std::collections::BTreeMap<String, usize> {
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for finding in findings {
        *counts
            .entry(finding.kind.canonical_str().to_string())
            .or_insert(0) += 1;
    }
    counts
}

fn count_raw_meta_findings(
    findings: &[chainvet_core::artifacts::Finding],
) -> std::collections::BTreeMap<String, usize> {
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for finding in findings {
        let canonical = surfaced::canonicalize_kind(&finding.finding_type);
        if canonical.is_empty() {
            continue;
        }
        *counts.entry(canonical).or_insert(0) += 1;
    }
    counts
}

fn machine_count_field(counts: &std::collections::BTreeMap<String, usize>) -> String {
    if counts.is_empty() {
        return "-".to_string();
    }
    counts
        .iter()
        .map(|(kind, count)| format!("{kind}={count}"))
        .collect::<Vec<_>>()
        .join(";")
}

#[cfg(test)]
mod tests {
    use super::{
        apply_static_fp_guards, build_locked_ether_candidates, build_static_fp_guards,
        extract_function_id_from_message, inject_static_runtime_backstops,
        keep_locked_ether_finding,
    };
    use chainvet_sa::analysis::detectors::{Finding, FindingKind, Severity};
    use crate::fuzzing::types::{FuzzFinding, FuzzFindingKind, FuzzSeverity};
    use chainvet_core::ir::{IrBlock, IrFunction, IrInstr, IrModule, IrValue, IrVar};
    use chainvet_core::norm::{
        Contract, ContractKind, Function, FunctionKind, Mutability, NormalizedAst, SourceFile,
        Span, StateVariable, Visibility,
    };

    fn finding(kind: FuzzFindingKind, message: &str) -> FuzzFinding {
        FuzzFinding {
            span: None,
            kind,
            severity: FuzzSeverity::Medium,
            message: message.to_string(),
            tx_sequence: Vec::new(),
            trace_hash: format!("hash-{message}"),
        }
    }

    fn span() -> Span {
        Span {
            file: 0,
            start: 0,
            end: 1,
        }
    }

    fn test_ast_with_source(function_name: &str, source: &str) -> NormalizedAst {
        let mut ast = NormalizedAst::default();
        ast.files.push(SourceFile {
            id: 0,
            path: "test.sol".to_string(),
            source: source.to_string(),
        });
        ast.functions.push(Function {
            id: 0,
            contract: None,
            name: Some(function_name.to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::Payable,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span {
                file: 0,
                start: 0,
                end: source.len() as u32,
            },
        });
        ast
    }

    #[test]
    fn extract_function_id_from_message_parses_common_format() {
        let msg = "Transaction order dependency: function 12 reads order-sensitive storage";
        assert_eq!(extract_function_id_from_message(msg), Some(12));
    }

    #[test]
    fn apply_static_fp_guards_filters_tod_and_sig_mall_without_static_support() {
        let findings = vec![
            finding(
                FuzzFindingKind::TransactionOrderDependency,
                "Transaction order dependency: function 1 reads order-sensitive storage",
            ),
            finding(
                FuzzFindingKind::SignatureMalleability,
                "Signature malleability risk: function 2 uses ecrecover",
            ),
            finding(
                FuzzFindingKind::UncheckedCall,
                "Unchecked external call in function 3",
            ),
        ];

        let mut tod_allowed = std::collections::HashSet::new();
        tod_allowed.insert(1u32);
        let sig_mall_allowed = std::collections::HashSet::new();

        let filtered = apply_static_fp_guards(findings, &tod_allowed, &sig_mall_allowed);
        assert_eq!(filtered.len(), 2);
        assert!(filtered
            .iter()
            .any(|f| matches!(f.kind, FuzzFindingKind::TransactionOrderDependency)));
        assert!(filtered
            .iter()
            .any(|f| matches!(f.kind, FuzzFindingKind::UncheckedCall)));
        assert!(!filtered
            .iter()
            .any(|f| matches!(f.kind, FuzzFindingKind::SignatureMalleability)));
    }

    #[test]
    fn build_static_fp_guards_collects_only_target_kinds() {
        let findings = vec![
            Finding {
                kind: FindingKind::TransactionOrderDependency,
                severity: Severity::Medium,
                message: "tod".to_string(),
                span: Span {
                    file: 0,
                    start: 0,
                    end: 1,
                },
                function: Some(7),
            },
            Finding {
                kind: FindingKind::SignatureMalleability,
                severity: Severity::Medium,
                message: "sig".to_string(),
                span: Span {
                    file: 0,
                    start: 0,
                    end: 1,
                },
                function: Some(9),
            },
            Finding {
                kind: FindingKind::TxOrigin,
                severity: Severity::High,
                message: "other".to_string(),
                span: Span {
                    file: 0,
                    start: 0,
                    end: 1,
                },
                function: Some(11),
            },
        ];

        let (tod, sig) = build_static_fp_guards(&findings);
        assert!(tod.contains(&7));
        assert!(sig.contains(&9));
        assert!(!tod.contains(&11));
        assert!(!sig.contains(&11));
    }

    fn make_contract_ast(payable: bool) -> NormalizedAst {
        let mut ast = NormalizedAst::from_sources(vec![SourceFile {
            id: 0,
            path: "test.sol".to_string(),
            source: "pragma solidity ^0.8.0;".to_string(),
        }]);
        ast.contracts.push(Contract {
            id: 0,
            name: "Vault".to_string(),
            kind: ContractKind::Contract,
            bases: Vec::new(),
            functions: vec![0],
            state_vars: Vec::new(),
            modifiers: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
            span: Span {
                file: 0,
                start: 0,
                end: 0,
            },
        });
        ast.functions.push(Function {
            id: 0,
            contract: Some(0),
            name: Some("deposit".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::External,
            mutability: if payable {
                Mutability::Payable
            } else {
                Mutability::NonPayable
            },
            params: vec!["amount".to_string()],
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span {
                file: 0,
                start: 0,
                end: 0,
            },
        });
        ast
    }

    #[test]
    fn locked_ether_candidate_true_for_payable_no_send_path() {
        let ast = make_contract_ast(true);
        let ir_module = IrModule {
            functions: vec![IrFunction {
                id: 0,
                name: Some("deposit".to_string()),
                source: Some(0),
                span: Span {
                    file: 0,
                    start: 0,
                    end: 0,
                },
                blocks: vec![IrBlock {
                    id: 0,
                    instrs: vec![IrInstr::Nop {
                        span: Span {
                            file: 0,
                            start: 0,
                            end: 0,
                        },
                    }],
                }],
            }],
        };
        let candidates = build_locked_ether_candidates(&ast, &ir_module);
        assert_eq!(candidates.get("Vault").copied(), Some(true));
    }

    #[test]
    fn locked_ether_candidate_false_when_send_path_exists() {
        let ast = make_contract_ast(true);
        let ir_module = IrModule {
            functions: vec![IrFunction {
                id: 0,
                name: Some("deposit".to_string()),
                source: Some(0),
                span: Span {
                    file: 0,
                    start: 0,
                    end: 0,
                },
                blocks: vec![IrBlock {
                    id: 0,
                    instrs: vec![IrInstr::Call {
                        dest: Vec::new(),
                        callee: IrValue::Var(IrVar::Named("transfer".to_string())),
                        args: Vec::new(),
                        options: Vec::new(),
                        span: Span {
                            file: 0,
                            start: 0,
                            end: 0,
                        },
                    }],
                }],
            }],
        };
        let candidates = build_locked_ether_candidates(&ast, &ir_module);
        assert_eq!(candidates.get("Vault").copied(), Some(false));
    }

    #[test]
    fn inject_static_runtime_backstops_adds_missing_runtime_kinds() {
        let ast = make_contract_ast(true);
        let static_findings = vec![
            Finding {
                kind: FindingKind::WeakPrng,
                severity: Severity::Medium,
                message: "weak-prng".to_string(),
                span: Span {
                    file: 0,
                    start: 0,
                    end: 1,
                },
                function: Some(0),
            },
            Finding {
                kind: FindingKind::LockedEther,
                severity: Severity::High,
                message: "locked".to_string(),
                span: Span {
                    file: 0,
                    start: 0,
                    end: 1,
                },
                function: Some(0),
            },
            Finding {
                kind: FindingKind::UnusedReturnValue,
                severity: Severity::Medium,
                message: "unchecked".to_string(),
                span: Span {
                    file: 0,
                    start: 0,
                    end: 1,
                },
                function: Some(0),
            },
        ];

        let injected = inject_static_runtime_backstops(&[], &static_findings, &ast);
        assert!(injected.iter().any(|f| f.kind == FuzzFindingKind::WeakPRNG));
        assert!(injected
            .iter()
            .any(|f| f.kind == FuzzFindingKind::LockedEther));
        assert!(injected
            .iter()
            .any(|f| f.kind == FuzzFindingKind::UncheckedCall));
    }

    #[test]
    fn inject_static_runtime_backstop_maps_force_ether_balance_check_to_locked_ether() {
        let ast = make_contract_ast(true);
        let static_findings = vec![Finding {
            kind: FindingKind::ForceEtherBalanceCheck,
            severity: Severity::High,
            message: "force-ether".to_string(),
            span: Span {
                file: 0,
                start: 0,
                end: 1,
            },
            function: Some(0),
        }];

        let injected = inject_static_runtime_backstops(&[], &static_findings, &ast);
        assert!(injected
            .iter()
            .any(|f| f.kind == FuzzFindingKind::LockedEther));
    }

    #[test]
    fn inject_static_runtime_backstop_recovers_dos_block_gas_limit_from_dos_path() {
        let source = "function refundDos() public { for (uint i; i < refundAddresses.length; i++) { refundAddresses[i].transfer(refundAmount[i]); } }";
        let mut ast = NormalizedAst::from_sources(vec![SourceFile {
            id: 0,
            path: "test.sol".to_string(),
            source: source.to_string(),
        }]);
        ast.contracts.push(Contract {
            id: 0,
            name: "CrowdFundBad".to_string(),
            kind: ContractKind::Contract,
            bases: Vec::new(),
            functions: vec![0],
            state_vars: Vec::new(),
            modifiers: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
            span: Span {
                file: 0,
                start: 0,
                end: source.len() as u32,
            },
        });
        ast.functions.push(Function {
            id: 0,
            contract: Some(0),
            name: Some("refundDos".to_string()),
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
                end: source.len() as u32,
            },
        });

        let runtime_findings = vec![finding(
            FuzzFindingKind::DosWithFailedCall,
            "Static-guided runtime backstop: function 0 ('refundDos') has static DoS-with-failed-call signal but runtime loop/call-failure evidence was not captured",
        )];
        let static_findings = vec![Finding {
            kind: FindingKind::DosBlockGasLimit,
            severity: Severity::Medium,
            message: "dynamic bound".to_string(),
            span: Span {
                file: 0,
                start: 0,
                end: source.len() as u32,
            },
            function: Some(0),
        }];

        let injected = inject_static_runtime_backstops(&runtime_findings, &static_findings, &ast);
        assert!(injected
            .iter()
            .any(|finding| finding.kind == FuzzFindingKind::DosBlockGasLimit));
    }

    #[test]
    fn inject_static_runtime_backstops_drop_checked_selector_wrapper_noise() {
        let ast = test_ast_with_source(
            "deposit",
            "function deposit(address target) public payable { require(target.call.value(msg.value)(bytes4(sha3(\"addToBalance()\")))); }",
        );
        let static_findings = vec![
            Finding {
                kind: FindingKind::DosWithFailedCall,
                severity: Severity::High,
                message: "dos".to_string(),
                span: span(),
                function: Some(0),
            },
            Finding {
                kind: FindingKind::UnusedReturnValue,
                severity: Severity::Medium,
                message: "unchecked".to_string(),
                span: span(),
                function: Some(0),
            },
            Finding {
                kind: FindingKind::ReentrancyNoEthTransfer,
                severity: Severity::Medium,
                message: "reentrancy".to_string(),
                span: span(),
                function: Some(0),
            },
        ];

        let injected = inject_static_runtime_backstops(&[], &static_findings, &ast);
        assert!(injected.is_empty());
    }

    #[test]
    fn inject_static_runtime_backstop_recovers_timestamp_dependency_from_timestamp_seeded_prng() {
        let source = "uint256 salt = block.timestamp; function random() public view returns (uint256) { return salt * block.number; }";
        let mut ast = NormalizedAst::from_sources(vec![SourceFile {
            id: 0,
            path: "test.sol".to_string(),
            source: source.to_string(),
        }]);
        ast.contracts.push(Contract {
            id: 0,
            name: "TheRun".to_string(),
            kind: ContractKind::Contract,
            bases: Vec::new(),
            functions: vec![0],
            state_vars: vec![0],
            modifiers: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
            span: Span {
                file: 0,
                start: 0,
                end: source.len() as u32,
            },
        });
        ast.state_vars.push(StateVariable {
            id: 0,
            contract: 0,
            name: "salt".to_string(),
            visibility: Visibility::Private,
            mutability: Mutability::NonPayable,
            constant: false,
            immutable: false,
            type_string: Some("uint256".to_string()),
            span: Span {
                file: 0,
                start: 0,
                end: source.find(';').unwrap() as u32 + 1,
            },
        });
        let function_start = source.find("function").unwrap() as u32;
        ast.functions.push(Function {
            id: 0,
            contract: Some(0),
            name: Some("random".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::View,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span {
                file: 0,
                start: function_start,
                end: source.len() as u32,
            },
        });

        let static_findings = vec![Finding {
            kind: FindingKind::WeakPrng,
            severity: Severity::Medium,
            message: "timestamp-seeded randomness".to_string(),
            span: Span {
                file: 0,
                start: function_start,
                end: source.len() as u32,
            },
            function: Some(0),
        }];

        let injected = inject_static_runtime_backstops(&[], &static_findings, &ast);
        assert!(injected.iter().any(|finding| {
            finding.kind == FuzzFindingKind::TimestampDependency
                && finding.message.contains("block.timestamp/now")
        }));
        assert!(injected
            .iter()
            .any(|finding| finding.kind == FuzzFindingKind::WeakPRNG));
    }

    #[test]
    fn strong_locked_ether_runtime_signal_survives_candidate_filter() {
        let strong = finding(
            FuzzFindingKind::LockedEther,
            "Forced-Ether invariant risk: function 12 checks this.balance/address(this).balance in require/assert before selfdestruct/suicide",
        );
        let generic = finding(
            FuzzFindingKind::LockedEther,
            "Contract accepts Ether but has no withdrawal mechanism — Ether may be permanently locked",
        );

        assert!(keep_locked_ether_finding(&strong, false));
        assert!(!keep_locked_ether_finding(&generic, false));
        assert!(keep_locked_ether_finding(&generic, true));
    }
}
