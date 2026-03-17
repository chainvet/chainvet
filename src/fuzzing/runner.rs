use std::time::Instant;

use rand::Rng;
use sha2::{Digest, Sha256};

use crate::analysis;
use crate::frontend::FrontendOutput;
use crate::fuzzing::executor;
use crate::fuzzing::generator;
use crate::fuzzing::mutator;
use crate::fuzzing::oracle;
use crate::fuzzing::scheduler::{self, CoverageMap};
use crate::fuzzing::types::{
    ContractAbi, Corpus, DependencyMap, Dictionary, FuzzConfig, FuzzFinding, FuzzFindingKind,
    FuzzReport, FuzzSeverity, build_dependency_map, extract_abis,
};
use crate::norm::{FunctionKind, Mutability, NormalizedAst};
use crate::{cfg, ir, meta};

/// Run the fuzzer on a parsed contract.
pub fn run(output: &FrontendOutput, config: &FuzzConfig) -> FuzzReport {
    let start = Instant::now();
    let ast = &output.ast;

    // Phase 1: Static analysis pre-pass
    let ir_module = ir::lower_module(ast);
    let cfgs = cfg::build_from_ir(&ir_module);
    let abis = extract_abis(ast, &output.compiler);
    let deps = build_dependency_map(&ir_module, ast);
    let static_call_graph = analysis::build_call_graph(ast);
    let static_taint = analysis::taint::analyze(ast, &cfgs);
    let static_findings = analysis::detectors::run_detectors(ast, &static_call_graph, &static_taint);
    let meta_findings =
        meta::analyze_for_engine(output, meta::ConsumerEngine::Fuzzing, &static_findings);
    let (tod_allowed, sig_mall_allowed) = build_static_fp_guards(&static_findings);
    let locked_ether_candidates = build_locked_ether_candidates(ast, &ir_module);

    // Extract dictionary from IR constants for smarter value generation
    let dictionary = generator::extract_dictionary(&ir_module);

    // Collect total blocks for coverage %
    let total_blocks: usize = cfgs.iter().map(|c| c.blocks.len()).sum();

    // If no contracts or functions, bail early
    if abis.is_empty() || abis.iter().all(|a| a.functions.is_empty()) {
        return FuzzReport {
            iterations: 0,
            coverage_pct: 0.0,
            total_blocks,
            covered_blocks: 0,
            findings: Vec::new(),
            meta_findings,
            corpus_size: 0,
            corpus_zero_reason: Some("no contracts or functions available for fuzzing".to_string()),
            elapsed_ms: start.elapsed().as_millis(),
        };
    }

    let mut all_findings: Vec<FuzzFinding> = Vec::new();
    let mut global_coverage = CoverageMap::new();
    let mut corpus = Corpus::default();

    // Run per-contract
    for abi in &abis {
        let locked_ether_candidate = locked_ether_candidates
            .get(&abi.contract_name)
            .copied()
            .unwrap_or(false);
        fuzz_contract(
            output,
            abi,
            &deps,
            config,
            ast,
            &ir_module,
            &cfgs,
            locked_ether_candidate,
            &mut all_findings,
            &mut global_coverage,
            &mut corpus,
            &dictionary,
            &start,
        );
    }

    // Add AST-only shadowing checks (project extension used by scoring fixtures).
    all_findings.extend(detect_shadowing_findings(ast));
    // Add AST-level access control pattern for taxonomy parity.
    all_findings.extend(detect_public_mint_burn_findings(ast, &output.compiler));
    all_findings = apply_static_fp_guards(all_findings, &tod_allowed, &sig_mall_allowed);
    all_findings.extend(inject_static_runtime_backstops(
        &all_findings,
        &static_findings,
        ast,
    ));

    // Deduplicate findings
    let findings = oracle::deduplicate(all_findings);
    let covered_blocks = global_coverage.count();
    let coverage_pct = if total_blocks > 0 {
        (covered_blocks as f64 / total_blocks as f64) * 100.0
    } else {
        0.0
    };

    FuzzReport {
        iterations: config.max_iterations,
        coverage_pct,
        total_blocks,
        covered_blocks,
        findings,
        meta_findings,
        corpus_size: corpus.entries.len(),
        corpus_zero_reason: zero_corpus_reason(&abis, &corpus),
        elapsed_ms: start.elapsed().as_millis(),
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
    compiler: &crate::frontend::CompilerInfo,
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
        if !crate::frontend::is_public_entrypoint(function, compiler)
            || function.kind != FunctionKind::Function
        {
            continue;
        }
        let detail = format!("{}:{}", function.id, lower);
        findings.push(FuzzFinding {
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
    let runtime_weak_prng_fns = runtime_findings
        .iter()
        .filter(|finding| finding.kind == FuzzFindingKind::WeakPRNG)
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
        if runtime_dos_fns.contains(&function_id) || !injected.insert(("dos", function_id)) {
            continue;
        }
        let function_name = ast
            .functions
            .get(function_id as usize)
            .and_then(|f| f.name.as_deref())
            .unwrap_or("<unknown>");
        out.push(FuzzFinding {
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

    for finding in static_findings
        .iter()
        .filter(|finding| finding.kind == analysis::detectors::FindingKind::WeakPrng)
    {
        let function_id = finding.function.unwrap_or(0);
        if runtime_weak_prng_fns.contains(&function_id)
            || !injected.insert(("weak-prng", function_id))
        {
            continue;
        }
        let function_name = ast
            .functions
            .get(function_id as usize)
            .and_then(|f| f.name.as_deref())
            .unwrap_or("<unknown>");
        out.push(FuzzFinding {
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
            FuzzFindingKind::TransactionOrderDependency => extract_function_id_from_message(
                finding.message.as_str(),
            )
            .map(|id| tod_allowed.contains(&id))
            .unwrap_or(false),
            FuzzFindingKind::SignatureMalleability => extract_function_id_from_message(
                finding.message.as_str(),
            )
            .map(|id| sig_mall_allowed.contains(&id))
            .unwrap_or(false),
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
        let payable = has_payable_function.get(&contract.id).copied().unwrap_or(false);
        let has_send = has_ether_send_path.get(&contract.id).copied().unwrap_or(false);
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
            let ir::IrInstr::Call { callee, options, .. } = instr else {
                return false;
            };
            let callee_name = match callee {
                crate::ir::IrValue::Var(crate::ir::IrVar::Named(name)) => name.to_ascii_lowercase(),
                crate::ir::IrValue::Var(crate::ir::IrVar::Temp(id)) => format!("tmp_{id}"),
                crate::ir::IrValue::Literal(lit) => lit.value.to_ascii_lowercase(),
                crate::ir::IrValue::Unknown => String::new(),
            };
            let has_value = options
                .iter()
                .any(|opt| matches!(opt, crate::ir::IrCallOption::Value(_)));
            has_value
                || callee_name == "send"
                || callee_name == "transfer"
                || callee_name.ends_with(".send")
                || callee_name.ends_with(".transfer")
        })
    })
}

fn fuzz_contract(
    output: &FrontendOutput,
    abi: &ContractAbi,
    deps: &DependencyMap,
    config: &FuzzConfig,
    _ast: &NormalizedAst,
    ir_module: &ir::IrModule,
    cfgs: &[cfg::CfgFunction],
    locked_ether_candidate: bool,
    all_findings: &mut Vec<FuzzFinding>,
    global_coverage: &mut CoverageMap,
    corpus: &mut Corpus,
    dictionary: &Dictionary,
    start_time: &Instant,
) {
    // Phase 2: Generate initial population (using dictionary for smarter values)
    let population =
        generator::generate_initial_population_with_dict(abi, deps, config, Some(dictionary));

    // Execute initial population
    for ind in &population {
        let trace = executor::execute_individual(ind, output, ir_module, cfgs, abi, deps);
        let mut findings = oracle::check_all(&trace, &ind.transactions, Some(&output.ast));
        findings.retain(|finding| keep_locked_ether_finding(finding, locked_ether_candidate));
        all_findings.extend(findings);
        scheduler::update_corpus(corpus, ind, &trace, global_coverage);
    }

    // Phase 3: Fuzzing loop
    let mut rng = match config.seed {
        Some(seed) => {
            <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(seed.wrapping_add(1))
        }
        None => <rand::rngs::StdRng as rand::SeedableRng>::from_entropy(),
    };

    // Coverage plateau detection: stall counter tracks iterations without new coverage
    let mut stall_counter: usize = 0;
    let mut last_coverage_count = global_coverage.count();

    for _iteration in 0..config.max_iterations {
        // Time-based stopping: check wall-clock time limit
        if let Some(max_ms) = config.max_duration_ms {
            if start_time.elapsed().as_millis() as u64 >= max_ms {
                break;
            }
        }

        // Select a parent from the corpus
        let parent = match scheduler::select_next(corpus, &mut rng) {
            Some(p) => p.clone(),
            None => continue,
        };

        // Determine if we're in havoc-only mode due to coverage plateau
        let havoc_only = stall_counter >= 100;

        // Mutate (or crossover), with occasional dependency-aware reseed on stalls.
        let child = if stall_counter >= 150 && rng.gen_bool(0.25) {
            generator::generate_dependency_seed_with_dict(
                abi,
                deps,
                config,
                &mut rng,
                Some(dictionary),
            )
            .unwrap_or_else(|| parent.clone())
        } else if rng.gen_bool(0.2) && corpus.entries.len() >= 2 {
            // Crossover with another random parent
            let other_idx = rng.gen_range(0..corpus.entries.len());
            let other = &corpus.entries[other_idx].individual;
            mutator::crossover(&parent, other, &mut rng)
        } else {
            mutator::mutate_individual_guided_with_dict(
                &parent,
                abi,
                deps,
                &mut rng,
                Some(dictionary),
                havoc_only,
            )
        };

        // Execute
        let trace = executor::execute_individual(&child, output, ir_module, cfgs, abi, deps);

        // Oracle check
        let mut findings = oracle::check_all(&trace, &child.transactions, Some(&output.ast));
        findings.retain(|finding| keep_locked_ether_finding(finding, locked_ether_candidate));
        if !findings.is_empty() {
            // Tag the corpus entry with finding hashes
            let hashes: Vec<String> = findings.iter().map(|f| f.trace_hash.clone()).collect();
            all_findings.extend(findings);

            // Add to corpus even if coverage is not new (it found bugs)
            let added = scheduler::update_corpus(corpus, &child, &trace, global_coverage);
            if !added {
                corpus.entries.push(crate::fuzzing::types::CorpusEntry {
                    individual: child.clone(),
                    coverage: trace.coverage.clone(),
                    finding_hashes: hashes,
                });
            }
        } else {
            scheduler::update_corpus(corpus, &child, &trace, global_coverage);
        }

        // Update coverage plateau detection
        let current_coverage = global_coverage.count();
        if current_coverage > last_coverage_count {
            stall_counter = 0;
            last_coverage_count = current_coverage;
        } else {
            stall_counter += 1;
        }

        // Re-assign energy periodically
        if _iteration % 50 == 0 {
            scheduler::assign_energy(corpus, global_coverage);
        }

        // Corpus minimization every 200 iterations
        if _iteration % 200 == 0 && _iteration > 0 {
            scheduler::minimize_corpus(corpus);
        }
    }
}

/// Print a text report of fuzz results, grouped by taxonomy category.
pub fn print_report(report: &FuzzReport) {
    println!("=== Fuzzing Report ===");
    println!(
        "iterations: {}, corpus: {}, time: {}ms",
        report.iterations, report.corpus_size, report.elapsed_ms
    );
    println!(
        "coverage: {}/{} blocks ({:.1}%)",
        report.covered_blocks, report.total_blocks, report.coverage_pct
    );
    if let Some(reason) = &report.corpus_zero_reason {
        println!("corpus_zero_reason: {reason}");
    }
    println!("runtime_findings: {}", report.findings.len());
    println!("meta_findings: {}", report.meta_findings.len());

    if report.findings.is_empty() {
        println!("  (no vulnerabilities detected)");
    } else {
        // Group by taxonomy category
        let mut by_category: std::collections::BTreeMap<&str, Vec<&FuzzFinding>> =
            std::collections::BTreeMap::new();
        for f in &report.findings {
            by_category.entry(f.kind.category()).or_default().push(f);
        }

        for (category, findings) in &by_category {
            println!("\n  [{}] {} finding(s):", category, findings.len());
            for (idx, f) in findings.iter().enumerate() {
                println!(
                    "    {}. [{}] [{}] [{}] {}",
                    idx + 1,
                    f.kind.canonical_str(),
                    f.severity.as_str(),
                    f.kind.confidence().as_str(),
                    f.message
                );
                println!("       Transaction sequence ({} txs):", f.tx_sequence.len());
                for (tx_idx, tx) in f.tx_sequence.iter().enumerate() {
                    let args_str: Vec<String> =
                        tx.args.iter().map(|a| format!("{}", a.as_uint())).collect();
                    println!(
                        "         {}: fn={} sender={} value={} args=[{}]",
                        tx_idx,
                        tx.function_id,
                        tx.sender,
                        tx.value,
                        args_str.join(", ")
                    );
                }
            }
        }
    }

    if !report.meta_findings.is_empty() {
        println!("\n  [Meta] {} finding(s):", report.meta_findings.len());
        for (idx, finding) in report.meta_findings.iter().enumerate() {
            println!(
                "    {}. kind={} severity={} evidence={} {}",
                idx + 1,
                finding.finding_type,
                finding.severity,
                finding.evidence_kind,
                finding.message
            );
            if let Some(location) = &finding.location {
                if let Some(file) = &location.file {
                    println!(
                        "       location: {}:{}-{}",
                        file,
                        location.start.unwrap_or(0),
                        location.end.unwrap_or(0)
                    );
                }
            }
        }
    }

    println!("=== End Report ===");
}

#[cfg(test)]
mod tests {
    use super::{
        apply_static_fp_guards, build_locked_ether_candidates, build_static_fp_guards,
        extract_function_id_from_message, inject_static_runtime_backstops,
        keep_locked_ether_finding,
    };
    use crate::analysis::detectors::{Finding, FindingKind, Severity};
    use crate::fuzzing::types::{FuzzFinding, FuzzFindingKind, FuzzSeverity};
    use crate::ir::{IrBlock, IrFunction, IrInstr, IrModule, IrValue, IrVar};
    use crate::norm::{
        Contract, ContractKind, Function, FunctionKind, Mutability, NormalizedAst, SourceFile,
        Span, Visibility,
    };

    fn finding(kind: FuzzFindingKind, message: &str) -> FuzzFinding {
        FuzzFinding {
            kind,
            severity: FuzzSeverity::Medium,
            message: message.to_string(),
            tx_sequence: Vec::new(),
            trace_hash: format!("hash-{message}"),
        }
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
        assert!(
            filtered
                .iter()
                .any(|f| matches!(f.kind, FuzzFindingKind::TransactionOrderDependency))
        );
        assert!(
            filtered
                .iter()
                .any(|f| matches!(f.kind, FuzzFindingKind::UncheckedCall))
        );
        assert!(
            !filtered
                .iter()
                .any(|f| matches!(f.kind, FuzzFindingKind::SignatureMalleability))
        );
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
        assert!(injected.iter().any(|f| f.kind == FuzzFindingKind::LockedEther));
        assert!(injected.iter().any(|f| f.kind == FuzzFindingKind::UncheckedCall));
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
        assert!(injected.iter().any(|f| f.kind == FuzzFindingKind::LockedEther));
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
