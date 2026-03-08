use std::time::Instant;

use rand::Rng;

use crate::fuzzing::executor;
use crate::fuzzing::generator;
use crate::fuzzing::mutator;
use crate::fuzzing::oracle;
use crate::fuzzing::scheduler::{self, CoverageMap};
use crate::fuzzing::types::{
    ContractAbi, Corpus, DependencyMap, Dictionary, FuzzConfig, FuzzFinding, FuzzReport,
    build_dependency_map, extract_abis,
};
use crate::norm::NormalizedAst;
use crate::{cfg, ir};

/// Run the fuzzer on a parsed contract.
pub fn run(ast: &NormalizedAst, config: &FuzzConfig) -> FuzzReport {
    let start = Instant::now();

    // Phase 1: Static analysis pre-pass
    let ir_module = ir::lower_module(ast);
    let cfgs = cfg::build_from_ir(&ir_module);
    let abis = extract_abis(ast);
    let deps = build_dependency_map(&ir_module, ast);

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
            corpus_size: 0,
            elapsed_ms: start.elapsed().as_millis(),
        };
    }

    let mut all_findings: Vec<FuzzFinding> = Vec::new();
    let mut global_coverage = CoverageMap::new();
    let mut corpus = Corpus::default();

    // Run per-contract
    for abi in &abis {
        fuzz_contract(
            abi,
            &deps,
            config,
            ast,
            &ir_module,
            &cfgs,
            &mut all_findings,
            &mut global_coverage,
            &mut corpus,
            &dictionary,
            &start,
        );
    }

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
        corpus_size: corpus.entries.len(),
        elapsed_ms: start.elapsed().as_millis(),
    }
}

fn fuzz_contract(
    abi: &ContractAbi,
    deps: &DependencyMap,
    config: &FuzzConfig,
    ast: &NormalizedAst,
    ir_module: &ir::IrModule,
    cfgs: &[cfg::CfgFunction],
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
        let trace = executor::execute_individual(ind, ast, ir_module, cfgs, abi);
        let findings = oracle::check_all(&trace, &ind.transactions);
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

        // Mutate (or crossover)
        let child = if rng.gen_bool(0.2) && corpus.entries.len() >= 2 {
            // Crossover with another random parent
            let other_idx = rng.gen_range(0..corpus.entries.len());
            let other = &corpus.entries[other_idx].individual;
            mutator::crossover(&parent, other, &mut rng)
        } else {
            mutator::mutate_individual_with_dict(
                &parent,
                abi,
                &mut rng,
                Some(dictionary),
                havoc_only,
            )
        };

        // Execute
        let trace = executor::execute_individual(&child, ast, ir_module, cfgs, abi);

        // Oracle check
        let findings = oracle::check_all(&trace, &child.transactions);
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
    println!("findings: {}", report.findings.len());

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
                    "    {}. [{}] [{}] {}",
                    idx + 1,
                    f.kind.as_str(),
                    f.severity.as_str(),
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

    println!("=== End Report ===");
}
