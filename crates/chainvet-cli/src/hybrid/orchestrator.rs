//! Hybrid control loop: static targeting → upfront SE seed → fuzz epochs with
//! on-stall SE assists. Replaces P2's single linear pass while keeping P2's
//! upfront SE pass as a recall floor (so SE-only findings are never lost).
//!
//! Continuity is via a persistent `FuzzSession` (option A): corpus + coverage
//! accumulate across epochs, so the per-epoch coverage delta is a real stall
//! signal. SE assists target only still-uncovered selected functions, so we
//! never re-run identical (deterministic) SE work.

use std::collections::HashSet;
use std::time::Instant;

use crate::analysis;
use chainvet_core::cfg;
use chainvet_core::artifacts::HybridReport;
use crate::frontend::FrontendOutput;
use crate::fuzzing::{self, runner::FuzzSession};
use chainvet_core::ir;
use crate::report::OutputFormat;
use crate::symbolic::{self, SymbolicOptions, results::SeFinding};
use chainvet_core::util::error::Result;

use super::budget::HybridBudget;
use super::report::{HybridFindingRow, HybridJsonReport, HybridRunSummary, print_hybrid_report};
use super::seeding::build_hybrid_seeds;
use super::targeting::{build_targets, classify_threshold, selected_targets};

pub fn run(output: &FrontendOutput, budget: &HybridBudget, format: OutputFormat) -> Result<()> {
    let ast = &output.ast;
    let ir_module = ir::lower_module(ast);
    let cfgs = cfg::build_from_ir(&ir_module);
    let call_graph = analysis::build_call_graph(ast);
    let taint = analysis::taint::analyze(ast, &cfgs);
    let static_findings = analysis::detectors::run_detectors(ast, &call_graph, &taint);

    let targets = build_targets(ast, &static_findings);
    let selected = selected_targets(&targets);
    let threshold = classify_threshold(&targets);
    let target_function_ids: HashSet<u32> = selected
        .iter()
        .filter_map(|target| target.function_id)
        .collect();

    let abis = fuzzing::types::extract_abis(ast, &output.compiler);
    let all_callable: HashSet<u32> = abis
        .iter()
        .flat_map(|abi| {
            abi.functions
                .iter()
                .filter(|f| f.is_fuzz_callable())
                .map(|f| f.id)
        })
        .collect();
    let mut session = FuzzSession::new(output, budget.fuzz_config(Vec::new()));

    let run_start = Instant::now();
    let mut all_se_findings: Vec<SeFinding> = Vec::new();
    let mut all_seeds = Vec::new();
    let mut pending_seeds: Vec<fuzzing::types::Individual> = Vec::new();
    let mut se_assists: u32 = 0;
    let mut se_done_functions: HashSet<u32> = HashSet::new();
    let mut total_states = 0usize;
    let mut symbolic_coverage = symbolic::results::coverage::CoverageReport::default();
    let mut epochs_run: u32 = 0;
    let mut time_to_first_finding_ms: Option<u128> = None;

    // --- Upfront SE pass (P2-equivalent recall floor) ---
    // Always run: targeted at the selected high-signal sinks when static found
    // any, otherwise full untargeted exploration (symbolic_options maps an empty
    // target set to `None`). Skipping this when there were no static targets is
    // what regressed recall for SE-detected bugs (timestamp/tx-origin/arithmetic).
    {
        let analysis = run_se_assist(output, budget, &target_function_ids)?;
        total_states += analysis.total_states;
        symbolic_coverage = analysis.coverage.clone();
        let seeds = build_hybrid_seeds(ast, &abis, &analysis.findings);
        pending_seeds = seeds.iter().map(|s| s.individual.clone()).collect();
        all_seeds.extend(seeds);
        all_se_findings.extend(analysis.findings);
        // If the upfront pass was untargeted (no high-signal sinks), it already
        // explored every function, so there is nothing left for the on-stall
        // assists. If it was targeted, only those sinks are done — leaving the
        // uncovered functions for the fuzzer-stall assists to crack.
        if target_function_ids.is_empty() {
            se_done_functions.extend(all_callable.iter().copied());
        } else {
            se_done_functions.extend(target_function_ids.iter().copied());
        }
        se_assists += 1;
    }

    // --- Adaptive ("smart") fuzz epochs ---
    // The epoch count is decided per contract, not fixed. Each slice returns its
    // new-edge delta: while the fuzzer keeps gaining coverage we keep running
    // (up to max_epochs / the time budget); when it plateaus we stop. On a stall
    // we try one SE assist over the still-uncovered functions, but if the epoch
    // right after an assist still makes no progress, SE isn't unlocking this
    // contract (e.g. deep code gated by multi-transaction state), so we stop
    // spending assists and end the loop. Empirically this converges in ~1-3
    // epochs on contracts that saturate or are stuck, while leaving headroom for
    // contracts that genuinely keep progressing. `total_runtime_ms` budgets fuzz
    // time only; `hard_cap_ms` is the overall wall-clock ceiling; `max_epochs`
    // (CLI-overridable) is the hard cap on epoch count.
    let mut stall_run: u32 = 0;
    let mut fuzz_ms_spent: u64 = 0;
    let mut just_assisted = false;
    let mut assists_useful = true;
    for epoch in 1..=budget.max_epochs {
        epochs_run = epoch;
        if fuzz_ms_spent >= budget.total_runtime_ms
            || run_start.elapsed().as_millis() as u64 >= budget.hard_cap_ms
        {
            break;
        }
        let epoch_ms = budget
            .fuzz_epoch_ms
            .min(budget.total_runtime_ms - fuzz_ms_spent);

        let extra = std::mem::take(&mut pending_seeds);
        let slice_started = Instant::now();
        let stats = session.run_slice(&extra, budget.fuzz_iters_per_epoch, Some(epoch_ms));
        fuzz_ms_spent += slice_started.elapsed().as_millis() as u64;
        if time_to_first_finding_ms.is_none() && stats.findings_total > 0 {
            time_to_first_finding_ms = Some(run_start.elapsed().as_millis());
        }

        let progressed = stats.delta_edges >= budget.min_coverage_delta;
        if progressed {
            stall_run = 0;
        } else {
            stall_run += 1;
        }
        // If the epoch right after an SE assist still didn't progress, the
        // injected witnesses didn't unlock coverage here — stop spending assists.
        if just_assisted && !progressed {
            assists_useful = false;
        }
        just_assisted = false;

        // Still making progress — keep going (this is what makes the count adaptive).
        if stall_run < budget.stall_epochs_threshold {
            continue;
        }

        // Plateaued. Try one SE assist over the uncovered frontier, but only while
        // assists are still paying off; otherwise the loop has converged — stop.
        let covered = session.covered_function_ids();
        let uncovered: HashSet<u32> = all_callable
            .iter()
            .filter(|id| !covered.contains(id) && !se_done_functions.contains(id))
            .copied()
            .collect();
        let within_hard_cap = (run_start.elapsed().as_millis() as u64) < budget.hard_cap_ms;
        if assists_useful
            && se_assists < budget.max_se_assists
            && !uncovered.is_empty()
            && within_hard_cap
        {
            let analysis = run_se_assist(output, budget, &uncovered)?;
            total_states += analysis.total_states;
            let seeds = build_hybrid_seeds(ast, &abis, &analysis.findings);
            pending_seeds = seeds.iter().map(|s| s.individual.clone()).collect();
            all_seeds.extend(seeds);
            all_se_findings.extend(analysis.findings);
            se_done_functions.extend(uncovered);
            se_assists += 1;
            just_assisted = true;
            stall_run = 0; // let the injected seeds breathe
        } else {
            break;
        }
    }

    let fuzz_report = session.finalize();
    dedup_se_findings(&mut all_se_findings);

    let runtime_findings = fuzz_report.findings.len() + all_se_findings.len();
    let hybrid_summary = HybridReport {
        run_id: format!("hybrid-{}-{}", ast.contracts.len(), ast.files.len()),
        runtime_ms: run_start.elapsed().as_millis(),
        total_epochs: epochs_run,
        coverage_curve: Vec::new(),
        findings_total: static_findings.len() + all_se_findings.len() + fuzz_report.findings.len(),
        findings_unique: static_findings.len() + all_se_findings.len() + fuzz_report.findings.len(),
        runtime_findings_total: runtime_findings,
        runtime_findings_unique: runtime_findings,
        meta_findings_total: static_findings.len(),
        meta_findings_unique: static_findings.len(),
        se_assists: se_assists as usize,
        seeds_injected_by_se: all_seeds.len(),
        se_new_edges_from_injected: 0,
        time_to_first_finding_ms,
    };

    let findings =
        HybridFindingRow::collect(ast, &static_findings, &all_se_findings, &fuzz_report.findings);
    let summary = HybridRunSummary {
        static_threshold: threshold.as_str().to_string(),
        static_targets_total: targets.len(),
        static_targets_selected: selected.len(),
        static_targets_skipped: targets.len().saturating_sub(selected.len()),
        se_targeted_functions: se_done_functions.len(),
        se_findings_total: all_se_findings.len(),
        se_seedable_findings: all_seeds.len(),
        fuzz_seed_count: all_seeds.len(),
        fuzz_corpus_size: fuzz_report.corpus_size,
        fuzz_findings_total: fuzz_report.findings.len(),
    };

    let payload = HybridJsonReport {
        summary,
        aggregate: hybrid_summary,
        targets,
        seeds: all_seeds,
        findings,
        symbolic_states_explored: total_states,
        symbolic_coverage,
        fuzz_coverage_pct: fuzz_report.coverage_pct,
        fuzz_total_blocks: fuzz_report.total_blocks,
        fuzz_covered_blocks: fuzz_report.covered_blocks,
        fuzz_hybrid_stats: fuzz_report.hybrid_stats,
    };

    print_hybrid_report(&payload, format)
}

fn run_se_assist(
    output: &FrontendOutput,
    budget: &HybridBudget,
    targets: &HashSet<u32>,
) -> Result<symbolic::SymbolicAnalysis> {
    let options: SymbolicOptions = budget.symbolic_options(targets.clone());
    symbolic::analyze_with_options(output, &options)
}

/// Deduplicate SE findings that repeat across assists (deterministic SE can emit
/// the same finding when target sets overlap).
fn dedup_se_findings(findings: &mut Vec<SeFinding>) {
    let mut seen = HashSet::new();
    findings.retain(|f| {
        let key = (
            f.kind.as_str().to_string(),
            f.function_id,
            f.span.start,
            f.span.end,
        );
        seen.insert(key)
    });
}
