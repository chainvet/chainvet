mod report;
mod seeding;
mod targeting;

use std::collections::HashSet;

use crate::analysis;
use crate::cfg;
use crate::core::artifacts::HybridReport;
use crate::frontend::FrontendOutput;
use crate::fuzzing;
use crate::ir;
use crate::report::OutputFormat;
use crate::symbolic::{self, SymbolicOptions};
use crate::util::error::Result;

use report::{print_hybrid_report, HybridFindingRow, HybridJsonReport, HybridRunSummary};
use seeding::build_hybrid_seeds;
use targeting::{build_targets, classify_threshold, selected_targets};

pub fn run(output: &FrontendOutput, format: OutputFormat) -> Result<()> {
    let ast = &output.ast;
    let ir_module = ir::lower_module(ast);
    let cfgs = cfg::build_from_ir(&ir_module);
    let call_graph = analysis::build_call_graph(ast);
    let taint = analysis::taint::analyze(ast, &cfgs);
    let static_findings = analysis::detectors::run_detectors(ast, &call_graph, &taint);

    let targets = build_targets(ast, &static_findings);
    let selected = selected_targets(&targets);
    let threshold = classify_threshold(&targets);
    let target_function_ids = selected
        .iter()
        .filter_map(|target| target.function_id)
        .collect::<HashSet<_>>();

    let symbolic = symbolic::analyze_with_options(
        output,
        &SymbolicOptions {
            target_function_ids: (!target_function_ids.is_empty()).then_some(target_function_ids),
            max_path_depth: Some(96),
            max_instructions: Some(3_000),
            max_loop_unrolling: Some(2),
            max_states: Some(2_000),
            total_timeout_s: Some(30),
        },
    )?;

    let abis = fuzzing::types::extract_abis(ast, &output.compiler);
    let seeds = build_hybrid_seeds(ast, &abis, &symbolic.findings);
    let fuzz_config = fuzzing::types::FuzzConfig {
        hybrid_mode: true,
        seed_corpus: seeds.iter().map(|seed| seed.individual.clone()).collect(),
        ..fuzzing::types::FuzzConfig::default()
    };
    let fuzz_report = fuzzing::runner::run(output, &fuzz_config);

    let hybrid_summary = HybridReport {
        run_id: format!(
            "hybrid-{}-{}",
            ast.contracts.len(),
            ast.files.len()
        ),
        runtime_ms: fuzz_report.elapsed_ms,
        total_epochs: 1,
        coverage_curve: Vec::new(),
        findings_total: static_findings.len() + symbolic.findings.len() + fuzz_report.findings.len(),
        findings_unique: static_findings.len() + symbolic.findings.len() + fuzz_report.findings.len(),
        runtime_findings_total: fuzz_report.findings.len() + symbolic.findings.len(),
        runtime_findings_unique: fuzz_report.findings.len() + symbolic.findings.len(),
        meta_findings_total: static_findings.len(),
        meta_findings_unique: static_findings.len(),
        se_assists: symbolic.findings.len(),
        seeds_injected_by_se: seeds.len(),
        se_new_edges_from_injected: 0,
        time_to_first_finding_ms: (!fuzz_report.findings.is_empty() || !symbolic.findings.is_empty())
            .then_some(fuzz_report.elapsed_ms),
    };

    let findings = HybridFindingRow::collect(ast, &selected, &symbolic.findings, &fuzz_report.findings);
    let summary = HybridRunSummary {
        static_threshold: threshold.as_str().to_string(),
        static_targets_total: targets.len(),
        static_targets_selected: selected.len(),
        static_targets_skipped: targets.len().saturating_sub(selected.len()),
        se_targeted_functions: selected
            .iter()
            .filter_map(|target| target.function_id)
            .collect::<HashSet<_>>()
            .len(),
        se_findings_total: symbolic.findings.len(),
        se_seedable_findings: seeds.len(),
        fuzz_seed_count: seeds.len(),
        fuzz_corpus_size: fuzz_report.corpus_size,
        fuzz_findings_total: fuzz_report.findings.len(),
    };

    let payload = HybridJsonReport {
        summary,
        aggregate: hybrid_summary,
        targets,
        seeds,
        findings,
        symbolic_states_explored: symbolic.total_states,
        symbolic_coverage: symbolic.coverage,
        fuzz_coverage_pct: fuzz_report.coverage_pct,
        fuzz_total_blocks: fuzz_report.total_blocks,
        fuzz_covered_blocks: fuzz_report.covered_blocks,
        fuzz_hybrid_stats: fuzz_report.hybrid_stats,
    };

    print_hybrid_report(&payload, format)
}
