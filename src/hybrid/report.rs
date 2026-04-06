use std::collections::HashSet;

use serde::Serialize;

use crate::core::artifacts::HybridReport;
use crate::fuzzing::types::{FuzzFinding, FuzzHybridStats};
use crate::norm::NormalizedAst;
use crate::report::OutputFormat;
use crate::symbolic::results::{coverage::CoverageReport, SeFinding};
use crate::util::error::{Error, Result};

use super::seeding::HybridSeed;
use super::targeting::HybridTarget;

#[derive(Debug, Clone, Serialize)]
pub struct HybridRunSummary {
    pub static_threshold: String,
    pub static_targets_total: usize,
    pub static_targets_selected: usize,
    pub static_targets_skipped: usize,
    pub se_targeted_functions: usize,
    pub se_findings_total: usize,
    pub se_seedable_findings: usize,
    pub fuzz_seed_count: usize,
    pub fuzz_corpus_size: usize,
    pub fuzz_findings_total: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct HybridFindingRow {
    pub provenance: String,
    pub kind: String,
    pub message: String,
    pub function_id: Option<u32>,
    pub file: Option<String>,
    pub start: Option<u32>,
    pub end: Option<u32>,
}

impl HybridFindingRow {
    pub fn collect(
        ast: &NormalizedAst,
        targets: &[HybridTarget],
        se_findings: &[SeFinding],
        fuzz_findings: &[FuzzFinding],
    ) -> Vec<Self> {
        let mut rows = Vec::new();
        let static_kinds = targets
            .iter()
            .map(|target| target.kind.clone())
            .collect::<HashSet<_>>();
        let symbolic_kinds = se_findings
            .iter()
            .map(|finding| finding.kind.as_str().to_string())
            .collect::<HashSet<_>>();

        for target in targets {
            rows.push(Self {
                provenance: "static".to_string(),
                kind: target.kind.clone(),
                message: target.target_reason.clone(),
                function_id: target.function_id,
                file: target.file.clone(),
                start: Some(target.span.start),
                end: Some(target.span.end),
            });
        }

        for finding in se_findings {
            rows.push(Self {
                provenance: "symbolic".to_string(),
                kind: finding.kind.as_str().to_string(),
                message: finding.message.clone(),
                function_id: finding.function_id,
                file: ast.files.get(finding.span.file as usize).map(|file| file.path.clone()),
                start: Some(finding.span.start),
                end: Some(finding.span.end),
            });
        }

        for finding in fuzz_findings {
            let canonical = finding.kind.canonical_str().to_string();
            let provenance = if static_kinds.contains(&canonical) || symbolic_kinds.contains(&canonical)
            {
                "hybrid-confirmed"
            } else {
                "fuzz"
            };
            rows.push(Self {
                provenance: provenance.to_string(),
                kind: canonical,
                message: finding.message.clone(),
                function_id: extract_function_id_from_message(&finding.message),
                file: None,
                start: None,
                end: None,
            });
        }

        rows
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HybridJsonReport {
    pub summary: HybridRunSummary,
    pub aggregate: HybridReport,
    pub targets: Vec<HybridTarget>,
    pub seeds: Vec<HybridSeed>,
    pub findings: Vec<HybridFindingRow>,
    pub symbolic_states_explored: usize,
    pub symbolic_coverage: CoverageReport,
    pub fuzz_coverage_pct: f64,
    pub fuzz_total_blocks: usize,
    pub fuzz_covered_blocks: usize,
    pub fuzz_hybrid_stats: Option<FuzzHybridStats>,
}

pub fn print_hybrid_report(report: &HybridJsonReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Text => {
            println!("=== Hybrid Analysis Report ===");
            println!(
                "static_targets: total={}, selected={}, skipped={}, threshold={}",
                report.summary.static_targets_total,
                report.summary.static_targets_selected,
                report.summary.static_targets_skipped,
                report.summary.static_threshold
            );
            println!(
                "symbolic: functions={}, findings={}, seedable={}, states={}",
                report.summary.se_targeted_functions,
                report.summary.se_findings_total,
                report.summary.se_seedable_findings,
                report.symbolic_states_explored
            );
            println!(
                "fuzzing: seeds={}, corpus={}, findings={}, coverage={}/{} ({:.1}%)",
                report.summary.fuzz_seed_count,
                report.summary.fuzz_corpus_size,
                report.summary.fuzz_findings_total,
                report.fuzz_covered_blocks,
                report.fuzz_total_blocks,
                report.fuzz_coverage_pct
            );
            if let Some(stats) = &report.fuzz_hybrid_stats {
                println!(
                    "hybrid_seed_stats: provided={}, executed={}",
                    stats.seeded_inputs_provided, stats.seeded_inputs_executed
                );
            }
            for finding in &report.findings {
                println!(
                    "[{}] {} {}",
                    finding.provenance, finding.kind, finding.message
                );
            }
            Ok(())
        }
        OutputFormat::Json => {
            let payload = serde_json::to_string_pretty(report)
                .map_err(|err| Error::msg(format!("failed to encode hybrid JSON report: {err}")))?;
            println!("{payload}");
            Ok(())
        }
    }
}

fn extract_function_id_from_message(message: &str) -> Option<u32> {
    let digits = message
        .split(|ch: char| !ch.is_ascii_digit())
        .find(|part| !part.is_empty())?;
    digits.parse().ok()
}
