use std::collections::{BTreeSet, HashMap, HashSet};

use serde::Serialize;

use chainvet_sa::analysis::detectors::Finding;
use chainvet_core::artifacts::HybridReport;
use chainvet_fuzzing::fuzzing::types::{FuzzFinding, FuzzHybridStats};
use chainvet_core::norm::NormalizedAst;
use chainvet_core::OutputFormat;
use chainvet_se::symbolic::results::{coverage::CoverageReport, SeFinding};
use chainvet_core::util::error::{Error, Result};

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
    /// Confidence tier derived from provenance: `confirmed` when corroborated by
    /// dynamic execution (fuzz/hybrid-confirmed) or a symbolic feasibility
    /// witness; `candidate` when reported by static heuristics only.
    pub tier: String,
    pub provenance: String,
    pub provenances: Vec<String>,
    pub kind: String,
    pub severity: Option<String>,
    pub confidence: Option<String>,
    pub category: Option<String>,
    pub message: String,
    pub function_id: Option<u32>,
    pub file: Option<String>,
    pub start: Option<u32>,
    pub end: Option<u32>,
}

impl HybridFindingRow {
    pub fn collect(
        ast: &NormalizedAst,
        static_findings: &[Finding],
        se_findings: &[SeFinding],
        fuzz_findings: &[FuzzFinding],
    ) -> Vec<Self> {
        let mut rows = Vec::new();
        let static_kinds = static_findings
            .iter()
            .map(|finding| finding.kind.as_str().to_string())
            .collect::<HashSet<_>>();
        let symbolic_kinds = se_findings
            .iter()
            .map(|finding| finding.kind.as_str().to_string())
            .collect::<HashSet<_>>();

        // Surface the full static detector output (not just the high-signal SE
        // targets) so static-only detections — TOD especially — reach the report.
        for finding in static_findings {
            rows.push(Self {
                tier: tier_for("static").to_string(),
                provenance: "static".to_string(),
                provenances: vec!["static".to_string()],
                kind: finding.kind.as_str().to_string(),
                severity: Some(finding.severity.as_str().to_string()),
                confidence: None,
                category: Some(finding.kind.category().as_str().to_string()),
                message: finding.message.clone(),
                function_id: finding.function,
                file: ast
                    .files
                    .get(finding.span.file as usize)
                    .map(|file| file.path.clone()),
                start: Some(finding.span.start),
                end: Some(finding.span.end),
            });
        }

        for finding in se_findings {
            rows.push(Self {
                tier: tier_for("symbolic").to_string(),
                provenance: "symbolic".to_string(),
                provenances: vec!["symbolic".to_string()],
                kind: finding.kind.as_str().to_string(),
                severity: Some(finding.severity.as_str().to_string()),
                confidence: Some(finding.confidence.as_str().to_string()),
                category: Some(finding.category().as_str().to_string()),
                message: finding.message.clone(),
                function_id: finding.function_id,
                file: ast
                    .files
                    .get(finding.span.file as usize)
                    .map(|file| file.path.clone()),
                start: Some(finding.span.start),
                end: Some(finding.span.end),
            });
        }

        for finding in fuzz_findings {
            let canonical = finding.kind.canonical_str().to_string();
            let provenance =
                if static_kinds.contains(&canonical) || symbolic_kinds.contains(&canonical) {
                    "hybrid-confirmed"
                } else {
                    "fuzz"
                };
            // Prefer the exact operation span the oracle attributed to this
            // finding; fall back to the owning function's span when it has none
            // (e.g. aggregate findings like reentrancy).
            let function_id = extract_function_id_from_message(&finding.message);
            let function_span = function_id
                .and_then(|id| ast.functions.get(id as usize))
                .map(|function| function.span);
            let loc = finding.span.or(function_span);
            rows.push(Self {
                tier: tier_for(provenance).to_string(),
                provenance: provenance.to_string(),
                provenances: vec![provenance.to_string()],
                kind: canonical,
                severity: Some(finding.severity.as_str().to_string()),
                confidence: Some(finding.kind.confidence().as_str().to_string()),
                category: Some(finding.kind.category().to_string()),
                message: finding.message.clone(),
                function_id,
                file: loc
                    .and_then(|span| ast.files.get(span.file as usize))
                    .map(|file| file.path.clone()),
                start: loc.map(|span| span.start),
                end: loc.map(|span| span.end),
            });
        }

        deduplicate_rows(rows)
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
            let confirmed = report
                .findings
                .iter()
                .filter(|f| f.tier == "confirmed")
                .count();
            let candidate = report.findings.len() - confirmed;
            println!(
                "findings: {} total — {} confirmed (dynamic/SE evidence), {} candidate (static-only)",
                report.findings.len(),
                confirmed,
                candidate
            );
            for finding in &report.findings {
                println!(
                    "  [{}|{}] {} {}",
                    finding.tier, finding.provenance, finding.kind, finding.message
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

fn category_for_hybrid_kind(kind: &str) -> Option<&'static str> {
    match kind {
        "reentrancy"
        | "reentrancy-negative-events"
        | "reentrancy-transfer"
        | "reentrancy-same-effect"
        | "reentrancy-eth-transfer"
        | "reentrancy-no-eth-transfer" => Some("Reentrancy"),
        "unsafe-delegatecall"
        | "unprotected-ether-withdrawal"
        | "unprotected-selfdestruct"
        | "unused-return-value"
        | "arbitrary-storage-write" => Some("Access Control"),
        "delegatecall-in-loop" => Some("Storage and Memory"),
        "dos-with-failed-call" => Some("Denial of Service"),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DedupKey {
    kind: String,
    category: Option<String>,
    function_id: Option<u32>,
    file: Option<String>,
}

fn deduplicate_rows(rows: Vec<HybridFindingRow>) -> Vec<HybridFindingRow> {
    let mut grouped = HashMap::<DedupKey, HybridFindingRow>::new();

    for row in rows {
        let key = DedupKey {
            kind: row.kind.clone(),
            category: row.category.clone(),
            function_id: row.function_id,
            file: row.file.clone(),
        };

        if let Some(existing) = grouped.get_mut(&key) {
            merge_rows(existing, row);
        } else {
            grouped.insert(key, row);
        }
    }

    let mut deduped = grouped.into_values().collect::<Vec<_>>();
    deduped.sort_by(|left, right| {
        (
            severity_rank(left.severity.as_deref()),
            left.kind.as_str(),
            left.file.as_deref().unwrap_or(""),
            left.function_id.unwrap_or(0),
            left.start.unwrap_or(0),
            left.message.as_str(),
        )
            .cmp(&(
                severity_rank(right.severity.as_deref()),
                right.kind.as_str(),
                right.file.as_deref().unwrap_or(""),
                right.function_id.unwrap_or(0),
                right.start.unwrap_or(0),
                right.message.as_str(),
            ))
    });
    // Recompute the tier from the merged provenance: a static finding that fuzz
    // or SE also reported becomes hybrid-confirmed, promoting it to `confirmed`.
    for row in &mut deduped {
        row.tier = tier_for(&row.provenance).to_string();
    }
    deduped
}

fn merge_rows(existing: &mut HybridFindingRow, incoming: HybridFindingRow) {
    let merged_provenances = existing
        .provenances
        .iter()
        .cloned()
        .chain(incoming.provenances)
        .collect::<BTreeSet<_>>();
    existing.provenances = merged_provenances.into_iter().collect();
    existing.provenance = select_primary_provenance(&existing.provenances).to_string();

    existing.severity = pick_more_severe(existing.severity.take(), incoming.severity);
    existing.confidence = pick_more_confident(existing.confidence.take(), incoming.confidence);

    if existing.category.is_none() {
        existing.category = incoming.category;
    }
    if existing.file.is_none() {
        existing.file = incoming.file;
    }
    if existing.function_id.is_none() {
        existing.function_id = incoming.function_id;
    }
    existing.start = min_opt(existing.start, incoming.start);
    existing.end = max_opt(existing.end, incoming.end);
    existing.message = merge_message(existing.message.as_str(), incoming.message.as_str());
}

/// Map a provenance to its confidence tier. Dynamic execution (fuzz /
/// hybrid-confirmed) and symbolic feasibility witnesses are `confirmed`; a
/// static-only heuristic is a `candidate`.
fn tier_for(provenance: &str) -> &'static str {
    match provenance {
        "hybrid-confirmed" | "fuzz" | "symbolic" => "confirmed",
        _ => "candidate",
    }
}

fn select_primary_provenance(provenances: &[String]) -> &'static str {
    if provenances.iter().any(|p| p == "hybrid-confirmed") {
        "hybrid-confirmed"
    } else if provenances.iter().any(|p| p == "fuzz") {
        "fuzz"
    } else if provenances.iter().any(|p| p == "symbolic") {
        "symbolic"
    } else {
        "static"
    }
}

fn severity_rank(value: Option<&str>) -> u8 {
    match value.unwrap_or_default() {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    }
}

fn confidence_rank(value: Option<&str>) -> u8 {
    match value.unwrap_or_default() {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    }
}

fn pick_more_severe(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => {
            if severity_rank(Some(left.as_str())) <= severity_rank(Some(right.as_str())) {
                Some(left)
            } else {
                Some(right)
            }
        }
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn pick_more_confident(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => {
            if confidence_rank(Some(left.as_str())) <= confidence_rank(Some(right.as_str())) {
                Some(left)
            } else {
                Some(right)
            }
        }
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn min_opt(left: Option<u32>, right: Option<u32>) -> Option<u32> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn max_opt(left: Option<u32>, right: Option<u32>) -> Option<u32> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn merge_message(left: &str, right: &str) -> String {
    if left == right {
        left.to_string()
    } else if left.is_empty() {
        right.to_string()
    } else if right.is_empty() {
        left.to_string()
    } else {
        format!("{left} | {right}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_merges_same_issue_and_preserves_provenance() {
        let rows = vec![
            HybridFindingRow {
                tier: String::new(),
                provenance: "symbolic".to_string(),
                provenances: vec!["symbolic".to_string()],
                kind: "reentrancy".to_string(),
                severity: Some("medium".to_string()),
                confidence: Some("medium".to_string()),
                category: Some("Reentrancy".to_string()),
                message: "symbolic path".to_string(),
                function_id: Some(7),
                file: Some("Vault.sol".to_string()),
                start: Some(10),
                end: Some(20),
            },
            HybridFindingRow {
                tier: String::new(),
                provenance: "hybrid-confirmed".to_string(),
                provenances: vec!["hybrid-confirmed".to_string()],
                kind: "reentrancy".to_string(),
                severity: Some("high".to_string()),
                confidence: Some("high".to_string()),
                category: Some("Reentrancy".to_string()),
                message: "fuzz replay".to_string(),
                function_id: Some(7),
                file: Some("Vault.sol".to_string()),
                start: Some(12),
                end: Some(18),
            },
        ];

        let deduped = deduplicate_rows(rows);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].provenance, "hybrid-confirmed");
        assert_eq!(
            deduped[0].provenances,
            vec!["hybrid-confirmed".to_string(), "symbolic".to_string()]
        );
        assert_eq!(deduped[0].severity.as_deref(), Some("high"));
        assert_eq!(deduped[0].confidence.as_deref(), Some("high"));
        assert_eq!(deduped[0].start, Some(10));
        assert_eq!(deduped[0].end, Some(20));
    }

    #[test]
    fn dedup_keeps_distinct_files_separate() {
        let rows = vec![
            HybridFindingRow {
                tier: String::new(),
                provenance: "symbolic".to_string(),
                provenances: vec!["symbolic".to_string()],
                kind: "reentrancy".to_string(),
                severity: Some("medium".to_string()),
                confidence: Some("medium".to_string()),
                category: Some("Reentrancy".to_string()),
                message: "a".to_string(),
                function_id: Some(7),
                file: Some("A.sol".to_string()),
                start: Some(1),
                end: Some(2),
            },
            HybridFindingRow {
                tier: String::new(),
                provenance: "hybrid-confirmed".to_string(),
                provenances: vec!["hybrid-confirmed".to_string()],
                kind: "reentrancy".to_string(),
                severity: Some("high".to_string()),
                confidence: Some("high".to_string()),
                category: Some("Reentrancy".to_string()),
                message: "b".to_string(),
                function_id: Some(7),
                file: Some("B.sol".to_string()),
                start: Some(1),
                end: Some(2),
            },
        ];

        assert_eq!(deduplicate_rows(rows).len(), 2);
    }
}
