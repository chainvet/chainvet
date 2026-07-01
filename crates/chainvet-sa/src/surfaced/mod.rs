use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};

const LOW_SIGNAL_KINDS: &[&str] = &[
    "default-visibility",
    "storage-array-by-value",
    "missing-input-validation",
    "tainted-call",
];

#[derive(Debug, Clone)]
pub struct FindingCandidate {
    pub kind: String,
    pub canonical_kind: String,
    pub category: String,
    pub severity: String,
    pub confidence: Option<String>,
    pub message: String,
    pub file: Option<String>,
    pub start: Option<u32>,
    pub end: Option<u32>,
    pub function_id: Option<u32>,
    pub function_name: Option<String>,
    pub analysis_layer: String,
    pub evidence_kind: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SurfacedFinding {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_kind: Option<String>,
    pub category: String,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,
    pub analysis_layer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_kind: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SurfacedCount {
    pub kind: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SurfaceBundle {
    pub runtime_findings: Vec<SurfacedFinding>,
    pub runtime_finding_counts: Vec<SurfacedCount>,
    pub raw_runtime_findings: usize,
    pub suppressed_runtime_findings: usize,
    pub meta_findings: Vec<SurfacedFinding>,
    pub meta_finding_counts: Vec<SurfacedCount>,
    pub raw_meta_findings: usize,
    pub suppressed_meta_findings: usize,
}

pub fn canonicalize_kind(kind: &str) -> String {
    let normalized = kind.trim();
    if normalized.is_empty() {
        return String::new();
    }
    if normalized.starts_with("reentrancy") {
        return "reentrancy".to_string();
    }
    match normalized {
        "hardcoded-gas" => "hardcoded-gas-transfer".to_string(),
        "storage-memory-issue" => "memory-manipulation".to_string(),
        "unused-return-value" => "unchecked-call".to_string(),
        "dangerous-block-timestamp" => "timestamp-dependency".to_string(),
        "underflow" => "integer-underflow".to_string(),
        "force-ether-balance-check" => "locked-ether".to_string(),
        _ => normalized.to_string(),
    }
}

pub fn default_category_for_kind(kind: &str) -> &'static str {
    match canonicalize_kind(kind).as_str() {
        "access-control"
        | "arbitrary-write"
        | "unchecked-call"
        | "exception-disorder"
        | "tx-origin"
        | "unprotected-selfdestruct"
        | "unsafe-delegatecall"
        | "wrong-constructor-name"
        | "uninit-permission-check"
        | "unprotected-ether-withdrawal"
        | "public-mint-burn" => "Access Control",
        "integer-overflow" | "integer-underflow" | "division-before-multiplication" => "Arithmetic",
        "weak-prng" | "timestamp-dependency" | "transaction-order-dependency" => {
            "Block Manipulation"
        }
        "dos-block-gas-limit"
        | "dos-with-failed-call"
        | "hardcoded-gas-transfer"
        | "locked-ether" => "Denial of Service",
        "memory-manipulation" | "shadowing" => "Storage and Memory",
        "reentrancy" => "Reentrancy",
        "cryptographic-issue" | "signature-malleability" => "Cryptographic",
        _ => "Miscellaneous",
    }
}

pub fn surface_findings(
    runtime_candidates: Vec<FindingCandidate>,
    meta_candidates: Vec<FindingCandidate>,
) -> SurfaceBundle {
    let raw_runtime_findings = runtime_candidates.len();
    let raw_meta_findings = meta_candidates.len();

    let runtime_deduped = deduplicate(runtime_candidates);
    let runtime_findings = suppress_low_signal(runtime_deduped);
    let runtime_keys = runtime_findings
        .iter()
        .map(runtime_kind_context_key)
        .collect::<HashSet<_>>();

    let meta_deduped = deduplicate(meta_candidates);
    let meta_findings = suppress_meta(meta_deduped, &runtime_keys);

    let runtime_finding_counts = build_counts(&runtime_findings);
    let meta_finding_counts = build_counts(&meta_findings);
    let runtime_findings = runtime_findings
        .into_iter()
        .map(to_surfaced_finding)
        .collect::<Vec<_>>();
    let meta_findings = meta_findings
        .into_iter()
        .map(to_surfaced_finding)
        .collect::<Vec<_>>();

    SurfaceBundle {
        suppressed_runtime_findings: raw_runtime_findings.saturating_sub(runtime_findings.len()),
        suppressed_meta_findings: raw_meta_findings.saturating_sub(meta_findings.len()),
        raw_runtime_findings,
        raw_meta_findings,
        runtime_findings,
        runtime_finding_counts,
        meta_findings,
        meta_finding_counts,
    }
}

fn deduplicate(candidates: Vec<FindingCandidate>) -> Vec<FindingCandidate> {
    let mut best_by_key = HashMap::<DedupKey, FindingCandidate>::new();
    for candidate in candidates
        .into_iter()
        .filter(|candidate| !candidate.kind.is_empty())
    {
        let key = dedup_key(&candidate);
        match best_by_key.get_mut(&key) {
            None => {
                best_by_key.insert(key, candidate);
            }
            Some(existing) => {
                if is_better_candidate(&candidate, existing) {
                    *existing = candidate;
                }
            }
        }
    }

    let mut out = best_by_key.into_values().collect::<Vec<_>>();
    out.sort_by_key(sort_key);
    out
}

fn suppress_low_signal(candidates: Vec<FindingCandidate>) -> Vec<FindingCandidate> {
    let strong_contexts = candidates
        .iter()
        .filter(|candidate| !is_low_signal(&candidate.canonical_kind))
        .map(context_key)
        .collect::<HashSet<_>>();
    let any_strong = !strong_contexts.is_empty();

    candidates
        .into_iter()
        .filter(|candidate| {
            if !is_low_signal(&candidate.canonical_kind) {
                return true;
            }
            !any_strong || !strong_contexts.contains(&context_key(candidate))
        })
        .collect()
}

fn suppress_meta(
    candidates: Vec<FindingCandidate>,
    runtime_keys: &HashSet<RuntimeKindContextKey>,
) -> Vec<FindingCandidate> {
    candidates
        .into_iter()
        .filter(|candidate| candidate.evidence_kind.as_deref() != Some("taxonomy-completion"))
        .filter(|candidate| !runtime_keys.contains(&runtime_kind_context_key(candidate)))
        .collect()
}

fn build_counts(candidates: &[FindingCandidate]) -> Vec<SurfacedCount> {
    let mut counts = BTreeMap::<String, usize>::new();
    for candidate in candidates {
        *counts.entry(candidate.canonical_kind.clone()).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(kind, count)| SurfacedCount { kind, count })
        .collect()
}

fn to_surfaced_finding(candidate: FindingCandidate) -> SurfacedFinding {
    let raw_kind = (candidate.kind != candidate.canonical_kind).then_some(candidate.kind);
    SurfacedFinding {
        kind: candidate.canonical_kind,
        raw_kind,
        category: candidate.category,
        severity: candidate.severity,
        confidence: candidate.confidence,
        message: candidate.message,
        file: candidate.file,
        start: candidate.start,
        end: candidate.end,
        function_id: candidate.function_id,
        function_name: candidate.function_name,
        analysis_layer: candidate.analysis_layer,
        evidence_kind: candidate.evidence_kind,
    }
}

fn is_low_signal(kind: &str) -> bool {
    LOW_SIGNAL_KINDS.contains(&kind)
}

fn is_better_candidate(candidate: &FindingCandidate, existing: &FindingCandidate) -> bool {
    candidate_score(candidate) > candidate_score(existing)
        || (candidate_score(candidate) == candidate_score(existing)
            && candidate.message.len() < existing.message.len())
        || (candidate_score(candidate) == candidate_score(existing)
            && candidate.message.len() == existing.message.len()
            && candidate.start.unwrap_or(u32::MAX) < existing.start.unwrap_or(u32::MAX))
}

fn candidate_score(candidate: &FindingCandidate) -> (u8, u8, u8, u8, u8) {
    (
        severity_rank(candidate.severity.as_str()),
        confidence_rank(candidate.confidence.as_deref()),
        evidence_rank(candidate.evidence_kind.as_deref()),
        u8::from(candidate.function_id.is_some() || candidate.function_name.is_some()),
        u8::from(candidate.file.is_some()),
    )
}

fn severity_rank(value: &str) -> u8 {
    match value {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn confidence_rank(value: Option<&str>) -> u8 {
    match value {
        Some("high") => 3,
        Some("medium") => 2,
        Some("low") => 1,
        _ => 0,
    }
}

fn evidence_rank(value: Option<&str>) -> u8 {
    match value.unwrap_or_default() {
        "rule" | "executor" => 4,
        value if value.contains("heuristic") => 1,
        value if value.contains("backstop") => 2,
        "taxonomy-completion" => 0,
        _ => 3,
    }
}

fn sort_key(candidate: &FindingCandidate) -> (String, Option<u32>, String, String, u32) {
    (
        candidate.file.clone().unwrap_or_default(),
        candidate.function_id,
        candidate.function_name.clone().unwrap_or_default(),
        candidate.canonical_kind.clone(),
        candidate.start.unwrap_or(0),
    )
}

type DedupKey = (String, String, String, Option<u32>, String);
type ContextKey = (String, Option<u32>, String);
type RuntimeKindContextKey = (String, String, Option<u32>, String);

fn dedup_key(candidate: &FindingCandidate) -> DedupKey {
    (
        candidate.analysis_layer.clone(),
        candidate.canonical_kind.clone(),
        candidate.file.clone().unwrap_or_default(),
        candidate.function_id,
        candidate.function_name.clone().unwrap_or_default(),
    )
}

fn context_key(candidate: &FindingCandidate) -> ContextKey {
    (
        candidate.file.clone().unwrap_or_default(),
        candidate.function_id,
        candidate.function_name.clone().unwrap_or_default(),
    )
}

fn runtime_kind_context_key(candidate: &FindingCandidate) -> RuntimeKindContextKey {
    (
        candidate.canonical_kind.clone(),
        candidate.file.clone().unwrap_or_default(),
        candidate.function_id,
        candidate.function_name.clone().unwrap_or_default(),
    )
}
