//! Optional AI review of findings (harvested from the AI-reporting feature).
//!
//! When `CHAINVET_AI_REPORT` is set, each finding is validated against its source
//! by a local LLM: findings the model judges `false_positive` are dropped, and
//! survivors gain a one-line AI rationale (and a corrected severity, if given).
//! Fully opt-in — disabled or with Ollama unreachable this is a no-op, so default
//! behaviour is unchanged.

use std::env;
use std::fs;

use chainvet_ai::ollama::{self, OllamaConfig};
use chainvet_hybrid::hybrid::HybridFindingRow as ScanFinding;

use crate::ScanResult;

const DEFAULT_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_NUM_PREDICT: u32 = 512;
const CONTEXT_PAD: usize = 400;

/// Apply AI review to a scan result in place. No-op unless enabled.
pub fn enhance(result: &mut ScanResult) {
    if !enabled() {
        return;
    }
    let config = OllamaConfig::from_env(DEFAULT_TIMEOUT_MS, DEFAULT_NUM_PREDICT);
    let reviewed: Vec<ScanFinding> = std::mem::take(&mut result.findings)
        .into_iter()
        .filter_map(|finding| review_one(&config, finding))
        .collect();
    // Keep the hybrid payload's findings consistent with the reviewed set.
    if let Some(hybrid) = result.hybrid.as_mut() {
        hybrid.findings = reviewed.clone();
    }
    result.findings = reviewed;
}

fn enabled() -> bool {
    matches!(
        env::var("CHAINVET_AI_REPORT")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Review a single finding. Returns `Some(annotated)` to keep it, `None` to drop
/// it as a false positive. On any AI error the finding is kept unchanged.
fn review_one(config: &OllamaConfig, mut finding: ScanFinding) -> Option<ScanFinding> {
    let context = source_context(&finding);
    let prompt = review_prompt(&finding, context.as_deref());
    let raw = match ollama::generate(config, &prompt) {
        Ok(raw) => raw,
        Err(err) => {
            if ollama::debug_enabled() {
                eprintln!("[ai-report] review skipped: {err}");
            }
            return Some(finding);
        }
    };
    let value = match ollama::parse_json_object(&raw) {
        Ok(value) => value,
        Err(_) => return Some(finding),
    };
    let verdict = value
        .get("verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("uncertain");
    if verdict == "false_positive" {
        return None;
    }
    if let Some(sev) = value.get("corrected_severity").and_then(|v| v.as_str()) {
        if !sev.is_empty() && sev != "null" {
            finding.severity = Some(sev.to_string());
        }
    }
    if let Some(reason) = value.get("reason").and_then(|v| v.as_str()) {
        if !reason.is_empty() {
            finding.message = format!("{} [AI: {reason}]", finding.message);
        }
    }
    Some(finding)
}

fn review_prompt(finding: &ScanFinding, source: Option<&str>) -> String {
    let source = source.unwrap_or("Source context unavailable.");
    let severity = finding.severity.as_deref().unwrap_or("unknown");
    format!(
        r#"You are Chainvet's local smart-contract audit verifier.

Validate whether the analyzer finding is correct for the provided Solidity code.
Be strict: if the source contradicts the finding, mark it false_positive; if it is
plausible but unproven, mark uncertain. Do not invent facts not in the source.

Return JSON only with this exact shape:
{{"verdict": "true_positive | false_positive | uncertain", "corrected_severity": "high | medium | low | informational | null", "reason": "short technical reason"}}

Finding: kind={kind} severity={severity}
Message: {message}

Source:
{source}"#,
        kind = finding.kind,
        message = finding.message,
    )
}

/// Read a window of the finding's source around its span for the model.
fn source_context(finding: &ScanFinding) -> Option<String> {
    let path = finding.file.as_ref()?;
    let content = fs::read_to_string(path).ok()?;
    let start = finding.start.unwrap_or(0) as usize;
    let end = finding.end.map(|e| e as usize).unwrap_or(start);
    let lo = start.saturating_sub(CONTEXT_PAD);
    let hi = (end + CONTEXT_PAD).min(content.len());
    // Snap to char boundaries so the slice is valid UTF-8.
    let lo = (0..=lo).rev().find(|&i| content.is_char_boundary(i))?;
    let hi = (hi..=content.len()).find(|&i| content.is_char_boundary(i))?;
    Some(content[lo..hi].to_string())
}
