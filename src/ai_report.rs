use crate::report::{AiFindingReview, AuditFinding, AuditMetric, AuditReport, ReportReviewSummary};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:11434";
const DEFAULT_MODEL: &str = "qwen2.5-coder:7b";
const DEFAULT_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_MAX_FINDINGS: usize = 1_000;
const DEFAULT_NUM_PREDICT: u32 = 512;

pub fn enhance_report_if_enabled(report: &AuditReport) -> AuditReport {
    if !ai_enabled()
        || report.findings.is_empty()
        || report
            .metrics
            .iter()
            .any(|metric| metric.label == "AI review")
    {
        return report.clone();
    }

    match enhance_report(report) {
        Ok(report) => report,
        Err(err) => {
            debug_log(format!("AI report enhancement skipped: {err}"));
            report.clone()
        }
    }
}

fn enhance_report(report: &AuditReport) -> std::result::Result<AuditReport, String> {
    let config = AiConfig::from_env();
    let max_findings = config.max_findings.min(report.findings.len());
    let mut enhanced = report.clone();
    let source_cache = load_source_contexts(report);
    let original_findings = std::mem::take(&mut enhanced.findings);
    let mut stats = ReviewStats::default();
    let mut reviewed_candidates = Vec::new();
    let mut kept_by_original_index = vec![None; original_findings.len()];

    for (idx, finding) in original_findings.iter().cloned().enumerate() {
        let context = source_for_finding(report, &finding, &source_cache);
        if let Some(reason) =
            deterministic_filter_reason(report, &finding, &original_findings, context.as_deref())
        {
            stats.filtered += 1;
            stats.deterministic_filtered += 1;
            debug_log(format!(
                "AI prefilter removed {}: {reason}",
                finding
                    .function_name
                    .as_deref()
                    .unwrap_or(finding.kind.as_str())
            ));
            continue;
        }
        reviewed_candidates.push((idx, finding, context));
    }

    reviewed_candidates
        .sort_by(|(_, left, _), (_, right, _)| review_priority(left).cmp(&review_priority(right)));
    stats.ai_candidates = reviewed_candidates.len();

    for (idx, mut finding, context) in reviewed_candidates {
        if stats.attempted >= max_findings {
            stats.skipped += 1;
            kept_by_original_index[idx] = Some(finding);
            continue;
        }

        stats.attempted += 1;
        match review_finding(&config, report, &finding, context.as_deref()) {
            Ok(review) => {
                stats.reviewed += 1;
                if review.verdict == "false_positive" {
                    stats.filtered += 1;
                    stats.ai_filtered += 1;
                    continue;
                }
                if let Some(severity) = corrected_severity(&review) {
                    finding.severity = severity;
                }
                finding.ai_review = Some(review);
                kept_by_original_index[idx] = Some(finding);
            }
            Err(err) => {
                stats.failed += 1;
                debug_log(format!(
                    "AI review skipped for {}: {err}",
                    finding
                        .function_name
                        .as_deref()
                        .unwrap_or(finding.kind.as_str())
                ));
                kept_by_original_index[idx] = Some(finding);
            }
        }
    }

    enhanced.findings = kept_by_original_index.into_iter().flatten().collect();
    enhanced.suppressed_findings = enhanced.suppressed_findings.saturating_add(stats.filtered);
    stats.final_findings = enhanced.findings.len();
    enhanced.review_summary = Some(ReportReviewSummary {
        raw_findings: original_findings.len(),
        deterministic_filtered: stats.deterministic_filtered,
        ai_candidates: stats.ai_candidates,
        ai_attempted: stats.attempted,
        ai_reviewed: stats.reviewed,
        ai_filtered: stats.ai_filtered,
        failed: stats.failed,
        skipped: stats.skipped,
        final_findings: stats.final_findings,
        model: config.model.clone(),
    });
    enhanced.metrics.push(AuditMetric::new(
        "AI review",
        ai_metric(&stats, &config.model),
    ));
    Ok(enhanced)
}

fn review_finding(
    config: &AiConfig,
    report: &AuditReport,
    finding: &AuditFinding,
    source_context: Option<&str>,
) -> std::result::Result<AiFindingReview, String> {
    let prompt = review_prompt(report, finding, source_context);
    let response = ollama_generate(config, &prompt)?;
    let mut review = parse_review(&response)?;
    sanitize_review_output(finding, source_context, &mut review);
    Ok(review)
}

fn review_prompt(
    report: &AuditReport,
    finding: &AuditFinding,
    source_context: Option<&str>,
) -> String {
    let source = source_context.unwrap_or("Source context unavailable.");
    format!(
        r#"You are ChainVet's local smart-contract audit verifier.

Task:
Validate whether the analyzer finding is correct for the provided Solidity code. Be strict. If the source contradicts the finding, mark it false_positive. If the finding is directionally plausible but unproven, mark uncertain. Do not invent facts not present in the source.

Return JSON only with this exact shape:
{{
  "verdict": "true_positive | false_positive | uncertain",
  "corrected_severity": "high | medium | low | informational | null",
  "reason": "short technical reason",
  "improved_poc": "specific exploit flow or Solidity snippet; no generic filler",
  "improved_remediation": "specific remediation for this code",
  "improved_remediation_code": "Solidity remediation snippet or empty string"
}}

Rules:
- Solidity version matters. Use syntax compatible with the pragma when writing snippets.
- If the source uses Solidity 0.4.x, do not use constructor(), receive(), call{{value: ...}}, or revert reasons.
- For a true_positive, improved_poc must describe the exact vulnerable function and concrete abuse path. A snippet must set up the target and call the affected function.
- For a true_positive, improved_remediation must name the exact state update / check / external call ordering fix for this code.
- For a false_positive, explain the exact source statement that disproves the finding and leave improved_remediation_code empty.
- A user withdrawing their own balance is not an access-control bug by itself.
- transfer/send fixed gas stipend is normally a DoS/liveness concern, not classic reentrancy.
- A low-level call wrapped in an if/require that reverts on failure is not unchecked.
- Checks-effects-interactions means state is updated before external calls.

Report target: {target}
Analysis mode: {mode}

Finding:
- kind: {kind}
- category: {category}
- severity: {severity}
- confidence: {confidence}
- function: {function}
- analysis layer: {layer}
- evidence: {evidence}
- message: {message}

Source context:
```solidity
{source}
```
"#,
        target = report.target,
        mode = report.analysis_mode,
        kind = finding.kind,
        category = finding.category,
        severity = finding.severity,
        confidence = finding.confidence.as_deref().unwrap_or("unknown"),
        function = finding.function_name.as_deref().unwrap_or("<unknown>"),
        layer = finding.analysis_layer,
        evidence = finding.evidence_kind.as_deref().unwrap_or("unknown"),
        message = finding.message,
        source = truncate_chars(source, 7_000)
    )
}

fn parse_review(raw: &str) -> std::result::Result<AiFindingReview, String> {
    let value = parse_json_object(raw)?;
    let verdict = normalize_verdict(string_field(&value, "verdict").unwrap_or("uncertain"));
    let reason = string_field(&value, "reason")
        .unwrap_or("")
        .trim()
        .to_string();
    if reason.is_empty() {
        return Err("missing AI review reason".to_string());
    }

    Ok(AiFindingReview {
        verdict,
        corrected_severity: non_empty_string_field(&value, "corrected_severity")
            .map(|value| normalize_severity(value.as_str()))
            .filter(|value| !value.is_empty()),
        reason,
        improved_poc: non_empty_string_field(&value, "improved_poc"),
        improved_remediation: non_empty_string_field(&value, "improved_remediation"),
        improved_remediation_code: non_empty_string_field(&value, "improved_remediation_code"),
    })
}

fn sanitize_review_output(
    finding: &AuditFinding,
    source_context: Option<&str>,
    review: &mut AiFindingReview,
) {
    let kind = crate::surfaced::canonicalize_kind(finding.kind.as_str());
    let compact_source = compact_solidity(source_context.unwrap_or_default());

    if review.verdict == "false_positive" {
        if kind == "hardcoded-gas-transfer"
            && uses_transfer_or_send_without_low_level_call(compact_source.as_str())
        {
            review.reason = "The source uses transfer/send fixed-gas semantics, but this is treated as a low-severity liveness/compatibility note rather than a confirmed exploitable vulnerability in this report context.".to_string();
        }
        review.improved_poc = None;
        review.improved_remediation_code = None;
        return;
    }

    let function = finding.function_name.as_deref().unwrap_or("");
    if let Some(poc) = review.improved_poc.as_deref() {
        let poc_lc = poc.to_ascii_lowercase();
        let function_lc = function.to_ascii_lowercase();
        let useful = !function_lc.is_empty() && poc_lc.contains(function_lc.as_str());
        let generic = poc_lc.contains("specific exploit flow")
            || poc_lc.contains("no generic filler")
            || poc.trim().len() < 40;
        if !useful || generic {
            review.improved_poc = None;
        }
    }

    if let Some(remediation) = review.improved_remediation.as_deref() {
        let remediation_lc = remediation.to_ascii_lowercase();
        let useful = remediation_lc.contains("state")
            || remediation_lc.contains("check")
            || remediation_lc.contains("access")
            || remediation_lc.contains("require")
            || remediation_lc.contains("transfer")
            || remediation_lc.contains("call");
        if !useful || remediation.trim().len() < 30 {
            review.improved_remediation = None;
        }
    }

    if let Some(code) = review.improved_remediation_code.as_deref() {
        if !looks_like_solidity_remediation(code) {
            review.improved_remediation_code = None;
        }
    }
}

fn looks_like_solidity_remediation(code: &str) -> bool {
    let code_lc = code.to_ascii_lowercase();
    code_lc.contains("function")
        && (code_lc.contains("require")
            || code_lc.contains("throw")
            || code_lc.contains("revert")
            || code_lc.contains("userbalance")
            || code_lc.contains("balances"))
}

fn parse_json_object(raw: &str) -> std::result::Result<Value, String> {
    if let Ok(value) = serde_json::from_str::<Value>(raw) {
        return Ok(value);
    }
    let start = raw
        .find('{')
        .ok_or_else(|| "AI response had no JSON object".to_string())?;
    let end = raw
        .rfind('}')
        .ok_or_else(|| "AI response had no JSON object end".to_string())?;
    serde_json::from_str(&raw[start..=end])
        .map_err(|err| format!("failed to parse AI JSON response: {err}"))
}

fn ollama_generate(config: &AiConfig, prompt: &str) -> std::result::Result<String, String> {
    let body = json!({
        "model": config.model,
        "prompt": prompt,
        "stream": false,
        "format": "json",
        "options": {
            "temperature": 0.1,
            "num_ctx": 8192,
            "num_predict": config.num_predict
        }
    })
    .to_string();

    let response = http_post_json(&config.endpoint, "/api/generate", &body, config.timeout)?;
    let parsed = serde_json::from_str::<Value>(&response)
        .map_err(|err| format!("failed to parse Ollama response: {err}"))?;
    parsed
        .get("response")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "Ollama response did not contain a response field".to_string())
}

fn http_post_json(
    endpoint: &str,
    path: &str,
    body: &str,
    timeout: Duration,
) -> std::result::Result<String, String> {
    let endpoint = endpoint.trim_end_matches('/');
    let (host, port) = parse_http_endpoint(endpoint)?;
    let mut stream = TcpStream::connect(format!("{host}:{port}"))
        .map_err(|err| format!("failed to connect to Ollama at {endpoint}: {err}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| format!("failed to set Ollama read timeout: {err}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| format!("failed to set Ollama write timeout: {err}"))?;

    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|err| format!("failed to write Ollama request: {err}"))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|err| format!("failed to read Ollama response: {err}"))?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| "malformed Ollama HTTP response".to_string())?;
    if !headers.starts_with("HTTP/1.1 200") && !headers.starts_with("HTTP/1.0 200") {
        return Err(format!(
            "Ollama returned non-200 response: {}",
            headers.lines().next().unwrap_or("unknown status")
        ));
    }
    if headers
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        decode_chunked_body(body)
    } else {
        Ok(body.to_string())
    }
}

fn decode_chunked_body(body: &str) -> std::result::Result<String, String> {
    let bytes = body.as_bytes();
    let mut pos = 0usize;
    let mut out = Vec::new();
    loop {
        let size_end =
            find_crlf(bytes, pos).ok_or_else(|| "malformed chunked Ollama response".to_string())?;
        let size_line = std::str::from_utf8(&bytes[pos..size_end])
            .map_err(|err| format!("invalid chunk header from Ollama: {err}"))?;
        let size_hex = size_line.split(';').next().unwrap_or(size_line).trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|err| format!("invalid chunk size from Ollama: {err}"))?;
        pos = size_end + 2;
        if size == 0 {
            break;
        }
        if bytes.len() < pos + size + 2 {
            return Err("truncated chunked Ollama response".to_string());
        }
        out.extend_from_slice(&bytes[pos..pos + size]);
        pos += size;
        if bytes.get(pos..pos + 2) != Some(b"\r\n") {
            return Err("malformed chunk terminator from Ollama".to_string());
        }
        pos += 2;
    }
    String::from_utf8(out).map_err(|err| format!("invalid UTF-8 Ollama response body: {err}"))
}

fn find_crlf(bytes: &[u8], start: usize) -> Option<usize> {
    bytes
        .get(start..)?
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|offset| start + offset)
}

fn parse_http_endpoint(endpoint: &str) -> std::result::Result<(String, u16), String> {
    let without_scheme = endpoint
        .strip_prefix("http://")
        .ok_or_else(|| "only http:// Ollama endpoints are supported".to_string())?;
    let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse::<u16>()
                .map_err(|err| format!("invalid Ollama endpoint port: {err}"))?;
            (host.to_string(), port)
        }
        None => (authority.to_string(), 80),
    };
    if host.is_empty() {
        return Err("empty Ollama endpoint host".to_string());
    }
    Ok((host, port))
}

fn load_source_contexts(report: &AuditReport) -> Vec<(String, String)> {
    let mut paths = Vec::<String>::new();
    if Path::new(&report.target).is_file() {
        paths.push(report.target.clone());
    }
    for finding in &report.findings {
        if let Some(file) = finding.file.as_deref() {
            if !paths.iter().any(|existing| existing == file) && Path::new(file).is_file() {
                paths.push(file.to_string());
            }
        }
    }
    paths
        .into_iter()
        .filter_map(|path| fs::read_to_string(&path).ok().map(|source| (path, source)))
        .collect()
}

fn source_for_finding(
    report: &AuditReport,
    finding: &AuditFinding,
    source_cache: &[(String, String)],
) -> Option<String> {
    let wanted = finding.file.as_deref().unwrap_or(report.target.as_str());
    let source = source_cache
        .iter()
        .find(|(path, _)| path == wanted)
        .or_else(|| source_cache.first())?
        .1
        .as_str();
    Some(extract_source_context(source, finding))
}

fn extract_source_context(source: &str, finding: &AuditFinding) -> String {
    if let (Some(start), Some(end)) = (finding.start, finding.end) {
        let start = start as usize;
        let end = end as usize;
        if start < source.len() && end <= source.len() && start < end {
            let lo = previous_line_boundary(source, start.saturating_sub(500));
            let hi = next_line_boundary(source, (end + 500).min(source.len()));
            return source[lo..hi].to_string();
        }
    }

    if let Some(function) = finding.function_name.as_deref() {
        if let Some(idx) = source.find(&format!("function {function}")) {
            let tail = &source[idx..];
            let hi_rel = tail
                .find("\n    function ")
                .or_else(|| tail.find("\n\tfunction "))
                .unwrap_or_else(|| tail.len().min(2_500));
            let hi = next_line_boundary(source, (idx + hi_rel).min(source.len()));
            return source[previous_line_boundary(source, idx)..hi].to_string();
        }
    }

    truncate_chars(source, 7_000)
}

fn previous_line_boundary(text: &str, mut idx: usize) -> usize {
    while idx > 0 && !text.is_char_boundary(idx) {
        idx -= 1;
    }
    text[..idx].rfind('\n').map(|pos| pos + 1).unwrap_or(0)
}

fn next_line_boundary(text: &str, mut idx: usize) -> usize {
    while idx < text.len() && !text.is_char_boundary(idx) {
        idx += 1;
    }
    text[idx..]
        .find('\n')
        .map(|pos| idx + pos)
        .unwrap_or(text.len())
}

fn ai_enabled() -> bool {
    matches!(
        env::var("CHAINVET_AI_REPORT")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn corrected_severity(review: &AiFindingReview) -> Option<String> {
    review.corrected_severity.clone()
}

fn deterministic_filter_reason(
    report: &AuditReport,
    finding: &AuditFinding,
    all_findings: &[AuditFinding],
    source_context: Option<&str>,
) -> Option<String> {
    let kind = crate::surfaced::canonicalize_kind(finding.kind.as_str());
    let source = source_context.unwrap_or_default();
    let compact = compact_solidity(source);

    if kind == "reentrancy" && has_stronger_same_function_finding(finding, all_findings) {
        return Some(
            "duplicate lower-confidence reentrancy finding for the same function".to_string(),
        );
    }

    if kind == "reentrancy" && fixed_before_low_level_call(compact.as_str()) {
        return Some("state is cleared before the low-level external call".to_string());
    }

    if kind == "reentrancy" && uses_transfer_or_send_without_low_level_call(compact.as_str()) {
        return Some("transfer/send fixed-gas path is not classic reentrancy".to_string());
    }

    if matches!(kind.as_str(), "unchecked-call" | "exception-disorder")
        && low_level_call_reverts_on_failure(compact.as_str())
    {
        return Some("low-level call return value is checked and failure reverts".to_string());
    }

    if kind == "exception-disorder"
        && uses_transfer_or_send_without_low_level_call(compact.as_str())
    {
        return Some(
            "transfer/send reverts on failure instead of returning unchecked false".to_string(),
        );
    }

    if kind == "unprotected-ether-withdrawal" && sender_owned_withdrawal(compact.as_str()) {
        return Some(
            "function withdraws msg.sender-owned accounting, not arbitrary funds".to_string(),
        );
    }

    if report.analysis_mode == "hybrid"
        && kind == "unchecked-call"
        && has_stronger_same_function_kind(finding, all_findings, "reentrancy")
    {
        return Some(
            "same function has a stronger reentrancy finding that explains the risk".to_string(),
        );
    }

    None
}

fn has_stronger_same_function_finding(
    finding: &AuditFinding,
    all_findings: &[AuditFinding],
) -> bool {
    let kind = crate::surfaced::canonicalize_kind(finding.kind.as_str());
    let function = finding.function_name.as_deref();
    function.is_some()
        && all_findings.iter().any(|other| {
            !std::ptr::eq(other, finding)
                && other.function_name.as_deref() == function
                && crate::surfaced::canonicalize_kind(other.kind.as_str()) == kind
                && finding_strength(other) < finding_strength(finding)
        })
}

fn has_stronger_same_function_kind(
    finding: &AuditFinding,
    all_findings: &[AuditFinding],
    stronger_kind: &str,
) -> bool {
    let function = finding.function_name.as_deref();
    function.is_some()
        && all_findings.iter().any(|other| {
            other.function_name.as_deref() == function
                && crate::surfaced::canonicalize_kind(other.kind.as_str()) == stronger_kind
                && finding_strength(other) <= finding_strength(finding)
        })
}

fn finding_strength(finding: &AuditFinding) -> (u8, u8, u8) {
    (
        severity_rank(finding.severity.as_str()),
        confidence_rank(finding.confidence.as_deref()),
        evidence_rank(finding.evidence_kind.as_deref()),
    )
}

fn review_priority(finding: &AuditFinding) -> (u8, u8, u8, u8, String) {
    (
        severity_rank(finding.severity.as_str()),
        confidence_rank(finding.confidence.as_deref()),
        evidence_rank(finding.evidence_kind.as_deref()),
        category_rank(finding.kind.as_str()),
        finding
            .function_name
            .as_deref()
            .unwrap_or(finding.kind.as_str())
            .to_string(),
    )
}

fn severity_rank(value: &str) -> u8 {
    let value = value.trim().to_ascii_lowercase();
    if value.contains("critical") || value.contains("high") {
        0
    } else if value.contains("medium") || value.contains("moderate") {
        1
    } else if value.contains("low") {
        2
    } else {
        3
    }
}

fn confidence_rank(value: Option<&str>) -> u8 {
    match value.unwrap_or("").trim().to_ascii_lowercase().as_str() {
        "high" => 0,
        "medium" | "moderate" => 1,
        "low" => 2,
        _ => 3,
    }
}

fn evidence_rank(value: Option<&str>) -> u8 {
    match value.unwrap_or("").trim().to_ascii_lowercase().as_str() {
        "rule-backstop" => 0,
        "executor" => 1,
        "static" => 2,
        _ => 3,
    }
}

fn category_rank(kind: &str) -> u8 {
    match crate::surfaced::canonicalize_kind(kind).as_str() {
        "reentrancy" => 0,
        "unprotected-ether-withdrawal" => 1,
        "unchecked-call" | "exception-disorder" => 2,
        "hardcoded-gas-transfer" => 3,
        _ => 4,
    }
}

fn compact_solidity(source: &str) -> String {
    source
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn fixed_before_low_level_call(source: &str) -> bool {
    let Some(call_pos) = first_position(source, &[".call.value(", ".call{"]) else {
        return false;
    };
    let Some(zero_pos) = first_position(source, &["userbalance[msg.sender]=0"]) else {
        return false;
    };
    zero_pos < call_pos
}

fn low_level_call_reverts_on_failure(source: &str) -> bool {
    first_position(source, &[".call.value(", ".call{"]).is_some()
        && (source.contains("if(!(") || source.contains("require("))
        && (source.contains("throw;") || source.contains("revert(") || source.contains("require("))
}

fn uses_transfer_or_send_without_low_level_call(source: &str) -> bool {
    (source.contains(".transfer(") || source.contains(".send("))
        && first_position(source, &[".call.value(", ".call{"]).is_none()
}

fn sender_owned_withdrawal(source: &str) -> bool {
    source.contains("msg.sender.transfer(userbalance[msg.sender])")
        || source.contains("msg.sender.send(userbalance[msg.sender])")
        || source.contains("msg.sender.call.value(userbalance[msg.sender])")
}

fn first_position(source: &str, patterns: &[&str]) -> Option<usize> {
    patterns
        .iter()
        .filter_map(|pattern| source.find(pattern))
        .min()
}

fn normalize_verdict(value: &str) -> String {
    match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "true_positive" | "true" | "valid" => "true_positive".to_string(),
        "false_positive" | "false" | "invalid" => "false_positive".to_string(),
        _ => "uncertain".to_string(),
    }
}

fn normalize_severity(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "high" | "medium" | "low" | "informational" | "info" => {
            if value.trim().eq_ignore_ascii_case("info") {
                "informational".to_string()
            } else {
                value.trim().to_ascii_lowercase()
            }
        }
        _ => String::new(),
    }
}

fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn non_empty_string_field(value: &Value, key: &str) -> Option<String> {
    string_field(value, key)
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "null")
        .map(str::to_string)
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (idx, ch) in text.chars().enumerate() {
        if idx >= max_chars {
            out.push_str("\n// ... truncated ...");
            break;
        }
        out.push(ch);
    }
    out
}

fn ai_metric(stats: &ReviewStats, model: &str) -> String {
    if stats.reviewed == 0 {
        format!(
            "raw {}; deterministic prefilter removed {}; AI reviewed 0/{} remaining; AI removed 0; final {}; failed {}; skipped {}; model {model}",
            stats.raw_findings(),
            stats.deterministic_filtered,
            stats.ai_candidates,
            stats.final_findings,
            stats.failed,
            stats.skipped
        )
    } else {
        format!(
            "raw {}; deterministic prefilter removed {}; AI reviewed {}/{} remaining; AI removed {}; final {}; failed {}; skipped {}; model {model}",
            stats.raw_findings(),
            stats.deterministic_filtered,
            stats.reviewed,
            stats.ai_candidates,
            stats.ai_filtered,
            stats.final_findings,
            stats.failed,
            stats.skipped
        )
    }
}

fn debug_log(message: String) {
    if env::var("CHAINVET_AI_DEBUG").ok().as_deref() == Some("1") {
        eprintln!("{message}");
    }
}

#[derive(Default)]
struct ReviewStats {
    ai_candidates: usize,
    attempted: usize,
    reviewed: usize,
    filtered: usize,
    ai_filtered: usize,
    deterministic_filtered: usize,
    failed: usize,
    skipped: usize,
    final_findings: usize,
}

impl ReviewStats {
    fn raw_findings(&self) -> usize {
        self.deterministic_filtered + self.ai_candidates
    }
}

struct AiConfig {
    endpoint: String,
    model: String,
    timeout: Duration,
    max_findings: usize,
    num_predict: u32,
}

impl AiConfig {
    fn from_env() -> Self {
        let endpoint =
            env::var("CHAINVET_AI_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string());
        let model = env::var("CHAINVET_AI_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_string());
        let timeout_ms = env::var("CHAINVET_AI_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_TIMEOUT_MS);
        let max_findings = env::var("CHAINVET_AI_MAX_FINDINGS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_FINDINGS);
        let num_predict = env::var("CHAINVET_AI_NUM_PREDICT")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(DEFAULT_NUM_PREDICT);
        Self {
            endpoint,
            model,
            timeout: Duration::from_millis(timeout_ms),
            max_findings,
            num_predict,
        }
    }
}
