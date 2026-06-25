use crate::analysis::detectors::{self, Finding, Severity};
use crate::analysis::{self, ResolvedTarget};
use crate::frontend::{FrontendMode, FrontendOutput};
use crate::meta;
use crate::norm::{ExprKind, Function, FunctionKind, NormalizedAst};
use crate::surfaced;
use crate::util::error::{Error, Result};
use crate::{cfg, ir, ssa};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const CHAINVET_LOGO_PNG: &[u8] = include_bytes!("../web/assets/logo.png");
const CHAINVET_LOGO_JPEG: &[u8] = include_bytes!("../web/assets/logo-pdf.jpg");

pub enum OutputFormat {
    Text,
    Json,
    Markdown,
    Pdf,
}

pub fn print_report(
    output: &FrontendOutput,
    requested_path: &str,
    format: OutputFormat,
) -> Result<()> {
    let report = build_report(output, requested_path);
    match format {
        OutputFormat::Text => print_text(&report),
        OutputFormat::Json => print_json(&report),
        OutputFormat::Markdown => print_markdown(&report, requested_path),
        OutputFormat::Pdf => print_pdf(&report, requested_path),
    }
}

#[derive(Debug, Clone)]
pub struct AuditMetric {
    pub label: String,
    pub value: String,
}

impl AuditMetric {
    pub fn new(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditFinding {
    pub category: String,
    pub kind: String,
    pub severity: String,
    pub confidence: Option<String>,
    pub message: String,
    pub file: Option<String>,
    pub start: Option<u32>,
    pub end: Option<u32>,
    pub function_name: Option<String>,
    pub analysis_layer: String,
    pub evidence_kind: Option<String>,
    pub ai_review: Option<AiFindingReview>,
}

impl AuditFinding {
    pub fn from_surfaced(finding: &surfaced::SurfacedFinding) -> Self {
        Self {
            category: finding.category.clone(),
            kind: finding.kind.clone(),
            severity: finding.severity.clone(),
            confidence: finding.confidence.clone(),
            message: finding.message.clone(),
            file: finding.file.clone(),
            start: finding.start,
            end: finding.end,
            function_name: finding.function_name.clone(),
            analysis_layer: finding.analysis_layer.clone(),
            evidence_kind: finding.evidence_kind.clone(),
            ai_review: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AiFindingReview {
    pub verdict: String,
    pub corrected_severity: Option<String>,
    pub reason: String,
    pub improved_poc: Option<String>,
    pub improved_remediation: Option<String>,
    pub improved_remediation_code: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ReportReviewSummary {
    pub raw_findings: usize,
    pub deterministic_filtered: usize,
    pub ai_candidates: usize,
    pub ai_attempted: usize,
    pub ai_reviewed: usize,
    pub ai_filtered: usize,
    pub failed: usize,
    pub skipped: usize,
    pub final_findings: usize,
    pub model: String,
}

#[derive(Debug, Clone)]
pub struct AuditReport {
    pub project_name: String,
    pub target: String,
    pub analysis_mode: String,
    pub raw_findings: usize,
    pub suppressed_findings: usize,
    pub metrics: Vec<AuditMetric>,
    pub findings: Vec<AuditFinding>,
    pub review_summary: Option<ReportReviewSummary>,
}

#[derive(Debug, Serialize)]
struct Report {
    mode: String,
    files: usize,
    functions: usize,
    cfgs: usize,
    calls: usize,
    ssa: SsaReport,
    taint: TaintReport,
    summaries: SummaryReport,
    call_resolution: CallResolution,
    finding_count_raw: usize,
    suppressed_findings: usize,
    finding_counts: Vec<ReportCount>,
    findings: Vec<ReportFinding>,
    findings_raw: Vec<ReportFinding>,
    top_callers: Vec<ReportTopCaller>,
}

#[derive(Debug, Serialize)]
struct CallResolution {
    resolved: usize,
    ambiguous: usize,
    external: usize,
    builtin: usize,
    unknown: usize,
}

#[derive(Debug, Serialize)]
struct ReportCount {
    kind: String,
    count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct ReportFinding {
    category: String,
    kind: String,
    severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    confidence: Option<String>,
    message: String,
    file: String,
    span: SpanRange,
    function: Option<String>,
}

#[derive(Debug, Clone)]
struct SyntheticFinding {
    category: String,
    kind: String,
    severity: String,
    confidence: Option<String>,
    message: String,
    file: String,
    span: SpanRange,
    function: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct SpanRange {
    start: u32,
    end: u32,
}

#[derive(Debug, Serialize)]
struct ReportTopCaller {
    function: String,
    count: usize,
}

#[derive(Debug, Serialize)]
struct TaintReport {
    functions: usize,
    source_functions: usize,
    tainted_functions: usize,
    tainted_vars: usize,
    tainted_calls: usize,
}

#[derive(Debug, Serialize)]
struct SummaryReport {
    functions: usize,
    functions_with_storage_writes: usize,
    storage_writes: usize,
    external_calls: usize,
    low_level_calls: usize,
    unresolved_calls: usize,
}

#[derive(Debug, Serialize)]
struct SsaReport {
    functions: usize,
    defs: usize,
    uses: usize,
    phis: usize,
}

fn build_report(output: &FrontendOutput, requested_path: &str) -> Report {
    let mode = match output.mode {
        FrontendMode::Full => "full",
        FrontendMode::Partial => "partial",
    }
    .to_string();
    let target_filter = TargetFilter::new(requested_path);

    let ir_module = ir::lower_module(&output.ast);
    let cfgs = cfg::build_from_ir(&ir_module);
    let call_graph = analysis::build_call_graph(&output.ast);
    let resolved = analysis::resolve_call_graph(&output.ast, &call_graph);
    let mut resolution = CallResolution {
        resolved: 0,
        ambiguous: 0,
        external: 0,
        builtin: 0,
        unknown: 0,
    };
    for edge in &resolved.edges {
        match &edge.target {
            ResolvedTarget::Function(_) => resolution.resolved += 1,
            ResolvedTarget::Ambiguous(_) => resolution.ambiguous += 1,
            ResolvedTarget::External(_) => resolution.external += 1,
            ResolvedTarget::Builtin(_) => resolution.builtin += 1,
            ResolvedTarget::Unknown => resolution.unknown += 1,
        }
    }
    let top_callers = build_top_callers(&output.ast, &resolved, 3)
        .into_iter()
        .map(|(name, count)| ReportTopCaller {
            function: name,
            count,
        })
        .collect::<Vec<_>>();
    let taint = analysis::taint::analyze(&output.ast, &cfgs);
    let propagation =
        analysis::taint::propagate_function_taint(output.ast.functions.len(), &taint, &resolved);
    let mut tainted_vars = 0;
    let mut tainted_calls = 0;
    for summary in &taint {
        tainted_vars += summary.tainted_vars.len();
        tainted_calls += summary.tainted_calls.len();
    }

    let findings = detectors::run_detectors(&output.ast, &call_graph, &taint);
    let report_findings = build_report_findings(output, &findings, &target_filter);
    let meta_report_findings = build_static_meta_findings(output, &findings, &target_filter);
    let mut all_report_findings_raw = report_findings.clone();
    all_report_findings_raw.extend(meta_report_findings.clone());
    let surfaced = surfaced::surface_findings(
        report_findings
            .iter()
            .map(|finding| report_finding_candidate(finding, "runtime", Some("rule")))
            .collect(),
        meta_report_findings
            .iter()
            .map(|finding| report_finding_candidate(finding, "meta", Some("static-meta")))
            .collect(),
    );
    let mut all_report_findings = surfaced
        .runtime_findings
        .iter()
        .chain(surfaced.meta_findings.iter())
        .map(report_finding_from_surfaced)
        .collect::<Vec<_>>();
    all_report_findings.sort_by(|left, right| {
        (
            left.file.as_str(),
            left.function.as_deref().unwrap_or(""),
            left.kind.as_str(),
            left.span.start,
        )
            .cmp(&(
                right.file.as_str(),
                right.function.as_deref().unwrap_or(""),
                right.kind.as_str(),
                right.span.start,
            ))
    });
    let finding_counts = build_finding_counts(&all_report_findings);
    let summaries = analysis::summary::summarize(&output.ast, &resolved);
    let summary_report = build_summary_report(&summaries);
    let ssa_functions = ssa::build_ssa(&output.ast, &cfgs);
    let ssa_report = build_ssa_report(&ssa_functions);

    Report {
        mode,
        files: output.ast.files.len(),
        functions: ir_module.functions.len(),
        cfgs: cfgs.len(),
        calls: call_graph.sites.len(),
        ssa: ssa_report,
        taint: TaintReport {
            functions: taint.len(),
            source_functions: propagation.source_functions,
            tainted_functions: propagation.tainted_functions,
            tainted_vars,
            tainted_calls,
        },
        summaries: summary_report,
        call_resolution: resolution,
        finding_count_raw: all_report_findings_raw.len(),
        suppressed_findings: surfaced.suppressed_runtime_findings
            + surfaced.suppressed_meta_findings,
        finding_counts,
        findings: all_report_findings,
        findings_raw: all_report_findings_raw,
        top_callers,
    }
}

fn print_text(report: &Report) -> Result<()> {
    println!(
        "mode: {}, files: {}, functions: {}, cfgs: {}, calls: {}, resolved: {}, ambiguous: {}, external: {}, builtin: {}, unknown: {}, findings: {} (raw={}, suppressed={})",
        report.mode,
        report.files,
        report.functions,
        report.cfgs,
        report.calls,
        report.call_resolution.resolved,
        report.call_resolution.ambiguous,
        report.call_resolution.external,
        report.call_resolution.builtin,
        report.call_resolution.unknown,
        report.findings.len(),
        report.finding_count_raw,
        report.suppressed_findings
    );
    println!(
        "taint: functions={}, source={}, tainted={}, vars={}, calls={}",
        report.taint.functions,
        report.taint.source_functions,
        report.taint.tainted_functions,
        report.taint.tainted_vars,
        report.taint.tainted_calls
    );
    println!(
        "ssa: functions={}, defs={}, uses={}, phis={}",
        report.ssa.functions, report.ssa.defs, report.ssa.uses, report.ssa.phis
    );
    println!(
        "summaries: functions={}, storage_writes={}, external_calls={}, low_level_calls={}, unresolved_calls={}",
        report.summaries.functions,
        report.summaries.storage_writes,
        report.summaries.external_calls,
        report.summaries.low_level_calls,
        report.summaries.unresolved_calls
    );

    if !report.finding_counts.is_empty() {
        let mut parts = Vec::new();
        for entry in &report.finding_counts {
            parts.push(format!("{}={}", entry.kind, entry.count));
        }
        println!("findings by type: {}", parts.join(", "));
    }

    if !report.top_callers.is_empty() {
        println!("top callers:");
        for entry in &report.top_callers {
            println!("  {}: {}", entry.function, entry.count);
        }
    }
    Ok(())
}

fn print_json(report: &Report) -> Result<()> {
    let payload = serde_json::to_string_pretty(report).map_err(|err| {
        crate::util::error::Error::msg(format!("failed to encode JSON report: {err}"))
    })?;
    println!("{payload}");
    Ok(())
}

fn print_markdown(report: &Report, requested_path: &str) -> Result<()> {
    let audit = audit_report_from_static(report, requested_path);
    println!("{}", render_audit_markdown(&audit));
    Ok(())
}

pub fn print_audit_markdown(report: &AuditReport) -> Result<()> {
    println!("{}", render_audit_markdown(report));
    Ok(())
}

pub fn print_audit_pdf(report: &AuditReport) -> Result<()> {
    io::stdout().write_all(&render_audit_pdf(report)?)?;
    Ok(())
}

pub fn audit_report_from_json_file(
    json_path: &str,
    target_path: &str,
    mode: &str,
) -> Result<AuditReport> {
    let text = fs::read_to_string(json_path)
        .map_err(|err| Error::msg(format!("failed to read cached analysis JSON: {err}")))?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|err| Error::msg(format!("failed to parse cached analysis JSON: {err}")))?;
    Ok(audit_report_from_json_value(&value, target_path, mode))
}

fn audit_report_from_json_value(value: &Value, target_path: &str, mode: &str) -> AuditReport {
    let mode = normalize_report_mode(mode);
    let findings = audit_findings_from_json(value, mode);
    let (raw_findings, suppressed_findings) = report_totals_from_json(value, mode, findings.len());
    let mut metrics = metrics_from_json(value, mode);
    metrics.push(AuditMetric::new(
        "Generated from",
        "Cached ChainVet analysis",
    ));

    AuditReport {
        project_name: project_name_from_path(target_path),
        target: target_path.to_string(),
        analysis_mode: mode.to_string(),
        raw_findings,
        suppressed_findings,
        metrics,
        findings,
        review_summary: None,
    }
}

fn audit_findings_from_json(value: &Value, mode: &str) -> Vec<AuditFinding> {
    match mode {
        "static" => json_array(value, "findings")
            .into_iter()
            .map(audit_finding_from_static_json)
            .collect(),
        "symbolic" => json_array(value, "vulnerabilities")
            .into_iter()
            .map(|finding| audit_finding_from_surfaced_json(finding, "symbolic"))
            .chain(
                json_array(value, "meta_findings")
                    .into_iter()
                    .map(|finding| audit_finding_from_surfaced_json(finding, "meta")),
            )
            .collect(),
        "fuzzing" | "hybrid" => json_array(value, "findings")
            .into_iter()
            .map(|finding| audit_finding_from_surfaced_json(finding, mode))
            .chain(
                json_array(value, "meta_findings")
                    .into_iter()
                    .map(|finding| audit_finding_from_surfaced_json(finding, "meta")),
            )
            .collect(),
        _ => Vec::new(),
    }
}

fn audit_finding_from_static_json(value: &Value) -> AuditFinding {
    let kind = json_string(value, "kind").unwrap_or_else(|| "finding".to_string());
    let span = value.get("span").unwrap_or(&Value::Null);
    AuditFinding {
        category: json_string(value, "category")
            .unwrap_or_else(|| surfaced::default_category_for_kind(&kind).to_string()),
        kind,
        severity: json_string(value, "severity").unwrap_or_else(|| "informational".to_string()),
        confidence: json_string(value, "confidence"),
        message: json_string(value, "message").unwrap_or_default(),
        file: json_string(value, "file"),
        start: json_u32(span, "start"),
        end: json_u32(span, "end"),
        function_name: json_string(value, "function"),
        analysis_layer: "static".to_string(),
        evidence_kind: Some("rule".to_string()),
        ai_review: None,
    }
}

fn audit_finding_from_surfaced_json(value: &Value, default_layer: &str) -> AuditFinding {
    let kind = json_string(value, "kind").unwrap_or_else(|| "finding".to_string());
    AuditFinding {
        category: json_string(value, "category")
            .unwrap_or_else(|| surfaced::default_category_for_kind(&kind).to_string()),
        kind,
        severity: json_string(value, "severity").unwrap_or_else(|| "informational".to_string()),
        confidence: json_string(value, "confidence"),
        message: json_string(value, "message").unwrap_or_default(),
        file: json_string(value, "file"),
        start: json_u32(value, "start"),
        end: json_u32(value, "end"),
        function_name: json_string(value, "function_name")
            .or_else(|| json_string(value, "function")),
        analysis_layer: json_string(value, "analysis_layer")
            .unwrap_or_else(|| default_layer.to_string()),
        evidence_kind: json_string(value, "evidence_kind"),
        ai_review: None,
    }
}

fn report_totals_from_json(value: &Value, mode: &str, surfaced_findings: usize) -> (usize, usize) {
    match mode {
        "static" => (
            json_usize(value, "finding_count_raw").unwrap_or(surfaced_findings),
            json_usize(value, "suppressed_findings").unwrap_or(0),
        ),
        "symbolic" => (
            json_usize(value, "vulnerability_count_raw").unwrap_or(0)
                + json_usize(value, "meta_finding_count_raw").unwrap_or(0),
            json_usize(value, "suppressed_vulnerabilities").unwrap_or(0)
                + json_usize(value, "suppressed_meta_findings").unwrap_or(0),
        ),
        "fuzzing" | "hybrid" => (
            json_usize(value, "finding_count_raw").unwrap_or(0)
                + json_usize(value, "meta_finding_count_raw").unwrap_or(0),
            json_usize(value, "suppressed_findings").unwrap_or(0)
                + json_usize(value, "suppressed_meta_findings").unwrap_or(0),
        ),
        _ => (surfaced_findings, 0),
    }
}

fn metrics_from_json(value: &Value, mode: &str) -> Vec<AuditMetric> {
    let mut metrics = Vec::new();
    match mode {
        "static" => {
            push_metric(&mut metrics, value, "Files", "files");
            push_metric(&mut metrics, value, "Functions", "functions");
            push_metric(&mut metrics, value, "CFGs", "cfgs");
            push_metric(&mut metrics, value, "Call sites", "calls");
            push_nested_metric(
                &mut metrics,
                value,
                "Resolved calls",
                "call_resolution",
                "resolved",
            );
            push_nested_metric(
                &mut metrics,
                value,
                "Tainted functions",
                "taint",
                "tainted_functions",
            );
            push_nested_metric(&mut metrics, value, "SSA definitions", "ssa", "defs");
        }
        "symbolic" => {
            push_metric(&mut metrics, value, "Files", "files");
            push_metric(&mut metrics, value, "Functions", "functions");
            push_metric(&mut metrics, value, "Instructions", "instructions");
            push_metric(&mut metrics, value, "Explored states", "explored_states");
            push_metric(&mut metrics, value, "Terminal paths", "terminal_paths");
            push_metric(&mut metrics, value, "Pruned branches", "pruned_branches");
        }
        "fuzzing" => {
            push_metric(&mut metrics, value, "Iterations", "iterations");
            push_metric(&mut metrics, value, "Corpus size", "corpus_size");
            push_metric(&mut metrics, value, "Covered blocks", "covered_blocks");
            push_metric(&mut metrics, value, "Total blocks", "total_blocks");
            push_metric(&mut metrics, value, "Coverage", "coverage_pct");
            push_metric_with_suffix(&mut metrics, value, "Elapsed", "elapsed_ms", "ms");
        }
        "hybrid" => {
            push_metric(&mut metrics, value, "Run ID", "run_id");
            push_metric_with_suffix(&mut metrics, value, "Runtime", "runtime_ms", "ms");
            push_metric(&mut metrics, value, "Epochs", "total_epochs");
            push_metric(&mut metrics, value, "Unique findings", "findings_unique");
            push_metric(
                &mut metrics,
                value,
                "Runtime findings",
                "runtime_findings_unique",
            );
            push_metric(&mut metrics, value, "Meta findings", "meta_findings_unique");
            push_metric(&mut metrics, value, "SE assists", "se_assists");
            push_metric(
                &mut metrics,
                value,
                "SE seeds injected",
                "seeds_injected_by_se",
            );
        }
        _ => {}
    }
    metrics
}

fn push_metric(metrics: &mut Vec<AuditMetric>, value: &Value, label: &str, key: &str) {
    if let Some(metric_value) = json_metric_string(value.get(key)) {
        metrics.push(AuditMetric::new(label, metric_value));
    }
}

fn push_nested_metric(
    metrics: &mut Vec<AuditMetric>,
    value: &Value,
    label: &str,
    parent_key: &str,
    key: &str,
) {
    if let Some(metric_value) = value
        .get(parent_key)
        .and_then(|parent| json_metric_string(parent.get(key)))
    {
        metrics.push(AuditMetric::new(label, metric_value));
    }
}

fn push_metric_with_suffix(
    metrics: &mut Vec<AuditMetric>,
    value: &Value,
    label: &str,
    key: &str,
    suffix: &str,
) {
    if let Some(metric_value) = json_metric_string(value.get(key)) {
        metrics.push(AuditMetric::new(label, format!("{metric_value}{suffix}")));
    }
}

fn json_array<'a>(value: &'a Value, key: &str) -> Vec<&'a Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

fn json_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(ToString::to_string)
}

fn json_usize(value: &Value, key: &str) -> Option<usize> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|number| usize::try_from(number).ok())
}

fn json_u32(value: &Value, key: &str) -> Option<u32> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|number| u32::try_from(number).ok())
}

fn json_metric_string(value: Option<&Value>) -> Option<String> {
    let value = value?;
    if let Some(text) = value.as_str() {
        if text.is_empty() {
            None
        } else {
            Some(text.to_string())
        }
    } else if let Some(number) = value.as_u64() {
        Some(number.to_string())
    } else if let Some(number) = value.as_i64() {
        Some(number.to_string())
    } else if let Some(number) = value.as_f64() {
        Some(format!("{number:.1}"))
    } else {
        None
    }
}

fn normalize_report_mode(mode: &str) -> &str {
    match mode.trim().to_ascii_lowercase().as_str() {
        "static" => "static",
        "symbolic" => "symbolic",
        "fuzzing" => "fuzzing",
        "hybrid" => "hybrid",
        _ => "hybrid",
    }
}

pub fn render_audit_pdf_base64(report: &AuditReport) -> Result<String> {
    Ok(base64_encode(&render_audit_pdf(report)?))
}

fn print_pdf(report: &Report, requested_path: &str) -> Result<()> {
    let audit = audit_report_from_static(report, requested_path);
    print_audit_pdf(&audit)
}

pub fn render_audit_markdown(report: &AuditReport) -> String {
    let report = crate::ai_report::enhance_report_if_enabled(report);
    render_audit_markdown_inner(&report)
}

fn render_audit_markdown_inner(report: &AuditReport) -> String {
    let mut findings = report.findings.clone();
    findings.sort_by(|left, right| {
        (
            severity_sort_rank(left.severity.as_str()),
            left.category.as_str(),
            left.kind.as_str(),
            left.file.as_deref().unwrap_or(""),
            left.start.unwrap_or(u32::MAX),
        )
            .cmp(&(
                severity_sort_rank(right.severity.as_str()),
                right.category.as_str(),
                right.kind.as_str(),
                right.file.as_deref().unwrap_or(""),
                right.start.unwrap_or(u32::MAX),
            ))
    });

    let counts = severity_counts(&findings);
    let total = findings.len();
    let logo_data_uri = chainvet_logo_data_uri();
    let mut out = String::new();

    push_line(&mut out, "---");
    push_line(&mut out, "title: ChainVet Smart Contract Audit Report");
    push_line(&mut out, "author: ChainVet");
    push_line(&mut out, "date: \\today");
    push_line(&mut out, "header-includes:");
    push_line(&mut out, "  - \\usepackage{titling}");
    push_line(&mut out, "  - \\usepackage{graphicx}");
    push_line(&mut out, "---");
    push_line(&mut out, "");
    push_line(&mut out, "\\begin{titlepage}");
    push_line(&mut out, "\\centering");
    push_line(&mut out, "\\begin{figure}[h]");
    push_line(&mut out, "\\centering");
    push_line(
        &mut out,
        "\\includegraphics[width=0.32\\textwidth]{src/web/assets/logo.png}",
    );
    push_line(&mut out, "\\end{figure}");
    push_line(&mut out, "\\vspace*{2cm}");
    push_line(&mut out, "{\\Huge\\bfseries ChainVet Audit Report\\par}");
    push_line(&mut out, "\\vspace{1cm}");
    push_line(
        &mut out,
        &format!(
            "{{\\Large {}\\par}}",
            escape_latex_text(report.project_name.as_str())
        ),
    );
    push_line(&mut out, "\\vspace{2cm}");
    push_line(
        &mut out,
        "{\\Large\\itshape Smart Contract Security Analysis\\par}",
    );
    push_line(&mut out, "\\vfill");
    push_line(&mut out, "{\\large \\today\\par}");
    push_line(&mut out, "\\end{titlepage}");
    push_line(&mut out, "");
    push_line(&mut out, "\\maketitle");
    push_line(&mut out, "");
    push_line(
        &mut out,
        &format!(
            "<p align=\"center\"><img src=\"{}\" width=\"160\" alt=\"ChainVet logo\"></p>",
            logo_data_uri
        ),
    );
    push_line(&mut out, "");
    push_line(&mut out, "Prepared by: **ChainVet**");
    push_line(&mut out, "");
    push_line(&mut out, "Lead Auditor: **ChainVet Analyzer**");
    push_line(&mut out, "");
    push_line(&mut out, "# Table of Contents");
    push_line(&mut out, "");
    for item in [
        "- [Protocol Summary](#protocol-summary)",
        "- [Disclaimer](#disclaimer)",
        "- [Risk Classification](#risk-classification)",
        "- [Audit Details](#audit-details)",
        "- [AI Review Summary](#ai-review-summary)",
        "- [Scope](#scope)",
        "- [Executive Summary](#executive-summary)",
        "- [Issues Found](#issues-found)",
        "- [Findings](#findings)",
        "  - [High](#high)",
        "  - [Medium](#medium)",
        "  - [Low](#low)",
        "  - [Informational](#informational)",
        "  - [Gas](#gas)",
    ] {
        push_line(&mut out, item);
    }
    push_line(&mut out, "");
    push_line(&mut out, "# Protocol Summary");
    push_line(&mut out, "");
    push_line(
        &mut out,
        &format!(
            "ChainVet analyzed `{}` using the `{}` analysis pipeline. This report is generated directly from the analyzer findings and does not include AI-generated or manually invented issues.",
            escape_md(report.target.as_str()),
            escape_md(report.analysis_mode.as_str())
        ),
    );
    push_line(&mut out, "");
    push_line(&mut out, "# Disclaimer");
    push_line(&mut out, "");
    push_line(
        &mut out,
        "The ChainVet team makes every effort to surface meaningful vulnerabilities from the analyzed source code, but automated analysis cannot guarantee that every issue has been found. This report is not an endorsement of the underlying protocol, business logic, or deployment readiness. The review is limited to the code and execution paths available to the analyzer at the time of execution.",
    );
    push_line(&mut out, "");
    push_line(&mut out, "# Risk Classification");
    push_line(&mut out, "");
    push_line(&mut out, "|  |  | Impact |  |  |");
    push_line(&mut out, "| --- | --- | --- | --- | --- |");
    push_line(&mut out, "|  |  | High | Medium | Low |");
    push_line(&mut out, "|  | High | H | H/M | M |");
    push_line(&mut out, "| Likelihood | Medium | H/M | M | M/L |");
    push_line(&mut out, "|  | Low | M | M/L | L |");
    push_line(&mut out, "");
    push_line(
        &mut out,
        "ChainVet maps analyzer severity to this matrix using detector confidence, impact category, and available static/runtime evidence.",
    );
    push_line(&mut out, "");
    push_line(&mut out, "# Audit Details");
    push_line(&mut out, "");
    push_line(&mut out, "| Field | Value |");
    push_line(&mut out, "| --- | --- |");
    push_line(
        &mut out,
        &format!(
            "| Project | {} |",
            escape_table(report.project_name.as_str())
        ),
    );
    push_line(
        &mut out,
        &format!("| Target | `{}` |", escape_table(report.target.as_str())),
    );
    push_line(
        &mut out,
        &format!(
            "| Analysis mode | `{}` |",
            escape_table(report.analysis_mode.as_str())
        ),
    );
    push_line(
        &mut out,
        &format!("| Raw findings | {} |", report.raw_findings),
    );
    push_line(
        &mut out,
        &format!(
            "| Suppressed low-signal findings | {} |",
            report.suppressed_findings
        ),
    );
    push_line(
        &mut out,
        &format!(
            "| AI assistance | {} |",
            escape_table(ai_assistance_status(report).as_str())
        ),
    );
    let confidence = report_confidence(report);
    push_line(
        &mut out,
        &format!("| Report confidence | {} |", escape_table(confidence.label)),
    );
    for metric in &report.metrics {
        if metric.label == "AI review" {
            continue;
        }
        push_line(
            &mut out,
            &format!(
                "| {} | {} |",
                escape_table(metric.label.as_str()),
                escape_table(metric.value.as_str())
            ),
        );
    }
    push_line(&mut out, "");
    push_ai_review_summary(&mut out, report, confidence.reason);
    push_line(&mut out, "## Scope");
    push_line(&mut out, "");
    push_line(&mut out, "| Path |");
    push_line(&mut out, "| --- |");
    push_line(
        &mut out,
        &format!("| `{}` |", escape_table(report.target.as_str())),
    );
    push_line(&mut out, "");
    push_line(&mut out, "# Executive Summary");
    push_line(&mut out, "");
    if total == 0 {
        push_line(
            &mut out,
            "ChainVet did not surface any reportable findings after deduplication and low-signal suppression.",
        );
    } else {
        push_line(
            &mut out,
            &format!(
                "ChainVet surfaced **{}** reportable finding(s): **{} high**, **{} medium**, **{} low**, and **{} informational**.",
                total, counts.high, counts.medium, counts.low, counts.informational
            ),
        );
    }
    push_line(&mut out, "");
    push_line(&mut out, "## Issues Found");
    push_line(&mut out, "");
    push_line(&mut out, "| Severity | Count |");
    push_line(&mut out, "| --- | ---: |");
    push_line(&mut out, &format!("| High | {} |", counts.high));
    push_line(&mut out, &format!("| Medium | {} |", counts.medium));
    push_line(&mut out, &format!("| Low | {} |", counts.low));
    push_line(
        &mut out,
        &format!("| Informational | {} |", counts.informational),
    );
    push_line(&mut out, "| Gas | 0 |");
    push_line(&mut out, "");
    if total > 0 {
        push_line(&mut out, "| ID | Severity | Title | Location |");
        push_line(&mut out, "| --- | --- | --- | --- |");
        for (idx, finding) in findings.iter().enumerate() {
            push_line(
                &mut out,
                &format!(
                    "| {} | {} | {} | {} |",
                    finding_id(idx + 1, finding.severity.as_str()),
                    severity_label(finding.severity.as_str()),
                    escape_table(finding_title(finding).as_str()),
                    escape_table(location_summary(finding).as_str())
                ),
            );
        }
        push_line(&mut out, "");
    }
    push_line(&mut out, "# Findings");
    push_line(&mut out, "");
    for (heading, key) in [
        ("High", "high"),
        ("Medium", "medium"),
        ("Low", "low"),
        ("Informational", "informational"),
    ] {
        push_line(&mut out, &format!("# {heading}"));
        push_line(&mut out, "");
        let mut any = false;
        for (idx, finding) in findings.iter().enumerate() {
            if severity_bucket(finding.severity.as_str()) != key {
                continue;
            }
            any = true;
            push_finding_section(&mut out, idx + 1, finding);
        }
        if !any {
            push_line(&mut out, "No findings.");
            push_line(&mut out, "");
        }
    }
    push_line(&mut out, "# Gas");
    push_line(&mut out, "");
    push_line(
        &mut out,
        "No gas-specific findings were generated by this report pass.",
    );
    out
}

pub fn render_audit_pdf(report: &AuditReport) -> Result<Vec<u8>> {
    let report = crate::ai_report::enhance_report_if_enabled(report);
    if std::env::var("CHAINVET_USE_PANDOC_PDF").ok().as_deref() == Some("1") {
        match render_markdown_pdf_with_pandoc(&render_audit_markdown_inner(&report)) {
            Ok(pdf) => return Ok(pdf),
            Err(_) => return Ok(render_audit_pdf_native(&report)),
        }
    }
    Ok(render_audit_pdf_native(&report))
}

fn render_audit_pdf_native(report: &AuditReport) -> Vec<u8> {
    let mut findings = report.findings.clone();
    findings.sort_by(|left, right| {
        (
            severity_sort_rank(left.severity.as_str()),
            left.category.as_str(),
            left.kind.as_str(),
            left.file.as_deref().unwrap_or(""),
            left.start.unwrap_or(u32::MAX),
        )
            .cmp(&(
                severity_sort_rank(right.severity.as_str()),
                right.category.as_str(),
                right.kind.as_str(),
                right.file.as_deref().unwrap_or(""),
                right.start.unwrap_or(u32::MAX),
            ))
    });

    let counts = severity_counts(&findings);
    let mut pdf = NativePdf::new("ChainVet Audit Report");
    pdf.cover(report);

    pdf.heading("Table of Contents");
    for item in [
        "Protocol Summary",
        "Disclaimer",
        "Risk Classification",
        "Audit Details",
        "AI Review Summary",
        "Scope",
        "Executive Summary",
        "Issues Found",
        "Findings",
        "High",
        "Medium",
        "Low",
        "Informational",
        "Gas",
    ] {
        pdf.toc_item(item);
    }

    pdf.heading("Protocol Summary");
    pdf.paragraph(format!(
        "ChainVet analyzed {} using the {} analysis pipeline. This report is generated directly from analyzer findings and does not include AI-generated or manually invented issues.",
        report.target, report.analysis_mode
    ));

    pdf.heading("Disclaimer");
    pdf.paragraph("Automated analysis cannot guarantee that every issue has been found. This report is not an endorsement of the underlying protocol, business logic, or deployment readiness. The review is limited to the code and execution paths available to the analyzer at the time of execution.");

    pdf.heading("Risk Classification");
    pdf.risk_matrix();
    pdf.paragraph("ChainVet maps analyzer severity to this matrix using detector confidence, impact category, and available static/runtime evidence.");

    pdf.heading("Audit Details");
    pdf.table_header("Field", "Value");
    pdf.kv("Project", report.project_name.as_str());
    pdf.kv("Target", report.target.as_str());
    pdf.kv("Analysis mode", report.analysis_mode.as_str());
    pdf.kv("Raw findings", report.raw_findings.to_string());
    pdf.kv(
        "Suppressed low-signal findings",
        report.suppressed_findings.to_string(),
    );
    pdf.kv("AI assistance", ai_assistance_status(report));
    let confidence = report_confidence(report);
    pdf.kv("Report confidence", confidence.label);
    for metric in &report.metrics {
        if metric.label == "AI review" {
            continue;
        }
        pdf.kv(metric.label.as_str(), metric.value.as_str());
    }

    pdf.heading("AI Review Summary");
    pdf.ai_review_summary(report, confidence.reason);

    pdf.heading("Scope");
    pdf.single_column_table("Path", &[report.target.as_str()]);

    pdf.heading("Executive Summary");
    if findings.is_empty() {
        pdf.paragraph("ChainVet did not surface any reportable findings after deduplication and low-signal suppression.");
    } else {
        pdf.paragraph(format!(
            "ChainVet surfaced {} reportable finding(s): {} high, {} medium, {} low, and {} informational.",
            findings.len(), counts.high, counts.medium, counts.low, counts.informational
        ));
    }
    pdf.summary_cards(&[
        ("High", counts.high, PdfColor::RED),
        ("Medium", counts.medium, PdfColor::PEACH),
        ("Low", counts.low, PdfColor::YELLOW),
        ("Info", counts.informational, PdfColor::SKY),
    ]);

    pdf.heading("Issues Found");
    pdf.table_header("Severity", "Count");
    pdf.kv("High", counts.high.to_string());
    pdf.kv("Medium", counts.medium.to_string());
    pdf.kv("Low", counts.low.to_string());
    pdf.kv("Informational", counts.informational.to_string());
    pdf.kv("Gas", "0");

    if !findings.is_empty() {
        pdf.issue_table_header();
        for (idx, finding) in findings.iter().enumerate() {
            pdf.issue_row(
                finding_id(idx + 1, finding.severity.as_str()),
                severity_label(finding.severity.as_str()),
                finding_title(finding),
                location_summary(finding),
                severity_color(finding.severity.as_str()),
            );
        }
    }

    pdf.heading("Findings");
    for (heading, key) in [
        ("High", "high"),
        ("Medium", "medium"),
        ("Low", "low"),
        ("Informational", "informational"),
    ] {
        pdf.subheading(heading);
        let mut any = false;
        for (idx, finding) in findings.iter().enumerate() {
            if severity_bucket(finding.severity.as_str()) != key {
                continue;
            }
            any = true;
            pdf.finding(idx + 1, finding);
        }
        if !any {
            pdf.muted("No findings.");
        }
    }

    pdf.heading("Gas");
    pdf.paragraph("No gas-specific findings were generated by this report pass.");
    pdf.finish()
}

#[derive(Clone, Copy)]
struct PdfColor {
    r: f32,
    g: f32,
    b: f32,
}

impl PdfColor {
    const fn new(r: f32, g: f32, b: f32) -> Self {
        Self { r, g, b }
    }

    const MAUVE: Self = Self::new(0.796, 0.651, 0.969);
    const PINK: Self = Self::new(0.961, 0.761, 0.906);
    const RED: Self = Self::new(0.953, 0.545, 0.659);
    const PEACH: Self = Self::new(0.980, 0.702, 0.529);
    const YELLOW: Self = Self::new(0.976, 0.886, 0.686);
    const GREEN: Self = Self::new(0.651, 0.890, 0.631);
    const TEAL: Self = Self::new(0.580, 0.886, 0.835);
    const SKY: Self = Self::new(0.537, 0.863, 0.922);
    const BLUE: Self = Self::new(0.537, 0.706, 0.980);
    const LAVENDER: Self = Self::new(0.706, 0.745, 0.996);
    const TEXT: Self = Self::new(0.804, 0.839, 0.957);
    const SUBTEXT1: Self = Self::new(0.729, 0.761, 0.871);
    const SUBTEXT0: Self = Self::new(0.651, 0.678, 0.784);
    const OVERLAY2: Self = Self::new(0.576, 0.600, 0.698);
    const SURFACE2: Self = Self::new(0.345, 0.357, 0.439);
    const SURFACE0: Self = Self::new(0.192, 0.196, 0.267);
    const BASE: Self = Self::new(0.118, 0.118, 0.180);
    const MANTLE: Self = Self::new(0.094, 0.094, 0.145);
    const CRUST: Self = Self::new(0.067, 0.067, 0.106);
}

struct NativePdf {
    pages: Vec<String>,
    current: String,
    title: String,
    y: f32,
    page_no: usize,
}

impl NativePdf {
    const PAGE_WIDTH: f32 = 595.0;
    const PAGE_HEIGHT: f32 = 842.0;
    const LEFT: f32 = 54.0;
    const RIGHT: f32 = 541.0;
    const TOP: f32 = 760.0;
    const BOTTOM: f32 = 64.0;

    fn new(title: impl Into<String>) -> Self {
        let mut pdf = Self {
            pages: Vec::new(),
            current: String::new(),
            title: title.into(),
            y: Self::TOP,
            page_no: 0,
        };
        pdf.begin_page();
        pdf
    }

    fn cover(&mut self, report: &AuditReport) {
        self.rect(
            0.0,
            0.0,
            Self::PAGE_WIDTH,
            Self::PAGE_HEIGHT,
            PdfColor::BASE,
            None,
        );
        self.rect(0.0, 650.0, Self::PAGE_WIDTH, 192.0, PdfColor::CRUST, None);
        self.rect(
            54.0,
            610.0,
            108.0,
            108.0,
            PdfColor::SURFACE0,
            Some(PdfColor::SURFACE2),
        );
        self.image_at(64.0, 620.0, 88.0, 88.0);
        self.text_at(
            54.0,
            570.0,
            35.0,
            true,
            PdfColor::TEXT,
            "ChainVet Audit Report",
        );
        self.text_at(
            56.0,
            538.0,
            18.0,
            false,
            PdfColor::SUBTEXT1,
            report.project_name.as_str(),
        );
        self.text_at(
            56.0,
            500.0,
            12.0,
            false,
            PdfColor::SUBTEXT0,
            "Smart Contract Security Analysis",
        );
        self.rect(
            54.0,
            394.0,
            487.0,
            72.0,
            PdfColor::SURFACE0,
            Some(PdfColor::SURFACE2),
        );
        self.text_at(72.0, 438.0, 10.0, true, PdfColor::LAVENDER, "TARGET");
        self.wrapped_at(
            72.0,
            416.0,
            11.0,
            false,
            PdfColor::TEXT,
            report.target.as_str(),
            84,
        );
        self.text_at(72.0, 358.0, 10.0, true, PdfColor::LAVENDER, "ANALYSIS MODE");
        self.text_at(
            72.0,
            336.0,
            12.0,
            false,
            PdfColor::TEXT,
            report.analysis_mode.as_str(),
        );
        self.text_at(
            72.0,
            112.0,
            10.0,
            false,
            PdfColor::OVERLAY2,
            "Prepared by ChainVet Analyzer",
        );
        self.page_break();
    }

    fn heading(&mut self, text: impl AsRef<str>) {
        self.ensure_space(42.0);
        self.y -= 32.0;
        self.text(Self::LEFT, 18.0, true, PdfColor::TEXT, text.as_ref());
        self.line(
            Self::LEFT,
            self.y + 6.0,
            Self::RIGHT,
            self.y + 6.0,
            PdfColor::SURFACE2,
            0.8,
        );
        self.y -= 10.0;
    }

    fn subheading(&mut self, text: impl AsRef<str>) {
        self.ensure_space(30.0);
        self.y -= 26.0;
        self.text(Self::LEFT, 13.0, true, PdfColor::LAVENDER, text.as_ref());
        self.y -= 4.0;
    }

    fn paragraph(&mut self, text: impl AsRef<str>) {
        for line in wrap_pdf_line(text.as_ref(), content_width(), 10.5) {
            self.text(Self::LEFT, 10.5, false, PdfColor::SUBTEXT1, line.as_str());
        }
        self.y -= 8.0;
    }

    fn code_block(&mut self, code: &str) {
        let mut lines = code
            .lines()
            .flat_map(|line| wrap_code_line(line, 92))
            .collect::<Vec<_>>();
        if lines.is_empty() {
            return;
        }
        while !lines.is_empty() {
            let available = (self.y - Self::BOTTOM - 24.0).max(0.0);
            if available < 42.0 {
                self.page_break();
                continue;
            }
            let max_lines = ((available - 18.0) / 12.0).floor().max(1.0) as usize;
            let take = max_lines.min(lines.len());
            let chunk = lines.drain(..take).collect::<Vec<_>>();
            let height = chunk.len() as f32 * 12.0 + 18.0;
            let y = self.y - height;
            self.rect(
                Self::LEFT,
                y,
                content_width(),
                height,
                PdfColor::CRUST,
                Some(PdfColor::SURFACE2),
            );
            let mut line_y = self.y - 18.0;
            for line in chunk {
                self.highlighted_code_line(Self::LEFT + 12.0, line_y, 8.3, line.as_str());
                line_y -= 12.0;
            }
            self.y = y - 12.0;
        }
    }

    fn highlighted_code_line(&mut self, x: f32, y: f32, size: f32, line: &str) {
        let advance = size * 0.60;
        let mut cursor = x;
        for token in solidity_highlight(line) {
            if !token.text.is_empty() {
                self.text_at_font(cursor, y, size, "F3", token.color, token.text.as_str());
                cursor += token.text.chars().count() as f32 * advance;
            }
        }
    }

    fn muted(&mut self, text: impl AsRef<str>) {
        self.ensure_space(22.0);
        self.text(Self::LEFT, 10.0, false, PdfColor::OVERLAY2, text.as_ref());
        self.y -= 4.0;
    }

    fn toc_item(&mut self, text: &str) {
        self.ensure_space(18.0);
        self.text_at(
            Self::LEFT + 14.0,
            self.y,
            10.5,
            false,
            PdfColor::SUBTEXT1,
            format!("- {text}"),
        );
        self.y -= 17.0;
    }

    fn table_header(&mut self, left: &str, right: &str) {
        self.ensure_space(28.0);
        let y = self.y - 20.0;
        self.rect(
            Self::LEFT,
            y,
            150.0,
            24.0,
            PdfColor::MANTLE,
            Some(PdfColor::SURFACE2),
        );
        self.rect(
            Self::LEFT + 150.0,
            y,
            content_width() - 150.0,
            24.0,
            PdfColor::MANTLE,
            Some(PdfColor::SURFACE2),
        );
        self.text_at(
            Self::LEFT + 9.0,
            y + 8.0,
            9.0,
            true,
            PdfColor::LAVENDER,
            left,
        );
        self.text_at(
            Self::LEFT + 162.0,
            y + 8.0,
            9.0,
            true,
            PdfColor::LAVENDER,
            right,
        );
        self.y -= 24.0;
    }

    fn kv(&mut self, label: impl AsRef<str>, value: impl AsRef<str>) {
        let value_lines = wrap_text_chars(value.as_ref(), 62);
        let row_height = (value_lines.len() as f32 * 12.8 + 11.0).max(24.0);
        self.ensure_space(row_height + 4.0);
        let y = self.y - row_height;
        self.rect(
            Self::LEFT,
            y,
            150.0,
            row_height,
            PdfColor::SURFACE0,
            Some(PdfColor::SURFACE2),
        );
        self.rect(
            Self::LEFT + 150.0,
            y,
            content_width() - 150.0,
            row_height,
            PdfColor::BASE,
            Some(PdfColor::SURFACE2),
        );
        self.text_at(
            Self::LEFT + 9.0,
            self.y - 15.0,
            9.0,
            true,
            PdfColor::SUBTEXT0,
            label.as_ref(),
        );
        let mut line_y = self.y - 15.0;
        for line in value_lines {
            self.text_at(
                Self::LEFT + 162.0,
                line_y,
                8.8,
                false,
                PdfColor::TEXT,
                line.as_str(),
            );
            line_y -= 12.8;
        }
        self.y = y;
    }

    fn ai_review_summary(&mut self, report: &AuditReport, confidence_reason: &str) {
        if let Some(summary) = report.review_summary.as_ref() {
            self.table_header("Stage", "Count");
            self.kv("Raw surfaced findings", summary.raw_findings.to_string());
            self.kv(
                "Deterministic prefilter removed",
                summary.deterministic_filtered.to_string(),
            );
            self.kv(
                "AI candidates after prefilter",
                summary.ai_candidates.to_string(),
            );
            self.kv("AI attempted", summary.ai_attempted.to_string());
            self.kv("AI reviewed", summary.ai_reviewed.to_string());
            self.kv("AI removed", summary.ai_filtered.to_string());
            self.kv("AI failures", summary.failed.to_string());
            self.kv("Skipped by review limit", summary.skipped.to_string());
            self.kv(
                "Final reportable findings",
                summary.final_findings.to_string(),
            );
            self.kv("Model", summary.model.as_str());
        } else {
            self.muted("AI review was not used for this report.");
        }
        let confidence = report_confidence(report);
        self.kv(
            "Report confidence",
            format!("{}: {}", confidence.label, confidence_reason),
        );
        self.y -= 8.0;
    }

    fn single_column_table(&mut self, header: &str, values: &[&str]) {
        self.ensure_space(32.0);
        let y = self.y - 20.0;
        self.rect(
            Self::LEFT,
            y,
            content_width(),
            24.0,
            PdfColor::MANTLE,
            Some(PdfColor::SURFACE2),
        );
        self.text_at(
            Self::LEFT + 9.0,
            y + 8.0,
            9.0,
            true,
            PdfColor::LAVENDER,
            header,
        );
        self.y -= 24.0;
        for value in values {
            let value_lines = wrap_text_chars(value, 86);
            let row_height = (value_lines.len() as f32 * 12.8 + 11.0).max(24.0);
            self.ensure_space(row_height + 4.0);
            let row_y = self.y - row_height;
            self.rect(
                Self::LEFT,
                row_y,
                content_width(),
                row_height,
                PdfColor::BASE,
                Some(PdfColor::SURFACE2),
            );
            let mut line_y = self.y - 15.0;
            for line in value_lines {
                self.text_at(
                    Self::LEFT + 9.0,
                    line_y,
                    8.8,
                    false,
                    PdfColor::TEXT,
                    line.as_str(),
                );
                line_y -= 12.8;
            }
            self.y = row_y;
        }
        self.y -= 8.0;
    }

    fn risk_matrix(&mut self) {
        self.ensure_space(120.0);
        let start_x = Self::LEFT;
        let start_y = self.y - 24.0;
        let widths = [118.0, 92.0, 92.0, 92.0, 93.0];
        let impact_x = start_x + widths[0] + widths[1];
        let impact_w = widths[2] + widths[3] + widths[4];
        let row_labels = ["High", "Medium", "Low"];
        let values = [["H", "H/M", "M"], ["H/M", "M", "M/L"], ["M", "M/L", "L"]];

        self.rect(
            start_x,
            start_y - 22.0,
            widths[0] + widths[1],
            44.0,
            PdfColor::MANTLE,
            Some(PdfColor::SURFACE2),
        );
        self.rect(
            impact_x,
            start_y,
            impact_w,
            22.0,
            PdfColor::MANTLE,
            Some(PdfColor::SURFACE2),
        );
        self.text_at(
            impact_x + impact_w / 2.0 - 18.0,
            start_y + 8.0,
            8.5,
            true,
            PdfColor::LAVENDER,
            "Impact",
        );

        let mut x = impact_x;
        for (idx, label) in ["High", "Medium", "Low"].iter().enumerate() {
            let y = start_y - 22.0;
            self.rect(
                x,
                y,
                widths[idx + 2],
                22.0,
                PdfColor::MANTLE,
                Some(PdfColor::SURFACE2),
            );
            self.text_at(x + 8.0, y + 8.0, 8.5, true, PdfColor::LAVENDER, *label);
            x += widths[idx + 2];
        }

        let body_top = start_y - 44.0;
        self.rect(
            start_x,
            body_top - 44.0,
            widths[0],
            66.0,
            PdfColor::MANTLE,
            Some(PdfColor::SURFACE2),
        );
        self.text_at(
            start_x + 8.0,
            body_top - 13.0,
            8.5,
            true,
            PdfColor::LAVENDER,
            "Likelihood",
        );

        for row_idx in 0..3 {
            let y = body_top - row_idx as f32 * 22.0;
            let fill = if row_idx % 2 == 0 {
                PdfColor::SURFACE0
            } else {
                PdfColor::BASE
            };
            self.rect(
                start_x + widths[0],
                y,
                widths[1],
                22.0,
                PdfColor::MANTLE,
                Some(PdfColor::SURFACE2),
            );
            self.text_at(
                start_x + widths[0] + 8.0,
                y + 8.0,
                8.5,
                true,
                PdfColor::LAVENDER,
                row_labels[row_idx],
            );

            let mut x = impact_x;
            for col_idx in 0..3 {
                self.rect(
                    x,
                    y,
                    widths[col_idx + 2],
                    22.0,
                    fill,
                    Some(PdfColor::SURFACE2),
                );
                self.text_at(
                    x + 8.0,
                    y + 8.0,
                    8.5,
                    false,
                    PdfColor::TEXT,
                    values[row_idx][col_idx],
                );
                x += widths[col_idx + 2];
            }
        }
        self.y -= 124.0;
    }

    fn summary_cards(&mut self, cards: &[(&str, usize, PdfColor)]) {
        self.ensure_space(88.0);
        let gap = 10.0;
        let width = (content_width() - gap * 3.0) / 4.0;
        let y = self.y - 58.0;
        for (idx, (label, value, color)) in cards.iter().enumerate() {
            let x = Self::LEFT + idx as f32 * (width + gap);
            self.rect(
                x,
                y,
                width,
                58.0,
                PdfColor::SURFACE0,
                Some(PdfColor::SURFACE2),
            );
            self.rect(x, y + 49.0, width, 9.0, *color, None);
            self.text_at(x + 12.0, y + 32.0, 20.0, true, *color, value.to_string());
            self.text_at(x + 12.0, y + 14.0, 9.0, true, PdfColor::SUBTEXT0, label);
        }
        self.y -= 76.0;
    }

    fn issue_table_header(&mut self) {
        self.ensure_space(30.0);
        let y = self.y - 23.0;
        self.rect(
            Self::LEFT,
            y,
            content_width(),
            25.0,
            PdfColor::MANTLE,
            Some(PdfColor::SURFACE2),
        );
        self.text_at(
            Self::LEFT + 14.0,
            y + 9.0,
            8.5,
            true,
            PdfColor::LAVENDER,
            "ID",
        );
        self.text_at(
            Self::LEFT + 58.0,
            y + 9.0,
            8.5,
            true,
            PdfColor::LAVENDER,
            "Severity",
        );
        self.text_at(
            Self::LEFT + 128.0,
            y + 9.0,
            8.5,
            true,
            PdfColor::LAVENDER,
            "Title",
        );
        self.text_at(
            Self::LEFT + 342.0,
            y + 9.0,
            8.5,
            true,
            PdfColor::LAVENDER,
            "Location",
        );
        self.y -= 27.0;
    }

    fn issue_row(
        &mut self,
        id: String,
        severity: &str,
        title: String,
        location: String,
        color: PdfColor,
    ) {
        self.ensure_space(36.0);
        let y = self.y - 25.0;
        self.rect(
            Self::LEFT,
            y,
            content_width(),
            27.0,
            PdfColor::SURFACE0,
            Some(PdfColor::SURFACE2),
        );
        self.rect(Self::LEFT, y, 6.0, 27.0, color, None);
        self.text_at(Self::LEFT + 14.0, y + 10.0, 8.5, true, color, id.as_str());
        self.text_at(Self::LEFT + 58.0, y + 10.0, 8.5, true, color, severity);
        self.text_at(
            Self::LEFT + 128.0,
            y + 10.0,
            8.8,
            true,
            PdfColor::TEXT,
            truncate_text(title.as_str(), 42).as_str(),
        );
        self.text_at(
            Self::LEFT + 342.0,
            y + 10.0,
            8.0,
            false,
            PdfColor::SUBTEXT0,
            truncate_text(location.as_str(), 38).as_str(),
        );
        self.y -= 31.0;
    }

    fn finding(&mut self, idx: usize, finding: &AuditFinding) {
        self.ensure_space(120.0);
        let color = severity_color(finding.severity.as_str());
        let title = format!(
            "[{}] {}",
            finding_id(idx, finding.severity.as_str()),
            finding_title(finding)
        );
        self.rect(
            Self::LEFT,
            self.y - 34.0,
            content_width(),
            34.0,
            PdfColor::SURFACE0,
            Some(PdfColor::SURFACE2),
        );
        self.rect(Self::LEFT, self.y - 34.0, 7.0, 34.0, color, None);
        self.text_at(
            Self::LEFT + 16.0,
            self.y - 21.0,
            11.0,
            true,
            PdfColor::TEXT,
            truncate_text(title.as_str(), 72).as_str(),
        );
        self.y -= 46.0;

        self.kv("Severity", severity_label(finding.severity.as_str()));
        self.kv("Category", finding.category.as_str());
        self.kv("Confidence", optional(finding.confidence.as_deref()));
        self.kv("Location", location_summary(finding));
        self.kv("Analysis layer", finding.analysis_layer.as_str());
        self.kv("Evidence", optional(finding.evidence_kind.as_deref()));
        self.kv("Final decision", final_decision_for_finding(finding));
        if let Some(review) = finding.ai_review.as_ref() {
            self.kv("AI validation", review.verdict.as_str());
            self.kv("AI review reason", review.reason.as_str());
        }

        self.subheading("Analyzer Claim");
        self.paragraph(finding.message.as_str());
        self.subheading("Impact");
        self.paragraph(impact_for_finding(finding));
        self.subheading("Proof of Concept / Evidence");
        let guidance = guidance_for_finding(finding);
        self.paragraph(guidance.abuse.as_str());
        if let Some(code) = guidance.poc_code.as_deref() {
            self.code_block(code);
        }
        self.subheading("Recommended Mitigation");
        self.paragraph(guidance.remediation.as_str());
        if let Some(code) = guidance.remediation_code.as_deref() {
            self.code_block(code);
        }
        self.y -= 8.0;
    }

    fn page_break(&mut self) {
        self.finish_page();
        self.begin_page();
    }

    fn finish(mut self) -> Vec<u8> {
        self.finish_page();
        build_native_pdf(self.pages)
    }

    fn begin_page(&mut self) {
        self.current.clear();
        self.page_no += 1;
        self.y = Self::TOP;
        self.rect(
            0.0,
            0.0,
            Self::PAGE_WIDTH,
            Self::PAGE_HEIGHT,
            PdfColor::BASE,
            None,
        );
        self.rect(0.0, 802.0, Self::PAGE_WIDTH, 40.0, PdfColor::MANTLE, None);
        let title = self.title.clone();
        self.text_at(
            Self::LEFT,
            818.0,
            10.0,
            true,
            PdfColor::TEXT,
            title.as_str(),
        );
        self.text_at(
            Self::RIGHT - 72.0,
            818.0,
            10.0,
            false,
            PdfColor::LAVENDER,
            "ChainVet",
        );
        self.text_at(
            Self::LEFT,
            32.0,
            8.0,
            false,
            PdfColor::OVERLAY2,
            format!("Page {}", self.page_no),
        );
    }

    fn ensure_space(&mut self, height: f32) {
        if self.y - height < Self::BOTTOM {
            self.page_break();
        }
    }

    fn text(&mut self, x: f32, size: f32, bold: bool, color: PdfColor, text: &str) {
        self.ensure_space(size + 8.0);
        self.text_at(x, self.y, size, bold, color, text);
        self.y -= size + 6.0;
    }

    fn wrapped_at(
        &mut self,
        x: f32,
        y: f32,
        size: f32,
        bold: bool,
        color: PdfColor,
        text: &str,
        max_chars: usize,
    ) {
        let mut line_y = y;
        for line in wrap_text_chars(text, max_chars) {
            self.text_at(x, line_y, size, bold, color, line.as_str());
            line_y -= size + 4.0;
        }
    }

    fn text_at(
        &mut self,
        x: f32,
        y: f32,
        size: f32,
        bold: bool,
        color: PdfColor,
        text: impl AsRef<str>,
    ) {
        let font = if bold { "F2" } else { "F1" };
        self.text_at_font(x, y, size, font, color, text);
    }

    fn text_at_font(
        &mut self,
        x: f32,
        y: f32,
        size: f32,
        font: &str,
        color: PdfColor,
        text: impl AsRef<str>,
    ) {
        self.current.push_str(&format!(
            "{:.3} {:.3} {:.3} rg BT /{} {:.2} Tf {:.2} {:.2} Td ({}) Tj ET\n",
            color.r,
            color.g,
            color.b,
            font,
            size,
            x,
            y,
            escape_pdf_text(text.as_ref())
        ));
    }

    fn rect(&mut self, x: f32, y: f32, w: f32, h: f32, fill: PdfColor, stroke: Option<PdfColor>) {
        self.current.push_str(&format!(
            "q {:.3} {:.3} {:.3} rg {:.2} {:.2} {:.2} {:.2} re f Q\n",
            fill.r, fill.g, fill.b, x, y, w, h
        ));
        if let Some(stroke) = stroke {
            self.current.push_str(&format!(
                "q {:.3} {:.3} {:.3} RG 0.7 w {:.2} {:.2} {:.2} {:.2} re S Q\n",
                stroke.r, stroke.g, stroke.b, x, y, w, h
            ));
        }
    }

    fn line(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, color: PdfColor, width: f32) {
        self.current.push_str(&format!(
            "q {:.3} {:.3} {:.3} RG {:.2} w {:.2} {:.2} m {:.2} {:.2} l S Q\n",
            color.r, color.g, color.b, width, x1, y1, x2, y2
        ));
    }

    fn image_at(&mut self, x: f32, y: f32, w: f32, h: f32) {
        self.current.push_str(&format!(
            "q {:.2} 0 0 {:.2} {:.2} {:.2} cm /Im1 Do Q\n",
            w, h, x, y
        ));
    }

    fn finish_page(&mut self) {
        if !self.current.trim().is_empty() {
            self.pages.push(std::mem::take(&mut self.current));
        }
    }
}

pub fn project_name_from_path(path: &str) -> String {
    let path = Path::new(path);
    path.file_stem()
        .or_else(|| path.file_name())
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("Protocol")
        .to_string()
}

pub fn audit_findings_from_surfaced<'a>(
    runtime_findings: impl IntoIterator<Item = &'a surfaced::SurfacedFinding>,
    meta_findings: impl IntoIterator<Item = &'a surfaced::SurfacedFinding>,
) -> Vec<AuditFinding> {
    runtime_findings
        .into_iter()
        .chain(meta_findings)
        .map(AuditFinding::from_surfaced)
        .collect()
}

fn audit_report_from_static(report: &Report, requested_path: &str) -> AuditReport {
    AuditReport {
        project_name: project_name_from_path(requested_path),
        target: requested_path.to_string(),
        analysis_mode: format!("static ({})", report.mode),
        raw_findings: report.finding_count_raw,
        suppressed_findings: report.suppressed_findings,
        metrics: vec![
            AuditMetric::new("Files", report.files.to_string()),
            AuditMetric::new("Functions", report.functions.to_string()),
            AuditMetric::new("CFGs", report.cfgs.to_string()),
            AuditMetric::new("Call sites", report.calls.to_string()),
            AuditMetric::new(
                "Resolved calls",
                report.call_resolution.resolved.to_string(),
            ),
            AuditMetric::new(
                "Tainted functions",
                report.taint.tainted_functions.to_string(),
            ),
            AuditMetric::new("SSA definitions", report.ssa.defs.to_string()),
        ],
        findings: report
            .findings
            .iter()
            .map(|finding| AuditFinding {
                category: finding.category.clone(),
                kind: finding.kind.clone(),
                severity: finding.severity.clone(),
                confidence: finding.confidence.clone(),
                message: finding.message.clone(),
                file: Some(finding.file.clone()),
                start: Some(finding.span.start),
                end: Some(finding.span.end),
                function_name: finding.function.clone(),
                analysis_layer: "static".to_string(),
                evidence_kind: Some("rule".to_string()),
                ai_review: None,
            })
            .collect(),
        review_summary: None,
    }
}

#[derive(Default)]
struct SeverityCounts {
    high: usize,
    medium: usize,
    low: usize,
    informational: usize,
}

fn severity_counts(findings: &[AuditFinding]) -> SeverityCounts {
    let mut counts = SeverityCounts::default();
    for finding in findings {
        match severity_bucket(finding.severity.as_str()) {
            "high" => counts.high += 1,
            "medium" => counts.medium += 1,
            "low" => counts.low += 1,
            _ => counts.informational += 1,
        }
    }
    counts
}

struct ReportConfidence {
    label: &'static str,
    reason: &'static str,
}

fn report_confidence(report: &AuditReport) -> ReportConfidence {
    let Some(summary) = report.review_summary.as_ref() else {
        return ReportConfidence {
            label: "Medium",
            reason: "Report generated from analyzer evidence without AI review metadata.",
        };
    };

    if summary.failed > 0 || summary.skipped > 0 {
        return ReportConfidence {
            label: "Medium",
            reason: "Some findings were retained without AI review because the model failed or the review limit was reached.",
        };
    }

    if summary.ai_candidates > 0 && summary.ai_reviewed == summary.ai_candidates {
        return ReportConfidence {
            label: "High",
            reason: "All findings that passed deterministic prefiltering were reviewed by the configured AI model.",
        };
    }

    if summary.ai_candidates == 0 {
        return ReportConfidence {
            label: "High",
            reason: "All surfaced findings were resolved by deterministic source-backed filters.",
        };
    }

    ReportConfidence {
        label: "Medium",
        reason: "The report includes analyzer evidence and deterministic filtering, but AI coverage was incomplete.",
    }
}

fn push_ai_review_summary(out: &mut String, report: &AuditReport, confidence_reason: &str) {
    push_line(out, "# AI Review Summary");
    push_line(out, "");
    let Some(summary) = report.review_summary.as_ref() else {
        push_line(out, "AI review was not used for this report.");
        push_line(out, "");
        push_line(
            out,
            &format!(
                "Report confidence: **{}**. {}",
                report_confidence(report).label,
                confidence_reason
            ),
        );
        push_line(out, "");
        return;
    };

    push_line(out, "| Stage | Count |");
    push_line(out, "| --- | ---: |");
    push_line(
        out,
        &format!("| Raw surfaced findings | {} |", summary.raw_findings),
    );
    push_line(
        out,
        &format!(
            "| Deterministic prefilter removed | {} |",
            summary.deterministic_filtered
        ),
    );
    push_line(
        out,
        &format!(
            "| AI candidates after prefilter | {} |",
            summary.ai_candidates
        ),
    );
    push_line(out, &format!("| AI attempted | {} |", summary.ai_attempted));
    push_line(out, &format!("| AI reviewed | {} |", summary.ai_reviewed));
    push_line(out, &format!("| AI removed | {} |", summary.ai_filtered));
    push_line(out, &format!("| AI failures | {} |", summary.failed));
    push_line(
        out,
        &format!("| Skipped by review limit | {} |", summary.skipped),
    );
    push_line(
        out,
        &format!("| Final reportable findings | {} |", summary.final_findings),
    );
    push_line(
        out,
        &format!("| Model | `{}` |", escape_table(summary.model.as_str())),
    );
    push_line(out, "");
    push_line(
        out,
        &format!(
            "Report confidence: **{}**. {}",
            report_confidence(report).label,
            confidence_reason
        ),
    );
    push_line(out, "");
}

fn push_finding_section(out: &mut String, idx: usize, finding: &AuditFinding) {
    push_line(
        out,
        &format!(
            "## [{}] {}",
            finding_id(idx, finding.severity.as_str()),
            finding_title(finding)
        ),
    );
    push_line(out, "");
    push_line(out, "| Field | Value |");
    push_line(out, "| --- | --- |");
    push_line(
        out,
        &format!(
            "| Severity | {} |",
            severity_label(finding.severity.as_str())
        ),
    );
    push_line(
        out,
        &format!("| Category | {} |", escape_table(finding.category.as_str())),
    );
    push_line(
        out,
        &format!(
            "| Confidence | {} |",
            escape_table(optional(finding.confidence.as_deref()))
        ),
    );
    push_line(
        out,
        &format!(
            "| Location | {} |",
            escape_table(location_summary(finding).as_str())
        ),
    );
    push_line(
        out,
        &format!(
            "| Analysis layer | {} |",
            escape_table(finding.analysis_layer.as_str())
        ),
    );
    push_line(
        out,
        &format!(
            "| Evidence | {} |",
            escape_table(optional(finding.evidence_kind.as_deref()))
        ),
    );
    push_line(
        out,
        &format!(
            "| Final decision | {} |",
            escape_table(final_decision_for_finding(finding))
        ),
    );
    if let Some(review) = finding.ai_review.as_ref() {
        push_line(
            out,
            &format!(
                "| AI validation | {} |",
                escape_table(review.verdict.as_str())
            ),
        );
        push_line(
            out,
            &format!(
                "| AI review reason | {} |",
                escape_table(review.reason.as_str())
            ),
        );
    }
    push_line(out, "");
    push_line(out, "### Analyzer Claim");
    push_line(out, "");
    push_line(out, escape_md(finding.message.as_str()).as_str());
    push_line(out, "");
    push_line(out, "### Impact");
    push_line(out, "");
    push_line(out, impact_for_finding(finding));
    push_line(out, "");
    push_line(out, "### Proof of Concept / Evidence");
    push_line(out, "");
    let guidance = guidance_for_finding(finding);
    push_line(out, escape_md(guidance.abuse.as_str()).as_str());
    if let Some(code) = guidance.poc_code.as_deref() {
        push_line(out, "");
        push_line(out, "```solidity");
        push_line(out, code);
        push_line(out, "```");
    }
    push_line(out, "");
    push_line(out, "### Recommended Mitigation");
    push_line(out, "");
    push_line(out, escape_md(guidance.remediation.as_str()).as_str());
    if let Some(code) = guidance.remediation_code.as_deref() {
        push_line(out, "");
        push_line(out, "```solidity");
        push_line(out, code);
        push_line(out, "```");
    }
    push_line(out, "");
}

fn finding_title(finding: &AuditFinding) -> String {
    let mut title = title_case_kind(finding.kind.as_str());
    if let Some(function) = finding
        .function_name
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        title.push_str(" in ");
        title.push_str(function);
    }
    title
}

fn finding_id(idx: usize, severity: &str) -> String {
    let prefix = match severity_bucket(severity) {
        "high" => "H",
        "medium" => "M",
        "low" => "L",
        _ => "I",
    };
    format!("{prefix}-{idx:02}")
}

fn severity_bucket(severity: &str) -> &'static str {
    let value = severity.trim().to_ascii_lowercase();
    if value.contains("critical") || value.contains("high") {
        "high"
    } else if value.contains("medium") || value.contains("moderate") {
        "medium"
    } else if value.contains("low") {
        "low"
    } else {
        "informational"
    }
}

fn severity_sort_rank(severity: &str) -> u8 {
    match severity_bucket(severity) {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    }
}

fn severity_label(severity: &str) -> &'static str {
    match severity_bucket(severity) {
        "high" => "High",
        "medium" => "Medium",
        "low" => "Low",
        _ => "Informational",
    }
}

fn ai_assistance_status(report: &AuditReport) -> String {
    if let Some(summary) = report.review_summary.as_ref() {
        let status = if summary.ai_reviewed == 0 && summary.ai_candidates > 0 {
            "Fallback only"
        } else if summary.failed > 0 || summary.skipped > 0 {
            "Used partially"
        } else {
            "Used"
        };
        return format!(
            "{status} (AI attempted {}; reviewed {}/{} remaining; failed {}; skipped {}; deterministic prefilter removed {}; AI removed {}; final {}; model {})",
            summary.ai_attempted,
            summary.ai_reviewed,
            summary.ai_candidates,
            summary.failed,
            summary.skipped,
            summary.deterministic_filtered,
            summary.ai_filtered,
            summary.final_findings,
            summary.model
        );
    }
    let Some(metric) = report
        .metrics
        .iter()
        .find(|metric| metric.label == "AI review")
    else {
        return "Not used".to_string();
    };
    if metric.value.starts_with("reviewed 0")
        || metric.value.starts_with("enabled; no findings reviewed")
        || metric.value.contains("AI reviewed 0/")
    {
        format!("Fallback only ({})", metric.value)
    } else if has_nonzero_ai_metric(metric.value.as_str(), "failed")
        || has_nonzero_ai_metric(metric.value.as_str(), "skipped")
    {
        format!("Used partially ({})", metric.value)
    } else {
        format!("Used ({})", metric.value)
    }
}

fn has_nonzero_ai_metric(value: &str, label: &str) -> bool {
    let Some(rest) = value.split(label).nth(1) else {
        return false;
    };
    let count = rest
        .trim_start()
        .split(|ch: char| !ch.is_ascii_digit())
        .next()
        .unwrap_or("");
    count.parse::<usize>().unwrap_or(0) > 0
}

fn final_decision_for_finding(finding: &AuditFinding) -> &'static str {
    match finding
        .ai_review
        .as_ref()
        .map(|review| review.verdict.as_str())
    {
        Some("true_positive") => "Reportable (AI confirmed)",
        Some("uncertain") => "Reportable (AI uncertain; retained for manual review)",
        Some(_) => "Reportable",
        None => "Reportable (analyzer/fallback retained)",
    }
}

fn location_summary(finding: &AuditFinding) -> String {
    let file = finding.file.as_deref().unwrap_or("<unknown>");
    let mut location = String::from(file);
    if let Some(function) = finding
        .function_name
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        location.push_str("::");
        location.push_str(function);
    }
    match (finding.start, finding.end) {
        (Some(start), Some(end)) if start != 0 || end != 0 => {
            location.push_str(format!(" ({start}-{end})").as_str());
        }
        (Some(start), _) if start != 0 => {
            location.push_str(format!(" ({start})").as_str());
        }
        _ => {}
    }
    location
}

struct FindingGuidance {
    abuse: String,
    poc_code: Option<String>,
    remediation: String,
    remediation_code: Option<String>,
}

fn strip_markdown_fence(text: &str) -> String {
    let trimmed = text.trim();
    if !trimmed.starts_with("```") {
        return trimmed.to_string();
    }
    if let Some(code) = extract_solidity_fence(trimmed) {
        return code;
    }
    let mut lines = trimmed.lines();
    let _ = lines.next();
    let body = lines.collect::<Vec<_>>().join("\n");
    body.trim_end_matches("```").trim().to_string()
}

fn text_without_fenced_blocks(text: &str) -> String {
    let mut in_fence = false;
    let mut lines = Vec::new();
    for line in text.lines() {
        if line.trim().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if !in_fence {
            lines.push(line);
        }
    }
    lines.join("\n").trim().to_string()
}

fn is_useful_ai_poc_code(code: &str, function: &str) -> bool {
    let normalized = code.to_ascii_lowercase();
    normalized.contains(function.to_ascii_lowercase().as_str())
        && (normalized.contains("function()") || normalized.contains("receive()"))
        && (normalized.contains("constructor")
            || normalized.contains("function reentrancypoc")
            || normalized.contains("function attacker")
            || normalized.contains("= ivictim(")
            || normalized.contains("= reentrance("))
}

fn extract_solidity_fence(text: &str) -> Option<String> {
    let mut in_fence = false;
    let mut code = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            if in_fence {
                return (!code.is_empty()).then(|| code.join("\n"));
            }
            let lang = trimmed.trim_start_matches("```").trim();
            if lang.is_empty()
                || lang.eq_ignore_ascii_case("solidity")
                || lang.eq_ignore_ascii_case("sol")
            {
                in_fence = true;
            }
            continue;
        }
        if in_fence {
            code.push(line);
        }
    }
    None
}

fn guidance_for_finding(finding: &AuditFinding) -> FindingGuidance {
    let mut guidance = deterministic_guidance_for_finding(finding);
    if let Some(review) = finding.ai_review.as_ref() {
        if let Some(poc) = review
            .improved_poc
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let prose = text_without_fenced_blocks(poc);
            guidance.abuse = if prose.is_empty() {
                format!("AI validation note: {}", review.reason.trim())
            } else {
                format!("{prose}\n\nAI validation note: {}", review.reason.trim())
            };
            if let Some(code) = extract_solidity_fence(poc) {
                let function = finding
                    .function_name
                    .as_deref()
                    .unwrap_or(finding.kind.as_str());
                if is_useful_ai_poc_code(code.as_str(), function) {
                    guidance.poc_code = Some(code);
                }
            }
        }
        if let Some(remediation) = review
            .improved_remediation
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let prose = text_without_fenced_blocks(remediation);
            if !prose.is_empty() {
                guidance.remediation = prose;
            }
        }
        if let Some(code) = review
            .improved_remediation_code
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            guidance.remediation_code =
                Some(extract_solidity_fence(code).unwrap_or_else(|| strip_markdown_fence(code)));
        }
    }
    guidance
}

fn deterministic_guidance_for_finding(finding: &AuditFinding) -> FindingGuidance {
    let kind = surfaced::canonicalize_kind(finding.kind.as_str());
    let function = finding
        .function_name
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("vulnerableFunction");
    let location = location_summary(finding);

    match kind.as_str() {
        "reentrancy" => FindingGuidance {
            abuse: format!(
                "An attacker can call `{function}` from a contract whose fallback re-enters the same function before the vulnerable contract finalizes its accounting. If the balance or entitlement is reduced after the external call, the attacker can withdraw more than their legitimate balance. A minimal abuse flow is: deposit or obtain credit, call `{function}`, re-enter from `receive()`, and repeat until the contract balance or gas is exhausted. Location: {location}."
            ),
            poc_code: Some(format!(
                r#"interface IVictim {{
    function addToBalance() public payable;
    function {function}() external;
}}

contract ReentrancyPoC {{
    IVictim public victim;
    uint256 public reentered;

    function ReentrancyPoC(address victim_) public {{
        victim = IVictim(victim_);
    }}

    function attack() public payable {{
        victim.addToBalance.value(msg.value)();
        victim.{function}();
    }}

    function() public payable {{
        if (reentered < 3 && address(victim).balance > 0) {{
            reentered++;
            victim.{function}();
        }}
    }}
}}"#
            )),
            remediation: "Apply checks-effects-interactions on the affected withdrawal path: validate the caller, calculate the amount, update all internal accounting before the external transfer, then perform the external call. Add a reentrancy guard on externally callable payout functions and prefer pull-based withdrawals for user funds.".to_string(),
            remediation_code: Some(format!(
                r#"bool private locked;
mapping(address => uint256) private balances;

modifier nonReentrant() {{
    require(!locked);
    locked = true;
    _;
    locked = false;
}}

function {function}() public nonReentrant {{
    uint256 amount = balances[msg.sender];
    require(amount != 0);

    balances[msg.sender] = 0; // effects before interaction

    if (!msg.sender.call.value(amount)()) {{
        throw;
    }}
}}"#
            )),
        },
        "access-control" | "unprotected-ether-withdrawal" | "public-mint-burn" => FindingGuidance {
            abuse: format!(
                "The function `{function}` appears to perform a privileged action without a reliable authorization gate. Any externally owned account or contract can call it directly, so an attacker can execute the privileged path without owning the protocol role. Depending on the function, this may drain ETH, mint/burn assets, or change security-critical state. Location: {location}."
            ),
            poc_code: Some(format!(
                r#"interface IVictim {{
    function {function}() external;
}}

contract UnauthorizedCallerPoC {{
    function exploit(address victim) external {{
        // Succeeds if {function} has no onlyOwner/role check.
        IVictim(victim).{function}();
    }}
}}"#
            )),
            remediation: "Restrict the function to the exact role that is supposed to execute it. Use `onlyOwner`, role-based access control, or a protocol-specific permission check, and add negative tests that prove arbitrary callers revert.".to_string(),
            remediation_code: Some(format!(
                r#"address private owner;

modifier onlyOwner() {{
    require(msg.sender == owner, "not authorized");
    _;
}}

function {function}() external onlyOwner {{
    // privileged logic
}}"#
            )),
        },
        "tx-origin" => FindingGuidance {
            abuse: format!(
                "Authorization based on `tx.origin` can be phished. An attacker deploys a contract that calls `{function}` and convinces the legitimate owner to trigger the attacker contract. During the nested call, `tx.origin` is still the owner, so the victim incorrectly authorizes the attacker's contract. Location: {location}."
            ),
            poc_code: Some(format!(
                r#"interface IVictim {{
    function {function}() external;
}}

contract TxOriginPhishingPoC {{
    IVictim private immutable victim;

    constructor(address victim_) {{
        victim = IVictim(victim_);
    }}

    function claimReward() external {{
        // If victim checks tx.origin == owner, this call can pass
        // when the owner is tricked into calling claimReward().
        victim.{function}();
    }}
}}"#
            )),
            remediation: "Never use `tx.origin` for authorization. Authorize the immediate caller with `msg.sender`, or use explicit signatures/meta-transaction validation when calls are intentionally relayed.".to_string(),
            remediation_code: Some(format!(
                r#"address private owner;

function {function}() external {{
    require(msg.sender == owner, "not owner");
    // privileged logic
}}"#
            )),
        },
        "weak-prng" | "timestamp-dependency" => FindingGuidance {
            abuse: format!(
                "The outcome can be influenced because it depends on block data such as timestamp, block number, block hash, or caller-controlled inputs. A validator or searcher can choose whether to include a transaction, reorder it, or slightly influence timestamp-dependent execution to bias the result. Location: {location}."
            ),
            poc_code: Some(
                r#"contract RandomnessBiasPoC {
    function attackerStrategy(address game, bytes calldata playTx) external {
        // The attacker simulates the outcome off-chain for the current block.
        // If the computed value is unfavorable, they do not submit/bundle playTx.
        // If favorable, they submit it or ask a block builder to include it.
        game.call(playTx);
    }
}"#
                .to_string(),
            ),
            remediation: "Do not derive value-bearing randomness from block variables or public transaction inputs. Use a commit-reveal scheme for low-value flows, or a verifiable randomness oracle such as Chainlink VRF for lotteries, games, winner selection, and asset distribution.".to_string(),
            remediation_code: Some(
                r#"// Commit-reveal sketch:
mapping(address => bytes32) public commits;

function commit(bytes32 commitment) external {
    commits[msg.sender] = commitment;
}

function reveal(uint256 secret) external {
    require(commits[msg.sender] == keccak256(abi.encode(secret, msg.sender)), "bad reveal");
    // Combine committed secret with a future source, or prefer VRF for high-value randomness.
}"#
                .to_string(),
            ),
        },
        "unchecked-call" => FindingGuidance {
            abuse: format!(
                "The contract appears to continue execution after an external call without requiring success. An attacker-controlled callee can revert or return `false`, while the victim still updates state as if the transfer or action succeeded. This can create incorrect accounting, unpaid withdrawals, or inconsistent protocol state. Location: {location}."
            ),
            poc_code: Some(
                r#"contract RejectsEther {
    receive() external payable {
        revert("reject payment");
    }
}

// If the victim ignores the return value:
// (bool ok, ) = user.call{value: amount}("");
// balances[user] = 0; // state changes even when ok == false"#
                    .to_string(),
            ),
            remediation: "Check the returned success flag for every low-level call. Only update accounting after the call succeeds, or use a pull-payment design where failed recipients can retry without blocking other users.".to_string(),
            remediation_code: Some(
                r#"(bool ok, ) = recipient.call{value: amount}("");
require(ok, "external call failed");"#
                    .to_string(),
            ),
        },
        "hardcoded-gas-transfer" => FindingGuidance {
            abuse: format!(
                "`transfer`/`send` forwards a fixed 2300 gas stipend. A recipient contract with a non-trivial `receive()` function can fail the transfer, causing withdrawals or payout loops to revert and creating a denial of service. Location: {location}."
            ),
            poc_code: Some(
                r#"contract GasHeavyReceiver {
    uint256 public writes;

    receive() external payable {
        writes += 1; // costs more than the 2300 gas stipend
    }
}"#
                    .to_string(),
            ),
            remediation: "Avoid relying on `transfer`/`send` for critical payouts. Use `call` with checked success, update state before the call, and prefer pull payments so one receiver cannot block the entire payout flow.".to_string(),
            remediation_code: Some(
                r#"uint256 amount = pending[msg.sender];
pending[msg.sender] = 0;

(bool ok, ) = msg.sender.call{value: amount}("");
require(ok, "ETH transfer failed");"#
                    .to_string(),
            ),
        },
        "integer-overflow" | "integer-underflow" => FindingGuidance {
            abuse: format!(
                "Unchecked arithmetic can wrap around and produce values that are much larger or smaller than intended. An attacker can choose inputs near integer boundaries to bypass balance, supply, or limit checks. Location: {location}."
            ),
            poc_code: Some(
                r#"contract OverflowPoC {
    function overflow(uint256 balance, uint256 amount) external pure returns (uint256) {
        unchecked {
            return balance + amount; // wraps if balance + amount > type(uint256).max
        }
    }
}"#
                    .to_string(),
            ),
            remediation: "Compile with Solidity 0.8 or newer and do not use `unchecked` around security-critical accounting. If the project must use an older compiler, use a reviewed SafeMath library for every arithmetic operation that affects balances, supply, limits, or authorization.".to_string(),
            remediation_code: Some(
                r#"pragma solidity ^0.8.20;

function addBalance(uint256 balance, uint256 amount) internal pure returns (uint256) {
    return balance + amount; // reverts automatically on overflow in Solidity 0.8+
}"#
                    .to_string(),
            ),
        },
        "locked-ether" => FindingGuidance {
            abuse: format!(
                "ETH can enter the contract, but the analyzer did not find a reliable recovery or withdrawal path for the affected balance. Funds may become permanently inaccessible after direct transfers, forced ETH via selfdestruct, or normal payable flows. Location: {location}."
            ),
            poc_code: Some(
                r#"contract ForceEther {
    constructor() payable {}

    function forceSend(address target) external {
        selfdestruct(payable(target));
    }
}"#
                    .to_string(),
            ),
            remediation: "Add an explicit, access-controlled recovery or withdrawal function for ETH that is not part of normal accounting. If ETH should never be accepted, make receive/fallback revert and document how forced ETH is handled.".to_string(),
            remediation_code: Some(
                r#"function recoverEther(address payable to, uint256 amount) external onlyOwner {
    require(to != address(0), "bad recipient");
    (bool ok, ) = to.call{value: amount}("");
    require(ok, "recovery failed");
}"#
                    .to_string(),
            ),
        },
        "unsafe-delegatecall" => FindingGuidance {
            abuse: format!(
                "Delegatecall executes code from another address in the storage context of the caller. If an attacker can influence the delegatecall target or calldata, they can overwrite storage, seize ownership, or drain funds. Location: {location}."
            ),
            poc_code: Some(
                r#"contract MaliciousImplementation {
    // Storage slot layout chosen to match the victim.
    address public owner;

    function seizeOwnership() external {
        owner = msg.sender;
    }
}"#
                    .to_string(),
            ),
            remediation: "Only delegatecall to trusted, immutable or allowlisted implementations. Validate calldata, preserve storage layout intentionally, and use a reviewed proxy pattern when upgradeability is required.".to_string(),
            remediation_code: Some(
                r#"mapping(address => bool) public approvedImplementation;

function execute(address implementation, bytes calldata data) external onlyOwner {
    require(approvedImplementation[implementation], "implementation not approved");
    (bool ok, bytes memory ret) = implementation.delegatecall(data);
    require(ok, "delegatecall failed");
}"#
                    .to_string(),
            ),
        },
        "unprotected-selfdestruct" => FindingGuidance {
            abuse: format!(
                "If an attacker can reach a selfdestruct path, they can permanently remove contract code or force remaining ETH to an arbitrary beneficiary. This can break integrations and destroy protocol availability. Location: {location}."
            ),
            poc_code: Some(format!(
                r#"interface IVictim {{
    function {function}() external;
}}

contract KillPoC {{
    function exploit(address victim) external {{
        IVictim(victim).{function}();
    }}
}}"#
            )),
            remediation: "Remove selfdestruct unless it is strictly required. If it must remain, restrict it to a timelocked governance or owner-only emergency path and emit an event before execution.".to_string(),
            remediation_code: Some(format!(
                r#"function {function}() external onlyOwner {{
    // Prefer removing this entirely.
    selfdestruct(payable(owner));
}}"#
            )),
        },
        "shadowing" => FindingGuidance {
            abuse: format!(
                "A local variable, parameter, or inherited declaration shadows another state item. This can cause reviewers and developers to believe a security-critical state variable is being read or updated when the code is actually using a different value. Location: {location}."
            ),
            poc_code: Some(
                r#"contract ShadowingExample {
    address public owner;

    function setOwner(address owner) external {
        // This assigns the parameter to itself, not the state variable.
        owner = owner;
    }
}"#
                    .to_string(),
            ),
            remediation: "Rename shadowing variables and use explicit naming conventions for parameters and storage variables. For example, use `newOwner` for parameters and assign it to `owner` directly.".to_string(),
            remediation_code: Some(
                r#"function setOwner(address newOwner) external onlyOwner {
    require(newOwner != address(0), "zero owner");
    owner = newOwner;
}"#
                    .to_string(),
            ),
        },
        _ => FindingGuidance {
            abuse: format!(
                "The finding points to behavior that may be exploitable depending on surrounding business logic. Review the path at {location}, identify who can call it, which state variables change, and whether an attacker can control the inputs or external call target."
            ),
            poc_code: None,
            remediation: recommendation_for_kind(finding.kind.as_str(), finding.category.as_str()).to_string(),
            remediation_code: None,
        },
    }
}

fn impact_for_finding(finding: &AuditFinding) -> &'static str {
    match surfaced::canonicalize_kind(finding.kind.as_str()).as_str() {
        "reentrancy" => {
            "A vulnerable external-call flow may allow an attacker-controlled contract to re-enter before state is finalized, potentially draining funds or corrupting accounting."
        }
        "access-control"
        | "tx-origin"
        | "unprotected-selfdestruct"
        | "unsafe-delegatecall"
        | "unprotected-ether-withdrawal"
        | "public-mint-burn" => {
            "Missing or weak authorization can allow unauthorized users to execute privileged actions or change sensitive protocol state."
        }
        "integer-overflow" | "integer-underflow" => {
            "Arithmetic edge cases can produce incorrect balances, limits, or accounting values when unchecked math is reachable."
        }
        "weak-prng" | "timestamp-dependency" | "transaction-order-dependency" => {
            "Block-derived or ordering-sensitive logic can be influenced by miners, validators, or transaction ordering, causing unfair or unexpected outcomes."
        }
        "dos-block-gas-limit" | "dos-with-failed-call" | "locked-ether" => {
            "The affected flow may become unavailable, fail for legitimate users, or permanently trap funds under realistic execution conditions."
        }
        "unchecked-call" | "hardcoded-gas-transfer" => {
            "External call failures may be missed or forced by gas constraints, causing state to continue under incorrect assumptions."
        }
        "memory-manipulation" | "shadowing" => {
            "Ambiguous storage or variable behavior can cause developers and users to reason incorrectly about the contract state."
        }
        _ => {
            "The finding indicates behavior that may weaken contract safety, correctness, or maintainability depending on the surrounding business logic."
        }
    }
}

fn recommendation_for_kind(kind: &str, category: &str) -> &'static str {
    match surfaced::canonicalize_kind(kind).as_str() {
        "reentrancy" => {
            "Apply checks-effects-interactions, update state before external calls, and consider a reentrancy guard on externally callable payout paths."
        }
        "access-control" | "unprotected-ether-withdrawal" | "public-mint-burn" => {
            "Add explicit authorization checks for privileged functions and cover them with tests for unauthorized callers."
        }
        "tx-origin" => {
            "Use `msg.sender` for authorization instead of `tx.origin`, and validate the intended caller model in tests."
        }
        "unprotected-selfdestruct" => {
            "Remove `selfdestruct` where possible, or restrict it to a tightly controlled administrative path."
        }
        "unsafe-delegatecall" => {
            "Avoid delegatecall to user-controlled addresses. If delegatecall is required, restrict targets to trusted implementations."
        }
        "integer-overflow" | "integer-underflow" => {
            "Use Solidity 0.8+ checked arithmetic or a reviewed SafeMath-style library for older compiler versions."
        }
        "weak-prng" | "timestamp-dependency" => {
            "Avoid block variables for randomness. Use a commit-reveal design or a verifiable randomness oracle for value-bearing outcomes."
        }
        "transaction-order-dependency" => {
            "Design state transitions so transaction ordering cannot give another participant a profitable advantage."
        }
        "dos-block-gas-limit" => {
            "Avoid unbounded loops over dynamic storage. Prefer pull-based accounting, pagination, or bounded batch processing."
        }
        "dos-with-failed-call" | "unchecked-call" => {
            "Check external call return values and isolate user-specific failures with pull payments or retryable accounting."
        }
        "hardcoded-gas-transfer" => {
            "Avoid relying on fixed gas stipends for critical transfers. Prefer explicit call handling with checked success."
        }
        "locked-ether" => {
            "Add a reviewed withdrawal or recovery path and test forced-Ether and accounting edge cases."
        }
        "shadowing" => {
            "Rename shadowed variables and avoid local or parameter names that hide state variables."
        }
        _ if category.eq_ignore_ascii_case("gas") => {
            "Review the affected code path for unnecessary storage access, repeated computation, or unbounded iteration."
        }
        _ => {
            "Review the affected code path manually, add a focused regression test, and apply the smallest code change that removes the unsafe behavior."
        }
    }
}

fn title_case_kind(kind: &str) -> String {
    kind.split(['-', '_', ' '])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => format!("{}{}", first.to_ascii_uppercase(), chars.as_str()),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn optional(value: Option<&str>) -> &str {
    value
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("unknown")
}

fn escape_md(value: &str) -> String {
    value.replace('|', "\\|")
}

fn escape_table(value: &str) -> String {
    escape_md(value).replace('\n', "<br>")
}

fn escape_latex_text(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\textbackslash{}"),
            '&' => escaped.push_str("\\&"),
            '%' => escaped.push_str("\\%"),
            '$' => escaped.push_str("\\$"),
            '#' => escaped.push_str("\\#"),
            '_' => escaped.push_str("\\_"),
            '{' => escaped.push_str("\\{"),
            '}' => escaped.push_str("\\}"),
            '~' => escaped.push_str("\\textasciitilde{}"),
            '^' => escaped.push_str("\\textasciicircum{}"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn chainvet_logo_data_uri() -> String {
    format!("data:image/png;base64,{}", base64_encode(CHAINVET_LOGO_PNG))
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let chunk = &bytes[index..index + 3];
        let value = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32;
        out.push(TABLE[((value >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((value >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((value >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(value & 0x3f) as usize] as char);
        index += 3;
    }

    match bytes.len().saturating_sub(index) {
        1 => {
            let value = (bytes[index] as u32) << 16;
            out.push(TABLE[((value >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((value >> 12) & 0x3f) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let value = ((bytes[index] as u32) << 16) | ((bytes[index + 1] as u32) << 8);
            out.push(TABLE[((value >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((value >> 12) & 0x3f) as usize] as char);
            out.push(TABLE[((value >> 6) & 0x3f) as usize] as char);
            out.push('=');
        }
        _ => {}
    }

    out
}

fn render_markdown_pdf_with_pandoc(markdown: &str) -> Result<Vec<u8>> {
    let Some(pandoc) = find_executable("pandoc") else {
        return Err(Error::msg(
            "PDF generation requires Pandoc, a LaTeX PDF engine, and the Eisvogel template. Install them or generate Markdown instead.",
        ));
    };

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let work_dir =
        std::env::temp_dir().join(format!("chainvet-report-{}-{stamp}", std::process::id()));
    fs::create_dir_all(&work_dir)?;

    let md_path = work_dir.join("report.md");
    let pdf_path = work_dir.join("report.pdf");
    fs::write(&md_path, markdown)?;

    let template = std::env::var("CHAINVET_PANDOC_TEMPLATE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "eisvogel".to_string());

    let output = Command::new(pandoc)
        .arg(&md_path)
        .arg("-o")
        .arg(&pdf_path)
        .arg("--from")
        .arg("markdown")
        .arg("--template")
        .arg(&template)
        .arg("--listings")
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        let _ = fs::remove_dir_all(&work_dir);
        return Err(Error::msg(format!(
            "Pandoc failed to generate the PDF with template `{template}`: {detail}"
        )));
    }

    let pdf = fs::read(&pdf_path)?;
    let _ = fs::remove_dir_all(&work_dir);
    Ok(pdf)
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let candidate = dir.join(format!("{name}.exe"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn severity_color(severity: &str) -> PdfColor {
    match severity_bucket(severity) {
        "high" => PdfColor::RED,
        "medium" => PdfColor::PEACH,
        "low" => PdfColor::YELLOW,
        _ => PdfColor::SKY,
    }
}

fn content_width() -> f32 {
    NativePdf::RIGHT - NativePdf::LEFT
}

fn wrap_pdf_line(text: &str, width: f32, font_size: f32) -> Vec<String> {
    let max_chars = ((width / (font_size * 0.52)).floor() as usize).max(24);
    wrap_text_chars(text, max_chars)
}

fn wrap_code_line(text: &str, max_chars: usize) -> Vec<String> {
    let line = text.replace('\t', "    ");
    if line.is_empty() {
        return vec![String::new()];
    }
    if line.chars().count() <= max_chars {
        return vec![line];
    }

    let indent = line.chars().take_while(|ch| *ch == ' ').collect::<String>();
    let continuation = format!("{indent}    ");
    let mut out = Vec::new();
    let mut remaining = line.as_str();
    let mut first = true;

    while remaining.chars().count() > max_chars {
        let width = if first {
            max_chars
        } else {
            max_chars
                .saturating_sub(continuation.chars().count())
                .max(24)
        };
        let mut split_at = 0usize;
        let mut last_break = None;
        for (idx, ch) in remaining.char_indices() {
            if remaining[..idx].chars().count() >= width {
                break;
            }
            split_at = idx + ch.len_utf8();
            if ch.is_whitespace() || matches!(ch, ',' | ';' | ')' | '(' | '{' | '}') {
                last_break = Some(split_at);
            }
        }
        let split_at = last_break.filter(|idx| *idx > 0).unwrap_or(split_at);
        let chunk = remaining[..split_at].trim_end();
        if first {
            out.push(chunk.to_string());
            first = false;
        } else {
            out.push(format!("{continuation}{chunk}"));
        }
        remaining = remaining[split_at..].trim_start();
    }
    if first {
        out.push(remaining.to_string());
    } else if !remaining.is_empty() {
        out.push(format!("{continuation}{remaining}"));
    }
    out
}

struct CodeToken {
    text: String,
    color: PdfColor,
}

fn solidity_highlight(line: &str) -> Vec<CodeToken> {
    let mut tokens = Vec::new();
    let chars = line.chars().collect::<Vec<_>>();
    let mut index = 0usize;

    while index < chars.len() {
        let ch = chars[index];

        if ch == '/' && chars.get(index + 1) == Some(&'/') {
            tokens.push(CodeToken {
                text: chars[index..].iter().collect(),
                color: PdfColor::OVERLAY2,
            });
            break;
        }

        if ch == '"' || ch == '\'' {
            let quote = ch;
            let start = index;
            index += 1;
            while index < chars.len() {
                if chars[index] == '\\' {
                    index = (index + 2).min(chars.len());
                    continue;
                }
                let done = chars[index] == quote;
                index += 1;
                if done {
                    break;
                }
            }
            tokens.push(CodeToken {
                text: chars[start..index].iter().collect(),
                color: PdfColor::GREEN,
            });
            continue;
        }

        if ch.is_ascii_alphabetic() || ch == '_' {
            let start = index;
            index += 1;
            while index < chars.len()
                && (chars[index].is_ascii_alphanumeric() || chars[index] == '_')
            {
                index += 1;
            }
            let word = chars[start..index].iter().collect::<String>();
            tokens.push(CodeToken {
                color: solidity_token_color(word.as_str()),
                text: word,
            });
            continue;
        }

        if ch.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < chars.len()
                && (chars[index].is_ascii_hexdigit()
                    || matches!(chars[index], 'x' | 'X' | '_' | '.'))
            {
                index += 1;
            }
            tokens.push(CodeToken {
                text: chars[start..index].iter().collect(),
                color: PdfColor::PEACH,
            });
            continue;
        }

        tokens.push(CodeToken {
            text: ch.to_string(),
            color: if "{}[]();,.".contains(ch) {
                PdfColor::SUBTEXT0
            } else if "+-*/%=!<>:&|".contains(ch) {
                PdfColor::SKY
            } else {
                PdfColor::TEXT
            },
        });
        index += 1;
    }

    tokens
}

fn solidity_token_color(word: &str) -> PdfColor {
    match word {
        "contract" | "interface" | "library" | "function" | "modifier" | "event" | "error"
        | "struct" | "enum" | "mapping" | "returns" | "return" | "if" | "else" | "for"
        | "while" | "do" | "try" | "catch" | "emit" | "new" | "delete" | "is" | "using"
        | "pragma" | "import" | "from" | "as" | "override" | "virtual" | "abstract" => {
            PdfColor::MAUVE
        }
        "external" | "public" | "private" | "internal" | "payable" | "view" | "pure" | "memory"
        | "storage" | "calldata" | "indexed" | "immutable" | "constant" => PdfColor::PINK,
        "address" | "bool" | "string" | "bytes" | "bytes32" | "uint" | "uint8" | "uint16"
        | "uint32" | "uint64" | "uint128" | "uint256" | "int" | "int8" | "int16" | "int32"
        | "int64" | "int128" | "int256" => PdfColor::TEAL,
        "require" | "assert" | "revert" | "selfdestruct" | "delegatecall" | "call" | "transfer"
        | "send" => PdfColor::RED,
        "msg" | "tx" | "block" | "this" | "super" | "true" | "false" => PdfColor::BLUE,
        _ => PdfColor::TEXT,
    }
}

fn wrap_text_chars(text: &str, max_chars: usize) -> Vec<String> {
    let normalized = text
        .replace('\n', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.is_empty() {
        return vec![String::new()];
    }

    let mut lines = Vec::new();
    let mut current = String::new();
    for word in normalized.split_whitespace() {
        if word.len() > max_chars {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            let mut chunk = String::new();
            for ch in word.chars() {
                chunk.push(ch);
                if chunk.len() >= max_chars {
                    lines.push(std::mem::take(&mut chunk));
                }
            }
            if !chunk.is_empty() {
                current = chunk;
            }
            continue;
        }
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= max_chars {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn truncate_text(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out = text
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>();
    out.push_str("...");
    out
}

fn escape_pdf_text(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        match ch {
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            '\\' => out.push_str("\\\\"),
            '\t' | '\r' | '\n' => out.push(' '),
            ch if ch.is_ascii_graphic() || ch == ' ' => out.push(ch),
            _ => out.push('?'),
        }
    }
    out
}

fn build_native_pdf(page_streams: Vec<String>) -> Vec<u8> {
    let streams = if page_streams.is_empty() {
        vec!["BT /F1 12 Tf 54 760 Td (ChainVet Audit Report) Tj ET\n".to_string()]
    } else {
        page_streams
    };
    let page_count = streams.len();
    let page_ids = (0..page_count).map(|idx| 7 + idx * 2).collect::<Vec<_>>();
    let content_ids = (0..page_count).map(|idx| 8 + idx * 2).collect::<Vec<_>>();

    let mut objects = Vec::<Vec<u8>>::new();
    objects.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());
    objects.push(
        format!(
            "<< /Type /Pages /Kids [{}] /Count {} >>",
            page_ids
                .iter()
                .map(|id| format!("{id} 0 R"))
                .collect::<Vec<_>>()
                .join(" "),
            page_count
        )
        .into_bytes(),
    );
    objects.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec());
    objects.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>".to_vec());
    objects.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>".to_vec());

    let mut logo = format!(
        "<< /Type /XObject /Subtype /Image /Width 160 /Height 160 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length {} >>\nstream\n",
        CHAINVET_LOGO_JPEG.len()
    )
    .into_bytes();
    logo.extend_from_slice(CHAINVET_LOGO_JPEG);
    logo.extend_from_slice(b"\nendstream");
    objects.push(logo);

    for (idx, stream) in streams.iter().enumerate() {
        objects.push(format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {:.0} {:.0}] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> /XObject << /Im1 6 0 R >> >> /Contents {} 0 R >>",
            NativePdf::PAGE_WIDTH,
            NativePdf::PAGE_HEIGHT,
            content_ids[idx]
        )
        .into_bytes());
        objects.push(
            format!(
                "<< /Length {} >>\nstream\n{}endstream",
                stream.len(),
                stream
            )
            .into_bytes(),
        );
    }

    let mut bytes = Vec::<u8>::new();
    bytes.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets = Vec::with_capacity(objects.len() + 1);
    offsets.push(0usize);
    for (idx, object) in objects.iter().enumerate() {
        offsets.push(bytes.len());
        bytes.extend_from_slice(format!("{} 0 obj\n", idx + 1).as_bytes());
        bytes.extend_from_slice(object);
        bytes.extend_from_slice(b"\nendobj\n");
    }
    let xref_offset = bytes.len();
    bytes.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        bytes.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    bytes.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
            objects.len() + 1,
            xref_offset
        )
        .as_bytes(),
    );
    bytes
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

fn build_finding_counts(findings: &[ReportFinding]) -> Vec<ReportCount> {
    let mut map = BTreeMap::<String, usize>::new();
    for finding in findings {
        *map.entry(finding.kind.clone()).or_insert(0) += 1;
    }
    map.into_iter()
        .map(|(kind, count)| ReportCount { kind, count })
        .collect()
}

fn report_finding_candidate(
    finding: &ReportFinding,
    analysis_layer: &str,
    evidence_kind: Option<&str>,
) -> surfaced::FindingCandidate {
    surfaced::FindingCandidate {
        kind: finding.kind.clone(),
        canonical_kind: surfaced::canonicalize_kind(&finding.kind),
        category: finding.category.clone(),
        severity: finding.severity.clone(),
        confidence: finding.confidence.clone(),
        message: finding.message.clone(),
        file: Some(finding.file.clone()),
        start: Some(finding.span.start),
        end: Some(finding.span.end),
        function_id: None,
        function_name: finding.function.clone(),
        analysis_layer: analysis_layer.to_string(),
        evidence_kind: evidence_kind.map(str::to_string),
    }
}

fn report_finding_from_surfaced(finding: &surfaced::SurfacedFinding) -> ReportFinding {
    ReportFinding {
        category: finding.category.clone(),
        kind: finding.kind.clone(),
        severity: finding.severity.clone(),
        confidence: finding.confidence.clone(),
        message: finding.message.clone(),
        file: finding
            .file
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string()),
        span: SpanRange {
            start: finding.start.unwrap_or(0),
            end: finding.end.unwrap_or(0),
        },
        function: finding.function_name.clone(),
    }
}

fn build_report_findings(
    output: &FrontendOutput,
    findings: &[Finding],
    target_filter: &TargetFilter,
) -> Vec<ReportFinding> {
    let mut out = Vec::new();
    for finding in findings {
        let file = resolve_file(output, finding.span.file);
        if !target_filter.matches(&file) {
            continue;
        }
        out.push(ReportFinding {
            category: finding.kind.category().as_str().to_string(),
            kind: normalized_kind(finding).to_string(),
            severity: severity_to_str(finding.severity).to_string(),
            confidence: Some(static_confidence_for_severity(finding.severity).to_string()),
            message: finding.message.clone(),
            file,
            span: SpanRange {
                start: finding.span.start,
                end: finding.span.end,
            },
            function: finding
                .function
                .and_then(|id| output.ast.functions.get(id as usize))
                .and_then(|func| func.name.clone())
                .or_else(|| finding.function.map(|id| format!("<function {id}>"))),
        });
    }
    out
}

fn build_static_meta_findings(
    output: &FrontendOutput,
    findings: &[Finding],
    target_filter: &TargetFilter,
) -> Vec<ReportFinding> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();

    for finding in meta::analyze(output) {
        if !matches!(finding.finding_type.as_str(), "incorrect-interface") {
            continue;
        }
        let Some(location) = finding.location.as_ref() else {
            continue;
        };
        let Some(file) = location.file.as_deref() else {
            continue;
        };
        if !target_filter.matches(file) {
            continue;
        }
        let key = (
            finding.finding_type.clone(),
            file.to_string(),
            location.start.unwrap_or(0),
            location.end.unwrap_or(0),
            location.function_name.clone().unwrap_or_default(),
        );
        if !seen.insert(key) {
            continue;
        }
        out.push(ReportFinding {
            category: meta_category(&finding.finding_type).to_string(),
            kind: finding.finding_type.clone(),
            severity: finding.severity.clone(),
            confidence: artifact_confidence_or_severity(&finding.metadata, &finding.severity),
            message: finding.message,
            file: file.to_string(),
            span: SpanRange {
                start: location.start.unwrap_or(0),
                end: location.end.unwrap_or(0),
            },
            function: location.function_name.clone(),
        });
    }

    for finding in detect_static_access_control_backstops(output) {
        if !target_filter.matches(&finding.file) {
            continue;
        }
        let key = (
            finding.kind.clone(),
            finding.file.clone(),
            finding.span.start,
            finding.span.end,
            finding.function.clone().unwrap_or_default(),
        );
        if !seen.insert(key) {
            continue;
        }
        out.push(ReportFinding {
            category: finding.category,
            kind: finding.kind,
            severity: finding.severity,
            confidence: finding.confidence,
            message: finding.message,
            file: finding.file,
            span: finding.span,
            function: finding.function,
        });
    }

    for finding in detect_static_reentrancy_backstops(output, findings) {
        if !target_filter.matches(&finding.file) {
            continue;
        }
        let key = (
            finding.kind.clone(),
            finding.file.clone(),
            finding.span.start,
            finding.span.end,
            finding.function.clone().unwrap_or_default(),
        );
        if !seen.insert(key) {
            continue;
        }
        out.push(ReportFinding {
            category: finding.category,
            kind: finding.kind,
            severity: finding.severity,
            confidence: finding.confidence,
            message: finding.message,
            file: finding.file,
            span: finding.span,
            function: finding.function,
        });
    }

    out
}

fn normalized_kind(finding: &Finding) -> &'static str {
    match finding.kind {
        detectors::FindingKind::ForceEtherBalanceCheck => "locked-ether",
        _ => finding.kind.as_str(),
    }
}

fn meta_category(kind: &str) -> &'static str {
    match kind {
        "access-control" => "Access Control",
        "incorrect-interface" => "Miscellaneous",
        _ => "Miscellaneous",
    }
}

fn resolve_file(output: &FrontendOutput, file_id: u32) -> String {
    output
        .ast
        .files
        .get(file_id as usize)
        .map(|file| file.path.clone())
        .unwrap_or_else(|| "<unknown>".to_string())
}

fn severity_to_str(severity: Severity) -> &'static str {
    severity.as_str()
}

fn static_confidence_for_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

fn confidence_from_severity_str(severity: &str) -> Option<String> {
    match severity.trim().to_ascii_lowercase().as_str() {
        "high" => Some("high".to_string()),
        "medium" => Some("medium".to_string()),
        "low" => Some("low".to_string()),
        _ => None,
    }
}

fn artifact_confidence_or_severity(
    metadata: &std::collections::BTreeMap<String, String>,
    severity: &str,
) -> Option<String> {
    metadata
        .get("confidence")
        .cloned()
        .or_else(|| confidence_from_severity_str(severity))
}

#[derive(Debug, Clone)]
struct TargetFilter {
    requested_file: Option<PathBuf>,
}

impl TargetFilter {
    fn new(requested_path: &str) -> Self {
        let path = Path::new(requested_path);
        let requested_file = fs::metadata(path)
            .ok()
            .filter(|meta| meta.is_file())
            .map(|_| canonical_or_original(path));
        Self { requested_file }
    }

    fn matches(&self, file: &str) -> bool {
        let Some(requested_file) = self.requested_file.as_ref() else {
            return true;
        };
        canonical_or_original(Path::new(file)) == *requested_file
    }
}

fn canonical_or_original(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn detect_static_access_control_backstops(output: &FrontendOutput) -> Vec<SyntheticFinding> {
    let ast = &output.ast;
    let mut out = Vec::new();

    for function in &ast.functions {
        if !is_public_authority_setter_candidate(output, function) {
            continue;
        }
        let Some(location_file) = ast.files.get(function.span.file as usize) else {
            continue;
        };
        let function_name = function
            .name
            .clone()
            .unwrap_or_else(|| format!("<function {}>", function.id));
        out.push(SyntheticFinding {
            category: "Access Control".to_string(),
            kind: "access-control".to_string(),
            severity: "medium".to_string(),
            confidence: Some("medium".to_string()),
            message: format!(
                "public authority-setting function '{}' can reassign ownership-like state without a sender authorization check",
                function_name
            ),
            file: location_file.path.clone(),
            span: SpanRange {
                start: function.span.start,
                end: function.span.end,
            },
            function: function.name.clone(),
        });
    }

    out
}

fn detect_static_reentrancy_backstops(
    output: &FrontendOutput,
    findings: &[Finding],
) -> Vec<SyntheticFinding> {
    let ast = &output.ast;
    let mut out = Vec::new();
    let functions_with_reentrancy = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind,
                detectors::FindingKind::ReentrancyNegativeEvents
                    | detectors::FindingKind::ReentrancyTransfer
                    | detectors::FindingKind::ReentrancySameEffect
                    | detectors::FindingKind::ReentrancyEthTransfer
                    | detectors::FindingKind::ReentrancyNoEthTransfer
            )
        })
        .filter_map(|finding| finding.function)
        .collect::<BTreeSet<_>>();

    for function in &ast.functions {
        if !crate::frontend::is_mutating_entrypoint(function, &output.compiler) {
            continue;
        }
        if functions_with_reentrancy.contains(&function.id) {
            continue;
        }
        let Some(source_lower) = function_source_lower(ast, function) else {
            continue;
        };
        let call_idx = [
            source_lower.find(".call.value("),
            source_lower.find(".call{value"),
            source_lower.find(".transfer("),
            source_lower.find(".transfer ("),
            source_lower.find(".send("),
            source_lower.find(".send ("),
        ]
        .into_iter()
        .flatten()
        .min();
        let Some(call_idx) = call_idx else {
            continue;
        };
        let tail = &source_lower[call_idx..];
        if !(tail.contains("delete ")
            || tail.contains("-=")
            || tail.contains("=0")
            || tail.contains(" = 0")
            || tail.contains("=false")
            || tail.contains("= false"))
        {
            continue;
        }
        let Some(location_file) = ast.files.get(function.span.file as usize) else {
            continue;
        };
        let function_name = function
            .name
            .clone()
            .unwrap_or_else(|| format!("<function {}>", function.id));
        out.push(SyntheticFinding {
            category: "Reentrancy".to_string(),
            kind: "reentrancy".to_string(),
            severity: "high".to_string(),
            confidence: Some("high".to_string()),
            message: format!(
                "reentrancy in '{}' : ETH-sending external call is followed by destructive state updates inside the same payout flow",
                function_name
            ),
            file: location_file.path.clone(),
            span: SpanRange {
                start: function.span.start,
                end: function.span.end,
            },
            function: function.name.clone(),
        });
    }

    out
}

fn function_source_lower(ast: &NormalizedAst, function: &Function) -> Option<String> {
    let file = ast.files.get(function.span.file as usize)?;
    file.source
        .get(function.span.start as usize..function.span.end as usize)
        .filter(|source| !source.is_empty())
        .unwrap_or(file.source.as_str())
        .to_ascii_lowercase()
        .into()
}

fn is_public_authority_setter_candidate(output: &FrontendOutput, function: &Function) -> bool {
    if function.kind != FunctionKind::Function {
        return false;
    }
    if !crate::frontend::is_mutating_entrypoint(function, &output.compiler) {
        return false;
    }
    if crate::frontend::is_legacy_named_constructor(function, &output.ast) {
        return false;
    }
    if crate::frontend::has_authority_modifier_hint(function, &output.ast) {
        return false;
    }
    if function
        .params
        .iter()
        .all(|param| !address_or_authority_param_name(param))
    {
        return false;
    }

    let Some(body) = function.body else {
        return false;
    };
    if stmt_contains_msg_sender(&output.ast, body) {
        return false;
    }
    if !stmt_assigns_authority_from_param(&output.ast, body, &function.params) {
        return false;
    }

    let function_name = function.name.as_deref().unwrap_or("").to_ascii_lowercase();
    function_name.contains("owner")
        || function_name.contains("admin")
        || function_name.contains("authority")
        || function_name.contains("operator")
        || function_name.contains("governance")
}

fn address_or_authority_param_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "addr",
        "address",
        "owner",
        "admin",
        "operator",
        "authority",
        "governance",
        "recipient",
        "target",
    ]
    .iter()
    .any(|hint| lower.contains(hint))
}

fn authority_like_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "owner",
        "admin",
        "authority",
        "operator",
        "governance",
        "controller",
    ]
    .iter()
    .any(|hint| lower.contains(hint))
}

fn stmt_contains_msg_sender(ast: &NormalizedAst, stmt_id: u32) -> bool {
    let mut found = false;
    walk_stmt_exprs(ast, stmt_id, &mut |expr_id| {
        if !found && expr_is_msg_sender(ast, expr_id) {
            found = true;
        }
    });
    found
}

fn stmt_assigns_authority_from_param(ast: &NormalizedAst, stmt_id: u32, params: &[String]) -> bool {
    let mut found = false;
    walk_stmt_exprs(ast, stmt_id, &mut |expr_id| {
        if found {
            return;
        }
        let Some(expr) = ast.expressions.get(expr_id as usize) else {
            return;
        };
        if let ExprKind::Assign { lhs, rhs, .. } = &expr.kind
            && expr_is_authority_target(ast, *lhs)
            && expr_references_any_param(ast, *rhs, params)
        {
            found = true;
        }
    });
    found
}

fn walk_stmt_exprs(ast: &NormalizedAst, stmt_id: u32, cb: &mut impl FnMut(u32)) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else {
        return;
    };
    match &stmt.kind {
        crate::norm::StmtKind::Block(stmts) => {
            for child in stmts {
                walk_stmt_exprs(ast, *child, cb);
            }
        }
        crate::norm::StmtKind::Expr(expr) | crate::norm::StmtKind::Emit(expr) => {
            walk_expr_tree(ast, *expr, cb);
        }
        crate::norm::StmtKind::Return(expr) | crate::norm::StmtKind::Revert(expr) => {
            if let Some(expr) = expr {
                walk_expr_tree(ast, *expr, cb);
            }
        }
        crate::norm::StmtKind::VarDecl { init, .. } => {
            if let Some(expr) = init {
                walk_expr_tree(ast, *expr, cb);
            }
        }
        crate::norm::StmtKind::If {
            cond,
            then_id,
            else_id,
        } => {
            walk_expr_tree(ast, *cond, cb);
            walk_stmt_exprs(ast, *then_id, cb);
            if let Some(else_id) = else_id {
                walk_stmt_exprs(ast, *else_id, cb);
            }
        }
        crate::norm::StmtKind::While { cond, body } => {
            walk_expr_tree(ast, *cond, cb);
            walk_stmt_exprs(ast, *body, cb);
        }
        crate::norm::StmtKind::DoWhile { body, cond } => {
            walk_stmt_exprs(ast, *body, cb);
            walk_expr_tree(ast, *cond, cb);
        }
        crate::norm::StmtKind::For {
            init,
            cond,
            step,
            body,
        } => {
            if let Some(init) = init {
                walk_stmt_exprs(ast, *init, cb);
            }
            if let Some(cond) = cond {
                walk_expr_tree(ast, *cond, cb);
            }
            if let Some(step) = step {
                walk_expr_tree(ast, *step, cb);
            }
            walk_stmt_exprs(ast, *body, cb);
        }
        crate::norm::StmtKind::Try { call, clauses } => {
            walk_expr_tree(ast, *call, cb);
            for clause in clauses {
                walk_stmt_exprs(ast, clause.body, cb);
            }
        }
        _ => {}
    }
}

fn walk_expr_tree(ast: &NormalizedAst, expr_id: u32, cb: &mut impl FnMut(u32)) {
    cb(expr_id);
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return;
    };
    match &expr.kind {
        ExprKind::Unary { expr, .. } => walk_expr_tree(ast, *expr, cb),
        ExprKind::Binary { lhs, rhs, .. } => {
            walk_expr_tree(ast, *lhs, cb);
            walk_expr_tree(ast, *rhs, cb);
        }
        ExprKind::Assign { lhs, rhs, .. } => {
            walk_expr_tree(ast, *lhs, cb);
            walk_expr_tree(ast, *rhs, cb);
        }
        ExprKind::Call { callee, args } => {
            walk_expr_tree(ast, *callee, cb);
            for arg in args {
                walk_expr_tree(ast, *arg, cb);
            }
        }
        ExprKind::Member { base, .. } => walk_expr_tree(ast, *base, cb),
        ExprKind::Index { base, index } => {
            walk_expr_tree(ast, *base, cb);
            if let Some(index) = index {
                walk_expr_tree(ast, *index, cb);
            }
        }
        ExprKind::Tuple(items) => {
            for item in items {
                walk_expr_tree(ast, *item, cb);
            }
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            walk_expr_tree(ast, *cond, cb);
            walk_expr_tree(ast, *then_expr, cb);
            walk_expr_tree(ast, *else_expr, cb);
        }
        _ => {}
    }
}

fn expr_is_msg_sender(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };
    match &expr.kind {
        ExprKind::Member { base, field } if field == "sender" => ast
            .expressions
            .get(*base as usize)
            .and_then(|base_expr| match &base_expr.kind {
                ExprKind::Ident(name) if name == "msg" => Some(()),
                _ => None,
            })
            .is_some(),
        _ => false,
    }
}

fn expr_is_authority_target(ast: &NormalizedAst, expr_id: u32) -> bool {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return false;
    };
    match &expr.kind {
        ExprKind::Ident(name) => authority_like_name(name),
        ExprKind::Member { base, field } => {
            authority_like_name(field) || expr_is_authority_target(ast, *base)
        }
        ExprKind::Index { base, .. } => expr_is_authority_target(ast, *base),
        _ => false,
    }
}

fn expr_references_any_param(ast: &NormalizedAst, expr_id: u32, params: &[String]) -> bool {
    let param_set = params
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let mut found = false;
    walk_expr_tree(ast, expr_id, &mut |inner_id| {
        if found {
            return;
        }
        let Some(expr) = ast.expressions.get(inner_id as usize) else {
            return;
        };
        if let ExprKind::Ident(name) = &expr.kind
            && param_set.contains(&name.to_ascii_lowercase())
        {
            found = true;
        }
    });
    found
}

fn build_summary_report(summaries: &[analysis::summary::FunctionSummary]) -> SummaryReport {
    let mut storage_writes = 0;
    let mut external_calls = 0;
    let mut low_level_calls = 0;
    let mut unresolved_calls = 0;
    let mut functions_with_storage_writes = 0;

    for summary in summaries {
        storage_writes += summary.storage_writes;
        external_calls += summary.external_calls;
        low_level_calls += summary.low_level_calls;
        unresolved_calls += summary.unresolved_calls;
        if summary.storage_writes > 0 {
            functions_with_storage_writes += 1;
        }
    }

    SummaryReport {
        functions: summaries.len(),
        functions_with_storage_writes,
        storage_writes,
        external_calls,
        low_level_calls,
        unresolved_calls,
    }
}

fn build_ssa_report(ssa_functions: &[ssa::SsaFunction]) -> SsaReport {
    let mut defs = 0;
    let mut uses = 0;
    let mut phis = 0;
    for func in ssa_functions {
        defs += func.defs.len();
        uses += func.uses.len();
        for block in &func.blocks {
            phis += block.phis.len();
        }
    }
    SsaReport {
        functions: ssa_functions.len(),
        defs,
        uses,
        phis,
    }
}

fn build_top_callers(
    ast: &crate::norm::NormalizedAst,
    resolved: &analysis::ResolvedCallGraph,
    limit: usize,
) -> Vec<(String, usize)> {
    let mut totals = Vec::new();
    for (func_id, edges) in &resolved.outgoing {
        totals.push((*func_id, edges.len()));
    }
    totals.sort_by(|a, b| b.1.cmp(&a.1));

    let mut results = Vec::new();
    for (func_id, count) in totals.into_iter().take(limit) {
        let name = ast
            .functions
            .get(func_id as usize)
            .and_then(|func| func.name.clone())
            .unwrap_or_else(|| format!("<function {}>", func_id));
        results.push((name, count));
    }
    results
}
