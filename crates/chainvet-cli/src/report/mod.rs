use chainvet_sa::analysis::detectors::{self, Finding, Severity};
use chainvet_sa::analysis::{self, ResolvedTarget};
use chainvet_frontend::frontend::{FrontendMode, FrontendOutput};
use crate::meta;
use chainvet_core::norm::{ExprKind, Function, FunctionKind, NormalizedAst};
use crate::surfaced;
use chainvet_core::util::error::Result;
use chainvet_core::{cfg, ir, ssa};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub enum OutputFormat {
    Text,
    Json,
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
    }
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
        chainvet_core::util::error::Error::msg(format!("failed to encode JSON report: {err}"))
    })?;
    println!("{payload}");
    Ok(())
}

fn build_finding_counts(findings: &[ReportFinding]) -> Vec<ReportCount> {
    let mut map = std::collections::BTreeMap::<String, usize>::new();
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
        if !chainvet_frontend::frontend::is_mutating_entrypoint(function, &output.compiler) {
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
    if !chainvet_frontend::frontend::is_mutating_entrypoint(function, &output.compiler) {
        return false;
    }
    if chainvet_frontend::frontend::is_legacy_named_constructor(function, &output.ast) {
        return false;
    }
    if chainvet_frontend::frontend::has_authority_modifier_hint(function, &output.ast) {
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
        chainvet_core::norm::StmtKind::Block(stmts) => {
            for child in stmts {
                walk_stmt_exprs(ast, *child, cb);
            }
        }
        chainvet_core::norm::StmtKind::Expr(expr) | chainvet_core::norm::StmtKind::Emit(expr) => {
            walk_expr_tree(ast, *expr, cb);
        }
        chainvet_core::norm::StmtKind::Return(expr) | chainvet_core::norm::StmtKind::Revert(expr) => {
            if let Some(expr) = expr {
                walk_expr_tree(ast, *expr, cb);
            }
        }
        chainvet_core::norm::StmtKind::VarDecl { init, .. } => {
            if let Some(expr) = init {
                walk_expr_tree(ast, *expr, cb);
            }
        }
        chainvet_core::norm::StmtKind::If {
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
        chainvet_core::norm::StmtKind::While { cond, body } => {
            walk_expr_tree(ast, *cond, cb);
            walk_stmt_exprs(ast, *body, cb);
        }
        chainvet_core::norm::StmtKind::DoWhile { body, cond } => {
            walk_stmt_exprs(ast, *body, cb);
            walk_expr_tree(ast, *cond, cb);
        }
        chainvet_core::norm::StmtKind::For {
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
        chainvet_core::norm::StmtKind::Try { call, clauses } => {
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
    ast: &chainvet_core::norm::NormalizedAst,
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
