use crate::analysis::detectors::{self, Finding, FindingKind, Severity};
use crate::analysis::{self, ResolvedTarget};
use crate::frontend::{FrontendMode, FrontendOutput};
use crate::util::error::Result;
use crate::{cfg, ir, ssa};
use serde::Serialize;

pub enum OutputFormat {
    Text,
    Json,
}

pub fn print_report(output: &FrontendOutput, format: OutputFormat) -> Result<()> {
    let report = build_report(output);
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
    finding_counts: Vec<ReportCount>,
    findings: Vec<ReportFinding>,
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

#[derive(Debug, Serialize)]
struct ReportFinding {
    kind: String,
    severity: String,
    message: String,
    file: String,
    span: SpanRange,
    function: Option<String>,
}

#[derive(Debug, Serialize)]
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

fn build_report(output: &FrontendOutput) -> Report {
    let mode = match output.mode {
        FrontendMode::Full => "full",
        FrontendMode::Partial => "partial",
    }
    .to_string();

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
    let finding_counts = build_finding_counts(&findings);
    let report_findings = build_report_findings(output, &findings);
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
        finding_counts,
        findings: report_findings,
        top_callers,
    }
}

fn print_text(report: &Report) -> Result<()> {
    println!(
        "mode: {}, files: {}, functions: {}, cfgs: {}, calls: {}, resolved: {}, ambiguous: {}, external: {}, builtin: {}, unknown: {}, findings: {}",
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
        report.findings.len()
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

fn build_finding_counts(findings: &[Finding]) -> Vec<ReportCount> {
    let mut counts = Vec::new();
    for kind in [
        FindingKind::TxOrigin,
        FindingKind::Delegatecall,
        FindingKind::UncheckedCall,
        FindingKind::Selfdestruct,
        FindingKind::TimestampDependency,
        FindingKind::Shadowing,
        FindingKind::Reentrancy,
        FindingKind::TaintedCall,
    ] {
        let mut count = 0;
        for finding in findings {
            if finding.kind == kind {
                count += 1;
            }
        }
        if count > 0 {
            counts.push(ReportCount {
                kind: kind.as_str().to_string(),
                count,
            });
        }
    }
    counts
}

fn build_report_findings(output: &FrontendOutput, findings: &[Finding]) -> Vec<ReportFinding> {
    let mut out = Vec::new();
    for finding in findings {
        out.push(ReportFinding {
            kind: finding.kind.as_str().to_string(),
            severity: severity_to_str(finding.severity).to_string(),
            message: finding.message.clone(),
            file: resolve_file(output, finding.span.file),
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
