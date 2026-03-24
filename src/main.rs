mod analysis;
mod cfg;
mod core;

mod frontend;
mod fuzzing;
mod ir;
mod meta;
mod norm;
mod report;
mod ssa;
mod surfaced;
mod symbolic;
mod util;
mod web;

use crate::util::error::Error;
use crate::util::error::Result;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnalysisMode {
    Static,
    Symbolic,
    Fuzzing,
    Hybrid,
}

impl AnalysisMode {
    fn from_flag(flag: &str) -> Option<Self> {
        match flag {
            "--static" => Some(Self::Static),
            "--symbolic" => Some(Self::Symbolic),
            "--fuzzing" => Some(Self::Fuzzing),
            "--hybrid" => Some(Self::Hybrid),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize)]
struct HybridCliReport {
    #[serde(flatten)]
    report: core::artifacts::HybridReport,
    finding_count_raw: usize,
    suppressed_findings: usize,
    findings: Vec<surfaced::SurfacedFinding>,
    findings_raw: Vec<core::artifacts::Finding>,
    meta_finding_count_raw: usize,
    suppressed_meta_findings: usize,
    meta_findings: Vec<surfaced::SurfacedFinding>,
    meta_findings_raw: Vec<core::artifacts::Finding>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn print_usage() {
    eprintln!(
        "usage: static-analyzer --web | [--static|--symbolic|--fuzzing|--hybrid] <path> [--json|--text|--format <json|text>] [--dump-ir <text|json|tuple>]"
    );
}

fn run() -> Result<()> {
    let mut input = None;
    let mut format = report::OutputFormat::Text;
    let mut dump_ir = None;
    let mut mode = AnalysisMode::Static;
    let mut mode_flag = None::<&'static str>;
    let mut web_mode = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if let Some(next_mode) = AnalysisMode::from_flag(&arg) {
            if let Some(existing_flag) = mode_flag {
                if mode != next_mode {
                    return Err(Error::msg(format!(
                        "multiple analysis modes provided: {existing_flag} and {arg}"
                    )));
                }
            } else {
                mode = next_mode;
                mode_flag = Some(match next_mode {
                    AnalysisMode::Static => "--static",
                    AnalysisMode::Symbolic => "--symbolic",
                    AnalysisMode::Fuzzing => "--fuzzing",
                    AnalysisMode::Hybrid => "--hybrid",
                });
            }
            continue;
        }

        match arg.as_str() {
            "--web" => web_mode = true,
            "--json" => format = report::OutputFormat::Json,
            "--text" => format = report::OutputFormat::Text,
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            "--format" => {
                let Some(value) = args.next() else {
                    return Err(Error::msg("missing value for --format"));
                };
                match value.as_str() {
                    "json" => format = report::OutputFormat::Json,
                    "text" => format = report::OutputFormat::Text,
                    _ => return Err(Error::msg(format!("unknown format: {value}"))),
                }
            }
            "--dump-ir" => {
                let Some(value) = args.next() else {
                    return Err(Error::msg("missing value for --dump-ir"));
                };
                let ir_format = match value.as_str() {
                    "json" => ir::DumpFormat::Json,
                    "text" => ir::DumpFormat::Text,
                    "tuple" => ir::DumpFormat::Tuple,
                    _ => return Err(Error::msg(format!("unknown IR format: {value}"))),
                };
                dump_ir = Some(ir_format);
            }
            "--fuzz" => {
                if let Some(existing_flag) = mode_flag {
                    if mode != AnalysisMode::Fuzzing {
                        return Err(Error::msg(format!(
                            "multiple analysis modes provided: {existing_flag} and --fuzz"
                        )));
                    }
                } else {
                    mode = AnalysisMode::Fuzzing;
                    mode_flag = Some("--fuzz");
                }
            }
            _ => {
                if arg.starts_with('-') {
                    return Err(Error::msg(format!("unknown flag: {arg}")));
                }
                if input.is_none() {
                    input = Some(arg);
                } else {
                    return Err(Error::msg("multiple input paths provided"));
                }
            }
        }
    }

    if web_mode {
        if input.is_some() || mode_flag.is_some() || dump_ir.is_some() {
            return Err(Error::msg(
                "--web cannot be combined with an input path, analysis mode, or --dump-ir",
            ));
        }
        return web::serve(std::env::current_dir()?);
    }

    let Some(input) = input else {
        print_usage();
        return Ok(());
    };

    if dump_ir.is_some() && mode != AnalysisMode::Static {
        return Err(Error::msg("--dump-ir is only supported in --static mode"));
    }

    match mode {
        AnalysisMode::Static => {
            let output = frontend::load_project(&input)?;
            if let Some(format) = dump_ir {
                let ir_module = ir::lower_module(&output.ast);
                let payload = ir::dump_module(&ir_module, format);
                println!("{payload}");
                return Ok(());
            }
            report::print_report(&output, &input, format)?;
        }
        AnalysisMode::Symbolic => {
            let output = frontend::load_project(&input)?;
            symbolic::run(&output, format)?;
        }
        AnalysisMode::Fuzzing => {
            let output = frontend::load_project(&input)?;
            let config = fuzzing::types::FuzzConfig::default();
            fuzzing::run_fuzzer(&output, &config, format)?;
        }
        AnalysisMode::Hybrid => {
            let output = core::scheduler::run_p1(&input, core::budget::Budget::default())?;
            let runtime_findings_raw = output
                .findings
                .iter()
                .filter(|finding| finding.analysis_layer != "meta")
                .cloned()
                .collect::<Vec<_>>();
            let meta_findings_raw = output
                .findings
                .iter()
                .filter(|finding| finding.analysis_layer == "meta")
                .cloned()
                .collect::<Vec<_>>();
            let surfaced = surfaced::surface_findings(
                runtime_findings_raw
                    .iter()
                    .map(hybrid_finding_candidate)
                    .collect(),
                meta_findings_raw
                    .iter()
                    .map(hybrid_finding_candidate)
                    .collect(),
            );
            match format {
                report::OutputFormat::Text => {
                    println!(
                        "hybrid: run_id={}, run_dir={}, runtime_ms={}, epochs={}, findings_total={}, findings_unique={}, runtime_findings_total={} (raw={}, suppressed={}), meta_findings_total={} (raw={}, suppressed={}), se_assists={}, se_seeds_injected={}, se_new_edges_from_injected={}",
                        output.run_id,
                        output.run_dir,
                        output.report.runtime_ms,
                        output.report.total_epochs,
                        output.report.findings_total,
                        output.report.findings_unique,
                        surfaced.runtime_findings.len(),
                        runtime_findings_raw.len(),
                        surfaced.suppressed_runtime_findings,
                        surfaced.meta_findings.len(),
                        meta_findings_raw.len(),
                        surfaced.suppressed_meta_findings,
                        output.report.se_assists,
                        output.report.seeds_injected_by_se,
                        output.report.se_new_edges_from_injected
                    );
                    if surfaced.runtime_findings.is_empty() {
                        println!("runtime findings: none");
                    } else {
                        println!("runtime findings (surfaced):");
                        for (idx, finding) in surfaced.runtime_findings.iter().enumerate() {
                            println!(
                                "  {}. kind={} severity={} confidence={} evidence={}",
                                idx + 1,
                                finding.kind,
                                finding.severity,
                                finding.confidence.as_deref().unwrap_or("unknown"),
                                finding.evidence_kind.as_deref().unwrap_or("runtime")
                            );
                            println!("     message: {}", finding.message);
                            if let Some(file) = &finding.file {
                                println!(
                                    "     location: {}:{}-{}",
                                    file,
                                    finding.start.unwrap_or(0),
                                    finding.end.unwrap_or(0)
                                );
                            }
                        }
                    }
                    if !surfaced.meta_findings.is_empty() {
                        println!("meta findings (surfaced):");
                        for (idx, finding) in surfaced.meta_findings.iter().enumerate() {
                            println!(
                                "  {}. kind={} severity={} evidence={}",
                                idx + 1,
                                finding.kind,
                                finding.severity,
                                finding.evidence_kind.as_deref().unwrap_or("meta")
                            );
                            println!("     message: {}", finding.message);
                        }
                    }
                }
                report::OutputFormat::Json => {
                    let cli_report = HybridCliReport {
                        report: output.report,
                        finding_count_raw: runtime_findings_raw.len(),
                        suppressed_findings: surfaced.suppressed_runtime_findings,
                        findings: surfaced.runtime_findings,
                        findings_raw: runtime_findings_raw,
                        meta_finding_count_raw: meta_findings_raw.len(),
                        suppressed_meta_findings: surfaced.suppressed_meta_findings,
                        meta_findings: surfaced.meta_findings,
                        meta_findings_raw,
                    };
                    let payload = serde_json::to_string_pretty(&cli_report).map_err(|err| {
                        Error::msg(format!("failed to encode hybrid JSON report: {err}"))
                    })?;
                    println!("{payload}");
                }
            }
        }
    }

    Ok(())
}

fn hybrid_finding_candidate(finding: &core::artifacts::Finding) -> surfaced::FindingCandidate {
    surfaced::FindingCandidate {
        kind: finding.finding_type.clone(),
        canonical_kind: surfaced::canonicalize_kind(&finding.finding_type),
        category: finding
            .metadata
            .get("category")
            .cloned()
            .unwrap_or_else(|| {
                surfaced::default_category_for_kind(&finding.finding_type).to_string()
            }),
        severity: finding.severity.clone(),
        confidence: finding
            .metadata
            .get("confidence")
            .cloned()
            .or_else(|| confidence_from_severity(finding.severity.as_str())),
        message: finding.message.clone(),
        file: finding
            .location
            .as_ref()
            .and_then(|location| location.file.clone()),
        start: finding
            .location
            .as_ref()
            .and_then(|location| location.start),
        end: finding.location.as_ref().and_then(|location| location.end),
        function_id: finding
            .location
            .as_ref()
            .and_then(|location| location.function_id),
        function_name: finding
            .location
            .as_ref()
            .and_then(|location| location.function_name.clone()),
        analysis_layer: finding.analysis_layer.clone(),
        evidence_kind: Some(finding.evidence_kind.clone()),
    }
}

fn confidence_from_severity(severity: &str) -> Option<String> {
    match severity.trim().to_ascii_lowercase().as_str() {
        "high" => Some("high".to_string()),
        "medium" => Some("medium".to_string()),
        "low" => Some("low".to_string()),
        _ => None,
    }
}
