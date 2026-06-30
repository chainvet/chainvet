//! CLI rendering of a typed [`ScanResult`]. This is the only place the binary
//! turns analysis results into text/JSON — the engines and the orchestrator
//! stay I/O-free, so any other frontend can render however it likes.

use chainvet_core::OutputFormat;
use chainvet_core::util::error::{Error, Result};
use chainvet_orchestrator::{ScanMode, ScanResult};

pub fn render(result: &ScanResult, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => render_json(result),
        OutputFormat::Text => render_text(result),
    }
}

fn render_json(result: &ScanResult) -> Result<()> {
    // Hybrid mode emits its full telemetry payload (the stable schema the
    // benchmark harness consumes); other modes emit the unified findings array.
    let payload = match &result.hybrid {
        Some(hybrid) => serde_json::to_string_pretty(hybrid),
        None => serde_json::to_string_pretty(&result.findings),
    }
    .map_err(|e| Error::msg(format!("failed to serialize report: {e}")))?;
    println!("{payload}");
    Ok(())
}

fn render_text(result: &ScanResult) -> Result<()> {
    println!("=== ChainVet {} ===", mode_label(result.mode));

    if let Some(h) = &result.hybrid {
        println!(
            "static_targets: total={}, selected={}, skipped={}, threshold={}",
            h.summary.static_targets_total,
            h.summary.static_targets_selected,
            h.summary.static_targets_skipped,
            h.summary.static_threshold,
        );
        println!(
            "symbolic: functions={}, findings={}, states={}",
            h.summary.se_targeted_functions, h.summary.se_findings_total, h.symbolic_states_explored,
        );
        println!(
            "fuzzing: seeds={}, corpus={}, coverage={}/{} ({:.1}%)",
            h.summary.fuzz_seed_count,
            h.summary.fuzz_corpus_size,
            h.fuzz_covered_blocks,
            h.fuzz_total_blocks,
            h.fuzz_coverage_pct,
        );
    }

    let confirmed = result
        .findings
        .iter()
        .filter(|f| f.tier == "confirmed")
        .count();
    let candidate = result.findings.len() - confirmed;
    println!(
        "findings: {} total — {} confirmed (dynamic/SE evidence), {} candidate (static-only)",
        result.findings.len(),
        confirmed,
        candidate
    );
    for f in &result.findings {
        let loc = match (&f.file, f.start) {
            (Some(file), Some(start)) => format!("{file}:{start}"),
            (Some(file), None) => file.clone(),
            _ => "?".to_string(),
        };
        let sev = f.severity.as_deref().unwrap_or("-");
        println!(
            "  [{}|{}] {} ({}) {} — {}",
            f.tier, f.provenance, f.kind, sev, loc, f.message
        );
    }
    Ok(())
}

fn mode_label(mode: ScanMode) -> &'static str {
    match mode {
        ScanMode::Static => "Static Analysis",
        ScanMode::Symbolic => "Symbolic Execution",
        ScanMode::Fuzzing => "Fuzzing",
        ScanMode::Hybrid => "Hybrid Analysis",
    }
}
