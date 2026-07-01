//! CLI rendering of a typed [`ScanResult`]. The only place the binary turns
//! analysis results into text/JSON — engines and the orchestrator stay I/O-free.
//!
//! `pretty` is a colored, tabular report for humans (color auto-disables off a
//! TTY, with `--no-color`, or under `NO_COLOR`); `json` is the stable
//! machine-readable payload the benchmark harness and other tools consume.

use std::collections::HashMap;
use std::io::IsTerminal;

use chainvet_core::util::error::{Error, Result};
use chainvet_orchestrator::{ScanFinding, ScanMode, ScanResult};
use comfy_table::{Cell, Color, ContentArrangement, Table};
use owo_colors::OwoColorize;

use crate::{Format, ScanArgs, Severity};

pub fn render(result: &ScanResult, args: &ScanArgs) -> Result<()> {
    match args.format {
        Format::Json => render_json(result),
        Format::Pretty => render_pretty(result, args),
    }
}

/// Stable machine-readable output — unchanged, never filtered or colored.
fn render_json(result: &ScanResult) -> Result<()> {
    let payload = match &result.hybrid {
        Some(hybrid) => serde_json::to_string_pretty(hybrid),
        None => serde_json::to_string_pretty(&result.findings),
    }
    .map_err(|e| Error::msg(format!("failed to serialize report: {e}")))?;
    println!("{payload}");
    Ok(())
}

fn render_pretty(result: &ScanResult, args: &ScanArgs) -> Result<()> {
    let no_color_env = std::env::var_os("NO_COLOR").is_some();
    let banner_color = !args.no_color && !no_color_env && std::io::stderr().is_terminal();
    let report_color =
        !args.no_color && !no_color_env && args.output.is_none() && std::io::stdout().is_terminal();

    // Banner → stderr, so stdout/`--output` stay a clean report.
    if !args.quiet && std::io::stderr().is_terminal() {
        print_banner(&args.path, result.mode, banner_color);
    }

    // Filter is a display concern (JSON stays complete for tooling parity).
    let min = args.min_severity.map(sev_rank_enum).unwrap_or(0);
    let mut findings: Vec<&ScanFinding> = result
        .findings
        .iter()
        .filter(|f| sev_rank(f.severity.as_deref()) >= min)
        .collect();
    findings.sort_by(|a, b| {
        sev_rank(b.severity.as_deref())
            .cmp(&sev_rank(a.severity.as_deref()))
            .then_with(|| a.kind.cmp(&b.kind))
    });

    let mut out = String::new();

    if let Some(h) = &result.hybrid {
        out.push_str(&format!(
            "static targets {}/{}  ·  symbolic findings {} ({} states)  ·  fuzz coverage {:.1}% ({} corpus)\n\n",
            h.summary.static_targets_selected,
            h.summary.static_targets_total,
            h.summary.se_findings_total,
            h.symbolic_states_explored,
            h.fuzz_coverage_pct,
            h.summary.fuzz_corpus_size,
        ));
    }

    if findings.is_empty() {
        out.push_str(&paint("✓ No findings", Paint::Green, report_color));
        out.push('\n');
    } else {
        let sources = load_sources(&findings);
        out.push_str(&format!("Findings ({})\n", findings.len()));
        out.push_str(&build_table(&findings, &sources, report_color).to_string());
        out.push('\n');
        out.push_str(&summary_line(&findings, report_color));
        out.push('\n');
    }

    match &args.output {
        Some(file) => {
            std::fs::write(file, &out).map_err(|e| Error::msg(format!("write {file}: {e}")))?
        }
        None => print!("{out}"),
    }
    Ok(())
}

fn print_banner(path: &str, mode: ScanMode, color: bool) {
    let title = format!(
        "chainvet {} · hybrid Solidity security analyzer",
        env!("CARGO_PKG_VERSION")
    );
    let rule = "─".repeat(title.chars().count());
    if color {
        eprintln!("{}", title.bold());
        eprintln!("{}", rule.dimmed());
    } else {
        eprintln!("{title}");
        eprintln!("{rule}");
    }
    eprintln!("target: {path}    mode: {}\n", mode_label(mode));
}

fn build_table(findings: &[&ScanFinding], sources: &HashMap<String, String>, color: bool) -> Table {
    let mut table = Table::new();
    table
        .load_preset(comfy_table::presets::UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_width(120)
        .set_header(vec!["Severity", "Kind", "Location", "Tier", "Message"]);

    for f in findings {
        let sev = f.severity.as_deref().unwrap_or("-");
        let sev_cell = maybe_color(Cell::new(sev.to_uppercase()), sev_color(sev), color);
        let tier_cell = maybe_color(Cell::new(&f.tier), tier_color(&f.tier), color);
        table.add_row(vec![
            sev_cell,
            Cell::new(&f.kind),
            Cell::new(location(f, sources)),
            tier_cell,
            Cell::new(truncate(&f.message, 64)),
        ]);
    }
    table
}

fn summary_line(findings: &[&ScanFinding], color: bool) -> String {
    let count = |s: &str| {
        findings
            .iter()
            .filter(|f| f.severity.as_deref() == Some(s))
            .count()
    };
    let (high, medium, low) = (count("high"), count("medium"), count("low"));
    let confirmed = findings.iter().filter(|f| f.tier == "confirmed").count();
    let candidate = findings.len() - confirmed;

    if color {
        format!(
            "  {} · {} · {}      {} · {}",
            format!("{high} high").red().bold(),
            format!("{medium} medium").yellow(),
            format!("{low} low").cyan(),
            format!("{confirmed} confirmed").green(),
            format!("{candidate} candidate").dimmed(),
        )
    } else {
        format!(
            "  {high} high · {medium} medium · {low} low      {confirmed} confirmed · {candidate} candidate"
        )
    }
}

// ---- helpers ----

enum Paint {
    Green,
}

fn paint(text: &str, p: Paint, color: bool) -> String {
    if !color {
        return text.to_string();
    }
    match p {
        Paint::Green => text.green().to_string(),
    }
}

fn maybe_color(cell: Cell, c: Color, color: bool) -> Cell {
    if color { cell.fg(c) } else { cell }
}

fn sev_color(sev: &str) -> Color {
    match sev {
        "high" => Color::Red,
        "medium" => Color::Yellow,
        "low" => Color::Cyan,
        _ => Color::Grey,
    }
}

fn tier_color(tier: &str) -> Color {
    match tier {
        "confirmed" => Color::Green,
        _ => Color::DarkGrey,
    }
}

fn sev_rank(sev: Option<&str>) -> u8 {
    match sev {
        Some("high") => 3,
        Some("medium") => 2,
        _ => 1, // low + unknown
    }
}

fn sev_rank_enum(sev: Severity) -> u8 {
    match sev {
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
    }
}

/// Read each referenced source once so byte offsets can be resolved to lines.
fn load_sources(findings: &[&ScanFinding]) -> HashMap<String, String> {
    let mut sources = HashMap::new();
    for f in findings {
        if let Some(path) = &f.file {
            sources
                .entry(path.clone())
                .or_insert_with(|| std::fs::read_to_string(path).unwrap_or_default());
        }
    }
    sources
}

fn location(f: &ScanFinding, sources: &HashMap<String, String>) -> String {
    let name = f.file.as_deref().map(basename).unwrap_or("-");
    match (&f.file, f.start) {
        (Some(path), Some(offset)) => {
            let line = sources.get(path).map(|c| line_of(c, offset)).unwrap_or(0);
            format!("{name}:{line}")
        }
        _ => name.to_string(),
    }
}

/// 1-based line number of a byte offset.
fn line_of(content: &str, offset: u32) -> u32 {
    let end = (offset as usize).min(content.len());
    content[..end].bytes().filter(|&b| b == b'\n').count() as u32 + 1
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max - 1).collect();
        t.push('…');
        t
    }
}

fn mode_label(mode: ScanMode) -> &'static str {
    match mode {
        ScanMode::Static => "static",
        ScanMode::Symbolic => "symbolic",
        ScanMode::Fuzzing => "fuzzing",
        ScanMode::Hybrid => "hybrid",
    }
}
