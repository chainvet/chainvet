//! PDF output by rendering the branded HTML report through an HTML→PDF engine.
//!
//! The report's brand look lives in the HTML/CSS (dark Catppuccin theme, severity
//! badges, cards). To get a PDF that matches it we render that same HTML with a
//! CSS-accurate engine — `weasyprint` (preferred) or `wkhtmltopdf` — rather than
//! a LaTeX toolchain, which never sees the CSS. So `-f pdf` == `-f html`, as a
//! PDF. For a fully dependency-free artifact, `-f html` + a browser's "Print to
//! PDF" produces the same thing.
//!
//! Engine: `CHAINVET_PDF_ENGINE` overrides; otherwise weasyprint then wkhtmltopdf,
//! whichever is on PATH.

use std::ffi::OsString;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use chainvet_core::util::error::{Error, Result};

use super::AuditReport;

/// Render `report` to a branded PDF at `output` via an HTML→PDF engine.
pub fn write_pdf(report: &AuditReport, output: &Path) -> Result<()> {
    let html = super::render_html(report);
    let (engine, args) = resolve_engine(output)?;

    let mut child = Command::new(&engine)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| Error::msg(format!("failed to launch `{engine}`: {err}")))?;

    child
        .stdin
        .take()
        .ok_or_else(|| Error::msg("failed to open the engine's stdin"))?
        .write_all(html.as_bytes())
        .map_err(|err| Error::msg(format!("failed to write HTML to `{engine}`: {err}")))?;

    let out = child
        .wait_with_output()
        .map_err(|err| Error::msg(format!("failed to run `{engine}`: {err}")))?;
    if !out.status.success() {
        return Err(Error::msg(format!(
            "`{engine}` failed to produce the PDF:\n{}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// The HTML→PDF engine to use and the argv to read HTML from stdin and write
/// `output`. Honors `CHAINVET_PDF_ENGINE`, else the first of weasyprint /
/// wkhtmltopdf found on PATH.
fn resolve_engine(output: &Path) -> Result<(String, Vec<OsString>)> {
    let explicit = std::env::var("CHAINVET_PDF_ENGINE")
        .ok()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty());

    let candidates: Vec<String> = match explicit {
        Some(engine) => vec![engine],
        None => vec!["weasyprint".to_string(), "wkhtmltopdf".to_string()],
    };

    for engine in &candidates {
        if !on_path(engine) {
            continue;
        }
        // Both read HTML from stdin (`-`) and take the output path as the last arg.
        let args: Vec<OsString> = match engine_kind(engine) {
            EngineKind::WeasyPrint => vec!["-".into(), output.into()],
            EngineKind::WkHtmlToPdf => vec!["-q".into(), "-".into(), output.into()],
        };
        return Ok((engine.clone(), args));
    }

    Err(Error::msg(format!(
        "no HTML->PDF engine found ({}). PDF output renders the HTML report with\n\
         weasyprint (recommended) or wkhtmltopdf. Install one, e.g. `weasyprint`,\n\
         or use `-f html` and \"Print to PDF\" from a browser.",
        candidates.join(" / ")
    )))
}

enum EngineKind {
    WeasyPrint,
    WkHtmlToPdf,
}

/// Argument style keyed off the engine's name (wkhtmltopdf-like vs weasyprint-like).
fn engine_kind(engine: &str) -> EngineKind {
    let name = Path::new(engine)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(engine);
    if name.contains("wkhtml") {
        EngineKind::WkHtmlToPdf
    } else {
        EngineKind::WeasyPrint
    }
}

/// Whether an executable of this name exists on PATH (or is an explicit path).
fn on_path(name: &str) -> bool {
    if name.contains('/') {
        return Path::new(name).is_file();
    }
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).is_file()))
        .unwrap_or(false)
}
