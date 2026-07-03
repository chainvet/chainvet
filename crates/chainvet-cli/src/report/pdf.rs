//! PDF output via a branded `pandoc` passthrough.
//!
//! Rendering a real `.pdf` in-process (a bundled PDF engine + embedded fonts) is
//! rare among analyzers and heavy to maintain; the common pattern — and what
//! audit firms actually do — is to author Markdown and convert it with a LaTeX
//! toolchain. So `-f pdf` renders the report body as Markdown and pipes it
//! through `pandoc` with a shipped ChainVet LaTeX template (branded cover page,
//! purple headings, breakable inline code). Requires `pandoc` plus a PDF engine.
//! For a dependency-free artifact, `-f html` + "Print to PDF" also works.
//!
//! Engine selection: pandoc has no "use whatever is installed" mode — it hard
//! defaults to `pdflatex`. So we honor `CHAINVET_PDF_ENGINE` if set, otherwise
//! bootstrap `tectonic` (the self-contained engine we recommend, which pandoc
//! won't pick on its own), otherwise let pandoc use its default and surface any
//! error. `CHAINVET_PANDOC` overrides the pandoc binary.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use chainvet_core::util::error::{Error, Result};

use super::AuditReport;

/// The branded template and cover logo, embedded so the tool is self-contained;
/// both are written to a temp dir at run time because pandoc needs file paths.
const TEMPLATE_TEX: &str = include_str!("../../assets/report-template.tex");
const LOGO_PNG: &[u8] = include_bytes!("../../assets/chainvet-logo.png");
/// Filter that gives tables content-proportional widths so LaTeX wraps cells.
const TABLES_LUA: &str = include_str!("../../assets/report-tables.lua");

/// Render `report` to a PDF at `output` via a branded pandoc conversion.
pub fn write_pdf_via_pandoc(report: &AuditReport, output: &Path) -> Result<()> {
    let pandoc = std::env::var("CHAINVET_PANDOC").unwrap_or_else(|_| "pandoc".to_string());

    // Stage the template + logo where pandoc/LaTeX can read them by path.
    let workdir = TempDir::new()?;
    let template = workdir.path.join("report-template.tex");
    let logo = workdir.path.join("chainvet-logo.png");
    let tables_filter = workdir.path.join("report-tables.lua");
    std::fs::write(&template, TEMPLATE_TEX)
        .and_then(|_| std::fs::write(&logo, LOGO_PNG))
        .and_then(|_| std::fs::write(&tables_filter, TABLES_LUA))
        .map_err(|err| Error::msg(format!("failed to stage report assets: {err}")))?;

    // The template supplies the branded cover from these variables, inserted raw
    // into LaTeX — so they must be LaTeX-escaped here.
    let body = super::render_markdown_body(report);

    let mut cmd = Command::new(&pandoc);
    cmd.arg("--from=gfm")
        .arg("--template")
        .arg(&template)
        .arg("--lua-filter")
        .arg(&tables_filter)
        // Body sections are `##`; shift so they become top-level LaTeX sections.
        .arg("--shift-heading-level-by=-1")
        .arg("--variable=title:ChainVet Audit Report")
        .arg(format!(
            "--variable=project:{}",
            latex_escape(&report.project_name)
        ))
        .arg(format!(
            "--variable=target:{}",
            latex_escape(&report.target)
        ))
        .arg(format!(
            "--variable=mode:{}",
            latex_escape(&report.analysis_mode)
        ))
        .arg(format!("--variable=logo:{}", logo.display()))
        .arg("--output")
        .arg(output)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(engine) = pdf_engine() {
        cmd.arg(format!("--pdf-engine={engine}"));
    }

    let mut child = cmd.spawn().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            Error::msg(format!(
                "`{pandoc}` was not found — PDF output is a pandoc passthrough.\n\
                 Install pandoc plus a PDF engine (e.g. tectonic, xelatex, or weasyprint),\n\
                 or use `-f html` and \"Print to PDF\" from a browser."
            ))
        } else {
            Error::msg(format!("failed to launch `{pandoc}`: {err}"))
        }
    })?;

    child
        .stdin
        .take()
        .ok_or_else(|| Error::msg("failed to open pandoc stdin"))?
        .write_all(body.as_bytes())
        .map_err(|err| Error::msg(format!("failed to write to pandoc: {err}")))?;

    let out = child
        .wait_with_output()
        .map_err(|err| Error::msg(format!("failed to run pandoc: {err}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let hint = if stderr.contains("pdf-engine") || stderr.to_lowercase().contains("latex") {
            "\nHint: pandoc needs a PDF engine — install tectonic/xelatex, or set \
             CHAINVET_PDF_ENGINE=weasyprint."
        } else {
            ""
        };
        return Err(Error::msg(format!(
            "pandoc failed to produce the PDF:\n{}{hint}",
            stderr.trim()
        )));
    }
    Ok(())
}

/// The PDF engine to hand pandoc: an explicit `CHAINVET_PDF_ENGINE` wins;
/// otherwise `tectonic` if installed (pandoc won't reach for it on its own);
/// otherwise `None` (pandoc uses its own default and reports if it's missing).
fn pdf_engine() -> Option<String> {
    if let Ok(engine) = std::env::var("CHAINVET_PDF_ENGINE") {
        let engine = engine.trim();
        if !engine.is_empty() {
            return Some(engine.to_string());
        }
    }
    on_path("tectonic").then(|| "tectonic".to_string())
}

/// Whether an executable of this name exists on PATH.
fn on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).is_file()))
        .unwrap_or(false)
}

/// Escape the LaTeX special characters, for values inserted raw into the template.
fn latex_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\textbackslash{}"),
            '&' => out.push_str("\\&"),
            '%' => out.push_str("\\%"),
            '$' => out.push_str("\\$"),
            '#' => out.push_str("\\#"),
            '_' => out.push_str("\\_"),
            '{' => out.push_str("\\{"),
            '}' => out.push_str("\\}"),
            '~' => out.push_str("\\textasciitilde{}"),
            '^' => out.push_str("\\textasciicircum{}"),
            _ => out.push(ch),
        }
    }
    out
}

/// A temporary directory removed on drop.
struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new() -> Result<Self> {
        let base = std::env::temp_dir().join(format!(
            "chainvet-report-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&base)
            .map_err(|err| Error::msg(format!("failed to create temp dir: {err}")))?;
        Ok(Self { path: base })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
