//! PDF output via a `pandoc` passthrough.
//!
//! Rendering a real `.pdf` in-process (a bundled PDF engine + embedded fonts) is
//! rare among analyzers and heavy to maintain; the common pattern — and what
//! audit firms actually do — is to author Markdown and convert it. So `-f pdf`
//! renders the same Markdown report and pipes it through `pandoc`. Requires
//! `pandoc` plus a PDF engine (a LaTeX engine like `tectonic`/`xelatex`, or
//! `weasyprint`) on PATH. For a branded, dependency-free artifact, use `-f html`
//! and "Print to PDF" from a browser instead.
//!
//! Overrides: `CHAINVET_PANDOC` (binary, default `pandoc`) and
//! `CHAINVET_PDF_ENGINE` (pandoc `--pdf-engine`, e.g. `tectonic`/`weasyprint`).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use chainvet_core::util::error::{Error, Result};

/// First PDF engine found on PATH, in order of preference (self-contained
/// tectonic first, then LaTeX engines, then HTML-based ones).
fn detect_pdf_engine() -> Option<String> {
    [
        "tectonic",
        "xelatex",
        "lualatex",
        "pdflatex",
        "weasyprint",
        "wkhtmltopdf",
        "context",
    ]
    .into_iter()
    .find(|engine| on_path(engine))
    .map(str::to_string)
}

/// Whether an executable of this name exists on PATH.
fn on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).is_file()))
        .unwrap_or(false)
}

/// Convert a Markdown report to a PDF at `output` by piping it through pandoc.
pub fn write_pdf_via_pandoc(markdown: &str, output: &Path) -> Result<()> {
    let pandoc = std::env::var("CHAINVET_PANDOC").unwrap_or_else(|_| "pandoc".to_string());

    let mut cmd = Command::new(&pandoc);
    cmd.arg("--from=gfm")
        .arg("--output")
        .arg(output)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Pandoc defaults to pdflatex; pick whatever engine is actually installed so
    // `-f pdf` works without the user configuring anything. An explicit
    // CHAINVET_PDF_ENGINE always wins; if nothing is found we let pandoc default
    // and surface its error.
    let engine = std::env::var("CHAINVET_PDF_ENGINE")
        .ok()
        .filter(|e| !e.trim().is_empty())
        .or_else(detect_pdf_engine);
    if let Some(engine) = engine {
        cmd.arg(format!("--pdf-engine={engine}"));
    }

    let mut child = cmd.spawn().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            Error::msg(format!(
                "`{pandoc}` was not found — PDF output is a pandoc passthrough.\n\
                 Install pandoc plus a PDF engine (e.g. tectonic, xelatex, or weasyprint),\n\
                 or use `-f html` and \"Print to PDF\" from a browser for a branded report."
            ))
        } else {
            Error::msg(format!("failed to launch `{pandoc}`: {err}"))
        }
    })?;

    child
        .stdin
        .take()
        .ok_or_else(|| Error::msg("failed to open pandoc stdin"))?
        .write_all(markdown.as_bytes())
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
