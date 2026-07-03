//! Markdown rendering of an [`AuditReport`] — the canonical human report and the
//! source the HTML/PDF renderers mirror. Cyfrin-style section ordering.

use std::fmt::Write;

use super::{
    AuditFinding, AuditReport, finding_id, finding_title, guidance_for_finding, impact_for_finding,
    location_summary, severity_bucket, severity_counts, severity_label, severity_sort_rank,
};

/// Render the report as GitHub-flavored Markdown (title block + body).
pub fn render_markdown(report: &AuditReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# ChainVet Audit Report");
    let _ = writeln!(out);
    let _ = writeln!(out, "**Project:** {}  ", report.project_name);
    let _ = writeln!(out, "**Target:** `{}`  ", report.target);
    let _ = writeln!(out, "**Analysis mode:** {}", report.analysis_mode);
    let _ = writeln!(out);
    out.push_str(&render_markdown_body(report));
    out
}

/// The report body only — no leading title block.
fn render_markdown_body(report: &AuditReport) -> String {
    let mut findings = report.findings.clone();
    findings.sort_by(|a, b| {
        severity_sort_rank(&a.severity)
            .cmp(&severity_sort_rank(&b.severity))
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| {
                a.start
                    .unwrap_or(u32::MAX)
                    .cmp(&b.start.unwrap_or(u32::MAX))
            })
    });
    let counts = severity_counts(&findings);

    let mut out = String::new();
    let w = &mut out;

    let _ = writeln!(w, "## Protocol Summary");
    let _ = writeln!(w);
    let _ = writeln!(
        w,
        "ChainVet analyzed `{}` using the {} analysis pipeline. This report is generated directly from analyzer findings and does not include manually invented issues.",
        report.target, report.analysis_mode
    );
    let _ = writeln!(w);

    let _ = writeln!(w, "## Disclaimer");
    let _ = writeln!(w);
    let _ = writeln!(
        w,
        "Automated analysis cannot guarantee that every issue has been found. This report is not an endorsement of the underlying protocol, business logic, or deployment readiness. The review is limited to the code and execution paths available to the analyzer at the time of execution."
    );
    let _ = writeln!(w);

    let _ = writeln!(w, "## Risk Classification");
    let _ = writeln!(w);
    let _ = writeln!(w, "| Severity | Meaning |");
    let _ = writeln!(w, "| --- | --- |");
    let _ = writeln!(
        w,
        "| High | Exploitable issue with direct impact on funds, ownership, or availability. |"
    );
    let _ = writeln!(
        w,
        "| Medium | Conditional or lower-impact issue that still warrants a fix. |"
    );
    let _ = writeln!(
        w,
        "| Low | Minor issue, defense-in-depth, or best-practice deviation. |"
    );
    let _ = writeln!(
        w,
        "| Informational | Non-security observation or code-quality note. |"
    );
    let _ = writeln!(w);

    let _ = writeln!(w, "## Audit Details");
    let _ = writeln!(w);
    let _ = writeln!(w, "| Field | Value |");
    let _ = writeln!(w, "| --- | --- |");
    let _ = writeln!(w, "| Project | {} |", md_cell(&report.project_name));
    let _ = writeln!(w, "| Target | {} |", md_cell(&report.target));
    let _ = writeln!(w, "| Analysis mode | {} |", md_cell(&report.analysis_mode));
    let _ = writeln!(w, "| Reportable findings | {} |", report.raw_findings);
    for metric in &report.metrics {
        let _ = writeln!(
            w,
            "| {} | {} |",
            md_cell(&metric.label),
            md_cell(&metric.value)
        );
    }
    let _ = writeln!(w);

    let _ = writeln!(w, "## Scope");
    let _ = writeln!(w);
    let _ = writeln!(w, "- `{}`", report.target);
    let _ = writeln!(w);

    let _ = writeln!(w, "## Executive Summary");
    let _ = writeln!(w);
    if findings.is_empty() {
        let _ = writeln!(
            w,
            "ChainVet did not surface any reportable findings after deduplication and low-signal suppression."
        );
    } else {
        let _ = writeln!(
            w,
            "ChainVet surfaced {} reportable finding(s): {} high, {} medium, {} low, and {} informational.",
            findings.len(),
            counts.high,
            counts.medium,
            counts.low,
            counts.informational
        );
    }
    let _ = writeln!(w);
    let _ = writeln!(w, "| Severity | Count |");
    let _ = writeln!(w, "| --- | --- |");
    let _ = writeln!(w, "| High | {} |", counts.high);
    let _ = writeln!(w, "| Medium | {} |", counts.medium);
    let _ = writeln!(w, "| Low | {} |", counts.low);
    let _ = writeln!(w, "| Informational | {} |", counts.informational);
    let _ = writeln!(w);

    if !findings.is_empty() {
        let _ = writeln!(w, "## Issues Found");
        let _ = writeln!(w);
        let _ = writeln!(w, "| ID | Severity | Title | Location |");
        let _ = writeln!(w, "| --- | --- | --- | --- |");
        for (idx, finding) in findings.iter().enumerate() {
            // Location as a code span so the PDF (\texttt+seqsplit) breaks long paths.
            let _ = writeln!(
                w,
                "| {} | {} | {} | `{}` |",
                finding_id(idx + 1, &finding.severity),
                severity_label(&finding.severity),
                md_cell(&finding_title(finding)),
                md_cell(&location_summary(finding))
            );
        }
        let _ = writeln!(w);
    }

    let _ = writeln!(w, "## Findings");
    let _ = writeln!(w);
    for (heading, bucket) in [
        ("High", "high"),
        ("Medium", "medium"),
        ("Low", "low"),
        ("Informational", "informational"),
    ] {
        let _ = writeln!(w, "### {heading}");
        let _ = writeln!(w);
        let mut any = false;
        for (idx, finding) in findings.iter().enumerate() {
            if severity_bucket(&finding.severity) != bucket {
                continue;
            }
            any = true;
            write_finding(w, idx + 1, finding);
        }
        if !any {
            let _ = writeln!(w, "_No findings._");
            let _ = writeln!(w);
        }
    }

    out
}

fn write_finding(w: &mut String, idx: usize, finding: &AuditFinding) {
    let _ = writeln!(
        w,
        "#### [{}] {}",
        finding_id(idx, &finding.severity),
        finding_title(finding)
    );
    let _ = writeln!(w);
    let _ = writeln!(w, "- **Severity:** {}", severity_label(&finding.severity));
    let _ = writeln!(w, "- **Category:** {}", finding.category);
    let _ = writeln!(
        w,
        "- **Confidence:** {}",
        finding.confidence.as_deref().unwrap_or("unknown")
    );
    let _ = writeln!(w, "- **Location:** `{}`", location_summary(finding));
    let _ = writeln!(w, "- **Analysis layer:** {}", finding.analysis_layer);
    let _ = writeln!(w);

    let _ = writeln!(w, "**Analyzer Claim**");
    let _ = writeln!(w);
    let _ = writeln!(w, "{}", finding.message);
    let _ = writeln!(w);

    let _ = writeln!(w, "**Impact**");
    let _ = writeln!(w);
    let _ = writeln!(w, "{}", impact_for_finding(finding));
    let _ = writeln!(w);

    let guidance = guidance_for_finding(finding);
    let _ = writeln!(w, "**Proof of Concept / Evidence**");
    let _ = writeln!(w);
    let _ = writeln!(w, "{}", guidance.abuse);
    let _ = writeln!(w);
    if let Some(code) = guidance.poc_code.as_deref() {
        let _ = writeln!(w, "```solidity");
        let _ = writeln!(w, "{code}");
        let _ = writeln!(w, "```");
        let _ = writeln!(w);
    }

    let _ = writeln!(w, "**Recommended Mitigation**");
    let _ = writeln!(w);
    let _ = writeln!(w, "{}", guidance.remediation);
    let _ = writeln!(w);
    if let Some(code) = guidance.remediation_code.as_deref() {
        let _ = writeln!(w, "```solidity");
        let _ = writeln!(w, "{code}");
        let _ = writeln!(w, "```");
        let _ = writeln!(w);
    }
}

/// Escape a value for a Markdown table cell (pipes and newlines break the row).
fn md_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}
