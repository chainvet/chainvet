//! HTML rendering of an [`AuditReport`] — a self-contained, branded document
//! (inline CSS, inlined logo) that mirrors the Markdown structure and is styled
//! to print cleanly to PDF from a browser (dark Catppuccin theme preserved).

use std::fmt::Write;

use super::{
    AuditFinding, AuditReport, finding_id, finding_title, guidance_for_finding, impact_for_finding,
    location_summary, severity_bucket, severity_counts, severity_label, severity_sort_rank,
};

/// The ChainVet wordmark, inlined so the report needs no external assets.
const LOGO_SVG: &str = include_str!("../assets/chainvet-logo.svg");

/// Render the report as a standalone HTML document.
pub fn render_html(report: &AuditReport) -> String {
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

    let mut w = String::new();
    let _ = write!(
        w,
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>ChainVet Audit Report — {}</title>\n<style>{}</style>\n</head>\n<body>\n",
        esc(&report.project_name),
        CSS
    );

    // Cover / header
    let _ = write!(
        w,
        "<header class=\"cover\">\n<div class=\"logo\">{LOGO_SVG}</div>\n\
         <h1>Audit Report</h1>\n<p class=\"project\">{}</p>\n\
         <p class=\"subtitle\">Smart Contract Security Analysis</p>\n\
         <div class=\"target\"><span class=\"tlabel\">TARGET</span><code>{}</code>\
         <span class=\"tlabel\">MODE</span><span>{}</span></div>\n</header>\n",
        esc(&report.project_name),
        esc(&report.target),
        esc(&report.analysis_mode),
    );

    section(&mut w, "Protocol Summary", |w| {
        let _ = write!(
            w,
            "<p>ChainVet analyzed <code>{}</code> using the {} analysis pipeline. \
             This report is generated directly from analyzer findings and does not include \
             manually invented issues.</p>",
            esc(&report.target),
            esc(&report.analysis_mode)
        );
    });

    section(&mut w, "Disclaimer", |w| {
        let _ = w.write_str(
            "<p>Automated analysis cannot guarantee that every issue has been found. This report \
             is not an endorsement of the underlying protocol, business logic, or deployment \
             readiness. The review is limited to the code and execution paths available to the \
             analyzer at the time of execution.</p>",
        );
    });

    section(&mut w, "Risk Classification", |w| {
        let _ =
            w.write_str("<table><thead><tr><th>Severity</th><th>Meaning</th></tr></thead><tbody>");
        for (label, cls, meaning) in [
            (
                "High",
                "high",
                "Exploitable issue with direct impact on funds, ownership, or availability.",
            ),
            (
                "Medium",
                "medium",
                "Conditional or lower-impact issue that still warrants a fix.",
            ),
            (
                "Low",
                "low",
                "Minor issue, defense-in-depth, or best-practice deviation.",
            ),
            (
                "Informational",
                "informational",
                "Non-security observation or code-quality note.",
            ),
        ] {
            let _ = write!(
                w,
                "<tr><td><span class=\"badge {cls}\">{label}</span></td><td>{meaning}</td></tr>"
            );
        }
        let _ = w.write_str("</tbody></table>");
    });

    section(&mut w, "Audit Details", |w| {
        let _ = w.write_str("<table><tbody>");
        kv(w, "Project", &report.project_name);
        kv(w, "Target", &report.target);
        kv(w, "Analysis mode", &report.analysis_mode);
        kv(w, "Reportable findings", &report.raw_findings.to_string());
        for metric in &report.metrics {
            kv(w, &metric.label, &metric.value);
        }
        let _ = w.write_str("</tbody></table>");
    });

    section(&mut w, "Scope", |w| {
        let _ = write!(w, "<ul><li><code>{}</code></li></ul>", esc(&report.target));
    });

    section(&mut w, "Executive Summary", |w| {
        if findings.is_empty() {
            let _ = w.write_str(
                "<p>ChainVet did not surface any reportable findings after deduplication and \
                 low-signal suppression.</p>",
            );
        } else {
            let _ = write!(
                w,
                "<p>ChainVet surfaced <strong>{}</strong> reportable finding(s): \
                 {} high, {} medium, {} low, and {} informational.</p>",
                findings.len(),
                counts.high,
                counts.medium,
                counts.low,
                counts.informational
            );
        }
        let _ = write!(
            w,
            "<div class=\"cards\">\
             <div class=\"card high\"><span class=\"n\">{}</span><span>High</span></div>\
             <div class=\"card medium\"><span class=\"n\">{}</span><span>Medium</span></div>\
             <div class=\"card low\"><span class=\"n\">{}</span><span>Low</span></div>\
             <div class=\"card informational\"><span class=\"n\">{}</span><span>Info</span></div>\
             </div>",
            counts.high, counts.medium, counts.low, counts.informational
        );
    });

    if !findings.is_empty() {
        section(&mut w, "Issues Found", |w| {
            let _ = w.write_str(
                "<table class=\"issues\"><thead><tr><th>ID</th><th>Severity</th><th>Title</th><th>Location</th>\
                 </tr></thead><tbody>",
            );
            for (idx, f) in findings.iter().enumerate() {
                let _ = write!(
                    w,
                    "<tr><td><code>{}</code></td><td><span class=\"badge {}\">{}</span></td>\
                     <td>{}</td><td><code>{}</code></td></tr>",
                    finding_id(idx + 1, &f.severity),
                    severity_bucket(&f.severity),
                    severity_label(&f.severity),
                    esc(&finding_title(f)),
                    esc(&location_summary(f))
                );
            }
            let _ = w.write_str("</tbody></table>");
        });
    }

    let _ = writeln!(&mut w, "<section><h2>Findings</h2>");
    for (heading, bucket) in [
        ("High", "high"),
        ("Medium", "medium"),
        ("Low", "low"),
        ("Informational", "informational"),
    ] {
        let _ = writeln!(&mut w, "<h3>{heading}</h3>");
        let mut any = false;
        for (idx, finding) in findings.iter().enumerate() {
            if severity_bucket(&finding.severity) != bucket {
                continue;
            }
            any = true;
            write_finding(&mut w, idx + 1, finding);
        }
        if !any {
            let _ = w.write_str("<p class=\"muted\">No findings.</p>\n");
        }
    }
    let _ = w.write_str("</section>\n");

    let _ = w.write_str("<footer>Prepared by ChainVet Analyzer</footer>\n</body>\n</html>\n");
    w
}

fn write_finding(w: &mut String, idx: usize, finding: &AuditFinding) {
    let bucket = severity_bucket(&finding.severity);
    let _ = write!(
        w,
        "<article class=\"finding {bucket}\">\n<h4>[{}] {}</h4>\n<dl class=\"meta\">",
        finding_id(idx, &finding.severity),
        esc(&finding_title(finding))
    );
    meta(w, "Severity", severity_label(&finding.severity));
    meta(w, "Category", &finding.category);
    meta(w, "Tier", &finding.tier);
    meta(
        w,
        "Confidence",
        finding.confidence.as_deref().unwrap_or("unknown"),
    );
    meta(w, "Location", &location_summary(finding));
    meta(w, "Analysis layer", &finding.analysis_layer);
    let _ = w.write_str("</dl>\n");

    block(w, "Analyzer Claim", &finding.message, None);
    block(w, "Impact", impact_for_finding(finding), None);

    let guidance = guidance_for_finding(finding);
    block(
        w,
        "Proof of Concept / Evidence",
        &guidance.abuse,
        guidance.poc_code.as_deref(),
    );
    block(
        w,
        "Recommended Mitigation",
        &guidance.remediation,
        guidance.remediation_code.as_deref(),
    );
    let _ = w.write_str("</article>\n");
}

fn section(w: &mut String, title: &str, body: impl FnOnce(&mut String)) {
    let _ = writeln!(w, "<section><h2>{title}</h2>");
    body(w);
    let _ = w.write_str("</section>\n");
}

fn block(w: &mut String, title: &str, prose: &str, code: Option<&str>) {
    let _ = write!(w, "<h5>{title}</h5>\n<p>{}</p>\n", esc(prose));
    if let Some(code) = code {
        let _ = writeln!(w, "<pre><code>{}</code></pre>", esc(code));
    }
}

fn kv(w: &mut String, label: &str, value: &str) {
    let _ = write!(w, "<tr><th>{}</th><td>{}</td></tr>", esc(label), esc(value));
}

fn meta(w: &mut String, label: &str, value: &str) {
    let _ = write!(w, "<dt>{}</dt><dd>{}</dd>", esc(label), esc(value));
}

/// Minimal HTML escaping for text/attribute content.
fn esc(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
    out
}

const CSS: &str = r#"
:root{--base:#1e1e2e;--mantle:#181825;--crust:#11111b;--s0:#313244;--s1:#45475a;--s2:#585b70;
--text:#cdd6f4;--sub1:#bac2de;--sub0:#a6adc8;--ov0:#6c7086;--red:#f38ba8;--peach:#fab387;
--yellow:#f9e2af;--green:#a6e3a1;--sky:#89dceb;--blue:#89b4fa;--mauve:#cba6f7;--lav:#b4befe}
*{box-sizing:border-box}
/* Full-bleed dark page: zero page margin so the background reaches the paper
   edge (weasyprint / print-to-PDF), with the reading inset applied on <body>. */
@page{size:A4;margin:0}
/* Background on <html> so the *whole* page is dark; color-adjust:exact so
   browsers print the background instead of dropping it to white. */
html{background:var(--base);-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{margin:0 auto;background:var(--base);color:var(--text);
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
max-width:900px;padding:40px 48px 56px}
h1,h2,h3,h4,h5{color:var(--text);line-height:1.2}
h2{font-size:1.35rem;margin:1.5rem 0 .5rem;padding-bottom:.25rem;border-bottom:1px solid var(--s2)}
h3{font-size:1.1rem;color:var(--lav);margin:1.1rem 0 .4rem}
h4{font-size:1rem;margin:0 0 .5rem}
h5{font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;color:var(--lav);margin:.7rem 0 .2rem}
a{color:var(--blue)}
code{font-family:"SF Mono",ui-monospace,Menlo,Consolas,monospace;font-size:.86em;
background:var(--crust);padding:.1em .35em;border-radius:4px;color:var(--sub1)}
pre{background:var(--crust);border:1px solid var(--s0);border-radius:8px;padding:10px 12px;
margin:.4rem 0;overflow-x:auto}
pre code{background:none;padding:0;color:var(--sub1);font-size:.78rem;line-height:1.4}
p{margin:.3rem 0}
.muted{color:var(--ov0)}
.cover{text-align:left;padding:1.5rem 0;border-bottom:2px solid var(--s0);margin-bottom:.8rem}
.cover .logo{max-width:240px;margin-bottom:1rem}
.cover .logo svg{width:100%;height:auto}
.cover h1{font-size:2.2rem;margin:0}
.cover .project{font-size:1.2rem;color:var(--sub1);margin:.3rem 0 0}
.cover .subtitle{color:var(--sub0);margin:.15rem 0 1.1rem}
.target{background:var(--s0);border:1px solid var(--s2);border-radius:10px;padding:14px 18px;
display:grid;grid-template-columns:auto 1fr;gap:.4rem 1rem;align-items:center;max-width:640px}
.tlabel{font-size:.7rem;font-weight:700;letter-spacing:.08em;color:var(--lav)}
table{width:100%;border-collapse:collapse;margin:.4rem 0;font-size:.9rem}
th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid var(--s0);vertical-align:top;
overflow-wrap:anywhere}
td code,.meta dd{overflow-wrap:anywhere;word-break:break-word}
th{color:var(--sub0);font-weight:600}
td code{font-size:.82em}
.badge{display:inline-block;padding:.15em .6em;border-radius:999px;font-size:.78rem;font-weight:700;
color:var(--crust);white-space:nowrap}
/* Issues table: fixed layout with a generous Location column so long paths wrap
   inside the column (never a char early) and the index columns stay on one line. */
table.issues{table-layout:fixed}
table.issues th:nth-child(1){width:8%}table.issues th:nth-child(2){width:13%}
table.issues th:nth-child(3){width:41%}table.issues th:nth-child(4){width:38%}
table.issues td:first-child,table.issues td:nth-child(2),
table.issues th:first-child,table.issues th:nth-child(2){white-space:nowrap}
.badge.high{background:var(--red)}.badge.medium{background:var(--peach)}
.badge.low{background:var(--yellow)}.badge.informational{background:var(--sky)}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:.7rem 0}
.card{background:var(--s0);border:1px solid var(--s2);border-radius:10px;padding:10px;
text-align:center;display:flex;flex-direction:column;gap:.15rem}
.card .n{font-size:1.6rem;font-weight:800}
.card.high .n{color:var(--red)}.card.medium .n{color:var(--peach)}
.card.low .n{color:var(--yellow)}.card.informational .n{color:var(--sky)}
.finding{background:var(--mantle);border:1px solid var(--s0);border-left:4px solid var(--s2);
border-radius:8px;padding:12px 16px;margin:.7rem 0}
.finding.high{border-left-color:var(--red)}.finding.medium{border-left-color:var(--peach)}
.finding.low{border-left-color:var(--yellow)}.finding.informational{border-left-color:var(--sky)}
.meta{display:grid;grid-template-columns:auto 1fr;gap:.1rem .8rem;margin:0 0 .4rem;font-size:.86rem}
.meta dt{color:var(--sub0);font-weight:600}
.meta dd{margin:0}
footer{margin-top:1.5rem;padding-top:.8rem;border-top:1px solid var(--s0);color:var(--ov0);font-size:.82rem}
/* Let long findings flow across pages (avoids big end-of-page gaps); keep code
   blocks, cards, and individual rows from splitting. */
@media print{*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
html,body{background:var(--base)}
pre,.card,tr{break-inside:avoid}}
"#;
