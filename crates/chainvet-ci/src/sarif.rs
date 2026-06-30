//! Map a [`ScanResult`] to a SARIF 2.1.0 document for CI code-scanning upload.

use std::collections::HashMap;
use std::fs;

use chainvet_orchestrator::{ScanFinding, ScanResult};
use serde_json::{Value, json};

/// SARIF severity level for a Chainvet severity string.
fn level_for(severity: Option<&str>) -> &'static str {
    match severity {
        Some("high") => "error",
        Some("medium") => "warning",
        _ => "note",
    }
}

/// 1-based line number of a byte offset within `content`.
fn line_of(content: &str, offset: u32) -> u32 {
    let end = (offset as usize).min(content.len());
    content[..end].bytes().filter(|&b| b == b'\n').count() as u32 + 1
}

/// Build a SARIF 2.1.0 document from a scan result.
pub fn to_sarif(result: &ScanResult) -> Value {
    // Read each referenced file once for offset→line resolution.
    let mut sources: HashMap<String, String> = HashMap::new();
    for f in &result.findings {
        if let Some(path) = &f.file {
            sources
                .entry(path.clone())
                .or_insert_with(|| fs::read_to_string(path).unwrap_or_default());
        }
    }

    let results: Vec<Value> = result
        .findings
        .iter()
        .map(|f| result_for(f, &sources))
        .collect();

    // One rule per distinct finding kind.
    let mut seen = HashMap::new();
    for f in &result.findings {
        seen.entry(f.kind.clone()).or_insert_with(|| {
            f.category
                .clone()
                .unwrap_or_else(|| "Miscellaneous".to_string())
        });
    }
    let mut rules: Vec<Value> = seen
        .into_iter()
        .map(|(id, category)| {
            json!({
                "id": id,
                "properties": { "category": category }
            })
        })
        .collect();
    rules.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Chainvet",
                    "informationUri": "https://github.com/chainvet/chainvet",
                    "rules": rules
                }
            },
            "results": results
        }]
    })
}

fn result_for(f: &ScanFinding, sources: &HashMap<String, String>) -> Value {
    let line = match (&f.file, f.start) {
        (Some(path), Some(start)) => sources.get(path).map(|c| line_of(c, start)).unwrap_or(1),
        _ => 1,
    };
    let uri = f.file.clone().unwrap_or_default();
    json!({
        "ruleId": f.kind,
        "level": level_for(f.severity.as_deref()),
        "message": { "text": f.message },
        "properties": {
            "tier": f.tier,
            "provenance": f.provenance,
            "category": f.category,
            "severity": f.severity,
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": { "uri": uri },
                "region": { "startLine": line }
            }
        }]
    })
}
