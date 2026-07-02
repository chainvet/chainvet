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

    // Code scanning requires every result to be anchored to a file location, so
    // drop findings that have no file — they can't be represented in SARIF, and
    // GitHub rejects the whole document otherwise ("expected at least one location").
    let results: Vec<Value> = result
        .findings
        .iter()
        .filter(|f| f.file.is_some())
        .map(|f| result_for(f, &sources))
        .collect();

    // One rule per distinct finding kind (of the findings we keep).
    let mut seen = HashMap::new();
    for f in result.findings.iter().filter(|f| f.file.is_some()) {
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

/// Make a path repo-relative when possible. GitHub code scanning maps artifact
/// URIs against the repository root, so absolute paths (e.g. the runner's
/// checkout dir) don't resolve to files.
fn relativize(path: &str) -> String {
    use std::path::Path;
    if let Ok(cwd) = std::env::current_dir()
        && let Ok(rel) = Path::new(path).strip_prefix(&cwd)
    {
        return rel.to_string_lossy().into_owned();
    }
    path.to_string()
}

fn result_for(f: &ScanFinding, sources: &HashMap<String, String>) -> Value {
    let mut result = json!({
        "ruleId": f.kind,
        "level": level_for(f.severity.as_deref()),
        "message": { "text": f.message },
        "properties": {
            "tier": f.tier,
            "provenance": f.provenance,
            "category": f.category,
            "severity": f.severity,
        }
    });

    // Only attach a location when the finding has a file. GitHub rejects the whole
    // SARIF if any result carries a location with an empty/missing artifactLocation
    // ("expected artifact location"); a result with no locations is valid.
    if let Some(path) = &f.file {
        let line = f
            .start
            .and_then(|start| sources.get(path).map(|c| line_of(c, start)))
            .unwrap_or(1);
        result["locations"] = json!([{
            "physicalLocation": {
                "artifactLocation": { "uri": relativize(path) },
                "region": { "startLine": line }
            }
        }]);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use chainvet_orchestrator::{ScanFinding, ScanMode, ScanResult};

    fn finding(file: Option<&str>) -> ScanFinding {
        ScanFinding {
            tier: "candidate".to_string(),
            provenance: "static".to_string(),
            provenances: Vec::new(),
            kind: "reentrancy".to_string(),
            severity: Some("high".to_string()),
            confidence: None,
            category: Some("Reentrancy".to_string()),
            message: "example".to_string(),
            function_id: None,
            file: file.map(String::from),
            start: Some(0),
            end: None,
        }
    }

    // GitHub rejects the whole SARIF ("expected artifact location") if a result
    // carries a location with no artifactLocation URI — so a file-less finding
    // must omit `locations` entirely rather than emit an empty URI.
    #[test]
    fn file_less_finding_has_no_locations() {
        let r = result_for(&finding(None), &HashMap::new());
        assert!(r.get("locations").is_none());
    }

    #[test]
    fn finding_with_file_emits_a_location_uri() {
        let r = result_for(&finding(Some("contracts/A.sol")), &HashMap::new());
        assert_eq!(
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "contracts/A.sol"
        );
    }

    #[test]
    fn to_sarif_drops_file_less_findings_and_keeps_locations() {
        let result = ScanResult {
            mode: ScanMode::Static,
            findings: vec![
                finding(None),
                finding(Some("contracts/A.sol")),
                finding(None),
            ],
            hybrid: None,
        };
        let sarif = to_sarif(&result);
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1, "file-less findings must be dropped");
        for r in results {
            let locs = r["locations"]
                .as_array()
                .expect("every result needs locations");
            assert!(!locs.is_empty(), "every result needs >= 1 location");
            let uri = locs[0]["physicalLocation"]["artifactLocation"]["uri"].as_str();
            assert!(
                uri.is_some_and(|u| !u.is_empty()),
                "location needs a non-empty uri"
            );
        }
    }
}
