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

    // GitHub needs every result anchored to a file location. For findings with no
    // file of their own (contract-level invariants like public-mint-burn), fall
    // back to the first file any finding references, at line 1 — so nothing is
    // dropped. A result is skipped only when NO finding has any file (degenerate).
    let fallback = result.findings.iter().find_map(|f| f.file.clone());
    let results: Vec<Value> = result
        .findings
        .iter()
        .filter_map(|f| result_for(f, &sources, fallback.as_deref()))
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

fn result_for(
    f: &ScanFinding,
    sources: &HashMap<String, String>,
    fallback: Option<&str>,
) -> Option<Value> {
    // Precise location from the finding's own file+offset; otherwise the fallback
    // file at line 1. `None` only when the finding has no file and no fallback
    // exists (would break the SARIF, so it's skipped — extremely rare).
    let (uri, line, message) = match &f.file {
        Some(path) => {
            let line = f
                .start
                .and_then(|start| sources.get(path).map(|c| line_of(c, start)))
                .unwrap_or(1);
            (relativize(path), line, f.message.clone())
        }
        // No source line: anchor at the fallback file, line 1, and say so in the
        // message so the line-1 anchor isn't mistaken for a precise location.
        None => (
            relativize(fallback?),
            1,
            format!(
                "{} — file-level finding (no specific source line)",
                f.message
            ),
        ),
    };
    Some(json!({
        "ruleId": f.kind,
        "level": level_for(f.severity.as_deref()),
        "message": { "text": message },
        "properties": {
            "tier": f.tier,
            "provenance": f.provenance,
            "confidence": f.confidence,
            "category": f.category,
            "severity": f.severity,
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": { "uri": uri },
                "region": { "startLine": line }
            }
        }]
    }))
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
            confidence: Some("high".to_string()),
            category: Some("Reentrancy".to_string()),
            message: "example".to_string(),
            function_id: None,
            file: file.map(String::from),
            start: Some(0),
            end: None,
        }
    }

    // A file-less finding borrows the fallback file at line 1 (never dropped when
    // a fallback exists) — GitHub needs >= 1 location with a non-empty URI.
    #[test]
    fn file_less_finding_uses_fallback_location() {
        let r = result_for(&finding(None), &HashMap::new(), Some("contracts/A.sol")).unwrap();
        assert_eq!(
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "contracts/A.sol"
        );
        assert_eq!(
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
            1
        );
        // the message must flag that this is a file-level (line-less) finding
        assert!(
            r["message"]["text"]
                .as_str()
                .unwrap()
                .contains("file-level")
        );
    }

    #[test]
    fn file_less_finding_without_fallback_is_skipped() {
        assert!(result_for(&finding(None), &HashMap::new(), None).is_none());
    }

    #[test]
    fn finding_with_file_emits_a_location_uri() {
        let r = result_for(&finding(Some("contracts/A.sol")), &HashMap::new(), None).unwrap();
        assert_eq!(
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "contracts/A.sol"
        );
    }

    // The raw per-detector confidence rides along in `properties` (not just tier).
    #[test]
    fn properties_carry_confidence() {
        let r = result_for(&finding(Some("contracts/A.sol")), &HashMap::new(), None).unwrap();
        assert_eq!(r["properties"]["confidence"], "high");
    }

    #[test]
    fn to_sarif_keeps_all_findings_and_locates_them() {
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
        assert_eq!(
            results.len(),
            3,
            "nothing dropped when a fallback file exists"
        );
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
