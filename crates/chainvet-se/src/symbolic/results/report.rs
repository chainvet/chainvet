use crate::symbolic::results::coverage::CoverageReport;
use crate::symbolic::results::finding::SeFinding;
use chainvet_core::OutputFormat;
use chainvet_core::norm::SourceFile;
use chainvet_core::util::error::{Error, Result};

/// Render SE engine results in the requested format.
pub fn print_se_report(
    findings: &[SeFinding],
    coverage: &CoverageReport,
    states_explored: usize,
    format: OutputFormat,
    files: &[SourceFile],
) -> Result<()> {
    match format {
        OutputFormat::Text => print_se_text(findings, coverage, states_explored),
        OutputFormat::Json => print_se_json(findings, coverage, states_explored, files),
    }
}

/// Render results in human-readable text format.
///
/// Prints a header with exploration stats, then one line per finding.
/// Short-circuits with "No findings." when the slice is empty.
fn print_se_text(findings: &[SeFinding], coverage: &CoverageReport, states: usize) -> Result<()> {
    println!("=== Symbolic Execution Results ===");
    println!("States explored : {states}");
    println!(
        "Block coverage  : {:.1}% ({}/{})",
        coverage.block_coverage_pct, coverage.blocks_visited, coverage.blocks_total
    );
    println!(
        "Functions covered: {}/{}",
        coverage.functions_visited, coverage.functions_total
    );
    println!("Edges visited   : {}", coverage.edges_visited);
    println!();

    if findings.is_empty() {
        println!("No findings.");
        return Ok(());
    }

    println!("{} finding(s):", findings.len());
    for f in findings {
        println!(
            "[{}] {} ({}) — {} [confidence: {}]",
            f.severity.as_str(),
            f.kind.as_str(),
            f.category().as_str(),
            f.message,
            f.confidence.as_str(),
        );
        if !f.path_constraints.is_empty() {
            for c in &f.path_constraints {
                println!("  constraint: {c}");
            }
        }
        if let Some(w) = &f.witness {
            let hex: String = w.msg_sender.iter().map(|b| format!("{b:02x}")).collect();
            println!("  witness msg.sender: 0x{hex}");
        }
    }
    Ok(())
}

/// Resolve a numeric file ID to its path string.
fn resolve_file(files: &[SourceFile], file_id: u32) -> Option<String> {
    files.get(file_id as usize).map(|f| f.path.clone())
}

/// Render results as a JSON object.
///
/// Serializes a wrapper with `states_explored`, `coverage`, and `findings`
/// as top-level keys, then pretty-prints to stdout. Each finding's numeric
/// `span.file` is resolved to the source file path.
fn print_se_json(
    findings: &[SeFinding],
    coverage: &CoverageReport,
    states: usize,
    files: &[SourceFile],
) -> Result<()> {
    #[derive(serde::Serialize)]
    struct ResolvedFinding<'a> {
        kind: &'a str,
        severity: &'a str,
        confidence: &'a str,
        category: &'a str,
        message: &'a str,
        file: Option<String>,
        start: u32,
        end: u32,
        function_id: Option<u32>,
        path_constraints: &'a [String],
        witness: &'a Option<super::witness::Witness>,
        state_id: u64,
        path_depth: u32,
    }

    let resolved: Vec<ResolvedFinding> = findings
        .iter()
        .map(|f| ResolvedFinding {
            kind: f.kind.as_str(),
            severity: f.severity.as_str(),
            confidence: f.confidence.as_str(),
            category: f.category().as_str(),
            message: &f.message,
            file: resolve_file(files, f.span.file),
            start: f.span.start,
            end: f.span.end,
            function_id: f.function_id,
            path_constraints: &f.path_constraints,
            witness: &f.witness,
            state_id: f.state_id,
            path_depth: f.path_depth,
        })
        .collect();

    #[derive(serde::Serialize)]
    struct SeReport<'a> {
        states_explored: usize,
        coverage: &'a CoverageReport,
        findings: Vec<ResolvedFinding<'a>>,
    }
    let report = SeReport {
        states_explored: states,
        coverage,
        findings: resolved,
    };
    let json = serde_json::to_string_pretty(&report).map_err(|e| Error::msg(e.to_string()))?;
    println!("{json}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbolic::results::finding::{Confidence, SeFinding, SeVulnKind};
    use crate::symbolic::results::witness::Witness;
    use chainvet_core::norm::Span;
    use chainvet_sa::analysis::detectors::Severity;

    // ── Fixtures ────────────────────────────────────────────────────────────────

    /// A CoverageReport with realistic non-zero values used across many tests.
    fn sample_coverage() -> CoverageReport {
        CoverageReport {
            blocks_visited: 3,
            blocks_total: 5,
            block_coverage_pct: 60.0,
            edges_visited: 2,
            functions_visited: 1,
            functions_total: 2,
            function_coverage_pct: 50.0,
        }
    }

    /// A CoverageReport where every counter is zero (division-by-zero guard).
    fn zero_coverage() -> CoverageReport {
        CoverageReport {
            blocks_visited: 0,
            blocks_total: 0,
            block_coverage_pct: 0.0,
            edges_visited: 0,
            functions_visited: 0,
            functions_total: 0,
            function_coverage_pct: 0.0,
        }
    }

    /// Build a minimal SeFinding with no path constraints and no witness.
    fn make_finding_bare(
        kind: SeVulnKind,
        severity: Severity,
        confidence: Confidence,
    ) -> SeFinding {
        SeFinding {
            kind,
            severity,
            confidence,
            message: "test finding message".to_string(),
            span: Span {
                file: 0,
                start: 0,
                end: 0,
            },
            function_id: None,
            path_constraints: vec![],
            witness: None,
            state_id: 1,
            path_depth: 0,
        }
    }

    /// Build a finding that has path constraints but no witness.
    fn make_finding_with_constraints() -> SeFinding {
        SeFinding {
            kind: SeVulnKind::IntegerOverflow,
            severity: Severity::High,
            confidence: Confidence::High,
            message: "overflow on addition".to_string(),
            span: Span {
                file: 0,
                start: 10,
                end: 20,
            },
            function_id: Some(3),
            path_constraints: vec!["x > 0".to_string(), "y < MAX_UINT256".to_string()],
            witness: None,
            state_id: 42,
            path_depth: 5,
        }
    }

    /// Build a finding that carries a concrete Witness.
    fn make_finding_with_witness() -> SeFinding {
        let witness = Witness {
            msg_sender: [
                0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ],
            msg_value: [0u8; 32],
            tx_origin: [0u8; 20],
            block_timestamp: 1_700_000_000,
            block_number: 18_000_000,
            this_balance: [0u8; 32],
            variables: vec![("x".to_string(), vec![0xff])],
        };
        SeFinding {
            kind: SeVulnKind::Reentrancy,
            severity: Severity::High,
            confidence: Confidence::High,
            message: "reentrancy via fallback".to_string(),
            span: Span {
                file: 0,
                start: 100,
                end: 200,
            },
            function_id: Some(7),
            path_constraints: vec!["balance > 0".to_string()],
            witness: Some(witness),
            state_id: 99,
            path_depth: 10,
        }
    }

    // ── print_se_report — text format ────────────────────────────────────────

    #[test]
    fn test_print_se_report_text_empty_findings_returns_ok() {
        // With an empty findings slice and text format the function must succeed.
        let result = print_se_report(&[], &sample_coverage(), 42, OutputFormat::Text, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_print_se_report_text_single_finding_returns_ok() {
        // A single bare finding (no constraints, no witness) must render without error.
        let findings = vec![make_finding_bare(
            SeVulnKind::IntegerOverflow,
            Severity::High,
            Confidence::High,
        )];
        let result = print_se_report(&findings, &sample_coverage(), 1, OutputFormat::Text, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_print_se_report_text_findings_with_constraints_returns_ok() {
        // Findings that carry path constraints must render the constraint lines without panic.
        let findings = vec![make_finding_with_constraints()];
        let result = print_se_report(&findings, &sample_coverage(), 5, OutputFormat::Text, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_print_se_report_text_findings_with_witness_returns_ok() {
        // Findings with a concrete witness must render the hex msg_sender line without panic.
        let findings = vec![make_finding_with_witness()];
        let result = print_se_report(&findings, &sample_coverage(), 10, OutputFormat::Text, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_print_se_report_text_multiple_findings_returns_ok() {
        // Multiple diverse findings (different kinds, severities, confidences) must succeed.
        let findings = vec![
            make_finding_bare(
                SeVulnKind::IntegerUnderflow,
                Severity::Medium,
                Confidence::Medium,
            ),
            make_finding_with_constraints(),
            make_finding_with_witness(),
            make_finding_bare(SeVulnKind::AssertionFailure, Severity::Low, Confidence::Low),
        ];
        let result = print_se_report(&findings, &sample_coverage(), 100, OutputFormat::Text, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_print_se_report_text_zero_coverage_returns_ok() {
        // A zero-coverage report (all zeroes, 0.0 pct) must not cause any formatting panic.
        let result = print_se_report(&[], &zero_coverage(), 0, OutputFormat::Text, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_print_se_report_text_zero_states_explored_returns_ok() {
        // states_explored == 0 is a valid value that must display cleanly.
        let result = print_se_report(&[], &sample_coverage(), 0, OutputFormat::Text, &[]);
        assert!(result.is_ok());
    }

    // ── print_se_report — JSON format ────────────────────────────────────────

    #[test]
    fn test_print_se_report_json_empty_findings_returns_ok() {
        // JSON rendering with no findings must succeed.
        let result = print_se_report(&[], &sample_coverage(), 10, OutputFormat::Json, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_print_se_report_json_with_findings_returns_ok() {
        // JSON rendering with a non-empty findings slice must succeed.
        let findings = vec![
            make_finding_bare(SeVulnKind::Reentrancy, Severity::High, Confidence::High),
            make_finding_with_witness(),
        ];
        let result = print_se_report(&findings, &sample_coverage(), 20, OutputFormat::Json, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_print_se_report_json_all_vuln_kinds_returns_ok() {
        // Every SeVulnKind variant must serialize without error in the JSON path.
        let all_kinds = [
            SeVulnKind::IntegerOverflow,
            SeVulnKind::IntegerUnderflow,
            SeVulnKind::Reentrancy,
            SeVulnKind::UnprotectedSelfdestruct,
            SeVulnKind::UncheckedCall,
            SeVulnKind::TxOriginAuth,
            SeVulnKind::UnsafeDelegatecall,
            SeVulnKind::TimestampDependency,
            SeVulnKind::AccessControlMissing,
            SeVulnKind::AssertionFailure,
        ];
        let findings: Vec<SeFinding> = all_kinds
            .iter()
            .map(|&k| make_finding_bare(k, Severity::Medium, Confidence::Medium))
            .collect();
        let result = print_se_report(&findings, &sample_coverage(), 99, OutputFormat::Json, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_print_se_report_json_zero_coverage_returns_ok() {
        // Zero coverage values must not cause serde serialization to fail.
        let result = print_se_report(&[], &zero_coverage(), 0, OutputFormat::Json, &[]);
        assert!(result.is_ok());
    }

    // ── serde_json serialization of CoverageReport ───────────────────────────

    #[test]
    fn test_coverage_report_serializes_to_json_with_expected_keys() {
        // CoverageReport must serialize to JSON containing the documented field names.
        let report = sample_coverage();
        let json = serde_json::to_string(&report).expect("serialization must succeed");
        assert!(
            json.contains("\"blocks_visited\""),
            "missing blocks_visited key"
        );
        assert!(
            json.contains("\"blocks_total\""),
            "missing blocks_total key"
        );
        assert!(
            json.contains("\"block_coverage_pct\""),
            "missing block_coverage_pct key"
        );
        assert!(
            json.contains("\"edges_visited\""),
            "missing edges_visited key"
        );
        assert!(
            json.contains("\"functions_visited\""),
            "missing functions_visited key"
        );
        assert!(
            json.contains("\"functions_total\""),
            "missing functions_total key"
        );
        assert!(
            json.contains("\"function_coverage_pct\""),
            "missing function_coverage_pct key"
        );
    }

    #[test]
    fn test_coverage_report_serializes_correct_values() {
        // The numeric values in the serialized JSON must match the struct fields exactly.
        let report = CoverageReport {
            blocks_visited: 7,
            blocks_total: 10,
            block_coverage_pct: 70.0,
            edges_visited: 5,
            functions_visited: 2,
            functions_total: 4,
            function_coverage_pct: 50.0,
        };
        let json = serde_json::to_string(&report).expect("serialization must succeed");
        // Key/value pairs as they appear in compact JSON
        assert!(
            json.contains("\"blocks_visited\":7"),
            "blocks_visited value mismatch"
        );
        assert!(
            json.contains("\"blocks_total\":10"),
            "blocks_total value mismatch"
        );
        assert!(
            json.contains("\"edges_visited\":5"),
            "edges_visited value mismatch"
        );
        assert!(
            json.contains("\"functions_visited\":2"),
            "functions_visited value mismatch"
        );
        assert!(
            json.contains("\"functions_total\":4"),
            "functions_total value mismatch"
        );
    }

    // ── serde_json serialization of SeFinding ────────────────────────────────

    #[test]
    fn test_sefinding_serializes_to_json_with_kind_field() {
        // A serialized SeFinding must carry the "kind" key.
        let finding = make_finding_bare(
            SeVulnKind::IntegerOverflow,
            Severity::High,
            Confidence::High,
        );
        let json = serde_json::to_string(&finding).expect("serialization must succeed");
        assert!(
            json.contains("\"kind\""),
            "missing kind field in SeFinding JSON"
        );
        assert!(
            json.contains("\"IntegerOverflow\""),
            "kind value should be IntegerOverflow"
        );
    }

    #[test]
    fn test_sefinding_serializes_severity_field() {
        // Severity must appear in the JSON output of a serialized SeFinding.
        let finding = make_finding_bare(SeVulnKind::Reentrancy, Severity::Medium, Confidence::Low);
        let json = serde_json::to_string(&finding).expect("serialization must succeed");
        assert!(json.contains("\"severity\""), "missing severity field");
        assert!(
            json.contains("\"Medium\""),
            "severity value should be Medium"
        );
    }

    #[test]
    fn test_sefinding_serializes_confidence_field() {
        // Confidence must appear in the JSON output.
        let finding = make_finding_bare(SeVulnKind::UncheckedCall, Severity::Low, Confidence::Low);
        let json = serde_json::to_string(&finding).expect("serialization must succeed");
        assert!(json.contains("\"confidence\""), "missing confidence field");
        assert!(json.contains("\"Low\""), "confidence value should be Low");
    }

    #[test]
    fn test_sefinding_serializes_message_field() {
        // The "message" field must be present and contain the original string.
        let finding =
            make_finding_bare(SeVulnKind::TxOriginAuth, Severity::High, Confidence::Medium);
        let json = serde_json::to_string(&finding).expect("serialization must succeed");
        assert!(json.contains("\"message\""), "missing message field");
        assert!(
            json.contains("test finding message"),
            "message value mismatch"
        );
    }

    #[test]
    fn test_sefinding_serializes_path_constraints() {
        // When path_constraints is non-empty the field must appear in the JSON.
        let finding = make_finding_with_constraints();
        let json = serde_json::to_string(&finding).expect("serialization must succeed");
        assert!(
            json.contains("\"path_constraints\""),
            "missing path_constraints field"
        );
        assert!(json.contains("x > 0"), "first constraint missing from JSON");
    }

    #[test]
    fn test_sefinding_serializes_witness_when_present() {
        // When a Witness is attached it must appear under the "witness" key (not null).
        let finding = make_finding_with_witness();
        let json = serde_json::to_string(&finding).expect("serialization must succeed");
        assert!(json.contains("\"witness\""), "missing witness field");
        // The witness should not serialize as null when Some(_) is present.
        assert!(
            !json.contains("\"witness\":null"),
            "witness should not be null"
        );
    }

    #[test]
    fn test_sefinding_serializes_null_witness_when_absent() {
        // When witness is None the field should serialize as null.
        let finding =
            make_finding_bare(SeVulnKind::AssertionFailure, Severity::Low, Confidence::Low);
        let json = serde_json::to_string(&finding).expect("serialization must succeed");
        assert!(
            json.contains("\"witness\":null"),
            "absent witness should serialize as null"
        );
    }

    // ── Top-level JSON structure (states_explored key) ────────────────────────

    #[test]
    fn test_json_output_contains_states_explored_key() {
        // The top-level JSON document produced by the JSON path must include
        // "states_explored". We verify this by replicating the anonymous SeReport
        // struct from print_se_json and serializing it directly.
        #[derive(serde::Serialize)]
        struct SeReport<'a> {
            states_explored: usize,
            coverage: &'a CoverageReport,
            findings: &'a [SeFinding],
        }
        let cov = sample_coverage();
        let findings: Vec<SeFinding> = vec![];
        let report = SeReport {
            states_explored: 77,
            coverage: &cov,
            findings: &findings,
        };
        let json = serde_json::to_string_pretty(&report).expect("serialization must succeed");
        assert!(
            json.contains("\"states_explored\""),
            "states_explored key must be present"
        );
        assert!(
            json.contains("77"),
            "states_explored value must appear in JSON"
        );
    }

    #[test]
    fn test_json_output_contains_coverage_key() {
        // The top-level document must also nest the coverage object under "coverage".
        #[derive(serde::Serialize)]
        struct SeReport<'a> {
            states_explored: usize,
            coverage: &'a CoverageReport,
            findings: &'a [SeFinding],
        }
        let cov = sample_coverage();
        let findings: Vec<SeFinding> = vec![];
        let report = SeReport {
            states_explored: 0,
            coverage: &cov,
            findings: &findings,
        };
        let json = serde_json::to_string_pretty(&report).expect("serialization must succeed");
        assert!(
            json.contains("\"coverage\""),
            "coverage key must be present at top level"
        );
    }

    #[test]
    fn test_json_output_contains_findings_key() {
        // The top-level document must contain a "findings" array key.
        #[derive(serde::Serialize)]
        struct SeReport<'a> {
            states_explored: usize,
            coverage: &'a CoverageReport,
            findings: &'a [SeFinding],
        }
        let cov = zero_coverage();
        let findings = vec![make_finding_bare(
            SeVulnKind::TimestampDependency,
            Severity::Low,
            Confidence::Low,
        )];
        let report = SeReport {
            states_explored: 1,
            coverage: &cov,
            findings: &findings,
        };
        let json = serde_json::to_string_pretty(&report).expect("serialization must succeed");
        assert!(
            json.contains("\"findings\""),
            "findings key must be present at top level"
        );
    }

    // ── Witness hex rendering (msg_sender byte layout) ────────────────────────

    #[test]
    fn test_witness_all_zero_sender_hex_is_40_chars() {
        // A msg_sender of [0u8; 20] must produce exactly 40 hex characters when
        // rendered with the same logic used in print_se_text.
        let w = Witness {
            msg_sender: [0u8; 20],
            msg_value: [0u8; 32],
            tx_origin: [0u8; 20],
            block_timestamp: 0,
            block_number: 0,
            this_balance: [0u8; 32],
            variables: vec![],
        };
        let hex: String = w.msg_sender.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex.len(), 40, "20-byte address must produce 40 hex chars");
        assert_eq!(
            hex,
            "0".repeat(40),
            "all-zero sender must produce 40 zero hex chars"
        );
    }

    #[test]
    fn test_witness_known_sender_hex_roundtrip() {
        // Verify the exact hex output for a known msg_sender value — the same
        // formatting that print_se_text uses when printing the witness line.
        let mut sender = [0u8; 20];
        sender[18] = 0xca;
        sender[19] = 0xfe;
        let w = Witness {
            msg_sender: sender,
            msg_value: [0u8; 32],
            tx_origin: [0u8; 20],
            block_timestamp: 0,
            block_number: 0,
            this_balance: [0u8; 32],
            variables: vec![],
        };
        let hex: String = w.msg_sender.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            hex.ends_with("cafe"),
            "last two bytes must appear as 'cafe'"
        );
        assert_eq!(hex.len(), 40);
    }
}
