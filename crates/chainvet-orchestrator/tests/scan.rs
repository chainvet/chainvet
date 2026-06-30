//! Orchestrator facade tests: each mode returns typed findings, and hybrid mode
//! matches the CLI's deduplicated finding count (the parity anchor).

use chainvet_orchestrator::{HybridBudget, ScanMode, scan_path};

const REENTRANCY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../chainvet-cli/tests/fixtures/vuln_reentrancy.sol"
);

#[test]
fn hybrid_scan_matches_cli_finding_count() {
    let r = scan_path(REENTRANCY, ScanMode::Hybrid, &HybridBudget::default()).unwrap();
    assert!(r.hybrid.is_some(), "hybrid mode carries run telemetry");
    // The CLI's `--hybrid --json` reports 24 deduplicated findings on this fixture.
    assert_eq!(
        r.findings.len(),
        24,
        "orchestrator hybrid findings must match the CLI"
    );
}

#[test]
fn static_scan_returns_static_only_findings() {
    let r = scan_path(REENTRANCY, ScanMode::Static, &HybridBudget::default()).unwrap();
    assert!(
        r.hybrid.is_none(),
        "non-hybrid modes carry no hybrid telemetry"
    );
    assert!(
        !r.findings.is_empty(),
        "static analysis finds the reentrancy"
    );
    assert!(r.findings.iter().all(|f| f.provenance == "static"));
}
