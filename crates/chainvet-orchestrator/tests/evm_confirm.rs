//! End-to-end check of the opt-in EVM confirmation layer. Runs a real scan with
//! `CHAINVET_EVM_CONFIRM` set and asserts fuzzer findings get EVM-provenance
//! annotations. Meaningful only when built with the `evm-validation` feature and
//! `#[ignore]`d because it invokes solc + revm:
//!
//!   cargo test -p chainvet-orchestrator --features evm-validation \
//!       --test evm_confirm -- --ignored --nocapture

#[cfg(feature = "evm-validation")]
#[test]
#[ignore = "invokes solc + revm; run with --features evm-validation --ignored"]
fn evm_layer_annotates_fuzz_findings() {
    use chainvet_frontend::frontend;
    use chainvet_orchestrator::{scan, HybridBudget, ScanMode};

    // The reentrancy fixture is a stateful pool whose fuzzer findings do NOT
    // reproduce on a real EVM (state-machine + msg.value gating), so they should
    // come back flagged `evm-divergent` and demoted out of the confirmed tier.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../chainvet-cli/tests/fixtures/vuln_reentrancy.sol"
    );

    // SAFETY: single-threaded test process; no other thread reads the env here.
    unsafe {
        std::env::set_var("CHAINVET_EVM_CONFIRM", "1");
    }

    let output = frontend::load_project(path).expect("parse");
    let result = scan(&output, ScanMode::Hybrid, &HybridBudget::default()).expect("scan");

    // The benchmark consumes the HybridJsonReport (result.hybrid); assert the
    // annotations reached *that* copy, not just result.findings.
    let hybrid = result.hybrid.as_ref().expect("hybrid payload present");
    let fuzz_rows: Vec<_> = hybrid
        .findings
        .iter()
        .filter(|r| r.provenance == "fuzz" || r.provenance == "hybrid-confirmed")
        .collect();
    println!("fuzz rows in HybridJsonReport: {}", fuzz_rows.len());

    if fuzz_rows.is_empty() {
        // Nothing for the layer to confirm this run; the path still executed.
        return;
    }

    let annotated = fuzz_rows
        .iter()
        .filter(|r| r.provenances.iter().any(|p| p.starts_with("evm-")))
        .count();
    for r in &fuzz_rows {
        println!("  [{}] {} :: {:?}", r.tier, r.kind, r.provenances);
    }
    assert!(
        annotated > 0,
        "the EVM layer should annotate fuzz findings in the hybrid payload"
    );
}
