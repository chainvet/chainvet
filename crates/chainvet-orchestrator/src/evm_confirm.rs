//! Opt-in EVM confirmation of fuzzer findings.
//!
//! The IR-level fuzzer can report a finding on a path a real EVM never takes
//! (measured: ~half of conclusively-replayable findings on stateful contracts
//! don't reproduce on revm). This layer replays each finding's triggering
//! `tx_sequence` on a real EVM and annotates the corresponding rows:
//!
//! - reproduces (terminal tx executes) → provenance `evm-confirmed`
//! - reverts on the real EVM → provenance `evm-divergent`, and a `confirmed`
//!   tier is downgraded to `candidate` (likely false positive)
//! - couldn't be replayed → provenance `evm-inconclusive`
//!
//! It is doubly gated: compiled only with the `evm-validation` cargo feature
//! (which pulls in revm), and at runtime only when `CHAINVET_EVM_CONFIRM` is
//! set. Default builds and default runs are completely unaffected — the JSON
//! report is byte-identical unless a user opts in.

use chainvet_fuzzing::fuzzing::types::{ContractAbi, FuzzFinding};

use crate::ScanResult;

/// No-op when the EVM validation layer isn't compiled in. Keeps `scan`'s call
/// site unconditional so the raw findings/ABIs are never "unused".
#[cfg(not(feature = "evm-validation"))]
pub fn enhance(
    _result: &mut ScanResult,
    _output: &chainvet_frontend::frontend::FrontendOutput,
    _fuzz_findings: &[FuzzFinding],
    _abis: &[ContractAbi],
) {
}

#[cfg(feature = "evm-validation")]
pub fn enhance(
    result: &mut ScanResult,
    output: &chainvet_frontend::frontend::FrontendOutput,
    fuzz_findings: &[FuzzFinding],
    abis: &[ContractAbi],
) {
    if !enabled() || fuzz_findings.is_empty() {
        return;
    }

    // Compile the sources to real bytecode. If solc isn't available or the
    // sources don't compile, this layer silently stands down — it must never
    // break a scan that would otherwise succeed.
    let compiled = match chainvet_evm::compile(&output.ast.files) {
        Ok(c) if !c.is_empty() => c,
        _ => return,
    };

    // Compute the EVM verdict per finding, keyed by message.
    let mut annotations: Vec<(String, &'static str)> = Vec::new();
    for finding in fuzz_findings {
        // Which contract does this finding's sequence target?
        let Some(abi) = finding.tx_sequence.first().and_then(|tx| {
            abis.iter()
                .find(|a| a.functions.iter().any(|f| f.id == tx.function_id))
        }) else {
            continue;
        };
        let Some(compiled_c) = compiled.iter().find(|c| c.name == abi.contract_name) else {
            continue;
        };

        let replay = chainvet_evm::replay_finding(
            compiled_c,
            abi,
            finding.kind.as_str(),
            &finding.message,
            &finding.tx_sequence,
        );
        let tag = match replay.verdict {
            chainvet_evm::FindingReplayVerdict::Consistent => "evm-confirmed",
            chainvet_evm::FindingReplayVerdict::Divergent => "evm-divergent",
            chainvet_evm::FindingReplayVerdict::Inconclusive(_) => "evm-inconclusive",
        };
        annotations.push((finding.message.clone(), tag));
    }

    // Apply to the shared rows AND the hybrid payload's copy, so the
    // benchmark-consumed `HybridJsonReport` reflects the same demotions
    // (mirrors how ai_report keeps the two finding lists in sync).
    annotate_rows(&mut result.findings, &annotations);
    if let Some(hybrid) = result.hybrid.as_mut() {
        annotate_rows(&mut hybrid.findings, &annotations);
    }
}

/// Annotate every fuzz-provenance row whose message matches an EVM verdict.
#[cfg(feature = "evm-validation")]
fn annotate_rows(
    rows: &mut [chainvet_hybrid::hybrid::HybridFindingRow],
    annotations: &[(String, &'static str)],
) {
    for row in rows.iter_mut() {
        let is_fuzz = row.provenance == "fuzz" || row.provenance == "hybrid-confirmed";
        if !is_fuzz {
            continue;
        }
        let Some((_, tag)) = annotations.iter().find(|(msg, _)| *msg == row.message) else {
            continue;
        };
        if !row.provenances.iter().any(|p| p == tag) {
            row.provenances.push((*tag).to_string());
        }
        // Demote only *pure fuzz* findings the real EVM refutes — those are the
        // likeliest false positives. Lower their confidence to `low` (rows no
        // longer carry a separate tier). A `hybrid-confirmed` finding has
        // independent static/SE corroboration (and SE may reach it by a path
        // the fuzzer's sequence doesn't represent), so we annotate it but leave
        // its confidence; the benchmark can still see the `evm-divergent` flag.
        if *tag == "evm-divergent" && row.provenance == "fuzz" {
            row.confidence = Some("low".to_string());
        }
    }
}

/// Truthy check for the `CHAINVET_EVM_CONFIRM` runtime gate.
#[cfg(feature = "evm-validation")]
fn enabled() -> bool {
    match std::env::var("CHAINVET_EVM_CONFIRM") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !(v.is_empty() || v == "0" || v == "false" || v == "no")
        }
        Err(_) => false,
    }
}
