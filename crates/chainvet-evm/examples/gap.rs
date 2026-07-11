//! IR-vs-EVM fidelity gap measurement.
//!
//! Runs the coverage-guided fuzzer (the IR-level interpreter) on a contract,
//! then replays its prized corpus and its findings on a real EVM (revm), and
//! reports where the two engines *disagree*. The point is to answer one
//! question with numbers instead of intuition: **is the IR interpreter faithful
//! enough, or is it exploring a contract that does not exist on a real EVM?**
//!
//! The headline metric is per-input agreement on the SAME sequence:
//!   - IR says the sequence completes, EVM agrees            → faithful
//!   - IR says it reverts, EVM agrees                         → faithful
//!   - IR completes but EVM reverts  (IR too optimistic)     → false coverage / false-positive risk
//!   - IR reverts but EVM completes  (IR too pessimistic)    → missed paths / false-negative risk
//!
//! Usage:
//!   cargo run -p chainvet-evm --example gap -- <path.sol>

use std::collections::HashSet;

use chainvet_core::{cfg, ir};
use chainvet_evm::replay::TxStatus;
use chainvet_evm::report::{replay_finding, FindingReplayVerdict};
use chainvet_evm::{compile, replay_individual_covered};
use chainvet_frontend::frontend;
use chainvet_fuzzing::fuzzing::executor::execute_individual;
use chainvet_fuzzing::fuzzing::runner::FuzzSession;
use chainvet_fuzzing::fuzzing::types::{
    build_dependency_map, extract_abis, ContractAbi, FuzzConfig, Individual,
};

/// Agreement tally between the IR interpreter and the EVM over one corpus.
#[derive(Default)]
struct Agreement {
    agree_complete: usize,   // both ran to completion
    agree_revert: usize,     // both reverted
    ir_opt_evm_revert: usize, // IR completed, EVM reverted (optimistic IR)
    ir_pess_evm_ok: usize,   // IR reverted, EVM completed (pessimistic IR)
    deploy_failed: usize,    // EVM could not deploy (e.g. constructor needs args)
    unreplayable: usize,     // every tx skipped (encoder gap / unknown ids)
}

impl Agreement {
    fn compared(&self) -> usize {
        self.agree_complete + self.agree_revert + self.ir_opt_evm_revert + self.ir_pess_evm_ok
    }
    fn agree(&self) -> usize {
        self.agree_complete + self.agree_revert
    }
    fn diverge(&self) -> usize {
        self.ir_opt_evm_revert + self.ir_pess_evm_ok
    }
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: cargo run -p chainvet-evm --example gap -- <path.sol>");
        std::process::exit(2);
    });

    // --- Parse + compile ---------------------------------------------------
    let output = frontend::load_project(&path).expect("frontend parse");
    let sources = frontend::collect_target_sources(&path).expect("collect sources");
    let compiled = match compile(&sources) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("solc compile failed: {e}");
            std::process::exit(1);
        }
    };

    // Locally rebuild what the IR re-execution needs (deterministic lowering,
    // identical to what the session uses internally).
    let ir_module = ir::lower_module(&output.ast);
    let cfgs = cfg::build_from_ir(&ir_module);
    let deps = build_dependency_map(&ir_module, &output.ast);
    let abis = extract_abis(&output.ast, &output.compiler);

    // --- Run the fuzzer (IR interpreter) -----------------------------------
    let budget = Some(5000u64);
    let config = FuzzConfig {
        seed: Some(0xC0FFEE), // deterministic
        max_duration_ms: budget,
        ..Default::default()
    };
    let iters = config.max_iterations.max(2000);

    let mut session = FuzzSession::new(&output, config);
    session.run_slice(&[], iters, budget);

    // Snapshot the IR side before finalize consumes the session.
    let corpus: Vec<Individual> =
        session.corpus().entries.iter().map(|e| e.individual.clone()).collect();
    let ir_covered = session.covered_block_set().len();
    let ir_total = session.reachable_block_total();
    let report = session.finalize();

    println!("== IR-vs-EVM fidelity gap: {path} ==\n");
    println!("Contracts compiled: {}", compiled.len());
    println!(
        "IR block coverage : {:.1}%  ({ir_covered}/{ir_total} reachable blocks)",
        report.coverage_pct
    );
    println!("Corpus size       : {}", corpus.len());
    println!("IR findings       : {}\n", report.findings.len());

    // --- Per-input agreement over the corpus -------------------------------
    let mut agg = Agreement::default();
    let mut evm_pcs: HashSet<usize> = HashSet::new();

    for ind in &corpus {
        let Some(abi_idx) = abi_for_individual(&abis, ind) else {
            continue;
        };
        let abi = &abis[abi_idx];
        let Some(compiled_c) = compiled.iter().find(|c| c.name == abi.contract_name) else {
            continue;
        };

        // IR side: does the sequence revert anywhere?
        let ir_trace = execute_individual(ind, &output, &ir_module, &cfgs, abi, &deps);
        let ir_reverted = ir_trace.reverted;

        // EVM side.
        let (replay, pcs) = replay_individual_covered(compiled_c, abi, ind);
        evm_pcs.extend(pcs);
        if !replay.deployed {
            agg.deploy_failed += 1;
            continue;
        }
        let replayable: Vec<&TxStatus> = replay
            .txs
            .iter()
            .map(|t| &t.status)
            .filter(|s| !matches!(s, TxStatus::Skipped(_)))
            .collect();
        if replayable.is_empty() {
            agg.unreplayable += 1;
            continue;
        }
        let evm_reverted = replayable.iter().any(|s| matches!(s, TxStatus::Reverted));

        match (ir_reverted, evm_reverted) {
            (false, false) => agg.agree_complete += 1,
            (true, true) => agg.agree_revert += 1,
            (false, true) => agg.ir_opt_evm_revert += 1,
            (true, false) => agg.ir_pess_evm_ok += 1,
        }
    }

    print_agreement(&agg, evm_pcs.len());

    // --- Finding fidelity --------------------------------------------------
    let mut consistent = 0usize;
    let mut divergent = 0usize;
    let mut inconclusive = 0usize;
    println!("\n-- Finding fidelity (each finding's triggering sequence, replayed on EVM) --");
    if report.findings.is_empty() {
        println!("  (no fuzzer findings to replay)");
    }
    for f in &report.findings {
        let Some(abi_idx) = f
            .tx_sequence
            .first()
            .and_then(|tx| abi_for_fn(&abis, tx.function_id))
        else {
            inconclusive += 1;
            continue;
        };
        let abi = &abis[abi_idx];
        let Some(compiled_c) = compiled.iter().find(|c| c.name == abi.contract_name) else {
            inconclusive += 1;
            continue;
        };
        let fr = replay_finding(compiled_c, abi, f.kind.as_str(), &f.message, &f.tx_sequence);
        let tag = match &fr.verdict {
            FindingReplayVerdict::Consistent => {
                consistent += 1;
                "consistent"
            }
            FindingReplayVerdict::Divergent => {
                divergent += 1;
                "DIVERGENT "
            }
            FindingReplayVerdict::Inconclusive(_) => {
                inconclusive += 1;
                "inconclusive"
            }
        };
        println!("  [{tag}] {} — {}", f.kind.as_str(), truncate(&f.message, 60));
    }
    println!(
        "\n  findings: {consistent} consistent, {divergent} divergent, {inconclusive} inconclusive"
    );

    // --- Verdict -----------------------------------------------------------
    print_recommendation(&agg, divergent, report.findings.len());
}

fn print_agreement(agg: &Agreement, evm_pc_union: usize) {
    println!("-- Per-input agreement (same sequence run on both engines) --");
    println!("  both complete         : {}", agg.agree_complete);
    println!("  both revert           : {}", agg.agree_revert);
    println!("  IR ok / EVM revert    : {}  (IR too optimistic)", agg.ir_opt_evm_revert);
    println!("  IR revert / EVM ok    : {}  (IR too pessimistic)", agg.ir_pess_evm_ok);
    println!("  ---");
    println!("  EVM deploy failed     : {}  (excluded — e.g. constructor args)", agg.deploy_failed);
    println!("  unreplayable (skipped): {}  (excluded — encoder/type gaps)", agg.unreplayable);
    let compared = agg.compared();
    if compared > 0 {
        let rate = 100.0 * agg.agree() as f64 / compared as f64;
        println!(
            "  => agreement {:.1}%  ({}/{} comparable inputs), divergence {}",
            rate,
            agg.agree(),
            compared,
            agg.diverge()
        );
    } else {
        println!("  => no comparable inputs (nothing deployed & replayed on the EVM)");
    }
    println!("  EVM PC union (corpus) : {evm_pc_union}");
}

fn print_recommendation(agg: &Agreement, divergent_findings: usize, total_findings: usize) {
    println!("\n== Is the EVM switch worth it? ==");
    let compared = agg.compared();
    let deploy_blocked = agg.deploy_failed;
    let unreplayable = agg.unreplayable;

    if compared == 0 {
        println!(
            "  INSUFFICIENT SIGNAL: no corpus input both deployed and replayed on the EVM \
             ({deploy_blocked} deploy-failed, {unreplayable} unreplayable). The gap can't be \
             measured on this contract — likely a constructor-args or unsupported-type gap in \
             the validation layer, not an IR-vs-EVM finding."
        );
        return;
    }

    let divergence = 100.0 * agg.diverge() as f64 / compared as f64;
    let finding_div = if total_findings > 0 {
        100.0 * divergent_findings as f64 / total_findings as f64
    } else {
        0.0
    };

    println!("  input divergence   : {divergence:.1}%");
    println!("  finding divergence : {finding_div:.1}%  ({divergent_findings}/{total_findings})");
    println!();
    if divergence < 5.0 && finding_div < 10.0 {
        println!(
            "  VERDICT: the IR interpreter tracks the real EVM closely here. A wholesale switch \
             is likely NOT worth its cost (revm build weight, per-run compile, slower execution). \
             Keep the IR engine; use this EVM layer only to validate/triage findings."
        );
    } else if divergence < 20.0 {
        println!(
            "  VERDICT: a moderate gap. The IR engine is mostly faithful but diverges on a real \
             minority of inputs. Prefer the targeted layer — replay findings + hot corpus inputs \
             on the EVM to prune false positives — over replacing the interpreter."
        );
    } else {
        println!(
            "  VERDICT: a large gap. The IR interpreter is exploring behavior the real EVM does \
             not reproduce; coverage and findings are being inflated by IR imprecision. Migrating \
             fuzzer execution behind an EVM backend is likely worth the cost — proceed to Step 2."
        );
    }
    println!(
        "\n  (Caveat: EVM deploy-failed [{deploy_blocked}] and unreplayable [{unreplayable}] inputs \
         are excluded; a large count there is a validation-layer limitation, not an IR verdict.)"
    );
}

/// Index of the ABI that declares `fid`, if any.
fn abi_for_fn(abis: &[ContractAbi], fid: u32) -> Option<usize> {
    abis.iter().position(|a| a.functions.iter().any(|f| f.id == fid))
}

/// Index of the ABI an individual targets, inferred from its first transaction.
fn abi_for_individual(abis: &[ContractAbi], ind: &Individual) -> Option<usize> {
    ind.transactions.first().and_then(|tx| abi_for_fn(abis, tx.function_id))
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}
