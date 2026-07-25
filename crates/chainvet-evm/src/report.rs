//! The differential report: the capstone of the EVM validation layer. It takes
//! what the IR-level fuzzer produced — its findings' triggering transaction
//! sequences and its corpus — and replays them on a real EVM to answer two
//! questions the IR interpreter cannot answer about itself:
//!
//!   1. **Reproducibility** — does a finding's exact triggering sequence still
//!      deploy and reach a non-reverting terminal transaction on a real EVM?
//!      A sequence that fully reverts (or fails to deploy) is a *divergence*
//!      candidate: the IR interpreter reached a state a real EVM would not.
//!   2. **Coverage delta** — how many distinct EVM program counters the corpus
//!      actually reaches. This is a real-EVM measure alongside the interpreter's
//!      IR-block coverage; the two use different denominators, so this reports
//!      the raw EVM figure rather than pretending it is the same percentage.
//!
//! This is deliberately a *measurement*, not a re-proof: confirming, say, a
//! reentrancy property on the EVM needs a full oracle, which is out of scope for
//! this layer. What it gives is an honest fidelity signal over real executions.

use std::collections::HashSet;

use chainvet_fuzzing::fuzzing::types::{ContractAbi, Environment, Individual, Transaction};

use crate::artifact::CompiledContract;
use crate::replay::{IndividualReplay, TxStatus, replay_individual_covered};

/// The EVM's verdict on replaying a finding's triggering sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingReplayVerdict {
    /// Deployed and the terminal replayed transaction executed without
    /// reverting — behavior consistent with the reported finding.
    Consistent,
    /// Deployed, but the terminal transaction reverted/halted on the real EVM —
    /// the IR-interpreter path may not be reachable on a real EVM.
    Divergent,
    /// Could not be evaluated (deploy failed, or no transaction was replayable
    /// because of unknown ids / unsupported argument types); carries the reason.
    Inconclusive(String),
}

/// One finding replayed on the EVM.
#[derive(Debug, Clone)]
pub struct FindingReplay {
    pub kind: String,
    pub message: String,
    pub verdict: FindingReplayVerdict,
    /// Distinct EVM PCs reached while replaying this finding's sequence.
    pub covered_pcs: usize,
    pub replay: IndividualReplay,
}

/// The aggregate differential report for one compiled contract.
#[derive(Debug, Clone)]
pub struct EvmDiffReport {
    pub contract: String,
    pub findings: Vec<FindingReplay>,
    /// Individuals in the replayed corpus.
    pub corpus_individuals: usize,
    /// How many of them deployed successfully.
    pub corpus_deployed: usize,
    /// Union of distinct EVM PCs reached across the whole corpus — the real-EVM
    /// coverage figure to weigh against the interpreter's IR-block coverage.
    pub corpus_covered_pcs: usize,
}

impl EvmDiffReport {
    pub fn consistent_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.verdict == FindingReplayVerdict::Consistent)
            .count()
    }
    pub fn divergent_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.verdict == FindingReplayVerdict::Divergent)
            .count()
    }
    pub fn inconclusive_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| matches!(f.verdict, FindingReplayVerdict::Inconclusive(_)))
            .count()
    }
}

/// Wrap a bare transaction sequence into an [`Individual`] for replay.
fn individual_from_sequence(txs: &[Transaction]) -> Individual {
    Individual {
        transactions: txs.to_vec(),
        environment: Environment::default(),
        energy: 1.0,
    }
}

/// Replay one finding's triggering sequence and classify the EVM's behavior.
pub fn replay_finding(
    compiled: &CompiledContract,
    fuzzer_abi: &ContractAbi,
    kind: &str,
    message: &str,
    tx_sequence: &[Transaction],
) -> FindingReplay {
    let individual = individual_from_sequence(tx_sequence);
    let (replay, _pcs) = replay_individual_covered(compiled, fuzzer_abi, &individual);
    let verdict = classify(&replay);
    FindingReplay {
        kind: kind.to_string(),
        message: message.to_string(),
        verdict,
        covered_pcs: replay.covered_pcs,
        replay,
    }
}

/// Classify a replay: look at the terminal *replayed* (non-skipped) transaction.
fn classify(replay: &IndividualReplay) -> FindingReplayVerdict {
    if !replay.deployed {
        return FindingReplayVerdict::Inconclusive("deployment failed on the EVM".to_string());
    }
    let terminal = replay
        .txs
        .iter()
        .rev()
        .find(|t| !matches!(t.status, TxStatus::Skipped(_)));
    match terminal {
        Some(t) => match t.status {
            TxStatus::Success => FindingReplayVerdict::Consistent,
            TxStatus::Reverted => FindingReplayVerdict::Divergent,
            TxStatus::Skipped(_) => unreachable!("filtered out above"),
        },
        None => FindingReplayVerdict::Inconclusive(
            "no transaction was replayable (unknown ids or unsupported types)".to_string(),
        ),
    }
}

/// Build the full differential report: replay every finding's sequence, then
/// replay the corpus to accumulate union EVM coverage.
pub fn diff_report(
    compiled: &CompiledContract,
    fuzzer_abi: &ContractAbi,
    findings: &[(String, String, Vec<Transaction>)],
    corpus: &[Individual],
) -> EvmDiffReport {
    let findings: Vec<FindingReplay> = findings
        .iter()
        .map(|(kind, message, seq)| replay_finding(compiled, fuzzer_abi, kind, message, seq))
        .collect();

    let mut union: HashSet<usize> = HashSet::new();
    let mut deployed = 0usize;
    for individual in corpus {
        let (replay, pcs) = replay_individual_covered(compiled, fuzzer_abi, individual);
        if replay.deployed {
            deployed += 1;
        }
        union.extend(pcs);
    }

    EvmDiffReport {
        contract: compiled.name.clone(),
        findings,
        corpus_individuals: corpus.len(),
        corpus_deployed: deployed,
        corpus_covered_pcs: union.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::AbiType;
    use crate::artifact::AbiFn;
    use chainvet_core::norm::{FunctionKind, Mutability, Visibility};
    use chainvet_fuzzing::fuzzing::types::{FunctionAbi, FuzzValue};

    fn creation_code(runtime: &[u8]) -> Vec<u8> {
        let len = runtime.len() as u8;
        let mut code = vec![
            0x60, len, 0x80, 0x60, 0x0b, 0x60, 0x00, 0x39, 0x60, 0x00, 0xf3,
        ];
        code.extend_from_slice(runtime);
        code
    }

    fn abi(id: u32, name: &str) -> ContractAbi {
        ContractAbi {
            contract_name: "C".to_string(),
            functions: vec![FunctionAbi {
                id,
                name: name.to_string(),
                params: Vec::new(),
                visibility: Visibility::External,
                mutability: Mutability::NonPayable,
                kind: FunctionKind::Function,
                is_payable: false,
            }],
        }
    }

    fn compiled(runtime: &[u8]) -> CompiledContract {
        CompiledContract {
            name: "C".to_string(),
            creation_bytecode: creation_code(runtime),
            functions: vec![AbiFn {
                name: "f".to_string(),
                inputs: vec![AbiType::Uint(256)],
            }],
        }
    }

    fn tx() -> Transaction {
        Transaction {
            function_id: 0,
            args: vec![FuzzValue::Uint(1)],
            sender: 1,
            value: 0,
        }
    }

    #[test]
    fn successful_terminal_tx_is_consistent() {
        let runtime = [0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]; // returns 42
        let fr = replay_finding(
            &compiled(&runtime),
            &abi(0, "f"),
            "Reentrancy",
            "msg",
            &[tx()],
        );
        assert_eq!(fr.verdict, FindingReplayVerdict::Consistent);
        assert!(fr.covered_pcs > 0);
    }

    #[test]
    fn reverting_terminal_tx_is_divergent() {
        let runtime = [0x60, 0x00, 0x60, 0x00, 0xfd]; // always REVERT
        let fr = replay_finding(
            &compiled(&runtime),
            &abi(0, "f"),
            "Overflow",
            "msg",
            &[tx()],
        );
        assert_eq!(fr.verdict, FindingReplayVerdict::Divergent);
    }

    #[test]
    fn unknown_function_is_inconclusive() {
        let runtime = [0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        // function_id 9 is not in the ABI → the only tx is skipped → inconclusive.
        let bad = Transaction {
            function_id: 9,
            args: vec![],
            sender: 1,
            value: 0,
        };
        let fr = replay_finding(&compiled(&runtime), &abi(0, "f"), "K", "m", &[bad]);
        assert!(matches!(fr.verdict, FindingReplayVerdict::Inconclusive(_)));
    }

    #[test]
    fn diff_report_unions_corpus_coverage() {
        let runtime = [0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        let corpus = vec![
            individual_from_sequence(&[tx()]),
            individual_from_sequence(&[tx(), tx()]),
        ];
        let report = diff_report(&compiled(&runtime), &abi(0, "f"), &[], &corpus);
        assert_eq!(report.corpus_individuals, 2);
        assert_eq!(report.corpus_deployed, 2);
        assert!(report.corpus_covered_pcs > 0, "corpus reached real EVM PCs");
    }
}
