//! Replay fuzzer inputs against the real EVM. Each [`Individual`] is a fresh
//! deployment followed by its transaction sequence (state persists across the
//! sequence, so multi-transaction setup chains behave as on-chain). The result
//! is the per-transaction EVM outcome — the signal for confirming or refuting
//! IR-interpreter findings and comparing behavior.

use std::collections::HashSet;

use chainvet_fuzzing::fuzzing::types::{ContractAbi, Individual};

use crate::abi::encode_call;
use crate::artifact::CompiledContract;
use crate::harness::EvmHarness;

/// What happened to one replayed transaction on the EVM.
#[derive(Debug, Clone)]
pub enum TxStatus {
    /// Executed without reverting.
    Success,
    /// Reverted or halted on the real EVM.
    Reverted,
    /// Not replayed (unknown function, no matching ABI overload, or an argument
    /// whose type the encoder does not support); carries the reason.
    Skipped(String),
}

#[derive(Debug, Clone)]
pub struct TxReplay {
    pub function: String,
    pub status: TxStatus,
    pub gas_used: u64,
}

#[derive(Debug, Clone)]
pub struct IndividualReplay {
    /// False when deployment itself reverted/failed (nothing was replayed).
    pub deployed: bool,
    pub txs: Vec<TxReplay>,
    /// Distinct EVM program counters executed across the whole sequence
    /// (constructor excluded). The real-EVM coverage reached by this input,
    /// to compare against the IR interpreter's coverage.
    pub covered_pcs: usize,
}

impl IndividualReplay {
    pub fn success_count(&self) -> usize {
        self.txs
            .iter()
            .filter(|t| matches!(t.status, TxStatus::Success))
            .count()
    }
    pub fn reverted_count(&self) -> usize {
        self.txs
            .iter()
            .filter(|t| matches!(t.status, TxStatus::Reverted))
            .count()
    }
    pub fn skipped_count(&self) -> usize {
        self.txs
            .iter()
            .filter(|t| matches!(t.status, TxStatus::Skipped(_)))
            .count()
    }
}

/// Replay one individual against a freshly deployed instance of `compiled`.
/// `fuzzer_abi` maps the fuzzer's `function_id`s to names, which are matched to
/// the compiled ABI (by name + arity, so overloads resolve).
pub fn replay_individual(
    compiled: &CompiledContract,
    fuzzer_abi: &ContractAbi,
    individual: &Individual,
) -> IndividualReplay {
    replay_individual_covered(compiled, fuzzer_abi, individual).0
}

/// As [`replay_individual`], but also returns the exact set of EVM program
/// counters reached. Deployment is deterministic (same bytecode, deployer, and
/// nonce → same contract address), so PC sets from separate individuals are
/// directly comparable and can be unioned into corpus-wide EVM coverage.
pub fn replay_individual_covered(
    compiled: &CompiledContract,
    fuzzer_abi: &ContractAbi,
    individual: &Individual,
) -> (IndividualReplay, HashSet<usize>) {
    let mut harness = match EvmHarness::deploy(compiled.creation_bytecode.clone()) {
        Ok(h) => h,
        Err(_) => {
            return (
                IndividualReplay {
                    deployed: false,
                    txs: Vec::new(),
                    covered_pcs: 0,
                },
                HashSet::new(),
            );
        }
    };

    let mut txs = Vec::new();
    for tx in &individual.transactions {
        let name = fuzzer_abi
            .functions
            .iter()
            .find(|f| f.id == tx.function_id)
            .map(|f| f.name.clone());
        let Some(name) = name else {
            txs.push(TxReplay {
                function: format!("#{}", tx.function_id),
                status: TxStatus::Skipped("unknown function id".to_string()),
                gas_used: 0,
            });
            continue;
        };

        // Match the compiled ABI by name + arity (resolves overloads).
        let abi_fn = compiled
            .functions
            .iter()
            .find(|f| f.name == name && f.inputs.len() == tx.args.len());
        let Some(abi_fn) = abi_fn else {
            txs.push(TxReplay {
                function: name,
                status: TxStatus::Skipped(
                    "no matching ABI (overload or unsupported types)".to_string(),
                ),
                gas_used: 0,
            });
            continue;
        };

        let Some(calldata) = encode_call(&abi_fn.name, &abi_fn.inputs, &tx.args) else {
            txs.push(TxReplay {
                function: name,
                status: TxStatus::Skipped("argument encoding failed".to_string()),
                gas_used: 0,
            });
            continue;
        };

        match harness.call(tx.sender, tx.value, calldata) {
            Ok(outcome) => txs.push(TxReplay {
                function: name,
                status: if outcome.success {
                    TxStatus::Success
                } else {
                    TxStatus::Reverted
                },
                gas_used: outcome.gas_used,
            }),
            Err(e) => txs.push(TxReplay {
                function: name,
                status: TxStatus::Skipped(format!("evm error: {e:?}")),
                gas_used: 0,
            }),
        }
    }

    let covered = harness.covered_pcs().clone();
    (
        IndividualReplay {
            deployed: true,
            covered_pcs: covered.len(),
            txs,
        },
        covered,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::AbiType;
    use crate::artifact::AbiFn;
    use chainvet_core::norm::{FunctionKind, Mutability, Visibility};
    use chainvet_fuzzing::fuzzing::types::{
        Environment, FunctionAbi, FuzzValue, Individual, Transaction,
    };

    /// Minimal constructor that returns `runtime` as the deployed code.
    fn creation_code(runtime: &[u8]) -> Vec<u8> {
        let len = runtime.len() as u8;
        let mut code = vec![
            0x60, len, 0x80, 0x60, 0x0b, 0x60, 0x00, 0x39, 0x60, 0x00, 0xf3,
        ];
        code.extend_from_slice(runtime);
        code
    }

    fn fuzzer_abi(id: u32, name: &str) -> ContractAbi {
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

    #[test]
    fn replay_maps_and_executes_a_transaction() {
        // Runtime returns 42 for any call.
        let runtime = [0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        let compiled = CompiledContract {
            name: "C".to_string(),
            creation_bytecode: creation_code(&runtime),
            functions: vec![AbiFn {
                name: "f".to_string(),
                inputs: vec![AbiType::Uint(256)],
            }],
        };
        let individual = Individual {
            transactions: vec![Transaction {
                function_id: 0,
                args: vec![FuzzValue::Uint(7)],
                sender: 1,
                value: 0,
            }],
            environment: Environment::default(),
            energy: 1.0,
        };
        let result = replay_individual(&compiled, &fuzzer_abi(0, "f"), &individual);
        assert!(result.deployed);
        assert_eq!(result.success_count(), 1, "the mapped call executed");
        assert_eq!(result.reverted_count(), 0);
        assert!(
            result.covered_pcs > 0,
            "EVM coverage was recorded for the sequence"
        );
    }

    #[test]
    fn reverting_runtime_is_reported_and_unknown_fn_skipped() {
        let runtime = [0x60, 0x00, 0x60, 0x00, 0xfd]; // always REVERT
        let compiled = CompiledContract {
            name: "C".to_string(),
            creation_bytecode: creation_code(&runtime),
            functions: vec![AbiFn {
                name: "f".to_string(),
                inputs: Vec::new(),
            }],
        };
        let individual = Individual {
            transactions: vec![
                Transaction {
                    function_id: 0,
                    args: vec![],
                    sender: 1,
                    value: 0,
                },
                // function_id 9 is not in the fuzzer ABI → skipped.
                Transaction {
                    function_id: 9,
                    args: vec![],
                    sender: 1,
                    value: 0,
                },
            ],
            environment: Environment::default(),
            energy: 1.0,
        };
        let result = replay_individual(&compiled, &fuzzer_abi(0, "f"), &individual);
        assert_eq!(result.reverted_count(), 1, "revert detected");
        assert_eq!(result.skipped_count(), 1, "unknown function id skipped");
    }
}
