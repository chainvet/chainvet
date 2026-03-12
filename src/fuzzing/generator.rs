use rand::Rng;

use crate::fuzzing::types::{
    ContractAbi, DependencyMap, Dictionary, Environment, FuzzConfig, FuzzValue, Individual,
    Transaction,
};
use crate::ir::IrModule;

/// Magic numbers commonly effective at finding integer edge cases.
const MAGIC_UINTS: &[u128] = &[
    0,
    1,
    2,
    0xFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF,
    0x7FFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    u128::MAX / 2,
    u128::MAX - 1,
    u128::MAX,
];

/// Generate a random FuzzValue for a parameter, optionally using dictionary values.
pub(crate) fn random_value(rng: &mut impl Rng) -> FuzzValue {
    random_value_with_dict(rng, None)
}

/// Generate a random FuzzValue, using dictionary constants when available.
pub(crate) fn random_value_with_dict(rng: &mut impl Rng, dict: Option<&Dictionary>) -> FuzzValue {
    let strategy: u32 = rng.gen_range(0..12);
    match strategy {
        // 33% chance: magic number
        0..=3 => {
            let idx = rng.gen_range(0..MAGIC_UINTS.len());
            FuzzValue::Uint(MAGIC_UINTS[idx])
        }
        // 25% chance: small random
        4..=6 => FuzzValue::Uint(rng.gen_range(0..10_000)),
        // 17% chance: large random
        7..=8 => FuzzValue::Uint(rng.gen_range(0..u128::MAX)),
        // 8% chance: bool
        9 => FuzzValue::Bool(rng.gen_bool(0.5)),
        // 17% chance: dictionary value (falls back to magic number if no dict)
        _ => {
            if let Some(dict) = dict {
                if !dict.values.is_empty() {
                    let idx = rng.gen_range(0..dict.values.len());
                    return FuzzValue::Uint(dict.values[idx]);
                }
            }
            // Fallback to magic number
            let idx = rng.gen_range(0..MAGIC_UINTS.len());
            FuzzValue::Uint(MAGIC_UINTS[idx])
        }
    }
}

/// Generate a random address index into the address pool.
fn random_sender(rng: &mut impl Rng, pool_size: usize) -> usize {
    rng.gen_range(0..pool_size)
}

/// Generate a random Ether value for payable functions.
fn random_value_amount(rng: &mut impl Rng) -> u128 {
    let strategy: u32 = rng.gen_range(0..5);
    match strategy {
        0 => 0,
        1 => 1,
        2 => rng.gen_range(1..1_000_000),
        3 => rng.gen_range(1_000_000..1_000_000_000_000_000_000),
        _ => u128::MAX,
    }
}

/// Generate a single random transaction targeting a function from the ABI.
pub(crate) fn random_transaction(
    abi: &ContractAbi,
    rng: &mut impl Rng,
    config: &FuzzConfig,
) -> Option<Transaction> {
    random_transaction_with_dict(abi, rng, config, None)
}

/// Generate a single random transaction, optionally using dictionary values.
pub(crate) fn random_transaction_with_dict(
    abi: &ContractAbi,
    rng: &mut impl Rng,
    config: &FuzzConfig,
    dict: Option<&Dictionary>,
) -> Option<Transaction> {
    let eligible: Vec<&crate::fuzzing::types::FunctionAbi> = abi
        .functions
        .iter()
        .filter(|f| f.is_fuzz_callable())
        .collect();

    if eligible.is_empty() {
        return None;
    }

    let func = eligible[rng.gen_range(0..eligible.len())];
    let args: Vec<FuzzValue> = func
        .params
        .iter()
        .map(|_p| random_value_with_dict(rng, dict))
        .collect();
    let value = if func.is_payable {
        random_value_amount(rng)
    } else {
        0
    };

    Some(Transaction {
        function_id: func.id,
        args,
        sender: random_sender(rng, config.address_pool_size),
        value,
    })
}

/// Build a dependency-aware transaction sequence.
/// Tries to place writers before readers when read-after-write dependencies exist.
fn dependency_aware_sequence(
    abi: &ContractAbi,
    deps: &DependencyMap,
    rng: &mut impl Rng,
    config: &FuzzConfig,
    length: usize,
    dict: Option<&Dictionary>,
) -> Vec<Transaction> {
    let mut txs = Vec::new();

    // Collect (function_id, written_vars) for all writer functions
    let writers: Vec<(u32, &std::collections::HashSet<String>)> = deps
        .functions
        .iter()
        .filter(|(_, fd)| !fd.writes.is_empty())
        .map(|(id, fd)| (*id, &fd.writes))
        .collect();

    // Collect (function_id, read_vars) for all reader functions
    let readers: Vec<(u32, &std::collections::HashSet<String>)> = deps
        .functions
        .iter()
        .filter(|(_, fd)| !fd.reads.is_empty())
        .map(|(id, fd)| (*id, &fd.reads))
        .collect();

    // Try to inject at least one writer→reader chain
    if !writers.is_empty() && !readers.is_empty() {
        let (wid, wvars) = &writers[rng.gen_range(0..writers.len())];
        // Find a reader that reads from this writer's writes
        let matching: Vec<&(u32, &std::collections::HashSet<String>)> = readers
            .iter()
            .filter(|(_, rvars)| rvars.intersection(wvars).next().is_some())
            .collect();

        if let Some((rid, _)) = matching.first() {
            // Generate the writer transaction
            if let Some(func) = abi.functions.iter().find(|f| f.id == *wid) {
                if func.is_fuzz_callable() {
                    let args: Vec<FuzzValue> = func
                        .params
                        .iter()
                        .map(|_| random_value_with_dict(rng, dict))
                        .collect();
                    txs.push(Transaction {
                        function_id: func.id,
                        args,
                        sender: random_sender(rng, config.address_pool_size),
                        value: if func.is_payable {
                            random_value_amount(rng)
                        } else {
                            0
                        },
                    });
                }
            }
            // Generate the reader transaction
            if let Some(func) = abi.functions.iter().find(|f| f.id == *rid) {
                if func.is_fuzz_callable() {
                    let args: Vec<FuzzValue> = func
                        .params
                        .iter()
                        .map(|_| random_value_with_dict(rng, dict))
                        .collect();
                    txs.push(Transaction {
                        function_id: func.id,
                        args,
                        sender: random_sender(rng, config.address_pool_size),
                        value: if func.is_payable {
                            random_value_amount(rng)
                        } else {
                            0
                        },
                    });
                }
            }
        }
    }

    // Fill remaining with random transactions
    while txs.len() < length {
        if let Some(tx) = random_transaction_with_dict(abi, rng, config, dict) {
            txs.push(tx);
        } else {
            break;
        }
    }

    txs
}

/// Extract a dictionary of numeric constants from the IR module.
/// These are used during value generation to produce inputs that match
/// constants in the contract (comparison targets, magic values, etc.).
pub fn extract_dictionary(ir_module: &IrModule) -> Dictionary {
    let mut seen = std::collections::HashSet::new();
    let mut values = Vec::new();

    for func in &ir_module.functions {
        for block in &func.blocks {
            for instr in &block.instrs {
                collect_literals_from_instr(instr, &mut seen, &mut values);
            }
        }
    }

    Dictionary { values }
}

/// Walk an IR instruction and extract numeric literals.
fn collect_literals_from_instr(
    instr: &crate::ir::IrInstr,
    seen: &mut std::collections::HashSet<u128>,
    values: &mut Vec<u128>,
) {
    use crate::ir::IrInstr;

    let collect = |val: &crate::ir::IrValue,
                   seen: &mut std::collections::HashSet<u128>,
                   values: &mut Vec<u128>| {
        if let crate::ir::IrValue::Literal(lit) = val {
            if let Ok(n) = lit.value.parse::<u128>() {
                if seen.insert(n) {
                    values.push(n);
                    // Also add boundary neighbors
                    if n > 0 && seen.insert(n - 1) {
                        values.push(n - 1);
                    }
                    if n < u128::MAX && seen.insert(n + 1) {
                        values.push(n + 1);
                    }
                }
            }
        }
    };

    match instr {
        IrInstr::Binary { lhs, rhs, .. } => {
            collect(lhs, seen, values);
            collect(rhs, seen, values);
        }
        IrInstr::Unary { expr, .. } => {
            collect(expr, seen, values);
        }
        IrInstr::Assign { src, .. } => {
            collect(src, seen, values);
        }
        IrInstr::Store { src, .. } => {
            collect(src, seen, values);
        }
        IrInstr::Declare { init, .. } => {
            if let Some(val) = init {
                collect(val, seen, values);
            }
        }
        IrInstr::Call { args, .. } => {
            for arg in args {
                collect(arg, seen, values);
            }
        }
        _ => {}
    }
}

/// Generate the initial population of test cases.
pub fn generate_initial_population(
    abi: &ContractAbi,
    deps: &DependencyMap,
    config: &FuzzConfig,
) -> Vec<Individual> {
    generate_initial_population_with_dict(abi, deps, config, None)
}

/// Generate the initial population, optionally using a dictionary.
pub fn generate_initial_population_with_dict(
    abi: &ContractAbi,
    deps: &DependencyMap,
    config: &FuzzConfig,
    dict: Option<&Dictionary>,
) -> Vec<Individual> {
    let mut rng = match config.seed {
        Some(seed) => <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(seed),
        None => <rand::rngs::StdRng as rand::SeedableRng>::from_entropy(),
    };

    let mut population = Vec::with_capacity(config.population_size);

    for i in 0..config.population_size {
        let seq_len = rng.gen_range(1..=config.max_sequence_length);
        // Half the population is dependency-aware, half is random
        let txs = if i % 2 == 0 {
            dependency_aware_sequence(abi, deps, &mut rng, config, seq_len, dict)
        } else {
            let mut txs = Vec::new();
            for _ in 0..seq_len {
                if let Some(tx) = random_transaction_with_dict(abi, &mut rng, config, dict) {
                    txs.push(tx);
                }
            }
            txs
        };

        if txs.is_empty() {
            continue;
        }

        population.push(Individual {
            transactions: txs,
            environment: Environment {
                block_timestamp: rng.gen_range(1_000_000_000..2_000_000_000),
                block_number: rng.gen_range(1..20_000_000),
                address_pool_size: config.address_pool_size,
            },
            energy: 1.0,
        });
    }

    population
}

/// Generate a single dependency-aware seed individual.
/// Returns `None` when no eligible transactions can be constructed.
pub fn generate_dependency_seed_with_dict(
    abi: &ContractAbi,
    deps: &DependencyMap,
    config: &FuzzConfig,
    rng: &mut impl Rng,
    dict: Option<&Dictionary>,
) -> Option<Individual> {
    let seq_len = rng.gen_range(2..=config.max_sequence_length.max(2));
    let txs = dependency_aware_sequence(abi, deps, rng, config, seq_len, dict);
    if txs.is_empty() {
        return None;
    }
    Some(Individual {
        transactions: txs,
        environment: Environment {
            block_timestamp: rng.gen_range(1_000_000_000..2_000_000_000),
            block_number: rng.gen_range(1..20_000_000),
            address_pool_size: config.address_pool_size,
        },
        energy: 1.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzzing::types::{FunctionAbi, ParamInfo};
    use crate::norm::{FunctionKind, Mutability, Visibility};

    fn sample_abi() -> ContractAbi {
        ContractAbi {
            contract_name: "Test".to_string(),
            functions: vec![
                FunctionAbi {
                    id: 0,
                    name: "deposit".to_string(),
                    params: vec![ParamInfo {
                        name: "amount".to_string(),
                    }],
                    visibility: Visibility::External,
                    mutability: Mutability::Payable,
                    kind: FunctionKind::Function,
                    is_payable: true,
                },
                FunctionAbi {
                    id: 1,
                    name: "withdraw".to_string(),
                    params: vec![ParamInfo {
                        name: "amount".to_string(),
                    }],
                    visibility: Visibility::External,
                    mutability: Mutability::NonPayable,
                    kind: FunctionKind::Function,
                    is_payable: false,
                },
            ],
        }
    }

    #[test]
    fn generates_non_empty_population() {
        let abi = sample_abi();
        let deps = DependencyMap::default();
        let config = FuzzConfig {
            max_iterations: 10,
            population_size: 5,
            max_sequence_length: 3,
            mutation_rate: 0.3,
            address_pool_size: 3,
            seed: Some(42),
            max_duration_ms: None,
        };
        let pop = generate_initial_population(&abi, &deps, &config);
        assert!(!pop.is_empty());
        for ind in &pop {
            assert!(!ind.transactions.is_empty());
            for tx in &ind.transactions {
                assert!(tx.sender < config.address_pool_size);
            }
        }
    }

    #[test]
    fn payable_gets_value() {
        let abi = sample_abi();
        let deps = DependencyMap::default();
        let config = FuzzConfig {
            seed: Some(123),
            population_size: 20,
            max_duration_ms: None,
            ..Default::default()
        };
        let pop = generate_initial_population(&abi, &deps, &config);
        // At least some payable transactions should have non-zero value
        let has_value = pop
            .iter()
            .flat_map(|i| &i.transactions)
            .any(|tx| tx.function_id == 0 && tx.value > 0);
        assert!(has_value, "expected at least one payable tx with value > 0");
    }

    #[test]
    fn dictionary_values_used() {
        let dict = Dictionary {
            values: vec![42, 1337, 9999],
        };
        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0);
        let mut found_dict_val = false;
        for _ in 0..100 {
            let val = random_value_with_dict(&mut rng, Some(&dict));
            if let FuzzValue::Uint(v) = val {
                if dict.values.contains(&v) {
                    found_dict_val = true;
                    break;
                }
            }
        }
        assert!(
            found_dict_val,
            "expected dictionary value to be used at least once in 100 tries"
        );
    }

    #[test]
    fn dependency_seed_prefers_writer_reader_prefix() {
        let abi = sample_abi();
        let mut deps = DependencyMap::default();
        deps.functions.insert(
            0,
            crate::fuzzing::types::FunctionDeps {
                reads: std::collections::HashSet::new(),
                writes: std::collections::HashSet::from(["balance".to_string()]),
            },
        );
        deps.functions.insert(
            1,
            crate::fuzzing::types::FunctionDeps {
                reads: std::collections::HashSet::from(["balance".to_string()]),
                writes: std::collections::HashSet::new(),
            },
        );
        let config = FuzzConfig {
            max_sequence_length: 4,
            address_pool_size: 3,
            seed: Some(7),
            ..Default::default()
        };
        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(9);
        let seed = generate_dependency_seed_with_dict(&abi, &deps, &config, &mut rng, None)
            .expect("seed");
        assert!(seed.transactions.len() >= 2);
        assert_eq!(seed.transactions[0].function_id, 0);
        assert_eq!(seed.transactions[1].function_id, 1);
    }
}
