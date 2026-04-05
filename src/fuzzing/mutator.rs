use rand::Rng;

use crate::fuzzing::types::{
    ContractAbi, DependencyMap, Dictionary, FuzzValue, Individual, Transaction,
};
/// Mutate an individual to produce a new test case.
/// Selects from 10 mutation strategies including the new havoc and arithmetic modes.
pub fn mutate_individual(ind: &Individual, abi: &ContractAbi, rng: &mut impl Rng) -> Individual {
    mutate_individual_with_dict(ind, abi, rng, None, false)
}

/// Mutate an individual, optionally using dictionary values and havoc-only mode.
/// When `havoc_only` is true, always uses the havoc strategy (stacking 2–16 mutations).
pub fn mutate_individual_with_dict(
    ind: &Individual,
    abi: &ContractAbi,
    rng: &mut impl Rng,
    dict: Option<&Dictionary>,
    havoc_only: bool,
) -> Individual {
    mutate_individual_core(ind, abi, None, rng, dict, havoc_only)
}

/// Mutate an individual with optional dependency guidance from storage RW map.
/// When deps are provided, one strategy can force a writer->reader chain prefix.
pub fn mutate_individual_guided_with_dict(
    ind: &Individual,
    abi: &ContractAbi,
    deps: &DependencyMap,
    rng: &mut impl Rng,
    dict: Option<&Dictionary>,
    havoc_only: bool,
) -> Individual {
    mutate_individual_core(ind, abi, Some(deps), rng, dict, havoc_only)
}

fn mutate_individual_core(
    ind: &Individual,
    abi: &ContractAbi,
    deps: Option<&DependencyMap>,
    rng: &mut impl Rng,
    dict: Option<&Dictionary>,
    havoc_only: bool,
) -> Individual {
    let mut mutant = ind.clone();

    if havoc_only {
        havoc_mutate(&mut mutant, abi, rng, dict);
        if let Some(deps) = deps {
            if rng.gen_bool(0.20) {
                inject_dependency_chain(&mut mutant, abi, deps, rng, dict);
            }
        }
        return mutant;
    }

    let strategy_space = if deps.is_some() { 11 } else { 10 };
    let strategy: u32 = rng.gen_range(0..strategy_space);

    match strategy {
        0 => mutate_value_with_dict(&mut mutant, rng, dict),
        1 => mutate_boundary_nudge(&mut mutant, rng),
        2 => mutate_bit_flip(&mut mutant, rng),
        3 => insert_transaction_with_dict(&mut mutant, abi, rng, dict),
        4 => remove_transaction(&mut mutant, rng),
        5 => swap_transactions(&mut mutant, rng),
        6 => mutate_environment(&mut mutant, rng),
        7 => havoc_mutate(&mut mutant, abi, rng, dict),
        8 => mutate_arithmetic(&mut mutant, rng),
        9 => mutate_sender_role(&mut mutant, rng),
        _ => {
            if let Some(deps) = deps {
                inject_dependency_chain(&mut mutant, abi, deps, rng, dict);
            } else {
                mutate_sender_role(&mut mutant, rng);
            }
        }
    }

    mutant
}

/// Crossover: splice two individuals at a random point.
pub fn crossover(a: &Individual, b: &Individual, rng: &mut impl Rng) -> Individual {
    let a_len = a.transactions.len();
    let b_len = b.transactions.len();

    if a_len == 0 {
        return b.clone();
    }
    if b_len == 0 {
        return a.clone();
    }

    let cut_a = rng.gen_range(0..a_len);
    let cut_b = rng.gen_range(0..b_len);

    let mut txs: Vec<Transaction> = a.transactions[..=cut_a].to_vec();
    txs.extend_from_slice(&b.transactions[cut_b..]);

    // Limit sequence length
    if txs.len() > 15 {
        txs.truncate(15);
    }

    Individual {
        transactions: txs,
        environment: if rng.gen_bool(0.5) {
            a.environment.clone()
        } else {
            b.environment.clone()
        },
        energy: 1.0,
    }
}

// --- Value-Level Mutations ---

/// Replace a random argument with a new random value.
fn mutate_value(ind: &mut Individual, rng: &mut impl Rng) {
    mutate_value_with_dict(ind, rng, None);
}

/// Replace a random argument, optionally using dictionary values.
fn mutate_value_with_dict(ind: &mut Individual, rng: &mut impl Rng, dict: Option<&Dictionary>) {
    if ind.transactions.is_empty() {
        return;
    }
    let tx_idx = rng.gen_range(0..ind.transactions.len());
    let tx = &mut ind.transactions[tx_idx];
    if tx.args.is_empty() {
        return;
    }
    let arg_idx = rng.gen_range(0..tx.args.len());
    tx.args[arg_idx] = crate::fuzzing::generator::random_value_with_dict(rng, dict);
}

/// Nudge a numeric value by ±1 (boundary exploration).
fn mutate_boundary_nudge(ind: &mut Individual, rng: &mut impl Rng) {
    if ind.transactions.is_empty() {
        return;
    }
    let tx_idx = rng.gen_range(0..ind.transactions.len());
    let tx = &mut ind.transactions[tx_idx];
    if tx.args.is_empty() {
        return;
    }
    let arg_idx = rng.gen_range(0..tx.args.len());
    if let FuzzValue::Uint(val) = &mut tx.args[arg_idx] {
        if rng.gen_bool(0.5) {
            *val = val.wrapping_add(1);
        } else {
            *val = val.wrapping_sub(1);
        }
    }
}

/// Flip a random bit in a numeric value.
fn mutate_bit_flip(ind: &mut Individual, rng: &mut impl Rng) {
    if ind.transactions.is_empty() {
        return;
    }
    let tx_idx = rng.gen_range(0..ind.transactions.len());
    let tx = &mut ind.transactions[tx_idx];
    if tx.args.is_empty() {
        return;
    }
    let arg_idx = rng.gen_range(0..tx.args.len());
    if let FuzzValue::Uint(val) = &mut tx.args[arg_idx] {
        let bit = rng.gen_range(0..128);
        *val ^= 1u128 << bit;
    }
}

/// Arithmetic mutation: apply *2, /2, or negate to a random numeric argument.
fn mutate_arithmetic(ind: &mut Individual, rng: &mut impl Rng) {
    if ind.transactions.is_empty() {
        return;
    }
    let tx_idx = rng.gen_range(0..ind.transactions.len());
    let tx = &mut ind.transactions[tx_idx];
    if tx.args.is_empty() {
        return;
    }
    let arg_idx = rng.gen_range(0..tx.args.len());
    if let FuzzValue::Uint(val) = &mut tx.args[arg_idx] {
        let op: u32 = rng.gen_range(0..3);
        match op {
            0 => *val = val.wrapping_mul(2),      // *2
            1 => *val /= 2,                       // /2
            _ => *val = 0u128.wrapping_sub(*val), // negate (two's complement)
        }
    }
}

// --- Sequence-Level Mutations ---

/// Insert a random transaction into the sequence.
fn insert_transaction(ind: &mut Individual, abi: &ContractAbi, rng: &mut impl Rng) {
    insert_transaction_with_dict(ind, abi, rng, None);
}

/// Insert a random transaction, optionally using dictionary values.
fn insert_transaction_with_dict(
    ind: &mut Individual,
    abi: &ContractAbi,
    rng: &mut impl Rng,
    dict: Option<&Dictionary>,
) {
    let config = crate::fuzzing::types::FuzzConfig::default();
    if let Some(tx) =
        crate::fuzzing::generator::random_transaction_with_dict(abi, rng, &config, dict)
    {
        let pos = if ind.transactions.is_empty() {
            0
        } else {
            rng.gen_range(0..=ind.transactions.len())
        };
        ind.transactions.insert(pos, tx);
        // Limit max length
        if ind.transactions.len() > 15 {
            ind.transactions.truncate(15);
        }
    }
}

/// Remove a random transaction from the sequence (if length > 1).
fn remove_transaction(ind: &mut Individual, rng: &mut impl Rng) {
    if ind.transactions.len() <= 1 {
        return;
    }
    let idx = rng.gen_range(0..ind.transactions.len());
    ind.transactions.remove(idx);
}

/// Swap two random transactions.
fn swap_transactions(ind: &mut Individual, rng: &mut impl Rng) {
    if ind.transactions.len() < 2 {
        return;
    }
    let a = rng.gen_range(0..ind.transactions.len());
    let mut b = rng.gen_range(0..ind.transactions.len());
    while b == a {
        b = rng.gen_range(0..ind.transactions.len());
    }
    ind.transactions.swap(a, b);
}

// --- Environment Mutations ---

/// Mutate the environment (timestamp, block number, sender).
fn mutate_environment(ind: &mut Individual, rng: &mut impl Rng) {
    let choice: u32 = rng.gen_range(0..3);
    match choice {
        0 => {
            ind.environment.block_timestamp = rng.gen_range(0..3_000_000_000);
        }
        1 => {
            ind.environment.block_number = rng.gen_range(0..50_000_000);
        }
        _ => {
            // Mutate a random transaction's sender
            if !ind.transactions.is_empty() {
                let idx = rng.gen_range(0..ind.transactions.len());
                ind.transactions[idx].sender = rng.gen_range(0..ind.environment.address_pool_size);
            }
        }
    }
}

/// Specifically toggle sender between owner (0), attacker (1), and random user roles.
/// This is more targeted than general environment mutation for exercising access control.
fn mutate_sender_role(ind: &mut Individual, rng: &mut impl Rng) {
    if ind.transactions.is_empty() {
        return;
    }
    let idx = rng.gen_range(0..ind.transactions.len());
    // Bias toward interesting senders: 0=owner, 1=attacker, rest=random
    let choice: u32 = rng.gen_range(0..4);
    ind.transactions[idx].sender = match choice {
        0 => 0, // likely contract owner
        1 => 1, // likely attacker
        _ => rng.gen_range(0..ind.environment.address_pool_size),
    };
}

// --- Havoc Mode ---

/// Havoc mutation: stack 2–16 random mutations in a single round.
/// This is a key AFL technique for escaping local optima.
fn havoc_mutate(
    ind: &mut Individual,
    abi: &ContractAbi,
    rng: &mut impl Rng,
    dict: Option<&Dictionary>,
) {
    let num_mutations = rng.gen_range(2..=16);
    for _ in 0..num_mutations {
        let strategy: u32 = rng.gen_range(0..9);
        match strategy {
            0 => mutate_value_with_dict(ind, rng, dict),
            1 => mutate_boundary_nudge(ind, rng),
            2 => mutate_bit_flip(ind, rng),
            3 => insert_transaction_with_dict(ind, abi, rng, dict),
            4 => remove_transaction(ind, rng),
            5 => swap_transactions(ind, rng),
            6 => mutate_environment(ind, rng),
            7 => mutate_arithmetic(ind, rng),
            _ => mutate_sender_role(ind, rng),
        }
    }
}

fn inject_dependency_chain(
    ind: &mut Individual,
    abi: &ContractAbi,
    deps: &DependencyMap,
    rng: &mut impl Rng,
    dict: Option<&Dictionary>,
) {
    let Some((writer, reader)) = pick_writer_reader_pair(deps, rng) else {
        return;
    };

    let pool = ind.environment.address_pool_size.max(2);
    let writer_sender = if rng.gen_bool(0.7) {
        0
    } else {
        rng.gen_range(0..pool)
    };
    let reader_sender = if rng.gen_bool(0.7) {
        1
    } else {
        rng.gen_range(0..pool)
    };

    let writer_tx = make_tx_for_function(abi, writer, rng, dict, pool, writer_sender);
    let reader_tx = make_tx_for_function(abi, reader, rng, dict, pool, reader_sender);
    let (Some(writer_tx), Some(reader_tx)) = (writer_tx, reader_tx) else {
        return;
    };

    if ind.transactions.is_empty() {
        ind.transactions.push(writer_tx);
        ind.transactions.push(reader_tx);
        return;
    }

    if ind.transactions.len() == 1 {
        ind.transactions[0] = writer_tx;
        ind.transactions.push(reader_tx);
        return;
    }

    ind.transactions[0] = writer_tx;
    ind.transactions[1] = reader_tx;
}

fn pick_writer_reader_pair(deps: &DependencyMap, rng: &mut impl Rng) -> Option<(u32, u32)> {
    let mut pairs = Vec::new();
    for (writer_id, writer_fd) in &deps.functions {
        if writer_fd.writes.is_empty() {
            continue;
        }
        for (reader_id, reader_fd) in &deps.functions {
            if writer_id == reader_id || reader_fd.reads.is_empty() {
                continue;
            }
            if reader_fd
                .reads
                .intersection(&writer_fd.writes)
                .next()
                .is_some()
            {
                pairs.push((*writer_id, *reader_id));
            }
        }
    }

    if pairs.is_empty() {
        return None;
    }
    Some(pairs[rng.gen_range(0..pairs.len())])
}

fn make_tx_for_function(
    abi: &ContractAbi,
    function_id: u32,
    rng: &mut impl Rng,
    dict: Option<&Dictionary>,
    address_pool_size: usize,
    sender: usize,
) -> Option<Transaction> {
    let func = abi.functions.iter().find(|f| f.id == function_id)?;
    if !func.is_fuzz_callable() {
        return None;
    }

    let args = func
        .params
        .iter()
        .map(|_| crate::fuzzing::generator::random_value_with_dict(rng, dict))
        .collect::<Vec<_>>();

    let value = if func.is_payable {
        random_payable_value(rng)
    } else {
        0
    };

    Some(Transaction {
        function_id,
        args,
        sender: sender.min(address_pool_size.saturating_sub(1)),
        value,
    })
}

fn random_payable_value(rng: &mut impl Rng) -> u128 {
    let strategy: u32 = rng.gen_range(0..5);
    match strategy {
        0 => 0,
        1 => 1,
        2 => rng.gen_range(1..1_000_000),
        3 => rng.gen_range(1_000_000..1_000_000_000_000_000_000),
        _ => u128::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzzing::types::{DependencyMap, Environment, FunctionAbi, FunctionDeps, ParamInfo};
    use crate::norm::{FunctionKind, Mutability, Visibility};
    use std::collections::{HashMap, HashSet};

    fn sample_individual() -> Individual {
        Individual {
            transactions: vec![
                Transaction {
                    function_id: 0,
                    args: vec![FuzzValue::Uint(100)],
                    sender: 0,
                    value: 0,
                },
                Transaction {
                    function_id: 1,
                    args: vec![FuzzValue::Uint(50)],
                    sender: 1,
                    value: 0,
                },
            ],
            environment: Environment::default(),
            energy: 1.0,
        }
    }

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
    fn mutate_produces_different() {
        let ind = sample_individual();
        let abi = sample_abi();
        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(42);
        // Run many mutations, at least one should differ
        let mut any_different = false;
        for _ in 0..20 {
            let mutant = mutate_individual(&ind, &abi, &mut rng);
            if mutant.transactions.len() != ind.transactions.len() {
                any_different = true;
                break;
            }
            for (orig, mut_tx) in ind.transactions.iter().zip(mutant.transactions.iter()) {
                if orig.function_id != mut_tx.function_id || orig.sender != mut_tx.sender {
                    any_different = true;
                    break;
                }
            }
            if any_different {
                break;
            }
        }
        assert!(
            any_different,
            "expected at least one mutation to produce a different individual"
        );
    }

    #[test]
    fn crossover_splices() {
        let a = sample_individual();
        let b = Individual {
            transactions: vec![Transaction {
                function_id: 2,
                args: vec![FuzzValue::Uint(999)],
                sender: 2,
                value: 0,
            }],
            environment: Environment::default(),
            energy: 1.0,
        };
        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(77);
        let child = crossover(&a, &b, &mut rng);
        assert!(!child.transactions.is_empty());
    }

    #[test]
    fn havoc_produces_changes() {
        let ind = sample_individual();
        let abi = sample_abi();
        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(99);
        let mutant = mutate_individual_with_dict(&ind, &abi, &mut rng, None, true);
        // Havoc should produce some change (stacks 2-16 mutations)
        let different = mutant.transactions.len() != ind.transactions.len()
            || mutant
                .transactions
                .iter()
                .zip(ind.transactions.iter())
                .any(|(a, b)| {
                    a.function_id != b.function_id
                        || a.sender != b.sender
                        || a.args.len() != b.args.len()
                });
        assert!(
            different,
            "havoc mode should produce a different individual"
        );
    }

    #[test]
    fn arithmetic_mutation_changes_value() {
        let mut ind = sample_individual();
        let original_val = if let FuzzValue::Uint(v) = &ind.transactions[0].args[0] {
            *v
        } else {
            0
        };
        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(42);
        // Run several times; arithmetic should change at least one value
        let mut changed = false;
        for _ in 0..10 {
            mutate_arithmetic(&mut ind, &mut rng);
            if let FuzzValue::Uint(v) = &ind.transactions[0].args[0] {
                if *v != original_val {
                    changed = true;
                    break;
                }
            }
        }
        assert!(changed, "arithmetic mutation should change a numeric value");
    }

    #[test]
    fn guided_mutation_can_inject_writer_reader_chain() {
        let ind = sample_individual();
        let abi = sample_abi();
        let mut deps = DependencyMap::default();
        deps.functions.insert(
            0,
            FunctionDeps {
                reads: HashSet::new(),
                writes: HashSet::from(["balance".to_string()]),
            },
        );
        deps.functions.insert(
            1,
            FunctionDeps {
                reads: HashSet::from(["balance".to_string()]),
                writes: HashSet::new(),
            },
        );

        let mut injected = false;
        for seed in 0..64u64 {
            let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(seed);
            let mutant =
                mutate_individual_guided_with_dict(&ind, &abi, &deps, &mut rng, None, false);
            if mutant.transactions.len() >= 2
                && mutant.transactions[0].function_id == 0
                && mutant.transactions[1].function_id == 1
            {
                injected = true;
                break;
            }
        }
        assert!(
            injected,
            "expected guided mutator to inject writer->reader chain"
        );
    }
}
