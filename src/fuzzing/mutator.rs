use rand::Rng;

use crate::fuzzing::types::{
    ContractAbi, Dictionary, FuzzValue, Individual, Transaction,
};

/// Mutate an individual to produce a new test case.
/// Selects from 10 mutation strategies including the new havoc and arithmetic modes.
pub fn mutate_individual(
    ind: &Individual,
    abi: &ContractAbi,
    rng: &mut impl Rng,
) -> Individual {
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
    let mut mutant = ind.clone();

    if havoc_only {
        havoc_mutate(&mut mutant, abi, rng, dict);
        return mutant;
    }

    let strategy: u32 = rng.gen_range(0..10);

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
        _ => mutate_sender_role(&mut mutant, rng),
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
            0 => *val = val.wrapping_mul(2),   // *2
            1 => *val /= 2,                     // /2
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
fn insert_transaction_with_dict(ind: &mut Individual, abi: &ContractAbi, rng: &mut impl Rng, dict: Option<&Dictionary>) {
    let config = crate::fuzzing::types::FuzzConfig::default();
    if let Some(tx) = crate::fuzzing::generator::random_transaction_with_dict(abi, rng, &config, dict) {
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
                ind.transactions[idx].sender =
                    rng.gen_range(0..ind.environment.address_pool_size);
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
        0 => 0,  // likely contract owner
        1 => 1,  // likely attacker
        _ => rng.gen_range(0..ind.environment.address_pool_size),
    };
}

// --- Havoc Mode ---

/// Havoc mutation: stack 2–16 random mutations in a single round.
/// This is a key AFL technique for escaping local optima.
fn havoc_mutate(ind: &mut Individual, abi: &ContractAbi, rng: &mut impl Rng, dict: Option<&Dictionary>) {
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


#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzzing::types::{Environment, FunctionAbi, ParamInfo};
    use crate::norm::{FunctionKind, Mutability, Visibility};

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
                    params: vec![ParamInfo { name: "amount".to_string() }],
                    visibility: Visibility::External,
                    mutability: Mutability::Payable,
                    kind: FunctionKind::Function,
                    is_payable: true,
                },
                FunctionAbi {
                    id: 1,
                    name: "withdraw".to_string(),
                    params: vec![ParamInfo { name: "amount".to_string() }],
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
        assert!(any_different, "expected at least one mutation to produce a different individual");
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
            || mutant.transactions.iter().zip(ind.transactions.iter())
                .any(|(a, b)| a.function_id != b.function_id || a.sender != b.sender || a.args.len() != b.args.len());
        assert!(different, "havoc mode should produce a different individual");
    }

    #[test]
    fn arithmetic_mutation_changes_value() {
        let mut ind = sample_individual();
        let original_val = if let FuzzValue::Uint(v) = &ind.transactions[0].args[0] { *v } else { 0 };
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
}
