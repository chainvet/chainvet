use crate::core::artifacts::{Seed, TxEnv, TxSeed};
use crate::fuzzing::types::{ContractAbi, Environment, FuzzValue, Individual, Transaction};
use crate::norm::NormalizedAst;
use crate::symbolic::results::{SeFinding, Witness};

#[derive(Debug, Clone, serde::Serialize)]
pub struct HybridSeed {
    pub id: String,
    pub source_kind: String,
    pub confidence: String,
    pub function_id: u32,
    pub path_constraints: Vec<String>,
    pub tx_count: usize,
    pub artifact: Seed,
    #[serde(skip_serializing)]
    pub individual: Individual,
}

pub fn build_hybrid_seeds(
    ast: &NormalizedAst,
    abis: &[ContractAbi],
    findings: &[SeFinding],
) -> Vec<HybridSeed> {
    findings
        .iter()
        .enumerate()
        .filter_map(|(index, finding)| to_seed(ast, abis, finding, index))
        .collect()
}

fn to_seed(
    ast: &NormalizedAst,
    abis: &[ContractAbi],
    finding: &SeFinding,
    index: usize,
) -> Option<HybridSeed> {
    let function_id = finding
        .function_id
        .or_else(|| infer_function_id(ast, finding))?;
    let witness = finding.witness.as_ref();
    let function = abis
        .iter()
        .flat_map(|abi| abi.functions.iter())
        .find(|function| function.id == function_id)?;

    let args = function
        .params
        .iter()
        .map(|_| FuzzValue::Uint(0))
        .collect::<Vec<_>>();
    let sender = witness.map(address_index_from_witness).unwrap_or(1);
    let value = witness.map(|witness| u128_from_be_bytes(&witness.msg_value)).unwrap_or(0);
    let environment = Environment {
        block_timestamp: witness
            .map(|witness| witness.block_timestamp as u128)
            .unwrap_or(Environment::default().block_timestamp),
        block_number: witness
            .map(|witness| witness.block_number as u128)
            .unwrap_or(Environment::default().block_number),
        address_pool_size: 5,
    };
    let tx = Transaction {
        function_id,
        args: args.clone(),
        sender,
        value,
    };
    let individual = Individual {
        transactions: vec![tx.clone()],
        environment: environment.clone(),
        energy: 2.0,
    };
    let id = format!("se-seed-{}-{index}", finding.kind.as_str());

    Some(HybridSeed {
        id: id.clone(),
        source_kind: finding.kind.as_str().to_string(),
        confidence: finding.confidence.as_str().to_string(),
        function_id,
        path_constraints: finding.path_constraints.clone(),
        tx_count: 1,
        artifact: Seed {
            id,
            txs: vec![TxSeed {
                function_id,
                selector: None,
                calldata: None,
                args: args.iter().map(format_fuzz_value).collect(),
                sender: format!("0x{:040x}", sender),
                value: value.to_string(),
                env: TxEnv {
                    block_timestamp: Some(environment.block_timestamp),
                    block_number: Some(environment.block_number),
                },
            }],
            state_snapshot_id: None,
            score: 1.0,
        },
        individual,
    })
}

fn format_fuzz_value(value: &FuzzValue) -> String {
    match value {
        FuzzValue::Uint(value) => value.to_string(),
        FuzzValue::Int(value) => value.to_string(),
        FuzzValue::Bool(value) => value.to_string(),
        FuzzValue::Address(value) => value.to_string(),
        FuzzValue::Bytes(value) => format!("0x{}", bytes_to_hex(value)),
        FuzzValue::StringVal(value) => value.clone(),
    }
}

fn address_index_from_witness(witness: &Witness) -> usize {
    witness.msg_sender[19] as usize % 5
}

fn u128_from_be_bytes(bytes: &[u8; 32]) -> u128 {
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[16..]);
    u128::from_be_bytes(out)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn infer_function_id(ast: &NormalizedAst, finding: &SeFinding) -> Option<u32> {
    ast.functions.iter().find_map(|function| {
        (function.span.file == finding.span.file
            && function.span.start <= finding.span.start
            && function.span.end >= finding.span.end)
            .then_some(function.id)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::detectors::Severity;
    use crate::fuzzing::types::{FunctionAbi, ParamInfo};
    use crate::norm::{FunctionKind, Mutability, Span, Visibility};
    use crate::symbolic::results::finding::{Confidence, SeFinding, SeVulnKind};

    fn sample_ast() -> NormalizedAst {
        let mut ast = NormalizedAst::from_sources(vec![crate::norm::SourceFile {
            id: 0,
            path: "seed.sol".to_string(),
            source: String::new(),
        }]);
        ast.functions.push(crate::norm::Function {
            id: 7,
            contract: None,
            name: Some("withdraw".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::External,
            mutability: Mutability::NonPayable,
            params: vec!["amount".to_string()],
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span { file: 0, start: 0, end: 100 },
        });
        ast
    }

    fn sample_abi() -> Vec<ContractAbi> {
        vec![ContractAbi {
            contract_name: "Seeded".to_string(),
            functions: vec![FunctionAbi {
                id: 7,
                name: "withdraw".to_string(),
                params: vec![ParamInfo {
                    name: "amount".to_string(),
                }],
                visibility: Visibility::External,
                mutability: Mutability::NonPayable,
                kind: FunctionKind::Function,
                is_payable: false,
            }],
        }]
    }

    fn sample_witness() -> Witness {
        Witness {
            msg_sender: [0u8; 20],
            msg_value: [0u8; 32],
            tx_origin: [0u8; 20],
            block_timestamp: 123,
            block_number: 456,
            this_balance: [0u8; 32],
            variables: Vec::new(),
        }
    }

    #[test]
    fn witness_becomes_seed_without_panicking() {
        let finding = SeFinding {
            kind: SeVulnKind::Reentrancy,
            severity: Severity::High,
            confidence: Confidence::High,
            message: "seed me".to_string(),
            span: Span { file: 0, start: 0, end: 0 },
            function_id: Some(7),
            path_constraints: vec!["balance > 0".to_string()],
            witness: Some(sample_witness()),
            state_id: 1,
            path_depth: 1,
        };
        let seeds = build_hybrid_seeds(&sample_ast(), &sample_abi(), &[finding]);
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].individual.transactions.len(), 1);
    }
}
