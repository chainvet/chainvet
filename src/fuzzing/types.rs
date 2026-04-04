use std::collections::{HashMap, HashSet};

use crate::core::artifacts::Finding;
use crate::frontend::{self, CompilerInfo};
use crate::ir::{IrInstr, IrModule, IrPlace, IrValue, IrVar, PlaceClass};
use crate::norm::{FunctionKind, Mutability, NormalizedAst, Visibility};

// ---------------------------------------------------------------------------
// ABI-like extraction from NormalizedAst
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ContractAbi {
    pub contract_name: String,
    pub functions: Vec<FunctionAbi>,
}

#[derive(Debug, Clone)]
pub struct FunctionAbi {
    pub id: u32,
    pub name: String,
    pub params: Vec<ParamInfo>,
    pub visibility: Visibility,
    pub mutability: Mutability,
    pub kind: FunctionKind,
    pub is_payable: bool,
}

impl FunctionAbi {
    pub fn is_fuzz_callable(&self) -> bool {
        match self.kind {
            FunctionKind::Function => {
                matches!(self.visibility, Visibility::Public | Visibility::External)
            }
            FunctionKind::Fallback => self.params.is_empty(),
            FunctionKind::Receive => self.is_payable && self.params.is_empty(),
            FunctionKind::Unknown => {
                // Be permissive on unknown legacy signatures so the engine can still
                // exercise candidate entrypoints instead of silently producing corpus:0.
                self.params.is_empty()
                    || matches!(self.visibility, Visibility::Public | Visibility::External)
            }
            FunctionKind::Constructor => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParamInfo {
    pub name: String,
}

pub fn extract_abis(ast: &NormalizedAst, compiler: &CompilerInfo) -> Vec<ContractAbi> {
    let mut abis = Vec::new();
    for contract in &ast.contracts {
        let mut functions = Vec::new();
        for &func_id in &contract.functions {
            let Some(func) = ast.functions.get(func_id as usize) else {
                continue;
            };
            let name = func.name.clone().unwrap_or_default();
            let display_name = match func.kind {
                FunctionKind::Constructor => "<constructor>".to_string(),
                FunctionKind::Fallback => "<fallback>".to_string(),
                FunctionKind::Receive => "<receive>".to_string(),
                FunctionKind::Function if name.is_empty() => "<fallback-legacy>".to_string(),
                _ => name,
            };
            let params: Vec<ParamInfo> = func
                .params
                .iter()
                .map(|p| ParamInfo { name: p.clone() })
                .collect();
            functions.push(FunctionAbi {
                id: func.id,
                name: display_name,
                params,
                visibility: frontend::effective_visibility(func, compiler),
                mutability: func.mutability,
                kind: func.kind,
                is_payable: func.mutability == Mutability::Payable,
            });
        }
        abis.push(ContractAbi {
            contract_name: contract.name.clone(),
            functions,
        });
    }
    abis
}

// ---------------------------------------------------------------------------
// Fuzzing Value Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum FuzzValue {
    Uint(u128),
    Int(i128),
    Bool(bool),
    Address(usize),
    Bytes(Vec<u8>),
    StringVal(String),
}

impl FuzzValue {
    pub fn as_uint(&self) -> u128 {
        match self {
            FuzzValue::Uint(v) => *v,
            FuzzValue::Int(v) => *v as u128,
            FuzzValue::Bool(v) => {
                if *v {
                    1
                } else {
                    0
                }
            }
            FuzzValue::Address(v) => *v as u128,
            _ => 0,
        }
    }

    pub fn is_truthy(&self) -> bool {
        match self {
            FuzzValue::Uint(v) => *v != 0,
            FuzzValue::Int(v) => *v != 0,
            FuzzValue::Bool(v) => *v,
            FuzzValue::Address(v) => *v != 0,
            FuzzValue::Bytes(v) => !v.is_empty(),
            FuzzValue::StringVal(v) => !v.is_empty(),
        }
    }

    pub fn default_val() -> Self {
        FuzzValue::Uint(0)
    }
}

// ---------------------------------------------------------------------------
// Transaction and Individual (Test Case)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Transaction {
    pub function_id: u32,
    pub args: Vec<FuzzValue>,
    pub sender: usize,
    pub value: u128,
}

#[derive(Debug, Clone)]
pub struct Environment {
    pub block_timestamp: u128,
    pub block_number: u128,
    pub address_pool_size: usize,
}

impl Default for Environment {
    fn default() -> Self {
        Self {
            block_timestamp: 1_700_000_000,
            block_number: 1_000_000,
            address_pool_size: 5,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Individual {
    pub transactions: Vec<Transaction>,
    pub environment: Environment,
    pub energy: f64,
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CorpusEntry {
    pub individual: Individual,
    pub coverage: HashSet<(u32, u32)>,
    pub finding_hashes: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Corpus {
    pub entries: Vec<CorpusEntry>,
}

// ---------------------------------------------------------------------------
// Fuzzing Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FuzzConfig {
    pub max_iterations: usize,
    pub population_size: usize,
    pub max_sequence_length: usize,
    pub mutation_rate: f64,
    pub address_pool_size: usize,
    pub seed: Option<u64>,
    /// Optional wall-clock time limit in milliseconds.
    pub max_duration_ms: Option<u64>,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            max_iterations: 1000,
            population_size: 50,
            max_sequence_length: 10,
            mutation_rate: 0.3,
            address_pool_size: 5,
            seed: None,
            max_duration_ms: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Dictionary (constants extracted from IR for smarter generation)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct Dictionary {
    pub values: Vec<u128>,
}

// ---------------------------------------------------------------------------
// Dependency Map (Read-After-Write analysis from IR)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FunctionDeps {
    pub reads: HashSet<String>,
    pub writes: HashSet<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DependencyMap {
    pub functions: HashMap<u32, FunctionDeps>,
}

pub fn build_dependency_map(ir_module: &IrModule, ast: &NormalizedAst) -> DependencyMap {
    let mut map = DependencyMap::default();
    for func in &ir_module.functions {
        let contract_name = ast
            .functions
            .get(func.id as usize)
            .and_then(|f| f.contract)
            .and_then(|cid| ast.contracts.get(cid as usize))
            .map(|c| c.name.clone());
        let mut reads = HashSet::new();
        let mut writes = HashSet::new();
        for block in &func.blocks {
            for instr in &block.instrs {
                match instr {
                    IrInstr::Store { dest, .. } => {
                        if is_storage_place(dest) {
                            if let Some(name) = place_root_name(dest, contract_name.as_deref()) {
                                writes.insert(name);
                            }
                        }
                    }
                    IrInstr::Load { src, .. } => {
                        if is_storage_place(src) {
                            if let Some(name) = place_root_name(src, contract_name.as_deref()) {
                                reads.insert(name);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        map.functions
            .insert(func.id, FunctionDeps { reads, writes });
    }
    map
}

fn is_storage_place(place: &IrPlace) -> bool {
    match place {
        IrPlace::Var { class, .. } => *class == PlaceClass::Storage,
        IrPlace::Member { class, .. } => *class == PlaceClass::Storage,
        IrPlace::Index { class, .. } => *class == PlaceClass::Storage,
    }
}

fn place_root_name(place: &IrPlace, contract_name: Option<&str>) -> Option<String> {
    match place {
        IrPlace::Var {
            var: IrVar::Named(name),
            ..
        } => Some(name.clone()),
        IrPlace::Member {
            base, field, root, ..
        } => {
            if is_contract_receiver(base, contract_name) {
                Some(field.clone())
            } else {
                root.clone()
            }
        }
        IrPlace::Index { root, .. } => root.clone(),
        _ => None,
    }
}

fn is_contract_receiver(value: &IrValue, contract_name: Option<&str>) -> bool {
    match value {
        IrValue::Var(IrVar::Named(name)) => {
            name == "this" || name == "super" || contract_name.map(|cn| cn == name).unwrap_or(false)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Execution Trace
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TraceEvent {
    pub function_id: u32,
    pub kind: TraceEventKind,
}

#[derive(Debug, Clone)]
pub enum TraceEventKind {
    BlockVisited {
        block_id: u32,
    },
    StorageWrite {
        var_name: String,
        slot_key: String,
        authority_sensitive: bool,
        caller_keyed: bool,
    },
    StorageRead {
        var_name: String,
        slot_key: String,
        order_sensitive: bool,
        caller_keyed: bool,
    },
    ExternalCall {
        callee: String,
        has_value: bool,
        reentrant_capable: bool,
        low_level: bool,
    },
    ReentrantCallback {
        into_function_id: u32,
    },
    Revert {
        message: Option<String>,
    },
    /// Generic condition check (e.g., require/assert)
    ConditionChecked,
    BranchOnTimestamp,
    /// Arithmetic expression mixes timestamp-derived data into a randomness-style value.
    TimestampArithmetic,
    ArithmeticOp {
        op: String,
        lhs: u128,
        rhs: u128,
        result: u128,
    },
    CallReturnUnchecked {
        callee: String,
    },
    /// msg.sender was compared to a storage value (owner check pattern)
    SenderChecked,
    /// tx.origin was loaded / used
    TxOriginUsed,
    /// selfdestruct / suicide called
    SelfDestructCall,
    /// Loop condition depends on a storage-derived value (unbounded iteration)
    UnboundedLoop {
        var_name: String,
    },
    /// A loop control point was encountered during execution.
    LoopEncountered,
    /// External call followed by state write; `checked` = whether return was require'd
    ExternalCallThenState {
        callee: String,
        checked: bool,
    },
    /// delegatecall detected
    DelegatecallDetected {
        callee: String,
    },
    /// Inline assembly block executed
    InlineAssemblyDetected,
    /// delegatecall inside a loop
    DelegatecallInLoop {
        callee: String,
    },
    /// block.number or blockhash used (PRNG / randomness source)
    BlockNumberUsed,
    /// assert/require condition depends on this.balance/address(this).balance
    BalanceInvariantCheck,
    /// ecrecover called
    EcrecoverCalled,
    /// ecrecover result compared against zero-address sentinel
    EcrecoverZeroChecked,
    /// .transfer() or .send() with hardcoded gas
    HardcodedGasCall {
        callee: String,
    },
    /// send() return value used directly in require/assert condition.
    UnsafeSendInRequire {
        callee: String,
    },
    /// Publicly callable, constructor-like function wrote an authority slot from msg.sender.
    WrongConstructorCandidate {
        function_name: String,
        slot_key: String,
    },
    /// Division followed by multiplication pattern
    DivisionBeforeMultiplication {
        function_id_inner: u32,
    },
    /// Ether sent to arbitrary / user-controlled address
    EtherSent {
        callee: String,
    },
}

#[derive(Debug, Clone, Default)]
pub struct ExecutionTrace {
    pub events: Vec<TraceEvent>,
    pub coverage: HashSet<(u32, u32)>,
    pub edge_coverage: HashSet<(u32, u32, u32)>,
    pub reverted: bool,
    pub final_state: HashMap<String, FuzzValue>,
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FuzzFinding {
    pub kind: FuzzFindingKind,
    pub severity: FuzzSeverity,
    pub message: String,
    pub tx_sequence: Vec<Transaction>,
    pub trace_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FuzzFindingKind {
    // --- Access Control ---
    Reentrancy,
    ReentrancyHeuristic,
    UncheckedCall,
    ExceptionDisorder,
    AccessControl,
    TxOriginAuth,
    SelfDestruct,
    UnsafeDelegatecall,
    DefaultVisibility,
    UninitializedPermissionCheck,
    WrongConstructorName,
    UnprotectedEtherWithdrawal,
    ArbitraryWrite,
    // --- Arithmetic ---
    IntegerOverflow,
    IntegerUnderflow,
    DivisionBeforeMultiplication,
    // --- Block Manipulation ---
    TimestampDependency,
    WeakPRNG,
    TransactionOrderDependency,
    // --- Cryptographic ---
    CryptographicIssue,
    SignatureMalleability,
    // --- Denial of Service ---
    DenialOfService,
    DosBlockGasLimit,
    HardcodedGas,
    LockedEther,
    UnsafeSendInRequire,
    DosWithFailedCall,
    // --- Storage & Memory ---
    StorageMemoryIssue,
    PublicMintBurn,
    // --- Project extensions ---
    Shadowing,
    // --- Other ---
    InvariantViolation,
}

impl FuzzFindingKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reentrancy => "reentrancy",
            Self::ReentrancyHeuristic => "reentrancy-heuristic",
            Self::TimestampDependency => "timestamp-dependency",
            Self::UncheckedCall => "unchecked-call",
            Self::ExceptionDisorder => "exception-disorder",
            Self::IntegerOverflow => "integer-overflow",
            Self::IntegerUnderflow => "integer-underflow",
            Self::DivisionBeforeMultiplication => "division-before-multiplication",
            Self::InvariantViolation => "invariant-violation",
            Self::AccessControl => "access-control",
            Self::TxOriginAuth => "tx-origin-auth",
            Self::SelfDestruct => "unprotected-selfdestruct",
            Self::DenialOfService => "denial-of-service",
            Self::DosBlockGasLimit => "dos-block-gas-limit",
            Self::UnsafeDelegatecall => "unsafe-delegatecall",
            Self::DefaultVisibility => "default-visibility",
            Self::UninitializedPermissionCheck => "uninit-permission-check",
            Self::WrongConstructorName => "wrong-constructor-name",
            Self::UnprotectedEtherWithdrawal => "unprotected-ether-withdrawal",
            Self::ArbitraryWrite => "arbitrary-write",
            Self::WeakPRNG => "weak-prng",
            Self::TransactionOrderDependency => "transaction-order-dependency",
            Self::CryptographicIssue => "cryptographic-issue",
            Self::SignatureMalleability => "signature-malleability",
            Self::HardcodedGas => "hardcoded-gas",
            Self::LockedEther => "locked-ether",
            Self::UnsafeSendInRequire => "unsafe-send-in-require",
            Self::DosWithFailedCall => "dos-with-failed-call",
            Self::StorageMemoryIssue => "storage-memory-issue",
            Self::PublicMintBurn => "public-mint-burn",
            Self::Shadowing => "shadowing",
        }
    }

    /// Canonical label used for cross-engine comparison and hybrid reporting.
    pub fn canonical_str(&self) -> &'static str {
        match self {
            Self::TxOriginAuth => "tx-origin",
            Self::HardcodedGas => "hardcoded-gas-transfer",
            Self::StorageMemoryIssue => "memory-manipulation",
            Self::ReentrancyHeuristic => "reentrancy",
            _ => self.as_str(),
        }
    }

    pub fn confidence(&self) -> FuzzConfidence {
        match self {
            Self::Reentrancy
            | Self::UncheckedCall
            | Self::TxOriginAuth
            | Self::SelfDestruct
            | Self::UnsafeDelegatecall
            | Self::UninitializedPermissionCheck
            | Self::WrongConstructorName
            | Self::UnprotectedEtherWithdrawal
            | Self::ArbitraryWrite
            | Self::UnsafeSendInRequire => FuzzConfidence::High,

            Self::TimestampDependency
            | Self::WeakPRNG
            | Self::TransactionOrderDependency
            | Self::IntegerOverflow
            | Self::IntegerUnderflow
            | Self::DivisionBeforeMultiplication
            | Self::DosBlockGasLimit
            | Self::HardcodedGas
            | Self::StorageMemoryIssue
            | Self::DosWithFailedCall
            | Self::PublicMintBurn
            | Self::Shadowing => FuzzConfidence::Medium,

            Self::ExceptionDisorder
            | Self::AccessControl
            | Self::DefaultVisibility
            | Self::DenialOfService
            | Self::LockedEther
            | Self::CryptographicIssue
            | Self::SignatureMalleability
            | Self::ReentrancyHeuristic
            | Self::InvariantViolation => FuzzConfidence::Low,
        }
    }

    /// Map this finding to its taxonomy category.
    pub fn category(&self) -> &'static str {
        match self {
            Self::AccessControl
            | Self::TxOriginAuth
            | Self::SelfDestruct
            | Self::UncheckedCall
            | Self::UnsafeDelegatecall
            | Self::DefaultVisibility
            | Self::UninitializedPermissionCheck
            | Self::WrongConstructorName
            | Self::UnprotectedEtherWithdrawal
            | Self::ArbitraryWrite => "Access Control",

            Self::IntegerOverflow | Self::IntegerUnderflow | Self::DivisionBeforeMultiplication => {
                "Arithmetic"
            }

            Self::TimestampDependency | Self::WeakPRNG | Self::TransactionOrderDependency => {
                "Block Manipulation"
            }

            Self::CryptographicIssue | Self::SignatureMalleability => "Cryptographic",

            Self::DenialOfService
            | Self::DosBlockGasLimit
            | Self::HardcodedGas
            | Self::LockedEther
            | Self::UnsafeSendInRequire
            | Self::DosWithFailedCall => "Denial of Service",

            Self::Reentrancy | Self::ReentrancyHeuristic => "Reentrancy",

            Self::StorageMemoryIssue => "Storage and Memory",
            Self::PublicMintBurn => "Access Control",
            Self::Shadowing => "Storage and Memory",

            Self::ExceptionDisorder | Self::InvariantViolation => "Access Control",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FuzzSeverity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy)]
pub enum FuzzConfidence {
    Low,
    Medium,
    High,
}

impl FuzzConfidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

impl FuzzSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

// ---------------------------------------------------------------------------
// Fuzz Report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FuzzReport {
    pub iterations: usize,
    pub coverage_pct: f64,
    pub total_blocks: usize,
    pub covered_blocks: usize,
    pub findings: Vec<FuzzFinding>,
    pub meta_findings: Vec<Finding>,
    pub corpus_size: usize,
    pub corpus_zero_reason: Option<String>,
    pub elapsed_ms: u128,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::norm::{
        Contract, ContractKind, Function, FunctionKind, Mutability, NormalizedAst, SourceFile,
        Span, Visibility,
    };

    fn make_ast() -> NormalizedAst {
        let mut ast = NormalizedAst::from_sources(vec![SourceFile {
            id: 0,
            path: "test.sol".to_string(),
            source: String::new(),
        }]);
        ast.functions.push(Function {
            id: 0,
            contract: Some(0),
            name: Some("deposit".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::External,
            mutability: Mutability::Payable,
            params: vec!["amount".to_string()],
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span {
                file: 0,
                start: 0,
                end: 0,
            },
        });
        ast.functions.push(Function {
            id: 1,
            contract: Some(0),
            name: Some("withdraw".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::External,
            mutability: Mutability::NonPayable,
            params: vec!["amount".to_string()],
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span {
                file: 0,
                start: 0,
                end: 0,
            },
        });
        ast.contracts.push(Contract {
            id: 0,
            name: "TestToken".to_string(),
            kind: ContractKind::Contract,
            bases: Vec::new(),
            functions: vec![0, 1],
            state_vars: Vec::new(),
            modifiers: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
            span: Span {
                file: 0,
                start: 0,
                end: 0,
            },
        });
        ast
    }

    #[test]
    fn extract_abis_basic() {
        let ast = make_ast();
        let abis = extract_abis(
            &ast,
            &CompilerInfo {
                compiler_name: "test".to_string(),
                compiler_version: Some("0.8.0".to_string()),
                legacy_omitted_visibility_is_public: false,
            },
        );
        assert_eq!(abis.len(), 1);
        assert_eq!(abis[0].contract_name, "TestToken");
        assert_eq!(abis[0].functions.len(), 2);
        assert_eq!(abis[0].functions[0].name, "deposit");
        assert!(abis[0].functions[0].is_payable);
        assert_eq!(abis[0].functions[1].name, "withdraw");
        assert!(!abis[0].functions[1].is_payable);
    }

    #[test]
    fn legacy_unknown_visibility_becomes_callable() {
        let mut ast = make_ast();
        ast.functions[0].visibility = Visibility::Unknown;
        let abis = extract_abis(
            &ast,
            &CompilerInfo {
                compiler_name: "test".to_string(),
                compiler_version: Some("0.4.15".to_string()),
                legacy_omitted_visibility_is_public: true,
            },
        );
        assert!(abis[0].functions[0].is_fuzz_callable());
    }

    #[test]
    fn legacy_unnamed_payable_function_is_kept_callable() {
        let mut ast = make_ast();
        ast.functions[0].name = None;
        ast.functions[0].kind = FunctionKind::Function;
        ast.functions[0].mutability = Mutability::Payable;
        ast.functions[0].params.clear();
        ast.functions[0].visibility = Visibility::Unknown;

        let abis = extract_abis(
            &ast,
            &CompilerInfo {
                compiler_name: "test".to_string(),
                compiler_version: Some("0.4.15".to_string()),
                legacy_omitted_visibility_is_public: true,
            },
        );
        assert_eq!(abis[0].functions[0].name, "<fallback-legacy>");
        assert!(abis[0].functions[0].is_fuzz_callable());
    }

    #[test]
    fn fuzz_value_truthy() {
        assert!(FuzzValue::Uint(1).is_truthy());
        assert!(!FuzzValue::Uint(0).is_truthy());
        assert!(FuzzValue::Bool(true).is_truthy());
        assert!(!FuzzValue::Bool(false).is_truthy());
    }
}
