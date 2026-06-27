pub mod access_control;
pub mod arithmetic;
pub mod block_manipulation;
pub mod cryptographic;
pub mod denial_of_service;
pub mod misc;
pub mod reentrancy;
pub mod storage_memory;

use serde::Serialize;

use crate::analysis::CallGraph;
use crate::norm::{NormalizedAst, Span};

// ═══════════════════════════════════════════════════════════════════════════════
//  Core types
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    pub message: String,
    pub span: Span,
    pub function: Option<u32>,
}

/// Vulnerability category — groups related detectors together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Category {
    AccessControl,
    Arithmetic,
    BlockManipulation,
    Cryptographic,
    DenialOfService,
    Reentrancy,
    StorageAndMemory,
    Miscellaneous,
}

impl Category {
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::AccessControl => "Access Control",
            Category::Arithmetic => "Arithmetic",
            Category::BlockManipulation => "Block Manipulation",
            Category::Cryptographic => "Cryptographic",
            Category::DenialOfService => "Denial of Service",
            Category::Reentrancy => "Reentrancy",
            Category::StorageAndMemory => "Storage and Memory",
            Category::Miscellaneous => "Miscellaneous",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    // ── Access Control (18) ──────────────────────────────────────────────────
    ArbitraryTransferFrom,          // AC-01
    ArbitraryCalldata,              // AC-02
    CallerNotChecked,               // AC-03
    ContractDestructable,           // AC-04
    DangerousStateVarInit,          // AC-05
    TxOrigin,                       // AC-06
    DefaultVisibility,              // AC-07
    UninitializedPermissionCheck,   // AC-08
    PermitArbitraryTransferFrom,    // AC-09
    MissingSenderCheckTransferFrom, // AC-10
    MissingInputValidation,         // AC-11
    ArbitraryEtherSend,             // AC-12
    UnprotectedSelfdestruct,        // AC-13
    UnprotectedEtherWithdrawal,     // AC-14
    UnsafeDelegatecall,             // AC-15
    UnusedReturnValue,              // AC-16
    PublicMintBurn,                 // AC-17
    ArbitraryStorageWrite,          // AC-18

    // ── Arithmetic (4) ───────────────────────────────────────────────────
    DivisionBeforeMultiplication, // AR-01
    IntegerOverflow,              // AR-02
    IntegerUnderflow,             // AR-03
    UnsafeArrayLengthAssignment,  // AR-04

    // ── Block Manipulation (3) ───────────────────────────────────────────
    DangerousBlockTimestamp,    // BM-01
    TransactionOrderDependency, // BM-02
    WeakPrng,                   // BM-03

    // ── Cryptographic (2) ────────────────────────────────────────────────
    LackOfSignatureVerification, // CR-01
    SignatureMalleability,       // CR-02

    // ── Denial of Service (6) ────────────────────────────────────────────
    HardcodedGasTransfer,   // DS-01
    LockedEther,            // DS-02
    DosBlockGasLimit,       // DS-03
    DosWithFailedCall,      // DS-04
    ForceEtherBalanceCheck, // DS-05
    UnsafeSendInRequire,    // DS-06
    UncheckedSend,          // DS-07

    // ── Reentrancy (5) ───────────────────────────────────────────────
    ReentrancyNegativeEvents, // RE-01
    ReentrancyTransfer,       // RE-02
    ReentrancySameEffect,     // RE-03
    ReentrancyEthTransfer,    // RE-04
    ReentrancyNoEthTransfer,  // RE-05

    // ── Storage & Memory (7) ─────────────────────────────────────────
    ArbitraryFunctionJump, // SM-01
    BytesVariablesRisk,    // SM-02
    MsgValueInLoop,        // SM-03
    ErrorProneAssembly,    // SM-04
    MemoryManipulation,    // SM-05
    StorageArrayByValue,   // SM-06
    DelegatecallInLoop,    // SM-07

    // ── Miscellaneous (2) ────────────────────────────────────────────────
    Shadowing,   // MI-01
    TaintedCall, // MI-02
}

pub const TAXONOMY_FINDING_KINDS: [FindingKind; 47] = [
    FindingKind::ArbitraryTransferFrom,
    FindingKind::ArbitraryCalldata,
    FindingKind::CallerNotChecked,
    FindingKind::ContractDestructable,
    FindingKind::DangerousStateVarInit,
    FindingKind::TxOrigin,
    FindingKind::DefaultVisibility,
    FindingKind::UninitializedPermissionCheck,
    FindingKind::PermitArbitraryTransferFrom,
    FindingKind::MissingSenderCheckTransferFrom,
    FindingKind::MissingInputValidation,
    FindingKind::ArbitraryEtherSend,
    FindingKind::UnprotectedSelfdestruct,
    FindingKind::UnprotectedEtherWithdrawal,
    FindingKind::UnsafeDelegatecall,
    FindingKind::UnusedReturnValue,
    FindingKind::PublicMintBurn,
    FindingKind::ArbitraryStorageWrite,
    FindingKind::DivisionBeforeMultiplication,
    FindingKind::IntegerOverflow,
    FindingKind::IntegerUnderflow,
    FindingKind::UnsafeArrayLengthAssignment,
    FindingKind::DangerousBlockTimestamp,
    FindingKind::TransactionOrderDependency,
    FindingKind::WeakPrng,
    FindingKind::LackOfSignatureVerification,
    FindingKind::SignatureMalleability,
    FindingKind::HardcodedGasTransfer,
    FindingKind::LockedEther,
    FindingKind::DosBlockGasLimit,
    FindingKind::DosWithFailedCall,
    FindingKind::ForceEtherBalanceCheck,
    FindingKind::UnsafeSendInRequire,
    FindingKind::UncheckedSend,
    FindingKind::ReentrancyNegativeEvents,
    FindingKind::ReentrancyTransfer,
    FindingKind::ReentrancySameEffect,
    FindingKind::ReentrancyEthTransfer,
    FindingKind::ReentrancyNoEthTransfer,
    FindingKind::ArbitraryFunctionJump,
    FindingKind::BytesVariablesRisk,
    FindingKind::MsgValueInLoop,
    FindingKind::ErrorProneAssembly,
    FindingKind::MemoryManipulation,
    FindingKind::StorageArrayByValue,
    FindingKind::DelegatecallInLoop,
    FindingKind::Shadowing,
];

pub const TAXONOMY_ROW_COUNT: usize = TAXONOMY_FINDING_KINDS.len();

impl FindingKind {
    pub fn is_taxonomy_kind(&self) -> bool {
        TAXONOMY_FINDING_KINDS.contains(self)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            // Access Control
            FindingKind::ArbitraryTransferFrom => "arbitrary-transfer-from",
            FindingKind::ArbitraryCalldata => "arbitrary-calldata",
            FindingKind::CallerNotChecked => "caller-not-checked",
            FindingKind::ContractDestructable => "contract-destructable",
            FindingKind::DangerousStateVarInit => "dangerous-state-var-init",
            FindingKind::TxOrigin => "tx-origin",
            FindingKind::DefaultVisibility => "default-visibility",
            FindingKind::UninitializedPermissionCheck => "uninit-permission-check",
            FindingKind::PermitArbitraryTransferFrom => "permit-arbitrary-transfer-from",
            FindingKind::MissingSenderCheckTransferFrom => "missing-sender-check-transfer-from",
            FindingKind::MissingInputValidation => "missing-input-validation",
            FindingKind::ArbitraryEtherSend => "arbitrary-ether-send",
            FindingKind::UnprotectedSelfdestruct => "unprotected-selfdestruct",
            FindingKind::UnprotectedEtherWithdrawal => "unprotected-ether-withdrawal",
            FindingKind::UnsafeDelegatecall => "unsafe-delegatecall",
            FindingKind::UnusedReturnValue => "unused-return-value",
            FindingKind::PublicMintBurn => "public-mint-burn",
            FindingKind::ArbitraryStorageWrite => "arbitrary-storage-write",
            // Arithmetic
            FindingKind::DivisionBeforeMultiplication => "division-before-multiplication",
            FindingKind::IntegerOverflow => "integer-overflow",
            FindingKind::IntegerUnderflow => "integer-underflow",
            FindingKind::UnsafeArrayLengthAssignment => "unsafe-array-length-assignment",
            // Block Manipulation
            FindingKind::DangerousBlockTimestamp => "dangerous-block-timestamp",
            FindingKind::TransactionOrderDependency => "transaction-order-dependency",
            FindingKind::WeakPrng => "weak-prng",
            // Cryptographic
            FindingKind::LackOfSignatureVerification => "lack-of-signature-verification",
            FindingKind::SignatureMalleability => "signature-malleability",
            // Denial of Service
            FindingKind::HardcodedGasTransfer => "hardcoded-gas-transfer",
            FindingKind::LockedEther => "locked-ether",
            FindingKind::DosBlockGasLimit => "dos-block-gas-limit",
            FindingKind::DosWithFailedCall => "dos-with-failed-call",
            FindingKind::ForceEtherBalanceCheck => "force-ether-balance-check",
            FindingKind::UnsafeSendInRequire => "unsafe-send-in-require",
            FindingKind::UncheckedSend => "unchecked-send",
            // Reentrancy
            FindingKind::ReentrancyNegativeEvents => "reentrancy-negative-events",
            FindingKind::ReentrancyTransfer => "reentrancy-transfer",
            FindingKind::ReentrancySameEffect => "reentrancy-same-effect",
            FindingKind::ReentrancyEthTransfer => "reentrancy-eth-transfer",
            FindingKind::ReentrancyNoEthTransfer => "reentrancy-no-eth-transfer",
            // Storage & Memory
            FindingKind::ArbitraryFunctionJump => "arbitrary-function-jump",
            FindingKind::BytesVariablesRisk => "bytes-variables-risk",
            FindingKind::MsgValueInLoop => "msg-value-in-loop",
            FindingKind::ErrorProneAssembly => "error-prone-assembly",
            FindingKind::MemoryManipulation => "memory-manipulation",
            FindingKind::StorageArrayByValue => "storage-array-by-value",
            FindingKind::DelegatecallInLoop => "delegatecall-in-loop",
            // Miscellaneous
            FindingKind::Shadowing => "shadowing",
            FindingKind::TaintedCall => "tainted-call",
        }
    }

    /// Which category this finding belongs to.
    pub fn category(&self) -> Category {
        match self {
            FindingKind::ArbitraryTransferFrom
            | FindingKind::ArbitraryCalldata
            | FindingKind::CallerNotChecked
            | FindingKind::ContractDestructable
            | FindingKind::DangerousStateVarInit
            | FindingKind::TxOrigin
            | FindingKind::DefaultVisibility
            | FindingKind::UninitializedPermissionCheck
            | FindingKind::PermitArbitraryTransferFrom
            | FindingKind::MissingSenderCheckTransferFrom
            | FindingKind::MissingInputValidation
            | FindingKind::ArbitraryEtherSend
            | FindingKind::UnprotectedSelfdestruct
            | FindingKind::UnprotectedEtherWithdrawal
            | FindingKind::UnsafeDelegatecall
            | FindingKind::UnusedReturnValue
            | FindingKind::PublicMintBurn
            | FindingKind::ArbitraryStorageWrite => Category::AccessControl,

            FindingKind::DivisionBeforeMultiplication
            | FindingKind::IntegerOverflow
            | FindingKind::IntegerUnderflow
            | FindingKind::UnsafeArrayLengthAssignment => Category::Arithmetic,

            FindingKind::DangerousBlockTimestamp
            | FindingKind::TransactionOrderDependency
            | FindingKind::WeakPrng => Category::BlockManipulation,

            FindingKind::LackOfSignatureVerification | FindingKind::SignatureMalleability => {
                Category::Cryptographic
            }

            FindingKind::HardcodedGasTransfer
            | FindingKind::LockedEther
            | FindingKind::DosBlockGasLimit
            | FindingKind::DosWithFailedCall
            | FindingKind::ForceEtherBalanceCheck
            | FindingKind::UnsafeSendInRequire
            | FindingKind::UncheckedSend => Category::DenialOfService,

            FindingKind::ReentrancyNegativeEvents
            | FindingKind::ReentrancyTransfer
            | FindingKind::ReentrancySameEffect
            | FindingKind::ReentrancyEthTransfer
            | FindingKind::ReentrancyNoEthTransfer => Category::Reentrancy,

            FindingKind::ArbitraryFunctionJump
            | FindingKind::BytesVariablesRisk
            | FindingKind::MsgValueInLoop
            | FindingKind::ErrorProneAssembly
            | FindingKind::MemoryManipulation
            | FindingKind::StorageArrayByValue
            | FindingKind::DelegatecallInLoop => Category::StorageAndMemory,

            FindingKind::Shadowing | FindingKind::TaintedCall => Category::Miscellaneous,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Detector runner
// ═══════════════════════════════════════════════════════════════════════════════

use crate::analysis::taint::TaintSummary;

pub fn run_detectors(
    ast: &NormalizedAst,
    call_graph: &CallGraph,
    taint_summaries: &[TaintSummary],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // ── Access Control category (18 rules) ───────────────────────────────
    findings.extend(access_control::detect_all(ast, call_graph, taint_summaries));

    // ── Arithmetic category (4 rules) ────────────────────────────────────
    findings.extend(arithmetic::detect_all(ast, taint_summaries));

    // ── Block Manipulation category (3 rules) ────────────────────────────
    findings.extend(block_manipulation::detect_all(ast));

    // ── Cryptographic category (2 rules) ─────────────────────────────────
    findings.extend(cryptographic::detect_all(ast));

    // ── Denial of Service category (6 rules) ─────────────────────────────
    findings.extend(denial_of_service::detect_all(ast));

    // ── Reentrancy category (5 rules) ────────────────────────────────────
    findings.extend(reentrancy::detect_all(ast));

    // ── Storage & Memory category (7 rules) ──────────────────────────────
    findings.extend(storage_memory::detect_all(ast));

    // ── Miscellaneous category (2 rules) ─────────────────────────────────
    findings.extend(misc::detect_all(ast, taint_summaries));

    findings
}

#[cfg(test)]
mod tests {
    use super::{FindingKind, run_detectors};
    use crate::{analysis, cfg, frontend, ir};

    fn benchmark_findings(path: &str) -> Vec<super::Finding> {
        let output = frontend::load_project(path).expect("frontend load should succeed");
        let ast = &output.ast;
        let ir_module = ir::lower_module(ast);
        let cfgs = cfg::build_from_ir(&ir_module);
        let call_graph = analysis::build_call_graph(ast);
        let taint = analysis::taint::analyze(ast, &cfgs);
        run_detectors(ast, &call_graph, &taint)
    }

    #[test]
    fn detects_auction_push_refund_dos() {
        let findings = benchmark_findings(
            "Benchmarks/Not-so-smart/not-so-smart-contracts-master/denial_of_service/auction.sol",
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == FindingKind::DosWithFailedCall),
            "expected dos-with-failed-call finding for auction.sol"
        );
    }

    #[test]
    fn detects_list_dos_twice() {
        let findings = benchmark_findings(
            "Benchmarks/Not-so-smart/not-so-smart-contracts-master/denial_of_service/list_dos.sol",
        );
        let count = findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.kind,
                    FindingKind::DosWithFailedCall | FindingKind::DosBlockGasLimit
                )
            })
            .count();
        assert!(
            count >= 2,
            "expected at least two DoS findings for list_dos.sol, got {count}"
        );
    }

    #[test]
    fn detects_race_condition_tod() {
        let findings = benchmark_findings(
            "Benchmarks/Not-so-smart/not-so-smart-contracts-master/race_condition/RaceCondition.sol",
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == FindingKind::TransactionOrderDependency),
            "expected transaction-order-dependency finding for RaceCondition.sol"
        );
    }

    #[test]
    fn detects_walletlibrary_init_takeover() {
        let findings = benchmark_findings(
            "Benchmarks/Not-so-smart/not-so-smart-contracts-master/unprotected_function/WalletLibrary_source_code/WalletLibrary.sol",
        );
        assert!(
            findings.iter().any(|finding| {
                matches!(
                    finding.kind,
                    FindingKind::UninitializedPermissionCheck | FindingKind::CallerNotChecked
                )
            }),
            "expected init takeover finding for WalletLibrary.sol"
        );
    }

    #[test]
    fn detects_kotet_unchecked_send() {
        let findings = benchmark_findings(
            "Benchmarks/Not-so-smart/not-so-smart-contracts-master/unchecked_external_call/KotET_source_code/KingOfTheEtherThrone.sol",
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == FindingKind::UnusedReturnValue),
            "expected unused-return-value finding for KingOfTheEtherThrone.sol"
        );
    }
}
