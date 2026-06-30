// Reuses Severity and Category from static analysis — these are stable,
// engine-agnostic classifications shared across all analysis modes.
use crate::symbolic::state::StateId;
use chainvet_core::norm::Span;
use chainvet_sa::analysis::detectors::{Category, Severity};
use serde::Serialize;

use super::witness::Witness;

/// Confidence in a symbolic execution finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Confidence {
    /// SAT + concrete witness, no approximations in path.
    High,
    /// SAT but path involves keccak approx, loop truncation, or havoc.
    Medium,
    /// Pattern-based detection, no solver confirmation.
    Low,
}

impl Confidence {
    /// Return a human-readable label for this confidence level.
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }
}

/// Vulnerability kinds that SE detectors check.
///
/// One variant per distinct vulnerability pattern from the taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum SeVulnKind {
    // Arithmetic
    IntegerOverflow,
    IntegerUnderflow,
    DivisionBeforeMultiplication,
    UnsafeArrayLength,
    // Reentrancy
    Reentrancy,
    // Access Control
    UnprotectedSelfdestruct,
    TxOriginAuth,
    UnsafeDelegatecall,
    AccessControlMissing,
    UnprotectedEtherWithdrawal,
    ArbitraryStorageWrite,
    PayableDelegatecallInLoop,
    // Block Manipulation
    TimestampDependency,
    WeakPRNG,
    // Denial of Service
    UncheckedCall,
    HardcodedGasAmount,
    DosBlockGasLimit,
    DosFailedCall,
    ForceSendEther,
    UnsafeSendInRequire,
    // Cryptographic
    MissingSignatureVerification,
    SignatureMalleability,
    // Storage & Memory
    MsgValueInLoop,
    ArbitraryFunctionJump,
    UnsafeAssembly,
    // Assertions
    AssertionFailure,
}

impl SeVulnKind {
    /// Return the kebab-case string identifier for this vulnerability kind.
    pub fn as_str(&self) -> &'static str {
        match self {
            SeVulnKind::IntegerOverflow => "integer-overflow",
            SeVulnKind::IntegerUnderflow => "integer-underflow",
            SeVulnKind::DivisionBeforeMultiplication => "division-before-multiplication",
            SeVulnKind::UnsafeArrayLength => "unsafe-array-length",
            SeVulnKind::Reentrancy => "reentrancy",
            SeVulnKind::UnprotectedSelfdestruct => "unprotected-selfdestruct",
            SeVulnKind::UncheckedCall => "unchecked-call",
            SeVulnKind::TxOriginAuth => "tx-origin-auth",
            SeVulnKind::UnsafeDelegatecall => "unsafe-delegatecall",
            SeVulnKind::TimestampDependency => "timestamp-dependency",
            SeVulnKind::AccessControlMissing => "access-control-missing",
            SeVulnKind::AssertionFailure => "assertion-failure",
            SeVulnKind::WeakPRNG => "weak-prng",
            SeVulnKind::HardcodedGasAmount => "hardcoded-gas-amount",
            SeVulnKind::DosBlockGasLimit => "dos-block-gas-limit",
            SeVulnKind::DosFailedCall => "dos-failed-call",
            SeVulnKind::ForceSendEther => "force-send-ether",
            SeVulnKind::UnsafeSendInRequire => "unsafe-send-in-require",
            SeVulnKind::UnprotectedEtherWithdrawal => "unprotected-ether-withdrawal",
            SeVulnKind::ArbitraryStorageWrite => "arbitrary-storage-write",
            SeVulnKind::ArbitraryFunctionJump => "arbitrary-function-jump",
            SeVulnKind::UnsafeAssembly => "unsafe-assembly",
            SeVulnKind::MsgValueInLoop => "msg-value-in-loop",
            SeVulnKind::PayableDelegatecallInLoop => "payable-delegatecall-in-loop",
            SeVulnKind::MissingSignatureVerification => "missing-signature-verification",
            SeVulnKind::SignatureMalleability => "signature-malleability",
        }
    }

    /// Map this vulnerability kind to its parent category.
    pub fn category(&self) -> Category {
        match self {
            SeVulnKind::IntegerOverflow
            | SeVulnKind::IntegerUnderflow
            | SeVulnKind::DivisionBeforeMultiplication
            | SeVulnKind::UnsafeArrayLength => Category::Arithmetic,
            SeVulnKind::Reentrancy => Category::Reentrancy,
            SeVulnKind::UnprotectedSelfdestruct
            | SeVulnKind::TxOriginAuth
            | SeVulnKind::AccessControlMissing
            | SeVulnKind::UnsafeDelegatecall
            | SeVulnKind::UnprotectedEtherWithdrawal
            | SeVulnKind::ArbitraryStorageWrite
            | SeVulnKind::PayableDelegatecallInLoop => Category::AccessControl,
            SeVulnKind::UncheckedCall
            | SeVulnKind::HardcodedGasAmount
            | SeVulnKind::DosBlockGasLimit
            | SeVulnKind::DosFailedCall
            | SeVulnKind::ForceSendEther
            | SeVulnKind::UnsafeSendInRequire => Category::DenialOfService,
            SeVulnKind::TimestampDependency | SeVulnKind::WeakPRNG => Category::BlockManipulation,
            SeVulnKind::AssertionFailure
            | SeVulnKind::MissingSignatureVerification
            | SeVulnKind::SignatureMalleability
            | SeVulnKind::MsgValueInLoop
            | SeVulnKind::ArbitraryFunctionJump
            | SeVulnKind::UnsafeAssembly => Category::Miscellaneous,
        }
    }
}

/// A finding from the symbolic execution engine.
#[derive(Debug, Clone, Serialize)]
pub struct SeFinding {
    /// Which vulnerability was detected.
    pub kind: SeVulnKind,
    /// How severe the vulnerability is.
    pub severity: Severity,
    /// How confident the engine is in this finding.
    pub confidence: Confidence,
    /// Human-readable description of the vulnerability.
    pub message: String,
    /// Source location where the vulnerability was detected.
    pub span: Span,
    /// ID of the function containing the vulnerability, if known.
    pub function_id: Option<u32>,
    /// Human-readable descriptions of path constraints leading to this finding.
    pub path_constraints: Vec<String>,
    /// Concrete counterexample extracted from Z3 model, if available.
    pub witness: Option<Witness>,
    /// Which symbolic state triggered this finding.
    pub state_id: StateId,
    /// Depth at which the finding was reported.
    pub path_depth: u32,
}

impl SeFinding {
    /// Derive the category from the finding's vulnerability kind.
    pub fn category(&self) -> Category {
        self.kind.category()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Confidence::as_str() tests ---

    #[test]
    fn test_confidence_as_str_high() {
        // High confidence should map to the string "high".
        assert_eq!(Confidence::High.as_str(), "high");
    }

    #[test]
    fn test_confidence_as_str_medium() {
        // Medium confidence should map to the string "medium".
        assert_eq!(Confidence::Medium.as_str(), "medium");
    }

    #[test]
    fn test_confidence_as_str_low() {
        // Low confidence should map to the string "low".
        assert_eq!(Confidence::Low.as_str(), "low");
    }

    // --- SeVulnKind::as_str() tests ---

    #[test]
    fn test_sevulnkind_as_str_integer_overflow() {
        assert_eq!(SeVulnKind::IntegerOverflow.as_str(), "integer-overflow");
    }

    #[test]
    fn test_sevulnkind_as_str_integer_underflow() {
        assert_eq!(SeVulnKind::IntegerUnderflow.as_str(), "integer-underflow");
    }

    #[test]
    fn test_sevulnkind_as_str_reentrancy() {
        assert_eq!(SeVulnKind::Reentrancy.as_str(), "reentrancy");
    }

    #[test]
    fn test_sevulnkind_as_str_unprotected_selfdestruct() {
        assert_eq!(
            SeVulnKind::UnprotectedSelfdestruct.as_str(),
            "unprotected-selfdestruct"
        );
    }

    #[test]
    fn test_sevulnkind_as_str_unchecked_call() {
        assert_eq!(SeVulnKind::UncheckedCall.as_str(), "unchecked-call");
    }

    #[test]
    fn test_sevulnkind_as_str_tx_origin_auth() {
        assert_eq!(SeVulnKind::TxOriginAuth.as_str(), "tx-origin-auth");
    }

    #[test]
    fn test_sevulnkind_as_str_unsafe_delegatecall() {
        assert_eq!(
            SeVulnKind::UnsafeDelegatecall.as_str(),
            "unsafe-delegatecall"
        );
    }

    #[test]
    fn test_sevulnkind_as_str_timestamp_dependency() {
        assert_eq!(
            SeVulnKind::TimestampDependency.as_str(),
            "timestamp-dependency"
        );
    }

    #[test]
    fn test_sevulnkind_as_str_access_control_missing() {
        assert_eq!(
            SeVulnKind::AccessControlMissing.as_str(),
            "access-control-missing"
        );
    }

    #[test]
    fn test_sevulnkind_as_str_assertion_failure() {
        assert_eq!(SeVulnKind::AssertionFailure.as_str(), "assertion-failure");
    }

    // --- SeVulnKind::category() tests ---

    #[test]
    fn test_sevulnkind_category_integer_overflow_is_arithmetic() {
        assert_eq!(SeVulnKind::IntegerOverflow.category(), Category::Arithmetic);
    }

    #[test]
    fn test_sevulnkind_category_integer_underflow_is_arithmetic() {
        assert_eq!(
            SeVulnKind::IntegerUnderflow.category(),
            Category::Arithmetic
        );
    }

    #[test]
    fn test_sevulnkind_category_reentrancy_is_reentrancy() {
        assert_eq!(SeVulnKind::Reentrancy.category(), Category::Reentrancy);
    }

    #[test]
    fn test_sevulnkind_category_unprotected_selfdestruct_is_access_control() {
        assert_eq!(
            SeVulnKind::UnprotectedSelfdestruct.category(),
            Category::AccessControl
        );
    }

    #[test]
    fn test_sevulnkind_category_tx_origin_auth_is_access_control() {
        assert_eq!(SeVulnKind::TxOriginAuth.category(), Category::AccessControl);
    }

    #[test]
    fn test_sevulnkind_category_access_control_missing_is_access_control() {
        assert_eq!(
            SeVulnKind::AccessControlMissing.category(),
            Category::AccessControl
        );
    }

    #[test]
    fn test_sevulnkind_category_unsafe_delegatecall_is_access_control() {
        assert_eq!(
            SeVulnKind::UnsafeDelegatecall.category(),
            Category::AccessControl
        );
    }

    #[test]
    fn test_sevulnkind_category_unchecked_call_is_denial_of_service() {
        assert_eq!(
            SeVulnKind::UncheckedCall.category(),
            Category::DenialOfService
        );
    }

    #[test]
    fn test_sevulnkind_category_timestamp_dependency_is_block_manipulation() {
        assert_eq!(
            SeVulnKind::TimestampDependency.category(),
            Category::BlockManipulation
        );
    }

    #[test]
    fn test_sevulnkind_category_assertion_failure_is_miscellaneous() {
        assert_eq!(
            SeVulnKind::AssertionFailure.category(),
            Category::Miscellaneous
        );
    }

    // --- SeFinding construction and category delegation ---

    /// Helper to build an SeFinding with given kind, for testing.
    fn make_finding(kind: SeVulnKind) -> SeFinding {
        SeFinding {
            kind,
            severity: Severity::High,
            confidence: Confidence::High,
            message: "test finding".to_string(),
            span: Span {
                file: 0,
                start: 10,
                end: 20,
            },
            function_id: Some(42),
            path_constraints: vec!["x > 0".to_string(), "y < 100".to_string()],
            witness: None,
            state_id: 7,
            path_depth: 3,
        }
    }

    #[test]
    fn test_sefinding_category_delegates_to_kind() {
        // SeFinding::category() should return the same value as its kind's category().
        let finding = make_finding(SeVulnKind::Reentrancy);
        assert_eq!(finding.category(), Category::Reentrancy);
        assert_eq!(finding.category(), finding.kind.category());
    }

    #[test]
    fn test_sefinding_all_fields_populated() {
        // Verify that constructing an SeFinding with all fields set preserves them.
        let finding = make_finding(SeVulnKind::IntegerOverflow);
        assert_eq!(finding.kind, SeVulnKind::IntegerOverflow);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::High);
        assert_eq!(finding.message, "test finding");
        assert_eq!(finding.span.file, 0);
        assert_eq!(finding.span.start, 10);
        assert_eq!(finding.span.end, 20);
        assert_eq!(finding.function_id, Some(42));
        assert_eq!(finding.path_constraints.len(), 2);
        assert!(finding.witness.is_none());
        assert_eq!(finding.state_id, 7);
        assert_eq!(finding.path_depth, 3);
    }

    #[test]
    fn test_sefinding_category_delegates_for_all_kinds() {
        // Exhaustive check: SeFinding::category() matches kind.category() for every variant.
        let all_kinds = [
            SeVulnKind::IntegerOverflow,
            SeVulnKind::IntegerUnderflow,
            SeVulnKind::DivisionBeforeMultiplication,
            SeVulnKind::UnsafeArrayLength,
            SeVulnKind::Reentrancy,
            SeVulnKind::UnprotectedSelfdestruct,
            SeVulnKind::UncheckedCall,
            SeVulnKind::TxOriginAuth,
            SeVulnKind::UnsafeDelegatecall,
            SeVulnKind::TimestampDependency,
            SeVulnKind::AccessControlMissing,
            SeVulnKind::AssertionFailure,
            SeVulnKind::WeakPRNG,
            SeVulnKind::HardcodedGasAmount,
            SeVulnKind::DosBlockGasLimit,
            SeVulnKind::DosFailedCall,
            SeVulnKind::ForceSendEther,
            SeVulnKind::UnsafeSendInRequire,
            SeVulnKind::UnprotectedEtherWithdrawal,
            SeVulnKind::ArbitraryStorageWrite,
            SeVulnKind::ArbitraryFunctionJump,
            SeVulnKind::UnsafeAssembly,
            SeVulnKind::MsgValueInLoop,
            SeVulnKind::PayableDelegatecallInLoop,
            SeVulnKind::MissingSignatureVerification,
            SeVulnKind::SignatureMalleability,
        ];
        for kind in all_kinds {
            let finding = make_finding(kind);
            assert_eq!(
                finding.category(),
                kind.category(),
                "SeFinding::category() should delegate to kind.category() for {:?}",
                kind
            );
        }
    }
}
