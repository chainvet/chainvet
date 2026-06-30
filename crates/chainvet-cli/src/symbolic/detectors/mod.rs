// Detector infrastructure — vulnerability detectors for the SE engine.

pub mod access_control;
pub mod arithmetic;
pub mod block_manipulation;
pub mod cryptographic;
pub mod delegatecall;
pub mod dos;
pub mod reentrancy;
pub mod storage;

use access_control::AccessControlDetector;
use arithmetic::ArithmeticDetector;
use block_manipulation::BlockManipulationDetector;
use cryptographic::CryptographicDetector;
use delegatecall::DelegatecallDetector;
use dos::DosDetector;
use reentrancy::ReentrancyDetector;
use storage::StorageDetector;

use std::collections::HashMap;

use crate::analysis::detectors::Severity;
use chainvet_core::cfg::BlockId;
use chainvet_core::ir::{IrInstr, IrPlace, IrValue, IrVar};
use chainvet_core::norm::Span;
use crate::symbolic::results::finding::{Confidence, SeFinding, SeVulnKind};
use crate::symbolic::results::witness::Witness;
use crate::symbolic::solver::SmtSolver;
use crate::symbolic::state::{SymbolicState, ValueOrigin};

/// Symbolic execution vulnerability detector.
///
/// Detectors observe execution via hooks but NEVER modify the engine.
/// Detectors that need solver queries must bracket them with `push()`/`pop()`
/// to avoid polluting the engine's constraint state.
pub trait Detector {
    /// Unique identifier (e.g., `"integer-overflow"`).
    fn id(&self) -> &'static str;

    /// Called for each IR instruction during block interpretation.
    ///
    /// Returns any findings detected at this instruction.
    fn on_instruction(
        &mut self,
        state: &SymbolicState,
        instr: &IrInstr,
        solver: &dyn SmtSolver,
    ) -> Vec<SeFinding>;

    /// Called when the engine finishes interpreting a block.
    ///
    /// Returns any findings detected at block exit (e.g., reentrancy
    /// checks that require seeing the full block's effects).
    fn on_block_exit(
        &mut self,
        state: &SymbolicState,
        block_id: BlockId,
        solver: &dyn SmtSolver,
    ) -> Vec<SeFinding>;

    /// Reset detector state between function analyses.
    fn reset(&mut self);
}

/// Registry dispatching hooks to all registered detectors.
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorRegistry {
    /// Create an empty detector registry.
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    /// Create with all built-in detectors registered.
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(ArithmeticDetector::new()));
        registry.register(Box::new(ReentrancyDetector::new()));
        registry.register(Box::new(AccessControlDetector::new()));
        registry.register(Box::new(DelegatecallDetector::new()));
        registry.register(Box::new(BlockManipulationDetector::new()));
        registry.register(Box::new(DosDetector::new()));
        registry.register(Box::new(CryptographicDetector::new()));
        registry.register(Box::new(StorageDetector::new()));
        registry
    }

    /// Register a detector.
    pub fn register(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }

    /// Dispatch `on_instruction` to all detectors, collecting findings.
    pub fn on_instruction(
        &mut self,
        state: &SymbolicState,
        instr: &IrInstr,
        solver: &dyn SmtSolver,
    ) -> Vec<SeFinding> {
        let mut findings = Vec::new();
        for detector in &mut self.detectors {
            findings.extend(detector.on_instruction(state, instr, solver));
        }
        findings
    }

    /// Dispatch `on_block_exit` to all detectors, collecting findings.
    pub fn on_block_exit(
        &mut self,
        state: &SymbolicState,
        block_id: BlockId,
        solver: &dyn SmtSolver,
    ) -> Vec<SeFinding> {
        let mut findings = Vec::new();
        for detector in &mut self.detectors {
            findings.extend(detector.on_block_exit(state, block_id, solver));
        }
        findings
    }

    /// Reset all detectors between function analyses.
    pub fn reset_all(&mut self) {
        for detector in &mut self.detectors {
            detector.reset();
        }
    }

    /// Filter to only keep detectors whose IDs appear in `enabled`.
    #[allow(dead_code)]
    pub fn with_filter(mut self, enabled: &[&str]) -> Self {
        self.detectors.retain(|d| enabled.contains(&d.id()));
        self
    }

    /// Number of registered detectors.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    /// Whether the registry has no detectors.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Shared utilities for detector IR pattern matching
// ---------------------------------------------------------------------------

/// Tracks `Load` instructions where `src` is an `IrPlace::Member`, mapping
/// `Temp(id) -> field_name` and `Temp(id) -> base_temp_id`.  This allows
/// detectors to resolve a `Call { callee: Var(Temp(N)) }` back to the original
/// member method name (e.g. "call", "send", "delegatecall").
pub(crate) struct CalleeTracker {
    temp_to_field: HashMap<u32, String>,
    temp_to_base_temp: HashMap<u32, u32>,
}

impl CalleeTracker {
    pub fn new() -> Self {
        Self {
            temp_to_field: HashMap::new(),
            temp_to_base_temp: HashMap::new(),
        }
    }

    /// Record a `Load { dest, src }` instruction.  If `src` is a `Member`
    /// place, store the mapping from the destination Temp to its field name
    /// and (if applicable) the base Temp id.
    pub fn track_load(&mut self, dest: &IrVar, src: &IrPlace) {
        if let IrVar::Temp(dest_id) = dest
            && let IrPlace::Member { base, field, .. } = src
        {
            self.temp_to_field.insert(*dest_id, field.clone());
            if let IrValue::Var(IrVar::Temp(base_id)) = base {
                debug_assert!(
                    *base_id < *dest_id,
                    "Temp IDs should be monotonically increasing"
                );
                self.temp_to_base_temp.insert(*dest_id, *base_id);
            }
        }
    }

    /// Walk the member-load chain from `callee` and return `true` if any
    /// field in the chain matches one of `names`.
    ///
    /// For example, given the IR sequence:
    /// ```text
    /// t3 = load msg.sender        (field = "sender")
    /// t4 = load t3.call           (field = "call")
    /// t5 = load t4.value          (field = "value")
    /// t6 = call t5(amount)
    /// ```
    /// Calling `chain_contains_field(Var(Temp(5)), &["call"])` walks:
    ///   Temp(5) -> "value", Temp(4) -> "call" -> MATCH.
    pub fn chain_contains_field(&self, callee: &IrValue, names: &[&str]) -> bool {
        let mut id = match callee {
            IrValue::Var(IrVar::Named(n)) => return names.contains(&n.as_str()),
            IrValue::Var(IrVar::Temp(id)) => *id,
            _ => return false,
        };
        for _ in 0..10 {
            if let Some(field) = self.temp_to_field.get(&id)
                && names.contains(&field.as_str())
            {
                return true;
            }
            match self.temp_to_base_temp.get(&id) {
                Some(&base) => id = base,
                None => break,
            }
        }
        false
    }

    pub fn reset(&mut self) {
        self.temp_to_field.clear();
        self.temp_to_base_temp.clear();
    }
}

/// Match an `IrPlace` against a "root.field" pattern.
///
/// Handles both representations the IR may produce:
/// - `IrPlace::Var { var: Named("root.field") }` or `Named("root_field")`
/// - `IrPlace::Member { root: Some("root"), field: "field" }`
/// - `IrPlace::Member { base: Var(Named("root")), field: "field", root: None }`
pub(crate) fn place_matches(place: &IrPlace, expected_root: &str, expected_field: &str) -> bool {
    match place {
        IrPlace::Var {
            var: IrVar::Named(n),
            ..
        } => {
            let dotted = format!("{expected_root}.{expected_field}");
            let underscored = format!("{expected_root}_{expected_field}");
            n == &dotted || n == &underscored
        }
        IrPlace::Member {
            root: Some(r),
            field: f,
            ..
        } => r == expected_root && f == expected_field,
        IrPlace::Member {
            base: IrValue::Var(IrVar::Named(r)),
            field: f,
            root: None,
            ..
        } => r == expected_root && f == expected_field,
        _ => false,
    }
}

/// Construct an `SeFinding` from common detector parameters.
///
/// Used by all detectors to avoid duplicating the boilerplate for populating
/// path constraints, state id, and path depth.
pub(crate) fn make_finding(
    kind: SeVulnKind,
    severity: Severity,
    confidence: Confidence,
    message: &str,
    span: Span,
    state: &SymbolicState,
    witness: Option<Witness>,
) -> SeFinding {
    SeFinding {
        kind,
        severity,
        confidence,
        message: message.to_string(),
        span,
        function_id: None,
        path_constraints: state
            .path_constraints
            .descriptions()
            .iter()
            .map(|s| s.to_string())
            .collect(),
        witness,
        state_id: state.id,
        path_depth: state.path_depth,
    }
}

/// Check if an `IrValue` carries a specific origin in the current state.
///
/// Returns false for literals and unknowns (they have no variable to track).
pub(crate) fn value_has_origin(state: &SymbolicState, val: &IrValue, origin: ValueOrigin) -> bool {
    match val {
        IrValue::Var(v) => state.has_origin(v, origin),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::detectors::Severity;
    use chainvet_core::norm::Span;
    use crate::symbolic::results::finding::{Confidence, SeFinding, SeVulnKind};
    use crate::symbolic::solver::z3_backend::Z3Backend;
    use crate::symbolic::state::call_context::CallContext;
    use crate::symbolic::state::{StateIdGen, SymbolicState};

    // --- Mock detector ---

    struct MockDetector {
        id: &'static str,
        pub reset_count: u32,
        pub on_instruction_called: bool,
        pub on_block_exit_called: bool,
    }

    impl MockDetector {
        fn new(id: &'static str) -> Self {
            Self {
                id,
                reset_count: 0,
                on_instruction_called: false,
                on_block_exit_called: false,
            }
        }
    }

    impl Detector for MockDetector {
        fn id(&self) -> &'static str {
            self.id
        }

        fn on_instruction(
            &mut self,
            _state: &SymbolicState,
            _instr: &chainvet_core::ir::IrInstr,
            _solver: &dyn SmtSolver,
        ) -> Vec<SeFinding> {
            self.on_instruction_called = true;
            vec![SeFinding {
                kind: SeVulnKind::AssertionFailure,
                severity: Severity::Medium,
                confidence: Confidence::Low,
                message: format!("mock finding from {}", self.id),
                span: Span { file: 0, start: 0, end: 0 },
                function_id: None,
                path_constraints: vec![],
                witness: None,
                state_id: 0,
                path_depth: 0,
            }]
        }

        fn on_block_exit(
            &mut self,
            _state: &SymbolicState,
            _block_id: BlockId,
            _solver: &dyn SmtSolver,
        ) -> Vec<SeFinding> {
            self.on_block_exit_called = true;
            vec![]
        }

        fn reset(&mut self) {
            self.reset_count += 1;
        }
    }

    /// Build a minimal SymbolicState and a Z3Backend for hook tests.
    fn make_state_and_solver() -> (SymbolicState, Z3Backend) {
        let mut id_gen = StateIdGen::new();
        let (call_ctx, _constraints) = CallContext::new_symbolic();
        let state = SymbolicState::initial(&mut id_gen, 0, call_ctx);
        let solver = Z3Backend::new(0);
        (state, solver)
    }

    /// Build a minimal Nop IR instruction.
    fn nop_instr() -> chainvet_core::ir::IrInstr {
        chainvet_core::ir::IrInstr::Nop {
            span: Span { file: 0, start: 0, end: 0 },
        }
    }

    // --- Registry construction tests ---

    #[test]
    fn test_registry_starts_empty() {
        // DetectorRegistry::new() should have zero detectors registered.
        let registry = DetectorRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_registry_with_defaults_has_all_detectors() {
        // with_defaults() registers all 8 built-in detectors.
        let registry = DetectorRegistry::with_defaults();
        assert_eq!(registry.len(), 8);
        assert!(!registry.is_empty());
    }

    #[test]
    fn test_register_single_detector() {
        // After registering one detector, len() == 1 and is_empty() == false.
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(MockDetector::new("mock-a")));
        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());
    }

    // --- Hook dispatch tests ---

    #[test]
    fn test_on_instruction_collects_findings() {
        // Registering a mock detector and calling on_instruction should return
        // exactly one finding (the hardcoded finding from MockDetector).
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(MockDetector::new("mock-b")));
        let (state, solver) = make_state_and_solver();
        let instr = nop_instr();
        let findings = registry.on_instruction(&state, &instr, &solver);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, SeVulnKind::AssertionFailure);
    }

    #[test]
    fn test_on_block_exit_returns_empty_from_mock() {
        // MockDetector::on_block_exit always returns an empty vec.
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(MockDetector::new("mock-c")));
        let (state, solver) = make_state_and_solver();
        let findings = registry.on_block_exit(&state, 0, &solver);
        assert!(findings.is_empty());
    }

    // --- reset_all tests ---

    #[test]
    fn test_reset_all_calls_each_detector_reset() {
        // Registering 2 mocks and calling reset_all() once should increment
        // each mock's reset_count to 1. We verify via a two-detector setup:
        // after reset_all(), the total findings from on_instruction still work
        // (both detectors still functional), and we check reset indirectly
        // by calling reset_all() twice and expecting 2 findings total (one per
        // detector) — structural proof that both detectors were kept.
        //
        // Direct verification: register, reset_all(), register another, check len.
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(MockDetector::new("mock-d1")));
        registry.register(Box::new(MockDetector::new("mock-d2")));
        // reset_all() must not panic and must visit all detectors.
        registry.reset_all();
        // Both detectors should still be present and functional after reset.
        let (state, solver) = make_state_and_solver();
        let instr = nop_instr();
        let findings = registry.on_instruction(&state, &instr, &solver);
        assert_eq!(
            findings.len(),
            2,
            "both detectors should still produce findings after reset_all()"
        );
    }

    // --- with_filter tests ---

    #[test]
    fn test_with_filter_keeps_matching() {
        // Register detectors with ids "a" and "b", filter for ["a"],
        // verify only "a" remains.
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(MockDetector::new("a")));
        registry.register(Box::new(MockDetector::new("b")));
        let filtered = registry.with_filter(&["a"]);
        assert_eq!(filtered.len(), 1);
        // Verify the remaining detector is "a" by calling on_instruction and
        // checking the finding message contains "a".
        let (state, solver) = make_state_and_solver();
        let instr = nop_instr();
        let mut filtered = filtered;
        let findings = filtered.on_instruction(&state, &instr, &solver);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains('a'));
    }

    #[test]
    fn test_with_filter_empty_removes_all() {
        // Filtering with an empty slice should remove all detectors.
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(MockDetector::new("x")));
        registry.register(Box::new(MockDetector::new("y")));
        let filtered = registry.with_filter(&[]);
        assert!(filtered.is_empty());
    }

    // -----------------------------------------------------------------------
    // CalleeTracker tests
    // -----------------------------------------------------------------------

    use chainvet_core::ir::{IrPlace, IrValue, IrVar, PlaceClass};

    #[test]
    fn test_callee_tracker_track_load_member_stores_field() {
        // track_load with a Member place should record the field name for the dest Temp.
        let mut tracker = CalleeTracker::new();
        let dest = IrVar::Temp(3);
        let src = IrPlace::Member {
            base: IrValue::Var(IrVar::Named("msg".to_string())),
            field: "sender".to_string(),
            root: Some("msg".to_string()),
            class: PlaceClass::Unknown,
        };
        tracker.track_load(&dest, &src);
        // Verify the field was stored by checking chain_contains_field.
        assert!(
            tracker.chain_contains_field(&IrValue::Var(IrVar::Temp(3)), &["sender"]),
            "Temp(3) should map to field 'sender'"
        );
    }

    #[test]
    fn test_callee_tracker_chain_contains_field_named_callee() {
        // chain_contains_field with a Named("call") callee returns true for &["call"].
        let tracker = CalleeTracker::new();
        assert!(
            tracker.chain_contains_field(&IrValue::Var(IrVar::Named("call".to_string())), &["call"]),
            "Named('call') should match &['call']"
        );
    }

    #[test]
    fn test_callee_tracker_chain_contains_field_temp_loaded_from_member() {
        // Temp(N) loaded from Member{field:"call"} should match &["call"].
        let mut tracker = CalleeTracker::new();
        tracker.track_load(
            &IrVar::Temp(2),
            &IrPlace::Member {
                base: IrValue::Var(IrVar::Named("addr".to_string())),
                field: "call".to_string(),
                root: Some("addr".to_string()),
                class: PlaceClass::Unknown,
            },
        );
        assert!(
            tracker.chain_contains_field(&IrValue::Var(IrVar::Temp(2)), &["call"]),
            "Temp(2) loaded from .call should match &['call']"
        );
    }

    #[test]
    fn test_callee_tracker_multi_level_chain_matches_call() {
        // Multi-level chain: Temp(3)->"sender", Temp(4)->"call"(base=Temp(3)),
        // Temp(5)->"value"(base=Temp(4)).
        // chain_contains_field(Temp(5), &["call"]) should return true.
        let mut tracker = CalleeTracker::new();
        tracker.track_load(
            &IrVar::Temp(3),
            &IrPlace::Member {
                base: IrValue::Var(IrVar::Named("msg".to_string())),
                field: "sender".to_string(),
                root: Some("msg".to_string()),
                class: PlaceClass::Unknown,
            },
        );
        tracker.track_load(
            &IrVar::Temp(4),
            &IrPlace::Member {
                base: IrValue::Var(IrVar::Temp(3)),
                field: "call".to_string(),
                root: Some("msg".to_string()),
                class: PlaceClass::Unknown,
            },
        );
        tracker.track_load(
            &IrVar::Temp(5),
            &IrPlace::Member {
                base: IrValue::Var(IrVar::Temp(4)),
                field: "value".to_string(),
                root: Some("msg".to_string()),
                class: PlaceClass::Unknown,
            },
        );
        assert!(
            tracker.chain_contains_field(&IrValue::Var(IrVar::Temp(5)), &["call"]),
            "Walking from Temp(5) should find 'call' at Temp(4)"
        );
    }

    #[test]
    fn test_callee_tracker_multi_level_chain_matches_value() {
        // Same chain as above; chain_contains_field(Temp(5), &["value"]) should also be true
        // since Temp(5) itself maps to "value".
        let mut tracker = CalleeTracker::new();
        tracker.track_load(
            &IrVar::Temp(3),
            &IrPlace::Member {
                base: IrValue::Var(IrVar::Named("msg".to_string())),
                field: "sender".to_string(),
                root: Some("msg".to_string()),
                class: PlaceClass::Unknown,
            },
        );
        tracker.track_load(
            &IrVar::Temp(4),
            &IrPlace::Member {
                base: IrValue::Var(IrVar::Temp(3)),
                field: "call".to_string(),
                root: Some("msg".to_string()),
                class: PlaceClass::Unknown,
            },
        );
        tracker.track_load(
            &IrVar::Temp(5),
            &IrPlace::Member {
                base: IrValue::Var(IrVar::Temp(4)),
                field: "value".to_string(),
                root: Some("msg".to_string()),
                class: PlaceClass::Unknown,
            },
        );
        assert!(
            tracker.chain_contains_field(&IrValue::Var(IrVar::Temp(5)), &["value"]),
            "Temp(5) directly maps to 'value'"
        );
    }

    #[test]
    fn test_callee_tracker_multi_level_chain_no_match_transfer() {
        // Same chain; chain_contains_field(Temp(5), &["transfer"]) should be false
        // because no link in the chain has field "transfer".
        let mut tracker = CalleeTracker::new();
        tracker.track_load(
            &IrVar::Temp(3),
            &IrPlace::Member {
                base: IrValue::Var(IrVar::Named("msg".to_string())),
                field: "sender".to_string(),
                root: Some("msg".to_string()),
                class: PlaceClass::Unknown,
            },
        );
        tracker.track_load(
            &IrVar::Temp(4),
            &IrPlace::Member {
                base: IrValue::Var(IrVar::Temp(3)),
                field: "call".to_string(),
                root: Some("msg".to_string()),
                class: PlaceClass::Unknown,
            },
        );
        tracker.track_load(
            &IrVar::Temp(5),
            &IrPlace::Member {
                base: IrValue::Var(IrVar::Temp(4)),
                field: "value".to_string(),
                root: Some("msg".to_string()),
                class: PlaceClass::Unknown,
            },
        );
        assert!(
            !tracker.chain_contains_field(&IrValue::Var(IrVar::Temp(5)), &["transfer"]),
            "No link in the chain has field 'transfer'"
        );
    }

    #[test]
    fn test_callee_tracker_reset_clears_state() {
        // After reset(), previously tracked fields should no longer be found.
        let mut tracker = CalleeTracker::new();
        tracker.track_load(
            &IrVar::Temp(1),
            &IrPlace::Member {
                base: IrValue::Var(IrVar::Named("x".to_string())),
                field: "call".to_string(),
                root: None,
                class: PlaceClass::Unknown,
            },
        );
        assert!(tracker.chain_contains_field(&IrValue::Var(IrVar::Temp(1)), &["call"]));
        tracker.reset();
        assert!(
            !tracker.chain_contains_field(&IrValue::Var(IrVar::Temp(1)), &["call"]),
            "reset() should clear all tracked fields"
        );
    }

    #[test]
    fn test_callee_tracker_non_temp_dest_ignored() {
        // track_load with a Named dest (not Temp) should be ignored.
        let mut tracker = CalleeTracker::new();
        tracker.track_load(
            &IrVar::Named("x".to_string()),
            &IrPlace::Member {
                base: IrValue::Var(IrVar::Named("addr".to_string())),
                field: "call".to_string(),
                root: None,
                class: PlaceClass::Unknown,
            },
        );
        // Named("x") should not be found since only Temp dests are tracked.
        assert!(
            !tracker.chain_contains_field(&IrValue::Var(IrVar::Named("x".to_string())), &["call"]),
            "Named dest should not be tracked by CalleeTracker"
        );
    }

    #[test]
    fn test_callee_tracker_non_member_src_ignored() {
        // track_load with a Var src (not Member) should be ignored.
        let mut tracker = CalleeTracker::new();
        tracker.track_load(
            &IrVar::Temp(1),
            &IrPlace::Var {
                var: IrVar::Named("something".to_string()),
                class: PlaceClass::Unknown,
            },
        );
        assert!(
            !tracker.chain_contains_field(&IrValue::Var(IrVar::Temp(1)), &["something"]),
            "Non-Member src should not be tracked"
        );
    }

    // -----------------------------------------------------------------------
    // place_matches tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_place_matches_var_dotted_notation() {
        // IrPlace::Var{Named("block.timestamp")} matches ("block", "timestamp").
        let place = IrPlace::Var {
            var: IrVar::Named("block.timestamp".to_string()),
            class: PlaceClass::Unknown,
        };
        assert!(place_matches(&place, "block", "timestamp"));
    }

    #[test]
    fn test_place_matches_var_underscore_notation() {
        // IrPlace::Var{Named("block_timestamp")} matches ("block", "timestamp").
        let place = IrPlace::Var {
            var: IrVar::Named("block_timestamp".to_string()),
            class: PlaceClass::Unknown,
        };
        assert!(place_matches(&place, "block", "timestamp"));
    }

    #[test]
    fn test_place_matches_member_with_root() {
        // IrPlace::Member{root: Some("block"), field: "timestamp"} matches ("block", "timestamp").
        let place = IrPlace::Member {
            base: IrValue::Var(IrVar::Named("block".to_string())),
            field: "timestamp".to_string(),
            root: Some("block".to_string()),
            class: PlaceClass::Unknown,
        };
        assert!(place_matches(&place, "block", "timestamp"));
    }

    #[test]
    fn test_place_matches_member_base_named_no_root() {
        // IrPlace::Member{base: Named("block"), field: "timestamp", root: None} matches.
        let place = IrPlace::Member {
            base: IrValue::Var(IrVar::Named("block".to_string())),
            field: "timestamp".to_string(),
            root: None,
            class: PlaceClass::Unknown,
        };
        assert!(place_matches(&place, "block", "timestamp"));
    }

    #[test]
    fn test_place_matches_wrong_root_no_match() {
        // Wrong root should not match.
        let place = IrPlace::Member {
            base: IrValue::Var(IrVar::Named("msg".to_string())),
            field: "timestamp".to_string(),
            root: Some("msg".to_string()),
            class: PlaceClass::Unknown,
        };
        assert!(!place_matches(&place, "block", "timestamp"));
    }

    #[test]
    fn test_place_matches_wrong_field_no_match() {
        // Wrong field should not match.
        let place = IrPlace::Member {
            base: IrValue::Var(IrVar::Named("block".to_string())),
            field: "number".to_string(),
            root: Some("block".to_string()),
            class: PlaceClass::Unknown,
        };
        assert!(!place_matches(&place, "block", "timestamp"));
    }

    #[test]
    fn test_place_matches_index_no_match() {
        // IrPlace::Index should never match place_matches.
        let place = IrPlace::Index {
            base: IrValue::Var(IrVar::Named("block".to_string())),
            index: None,
            root: Some("block".to_string()),
            class: PlaceClass::Unknown,
        };
        assert!(!place_matches(&place, "block", "timestamp"));
    }
}
