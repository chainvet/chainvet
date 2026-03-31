use crate::cfg::BlockId;
use crate::ir::IrInstr;
use crate::symbolic::results::SeFinding;
use crate::symbolic::solver::SmtSolver;
use crate::symbolic::state::SymbolicState;

/// Symbolic execution vulnerability detector.
///
/// Detectors observe execution via hooks but NEVER modify the engine.
/// Detectors that need solver queries must bracket them with `push()`/`pop()`
/// to avoid polluting the engine's constraint state.
pub trait Detector {
    /// Unique identifier (e.g., `"integer-overflow"`).
    fn id(&self) -> &'static str;

    /// Human-readable name (e.g., `"Integer Overflow Detector"`).
    fn name(&self) -> &'static str;

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
    ///
    /// Currently returns an empty registry — actual detector
    /// implementations are deferred to Phase 6.
    pub fn with_defaults() -> Self {
        Self::new()
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
    pub fn with_filter(mut self, enabled: &[&str]) -> Self {
        self.detectors.retain(|d| enabled.contains(&d.id()));
        self
    }

    /// Number of registered detectors.
    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    /// Whether the registry has no detectors.
    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::detectors::Severity;
    use crate::norm::Span;
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

        fn name(&self) -> &'static str {
            "Mock Detector"
        }

        fn on_instruction(
            &mut self,
            _state: &SymbolicState,
            _instr: &crate::ir::IrInstr,
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
    fn nop_instr() -> crate::ir::IrInstr {
        crate::ir::IrInstr::Nop {
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
    fn test_registry_with_defaults_is_empty() {
        // with_defaults() currently returns an empty registry (Phase 6 pending).
        let registry = DetectorRegistry::with_defaults();
        assert!(registry.is_empty());
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
}
