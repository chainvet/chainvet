pub mod call_context;
pub mod constraints;
pub mod memory;
pub mod storage;
pub mod variables;

use std::collections::{HashMap, HashSet};

use crate::cfg::BlockId;
use crate::ir::IrVar;
use crate::norm::Span;

use self::call_context::CallContext;
use self::constraints::PathConstraints;
use self::memory::SymbolicMemory;
use self::storage::SymbolicStorage;
use self::variables::VariableEnv;

/// Tracks where a variable's value originally came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueOrigin {
    /// block.timestamp / now
    Timestamp,
    /// block.number
    BlockNumber,
    /// address(this).balance
    ThisBalance,
    /// tx.origin
    TxOrigin,
    /// Return from .call()
    LowLevelCallRef,
    /// Return from .send()
    SendRef,
    /// Return from .delegatecall()
    DelegatecallRef,
    /// Return from .call{value:...}()
    #[allow(dead_code)] // Used when call options include `value`
    ValueCallRef,
    /// Return from .transfer()
    TransferRef,
}

/// A low-level call whose return value has not yet been checked.
#[derive(Debug, Clone)]
pub struct PendingCallInfo {
    pub callee: String,
    pub span: Span,
}

/// Unique identifier for a symbolic state in the exploration tree.
pub type StateId = u64;

/// Counter for generating unique `StateId`s.
pub struct StateIdGen {
    next: StateId,
}

impl StateIdGen {
    pub fn new() -> Self {
        Self { next: 1 } // 0 reserved for "no parent"
    }

    pub fn next_id(&mut self) -> StateId {
        let id = self.next;
        self.next += 1;
        id
    }
}

impl Default for StateIdGen {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of one execution path through the CFG.
///
/// Pure data + accessors. No solving logic.
/// Cloned at branch points via `clone_forked()`.
#[derive(Clone)]
pub struct SymbolicState {
    /// Unique ID for this state (monotonically increasing).
    pub id: StateId,
    /// Parent state's ID (0 for initial state — creates a fork tree for debugging).
    #[allow(dead_code)] // Phase 6: used by witness reconstruction to trace fork history
    pub parent_id: StateId,
    /// Variable bindings: `IrVar → SymbolicValue`.
    pub variables: VariableEnv,
    /// Word-addressed symbolic memory (call-local, transient).
    pub memory: SymbolicMemory,
    /// Persistent contract storage.
    pub storage: SymbolicStorage,
    /// Blockchain environment (`msg.sender`, `block.*`, etc.).
    pub call_context: CallContext,
    /// Accumulated path constraints (pure data, fed to solver by the engine).
    pub path_constraints: PathConstraints,
    /// Current CFG block being executed.
    pub current_block: BlockId,
    /// Number of branch points along this path.
    pub path_depth: u32,
    /// Total IR instructions executed on this path.
    pub instruction_count: u32,
    /// Taint tracking: which value origins each variable carries.
    pub origins: HashMap<IrVar, HashSet<ValueOrigin>>,
    /// Low-level calls whose return values have not been checked yet.
    pub pending_calls: HashMap<IrVar, PendingCallInfo>,
}

impl SymbolicState {
    /// Create the initial state for a function entry.
    pub fn initial(
        id_gen: &mut StateIdGen,
        entry_block: BlockId,
        call_context: CallContext,
    ) -> Self {
        Self {
            id: id_gen.next_id(),
            parent_id: 0,
            variables: VariableEnv::new(),
            memory: SymbolicMemory::new("mem_0"),
            storage: SymbolicStorage::new("storage_0"),
            call_context,
            path_constraints: PathConstraints::new(),
            current_block: entry_block,
            path_depth: 0,
            instruction_count: 0,
            origins: HashMap::new(),
            pending_calls: HashMap::new(),
        }
    }

    /// Check if a variable carries a specific origin.
    pub fn has_origin(&self, var: &IrVar, origin: ValueOrigin) -> bool {
        self.origins
            .get(var)
            .is_some_and(|set| set.contains(&origin))
    }

    /// Get all origins for a variable.
    #[allow(dead_code)] // Public API for detectors to query full origin set
    pub fn get_origins(&self, var: &IrVar) -> Option<&HashSet<ValueOrigin>> {
        self.origins.get(var)
    }

    /// Tag a variable with an origin.
    pub fn set_origin(&mut self, var: IrVar, origin: ValueOrigin) {
        self.origins.entry(var).or_default().insert(origin);
    }

    /// Copy all origins from one variable to another.
    pub fn copy_origins(&mut self, from: &IrVar, to: &IrVar) {
        if let Some(origins) = self.origins.get(from).cloned() {
            self.origins.entry(to.clone()).or_default().extend(origins);
        }
    }

    /// Union origins from multiple source variables into a destination.
    pub fn union_origins(&mut self, sources: &[&IrVar], dest: &IrVar) {
        let mut combined: HashSet<ValueOrigin> = HashSet::new();
        for src in sources {
            if let Some(origins) = self.origins.get(*src) {
                combined.extend(origins);
            }
        }
        if !combined.is_empty() {
            self.origins.entry(dest.clone()).or_default().extend(combined);
        }
    }

    /// Register a low-level call return variable as pending (unchecked).
    pub fn register_pending_call(&mut self, var: IrVar, info: PendingCallInfo) {
        self.pending_calls.insert(var, info);
    }

    /// Clear a pending call by variable (the return was checked).
    pub fn clear_pending_by_var(&mut self, var: &IrVar) {
        // Remove by matching span — if the same call's return is aliased
        // to multiple variables, checking one clears all aliases.
        if let Some(info) = self.pending_calls.get(var) {
            let span = info.span;
            self.pending_calls.retain(|_, v| v.span != span);
        }
    }

    /// Propagate pending-call status from one variable to another.
    pub fn propagate_pending(&mut self, from: &IrVar, to: &IrVar) {
        if let Some(info) = self.pending_calls.get(from).cloned() {
            self.pending_calls.insert(to.clone(), info);
        }
    }

    /// Drain all remaining pending calls (for flushing at function exit).
    pub fn drain_pending(&mut self) -> Vec<(IrVar, PendingCallInfo)> {
        std::mem::take(&mut self.pending_calls).into_iter().collect()
    }

    /// Clone this state for a branch fork.
    ///
    /// The new state gets a fresh ID and records this state as parent,
    /// creating a tree structure useful for debugging exploration order.
    #[allow(dead_code)] // Phase 6: used by inter-procedural call handling
    pub fn clone_forked(&self, id_gen: &mut StateIdGen) -> Self {
        let mut forked = self.clone();
        forked.id = id_gen.next_id();
        forked.parent_id = self.id;
        forked
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::IrVar;
    use crate::symbolic::types::SymbolicValue;
    use z3::ast::BV;

    // --- StateIdGen tests ---

    #[test]
    fn test_state_id_gen_starts_at_one() {
        // IDs should start at 1, since 0 is reserved for "no parent".
        let mut id_gen = StateIdGen::new();
        assert_eq!(id_gen.next_id(), 1);
    }

    #[test]
    fn test_state_id_gen_monotonically_increasing() {
        // Each call to next_id() should return a strictly larger value.
        let mut id_gen = StateIdGen::new();
        let a = id_gen.next_id();
        let b = id_gen.next_id();
        let c = id_gen.next_id();
        assert!(a < b);
        assert!(b < c);
        assert_eq!(a, 1);
        assert_eq!(b, 2);
        assert_eq!(c, 3);
    }

    #[test]
    fn test_state_id_gen_default_equals_new() {
        let mut id_gen = StateIdGen::default();
        assert_eq!(id_gen.next_id(), 1);
    }

    // --- SymbolicState tests ---

    fn make_initial_state() -> (SymbolicState, StateIdGen) {
        let mut id_gen = StateIdGen::new();
        let (ctx, _constraints) = call_context::CallContext::new_symbolic();
        let state = SymbolicState::initial(&mut id_gen, 0, ctx);
        (state, id_gen)
    }

    #[test]
    fn test_symbolic_state_initial_has_id_one() {
        // The first state created should get ID 1.
        let (state, _) = make_initial_state();
        assert_eq!(state.id, 1);
    }

    #[test]
    fn test_symbolic_state_initial_parent_is_zero() {
        // The initial state has no parent, represented as parent_id == 0.
        let (state, _) = make_initial_state();
        assert_eq!(state.parent_id, 0);
    }

    #[test]
    fn test_symbolic_state_initial_empty_constraints_and_vars() {
        // The initial state should have empty path constraints and no variable bindings.
        let (state, _) = make_initial_state();
        assert!(state.path_constraints.is_empty());
        assert!(state.variables.is_empty());
        assert_eq!(state.path_depth, 0);
        assert_eq!(state.instruction_count, 0);
    }

    #[test]
    fn test_symbolic_state_initial_current_block() {
        // The initial state's current_block should match the entry_block argument.
        let mut id_gen = StateIdGen::new();
        let (ctx, _) = call_context::CallContext::new_symbolic();
        let state = SymbolicState::initial(&mut id_gen, 42, ctx);
        assert_eq!(state.current_block, 42);
    }

    #[test]
    fn test_symbolic_state_clone_forked_gets_new_id() {
        // A forked state should get a different (larger) ID than the original.
        let (state, mut id_gen) = make_initial_state();
        let forked = state.clone_forked(&mut id_gen);

        assert_ne!(forked.id, state.id);
        assert!(forked.id > state.id);
    }

    #[test]
    fn test_symbolic_state_clone_forked_parent_id_correct() {
        // The forked state's parent_id should be the original state's id.
        let (state, mut id_gen) = make_initial_state();
        let forked = state.clone_forked(&mut id_gen);

        assert_eq!(forked.parent_id, state.id);
    }

    #[test]
    fn test_symbolic_state_clone_forked_preserves_block() {
        // The forked state should inherit the same current_block.
        let (state, mut id_gen) = make_initial_state();
        let forked = state.clone_forked(&mut id_gen);
        assert_eq!(forked.current_block, state.current_block);
    }

    #[test]
    fn test_symbolic_state_modifying_fork_does_not_affect_original() {
        // Adding variables or constraints to a fork should not change the original.
        let (state, mut id_gen) = make_initial_state();
        let mut forked = state.clone_forked(&mut id_gen);

        // Modify the fork: add a variable and a path constraint.
        forked.variables.set(
            IrVar::Named("forked_var".into()),
            SymbolicValue::BitVec {
                width: 256,
                val: BV::from_u64(123, 256),
            },
        );
        forked.path_constraints.add(
            z3::ast::Bool::from_bool(true),
            "fork constraint".into(),
        );
        forked.path_depth = 5;
        forked.instruction_count = 100;

        // Original should be unaffected.
        assert!(state.variables.is_empty(), "original variables should be unchanged");
        assert!(state.path_constraints.is_empty(), "original constraints should be unchanged");
        assert_eq!(state.path_depth, 0);
        assert_eq!(state.instruction_count, 0);
    }

    #[test]
    fn test_symbolic_state_multiple_forks_get_unique_ids() {
        // Forking the same state multiple times should produce unique IDs.
        let (state, mut id_gen) = make_initial_state();
        let fork1 = state.clone_forked(&mut id_gen);
        let fork2 = state.clone_forked(&mut id_gen);
        let fork3 = state.clone_forked(&mut id_gen);

        assert_ne!(fork1.id, fork2.id);
        assert_ne!(fork2.id, fork3.id);
        assert_ne!(fork1.id, fork3.id);
        // All forks share the same parent.
        assert_eq!(fork1.parent_id, state.id);
        assert_eq!(fork2.parent_id, state.id);
        assert_eq!(fork3.parent_id, state.id);
    }

    #[test]
    fn test_symbolic_state_chained_forks_form_tree() {
        // Forking a fork should create a chain: initial -> fork1 -> fork2.
        let (state, mut id_gen) = make_initial_state();
        let fork1 = state.clone_forked(&mut id_gen);
        let fork2 = fork1.clone_forked(&mut id_gen);

        assert_eq!(fork1.parent_id, state.id);
        assert_eq!(fork2.parent_id, fork1.id);
        assert!(fork2.id > fork1.id);
    }
}
