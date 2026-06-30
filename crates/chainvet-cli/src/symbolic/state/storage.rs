use std::collections::{HashMap, HashSet};

use z3::ast::{Array, BV};
use z3::Sort;

use crate::symbolic::types::symbolic_array;
use crate::symbolic::types::SymbolicValue;
use crate::util::error::Result;

const WORD_WIDTH: u32 = 256;

/// Symbolic model of EVM persistent storage.
///
/// Two-layer design:
/// 1. **Raw slot access**: `Array<BV256, BV256>` for direct sload/sstore by slot number.
/// 2. **Per-mapping arrays**: separate `Array<BV256, BV256>` per mapping variable,
///    using Z3 Array theory (select/store with symbolic key) instead of
///    keccak256-based slot computation.
///
/// For simple state variables: direct slot read/write via `sload`/`sstore`.
/// For mappings: `mapping_read`/`mapping_write` with the mapping's name as key.
/// For struct members: `base_slot + field_offset` arithmetic (computed by `StorageLayout`).
#[derive(Clone)]
pub struct SymbolicStorage {
    /// Raw storage slots: `Array<BV256, BV256>`, default 0.
    slots: Array,
    /// Per-mapping arrays for high-level modeling.
    /// Key: variable name (e.g., "balances"). Value: `Array<BV256, BV256>`.
    mappings: HashMap<String, Array>,
}

impl SymbolicStorage {
    /// Create fresh storage with all slots zero-initialized.
    pub fn new(_name: &str) -> Self {
        let zero = BV::from_u64(0, WORD_WIDTH);
        let key_sort = Sort::bitvector(WORD_WIDTH);
        Self {
            slots: Array::const_array(&key_sort, &zero),
            mappings: HashMap::new(),
        }
    }

    /// Low-level: read storage slot by 256-bit slot number.
    pub fn sload(&self, slot: &BV) -> Result<SymbolicValue> {
        symbolic_array::array_select(&self.slots, slot, WORD_WIDTH)
    }

    /// Low-level: write to storage slot.
    pub fn sstore(&mut self, slot: &BV, value: &BV) {
        self.slots = self.slots.store(slot, value);
    }

    /// High-level: read a mapping value by key.
    ///
    /// Uses a per-mapping Z3 Array (not raw slot keccak256 computation).
    /// If the mapping hasn't been seen before, creates a fresh symbolic array
    /// (uninitialized reads return a symbolic default).
    pub fn mapping_read(&mut self, mapping_name: &str, key: &BV) -> Result<SymbolicValue> {
        let arr = self.get_or_create_mapping(mapping_name);
        symbolic_array::array_select(arr, key, WORD_WIDTH)
    }

    /// High-level: write to a mapping.
    pub fn mapping_write(&mut self, mapping_name: &str, key: &BV, value: &BV) {
        let arr = self.get_or_create_mapping(mapping_name);
        let updated = arr.store(key, value);
        self.mappings.insert(mapping_name.to_string(), updated);
    }

    /// Get the Z3 Array for a mapping, creating a fresh symbolic one if first access.
    fn get_or_create_mapping(&mut self, mapping_name: &str) -> &Array {
        self.mappings
            .entry(mapping_name.to_string())
            .or_insert_with(|| {
                let key_sort = Sort::bitvector(WORD_WIDTH);
                let val_sort = Sort::bitvector(WORD_WIDTH);
                let name = format!("mapping_{mapping_name}");
                Array::new_const(name.as_str(), &key_sort, &val_sort)
            })
    }
}

/// Storage layout computed once from the NormalizedAst before execution begins.
///
/// Maps state variable names to their storage slot numbers (assigned by
/// declaration order within each contract, following Solidity's layout rules).
/// Also identifies which variables are mappings for high-level array modeling.
///
/// This is shared read-only context — NOT cloned with SymbolicState.
pub struct StorageLayout {
    /// `(contract_name, var_name)` → base slot number.
    slots: HashMap<(String, String), u64>,
    /// `(struct_name, field_name)` → field offset within struct.
    field_offsets: HashMap<(String, String), u64>,
    /// Names of variables that are mapping types.
    mapping_names: HashSet<String>,
}

impl StorageLayout {
    /// Build layout from NormalizedAst state variables.
    ///
    /// Slots are assigned by declaration order within each contract.
    /// Constants and immutables do not occupy storage slots.
    /// Mappings are detected by checking `type_string` for "mapping".
    pub fn from_ast(ast: &crate::norm::NormalizedAst) -> Self {
        let mut slots = HashMap::new();
        let mut mapping_names = HashSet::new();

        // Group state variables by contract, preserving declaration order.
        for contract in &ast.contracts {
            let mut slot_counter: u64 = 0;

            for &var_id in &contract.state_vars {
                // Find the state variable by ID.
                let Some(var) = ast.state_vars.iter().find(|v| v.id == var_id) else {
                    continue;
                };

                // Constants and immutables don't occupy storage slots.
                if var.constant || var.immutable {
                    continue;
                }

                slots.insert(
                    (contract.name.clone(), var.name.clone()),
                    slot_counter,
                );

                // Detect mapping types from type_string.
                let is_map = var
                    .type_string
                    .as_ref()
                    .map(|ts| ts.contains("mapping"))
                    .unwrap_or(false);
                if is_map {
                    mapping_names.insert(var.name.clone());
                }

                slot_counter += 1;
            }
        }

        Self {
            slots,
            field_offsets: HashMap::new(), // TODO: populate from struct definitions
            mapping_names,
        }
    }

    /// Look up the base slot for a state variable.
    pub fn get_slot(&self, contract_name: &str, var_name: &str) -> Option<u64> {
        self.slots
            .get(&(contract_name.to_string(), var_name.to_string()))
            .copied()
    }

    /// Look up the field offset within a struct.
    pub fn get_field_offset(&self, struct_name: &str, field_name: &str) -> Option<u64> {
        self.field_offsets
            .get(&(struct_name.to_string(), field_name.to_string()))
            .copied()
    }

    /// Check if a variable is a mapping type.
    pub fn is_mapping(&self, var_name: &str) -> bool {
        self.mapping_names.contains(var_name)
    }

    /// Create an empty layout with no slots, offsets, or mappings.
    pub fn empty() -> Self {
        Self {
            slots: HashMap::new(),
            field_offsets: HashMap::new(),
            mapping_names: HashSet::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::ast::BV;
    use z3::{SatResult, Solver};

    const W: u32 = 256;

    // --- SymbolicStorage tests ---

    #[test]
    fn test_storage_new_exists() {
        // Creating new storage should not panic.
        let _s = SymbolicStorage::new("s");
    }

    #[test]
    fn test_storage_sload_uninitialized_is_zero() {
        // Reading an uninitialized slot should return zero.
        let storage = SymbolicStorage::new("s");
        let slot = BV::from_u64(0, W);
        let val = storage.sload(&slot).expect("sload should succeed");
        let bv = val.as_bv().expect("should be BitVec");

        let zero = BV::from_u64(0, W);
        let solver = Solver::new_for_logic("QF_ABV").unwrap();
        solver.assert(&bv.eq(&zero).not());
        assert_eq!(solver.check(), SatResult::Unsat, "uninitialized slot should be zero");
    }

    #[test]
    fn test_storage_sstore_sload_roundtrip() {
        // Writing to a slot and reading it back should return the written value.
        let mut storage = SymbolicStorage::new("s");
        let slot = BV::from_u64(3, W);
        let written = BV::from_u64(0xCAFE, W);

        storage.sstore(&slot, &written);
        let read_val = storage.sload(&slot).expect("sload should succeed");
        let bv = read_val.as_bv().expect("should be BitVec");

        let solver = Solver::new_for_logic("QF_ABV").unwrap();
        solver.assert(&bv.eq(&written).not());
        assert_eq!(solver.check(), SatResult::Unsat, "sload after sstore should return written value");
    }

    #[test]
    fn test_storage_sstore_does_not_affect_other_slot() {
        // Writing to one slot should not change another slot (still zero).
        let mut storage = SymbolicStorage::new("s");
        storage.sstore(&BV::from_u64(0, W), &BV::from_u64(42, W));

        let other = storage.sload(&BV::from_u64(1, W)).expect("sload should succeed");
        let bv = other.as_bv().unwrap();

        let zero = BV::from_u64(0, W);
        let solver = Solver::new_for_logic("QF_ABV").unwrap();
        solver.assert(&bv.eq(&zero).not());
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    #[test]
    fn test_storage_mapping_write_read_roundtrip() {
        // Writing to a mapping and reading with the same key should return the value.
        let mut storage = SymbolicStorage::new("s");
        let key = BV::from_u64(100, W);
        let val = BV::from_u64(200, W);

        storage.mapping_write("balances", &key, &val);
        let read_val = storage.mapping_read("balances", &key).expect("mapping_read should succeed");
        let bv = read_val.as_bv().expect("should be BitVec");

        let solver = Solver::new_for_logic("QF_ABV").unwrap();
        solver.assert(&bv.eq(&val).not());
        assert_eq!(solver.check(), SatResult::Unsat, "mapping read after write should return written value");
    }

    #[test]
    fn test_storage_mapping_distinct_keys() {
        // Writing different values under different keys in the same mapping
        // should preserve each value independently.
        let mut storage = SymbolicStorage::new("s");
        let k1 = BV::from_u64(1, W);
        let k2 = BV::from_u64(2, W);
        let v1 = BV::from_u64(10, W);
        let v2 = BV::from_u64(20, W);

        storage.mapping_write("m", &k1, &v1);
        storage.mapping_write("m", &k2, &v2);

        let r1 = storage.mapping_read("m", &k1).unwrap();
        let r2 = storage.mapping_read("m", &k2).unwrap();

        let solver = Solver::new_for_logic("QF_ABV").unwrap();
        solver.assert(&r1.as_bv().unwrap().eq(&v1).not());
        assert_eq!(solver.check(), SatResult::Unsat, "key1 should still have value1");

        let solver2 = Solver::new_for_logic("QF_ABV").unwrap();
        solver2.assert(&r2.as_bv().unwrap().eq(&v2).not());
        assert_eq!(solver2.check(), SatResult::Unsat, "key2 should have value2");
    }

    #[test]
    fn test_storage_mapping_read_uninitialized_is_symbolic() {
        // Reading from a mapping that has never been written should return a symbolic
        // value (not necessarily zero, since mappings use symbolic arrays).
        let mut storage = SymbolicStorage::new("s");
        let key = BV::from_u64(42, W);
        let val = storage.mapping_read("unknown_map", &key).expect("should succeed");
        assert_eq!(val.width(), 256);
    }

    #[test]
    fn test_storage_separate_mappings_are_independent() {
        // Writing to mapping "a" should not affect reads from mapping "b".
        let mut storage = SymbolicStorage::new("s");
        let key = BV::from_u64(1, W);
        let val = BV::from_u64(999, W);

        storage.mapping_write("a", &key, &val);

        // Read from a different mapping with the same key
        let read_b = storage.mapping_read("b", &key).expect("should succeed");
        let bv_b = read_b.as_bv().unwrap();

        // "b" is a fresh symbolic array, so the value should be satisfiable
        // as something other than 999.
        let solver = Solver::new_for_logic("QF_ABV").unwrap();
        solver.assert(&bv_b.eq(&val).not());
        assert_eq!(solver.check(), SatResult::Sat, "different mapping should be independent");
    }

    // --- StorageLayout tests ---

    fn make_test_ast() -> crate::norm::NormalizedAst {
        // Create a minimal NormalizedAst with one contract "TestContract" having:
        //  - "owner" (regular address, slot 0)
        //  - "balances" (mapping, slot 1)
        //  - "MAX_SUPPLY" (constant, no slot)
        //  - "totalSupply" (regular uint, slot 2)
        use crate::norm::{
            Contract, ContractKind, Mutability, NormalizedAst, Span, StateVariable, Visibility,
        };

        let owner = StateVariable {
            id: 1,
            contract: 0,
            name: "owner".into(),
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            constant: false,
            immutable: false,
            type_string: Some("address".into()),
            span: Span::default(),
        };
        let balances = StateVariable {
            id: 2,
            contract: 0,
            name: "balances".into(),
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            constant: false,
            immutable: false,
            type_string: Some("mapping(address => uint256)".into()),
            span: Span::default(),
        };
        let max_supply = StateVariable {
            id: 3,
            contract: 0,
            name: "MAX_SUPPLY".into(),
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            constant: true,
            immutable: false,
            type_string: Some("uint256".into()),
            span: Span::default(),
        };
        let total_supply = StateVariable {
            id: 4,
            contract: 0,
            name: "totalSupply".into(),
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            constant: false,
            immutable: false,
            type_string: Some("uint256".into()),
            span: Span::default(),
        };

        let contract = Contract {
            id: 0,
            name: "TestContract".into(),
            kind: ContractKind::Contract,
            bases: vec![],
            functions: vec![],
            state_vars: vec![1, 2, 3, 4],
            modifiers: vec![],
            events: vec![],
            errors: vec![],
            span: Span::default(),
        };

        NormalizedAst {
            contracts: vec![contract],
            state_vars: vec![owner, balances, max_supply, total_supply],
            ..NormalizedAst::empty()
        }
    }

    #[test]
    fn test_storage_layout_slot_assignment_skips_constants() {
        // Constants should not occupy storage slots. "owner" gets slot 0,
        // "balances" gets slot 1, "MAX_SUPPLY" is skipped, "totalSupply" gets slot 2.
        let ast = make_test_ast();
        let layout = StorageLayout::from_ast(&ast);

        assert_eq!(layout.get_slot("TestContract", "owner"), Some(0));
        assert_eq!(layout.get_slot("TestContract", "balances"), Some(1));
        assert_eq!(
            layout.get_slot("TestContract", "MAX_SUPPLY"),
            None,
            "constants should not have slots"
        );
        assert_eq!(layout.get_slot("TestContract", "totalSupply"), Some(2));
    }

    #[test]
    fn test_storage_layout_detects_mappings() {
        // Variables with "mapping" in their type_string should be detected as mappings.
        let ast = make_test_ast();
        let layout = StorageLayout::from_ast(&ast);

        assert!(layout.is_mapping("balances"), "balances should be a mapping");
        assert!(!layout.is_mapping("owner"), "owner is not a mapping");
        assert!(!layout.is_mapping("totalSupply"), "totalSupply is not a mapping");
    }

    #[test]
    fn test_storage_layout_unknown_variable_returns_none() {
        // Looking up a variable that does not exist should return None.
        let ast = make_test_ast();
        let layout = StorageLayout::from_ast(&ast);

        assert_eq!(layout.get_slot("TestContract", "nonexistent"), None);
        assert_eq!(layout.get_slot("OtherContract", "owner"), None);
    }

    #[test]
    fn test_storage_layout_immutable_skipped() {
        // Immutable variables should also be skipped in slot assignment.
        use crate::norm::{
            Contract, ContractKind, Mutability, NormalizedAst, Span, StateVariable, Visibility,
        };

        let imm_var = StateVariable {
            id: 1,
            contract: 0,
            name: "deployTime".into(),
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            constant: false,
            immutable: true,
            type_string: Some("uint256".into()),
            span: Span::default(),
        };
        let regular = StateVariable {
            id: 2,
            contract: 0,
            name: "count".into(),
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            constant: false,
            immutable: false,
            type_string: Some("uint256".into()),
            span: Span::default(),
        };
        let contract = Contract {
            id: 0,
            name: "C".into(),
            kind: ContractKind::Contract,
            bases: vec![],
            functions: vec![],
            state_vars: vec![1, 2],
            modifiers: vec![],
            events: vec![],
            errors: vec![],
            span: Span::default(),
        };
        let ast = NormalizedAst {
            contracts: vec![contract],
            state_vars: vec![imm_var, regular],
            ..NormalizedAst::empty()
        };

        let layout = StorageLayout::from_ast(&ast);
        assert_eq!(layout.get_slot("C", "deployTime"), None, "immutable should have no slot");
        assert_eq!(layout.get_slot("C", "count"), Some(0), "first non-immutable should be slot 0");
    }

    #[test]
    fn test_storage_layout_empty_ast() {
        // An empty AST should produce an empty layout with no slots.
        let ast = crate::norm::NormalizedAst::empty();
        let layout = StorageLayout::from_ast(&ast);
        assert_eq!(layout.get_slot("Anything", "x"), None);
        assert!(!layout.is_mapping("x"));
    }

    #[test]
    fn test_storage_layout_field_offset_returns_none_when_empty() {
        // Field offsets are not yet populated (TODO in impl), so should return None.
        let ast = make_test_ast();
        let layout = StorageLayout::from_ast(&ast);
        assert_eq!(layout.get_field_offset("SomeStruct", "field"), None);
    }
}

/// Result of resolving an `IrPlace` against the storage layout.
///
/// Used by the executor (Phase 4) to determine how to read/write storage.
#[allow(dead_code)] // Phase 6: used by executor resolve_place for typed storage accesses
pub enum StorageAccess {
    /// Direct slot access (simple state variable or struct field).
    DirectSlot { slot: u64 },
    /// Mapping access: mapping name + symbolic key.
    Mapping { name: String },
    /// Could not resolve — fall back to fresh symbolic value.
    Unknown,
}
