# Symbolic Execution Engine

Read `@symbolic/se_engine_specification.md` before making any changes in this directory. It is the authoritative design document.

## Architecture in Brief

CFG-driven exploration. The CFG is the navigation structure; IR provides instruction-level semantics within basic blocks. The engine never steps through IR with a flat program counter — it picks a basic block from a worklist, interprets all IR instructions within it, then uses CFG edges to determine successors.

## Module Responsibilities

Do not put code in the wrong module. Follow this mapping:

- `engine/` — Exploration loop, block interpretation, worklist scheduling. Nothing about types or solving here.
- `state/` — SymbolicState and its components (memory, storage, call context). Pure data + accessors. No solving logic.
- `types/` — SymbolicValue enum and operations (bitvec arithmetic, array theory wrappers, keccak256 modeling). No engine or state logic.
- `solver/` — Z3 integration, constraint management, model extraction. Accessed only through the `Solver` trait.
- `detectors/` — Vulnerability detectors. Each detector is one file implementing the `Detector` trait. Detectors observe execution but do not modify the engine.
- `results/` — Finding, coverage, and witness types. Output-only — nothing here drives execution.

## Key Types

- `SymbolicValue` — Tagged enum: `BitVec(width, z3_bv)`, `Bool(z3_bool)`, `SymArray(key, val, z3_array)`, `SymBytes(len, content)`
- `SymbolicState` — Bundles memory, storage, call_context, path_constraints, and current block_id
- `ExplorationStrategy` trait — Determines worklist ordering. Implementations: DFS, BFS, Priority, Targeted.
- `Detector` trait — Hooks: `on_instruction()` and `on_block_exit()`. Each detector is independent.
- `Solver` trait — Abstracts Z3. Methods: `check_sat()`, `get_model()`, `push()`, `pop()`, `assert_constraint()`

## Z3 Usage Rules

- Use bitvectors (`BV<N>`) for all numeric types. Never use Z3 integer theory — it does not model EVM wrap-around semantics.
- Use native Z3 booleans for branch conditions, not `BV<1>` or `BV<256> != 0`.
- Use Z3 Array theory for mappings: `Array<BV256, BV256>`.
- Model keccak256 as concrete when inputs are concrete, uninterpreted function when inputs are symbolic.
- Use incremental solving with push/pop when exploring paths. Do not create fresh solver contexts per query.

## Adding a New Detector

1. Create `detectors/your_detector.rs`
2. Implement the `Detector` trait
3. Register it in `detectors/mod.rs` in the `DetectorRegistry`
4. Add tests in the same file under `#[cfg(test)]`
5. No changes to engine code should be required

## Testing

- Unit test each type operation in `types/` with known inputs and expected Z3 outputs.
- Test detectors against minimal IR/CFG fixtures that represent known vulnerability patterns.
- Test the engine with small hand-crafted CFGs (3-5 blocks) to verify exploration order and state forking.
- Use `proptest` for property-based testing of bitvector operations where applicable.