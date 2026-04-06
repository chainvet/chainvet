# Symbolic Execution Engine — Technical Specification

**Project:** Hybrid Smart Contract Analysis Tool
**Component:** Symbolic Execution (SE) Engine
**Target:** EVM / Solidity
**Language:** Rust
**Status:** Core interpreter loop exists; IR, AST, and CFG pipeline complete

---

## 1. Overview

The SE engine is the core analysis component responsible for systematically exploring execution paths through smart contracts to discover vulnerabilities, generate counterexamples, and prove properties. It operates on the project's custom IR and uses the CFG as its primary navigation structure.

This document specifies:

- How the SE engine incorporates IR and CFG
- The type system used for symbolic values
- The directory structure and module organization for `/symbolic`

---

## 2. Architectural Model: CFG-Driven Symbolic Execution

### 2.1 Why CFG-Driven (Not Flat IR Interpretation)

The SE engine uses a **CFG-driven exploration model** rather than stepping through IR instructions with a flat program counter. In this model, the CFG is the primary navigation structure and the IR provides the instruction-level semantics within each basic block.

**Rationale:**

- **No mid-block branching.** Basic blocks contain no branches by definition. The engine interprets all IR instructions within a block without forking or solver queries, then makes exploration decisions only at block boundaries. This reduces solver overhead significantly.
- **Coverage awareness.** The CFG provides a map of the entire program. The engine can track which blocks have been visited, compute distances to uncovered regions, and identify blocks containing sensitive operations (SSTORE, CALL, SELFDESTRUCT, DELEGATECALL).
- **Graph-based prioritization.** With the CFG as a graph, the engine can apply shortest-path algorithms to guide exploration toward high-value targets. This is the natural integration point for the AI-guided prioritization component.
- **SAST integration.** The SAST component already reasons about the CFG. Sharing the same structure allows SAST to annotate blocks with vulnerability hints that the SE engine consumes directly — no translation layer needed.
- **Fuzzer integration.** When SE discovers a feasible path to a bug, the concrete inputs from the constraint solver can seed the fuzzer. The CFG provides the shared reference frame for communicating path information between components.

### 2.2 The Execution Model

The SE engine operates as a worklist-based explorer over the CFG:

```
┌──────────────────────────────────────────┐
│           Worklist / Frontier            │
│  [(SymbolicState, BlockId, Priority)]    │
└──────────────────┬───────────────────────┘
                   │ select next state by priority
                   ▼
┌──────────────────────────────────────────┐
│     Interpret Basic Block                │
│     Walk IR instructions sequentially    │
│     Update symbolic state               │
│     No branching within block            │
└──────────────────┬───────────────────────┘
                   │
          ┌────────┴─────────┐
          ▼                  ▼
    Conditional           Terminal
    Terminator?           (return/revert/stop)
          │                  │
          ▼                  ▼
   Query solver for      Record execution
   branch feasibility    result and report
          │
    ┌─────┴──────┐
    ▼            ▼
  True feasible  False feasible
    │            │
    ▼            ▼
  Fork state,  Fork state,
  add true     add false
  successor    successor
  to worklist  to worklist
```

### 2.3 How IR and CFG Interact

The IR and CFG serve distinct, complementary roles:

**CFG provides:**
- The graph of basic blocks and edges (the "map")
- Block-level metadata: which blocks contain storage writes, external calls, etc.
- Dominator/post-dominator trees for path sensitivity
- Annotations from SAST (vulnerability hints, taint information)
- The structure for coverage tracking and exploration prioritization

**IR provides:**
- The instruction semantics within each basic block (the "meaning")
- Typed operations: arithmetic, comparisons, storage reads/writes, calls
- Variable and temporary definitions
- The branch condition expression at conditional terminators

**During execution, the engine:**

1. Receives a `(SymbolicState, BlockId)` from the worklist.
2. Looks up the basic block in the CFG by `BlockId`.
3. Iterates through the block's IR instructions sequentially, updating the symbolic state for each instruction (e.g., evaluating a symbolic add, recording a symbolic storage write).
4. Reaches the block's terminator instruction.
5. If **unconditional jump**: pushes the single CFG successor onto the worklist.
6. If **conditional branch**: extracts the symbolic condition from the IR, queries the solver for feasibility of both branches, and pushes feasible successors onto the worklist with forked states.
7. If **terminal** (return, revert, stop, selfdestruct): records the execution result and path constraints. If a vulnerability detector triggers, reports the finding.

### 2.4 Exploration Strategies

The worklist ordering determines the exploration strategy. The engine supports pluggable strategies via a trait:

- **DFS (depth-first):** Stack-based. Low memory, explores deep paths first. Risk of getting stuck in loops.
- **BFS (breadth-first):** Queue-based. Better coverage breadth but higher memory usage.
- **Priority-guided:** Each state is scored based on heuristics. The highest-priority state is explored next. Heuristic factors include:
  - Distance to uncovered CFG blocks (prefer states closer to unexplored territory)
  - Proximity to sensitive operations (prefer states near SSTORE, CALL, DELEGATECALL, SELFDESTRUCT)
  - Path depth (penalize very deep paths to avoid explosion)
  - AI-assigned scores from the ML component
- **Targeted:** Given a specific target block (e.g., one flagged by SAST), compute shortest paths through the CFG and prioritize states on those paths.

**Recommended default:** Priority-guided with fallback to bounded DFS. The AI component can learn better priority functions over time.

### 2.5 Path Termination Conditions

Exploration of a path terminates when any of the following occur:

- The path reaches a terminal instruction (RETURN, REVERT, STOP, SELFDESTRUCT)
- The path depth exceeds the configured maximum (default: 256 blocks)
- The instruction count on the path exceeds the configured maximum (default: 10,000)
- A loop iteration bound is exceeded (default: 3 unrollings)
- The solver returns UNKNOWN for a branch feasibility query (path is abandoned)
- A timeout is reached for the individual path

---

## 3. Symbolic Type System

### 3.1 Design Principles

The type system preserves Solidity-level type information in the IR while lowering to SMT-compatible representations for constraint solving. This gives rich type info for vulnerability detection and clean encoding for Z3.

**Guiding rules:**

- Use bitvectors (not mathematical integers) for all numeric types — this correctly models EVM wrap-around semantics and overflow behavior.
- Use native Z3 booleans for boolean values — more efficient for branch conditions than `bv256 != 0`.
- Use Z3 Array theory for mappings — enables reasoning about mappings without enumerating keys.
- Model keccak256 as a hybrid: concrete when inputs are concrete, uninterpreted function when inputs are symbolic.
- Be precise where it matters for bugs (overflow, mapping access, address comparisons) and abstract where it doesn't (string contents, rare type conversions).

### 3.2 Core Symbolic Value Types

The symbolic value representation in the engine uses the following core types:

| Symbolic Type | Solidity Types Covered | SMT Encoding | Notes |
|---|---|---|---|
| `BitVec(width)` | uint8–uint256, int8–int256, bytes1–bytes32, address | `BV<N>` | Address is BV<160> but tagged distinctly in the IR |
| `Bool` | bool | Z3 Bool | Native booleans, not `BV<1>` — much faster for solver |
| `SymArray(key_sort, val_sort)` | mapping(K => V), storage | Z3 `Array<K, V>` | Supports nested mappings via nested arrays |
| `SymBytes(sym_length, content)` | bytes, string | BV<256> length + `Array<BV256, BV8>` | Bounded to configurable max length (default 256 bytes) |
| `SymDynArray(elem_sort, sym_length)` | T[] (dynamic arrays) | BV<256> length + `Array<BV256, elem_sort>` | Bounded length, index-out-of-bounds checked |

### 3.3 Numeric Types in Detail

**Unsigned integers (uint8 through uint256):**
Modeled as `BV<N>` where N is the bit width. Arithmetic operations use unsigned bitvector semantics: `bvadd`, `bvmul`, `bvudiv`, `bvurem`. For Solidity >=0.8.0, overflow/underflow checks are modeled as explicit assertions — if the engine can satisfy a path where the assertion fails, it reports an overflow vulnerability.

**Signed integers (int8 through int256):**
Also `BV<N>`, but arithmetic uses signed bitvector operations: `bvsdiv`, `bvsrem`, `bvslt`, `bvsgt`. Sign extension is applied when widening.

**address:**
Semantically `BV<160>`. Tagged distinctly in the IR type system (not just a uint160) because addresses have special significance: they appear in access control checks (`msg.sender == owner`), in external call targets, and in approval patterns. The distinct tag enables vulnerability detectors to track address flows.

**bool:**
Mapped to Z3's native Bool sort. Conversions: `bool_to_bv256` produces `ite(b, bv256(1), bv256(0))`. `bv256_to_bool` produces `bv != bv256(0)`.

### 3.4 Fixed-Size Byte Types

`bytes1` through `bytes32` are modeled as `BV<N*8>`. They share the bitvector representation with numeric types but support different operations: byte indexing, concatenation, slicing, and bitwise operations rather than arithmetic. `bytes32` is particularly important as it is used for storage slot computation and as a general-purpose 256-bit container.

### 3.5 Mappings and Storage

**Mappings** are the most critical type for smart contract SE because nearly all contract state (balances, allowances, ownership records) lives in mappings.

A `mapping(K => V)` is modeled as `Array<K_sort, V_sort>` using Z3's Array theory. This allows the solver to reason about mappings without enumerating all possible keys.

Examples:
- `mapping(address => uint256)` → `Array<BV160, BV256>`
- `mapping(address => mapping(address => uint256))` → `Array<BV160, Array<BV160, BV256>>`
- `mapping(uint256 => bool)` → `Array<BV256, Bool>`

**Contract storage** is modeled as a top-level `Array<BV256, BV256>` representing the raw slot-to-value mapping. Individual Solidity state variables are projected from this via known slot offsets. Mapping slot computation uses keccak256 (see Section 3.8).

### 3.6 Dynamic Types

**`bytes` and `string`:** Modeled as a symbolic length (`BV<256>`) plus a content array (`Array<BV256, BV8>`). The length is constrained to be at most a configurable bound (default: 256 bytes). Most vulnerabilities do not depend on unbounded string lengths, so this is a practical tradeoff.

**Dynamic arrays (`T[]`):** Modeled as a symbolic length plus `Array<BV256, T_sort>`. Array access generates an implicit bounds-check assertion: `index < length`. If the engine finds a path where this assertion fails, it reports an out-of-bounds access.

### 3.7 Composite Types

**Structs** are flattened into their component fields. Each field becomes a separate symbolic variable. For example:

```
struct Position {
    uint256 size;
    uint256 collateral;
    address owner;
}
```

When stored in a mapping like `mapping(uint256 => Position)`, this becomes three separate symbolic arrays:
- `positions_size: Array<BV256, BV256>`
- `positions_collateral: Array<BV256, BV256>`
- `positions_owner: Array<BV256, BV160>`

This avoids needing composite types in the SMT encoding while preserving field-level precision.

**Enums** are modeled as bounded unsigned integers. An enum with N variants is a `BV<8>` with the added constraint `value < N`.

**Tuples** are flattened identically to structs.

### 3.8 The Keccak256 Problem

Solidity uses keccak256 extensively for mapping storage slot computation, for ecrecover/signature operations, and for general hashing. Keccak256 is not expressible in standard SMT theories.

**Hybrid approach (recommended):**

1. **Concrete evaluation:** When all inputs to keccak256 are concrete, compute the actual hash value and use the concrete result. This is the common case for storage slot computation (e.g., `keccak256(key . slot)` where both key and slot are known).
2. **Uninterpreted function:** When inputs are symbolic, model keccak256 as an uninterpreted function. The solver knows that `keccak(x) == keccak(y) ⟹ x == y` (injectivity) and `keccak(x) != keccak(y)` when `x != y` (collision-freeness), but cannot compute actual hash values.
3. **Hash collision axioms:** Add constraints asserting that hash outputs do not collide with small constants or known slot numbers, preventing the solver from generating unrealistic scenarios.

### 3.9 Blockchain Environment Types

The SE engine must model the blockchain environment as symbolic inputs. These represent attacker-controlled or environment values:

| Variable | Symbolic Type | Notes |
|---|---|---|
| `msg.sender` | `BV<160>` | Primary attacker-controlled address |
| `msg.value` | `BV<256>` | Ether sent with call |
| `tx.origin` | `BV<160>` | Transaction originator |
| `block.timestamp` | `BV<256>` | Constrained: `prev_timestamp < timestamp` |
| `block.number` | `BV<256>` | Constrained: `prev_block < block_number` |
| `block.coinbase` | `BV<160>` | Miner/validator address |
| `block.difficulty` | `BV<256>` | (prevrandao post-merge) |
| `block.gaslimit` | `BV<256>` | Constrained to realistic range |
| `block.chainid` | `BV<256>` | Typically concrete (1 for mainnet) |
| `this` (contract address) | `BV<160>` | Typically concrete for target contract |
| `this.balance` | `BV<256>` | Symbolic, constrained >= msg.value for payable |

---

## 4. Directory Structure: `/symbolic`

### 4.1 Design Principles for Module Organization

- **Separation of concerns.** Each module has a single, clear responsibility.
- **Trait-based extensibility.** Core behaviors (exploration strategy, vulnerability detection, constraint solving) are defined as traits so implementations can be swapped or extended.
- **Testability.** Each module can be unit-tested independently. Vulnerability detectors in particular benefit from isolated testing against known-vulnerable patterns.
- **Incremental development.** The structure supports building components one at a time. The engine can run with a basic DFS strategy and no detectors initially, adding sophistication over time.

### 4.2 Directory Layout

```
symbolic/
├── mod.rs                      # Public API, re-exports, and module declarations
│
├── engine/
│   ├── mod.rs                  # Engine orchestration: the main exploration loop
│   ├── executor.rs             # Basic block interpreter: walks IR instructions,
│   │                           #   updates symbolic state per instruction
│   ├── explorer.rs             # Path exploration strategies: trait definition +
│   │                           #   implementations (DFS, BFS, priority-guided)
│   └── scheduler.rs            # Worklist management: state queuing, priority
│                               #   scoring, termination checks, loop bounding
│
├── state/
│   ├── mod.rs                  # SymbolicState struct: the complete snapshot of
│   │                           #   one execution path at a point in time
│   ├── memory.rs               # Symbolic memory model: word-addressed, supports
│   │                           #   symbolic reads/writes with aliasing
│   ├── storage.rs              # Symbolic contract storage: models the global
│   │                           #   Array<BV256, BV256> and slot projections
│   ├── stack.rs                # Symbolic stack operations (if IR is stack-based)
│   │                           #   or variable environment (if register-based)
│   └── call_context.rs         # Blockchain environment: msg.sender, msg.value,
│                               #   block.*, tx.*, and call depth tracking
│
├── types/
│   ├── mod.rs                  # SymbolicValue enum and core type definitions
│   ├── bitvec.rs               # Bitvector operations: arithmetic, bitwise,
│   │                           #   comparisons, sign extension, truncation
│   ├── symbolic_array.rs       # Z3 Array theory wrappers for mappings and
│   │                           #   dynamic arrays
│   ├── symbolic_bytes.rs       # Dynamic bytes/string: bounded-length model
│   │                           #   with symbolic content
│   └── hash.rs                 # Keccak256 modeling: concrete evaluation when
│                               #   possible, uninterpreted function otherwise
│
├── solver/
│   ├── mod.rs                  # Solver trait and high-level constraint interface
│   ├── z3_backend.rs           # Z3 integration: context management, push/pop,
│   │                           #   incremental solving, model extraction
│   ├── constraints.rs          # Path constraint set: conjunction of branch
│   │                           #   conditions accumulated along a path
│   └── optimization.rs         # Constraint simplification, caching, and
│                               #   solver query optimization
│
├── detectors/
│   ├── mod.rs                  # Detector trait definition, detector registry,
│   │                           #   and severity/confidence types
│   ├── reentrancy.rs           # Reentrancy patterns: checks-effects-interactions
│   │                           #   violations, cross-function reentrancy
│   ├── overflow.rs             # Integer overflow/underflow (pre-0.8.0 contracts
│   │                           #   without SafeMath)
│   ├── access_control.rs       # Missing or incorrect access control: unprotected
│   │                           #   selfdestruct, unprotected state changes
│   ├── unchecked_call.rs       # Unchecked external call return values,
│   │                           #   failed send/transfer handling
│   ├── tx_origin.rs            # tx.origin used for authentication instead of
│   │                           #   msg.sender
│   ├── delegatecall.rs         # Unsafe delegatecall patterns: to user-controlled
│   │                           #   addresses, storage collision risks
│   ├── selfdestruct.rs         # Unprotected or attacker-triggerable selfdestruct
│   ├── timestamp_dependency.rs # Block.timestamp used in critical logic
│   │                           #   (gambling, time-locks) with manipulable range
│   └── custom.rs               # User-defined assertion checking: custom
│                               #   invariants expressed as IR annotations
│
└── results/
    ├── mod.rs                  # Analysis result types, report generation
    ├── finding.rs              # Individual finding: vulnerability type, severity,
    │                           #   source location, path constraints, and
    │                           #   concrete counterexample (if available)
    ├── coverage.rs             # CFG coverage tracking: visited blocks, edges,
    │                           #   and functions; coverage percentage reporting
    └── witness.rs              # Witness/counterexample generation: extracts
                                #   concrete inputs from solver models that
                                #   trigger the reported vulnerability
```

### 4.3 Module Responsibilities

**`symbolic/mod.rs`** — The public-facing API of the symbolic execution component. It re-exports the key types (`SymbolicState`, `SymbolicValue`, `Finding`, `CoverageReport`) and exposes the top-level entry point function that the orchestrator calls, passing in the IR and CFG. This file should be thin — it delegates to `engine/` for actual work.

**`engine/`** — The core exploration machinery. `mod.rs` contains the main `run()` function that initializes the worklist, creates the initial symbolic state, and runs the exploration loop. `executor.rs` handles interpreting a single basic block — it takes a symbolic state and a list of IR instructions, and returns the updated state plus any generated assertions. `explorer.rs` defines the `ExplorationStrategy` trait and provides implementations. `scheduler.rs` manages the worklist data structure, applies priority scoring, and enforces termination bounds.

**`state/`** — Everything related to representing the symbolic state of an execution. `mod.rs` defines the top-level `SymbolicState` struct that bundles together memory, storage, call context, path constraints, and the current block ID. The submodules each own one component of that state. `call_context.rs` is particularly important — it holds the symbolic blockchain environment variables and manages the call stack for inter-contract calls.

**`types/`** — The symbolic type system. `mod.rs` defines the `SymbolicValue` enum (the core tagged union of BitVec, Bool, SymArray, SymBytes). The submodules implement operations on each type. `hash.rs` encapsulates the hybrid keccak256 strategy — the rest of the engine calls `hash.rs` and doesn't need to know whether a concrete or uninterpreted result was returned.

**`solver/`** — Constraint solving abstraction. `mod.rs` defines a `Solver` trait so the engine isn't hardcoded to Z3 (even though Z3 is the primary backend). This enables future experimentation with other solvers (Bitwuzla, CVC5) or with a portfolio approach. `z3_backend.rs` manages Z3 context lifetime, implements incremental solving with push/pop, and extracts concrete models for counterexample generation. `constraints.rs` manages the path constraint set — the accumulated branch conditions along a path. `optimization.rs` handles constraint simplification (e.g., constant folding, redundant constraint elimination) and solver query caching.

**`detectors/`** — Vulnerability detectors, each in its own file. `mod.rs` defines the `Detector` trait with two key hooks: `on_instruction(state, ir_instruction)` — called for each IR instruction during block interpretation, allowing detectors to monitor for patterns; `on_block_exit(state, block_id, terminator)` — called when the engine finishes a block, for detectors that reason about block-level patterns. Each detector file implements one vulnerability class. Detectors are registered in a `DetectorRegistry` and the engine runs all registered detectors during execution. New detectors can be added by creating a new file and registering it — no changes to the engine needed.

**`results/`** — Output of the analysis. `finding.rs` defines the `Finding` struct: vulnerability type, severity, confidence, source location (mapped back from IR to Solidity via source maps), the path constraints that led to the finding, and optionally a concrete counterexample. `coverage.rs` tracks which CFG blocks and edges were visited during exploration, enabling coverage reporting and identifying unreachable code. `witness.rs` takes a satisfiable path constraint set and extracts concrete values from the solver model — these are the actual inputs (msg.sender value, msg.value, calldata) that trigger the bug.

### 4.4 Key Trait Interfaces

The following traits define the extensibility boundaries of the system:

**`ExplorationStrategy`** — Determines which state to explore next from the worklist. Implementations: `DfsStrategy`, `BfsStrategy`, `PriorityStrategy`, `TargetedStrategy`.

**`Detector`** — Monitors execution for vulnerability patterns. Each detector is independent. The engine calls all registered detectors but detectors do not interact with each other.

**`Solver`** — Abstracts the constraint solver. The engine calls `check_sat()`, `get_model()`, `push()`, `pop()` through this trait without knowing which solver is underneath.

**`BlockInterpreter`** — Interprets IR instructions within a basic block and updates the symbolic state. Separating this behind a trait allows testing with mock IR and supports potential future alternative IR formats.

### 4.5 Why Not a Single `mod.rs`?

A monolithic `mod.rs` would work for early prototyping but becomes untenable quickly for the following reasons:

- **Detectors must be separate files.** Each detector is an independent analysis pass. Developers (and the AI component) will add new detectors frequently. A single file containing all detectors would create constant merge conflicts and make it hard to test or disable individual detectors.
- **Solver code is mechanically different.** The Z3 FFI bindings, context management, and memory safety concerns are qualitatively different from the exploration logic. Mixing them makes both harder to reason about.
- **State components have different change frequencies.** Memory modeling might be revised independently of storage modeling. Separate files let you modify one without risk to the other.
- **Testing granularity.** Each file can have its own `#[cfg(test)] mod tests` block with focused unit tests. A monolithic file leads to a massive, unstructured test module.

---

## 5. Integration Points with Other Components

### 5.1 SAST → SE

The SAST component annotates CFG blocks with vulnerability hints before SE begins. These annotations are attached to the CFG structure and consumed by the SE engine's priority scoring and detector initialization. Examples: "this block contains a state change after an external call" (reentrancy hint), "this block has an unchecked arithmetic operation" (overflow hint).

### 5.2 SE → Fuzzer

When the SE engine finds a feasible path to a vulnerability, it extracts a concrete counterexample (specific values for msg.sender, msg.value, calldata, block.timestamp, etc.) from the solver model. These concrete values are passed to the fuzzer as seed inputs. The fuzzer can then mutate these seeds to explore nearby paths that SE may have missed due to path bounds or solver timeouts.

### 5.3 AI → SE

The AI component influences SE through the priority-guided exploration strategy. It assigns scores to CFG blocks or symbolic states based on learned patterns from past analyses. The `PriorityStrategy` in `explorer.rs` queries the AI scoring function when computing state priorities. This is the primary integration point — the AI does not modify the SE engine internals, it only influences exploration ordering.

### 5.4 SE → AI

The SE engine provides training data to the AI component: which paths led to real vulnerabilities, which were false positives, which blocks were unreachable, and coverage statistics. This feedback loop enables the AI to improve its priority scoring over time.

---

## 6. Configuration Parameters

| Parameter | Default | Description |
|---|---|---|
| `max_path_depth` | 256 | Maximum basic blocks per path |
| `max_instructions` | 10,000 | Maximum IR instructions per path |
| `max_loop_unrolling` | 3 | Maximum iterations per loop |
| `max_states` | 10,000 | Maximum live states in worklist |
| `solver_timeout_ms` | 5,000 | Per-query solver timeout |
| `total_timeout_s` | 300 | Total analysis timeout per contract |
| `dynamic_bytes_bound` | 256 | Maximum length for symbolic bytes/string |
| `exploration_strategy` | Priority | DFS, BFS, Priority, or Targeted |
| `detectors` | All | List of enabled vulnerability detectors |

---

## 7. Future Considerations

- **Function summaries.** Compute symbolic summaries for internal functions to avoid re-executing them on every path. This is the path from Approach 2 (CFG-driven) to Approach 3 (summaries) discussed in the design phase.
- **Concolic mode.** Add a concolic execution mode that runs concrete inputs while collecting symbolic constraints, then negates constraints to generate new inputs. Integrates tightly with the fuzzer.
- **Cross-contract analysis.** Extend the call context to model inter-contract calls symbolically, enabling detection of cross-contract reentrancy and flash loan attacks.
- **Parallel exploration.** The worklist-based architecture naturally supports parallelism — multiple worker threads can pop states from the worklist and explore independently, synchronizing only for coverage updates and result reporting.