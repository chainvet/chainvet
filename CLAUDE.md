# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A hybrid Solidity smart contract analysis platform in Rust supporting three analysis modes: static analysis, symbolic execution (Z3-based), and fuzzing. All engines share a unified frontend and intermediate representation pipeline.

## Build & Run Commands

```bash
cargo build                  # Build (requires z3 system library)
cargo build --release        # Release build
cargo check                  # Type-check without full build
cargo fmt                    # Format code
cargo clippy -- -D warnings  # Lint

# Run analysis (default mode: static)
cargo run -- <path.sol>
cargo run -- <path.sol> --json              # JSON output
cargo run -- <path.sol> --dump-ir text      # Dump IR (text|json|tuple)

# Select analysis mode
cargo run -- --static <path.sol>
cargo run -- --symbolic <path.sol>
cargo run -- --fuzzing <path.sol>
cargo run -- --hybrid <path.sol>
```

Test Solidity fixtures are in `fixtures/` (e.g., `fixtures/vuln_reentrancy.sol`).

## Architecture

### Pipeline: M1 -> M2 -> M3 -> Engines

1. **M1 Frontend** (`src/frontend/solc.rs`, `solc_manager.rs`): Primary path. Invokes `solc` compiler to produce a full AST. Solc binary is auto-managed and cached in `~/.cache/static/solc`.
2. **M2 Frontend** (`src/frontend/parser.rs`): Fallback when solc fails. Uses tree-sitter-solidity for error-tolerant parsing.
3. **Normalization** (`src/norm/`): Both frontends produce a `NormalizedAst` that abstracts away solc version differences. This is the shared type consumed downstream.
4. **M3 IR/CFG/SSA** (`src/ir/`, `src/cfg/`, `src/ssa/`): Lowers `NormalizedAst` into a SlithIR-style instruction set, builds control flow graphs, and computes SSA form with phi nodes and def/use chains.

### Analysis Engines

- **Static Analysis** (`src/analysis/`): Fully implemented. Call graph construction, taint analysis, function summaries, and 45+ vulnerability detectors organized by category in `src/analysis/detectors/` (access control, arithmetic, reentrancy, DoS, etc.). Detector IDs follow a prefix convention (AC-01, AR-01, RE-01, etc.).
- **Symbolic Execution** (`src/symbolic/`): Skeleton/in-progress. Uses Z3 SMT solver. Active development on `se-engine` branch.
- **Fuzzing** (`src/fuzzing/`): Framework implemented with generator, mutator, executor, oracle, and scheduler modules.
- **Reporting** (`src/report/`): Generates text or JSON output from analysis findings.

### Entry Point

`src/main.rs` parses CLI args (analysis mode, output format, IR dump flags) and dispatches to the selected engine. Custom error types are in `src/util/error.rs`.

## Key Dependencies

- **z3** (0.19.11): SMT solver for symbolic execution
- **tree-sitter** / **tree-sitter-solidity**: Fallback parser
- **serde** / **serde_json**: Serialization for JSON output and IR dump

## Branch Strategy

- `main`: Stable branch
- `se-engine`: Symbolic execution development
- Feature branches exist for different hybrid integration strategies
