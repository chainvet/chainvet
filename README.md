# Solidity Multi-Modal Analysis Platform (Static / Symbolic / Fuzzing)

This project is a modular analysis platform for Solidity smart contracts, built on a shared foundation of **Frontend (M1/M2)** and **Analysis Model (M3)**. It supports three distinct analysis approaches:

1.  **Static Analysis** (Implemented in `src/analysis`)
2.  **Symbolic Execution** (Skeleton in `src/symbolic`)
3.  **Fuzzing** (Skeleton in `src/fuzzing`)

## Architecture Overview

All engines operate on a unified Intermediate Representation (IR), Control Flow Graph (CFG), and Static Single Assignment (SSA) form.

1.  **M1 (Primary Frontend):** Uses `solc` to compile and produce a rich AST.
2.  **M2 (Fallback Frontend):** Uses `tree-sitter` for error-tolerant parsing when compilation fails.
3.  **M3 (IR/CFG/SSA):** Lowers the AST into a SlithIR-style IR, builds CFGs, and computes SSA.

For deep technical details on M1-M3, see **[M1_M2_M3_DETAILS.md](./M1_M2_M3_DETAILS.md)**.
For usage examples and integrating new engines, see **[M1_M2_M3_USAGE.md](./M1_M2_M3_USAGE.md)**.

## Project Structure

```bash
src/
├── analysis/           # Static Analysis Engine (Taint, Call Graph, Detectors)
│   ├── detectors/      # Security detectors (e.g., tx.origin, reentrancy)
│   └── ...
├── symbolic/           # Symbolic Execution Engine (Start implementation here!)
├── fuzzing/            # Fuzzing Engine (Start implementation here!)
├── frontend/           # M1/M2 Frontends (solc + parser)
├── ir/                 # M3 Intermediate Representation definition & lowering
├── cfg/                # M3 Control Flow Graph construction
├── ssa/                # M3 SSA construction
└── main.rs             # CLI Entry point
```

## Getting Started

### Prerequisites
- Rust (latest stable)
- `solc` (managed automatically, but having it installed helps)

### Build & Run

```bash
# Build the project
cargo build

# Run Static Analysis (default)
cargo run -- <path-to-solidity-file-or-project>

# Run with JSON output
cargo run -- <path> --json

# Dump IR for debugging
cargo run -- <path> --dump-ir text
cargo run -- <path> --dump-ir tuple
```

## Contributor Guide

### Static Analysis Team
- Detectors are located in `src/analysis/detectors/`.
- Core analysis logic (taint, summaries) is in `src/analysis/`.

### Symbolic Execution Team
- Your workspace is **`src/symbolic/`**.
- Refer to **Example B** in `M1_M2_M3_USAGE.md` for how to consume the IR/CFG/SSA.
- Goal: Implement an interpreter that executes IR instructions over symbolic values.

### Fuzzing Team
- Your workspace is **`src/fuzzing/`**.
- Refer to **Example C** in `M1_M2_M3_USAGE.md`.
- Goal: Use CFG and Call Graph to generate harnesses and guide fuzzer inputs.

## License
[Add License Here]
