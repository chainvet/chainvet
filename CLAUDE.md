# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Chainvet is a hybrid Solidity smart-contract analyzer in Rust: static analysis, symbolic execution (Z3), and coverage-guided fuzzing, plus a hybrid mode that runs them as one feedback loop. It is a **Cargo workspace** — the engines are pure libraries (no I/O), one orchestration crate exposes a typed `scan()`, and thin frontend binaries render the result.

## Build & Run Commands

```bash
cargo build --release        # Build the workspace (requires the z3 system library)
cargo test                   # Run tests
cargo clippy -- -D warnings  # Lint
cargo fmt                    # Format

# CLI (binary: chainvet)
cargo run -p chainvet-cli -- scan <path.sol>              # hybrid (the default mode)
cargo run -p chainvet-cli -- scan -m static <path.sol>   # -m static|symbolic|fuzzing|hybrid
cargo run -p chainvet-cli -- scan -f json <path.sol>     # -f pretty|json
cargo run -p chainvet-cli -- ir <path.sol> -f text       # dump IR: text|json|tuple

# Other frontends
cargo run -p chainvet-ci -- <path> --fail-on high --sarif out.sarif
CHAINVET_SERVER_ROOT=./contracts cargo run -p chainvet-server   # REST on :8080
cargo run -p chainvet-lsp                                       # stdio language server
```

Test fixtures live in `crates/chainvet-cli/tests/fixtures/` (e.g. `vuln_reentrancy.sol`).

## Architecture

### Pipeline: frontend → IR/CFG/SSA → engines → orchestrator → frontend

1. **Frontend** (`chainvet-frontend`): solc primary → tree-sitter fallback → optional AI fallback (`ai_fallback.rs`, env-gated). Produces a `NormalizedAst`.
2. **Core** (`chainvet-core`): the shared types every crate agrees on — `norm` (NormalizedAst), `ir` (SlithIR-style), `cfg`, `ssa`, `artifacts` (finding model), `util::error`, `OutputFormat`. No engine logic, no I/O.
3. **Engines** (each a pure library):
   - `chainvet-sa` — call graph, taint, function summaries, 45+ detectors in `analysis/detectors/` (IDs like AC-01, RE-04). Also hosts `meta` + `surfaced`.
   - `chainvet-se` — Z3 symbolic execution; `analyze_with_options` returns typed findings + witnesses.
   - `chainvet-fuzzing` — generator/mutator/executor/oracle/scheduler; `runner::run` returns a typed report.
   - `chainvet-hybrid` — the control loop; `analyze()` returns the typed payload, `run()` = analyze + print.
4. **Orchestrator** (`chainvet-orchestrator`): `scan(output, ScanMode, budget) -> ScanResult` — runs the engine(s), unifies findings via `HybridFindingRow::collect` (merge/dedup/tier), and applies optional AI review (`ai_report`, env-gated). This is the one entry point every frontend calls.
5. **Frontends** (thin, depend only on the orchestrator): `chainvet-cli` (render text/JSON), `chainvet-ci` (SARIF + exit codes), `chainvet-server` (axum REST), `chainvet-lsp` (tower-lsp diagnostics).

### AI features

`chainvet-ai` is a transport-only Ollama client (raw TCP, no HTTP dep). Both AI features are opt-in env vars and no-ops by default: `CHAINVET_AI_FALLBACK_PARSER` (frontend) and `CHAINVET_AI_REPORT` (orchestrator). Endpoint/model via `CHAINVET_AI_ENDPOINT`/`CHAINVET_AI_MODEL`.

## Conventions

- **Purity:** `chainvet-core`/`-sa`/`-se`/`-fuzzing`/`-hybrid` must not depend on axum/tokio/reqwest. I/O lives in the frontends.
- **Parity:** the hybrid `--json` output is the stable, benchmark-consumed schema (`HybridJsonReport`); don't change its shape casually.
- Integrations (`chainvet-vscode`, `chainvet-web`, `chainvet-action`) live in separate repos and consume the LSP / server / CI frontends respectively.

## Key Dependencies

- **z3** (0.19.11) — symbolic execution
- **tree-sitter** / **tree-sitter-solidity** — fallback parser
- **axum** / **tower-http** — server frontend; **tower-lsp** — LSP frontend
- **serde** / **serde_json** — serialization
