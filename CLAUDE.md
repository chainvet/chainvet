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
cargo run -p chainvet-cli -- scan -f json <path.sol>     # -f pretty|json|md|html|pdf
cargo run -p chainvet-cli -- scan -f pdf -o out.pdf <p>  # branded audit report (md|html|pdf)
cargo run -p chainvet-cli -- scan -s high --severity medium <p>  # filters: -s/-c floors, --severity/--confidence exact
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
   - `chainvet-sa` — call graph, taint, function summaries, 45+ detectors in `analysis/detectors/` (IDs like AC-01, RE-04). Also hosts `meta` + `surfaced`, and defines the shared `Confidence` scale (`-se` re-exports it) so every engine ranks findings on one axis. Each static `Finding` resolves confidence via `Finding::confidence()`: a detector's `confidence_override` when set, else the per-kind `FindingKind::base_confidence()` default (detectors with local evidence — reentrancy call type, taint sink type — set the override).
   - `chainvet-se` — Z3 symbolic execution; `analyze_with_options` returns typed findings + witnesses.
   - `chainvet-fuzzing` — generator/mutator/executor/oracle/scheduler; `runner::run` returns a typed report.
   - `chainvet-hybrid` — the control loop; `analyze()` returns the typed payload, `run()` = analyze + print.
4. **Orchestrator** (`chainvet-orchestrator`): `scan(output, ScanMode, budget) -> ScanResult` — runs the engine(s), unifies findings via `HybridFindingRow::collect` (merge/dedup/tier), and applies optional AI review (`ai_report`, env-gated). This is the one entry point every frontend calls.
5. **Frontends** (thin, built on the orchestrator + the shared `chainvet-report` renderer): `chainvet-cli` (render text/JSON + audit reports), `chainvet-ci` (SARIF + exit codes), `chainvet-server` (axum REST: file browser, analyze with filters/budget, `/api/report` md/html/pdf), `chainvet-lsp` (tower-lsp diagnostics).

### Audit reports (`chainvet-report`)

`chainvet-report` is a **shared crate** used by both the CLI (`-f md|html|pdf`) and the server (`GET /api/report?format=…`), so the two frontends emit identical reports. It renders a Cyfrin-style audit report (cover, disclaimer, risk classification, per-finding impact/PoC/mitigation) from one `AuditReport` model built off `ScanResult`. `lib.rs` holds the model + a **deterministic, AI-independent guidance library** (per-detector abuse/PoC/remediation, harvested from the old `feature/ai-assisted-reporting` branch); `AuditReport::from_scan` builds it from a single scan, `from_scans` accumulates several (the server analyzes a project file-by-file). `markdown.rs`/`html.rs` are native renderers; **`html` and `pdf` share one branded look** (dark Catppuccin theme, logo, severity colors) — `pdf.rs` pipes the HTML through an HTML→PDF engine (**weasyprint** preferred, else wkhtmltopdf; override `CHAINVET_PDF_ENGINE`) via `render_pdf_bytes` (in-memory, so the server can stream it) or `write_pdf`. No LaTeX/pandoc. In the CLI, `-f pdf`/`html` honor `--output`; `pdf` requires it.

### AI features

`chainvet-llm` is a transport-only LLM client (raw TCP, no HTTP dep). It's provider-agnostic: consumers depend on the `LlmProvider` trait, with `providers::ollama` the only implementation wired up today (add a provider by dropping a module under `providers/` that reuses the shared `http` transport). Both AI features are opt-in env vars and no-ops by default: `CHAINVET_LLM_FALLBACK_PARSER` (frontend) and `CHAINVET_LLM_REPORT` (orchestrator). Endpoint/model via `CHAINVET_LLM_ENDPOINT`/`CHAINVET_LLM_MODEL`.

## Conventions

- **Purity:** `chainvet-core`/`-sa`/`-se`/`-fuzzing`/`-hybrid` must not depend on axum/tokio/reqwest. I/O lives in the frontends.
- **Parity:** the hybrid `--json` output is the stable, benchmark-consumed schema (`HybridJsonReport`); don't change its shape casually.
- Integrations (`chainvet-vscode`, `chainvet-web`, `chainvet-action`) live in separate repos and consume the LSP / server / CI frontends respectively.

## Key Dependencies

- **z3** (0.19.11) — symbolic execution
- **tree-sitter** / **tree-sitter-solidity** — fallback parser
- **axum** / **tower-http** — server frontend; **tower-lsp** — LSP frontend
- **serde** / **serde_json** — serialization
- **weasyprint** (or wkhtmltopdf) — *external runtime tool*, not a crate: required only for `chainvet scan -f pdf` (renders the branded HTML). `-f md`/`html` need nothing extra.
