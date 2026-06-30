# Contributing to Chainvet

Thanks for your interest in improving Chainvet!

## Getting started

```bash
# Requires the Z3 system library (e.g. `sudo apt-get install libz3-dev`)
cargo build --release
cargo test
```

## Project layout

Chainvet is a Cargo workspace (see [README](./README.md) and [CLAUDE.md](./CLAUDE.md)).
The important rule: **engine crates are pure**. `chainvet-core`, `-sa`, `-se`,
`-fuzzing`, and `-hybrid` must not do I/O or depend on a web/LSP stack — they take
typed inputs and return typed results. All rendering and I/O lives in the frontend
crates (`-cli`, `-ci`, `-server`, `-lsp`), which talk to engines only through
`chainvet-orchestrator`'s `scan()`.

## Where things go

- **A new detector** → `crates/chainvet-sa/src/analysis/detectors/`.
- **Symbolic / fuzzing work** → `crates/chainvet-se` / `crates/chainvet-fuzzing`.
- **A new output format or integration** → a frontend crate that calls `scan()`;
  do not reach into the engines directly.
- **Shared types** → `chainvet-core` (keep it I/O-free).

## Before you open a PR

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace
```

- Keep the hybrid `--json` output schema stable — it is consumed by benchmarks and
  the CI/SARIF frontend.
- Add a fixture + test for new detections under `crates/<engine>/.../tests`.
- Conventional, focused commits with a clear message are appreciated.

## Reporting issues

Security analysis is nuanced — when filing a false positive/negative, please
include a minimal Solidity snippet, the mode used, and the expected vs actual
finding.
