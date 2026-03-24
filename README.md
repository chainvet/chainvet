# Solidity Multi-Modal Analysis Platform

This project analyzes Solidity smart contracts using four modes over a shared frontend + IR/CFG/SSA pipeline:

- `--static`
- `--symbolic`
- `--fuzzing`
- `--hybrid`

## Quick Start

Prerequisites:

- Rust (stable)
- `solc` (optional but recommended; the frontend also supports managed/cache resolution)

Run commands:

```bash
# Web UI (rooted at the directory you launch it from)
# Prints the localhost URL; does not auto-open a browser
cargo run -- --web

# Static (default if no mode flag is passed)
cargo run -- --static <path-to-solidity-or-project>

# Symbolic
cargo run -- --symbolic <path-to-solidity-or-project>

# Fuzzing
cargo run -- --fuzzing <path-to-solidity-or-project>

# Hybrid (P1 scheduler)
cargo run -- --hybrid <path-to-solidity-or-project>
```

Useful options:

```bash
# JSON output
cargo run -- --static <path> --json

# IR dump
cargo run -- --static <path> --dump-ir text
cargo run -- --static <path> --dump-ir json
```

Output behavior:

- Default CLI text output now shows a low-noise surfaced finding set.
- Default JSON output also surfaces the cleaned finding set first.
- Raw findings are still preserved in JSON under `*_raw` fields for benchmarking, debugging, and artifact consumers.
- Fuzzing text output also emits machine-readable `*_raw` count lines so the benchmark harness can keep using raw data without reintroducing noise into the human-facing sections.

## Code Layout

```text
src/
  analysis/      static analysis + detectors
  symbolic/      symbolic engine
  fuzzing/       fuzzing engine
  web/           localhost web UI + API
  frontend/      solc + parser frontend
  ir/            IR types/lowering/dump
  cfg/           control-flow graph construction
  ssa/           SSA construction
  core/          hybrid scheduler/artifacts/queues/store/triage
  main.rs        CLI entrypoint
```

## Documentation

- Documentation index: `docs/README.md`
- IR guide: `docs/IR_USAGE.md`
- Hybrid architecture:
  - `docs/architecture_current.md`
  - `docs/architecture_target.md`
  - `docs/hybrid_handoff_plan.md`
- Benchmark and scoring:
  - `docs/evaluation_modes.md`
  - `docs/not_so_smart_comparison.md`
  - `docs/smartbugs_external_tools_comparison.md`
  - `docs/grad_project_presentation_plan.md`

## Notes

- `runs/` contains generated run artifacts.
- `Benchmarks/Not-so-smart/` contains the benchmark dataset used for comparison work.
