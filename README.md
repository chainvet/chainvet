# Chainvet

A hybrid security analyzer for Solidity smart contracts. Chainvet combines three
engines over a shared frontend and IR — **static analysis** (45+ detectors),
**symbolic execution** (Z3), and **coverage-guided fuzzing** — and a **hybrid**
mode that runs them as one feedback loop: static analysis steers symbolic
execution, whose concrete witnesses seed the fuzzer, whose coverage stalls
trigger further symbolic assists. Findings are merged, deduplicated, and tagged
with a confidence tier (**confirmed** by dynamic/symbolic evidence vs **candidate**
from static heuristics only).

## Workspace

Chainvet is a Cargo workspace. The engines are pure libraries (no I/O); one
orchestration crate exposes a typed `scan()` facade; thin frontends render it.

```
crates/
  chainvet-core          shared types: normalized AST, IR, CFG, SSA, findings
  chainvet-frontend      load Solidity: solc → tree-sitter → optional AI fallback
  chainvet-ai            local-LLM (Ollama) transport, shared by frontend + reports
  chainvet-sa            static analysis: call graph, taint, detectors
  chainvet-se            symbolic execution (Z3)
  chainvet-fuzzing       coverage-guided greybox fuzzer
  chainvet-hybrid        the hybrid control loop
  chainvet-orchestrator  scan(config) -> ScanResult (merge/dedup/tier + AI review)
  chainvet-cli           binary: chainvet
  chainvet-ci            binary: chainvet-ci  (SARIF + fail-on-severity)
  chainvet-server        binary: chainvet-server (REST API)
  chainvet-lsp           binary: chainvet-lsp (language server)
```

Integrations live in their own repositories: **chainvet-vscode** (VS Code
extension → LSP), **chainvet-web** (web UI → server), **chainvet-action**
(GitHub Action → CI).

## Install

Requires a Rust toolchain and the **Z3** system library.

```bash
# Debian/Ubuntu: sudo apt-get install libz3-dev
# macOS:         brew install z3
git clone https://github.com/chainvet/chainvet
cd chainvet
cargo build --release
```

Binaries land in `target/release/`: `chainvet`, `chainvet-ci`, `chainvet-server`,
`chainvet-lsp`.

## Usage

### CLI

```bash
chainvet <path.sol>                 # static analysis (default)
chainvet --hybrid <path.sol>        # full hybrid analysis
chainvet --symbolic <path.sol>      # symbolic execution
chainvet --fuzzing <path.sol>       # fuzzing
chainvet --hybrid <path.sol> --json # machine-readable output
chainvet <path.sol> --dump-ir text  # inspect the IR (text|json|tuple)
```

Hybrid budget overrides (epochs, time caps, SE depth, fuzz iters, seed) are
available as flags — run `chainvet --help`.

### CI (SARIF)

```bash
chainvet-ci contracts/ --mode hybrid --fail-on high --sarif chainvet.sarif
```

Emits a SARIF 2.1.0 report and exits non-zero when a finding meets `--fail-on`
(`high`/`medium`/`low`/`none`). See **chainvet-action** for a ready-made GitHub
workflow that uploads the SARIF to code scanning.

### Server (REST)

```bash
CHAINVET_SERVER_ROOT=./contracts chainvet-server   # listens on 127.0.0.1:8080
```

`GET /health`, `POST /scan {source, mode}` → `ScanResult`, plus a project API
(`/api/files`, `/api/file`, `/api/analyze` + status/cancel) consumed by
**chainvet-web**.

### Editor (LSP)

`chainvet-lsp` is a stdio language server that publishes findings as diagnostics.
Point any LSP client at it (the **chainvet-vscode** extension does this for you).

## Optional AI features

Both are **opt-in** and call a local [Ollama](https://ollama.com) server — with
them off (the default), Chainvet runs fully offline and deterministically.

| Env var | Effect |
|---|---|
| `CHAINVET_AI_FALLBACK_PARSER=1` | AI-assisted parsing when solc and tree-sitter both fail |
| `CHAINVET_AI_REPORT=1` | LLM review of findings: drop false positives, annotate the rest |
| `CHAINVET_AI_ENDPOINT`, `CHAINVET_AI_MODEL` | Ollama endpoint/model (default `http://127.0.0.1:11434`, `qwen2.5-coder:7b`) |

## Development

```bash
cargo build              # build the workspace
cargo test               # run tests
cargo clippy -- -D warnings
cargo fmt
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) and [CLAUDE.md](./CLAUDE.md).

## License

MIT — see [LICENSE](./LICENSE).
