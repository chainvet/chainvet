# M1–M3 Deep Dive (Parsing → Normalization → IR/CFG/SSA)

This document explains in detail what Milestones M1, M2, and M3 do, how they work in this codebase, and why each design choice exists. It is intentionally verbose so the team can reason about correctness and extend the system safely.

## M1: Primary Frontend (solc) + Normalized AST

### What M1 does
M1 is the **primary, full‑fidelity frontend**. It takes Solidity sources (0.4.x–0.8.x), selects an appropriate `solc` version, runs `solc` in standard‑json mode, and normalizes the compiler AST into the project’s **Normalized AST** schema.

**Key deliverables:**
- Solidity version resolution and `solc` invocation.
- Standard‑json build of ASTs across source files.
- Normalization into a stable AST schema used everywhere else.

### Why M1 exists
- `solc` is the only reliable source of typed and version‑aware ASTs across the entire Solidity version range.
- Compiler ASTs contain semantic details (e.g., precise function kinds, storage layout hints) that raw parsing does not.
- By normalizing, we hide `solc`’s version drift behind a stable schema so analysis code doesn’t need to care about compiler versions.

### How M1 works

#### 1) Source discovery
- `src/frontend/mod.rs::load_sources` walks a file or directory, collecting `.sol` files.
- Each file becomes a `SourceFile` with `id`, `path`, and `source` content.

#### 2) Version resolution + solc selection
- `src/frontend/solc_manager.rs` scans Solidity pragma lines across all sources.
- The version resolver chooses the latest `solc` that satisfies all pragmas.
- `solc` binaries are cached in `~/.cache/static/solc` to avoid repeated downloads.

#### 3) Standard‑json compile
- `src/frontend/solc.rs::build_standard_json` builds the standard‑json payload.
- `run_solc` executes `solc --standard-json`, capturing the AST and errors.
- Errors are converted into a single “solc frontend failed” message and reported.

#### 4) Normalization to project AST
- `src/frontend/solc.rs::normalize_output` iterates over the compiler AST.
- Each node type is parsed into the project’s `NormalizedAst` format.
- Both **older** and **newer** solc AST formats are supported via flexible field reading.

### Normalized AST overview (M1 output)
The normalized AST (in `src/norm/mod.rs`) is the single shared format for all later passes. Key design decisions:

- **IDs everywhere:** `FileId`, `FunctionId`, `ExprId`, etc. All are integer handles into Vec‑based arenas.
- **Minimal semantic assumptions:** where typing is incomplete or unknown, nodes are marked as `Unknown` but still carry spans.
- **Spans on all nodes:** every AST and IR node stores source span to support diagnostics and reports.

Key normalized nodes:
- `Contract`, `Function`, `StateVariable`, `Modifier`, `Event`, `ErrorDefinition`
- `StmtKind` includes block/if/for/while/try/revert/emit/etc.
- `ExprKind` includes literal/ident/member/call/call‑options/index/tuple/conditional/new/etc.
- `ExprMeta` includes call chain metadata and call target classification.

### Why the normalized AST matters
- It isolates analysis passes from compiler AST drift.
- It merges both frontends (M1 and M2) into the same model.
- It carries enough structure to build SlithIR‑style IR and dataflow.


## M2: Fallback Frontend (tree‑sitter + legacy parser) + Normalized AST

### What M2 does
M2 is the **fallback parser** used when `solc` fails (broken code, missing imports, version mismatch). It parses source files with **tree‑sitter‑solidity** and normalizes into the same `NormalizedAst` as M1. If tree‑sitter fails, it falls back to a simpler heuristic tokenizer parser.

**Key deliverables:**
- Error‑tolerant parsing of broken code.
- Call chain metadata (member/index/call) even when types are missing.
- Compatibility with older Solidity syntax when possible.

### Why M2 exists
- `solc` fails if dependencies are missing or code is partially broken.
- Security tools must still glean structure from incomplete projects.
- Syntax‑level parsing enables “partial” findings and triage even when full compilation is impossible.

### How M2 works

#### 1) Tree‑sitter parse
- `src/frontend/parser.rs::parse_file_tree_sitter` attempts to parse each file.
- It walks the parse tree and creates normalized nodes for:
  - contracts, functions, state vars
  - statements (if/for/while/return/etc.)
  - expressions (calls, member access, tuple, etc.)
- It builds `ExprMeta` call‑chain metadata (for call graph building).

#### 2) Legacy token parser fallback
- If tree‑sitter fails, the legacy tokenizer is used.
- It can recognize contracts/functions and simple statements, enough to preserve structure.
- This keeps the pipeline functional even on severely malformed source.

#### 3) Normalized AST output
- M2 outputs the same `NormalizedAst` schema as M1.
- Missing types or ambiguous structures are marked `Unknown` but still useful.

### Normalization decisions (M2)
- Function parameters and return parameters are recorded by name if possible; otherwise, synthetic names are used (e.g., `_ret0`).
- Call options like `{value:…, gas:…}` are captured when visible.
- Type casts become calls in the normalized AST (e.g., `address(x)` becomes a call to `address`).

### Why this is “good enough” for partial analysis
- The analysis engine can still build CFG/SSA and find structure‑based vulnerabilities.
- Results are marked `partial` so the reporting layer can reduce confidence.


## M3: IR + CFG + SSA (Analysis‑ready Model)

### What M3 does
M3 transforms the normalized AST into a reduced, analysis‑friendly IR, builds a control flow graph (CFG), and computes SSA + def‑use chains.

**Key deliverables:**
- SlithIR‑style reduced instruction set.
- CFG blocks and edges for each function.
- SSA renaming with phi insertion and def‑use tracking.

### Why M3 exists
- ASTs are too rich and inconsistent for dataflow analysis.
- A smaller IR makes detectors predictable and simpler.
- SSA and CFG are essential for precise flow‑ and data‑dependency analysis.

### How M3 works

#### 1) IR Lowering (SlithIR‑style)
- Implemented in `src/ir/lower.rs`.
- Transforms AST statements/expressions into an instruction list, then into blocks.

Key IR instruction types (see `src/ir/mod.rs`):
- `Declare`, `Assign`, `Load`, `Store`
- `Binary`, `Unary`, `Select`
- `Call` with multi‑return destinations
- `Return` with multiple values
- `Control` (If/Else/Loop/Break/Continue/Revert/Try/Catch)

Important IR design choices:
- **Storage vs memory tagging** via `PlaceClass` to differentiate state writes from locals.
- **Call options** preserved (`gas`, `value`, `salt`).
- **Multi‑return calls** modeled as `Call { dest: Vec<IrVar> }`.
- **Tuple destructuring** lowered by assigning each return temp to its target.
- **Type casts** modeled as calls to the cast “function”.
- **`new` expressions** lowered as typed calls (for constructors).

#### 2) CFG building
- Implemented in `src/cfg/mod.rs`.
- The IR is split into blocks at control instructions.
- Edges are added for `if/else`, loops, breaks/continues, try/catch, and fall‑through.

#### 3) SSA + def‑use
- Implemented in `src/ssa/mod.rs`.
- Collects variable definitions and uses.
- Computes dominators and dominance frontiers.
- Inserts phi nodes at join points.
- Performs renaming to create SSA versions.

### Why M3 is core for all analysis types
- Static analysis needs def‑use, taint, and call graph built on SSA/CFG.
- Symbolic execution benefits from clear control flow and explicit data dependencies.
- Fuzzing uses CFG and call summaries for target selection and guided input.


## Summary: M1–M3 as a unified foundation

- **M1** provides full‑fidelity compiler ASTs and typed metadata when possible.
- **M2** provides robust parsing when compilation fails.
- **M3** converts both inputs into a shared IR/CFG/SSA that drives all higher‑level analysis passes.

Together, they create a single, reusable program model that all engines (static, symbolic, fuzzing) can build on.
