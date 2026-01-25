# Static Analysis Tool Plan (Rust, Solidity 0.4.x-0.8.x)

This plan focuses on performance where it matters (analysis engine) while keeping parsing and IR simple and robust.

## Goals and non-goals
- Goals
  - Support Solidity 0.4.x through 0.8.x.
  - Primary frontend uses solc; fallback parser handles broken or missing-dependency code.
  - Heuristic-only v1 (no user-defined invariants).
  - Shared analysis core for both frontends.
- Non-goals (v1)
  - Complete semantic typing for fallback input.
  - Full proof of logical correctness (only heuristics).
  - Bytecode-level analysis.

## Architecture overview
1. Frontends
   - Primary: solc AST (typed, full metadata).
   - Fallback: error-tolerant parser (tree-sitter) to recover syntax.
2. Normalized AST
   - Single schema to isolate version differences and frontend quirks.
3. IR + CFG + SSA
   - SlithIR-style reduced instruction set in native Rust.
4. Analysis core
   - Dataflow, taint, def-use, call graph, summaries.
5. Detectors
   - Thin rules that query the shared facts database.
6. Reporting
   - JSON + text.

## External tools
- solc (required)
  - Why: gives the only reliable typed AST and storage layout across versions.
- tree-sitter-solidity (fallback)
  - Why: error-tolerant parsing for broken/missing-dependency code.
- Optional: solang-parser (secondary fallback)
  - Why: higher-level AST for valid but unbuildable sources.

## Module layout
- src/frontend/
  - solc.rs: version selection, standard-json, AST ingestion.
  - parser.rs: tree-sitter fallback, best-effort AST.
- src/norm/
  - mod.rs: normalized AST types and IDs.
  - adapter_solc.rs: solc AST -> normalized AST.
  - adapter_fallback.rs: parser AST -> normalized AST.
- src/ir/
  - mod.rs: IR types, instructions, lowering.
- src/cfg/
  - mod.rs: basic blocks, edges, traversal.
- src/ssa/
  - mod.rs: phi insertion, renaming, def-use.
- src/analysis/
  - mod.rs: dataflow engine, taint, call graph, summaries.
- src/detectors/
  - mod.rs: rules and findings.
- src/report/
  - mod.rs: JSON/text output.
- src/util/
  - ids, spans, interning, error types.

## Detailed phases

### Phase 0: Project scaffolding
- Define crates and modules.
- Decide data structures for IDs and arenas (Vec + integer handles).
- Add a minimal CLI entrypoint.

Deliverables:
- Base crate layout, logging, error types.
- CLI arguments: input path, solc path, output format.

### Phase 1: solc frontend (primary)
- Parse pragmas and select solc version (per file or project).
- Run solc standard-json to get AST and metadata.
- Handle legacy AST formats for older versions.
- Cache by (solc version, source hash).

Deliverables:
- solc version resolver.
- solc invocation and AST loader.
- JSON deserializer for AST.

### Phase 2: fallback parser (secondary)
- Use tree-sitter to parse per file.
- Build a syntax AST with spans.
- Mark missing type info as Unknown.

Deliverables:
- Parser wrapper and syntax tree adapter.
- Fallback activation when solc fails.

### Phase 3: normalized AST
- Design a stable AST schema that fits 0.4-0.8.
- Normalize both solc and fallback ASTs into one model.
- Store spans for all nodes.

Deliverables:
- Normalized AST types.
- Adapter for solc and fallback.

### Phase 4: IR, CFG, SSA
- Implement SlithIR-style IR (reduced instruction set).
- Lower normalized AST to IR with spans and type IDs.
- Build CFG per function.
- Convert to SSA and construct def-use chains.

Deliverables:
- IR lowering pass.
- CFG builder.
- SSA conversion and def-use graph.

### Phase 5: analysis core (performance focus)
- Implement reusable dataflow engine with worklists.
- Use bitsets for facts; avoid HashMap in hot loops.
- Build call graph and function summaries.
- Add taint tracking for user inputs.

Deliverables:
- Dataflow engine (forward/backward).
- Call graph, summaries, taint analysis.

### Phase 6: detectors (v1 heuristic set)
Start with rules that map cleanly to dataflow facts:
- Reentrancy: external call before storage write.
- Missing access control for sensitive state writes.
- Unchecked low-level call results.
- Dangerous tx.origin usage.
- Delegatecall to untrusted target.
- Selfdestruct without guard.
- Unbounded loops based on user input.

Deliverables:
- Rules as thin queries on shared facts.
- Severity, confidence, and spans per finding.

### Phase 7: reporting
- JSON output with full metadata.
- Human-readable output for CLI.
- Tag findings as "full" (solc) or "partial" (fallback).

Deliverables:
- JSON schema.
- Text renderer.

## Performance strategy
- Use arenas (Vec) with integer IDs; avoid string keys in hot paths.
- Bitset dataflow facts with interning for symbols.
- Cache function summaries and call graph SCCs.
- Parallelize per-contract or per-function analyses when independent.
- Bound interprocedural depth and track only interesting variables.

## Fallback behavior rules
- If fallback used, mark results as partial.
- Disable detectors that require accurate typing or storage layout.
- Keep syntax-based rules and lower confidence when types are unknown.

## Testing strategy
- Unit tests for normalized AST adapters.
- Golden tests for IR lowering and CFG/SSA on small contracts.
- Regression suite of known vulnerability fixtures.
- Version matrix tests for 0.4.x, 0.5.x, 0.6.x, 0.7.x, 0.8.x.

## Milestones
1. M1: solc frontend + normalized AST (solc path).
2. M2: fallback parser + normalized AST (fallback path).
3. M3: IR + CFG + SSA.
4. M4: dataflow engine + call graph + summaries.
5. M5: initial detector set + JSON report.
6. M6: performance tuning and scaling tests.

## Progress tracking (weighted)
- [x] M1 (15%): solc frontend + normalized AST (solc path). Done.
- [x] M2 (10%): fallback parser + normalized AST (fallback path). Tree-sitter fallback integrated; heuristic parser kept as backup.
- [x] M3 (15%): IR + CFG + SSA. CFG covers if/else/loops/try/break/continue; IR uses 3-address style (temps, Assign/Store/Load/Binary/Call/Select) with IrValue/IrPlace and memory/storage tags; SSA + def-use done (name-based); tuple decl/assign lowering added; IR dump (text/json) added; fixture tests cover tuple lowering.
- [~] M4 (20%): dataflow engine + call graph + summaries. Call graph + intraprocedural taint done; call-graph taint propagation done; summary pass done.
- [~] M5 (25%): detector set + JSON report. Four detectors done; JSON report done.
- [~] M6 (15%): performance tuning and scaling tests. Not started.

Estimated completion: ~48%.

## Risks and mitigations
- solc version mismatches: mitigate with strict pragma parsing and version cache.
- AST drift across versions: isolate in adapter layer, add fixture tests.
- Dataflow blowups: bound analysis depth and track only key variables.
- Fallback false positives: tag partial findings and lower confidence.
