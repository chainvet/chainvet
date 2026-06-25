# Static Approach Evolution

Date: 2026-03-25

This document explains how the static approach changed from `refs/heads/main` to the current branch, what changed in the flow, what problems we faced, and how we fixed them.

## What The Main Branch Did

On `refs/heads/main`, the static path was essentially:

1. load target through `frontend::load_project(...)`
2. build IR, CFG, call graph, SSA, taint, and summaries
3. run raw detectors with `detectors::run_detectors(...)`
4. print a direct report with `report::print_report(&output, format)`

The key entrypoints were:

- `src/main.rs`
- `src/frontend/mod.rs`
- `src/report/mod.rs`
- `src/analysis/detectors/*`

Important properties of the old flow:

- `FrontendOutput` only carried:
  - `mode`
  - `ast`
- frontend fallback was coarse:
  - try `solc`
  - if that fails, fall back to parser
- report output was mostly a raw detector dump with counts
- there was no surfaced layer
- there was no raw-vs-suppressed split
- there was no confidence field
- there was no path-aware target filtering for folder/file reports

## What The Current Branch Does

The static path is still cheap and broad, but the flow is much more structured:

1. collect target sources and infer compiler behavior in `src/frontend/mod.rs`
2. choose `solc` or parser path using compiler-aware logic
3. build IR, CFG, call graph, taint, summaries, and SSA
4. run static detectors
5. derive runtime-style report findings plus static meta findings
6. normalize both through `src/surfaced/mod.rs`
7. emit:
   - surfaced findings
   - raw findings
   - suppressed counts
   - confidence

The current CLI path is also slightly different:

- `src/main.rs` now calls `report::print_report(&output, &input, format)?`
- the requested path is passed into the report layer so the report can stay aligned with the selected target rather than the whole loaded AST

## Main Branch vs Current Branch

| Area | `refs/heads/main` | Current branch | Why it changed |
| --- | --- | --- | --- |
| Frontend payload | `FrontendOutput { mode, ast }` | `FrontendOutput { mode, ast, compiler }` | later engines needed compiler/version semantics, especially for legacy Solidity |
| Source loading | simple `solc` then parser fallback | source collection, compiler inference, `solc` source loading, legacy parser path | old benchmark fixtures frequently failed because old Solidity syntax was treated like modern Solidity |
| Reporting | direct raw detector report | surfaced runtime + surfaced meta + raw + suppressed | raw detector output was too noisy for evaluation and demo use |
| Confidence | not present | added to static findings in report output | the benchmark/UI needed a unified field across engines |
| Normalization | none | canonicalized through `surfaced::surface_findings(...)` | the system needed one comparable output shape across approaches |
| Benchmark fit | good breadth, weaker signal quality | better benchmark alignment and better precision discipline | raw detector inflation hurt measured precision |

## Problems We Faced And How We Fixed Them

### Problem A: legacy Solidity compatibility broke useful static analysis

Many benchmark contracts are old, pragma-less, or use syntax that modern `solc` rejects. On the old flow, this meant:

- parse failures
- partial loads
- unstable visibility semantics
- weaker downstream analysis quality

Examples of the underlying compatibility class:

- named constructors
- old fallback/function forms
- `constant`/`throw` era syntax
- omitted visibility in legacy code

### Fix

We pushed compiler/version awareness down into the frontend:

- `src/frontend/mod.rs`
- `src/frontend/solc.rs`
- `src/frontend/solc_manager.rs`
- `src/frontend/parser.rs`

The new frontend now:

- infers compiler behavior from source markers
- carries compiler metadata forward
- retries older `solc` behavior for legacy contracts
- selects legacy parsing paths when full compilation is not realistic
- exposes helper logic like:
  - `effective_visibility(...)`
  - `is_public_entrypoint(...)`
  - `is_legacy_named_constructor(...)`

This fixed a real analysis problem, not a cosmetic one. Without it, the static engine was frequently operating on the wrong visibility or failing to load the fixture meaningfully.

### Problem B: raw static findings inflated precision loss

The detector set on `main` was already broad, but the output flow treated all raw detections as roughly equal. This created two issues:

- duplicate or near-duplicate findings from different detector views
- lower-signal meta/static backstop findings being presented alongside stronger findings

That behavior was bad for:

- CLI readability
- web UI consistency
- benchmark precision

### Fix

We inserted a surfaced layer:

- `src/surfaced/mod.rs`
- `src/report/mod.rs`

The new report flow:

1. builds raw static runtime findings
2. builds static meta findings
3. passes both through `surfaced::surface_findings(...)`
4. emits:
   - `findings`
   - `findings_raw`
   - `finding_count_raw`
   - `suppressed_findings`
   - `confidence`

This gave static the same output discipline later reused by symbolic, fuzzing JSON output, the hybrid web layer, and benchmark scoring.

### Problem C: several important static families were overfiring

A lot of precision work in this branch came from reducing generalized tool noise without hardcoding benchmark-specific exceptions into the engine logic.

The biggest recurring static problems were:

- access-control overfire
- transaction-order-dependency/front-running overfire
- locked-ether false positives
- stipend-style reentrancy overfire
- tainted-call spillover

### Fix

We tightened the detectors themselves, especially in:

- `src/analysis/detectors/access_control.rs`
- `src/analysis/detectors/block_manipulation.rs`
- `src/analysis/detectors/denial_of_service.rs`
- `src/analysis/detectors/reentrancy.rs`
- `src/analysis/detectors/misc.rs`
- shared frontend heuristics in `src/frontend/mod.rs`

Examples of the generalized fixes:

- authority-aware suppression for functions already guarded by owner/admin/sender checks
- public sender-payout recognition so intentional reward claims do not look like open drains
- identifier-token matching for TOD/front-running hints instead of brittle substring matching
- `.call.value(...)()` treated as a real Ether exit when evaluating locked-Ether logic
- `.send()` / `.transfer()` treated differently from callback-capable calls for reentrancy logic
- helper/library/event-style calls filtered out of tainted-call style detections

These were not benchmark-only patches. They improved the semantic quality of the rules.

## What Changed In Static Flow

The static approach on the current branch is still a static pass, but it is no longer "parse, detect, print".

It is now:

1. compiler-aware load
2. detector run
3. meta augmentation
4. normalization/suppression
5. confidence assignment
6. target-aware report rendering

That is the main static-flow upgrade.

## Why The Static Improvements Matter

The static approach is still the cheapest engine, so it must carry a lot of responsibility:

- it drives standalone static benchmarking
- it feeds hybrid planning
- it acts as a source of static backstops for fuzzing and hybrid runtime flows

Improving static was not only about making static itself better. It also improved:

- fuzzing guidance quality
- hybrid seed quality
- hybrid sink/frontier prioritization
- cross-engine consistency in evaluation and UI
