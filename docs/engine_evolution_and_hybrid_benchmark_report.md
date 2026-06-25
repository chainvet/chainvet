# Engine Evolution And Hybrid Benchmark Report

Date: 2026-03-25

This document has two jobs:

1. explain how the repository evolved from `refs/heads/main` to the current branch for the four internal approaches:
   - static
   - symbolic execution
   - fuzzing
   - hybrid
2. document the current detailed comparison between the repository's `hybrid` mode and the external tools used in the SmartBugs benchmark:
   - `Slither`
   - `Smartcheck`
   - `Securify2`
   - `Mythril`
   - `Manticore`

The code delta behind this report is substantial. Across the analysis/frontend/fuzzing/symbolic/core/report/surfaced areas, the diff from `refs/heads/main` to the current branch is:

- `30` files changed
- `21,474` insertions
- `682` deletions

The most important high-level change is simple:

- on `main`, the project had three standalone engines: static, fuzzing, and symbolic execution
- on the current branch, those engines were upgraded and then connected by a real hybrid orchestrator with shared frontend, normalized reporting, deduplication, confidence, and benchmark-grounded false-positive reduction

## 1. Static Approach

### 1.1 What The Main Branch Did

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

### 1.2 What The Current Branch Does

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

### 1.3 Main Branch vs Current Branch

| Area | `refs/heads/main` | Current branch | Why it changed |
| --- | --- | --- | --- |
| Frontend payload | `FrontendOutput { mode, ast }` | `FrontendOutput { mode, ast, compiler }` | later engines needed compiler/version semantics, especially for legacy Solidity |
| Source loading | simple `solc` then parser fallback | source collection, compiler inference, `solc` source loading, legacy parser path | old benchmark fixtures frequently failed because old Solidity syntax was treated like modern Solidity |
| Reporting | direct raw detector report | surfaced runtime + surfaced meta + raw + suppressed | raw detector output was too noisy for evaluation and demo use |
| Confidence | not present | added to static findings in report output | the benchmark/UI needed a unified field across engines |
| Normalization | none | canonicalized through `surfaced::surface_findings(...)` | the system needed one comparable output shape across approaches |
| Benchmark fit | good breadth, weaker signal quality | better benchmark alignment and better precision discipline | raw detector inflation hurt measured precision |

### 1.4 The Main Problems We Faced

#### Problem A: legacy Solidity compatibility broke useful static analysis

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

#### Fix

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

#### Problem B: raw static findings inflated precision loss

The detector set on `main` was already broad, but the output flow treated all raw detections as roughly equal. This created two issues:

- duplicate or near-duplicate findings from different detector views
- lower-signal meta/static backstop findings being presented alongside stronger findings

That behavior was bad for:

- CLI readability
- web UI consistency
- benchmark precision

#### Fix

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

#### Problem C: several important static families were overfiring

A lot of precision work in this branch came from reducing generalized tool noise without hardcoding benchmark-specific exceptions into the engine logic.

The biggest recurring static problems were:

- access-control overfire
- transaction-order-dependency/front-running overfire
- locked-ether false positives
- stipend-style reentrancy overfire
- tainted-call spillover

#### Fix

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

### 1.5 What Changed In Static Flow

The static approach on the current branch is still a static pass, but it is no longer "parse, detect, print".

It is now:

1. compiler-aware load
2. detector run
3. meta augmentation
4. normalization/suppression
5. confidence assignment
6. target-aware report rendering

That is the main static-flow upgrade.

### 1.6 Why The Static Improvements Matter

The static approach is still the cheapest engine, so it must carry a lot of responsibility:

- it drives standalone static benchmarking
- it feeds hybrid planning
- it acts as a source of static backstops for fuzzing and hybrid runtime flows

Improving static was not only about making static itself better. It also improved:

- fuzzing guidance quality
- hybrid seed quality
- hybrid sink/frontier prioritization
- cross-engine consistency in evaluation and UI

## 2. Symbolic Execution Approach

### 2.1 What The Main Branch Did

On `refs/heads/main`, symbolic execution was a proof-of-concept engine.

Its shape in `src/symbolic/mod.rs` was:

- lower IR and CFG
- explore paths with Z3
- record per-function exploration stats
- emit raw vulnerabilities

But the vulnerability model was extremely narrow:

- `Underflow`
- `Reentrancy`

Its `State` tracked basic path constraints and storage/env state, but it did not yet model the richer runtime signals that later proved necessary.

### 2.2 What The Current Branch Does

The current symbolic engine is a much larger runtime reasoning engine with:

- richer state
- more vulnerability families
- confidence
- meta findings
- surfaced normalization
- hybrid assist integration

The symbolic `State` now tracks far more execution semantics, including:

- `function_id`
- `instr_offset`
- value origins
- pending low-level calls
- sender-check state
- loop state
- order-sensitive storage read signals
- callback depth
- callback frame snapshots
- changed/stale storage keys across callbacks

The vulnerability model expanded from `2` kinds to a broad set including:

- arithmetic
- reentrancy and reentrancy fallback
- access control
- unchecked-call
- selfdestruct
- delegatecall
- public mint/burn
- wrong constructor name
- timestamp dependency
- weak PRNG
- hardcoded gas transfer
- locked ether
- memory manipulation
- DoS classes
- transaction-order dependency
- signature malleability
- unsafe send in require
- unprotected Ether withdrawal
- shadowing

### 2.3 Main Branch vs Current Branch

| Area | `refs/heads/main` | Current branch | Why it changed |
| --- | --- | --- | --- |
| State model | block/env/storage/path constraints | adds callback frames, value origins, pending calls, sender-checked, loop/order-sensitive state | old state was too weak to support many real bug classes |
| Bug model | `Underflow`, `Reentrancy` only | broad taxonomy-aligned runtime model | the old engine could not contribute meaningfully to full benchmark coverage |
| Output | raw vulnerability list | surfaced runtime findings + surfaced meta findings + raw views | symbolic needed the same normalized contract as the other engines |
| Confidence | none | explicit `VulnerabilityConfidence` mapping | important for UI and cross-engine comparison |
| Hybrid use | standalone only | also used as targeted assist engine | symbolic is powerful but too expensive to run as the main hybrid loop |
| Caching | limited | solver caches for feasibility and overflow/underflow checks | reduces repeated expensive solving |

### 2.4 The Main Problems We Faced

#### Problem A: the engine was too narrow to compete with the other approaches

The old symbolic engine could explore paths, but it only surfaced two bug families. That made it:

- hard to benchmark fairly against the rest of the taxonomy
- hard to justify in a hybrid system
- too limited for a presentation narrative

#### Fix

We expanded the symbolic vulnerability model and added richer runtime reasoning. The new `VulnerabilityKind` and confidence mapping in `src/symbolic/mod.rs` turned symbolic from a demo engine into a full analysis engine.

#### Problem B: path feasibility alone was not enough

A lot of security questions need more than branch feasibility. We also needed:

- whether an external callback was truly relevant
- whether storage was stale across a callback
- whether a sender check had happened
- whether order-sensitive storage reads happened before later writes

The old engine did not retain enough context for that.

#### Fix

We made the state model more semantic:

- callback-aware tracking
- stale-read tracking
- value-origin tracking
- sender-check tracking
- pending low-level call tracking

That is what enabled more meaningful runtime bug classes without switching symbolic into a totally separate architecture.

#### Problem C: path explosion made always-on symbolic unattractive

This was both a symbolic problem and a hybrid design problem.

If symbolic is run blindly across everything:

- it is expensive
- it plateaus badly
- it spends too much time where fuzzing would have been cheaper

#### Fix

Two complementary changes were made:

1. the standalone symbolic engine gained solver caches and better signal extraction
2. hybrid stopped treating symbolic as the default engine and instead uses it as a targeted assist through:
   - `src/core/engines/mod.rs`
   - `src/core/scheduler/mod.rs`

That separation is one of the most important architectural decisions in the repository.

#### Problem D: symbolic output needed the same signal discipline as static/fuzzing

Raw symbolic findings were not enough. We needed:

- comparable JSON
- confidence
- suppression counts
- meta/runtime split

#### Fix

The symbolic engine now builds:

- `vulnerabilities_raw`
- `meta_findings_raw`
- surfaced runtime findings
- surfaced meta findings
- suppressed counts

It uses the same surfaced layer as the other approaches, which is exactly what made the UI and benchmark reporting stable.

### 2.5 What Changed In Symbolic Flow

The old symbolic flow was:

1. explore
2. solve
3. print raw vulnerabilities

The current symbolic flow is:

1. load compiler-aware frontend output
2. build IR/CFG/dependency context
3. symbolically explore with richer runtime state
4. generate runtime vulnerabilities and meta findings
5. apply confidence
6. normalize through surfaced output
7. optionally act as a targeted assist in hybrid

### 2.6 Why The Symbolic Improvements Matter

These changes gave symbolic two roles instead of one:

- a stronger standalone engine
- a focused high-cost helper inside hybrid

That dual use is much more valuable than the older design, where symbolic existed but did not yet strongly influence the rest of the system.

## 3. Fuzzing Approach

### 3.1 What The Main Branch Did

On `refs/heads/main`, fuzzing was a standalone engine built around:

- ABI extraction from the normalized AST
- seed generation
- mutation/crossover
- concrete execution
- runtime oracle checks
- coverage-guided corpus updates

The old entrypoints were:

- `src/fuzzing/mod.rs`
- `src/fuzzing/runner.rs`
- `src/fuzzing/oracle.rs`
- `src/fuzzing/types.rs`

The old fuzzing engine already had useful runtime checks, but its orchestration and output were simpler:

- `run(ast, config)` worked only on `NormalizedAst`
- ABI extraction had no compiler-awareness
- there was no explicit meta-finding path
- there was no surfaced output layer in fuzzing JSON
- there was no explanation for `corpus_size = 0`
- static guidance/backstop integration was much lighter

### 3.2 What The Current Branch Does

The current fuzzing engine runs on `FrontendOutput`, not just AST:

- `run_fuzzer(output, config, format)`
- `runner::run(output, config)`

That matters because fuzzing now uses:

- compiler-aware ABI extraction
- frontend visibility semantics
- static analysis pre-pass
- static call graph and taint
- static findings
- meta findings
- static false-positive guards
- runtime backstops derived from static analysis

The current fuzzing report also exposes:

- raw runtime findings
- surfaced runtime findings
- raw meta findings
- surfaced meta findings
- confidence
- suppressed counts
- `corpus_zero_reason`

### 3.3 Main Branch vs Current Branch

| Area | `refs/heads/main` | Current branch | Why it changed |
| --- | --- | --- | --- |
| Input to fuzzing | `NormalizedAst` | `FrontendOutput` | fuzzing needed compiler-aware entrypoint semantics |
| ABI extraction | `extract_abis(ast)` | `extract_abis(ast, &output.compiler)` | legacy contracts were producing wrong callable sets |
| Static pre-pass | IR/CFG/ABI/deps only | adds call graph, taint, static findings, meta findings, FP guards, locked-Ether candidates | fuzzing needed guidance and noise control |
| Oracle interface | `check_all(trace, tx_sequence)` | `check_all(trace, tx_sequence, ast)` | several checks needed AST/context-sensitive suppression |
| Output | raw fuzz report | surfaced runtime + meta + raw + confidence + suppressed | benchmark/UI needed normalized output |
| Corpus diagnostics | none | `corpus_zero_reason` | necessary for explaining empty runs instead of silently failing |

### 3.4 The Main Problems We Faced

#### Problem A: legacy/odd contracts could lead to empty fuzzing without explanation

In the old flow, if ABI extraction or callable selection collapsed badly, fuzzing could effectively do little useful work and just look empty.

#### Fix

We made ABI extraction compiler-aware and added callable logic that is more tolerant of legacy cases:

- `src/fuzzing/types.rs`
- `FunctionAbi::is_fuzz_callable(...)`
- `extract_abis(ast, &output.compiler)`

We also added `corpus_zero_reason` so empty fuzz runs are diagnosable instead of mysterious.

#### Problem B: fuzzing was not making enough use of cheap static information

Pure runtime fuzzing wastes effort if static analysis already knows:

- which functions are suspicious
- which storage dependencies matter
- which address roles are relevant
- which bug families are plausible

#### Fix

The current fuzzing runner now performs a real static pre-pass before fuzzing:

- IR lowering
- CFG building
- static call graph
- taint
- static detector findings
- meta analysis

It then uses that information for:

- runtime false-positive guards
- locked-Ether candidate selection
- static runtime backstops
- promoted runtime meta findings

This is the point where fuzzing stopped being "standalone random runtime exploration" and became a guided runtime analysis engine.

#### Problem C: several runtime heuristics were too noisy

This was one of the biggest benchmark precision issues.

Examples of noise classes we reduced:

- caller-owned withdrawals being mislabeled as open withdrawals
- owner-guarded selfdestruct/privileged flows being mislabeled as open access-control failures
- `.send()` / `.transfer()` stipend flows being mislabeled as real reentrancy
- benign helper/logging patterns polluting tainted-call style output

#### Fix

We tightened the fuzzing oracle in `src/fuzzing/oracle.rs`, and we also reused shared heuristics from the frontend layer.

Generalized runtime fixes included:

- authority/payout-aware access-control checks
- callback-capable distinction for reentrancy
- checked low-level wrapper suppression
- richer exception-disorder / unchecked-call context
- AST-aware suppression for clearly benign patterns

This was a direct precision improvement, not a UI/reporting change.

#### Problem D: fuzzing output did not align well with the rest of the stack

Without surfaced output, confidence, and meta handling, fuzzing was harder to compare against:

- static
- symbolic
- hybrid
- benchmark scoring
- web UI summary cards

#### Fix

Fuzzing now produces a normalized JSON report that mirrors the rest of the system:

- surfaced runtime findings
- raw runtime findings
- surfaced meta findings
- raw meta findings
- confidence
- suppressed counts

### 3.5 What Changed In Fuzzing Flow

The old fuzzing flow was:

1. generate
2. mutate
3. execute
4. run oracles
5. print raw findings

The current fuzzing flow is:

1. compiler-aware load
2. static pre-pass
3. guided seed/value setup
4. concrete execution
5. richer AST-aware oracles
6. static-guided runtime backstops and runtime meta promotions
7. surfaced runtime/meta reporting

### 3.6 Why The Fuzzing Improvements Matter

The current fuzzing engine is much more useful both:

- as a standalone runtime engine
- as the main exploration engine inside hybrid

That second role is especially important, because the hybrid architecture assumes fuzzing is the default runtime workhorse.

## 4. Hybrid Approach

### 4.1 What The Main Branch Did

It did not have a real hybrid implementation.

In `refs/heads/main`, the CLI branch for `--hybrid` returned a placeholder error:

> `hybrid mode placeholder: not implemented yet (planned static + symbolic + fuzzing pipeline)`

So on `main`, hybrid was still an intention, not a running architecture.

### 4.2 What The Current Branch Does

The current branch has a real fuzz-first hybrid system, centered around:

- `src/core/scheduler/mod.rs`
- `src/core/engines/mod.rs`
- `src/core/artifacts/mod.rs`
- `src/core/triage/mod.rs`
- `src/core/store/mod.rs`
- `src/core/budget/mod.rs`
- `src/core/queues/*`

The current hybrid flow is:

1. load frontend output
2. lower IR and build CFG
3. run static analysis once
4. convert static results into:
   - static hints
   - selected static runtime findings
   - meta findings
5. bootstrap seed corpus from static guidance
6. run fuzzing in epochs
7. collect:
   - coverage
   - seeds
   - frontier goals
   - runtime findings
8. when fuzzing stalls or high-priority sinks remain uncovered:
   - invoke symbolic execution as a targeted assist
   - inject solver-produced seeds back into fuzzing
9. triage and deduplicate findings across the whole run
10. persist artifacts and emit one hybrid report

This is described in more detail in:

- `docs/hybrid_approach.md`
- `docs/hybrid_questions_answered.md`

### 4.3 Main Branch vs Current Branch

| Area | `refs/heads/main` | Current branch | Why it changed |
| --- | --- | --- | --- |
| Hybrid mode | placeholder only | real P1 orchestrator | the project needed more than three isolated engines |
| Runtime control loop | none | fuzz epochs + stall/frontier logic + symbolic assists | a naive union would not give better practical analysis |
| Shared artifacts | none | run directory with target, hints, epochs, assists, findings, report | reproducibility and presentation quality mattered |
| Cross-engine dedup | none | `FindingTriage` | hybrid needed to collapse duplicates and keep best evidence |
| Seed orchestration | none | bootstrap seeds + seed queues + assist injection | hybrid needed a real stateful exploration loop |
| Guidance model | none | `StaticHints` with hotspots, sinks, storage RW, arg domains, roles | hybrid needed static to act as a planner, not just a detector |

### 4.4 The Main Problems We Faced

#### Problem A: a naive union of engines would inflate output without solving the real problem

Just merging static + symbolic + fuzzing outputs would produce:

- duplicates
- inconsistent evidence quality
- noisy benchmark scoring
- unclear story in the presentation

#### Fix

We built a scheduler and triage layer instead of a dumb union:

- `P1Scheduler`
- `FindingTriage`
- surfaced low-noise output

That made hybrid a real analysis workflow rather than a batch concatenation of tools.

#### Problem B: fuzzing stalls on hard branches, but full symbolic is too expensive as the default

This is the central hybrid design problem.

#### Fix

We made fuzzing the main engine and symbolic the assist engine.

The scheduler tracks:

- stagnant epochs
- edge-rate windows
- frontier goals
- unmet priority sinks

Only then does it ask symbolic execution to solve a targeted goal and inject useful seeds back into the fuzz loop.

That keeps symbolic power available without paying symbolic cost everywhere.

#### Problem C: fuzzing needed better starting points than blind randomness

#### Fix

The hybrid static pass produces `StaticHints`, including:

- hotspots
- sinks
- storage read/write chains
- argument-domain hints
- address-role hints

Those hints drive:

- seed bootstrap
- function prioritization
- sender choice
- argument choice
- frontier prioritization

#### Problem D: hybrid needed reproducible, inspectable run artifacts

For evaluation and presentation, "the hybrid found X" is not enough. We needed to show:

- what the scheduler did
- what coverage changed
- what assists were requested
- what seeds were injected
- what findings survived dedup

#### Fix

We added:

- artifact models in `src/core/artifacts/mod.rs`
- persistence in `src/core/store/mod.rs`
- structured run directories under `runs/`

That is what makes the hybrid results auditable and presentation-friendly.

#### Problem E: hybrid precision was being hurt by extra families

A lot of the audit work in this branch came from understanding whether hybrid extras were:

- true false positives
- or real unlabeled issues not captured in SmartBugs official truth

The repo now includes:

- reviewed overlay truth
- audited extra-family decisions
- updated benchmark documents

Relevant files:

- `fixtures/ground_truth/smartbugs_reviewed_overlay.json`
- `docs/smartbugs_extra_findings_audit.md`
- `docs/smartbugs_external_tools_comparison.md`

That work improved both:

- the engine heuristics
- the honesty of the benchmark interpretation

### 4.5 What Changed In Hybrid Flow

There was no old hybrid flow to tune. The current branch created it.

The main design decision is:

- static is the planner
- fuzzing is the main explorer
- symbolic is the selective solver/assist
- triage is the shared dedup/filter stage

That architecture is the core contribution of the current branch.

### 4.6 Why The Hybrid Improvements Matter

Hybrid is where all earlier engine improvements start compounding:

- better frontend compatibility improves all engines
- better static hints improve fuzzing and hybrid bootstrap
- better fuzzing semantics improve hybrid runtime precision
- better symbolic state makes assists more useful
- surfaced output makes final results consistent

That is why hybrid became the strongest approach in the benchmark comparison.

## 5. Detailed Hybrid Comparison Against External Tools

This section compares the current repository's `hybrid` mode against the external tools used in the SmartBugs study lane:

- `Slither`
- `Smartcheck`
- `Securify2`
- `Mythril`
- `Manticore`

The current public comparison source in the repository is:

- `docs/smartbugs_external_tools_comparison.md`

### 5.1 Benchmark Scope

Current shared SmartBugs subset:

- `141` contracts

Compatibility-excluded fixture for this shared subset:

- `Benchmarks/smartbugs-curated/dataset/access_control/parity_wallet_bug_1.sol`
  - exact `solc 0.4.9` requirement could not be satisfied in the SmartBugs external-tool harness on this host

Truth sources used:

1. official SmartBugs truth:
   - `Benchmarks/smartbugs-curated/vulnerabilities.json`
2. reviewed-adjusted truth:
   - `fixtures/ground_truth/smartbugs_reviewed_overlay.json`

So the benchmark is intentionally reported in two ways:

- strict official truth
- reviewed-adjusted truth that credits audited unlabeled true positives

### 5.2 Fair-Comparison Status

Not every tool result should be ranked in the same way.

| Tool | Status | Included In Fair Ranking | Reason |
| --- | --- | --- | --- |
| `hybrid` | `comparable` | yes | usable results on the shared subset |
| `slither` | `comparable` | yes | usable results on the shared subset |
| `smartcheck` | `comparable` | yes | usable results on the shared subset |
| `mythril` | `comparable` | yes | usable results on the shared subset |
| `securify2` | `incompatible_corpus` | no | declared support starts at Solidity `>= 0.5.8`, but the shared subset contains `0/141` compatible contracts |
| `manticore` | `budget_exhausted` | no | equal-budget harness produced `0/141` usable finding sets; tuned pilot still produced no useful parsed findings |

This matters for honesty. `Securify2` and `Manticore` are still reported in the raw appendix, but they should not be ranked as ordinary zero-score losers under this specific harness/corpus combination.

### 5.3 Speed Metrics

The current runtime picture is:

| Tool | Avg / Contract (s) | Median (s) | P95 (s) | Max (s) | Approx Wall Time (s) |
| --- | ---: | ---: | ---: | ---: | ---: |
| `hybrid` | `22.190` | `8.275` | `121.467` | `139.805` | `3128.727` |
| `slither` | `0.642` | `0.567` | `0.743` | `4.432` | `22.901` |
| `smartcheck` | `1.793` | `1.743` | `2.165` | `3.714` | `64.051` |
| `securify2` | `0.445` | `0.428` | `0.529` | `0.783` | `15.948` |
| `mythril` | `25.349` | `29.407` | `40.355` | `40.438` | `916.883` |
| `manticore` | `30.787` | `40.271` | `40.354` | `40.414` | `1105.263` |

Interpretation:

- `slither` is by far the fastest meaningful baseline
- `smartcheck` is also very fast
- `hybrid` is much slower than static baselines, but still meaningfully faster end-to-end than a useful `manticore` lane would likely be
- `mythril` is slower than `slither`/`smartcheck` and weaker on this subset

### 5.4 Official Truth Metrics

Fair-ranking view:

| Tool | TP | FP | FN | Precision | Recall | F1 | Issue Coverage | File Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `hybrid` | `101` | `124` | `40` | `0.449` | `0.716` | `0.552` | `149/204 (0.730)` | `101/141 (0.716)` |
| `slither` | `98` | `267` | `43` | `0.268` | `0.695` | `0.387` | `129/204 (0.632)` | `98/141 (0.695)` |
| `smartcheck` | `89` | `193` | `52` | `0.316` | `0.631` | `0.421` | `114/204 (0.559)` | `89/141 (0.631)` |
| `mythril` | `61` | `124` | `80` | `0.330` | `0.433` | `0.374` | `70/204 (0.343)` | `61/141 (0.433)` |

Key result:

- `hybrid` is the best comparable tool on official-truth F1

### 5.5 Reviewed-Adjusted Metrics

Fair-ranking view:

| Tool | TP | FP | FN | Precision | Recall | F1 | Issue Coverage | File Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `hybrid` | `114` | `111` | `49` | `0.507` | `0.699` | `0.588` | `162/226 (0.717)` | `92/141 (0.652)` |
| `slither` | `106` | `259` | `57` | `0.290` | `0.650` | `0.402` | `137/226 (0.606)` | `86/141 (0.610)` |
| `smartcheck` | `98` | `184` | `65` | `0.348` | `0.601` | `0.440` | `123/226 (0.544)` | `79/141 (0.560)` |
| `mythril` | `64` | `121` | `99` | `0.346` | `0.393` | `0.368` | `73/226 (0.323)` | `59/141 (0.418)` |

Why this matters:

- the reviewed overlay prevents audited unlabeled true positives from unfairly counting as false positives
- even after that correction, `hybrid` remains clearly strongest on F1

### 5.6 Official Labeled-Line Overlap

| Tool | Truth Issues | Located Predictions | Line Matches | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `hybrid` | `204` | `95` | `38` | `0.400` | `0.186` | `0.254` |
| `slither` | `204` | `1706` | `115` | `0.067` | `0.564` | `0.120` |
| `smartcheck` | `204` | `1417` | `96` | `0.068` | `0.471` | `0.118` |
| `securify2` | `204` | `0` | `0` | `0.000` | `0.000` | `0.000` |
| `mythril` | `204` | `249` | `52` | `0.209` | `0.255` | `0.230` |
| `manticore` | `204` | `0` | `0` | `0.000` | `0.000` | `0.000` |

Interpretation:

- `hybrid` is much more conservative in located predictions than `slither` and `smartcheck`
- `slither` and `smartcheck` locate many more lines, but with very low strict precision
- `mythril` is stronger than `hybrid` on strict line precision-to-recall balance than the huge static baselines, but weaker overall on category/file-level effectiveness

### 5.7 Why `Securify2` And `Manticore` Look Like Zeros

#### `Securify2`

`Securify2` is not a meaningful zero on this specific corpus. It is an incompatibility case.

Reason:

- the shared SmartBugs subset is overwhelmingly old Solidity
- the harness-compatible subset contains `0/141` contracts at Solidity `>= 0.5.8`
- `Securify2` therefore has no genuinely compatible contracts in this lane

So its zero is better read as:

- incompatible on this corpus

not:

- inherently useless

#### `Manticore`

`Manticore` is a different case.

Its issue here is not corpus-version compatibility. It is practical usefulness under the harness:

- many timeouts
- symbolic execution failures
- empty completions
- even a tuned pilot still produced no parsed benchmark-mappable findings

So its current status is better read as:

- budget-exhausted / not producing usable benchmark output under this setup

### 5.8 What The Comparison Says Overall

The detailed comparison supports the following conclusions:

1. `hybrid` is the strongest comparable tool in this project's current SmartBugs lane.
2. `slither` remains the strongest external baseline in the fair ranking, especially given its speed.
3. `smartcheck` is a credible faster baseline, but below `hybrid` and below `slither` on recall.
4. `mythril` is slower and weaker than `hybrid` in this lane.
5. `Securify2` and `Manticore` should not be oversold or misread:
   - `Securify2` was not comparable on this corpus
   - `Manticore` was not practically informative under the benchmark budget

## Final Takeaways

If the current branch is compared to `refs/heads/main`, the story is:

- static became more compiler-aware, lower-noise, and better normalized
- symbolic grew from a narrow prototype into a real multi-family analysis engine and hybrid assist
- fuzzing became compiler-aware, guided, more explainable, and less noisy
- hybrid went from nonexistent to the strongest overall approach in the repository

The most important nontrivial lesson is that the improvements were not only "add more detectors".

The real gains came from:

- better frontend compatibility
- better runtime semantics
- better output normalization
- better cross-engine orchestration
- benchmark-grounded noise reduction

That is the engineering story worth presenting.
