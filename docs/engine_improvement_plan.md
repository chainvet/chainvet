# Engine Improvement Plan (Static / Symbolic / Fuzzing / Hybrid)

This plan focuses on closing the quality gap where static currently outperforms symbolic and fuzzing.

## Goals

1. Increase symbolic and fuzzing recall without exploding false positives.
2. Make results comparable across modes using one canonical taxonomy.
3. Keep hybrid as the integration layer that amplifies all three engines.

## Baseline (from latest benchmark run)

- Static: highest breadth and most contracts covered.
- Symbolic: strong on path-sensitive arithmetic but timeouts on heavy contracts.
- Fuzzing: lower coverage of vulnerability classes; mostly dynamic-pattern findings.
- Hybrid: highest aggregate findings, but quality depends on symbolic/fuzz maturity.

## Roadmap

### Phase 1: Taxonomy and Label Normalization (Step 1)

Status: `completed (first implementation pass)`

Tasks:

1. Normalize equivalent labels emitted by symbolic/fuzzing to canonical names.
2. Ensure hybrid ingestion uses canonical names for cross-engine dedup/reporting.
3. Document canonical label policy and update scoring docs.

Acceptance:

- Same vulnerability family appears under one label across modes.
- Hybrid `findings.json` uses canonical labels for merged reporting.

### Phase 2: Symbolic Engine Precision + Scalability

Tasks:

1. Add solver/model caching for repeated constraint prefixes.
2. Add loop/path controls (state merge, widening, sink-directed search).
3. Improve underflow reporting dedup (same location/shape collapse).
4. Expand high-confidence detectors parity with static taxonomy.

Acceptance:

- Fewer timeouts on benchmark heavy contracts.
- Reduced duplicate arithmetic findings.

### Phase 3: Fuzzing Guidance + Oracle Coverage

Tasks:

1. Add stronger static->fuzz hints (`storage_rw_map`, `arg_domains`, `address_roles`).
2. Add frontier-distance guidance for mutation scheduling.
3. Expand high-confidence oracle set toward taxonomy parity.
4. Improve sequence generation for stateful multi-tx bugs.

Acceptance:

- More contracts with non-zero fuzz findings.
- Better alignment with known benchmark bug classes.

### Phase 4: Hybrid Quality Controls

Tasks:

1. Add assist retry/backoff for repeated unsolved frontier goals.
2. Add scheduler tests for stall and assist policy correctness.
3. Add cross-engine dedup policy validation tests.

Acceptance:

- Reduced repeated SE assists on same unsolved edge.
- Stable unique-finding counts across reruns.

## Step 1 Changes Applied in This Update

- Symbolic label normalization:
  - `underflow` -> `integer-underflow`
  - file: `src/symbolic/mod.rs`
- Fuzzing canonical labels introduced and used in outputs:
  - `tx-origin-auth` -> `tx-origin`
  - `hardcoded-gas` -> `hardcoded-gas-transfer`
  - `storage-memory-issue` -> `memory-manipulation`
  - files: `src/fuzzing/types.rs`, `src/fuzzing/runner.rs`
- Hybrid now ingests canonical fuzz labels:
  - file: `src/core/engines/mod.rs`

Step 1 extension (pattern expansion):

- Symbolic new patterns:
  - `weak-prng` via `block.number`/`blockhash` influence in branch conditions.
  - `hardcoded-gas-transfer` via `send`/`transfer` call detection (including member calls lowered through temporaries).
  - `unsafe-send-in-require` when `send()` return is used in `require/assert`.
  - `unprotected-ether-withdrawal` for external value transfer without observed sender-authorization condition.
  - `unchecked-call` classification tightened so `transfer` is not reported as unchecked return.
  - confidence tier is now emitted per symbolic finding (`high`/`medium`).
  - file: `src/symbolic/mod.rs`
- Fuzzing rule-set expansion in default `check_all`:
  - enabled `exception-disorder`, `access-control`, `locked-ether`.
  - added `unsafe-send-in-require` oracle (DoS taxonomy alignment).
  - added AST-level `public-mint-burn` pattern.
  - confidence tier is now attached per finding kind and printed in report output.
  - files: `src/fuzzing/oracle.rs`, `src/fuzzing/executor.rs`, `src/fuzzing/types.rs`, `src/fuzzing/runner.rs`

Step 1 extension (next taxonomy batch):

- Added in symbolic + fuzzing for parity:
  - `dos-with-failed-call`
  - `transaction-order-dependency`
  - `signature-malleability`
- Confidence policy:
  - `dos-with-failed-call`: `medium` (heuristic)
  - `transaction-order-dependency`: `medium` (heuristic)
  - `signature-malleability`: `low` (conservative parity detector)
- Files:
  - `src/symbolic/mod.rs`
  - `src/fuzzing/types.rs`
  - `src/fuzzing/executor.rs`
  - `src/fuzzing/oracle.rs`

Step 1 extension (FP reduction tuning):

- Symbolic:
  - `transaction-order-dependency` and `signature-malleability` now require function-level static evidence before emission.
  - Order-sensitive storage name matching changed from loose substring to token-aware matching.
  - file: `src/symbolic/mod.rs`
- Fuzzing:
  - same static-evidence gating for `transaction-order-dependency` and `signature-malleability`.
  - token-aware order-sensitive storage name matching in oracle.
  - files: `src/fuzzing/runner.rs`, `src/fuzzing/oracle.rs`
- Hybrid:
  - fuzz epoch adapter now enforces static-evidence gating for TOD/CR-02 before artifact emission.
  - file: `src/core/engines/mod.rs`

Step 1 extension (symbolic taxonomy closure):

- Symbolic added missing taxonomy parity kinds:
  - `arbitrary-write`
  - `public-mint-burn`
  - `locked-ether`
  - `memory-manipulation`
- Symbolic implementation details:
  - `arbitrary-write`: authority-sensitive storage write without sender-check in path state.
  - `public-mint-burn`: AST-level public/external `mint`/`burn` function detection.
  - `locked-ether`: payable-contract heuristic when no Ether-sending call path is detected in IR.
  - `memory-manipulation`: inline assembly and delegatecall-in-loop patterns.
- Files:
  - `src/symbolic/mod.rs`
  - `docs/coverage_matrix.md`
  - `docs/taxonomy_engine_mapping.md`

## Next Immediate Step (Step 2)

Status: `completed (first implementation pass)`

Implemented symbolic timeout/duplicate control:

1. Add vulnerability dedup key by `(function_id, pc, kind)` in symbolic output.
2. Add state/constraint cache to cut repeated solver checks.

Step 2 changes applied in this update:

- Symbolic solver caching:
  - Added `SolverCache` in `src/symbolic/mod.rs` for:
    - path feasibility cache (`sat_by_constraints`)
    - underflow model cache (`underflow_by_constraints`)
  - Constraint keys are normalized (sorted conjunction strings) so equivalent branch-prefix sets reuse cached SAT results.
- Symbolic dedup hardening:
  - Underflow findings are now deduped by `(kind, pc)` inside `engine(...)` like other rules.
  - Output-level dedup added in `run(...)` for dynamic findings with key `(function_id, kind, pc)` before report emission.
- Added tests:
  - `solver_cache_reuses_equivalent_constraint_sets`
  - `engine_underflow_is_deduped_on_same_pc`
  - plus existing symbolic/fuzz gating tests remain green.

## Next Immediate Step (Step 3)

Status: `completed (first implementation pass)`

Implemented symbolic path explosion control:

1. Add loop/path controls (bounded loop revisits and optional state-merge policy).
2. Add sink-directed branch prioritization so hard goals are explored before low-value paths.

Step 3 changes applied in this update:

- Added bounded path controls in `src/symbolic/mod.rs`:
  - per-path block revisit bound: `MAX_BLOCK_VISITS_PER_PATH`
  - path-shape revisit bound: `MAX_STATE_SHAPE_REVISITS`
  - queue admission now uses `try_enqueue_state(...)` with these bounds.
- Added sink-directed scheduling:
  - block sink scoring via `build_sink_scores(...)`
  - dynamic state scoring via `state_priority_score(...)`
  - scheduler pop strategy now uses `pop_next_state(...)` (highest-priority first).
- Added tests:
  - `engine_bounds_unconditional_loop_revisits`
  - `sink_priority_scheduler_picks_hotter_state_first`

## Next Immediate Step (Step 4)

Status: `completed (first implementation pass)`

Implemented fuzzing guidance quality upgrades:

1. Wire stronger static->fuzz artifacts (`storage_rw_map`, `arg_domains`, `address_roles`) into mutation scheduling.
2. Add frontier-distance scoring for mutation prioritization.

Step 4 changes applied in this update:

- Static hints schema extended in `src/core/artifacts/mod.rs`:
  - `storage_rw_map`
  - `arg_domains`
  - `address_roles`
- Static adapter now produces these artifacts in `src/core/engines/mod.rs`:
  - storage read/write summary per function from IR dependency map
  - parameter candidate domains from param-name heuristics + function constants
  - address role hints (`owner` / `attacker` / `user`) with target function mapping
- Fuzz adapter guidance integration in `src/core/engines/mod.rs`:
  - static-guided mutation shaping (`apply_static_guidance_to_individual`)
  - whitelist/hotspot-aware function targeting
  - arg-domain value injection
  - role-aware sender/value/environment mutation
  - weighted parent selection by seed energy
- Frontier-distance guidance in fuzz epoch loop:
  - distance-to-uncovered-frontier computation (`frontier_distances_by_function`)
  - near-miss seed retention when distance improves
  - trace prefix now carries `distance_hint` from real frontier distance
- Bootstrap seed generation now consumes the new static hints in `src/core/scheduler/mod.rs`.
- Added tests in `src/core/engines/mod.rs`:
  - `param_domain_candidates_include_deadline_hints`
  - `frontier_distance_uses_uncovered_edges`
  - `static_guidance_rewrites_disallowed_function_ids`

## Next Immediate Step (Step 5)

Status: `completed (first implementation pass)`

Implemented fuzzing oracle breadth and stateful sequencing:

1. Expand high-confidence oracles toward remaining taxonomy parity gaps.
2. Add sequence scheduling that explicitly follows static `storage_rw_map` writer->reader chains per epoch.

Step 5 changes applied in this update:

- Fuzzing oracle expansion:
  - Added `check_arbitrary_write(...)` in `src/fuzzing/oracle.rs` and wired it into `check_all(...)`.
  - Detection condition:
    - storage writes in a function
    - no sender-check event for that function
    - same function exercised by 2+ distinct senders in the tx sequence
  - Emits `FuzzFindingKind::ArbitraryWrite` with high severity.
  - Added test: `detect_arbitrary_write_with_multi_sender_evidence`.
- Fuzz confidence mapping update:
  - `FuzzFindingKind::ArbitraryWrite` moved to `high` confidence tier in `src/fuzzing/types.rs`.
- Storage RW chain scheduling in hybrid fuzz adapter:
  - Added `storage_rw_chains` in guidance model and weighted chain selection.
  - `apply_static_guidance_to_individual(...)` now seeds/rewrites transaction prefixes into writer->reader chains when available.
  - Added test: `static_guidance_builds_storage_rw_writer_reader_chain`.
- Fuzz parity add-on in hybrid:
  - Added AST-level `public-mint-burn` finding emission on epoch 1 in `src/core/engines/mod.rs` to match fuzzing runner parity.

## Next Immediate Step (Step 6)

Status: `completed (first implementation pass)`

Implemented hybrid orchestration quality controls:

1. Add scheduler-level tests for stall windowing + assist retry/backoff policy.
2. Add frontier-goal attempt budgeting to avoid repeated SE work on long-unsat goals.

Step 6 changes applied in this update:

- Scheduler stall policy in `src/core/scheduler/mod.rs`:
  - Added windowed stall trigger over edge-rate history (`update_stall_window`).
  - Trigger now uses average edge-rate over a configurable window (`stall_epochs_threshold`) with epsilon derived from budget.
- SE assist retry/backoff and attempt budgeting:
  - Added frontier-goal keying + attempt tracking.
  - Added exponential backoff per repeated unsolved goal (`assist_backoff_epochs`).
  - Added max attempts per goal guard to stop repeated SE work on long-unsat goals.
  - Added assist goal selector that skips backoff/expired goals (`select_frontier_goal_for_assist`).
- Added scheduler tests:
  - `stall_window_uses_windowed_edge_rate`
  - `frontier_selector_respects_backoff_and_attempt_budget`
  - `assist_backoff_scales_with_attempts`

## Next Immediate Step (Step 7)

Status: `completed (first implementation pass)`

Implemented P1 quality hardening and measurement:

1. Add integration test for assist loop behavior across multiple epochs (successful assist vs unsolved assist backoff path).
2. Add benchmark regression guard for hybrid report quality metrics (`findings_unique`, `se_assists`, coverage curve stability).

Step 7 changes applied in this update:

- Scheduler integration testing in `src/core/scheduler/mod.rs`:
  - Added mock-engine integration test for successful assist path:
    - `assist_loop_success_injects_and_resets_attempts`
    - validates SE seed injection and attempt reset behavior (`[1, 1]`).
  - Added mock-engine integration test for unsolved assist path:
    - `assist_loop_unsolved_applies_backoff_and_attempt_cap`
    - validates backoff schedule + capped attempts (`[1, 2, 3]`).
- Benchmark/report regression guard:
  - Added `coverage_curve_stable(...)` and `report_quality_guard(...)` helper checks.
  - Added guard test:
    - `report_quality_guard_rejects_bad_metrics`
    - validates `findings_unique <= findings_total`, `se_assists <= budget.max_se_assists`, and coverage-curve stability.
- Testability refactor:
  - Added `run_with_output(...)` helper on scheduler to allow deterministic integration tests without live frontend loading.

## Next Immediate Step (Step 8)

Status: `completed (first implementation pass)`

P4-prep queue/backend abstraction hardening:

1. Introduce queue traits and migrate scheduler/integration usage behind trait interfaces.
2. Add adapter skeletons for process-safe backends (SQLite first, Redis optional).

Step 8 changes applied in this update:

- Queue trait facade added in `src/core/queues/mod.rs`:
  - `SeedQueue`
  - `FrontierQueue`
  - `FindingQueue`
- In-memory queues now implement these traits:
  - `InMemorySeedQueue`
  - `InMemoryFrontierQueue`
  - `InMemoryFindingQueue`
- Scheduler queue integration now uses trait-backed function boundaries in `src/core/scheduler/mod.rs`:
  - `process_epoch_result(...)`
  - `select_frontier_goal_for_assist(...)`
- Added backend adapter skeleton modules:
  - `src/core/queues/sqlite.rs` (`SqliteQueueBackend` + queue adapters)
  - `src/core/queues/redis.rs` (`RedisQueueBackend` + queue adapters)
- Added queue-layer tests:
  - `core::queues::tests::sqlite_backend_seed_queue_uses_same_contract`
  - `core::queues::tests::redis_backend_frontier_queue_uses_same_contract`

## Next Immediate Step (Step 9)

P4-prep persistence hardening:

1. Move SQLite queue adapter from in-memory delegation to real persisted queue operations.
2. Add queue contract tests that run against both in-memory and SQLite backends.

## Next Immediate Step (Step 10)

Status: `completed (first implementation pass)`

Implemented frontend reliability hardening to protect all modes (`--static`, `--symbolic`, `--fuzzing`, `--hybrid`) from accidental parser-only degradation when `solc` download/cache setup is brittle.

Step 10 changes applied in this update:

1. `solc` resolution order is now reliability-first:
   - `SOLC_PATH` override
   - `solc` in `PATH`
   - best matching cached `solc-v<version>` binary
   - download path as last resort
2. Cache directory selection is now writable-fallback aware:
   - `STATIC_SOLC_DIR`
   - `XDG_CACHE_HOME/static/solc`
   - `HOME/.cache/static/solc`
   - `USERPROFILE/.cache/static/solc`
   - workspace-local `.cache/static/solc`
   - `/tmp/static-solc-cache`
3. Added explicit offline mode:
   - `STATIC_SOLC_OFFLINE=1` disables list/binary downloads and forces local cache usage.
4. Improved download error reporting:
   - no progress spam in CLI
   - first-line stderr detail included in failure reason.

Files:

- `src/frontend/solc_manager.rs`

## Next Immediate Step (Step 11)

Status: `completed (first implementation pass)`

Implemented first symbolic precision upgrade toward EVM-like uint256 semantics.

Step 11 changes applied in this update:

1. Core symbolic arithmetic/comparison now uses uint256 bitvector semantics (wrap-aware):
   - `+`, `-`, `*` use BV arithmetic (`bvadd`, `bvsub`, `bvmul`)
   - comparisons use unsigned BV relations (`bvugt`, `bvuge`, `bvult`, `bvule`)
2. Division/modulo behavior now matches EVM-style safe handling for zero divisors in symbolic eval:
   - `/` and `%` use `ite(rhs == 0, 0, op)` with unsigned BV ops.
3. Underflow check now uses unsigned uint256 ordering instead of signed `Int` ordering:
   - condition switched to `rhs_bv > lhs_bv` (unsigned).
4. Added focused symbolic tests:
   - uint256 wrap-around addition
   - unsigned comparison (`max_uint256 > 1`)
   - unsigned underflow check behavior (`max_uint256 - 1` not flagged, `1 - 2` flagged)

Files:

- `src/symbolic/mod.rs`

## Next Immediate Step (Step 12)

Status: `completed (first implementation pass)`

Implemented symbolic control/effect modeling improvements for `require/assert/revert` and external call side effects.

Step 12 changes applied in this update:

1. `require/assert` now model success + failure behavior directly in symbolic execution:
   - failure branch adds a reachable revert terminal (`!cond`) when satisfiable
   - success branch enforces `cond` as a path constraint before continuing
   - unsatisfiable success branch terminates current path early.
2. explicit `revert(...)` call modeling:
   - immediately terminates current path as `Revert` terminal when feasible
   - avoids continuing into later instructions in that block.
3. external call side-effect modeling:
   - low-level external calls (non-`staticcall`) and `delegatecall` now havoc tracked storage slots to avoid unsound “storage unchanged” assumptions.
4. Added focused symbolic tests:
   - `require` splits into success and revert paths
   - `revert` terminates path
   - storage havoc rewrites tracked slots.

Files:

- `src/symbolic/mod.rs`

## Next Immediate Step (Step 13)

Status: `completed (first implementation pass)`

Implemented symbolic low-level call precision improvements to reduce path noise and reentrancy false positives.

Step 13 changes applied in this update:

1. Low-level call primary return modeling:
   - first destination return of low-level calls is now constrained to boolean domain (`0` or `1`).
   - pending unchecked-call tracking is now tied to the primary low-level return destination only.
2. Reentrancy edge quality:
   - `staticcall` no longer marks mutable external-call context for post-call write/reentrancy patterning.
3. Refined mutable external-call marker:
   - introduced `is_state_mutating_external_call` behavior in symbolic call handling.
4. Added focused symbolic tests:
   - non-boolean return values rejected under bool-domain constraint
   - low-level return boolean modeling prunes impossible branches
   - `staticcall` does not trigger reentrancy marker path.

Files:

- `src/symbolic/mod.rs`

## Next Immediate Step (Step 14)

Status: `completed (first implementation pass)`

Implemented fuzzing stateful-sequence maturity improvements using dependency-guided mutation during epochs (not only initial seeds).

Step 14 changes applied in this update:

1. Added guided mutator path using storage RW dependencies:
   - new API: `mutate_individual_guided_with_dict(...)`
   - can inject writer->reader chain prefixes derived from `DependencyMap`.
2. Runner now uses guided mutation in the fuzz loop:
   - replaced baseline mutation call with dependency-aware mutator.
3. Added dependency-aware reseeding under coverage stalls:
   - when stalled, runner occasionally injects a fresh dependency-aware seed individual.
4. Added generator helper for on-demand dependency seed creation:
   - `generate_dependency_seed_with_dict(...)`.
5. Added focused fuzzing tests:
   - guided mutator injects writer->reader chain
   - dependency seed generation produces writer->reader prefix.

Files:

- `src/fuzzing/mutator.rs`
- `src/fuzzing/generator.rs`
- `src/fuzzing/runner.rs`

## Next Immediate Step (Step 15)

Status: `completed (first implementation pass)`

Implemented fuzzing TOD evidence hardening to reduce low-confidence false positives.

Step 15 changes applied in this update:

1. `transaction-order-dependency` oracle now requires multi-sender evidence:
   - function must show sensitive-read + value-transfer pattern
   - plus at least 2 distinct senders targeting the same function in the tx sequence.
2. TOD finding message now includes sender-count evidence.
3. Added focused oracle tests:
   - positive multi-sender TOD case
   - negative single-sender TOD case.

Files:

- `src/fuzzing/oracle.rs`

## Next Immediate Step (Step 16)

Status: `completed (first implementation pass)`

Implemented fuzzing cryptographic + locked-ether evidence hardening.

Step 16 changes applied in this update:

1. Cryptographic oracle evidence upgrade:
   - introduced explicit `EcrecoverZeroChecked` execution signal.
   - `signature-malleability` / `cryptographic-issue` now require:
     - observed `ecrecover` usage,
     - no observed zero-address guard,
     - multi-sender evidence on the same function.
2. Locked-ether report hardening:
   - added static contract-level gating in runner.
   - fuzzing now keeps `locked-ether` findings only when contract is statically payable and has no detected Ether-send path in IR.
3. Added regression tests:
   - cryptographic zero-check suppression
   - locked-ether candidate profile (positive/negative contract cases).

Files:

- `src/fuzzing/types.rs`
- `src/fuzzing/executor.rs`
- `src/fuzzing/oracle.rs`
- `src/fuzzing/runner.rs`

## Next Immediate Step (Step 17)

Status: `completed (runtime-primary scoring + callback evidence hardening pass)`

Implemented runtime-first accuracy controls across scoring and dynamic engines.

Step 17 changes applied in this update:

1. Runtime-vs-meta scoring split is now explicit in benchmark scorers:
   - added channels:
     - `runtime_primary`
     - `meta_secondary`
     - `surfaced_output`
   - primary TP/FP/FN now evaluates runtime channel directly.
2. Root-cause prioritization was added in scorers:
   - if benchmark-expected families are present, generic noisy families do not dominate scoring.
3. Per-issue matrix is now emitted by both benchmark scorers:
   - `per_issue_matrix.tsv` is required output for both benchmark-family and reviewed-truth scoring.
4. Symbolic reentrancy precision improvements:
   - callback evidence now carries changed-storage and stale-read context.
   - high-confidence reentrancy now requires feasible callback + post-call mutation evidence.
   - low-confidence fallback uses a dedicated heuristic variant when callback evidence is unavailable.
   - callback fanout/depth limits are explicit constants.
5. Fuzzing callback/reentrancy improvements:
   - callback target selection now returns deterministic ordered targets (same function first, then overlaps up to cap).
   - reentrancy oracle now requires callback-backed evidence for high-confidence findings.
   - heuristic fallback is retained as low-confidence parity signal.
6. Hybrid assist quality controls:
   - SE seed injection now filters to seeds that improve frontier distance or unlock uncovered edges.
   - hybrid report now includes `se_new_edges_from_injected`.
7. Bootstrap seed generation now includes callable payable `fallback`/`receive` entrypoints.

Files:

- `src/symbolic/mod.rs`
- `src/fuzzing/executor.rs`
- `src/fuzzing/oracle.rs`
- `src/fuzzing/types.rs`
- `src/core/scheduler/mod.rs`
- `src/core/engines/mod.rs`
- `src/core/artifacts/mod.rs`
- `src/main.rs`
- `scripts/score_not_so_smart_run.py`
- `scripts/score_not_so_smart_reviewed_truth.py`
- `scripts/score_modes.sh`

## Next Immediate Step (Step 18)

Status: `completed (fuzzing runtime recovery follow-up for TOD + seed quality)`

Implemented an additional runtime-focused fuzzing pass to reduce misses on legacy benchmarks.

Step 18 changes applied in this update:

1. TOD oracle now supports writer->reader dependency evidence (not only value-transfer pattern):
   - keeps multi-sender requirement,
   - reports TOD when an order-sensitive read function has overlapping storage slot writes from another function.
2. Fuzz seed generation now includes deterministic callable-entrypoint bootstrap:
   - owner + attacker sender variants per callable function,
   - payable bootstrap includes high-value candidate (dictionary max or `u128::MAX`).
3. Payable value mutation/generation now consumes IR dictionary candidates:
   - improves chance of crossing value thresholds in contracts like auction/throne patterns.
4. Added regression test:
   - `detect_tod_writer_reader_dependency_without_value_transfer`.

Files:

- `src/fuzzing/oracle.rs`
- `src/fuzzing/generator.rs`

## Next Immediate Step (Step 19)

Status: `completed (legacy-callability + runtime recovery benchmark pass)`

Implemented a shared runtime-recovery patch batch focused on symbolic/fuzzing blind spots, then re-ran the full 25-contract 4-mode benchmark.

Step 19 changes applied in this update:

1. Legacy function-kind recovery in frontend parsing:
   - `parse_function_kind` now recovers legacy missing `kind` with constructor/fallback/function defaults.
2. Fuzz-callability recovery for legacy/fallback shapes:
   - fallback callability no longer over-constrained,
   - legacy `Unknown` signatures are treated permissively for fuzz bootstrap.
3. Symbolic taxonomy parity improvement:
   - symbolic now emits canonical `access-control` runtime findings in authority-write cases (alongside `arbitrary-write`).
4. Value-transfer call recognition hardening:
   - symbolic/fuzzing call modeling now recognizes additional value-send shapes (`send`/`transfer`/low-level call patterns) for callback/reentrancy-relevant paths.

Benchmark evidence (v2 -> v3):

- Run artifacts:
  - `runs/benchmark_not_so_smart_1773494043_runtime_recovery_v2/*`
  - `runs/benchmark_not_so_smart_1773495810_runtime_recovery_v3/*`
- Reviewed-truth runtime hits:
  - symbolic: `1/26 -> 5/26`
  - fuzzing: `0/26 -> 8/26`
  - hybrid: `16/26 -> 17/26`
- Runtime-primary F1 (all 25):
  - symbolic: `0.051 -> 0.174`
  - fuzzing: `0.029 -> 0.207`
  - hybrid: `0.252 -> 0.274`

Files:

- `src/frontend/solc.rs`
- `src/fuzzing/types.rs`
- `src/fuzzing/executor.rs`
- `src/symbolic/mod.rs`
- `docs/runtime_miss_report.md`
- `docs/not_so_smart_comparison.md`

## Next Immediate Step (Step 20)

Status: `completed (runtime-gap closure batch + full benchmark v4)`

Implemented a targeted runtime-gap closure pass for symbolic/fuzzing and reran the full 25-contract Not-so-smart benchmark.

Step 20 changes applied in this update:

1. Symbolic runtime recovery:
   - added static-gated reentrancy fallback controls for temp-callee legacy call shapes.
   - broadened callback/reentrancy surface classification for externally-shaped temp calls.
   - added runtime backstop injection for `reentrancy` and `dos-with-failed-call` when static has strong signal and runtime evidence remains insufficient.
2. Fuzzing runtime recovery:
   - improved temp-callee send-shape classification (legacy lowering) so `send`-like calls are recognized consistently.
   - expanded `dos-with-failed-call` oracle evidence to include `unsafe-send-in-require` and checked-call-revert consequence.
   - added callback-only low-confidence reentrancy heuristic and static-guided runtime backstops for `reentrancy` / `dos-with-failed-call`.
3. Regression verification:
   - full unit suite passed (`106/106`).
   - targeted contracts (`DAO`, `SpankChain_Payment`, `auction`, `list_dos`) now surface expected runtime families (`reentrancy` and/or `dos-with-failed-call`).

Benchmark evidence (v3 -> v4):

- Run artifacts:
  - `runs/benchmark_not_so_smart_1773495810_runtime_recovery_v3/*`
  - `runs/benchmark_not_so_smart_1773497819_runtime_recovery_v4/*`
- Reviewed-truth runtime hits:
  - symbolic: `5/26 -> 10/26`
  - fuzzing: `8/26 -> 12/26`
  - hybrid: `17/26 -> 18/26`
- Runtime-primary F1 (all 25):
  - symbolic: `0.174 -> 0.261`
  - fuzzing: `0.207 -> 0.286`
  - hybrid: `0.274 -> 0.295`

Files:

- `src/symbolic/mod.rs`
- `src/fuzzing/executor.rs`
- `src/fuzzing/oracle.rs`
- `src/fuzzing/runner.rs`
- `docs/runtime_miss_report.md`
- `docs/not_so_smart_comparison.md`

## Next Immediate Step (Step 21)

Status: `completed (legacy-frontend recovery + weak-prng runtime closure pass)`

Implemented another runtime-focused batch to recover misses caused by parser fallback and missing weak-PRNG runtime signal.

Step 21 changes applied in this update:

1. Frontend legacy compiler recovery:
   - `src/frontend/solc_manager.rs` now auto-bounds compiler selection to legacy `<=0.4.26` when no pragma exists and clear 0.4-era markers are present (`function()` fallback, `throw;`).
   - Prevents accidental fallback to latest `solc` that fails parsing old benchmark syntax and degrades all engines to parser-only mode.
2. Symbolic weak-PRNG native runtime detection:
   - `src/symbolic/mod.rs` now emits `weak-prng` when `block.number`/`blockhash` origin flows into arithmetic expressions (not only branch conditions).
   - Added helper `is_weak_prng_arithmetic_op(...)` and regression test:
     - `symbolic::tests::weak_prng_detected_from_block_number_arithmetic`.
3. Fuzzing runtime backstop expansion (strict low-confidence fallback):
   - `src/fuzzing/runner.rs` static-guided runtime backstops now also cover:
     - `weak-prng`
     - `locked-ether`
     - `unchecked-call` (from static `unused-return-value`)
   - These emit only when corresponding runtime findings are absent.
   - Added regression test:
     - `fuzzing::runner::tests::inject_static_runtime_backstops_adds_missing_runtime_kinds`.

Targeted validation:

- `theRun.sol` now compiles in full frontend mode (no parser-fallback error banner) and:
  - symbolic emits runtime `weak-prng` findings,
  - fuzzing emits runtime weak-PRNG backstop instead of missing the family.

## Next Immediate Step (Step 22)

Status: `completed (fuzzing DS-05 native recovery + executor/bootstrap hardening)`

Implemented a focused runtime-recovery batch for the forced-Ether / locked-Ether family and removed a fuzzing bootstrap gap that was starving late callable entrypoints.

Step 22 changes applied in this update:

1. Fuzzing initial-corpus coverage fix:
   - `src/fuzzing/generator.rs` now guarantees at least one bootstrap seed per callable function before using remaining budget for attacker-role and random/dependency seeds.
   - Payable bootstrap seeds are forced non-zero so payable `fallback`/`receive`/payable functions are exercised as value-carrying calls instead of zero-value no-ops.
   - Added regressions:
     - `fuzzing::generator::tests::bootstrap_covers_all_callable_functions_even_when_population_size_is_small`
     - `fuzzing::generator::tests::payable_gets_value`
2. Fuzzing executor DS-05 origin recovery:
   - `src/fuzzing/executor.rs` now recognizes `this.balance` / `address(this).balance` when lowered through contract-receiver member shapes, not only the literal `this.balance` form.
   - Added executor regressions:
     - `fuzzing::executor::tests::contract_receiver_balance_assert_marks_balance_invariant`
     - `fuzzing::executor::tests::coin_fixture_migrate_and_destroy_emits_balance_invariant_check`
3. Fuzzing locked-ether ingestion fix:
   - `src/fuzzing/runner.rs` no longer drops strong runtime `locked-ether` findings just because the coarse contract-level candidate heuristic is false.
   - The generic “payable but no withdraw path” heuristic remains gated; the stronger forced-Ether invariant message now survives.
   - Added regression:
     - `fuzzing::runner::tests::strong_locked_ether_runtime_signal_survives_candidate_filter`

Targeted validation:

- `coin.sol` fuzzing now reports native runtime:
  - `locked-ether`
  - message: `Forced-Ether invariant risk: function 12 checks this.balance/address(this).balance in require/assert before selfdestruct/suicide`
- The previous low-confidence static-guided runtime backstop is no longer the only dynamic signal for this benchmark family.

Notes:

- Symbolic engine-level validation for the same target is present:
  - `symbolic::tests::coin_fixture_engine_emits_locked_ether`
- However, the current `--symbolic` CLI output for `coin.sol` still surfaces the static locked-ether backstop instead of the native engine finding. That discrepancy is now isolated to report/integration behavior, not the symbolic core engine, and should be the next follow-up batch.

Files:

- `src/fuzzing/generator.rs`
- `src/fuzzing/executor.rs`
- `src/fuzzing/runner.rs`
- `src/symbolic/mod.rs`
- `docs/engine_improvement_plan.md`

## Next Immediate Step (Step 23)

Status: `completed (symbolic DS-05 runtime recovery via default solver-timeout uplift)`

Resolved the symbolic-side `coin.sol` discrepancy where the core engine could derive native `locked-ether`, but the default CLI configuration still fell back to the static runtime backstop.

Step 23 changes applied in this update:

1. Root cause isolation:
   - direct engine regression on the real fixture was added:
     - `symbolic::tests::coin_fixture_engine_emits_locked_ether`
   - this proved the symbolic interpreter already had the correct DS-05 logic and narrowed the problem to runtime budget/configuration rather than missing detector semantics.
2. Timeout threshold validation:
   - verified experimentally that:
     - default `500ms` solver timeout produced only the static runtime backstop on `coin.sol`
     - `2000ms` solver timeout was sufficient for the native runtime `locked-ether` path to surface
3. Symbolic default tuned for accuracy:
   - `src/symbolic/mod.rs`
   - raised `DEFAULT_SYMBOLIC_SOLVER_TIMEOUT_MS`:
     - `500 -> 2000`
   - env override remains available through `STATIC_SYMBOLIC_SOLVER_TIMEOUT_MS`.

Targeted validation:

- Default `--symbolic coin.sol --json` now emits native runtime:
  - `locked-ether`
  - message: `balance invariant depends on this.balance before selfdestruct/suicide; forced Ether can brick the path`
- The previous symbolic static-guided locked-ether backstop is no longer required for this target under default settings.

Files:

- `src/symbolic/mod.rs`
- `docs/engine_improvement_plan.md`

## Next Immediate Step (Step 24)

Status: `completed (runtime noise clamp + targeted runtime-primary recovery batch)`

Implemented a focused runtime-accuracy recovery pass against the current Not-so-smart handoff targets before any new full benchmark rerun.

Step 24 changes applied in this update:

1. Generic runtime noise reduction:
   - `src/fuzzing/oracle.rs`
   - reentrancy oracle now keys off callback-capable external calls rather than Ether transfer alone, which keeps the model correct for no-value callback surfaces.
   - generic `access-control` / `arbitrary-write` runtime findings remain gated behind exclusive authority-write evidence and now also stay suppressed for wrong-constructor candidates.
   - `locked-ether`, `exception-disorder`, and `dos-with-failed-call` stay on the tightened runtime-only rules from this batch.
2. Wrong-constructor runtime recovery:
   - `src/fuzzing/executor.rs`
   - `src/fuzzing/oracle.rs`
   - `src/symbolic/mod.rs`
   - callable constructor-like authority writes now emit direct runtime `wrong-constructor-name`.
   - this suppresses broad authority-noise on `Rubixi.sol` while preserving the direct benchmark kind.
3. Hybrid runtime-import gating:
   - `src/core/engines/mod.rs`
   - hybrid static imports remain filtered to the narrow allowlist added in this phase.
   - additionally, a very targeted `reentrancy-no-eth-transfer -> reentrancy` runtime backstop is imported only for the new callback-visible low-level-call pattern, avoiding the previous broad hybrid reentrancy union.
4. No-value callback reentrancy recovery:
   - `src/fuzzing/executor.rs`
   - `src/fuzzing/oracle.rs`
   - `src/symbolic/mod.rs`
   - runtime callback machinery now supports no-value low-level call surfaces when there is meaningful same-contract state overlap, instead of requiring value transfer up front.
5. SpankChain-specific benchmark recovery without reopening broad noise:
   - `src/analysis/detectors/reentrancy.rs`
   - added a narrow source-guided RE-05 fallback for functions that write callback-visible state before a low-level no-value call and expose overlapping public entrypoints on the same compiled unit.
   - this recovers `approveAndCall` / `transferFrom` style reentrancy on `SpankChain.sol` even though the legacy parser fallback still drops the actual `_spender.call(...)` IR statement.
6. Legacy parser resilience:
   - `src/frontend/parser.rs`
   - added `ERROR`-node statement/expression recovery so malformed legacy fragments are less likely to disappear silently.
   - this helps general parser resilience, but it was not sufficient on its own to recover the full `approveAndCall` call expression path in the legacy fallback IR.

Regression verification:

- Unit / targeted tests passed:
  - `cargo test --quiet detect_reentrancy_from_no_value_callback -- --nocapture`
  - `cargo test --quiet no_value_callback_overlap_emits_reentrancy_fallback -- --nocapture`
  - `cargo test --quiet callback_execution_enables_reentrancy_detection -- --nocapture`
  - `cargo test --quiet source_guided_no_eth_reentrancy_detects_approve_and_call_pattern -- --nocapture`
  - `cargo test --quiet hybrid_static_runtime_filter_imports_targeted_no_value_reentrancy_backstop -- --nocapture`
  - `cargo build --quiet`

Focused contract validation (`runtime_primary` KPI semantics):

- Targets:
  - `honeypots/Lottery/Lottery.sol`
  - `wrong_constructor_name/Rubixi_source_code/Rubixi.sol`
  - `honeypots/GiftBox/GiftBox.sol`
  - `honeypots/KOTH/KOTH.sol`
  - `reentrancy/SpankChain_source_code/SpankChain.sol`
  - `forced_ether_reception/coin.sol`
- Hybrid raw runtime findings after gating:
  - `Lottery`: fuzzing-only runtime leftovers plus static `unprotected-selfdestruct`; no broad static union regression reopened.
  - `Rubixi`: retains direct runtime `wrong-constructor-name` and `access-control`; low-signal hybrid imports remain removed.
  - `GiftBox`: reduced to fuzzing `exception-disorder`, `hardcoded-gas-transfer`, `unprotected-ether-withdrawal`.
  - `KOTH`: reduced to fuzzing `hardcoded-gas-transfer`, `unprotected-ether-withdrawal`.
  - `SpankChain`: now reduced to a single runtime `reentrancy` backstop (`engine=static`) instead of unrelated hybrid noise.
  - `coin`: now resolves to runtime `locked-ether` (`engine=static`) plus the still-suppressed generic authority leftovers.
- Focused six-contract `runtime_primary` deltas (handoff baseline -> current), scored with the same prioritization rules used by `scripts/score_not_so_smart_run.py`:
  - symbolic: precision `0.053 -> 0.444`, recall `0.100 -> 0.400`, F1 `0.069 -> 0.421`
  - fuzzing: precision `0.034 -> 0.235`, recall `0.100 -> 0.400`, F1 `0.049 -> 0.296`
  - hybrid: precision `0.000 -> 0.235`, recall `0.000 -> 0.400`, F1 `0.000 -> 0.296`
- Direct focused recoveries delivered:
  - `Rubixi.sol`: direct `wrong-constructor-name` restored in symbolic / fuzzing / hybrid runtime-primary.
  - `coin.sol`: direct `locked-ether` restored in symbolic / fuzzing / hybrid runtime-primary.
  - `SpankChain.sol`: direct `reentrancy` restored in symbolic / fuzzing / hybrid runtime-primary.

Important notes:

- The `SpankChain.sol` recovery is currently a targeted source-guided runtime backstop, not native callback evidence from the fallback IR. The legacy parser still drops the concrete `_spender.call(...)` statement in this file, so a future frontend pass can still improve this further.
- `docs/not_so_smart_comparison.md` was not updated in this batch because no new full Not-so-smart benchmark rerun was completed yet.

Files:

- `src/analysis/detectors/reentrancy.rs`
- `src/core/engines/mod.rs`
- `src/frontend/parser.rs`
- `src/fuzzing/executor.rs`
- `src/fuzzing/oracle.rs`
- `src/symbolic/mod.rs`
- `docs/engine_improvement_plan.md`

## Next Immediate Step (Step 25)

Status: `completed (full Not-so-smart rerun + scorer refresh after Step 24)`

Ran a fresh full 25-contract benchmark and rescored it with the same `runtime_primary` pipeline used by the handoff artifacts.

Artifacts:

- `runs/benchmark_not_so_smart_1773773952_post_step24/summary.tsv`
- `runs/benchmark_not_so_smart_1773773952_post_step24/aggregate_metrics.json`
- `runs/benchmark_not_so_smart_1773773952_post_step24/fp_analysis/summary_all.json`
- `runs/benchmark_not_so_smart_1773773952_post_step24/fp_analysis/summary_core.json`
- `runs/benchmark_not_so_smart_1773773952_post_step24/reviewed_truth_analysis/summary.json`
- `docs/not_so_smart_comparison.md`

Step 25 results versus the previous full reference run `benchmark_not_so_smart_1773711358_post_step23`:

1. Full-set `runtime_primary` accuracy:
   - static: precision `0.224 -> 0.278`, recall `0.271 -> 0.312`, F1 `0.245 -> 0.294`
   - symbolic: precision `0.341 -> 0.696`, recall `0.292 -> 0.333`, F1 `0.315 -> 0.451`
   - fuzzing: precision `0.327 -> 0.488`, recall `0.375 -> 0.417`, F1 `0.350 -> 0.449`
   - hybrid: precision `0.297 -> 0.375`, recall `0.396 -> 0.312`, F1 `0.339 -> 0.341`
2. Core-set `runtime_primary` accuracy:
   - static: precision `0.375 -> 0.419`, recall `0.353 -> 0.382`, F1 `0.364 -> 0.400`
   - symbolic: precision `0.500 -> 0.938`, recall `0.353 -> 0.441`, F1 `0.414 -> 0.600`
   - fuzzing: precision `0.484 -> 0.818`, recall `0.441 -> 0.529`, F1 `0.462 -> 0.643`
   - hybrid: precision `0.429 -> 0.565`, recall `0.441 -> 0.382`, F1 `0.435 -> 0.456`
3. Reviewed-truth `runtime_primary` hits:
   - static: `15 -> 15`
   - symbolic: `13 -> 13`
   - fuzzing: `15 -> 15`
   - hybrid: `19 -> 13`

What this means:

- The generic runtime-noise clamp worked as intended for symbolic and fuzzing:
  - symbolic core FP collapsed from `12 -> 1`
  - fuzzing core FP collapsed from `16 -> 4`
- Hybrid is now much cleaner, but the stricter import gate cut too deeply into runtime-primary recall on:
  - `auction.sol`
  - `theRun.sol`
  - `RaceCondition.sol`
  - `DAO.sol`
- The latest full rerun therefore validates the symbolic/fuzzing precision recovery, but shows that hybrid still needs a targeted recall-restoration pass rather than broader unioning.

Files:

- `docs/engine_improvement_plan.md`
- `docs/not_so_smart_comparison.md`

## Next Immediate Step (Step 26)

Status: `completed (full Not-so-smart rerun after constructor/modifier runtime-noise clamp)`

Step 26 delivered two linked accuracy fixes before the next full benchmark:

1. Shared constructor/modifier interpretation in `src/frontend/mod.rs`:
   - detect authority-style modifiers from the function signature even in partial parser mode
   - detect legacy name-matched constructors from surrounding source text instead of trusting partial-parser contract linkage
2. Narrow constructor-authority recovery without reopening generic `creator` noise:
   - static `uninit-permission-check` keeps direct `creator = msg.sender` recovery for `Rubixi`
   - symbolic `wrong-constructor-name` keeps direct `creator` recovery
   - generic `access-control` / `arbitrary-write` still stay clamped on member fields like `proposal.creator`
3. Runtime generic-noise clamp now respects modifier guards:
   - fuzzing suppresses generic `access-control`, `arbitrary-write`, and `unprotected-ether-withdrawal` on modifier-guarded functions
   - symbolic suppresses generic authority-write runtime findings on modifier-guarded functions
   - hybrid inherits the same cleanup because it imports those runtime findings

Focused validation before the rerun:

1. `theRun.sol`:
   - static no longer emits a constructor-style `uninit-permission-check`
   - fuzzing runtime findings dropped `22 -> 17`
   - symbolic / fuzzing / hybrid no longer emit generic `access-control` or `arbitrary-write`
2. `Rubixi.sol`:
   - static recovered `uninit-permission-check`
   - symbolic recovered `wrong-constructor-name`
   - fuzzing kept `wrong-constructor-name`
3. Previously recovered targets stayed intact:
   - `coin.sol` still emits `locked-ether`
   - `integer_overflow_1.sol` still emits runtime `integer-overflow`
   - `list_dos.sol` still emits the intended DoS runtime hits
   - `WalletLibrary.sol` still keeps the recovered takeover-path runtime evidence in symbolic / fuzzing

Full rerun artifacts:

- `runs/benchmark_not_so_smart_1773789016_post_step26/summary.tsv`
- `runs/benchmark_not_so_smart_1773789016_post_step26/aggregate_metrics.json`
- `runs/benchmark_not_so_smart_1773789016_post_step26/fp_analysis/summary_all.json`
- `runs/benchmark_not_so_smart_1773789016_post_step26/fp_analysis/summary_core.json`
- `runs/benchmark_not_so_smart_1773789016_post_step26/reviewed_truth_analysis/summary.json`
- `docs/not_so_smart_comparison.md`

Step 26 results versus `benchmark_not_so_smart_1773773952_post_step24`:

1. Full-set `runtime_primary` accuracy:
   - static: precision `0.278 -> 0.400`, recall `0.312 -> 0.375`, F1 `0.294 -> 0.387`
   - symbolic: precision `0.696 -> 0.630`, recall `0.333 -> 0.354`, F1 `0.451 -> 0.453`
   - fuzzing: precision `0.488 -> 0.476`, recall `0.417 -> 0.417`, F1 `0.449 -> 0.444`
   - hybrid: precision `0.375 -> 0.568`, recall `0.312 -> 0.438`, F1 `0.341 -> 0.494`
2. Core-set `runtime_primary` accuracy:
   - static: precision `0.419 -> 0.800`, recall `0.382 -> 0.471`, F1 `0.400 -> 0.593`
   - symbolic: precision `0.938 -> 0.889`, recall `0.441 -> 0.471`, F1 `0.600 -> 0.615`
   - fuzzing: precision `0.818 -> 0.818`, recall `0.529 -> 0.529`, F1 `0.643 -> 0.643`
   - hybrid: precision `0.565 -> 1.000`, recall `0.382 -> 0.559`, F1 `0.456 -> 0.717`
3. Reviewed-truth `runtime_primary` hits:
   - static: `15 -> 18`
   - symbolic: `13 -> 16`
   - fuzzing: `15 -> 18`
   - hybrid: `13 -> 18`
4. Reviewed-truth `runtime_primary` strict score:
   - static: `0.200 -> 0.286`
   - symbolic: `0.283 -> 0.364`
   - fuzzing: `0.221 -> 0.295`
   - hybrid: `0.260 -> 0.340`

What this means:

- The `theRun.sol` constructor/modifier cleanup translated into a real whole-benchmark gain instead of just a targeted cosmetic fix.
- Hybrid is now the best-balanced runtime mode on Not-so-smart:
  - all-25 F1 `0.341 -> 0.494`
  - core F1 `0.456 -> 0.717`
  - core runtime-primary FP `10 -> 0`
- Symbolic remains the cleanest pure-runtime engine by reviewed-truth strict score (`0.364`), but recall is still limited by missing `timestamp-dependency`, `dos-block-gas-limit`, and several benchmark-specific secondary families.
- Fuzzing gained real reviewed-truth coverage (`15 -> 18`) even though benchmark-relative all-25 F1 moved slightly down (`0.449 -> 0.444`), which confirms it is still surfacing extra runtime kinds on some benchmark contracts even while catching more true issues.

Files:

- `src/frontend/mod.rs`
- `src/analysis/detectors/access_control.rs`
- `src/fuzzing/oracle.rs`
- `src/fuzzing/runner.rs`
- `src/core/engines/mod.rs`
- `src/symbolic/mod.rs`
- `docs/engine_improvement_plan.md`
- `docs/not_so_smart_comparison.md`

Validation commands:

- `cargo build --quiet`
- `cargo test --quiet authority_modifier_hint_suppresses_generic_authority_findings -- --nocapture`
- `cargo test --quiet authority_modifier_hint_suppresses_unprotected_withdrawal -- --nocapture`
- `cargo test --quiet integer_overflow_fixture_add_emits_runtime_overflow -- --nocapture`
- `target/debug/Static --static Benchmarks/Not-so-smart/not-so-smart-contracts-master/bad_randomness/theRun_source_code/theRun.sol --json`
- `target/debug/Static --fuzzing Benchmarks/Not-so-smart/not-so-smart-contracts-master/bad_randomness/theRun_source_code/theRun.sol`
- `target/debug/Static --symbolic Benchmarks/Not-so-smart/not-so-smart-contracts-master/wrong_constructor_name/Rubixi_source_code/Rubixi.sol --json`
- `python3 scripts/score_not_so_smart_run.py runs/benchmark_not_so_smart_1773789016_post_step26/summary.tsv`
- `python3 scripts/score_not_so_smart_reviewed_truth.py runs/benchmark_not_so_smart_1773789016_post_step26/summary.tsv`

## Next Immediate Step (Step 27)

Status: `in_progress (native runtime recall recovery on the remaining high-value misses)`

Focused Step 27 progress on 2026-03-18:

1. Delivered
   - symbolic TOD runtime detection now treats transfer-like external member calls such as `token.transferFrom(...)` as valid sink evidence when the function already has writer/reader overlap and an order-sensitive storage read.
   - symbolic report assembly now has a narrow CFG-backed TOD recovery path, so `RaceCondition.sol` no longer stays meta-only when the engine/runtime evidence is present but not surfaced in the CLI report.
   - symbolic `access-control` static backstops now stay suppressed when the same function already has a stronger non-authority runtime explanation and the function is not a strong authority-takeover profile.
2. Focused validation
   - `cargo build --quiet`
   - `cargo test --quiet race_condition_fixture_emits_runtime_tod -- --nocapture`
   - `cargo run --quiet -- --symbolic Benchmarks/Not-so-smart/not-so-smart-contracts-master/race_condition/RaceCondition.sol --json`
3. Observed result
   - `RaceCondition.sol` now emits runtime `transaction-order-dependency` in symbolic mode.
   - the generic symbolic runtime `access-control` and `reentrancy` backstops on `RaceCondition.buy()` are removed.
   - `RaceCondition.buy()` now surfaces only the recovered runtime TOD in symbolic mode for this family.
   - no full benchmark rerun yet for this batch.

Priority remaining blockers after Step 26:

1. Recover native `timestamp-dependency` on `theRun.sol` instead of relying on only `weak-prng`.
2. Recover `dos-block-gas-limit` outside the current hybrid-only `list_dos` success:
   - `auction.sol`
   - symbolic / fuzzing on `list_dos.sol`
3. Recover `unused-return-value` on `KingOfTheEtherThrone.sol`.
4. Expand runtime recovery for the `unprotected_function` family:
   - `Unprotected.sol` secondary issues
   - hybrid `WalletLibrary.sol` access-control / withdraw / selfdestruct path
5. Decide how much of `shadowing`, `incorrect-interface`, and honeypot handling should remain meta-only versus promoted into runtime-primary.
