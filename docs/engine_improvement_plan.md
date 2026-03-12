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
