# Hybrid Handoff Plan (P1 -> P4)

This document is the handoff context for the next agent. It is aligned to the project plan:

- **P1**: Static triage -> coverage-guided fuzzing -> SE-on-stall -> seed feedback loop
- **P4**: Parallel cooperative hybrid with shared queues/store/dedup

## 1) Current Status vs Plan

### Progress log (2026-03-10)

Started Phase A with concrete fixes already merged:

- Stall trigger tuned to use `< min_coverage_delta` (instead of `<=`), reducing premature SE assists.
  - `src/core/scheduler/mod.rs`
- Frontier queue now deduplicates equivalent goals by `(function_id, block/edge, sink_kind)`.
  - `src/core/queues/mod.rs`
- Triage signature redesigned to remove tx-length fragmentation and include richer location keys + optional revert hash.
  - `src/core/triage/mod.rs`
- Fuzz finding attribution improved by parsing function id from finding message and attaching function name.
  - `src/core/engines/mod.rs`
- Coverage summary in hybrid now computes edge counts from CFG edge set (using covered-block projection), not raw block counts.
  - `src/core/engines/mod.rs`
- Replaced placeholder SE assist with goal-targeted symbolic solving.
  - `SymbolicAssistAdapter::solve` now performs CFG-guided symbolic exploration, solves path constraints with Z3, and emits solver-derived seeds.
  - Added a unit test for branch-target solving behavior.
  - `src/core/engines/mod.rs`
- Switched coverage accounting to true executed CFG edges from fuzz traces.
  - `ExecutionTrace` now records `edge_coverage` directly in the executor.
  - Hybrid coverage metrics (`covered_edges`, `delta_edges`) now use real edge sets, not block projection.
  - `src/fuzzing/types.rs`, `src/fuzzing/executor.rs`, `src/core/engines/mod.rs`
- Promoted frontier goals to edge-level targets.
  - Frontier generation now emits uncovered `(edge_from, edge_to)` goals with sink/hotspot ranking.
  - `src/core/engines/mod.rs`
- Normalized cross-engine finding labels (Step 1 of improvement plan).
  - Symbolic label update: `underflow` -> `integer-underflow`.
  - Fuzzing canonical aliases in report/hybrid ingestion:
    - `tx-origin-auth` -> `tx-origin`
    - `hardcoded-gas` -> `hardcoded-gas-transfer`
    - `storage-memory-issue` -> `memory-manipulation`
  - Files: `src/symbolic/mod.rs`, `src/fuzzing/types.rs`, `src/fuzzing/runner.rs`, `src/core/engines/mod.rs`
- Added new detection patterns in symbolic/fuzzing to close static gap.
  - Symbolic: `weak-prng`, `hardcoded-gas-transfer`.
  - Symbolic call classification refined so member-based `send`/`transfer` lowered via temps are recognized, and `transfer` is not misreported as `unchecked-call`.
  - Symbolic added: `unsafe-send-in-require`, `unprotected-ether-withdrawal`.
  - Fuzzing default `check_all`: enabled `exception-disorder`, `access-control`, `locked-ether`.
  - Fuzzing added: `unsafe-send-in-require` oracle and AST-level `public-mint-burn`.
  - Next taxonomy batch added in both symbolic/fuzzing:
    - `dos-with-failed-call`
    - `transaction-order-dependency`
    - `signature-malleability`
  - FP reduction: TOD/CR-02 findings are now static-gated in symbolic, fuzzing, and hybrid fuzz adapter.
  - Confidence tiers added to fuzzing and symbolic findings; hybrid now stores fuzz confidence in finding metadata.
  - Coverage matrix document added: `docs/coverage_matrix.md`.
  - Files: `src/symbolic/mod.rs`, `src/fuzzing/oracle.rs`, `src/fuzzing/executor.rs`, `src/fuzzing/types.rs`, `src/fuzzing/runner.rs`, `src/core/engines/mod.rs`, `docs/coverage_matrix.md`
- Symbolic Step 2 (precision/scalability) landed.
  - Added solver cache for repeated feasibility/underflow checks:
    - `sat_by_constraints` and `underflow_by_constraints`.
  - Added underflow dedup at engine level and output-level dedup key `(function_id, kind, pc)` for dynamic symbolic findings.
  - Added focused tests:
    - `symbolic::tests::engine_underflow_is_deduped_on_same_pc`
    - `symbolic::tests::solver_cache_reuses_equivalent_constraint_sets`
  - File: `src/symbolic/mod.rs`
- Symbolic Step 3 (path explosion control) landed.
  - Added bounded path controls:
    - per-path block revisit cap (`MAX_BLOCK_VISITS_PER_PATH`)
    - path-shape revisit cap (`MAX_STATE_SHAPE_REVISITS`)
  - Added sink-directed exploration priority:
    - block sink scoring (`build_sink_scores`)
    - priority scheduler pop (`pop_next_state`)
  - Added focused tests:
    - `symbolic::tests::engine_bounds_unconditional_loop_revisits`
    - `symbolic::tests::sink_priority_scheduler_picks_hotter_state_first`
  - File: `src/symbolic/mod.rs`
- Fuzzing Step 4 (guidance quality) landed.
  - `StaticHints` now includes:
    - `storage_rw_map`
    - `arg_domains`
    - `address_roles`
  - `StaticAdapter::analyze` now fills these fields from IR dependency map + param/domain heuristics + role extraction.
  - `FuzzAdapter::run_epoch` now applies static-guided mutation shaping:
    - function whitelist/hotspot targeting
    - arg-domain injection
    - role-aware sender/value/env mutation
    - weighted parent scheduling by seed energy
  - Added frontier-distance guidance:
    - computes distance-to-uncovered-frontier per function
    - keeps near-miss seeds when distance improves
    - emits `TracePrefix.distance_hint` from real frontier distance
  - `bootstrap_seeds` now consumes new static hints for better initial tx seeds.
  - Added focused tests:
    - `core::engines::tests::param_domain_candidates_include_deadline_hints`
    - `core::engines::tests::frontier_distance_uses_uncovered_edges`
    - `core::engines::tests::static_guidance_rewrites_disallowed_function_ids`
  - Files:
    - `src/core/artifacts/mod.rs`
    - `src/core/engines/mod.rs`
    - `src/core/scheduler/mod.rs`
- Fuzzing Step 5 (oracle breadth + stateful sequencing) landed.
  - Added oracle: `arbitrary-write` with stronger dynamic evidence in `src/fuzzing/oracle.rs`:
    - storage write without sender check
    - same function exercised by multiple distinct senders
  - Promoted fuzz confidence tier for `ArbitraryWrite` to `high` in `src/fuzzing/types.rs`.
  - Added storage RW chain scheduler in hybrid fuzz adapter:
    - guidance model now computes weighted writer->reader chains from `StaticHints.storage_rw_map`
    - mutation shaping enforces chain prefixes during epochs when available
  - Added hybrid fuzz parity hook:
    - epoch-1 AST pattern emission for `public-mint-burn` in `src/core/engines/mod.rs`
  - Added focused tests:
    - `fuzzing::oracle::tests::detect_arbitrary_write_with_multi_sender_evidence`
    - `core::engines::tests::static_guidance_builds_storage_rw_writer_reader_chain`
  - Files:
    - `src/fuzzing/oracle.rs`
    - `src/fuzzing/types.rs`
    - `src/core/engines/mod.rs`
- Hybrid Step 6 (scheduler quality controls) landed.
  - Stall trigger is now windowed over edge-rate history (`update_stall_window`), using epsilon derived from budget.
  - Frontier assist policy now enforces:
    - per-goal attempt budgeting
    - exponential retry backoff for unsolved goals
    - selection that skips goals still in backoff
  - Added focused scheduler tests:
    - `core::scheduler::tests::stall_window_uses_windowed_edge_rate`
    - `core::scheduler::tests::frontier_selector_respects_backoff_and_attempt_budget`
    - `core::scheduler::tests::assist_backoff_scales_with_attempts`
  - File: `src/core/scheduler/mod.rs`
- Hybrid Step 7 (P1 quality hardening) landed.
  - Added deterministic scheduler integration tests for assist-loop outcomes:
    - `core::scheduler::tests::assist_loop_success_injects_and_resets_attempts`
    - `core::scheduler::tests::assist_loop_unsolved_applies_backoff_and_attempt_cap`
  - Added report-quality regression guard helpers:
    - `coverage_curve_stable(...)`
    - `report_quality_guard(...)`
    - test: `core::scheduler::tests::report_quality_guard_rejects_bad_metrics`
  - Added scheduler testability hook:
    - `run_with_output(...)` to run integration tests without live frontend loading.
  - File: `src/core/scheduler/mod.rs`
- Hybrid Step 8 (P4 queue abstraction prep) landed.
  - Added queue trait facade:
    - `SeedQueue`
    - `FrontierQueue`
    - `FindingQueue`
  - Migrated queue usage boundaries in scheduler helpers to trait-backed signatures.
  - Added backend adapter skeletons:
    - `src/core/queues/sqlite.rs`
    - `src/core/queues/redis.rs`
  - Added queue backend contract tests:
    - `core::queues::tests::sqlite_backend_seed_queue_uses_same_contract`
    - `core::queues::tests::redis_backend_frontier_queue_uses_same_contract`
  - Files: `src/core/queues/mod.rs`, `src/core/queues/sqlite.rs`, `src/core/queues/redis.rs`, `src/core/scheduler/mod.rs`
- Taxonomy parity closure for symbolic landed.
  - Added missing symbolic kinds used by hybrid ingestion parity:
    - `arbitrary-write`
    - `public-mint-burn`
    - `locked-ether`
    - `memory-manipulation`
  - Coverage matrix and taxonomy mapping docs updated for symbolic parity status.
  - Files: `src/symbolic/mod.rs`, `docs/coverage_matrix.md`, `docs/taxonomy_engine_mapping.md`
- Engine maturity Step 10 (frontend reliability hardening) landed.
  - `solc` selection now prefers local resolution before network:
    - `SOLC_PATH` -> `solc` in `PATH` -> cached `solc-v*` binary -> download.
  - Cache directory now uses writable fallback chain:
    - env/XDG/HOME/USERPROFILE -> workspace `.cache/static/solc` -> `/tmp/static-solc-cache`.
  - Added `STATIC_SOLC_OFFLINE=1` to force cache-only behavior.
  - Download logging is now quieter and includes concise error detail.
  - File: `src/frontend/solc_manager.rs`
  - Rationale: keep P1 and all three engines in `FrontendMode::Full` more often; fewer false regressions from parser fallback.
- Engine maturity Step 11 (symbolic uint256 precision upgrade) landed.
  - Core symbolic arithmetic/comparison now uses uint256 bitvector semantics:
    - wrap-aware `+/-/*` and unsigned relational comparisons.
  - Division/modulo now use safe zero-divisor handling via `ite(rhs == 0, 0, op)`.
  - Underflow satisfiability check now uses unsigned uint256 ordering (`rhs_bv > lhs_bv`) instead of signed Int ordering.
  - Added regression tests for wrap-around, unsigned comparison, and underflow behavior.
  - File: `src/symbolic/mod.rs`
- Engine maturity Step 12 (symbolic call/control semantics) landed.
  - `require/assert` now:
    - add revert terminal for feasible `!cond` path
    - enforce `cond` on continuation path
    - terminate early when success path is unsat.
  - explicit `revert(...)` call now terminates path immediately.
  - low-level non-static calls and `delegatecall` now havoc tracked storage slots.
  - Added regression tests:
    - `require_call_splits_success_and_revert_paths`
    - `revert_call_terminates_current_path`
    - `havoc_storage_rewrites_existing_slots`
  - File: `src/symbolic/mod.rs`
- Engine maturity Step 13 (symbolic low-level call precision) landed.
  - primary low-level call return is now constrained to boolean domain (`0|1`).
  - unchecked-call pending tracking now keys off primary low-level return destination only.
  - `staticcall` no longer marks mutable external-call context for reentrancy edge patterning.
  - Added regression tests:
    - `boolean_domain_constraint_rejects_non_boolean_value`
    - `low_level_call_return_is_modeled_as_boolean`
    - `staticcall_does_not_mark_reentrancy_edge`
  - File: `src/symbolic/mod.rs`
- Engine maturity Step 14 (fuzzing stateful sequence guidance) landed.
  - Added guided fuzz mutator API:
    - `mutate_individual_guided_with_dict(...)`
    - can inject writer->reader chain prefixes from `DependencyMap`.
  - Fuzzing runner now uses guided mutation in epoch loop.
  - Added stall-time dependency reseeding:
    - occasional fresh dependency-aware seed when coverage plateaus.
  - Added generator helper:
    - `generate_dependency_seed_with_dict(...)`.
  - Added tests:
    - `guided_mutation_can_inject_writer_reader_chain`
    - `dependency_seed_prefers_writer_reader_prefix`
  - Files:
    - `src/fuzzing/mutator.rs`
    - `src/fuzzing/generator.rs`
    - `src/fuzzing/runner.rs`
- Engine maturity Step 15 (fuzzing TOD evidence hardening) landed.
  - `transaction-order-dependency` now requires multi-sender evidence for the same function.
  - TOD finding now includes sender-count evidence in message.
  - Added regression tests:
    - `detect_transaction_order_dependency`
    - `tod_requires_multi_sender_evidence`
  - File: `src/fuzzing/oracle.rs`
- Engine maturity Step 16 (fuzzing crypto + locked-ether evidence hardening) landed.
  - Added new cryptographic evidence signal:
    - `TraceEventKind::EcrecoverZeroChecked`.
  - `signature-malleability` and `cryptographic-issue` now require:
    - observed `ecrecover`,
    - missing zero-address check evidence,
    - multi-sender execution evidence for the same function.
  - Added static locked-ether gating in fuzz runner:
    - keep `locked-ether` only when contract is statically payable and has no IR-detected Ether-send path.
  - Added tests:
    - `cryptographic_zero_check_suppresses_malleability_finding`
    - `locked_ether_candidate_true_for_payable_no_send_path`
    - `locked_ether_candidate_false_when_send_path_exists`
  - Files:
    - `src/fuzzing/types.rs`
    - `src/fuzzing/executor.rs`
    - `src/fuzzing/oracle.rs`
    - `src/fuzzing/runner.rs`
- Engine maturity Step 17 (runtime-primary accuracy control pass) landed.
  - Scoring channel split implemented:
    - `runtime_primary`, `meta_secondary`, `surfaced_output`
    - primary benchmark TP/FP/FN now runtime-first.
  - Per-issue matrix artifacts now emitted by both benchmark scorers.
  - Hybrid SE injection gating improved:
    - accept SE seeds only if they improve frontier distance or unlock uncovered edges.
    - new report metric: `se_new_edges_from_injected`.
  - Symbolic reentrancy evidence tightened:
    - callback changed-storage and stale-read evidence modeled.
    - low-confidence fallback kept as separate heuristic variant.
  - Fuzzing callback/reentrancy improved:
    - deterministic callback target set (same function first, then overlaps up to cap).
    - callback-backed reentrancy elevated; heuristic fallback retained at low confidence.
  - Bootstrap seeds now include payable `fallback`/`receive` entrypoints.
  - Files:
    - `src/symbolic/mod.rs`
    - `src/fuzzing/executor.rs`
    - `src/fuzzing/oracle.rs`
    - `src/fuzzing/types.rs`
    - `src/core/scheduler/mod.rs`
    - `src/core/engines/mod.rs`
    - `src/core/artifacts/mod.rs`
    - `scripts/score_not_so_smart_run.py`
    - `scripts/score_not_so_smart_reviewed_truth.py`
- Engine maturity Step 18 (fuzzing runtime recovery follow-up) landed.
  - TOD oracle now has writer->reader dependency mode (in addition to value-transfer mode):
    - keeps multi-sender requirement,
    - triggers when order-sensitive read slots overlap writer-function slots.
  - Fuzz initial population now bootstraps callable entrypoints deterministically:
    - owner + attacker sender variants,
    - payable high-value seed candidate (dictionary max or `u128::MAX`).
  - Payable transaction value generation now consumes dictionary constants to improve threshold crossing.
  - Added oracle regression test:
    - `detect_tod_writer_reader_dependency_without_value_transfer`
  - Files:
    - `src/fuzzing/oracle.rs`
    - `src/fuzzing/generator.rs`

Focus note:

- P4 transition is intentionally deferred; current priority is P1 + engine maturity.

### P1 requirements

- Static triage produced once: **Implemented**
  - `StaticHints` includes function filters, hotspots, sinks, callgraph summary, taint summary.
- Coverage-guided fuzzing epochs: **Implemented (partial semantics)**
  - Epoch loop exists and coverage is tracked.
  - Coverage now reports true executed CFG edge counts from fuzz traces.
- SE-on-stall assist: **Implemented**
  - Triggering/reinjection loop is wired.
  - SE worker now generates concrete seeds from solver models for targeted frontier goals.
- Seed feedback loop: **Implemented**
  - SE-produced seeds are injected into seed queue.
- Artifact persistence (`runs/<run_id>`): **Implemented**
  - Target, hints, epochs, findings, assists, report, corpus persisted.
- Central dedup/minimization: **Implemented**
  - Signature quality is improved (location-based key, optional revert hash, no tx-length keying).

### P4 readiness requirements

- Stable shared schemas/interfaces: **Implemented**
- Queue abstraction boundaries: **Implemented (trait-backed with in-memory default)**
- Alternate backend adapter skeletons: **Implemented (SQLite/Redis scaffolds)**
- Worker pool orchestration: **Missing**
- Shared process-safe queue backend: **Missing (skeletons are not yet persistent)**
- Dynamic quota coordinator: **Missing**

## 2) Review Findings (Prioritized)

## Medium

1. **Queue abstraction still in-memory only**
   - Trait boundaries are now in place, but backend adapters still delegate to in-memory internals.
   - Impact: no cross-process queue persistence yet.

2. **Cross-engine dedup collapse policy is still basic**
   - Current dedup is stable, but merge policy for equivalent findings across engines should be tightened and documented.
   - Impact: unique finding counts may still drift with future rule growth.

3. **Coordinator quota policy is single-run only**
   - Current scheduler budgets are tuned for one orchestrator loop.
   - Impact: P4 worker pools still need explicit fairness policy wiring.

## 3) Next Work Plan (for next agent)

## Phase A: Step 9 (P4-prep persistence hardening)

1. Implement real SQLite-backed queue operations behind existing queue traits.
2. Add backend parity tests (in-memory vs SQLite) for push/dedup/pop semantics.

## Phase B: P4 orchestration prep

1. Add coordinator-ready budget policy interface for future worker fairness.
2. Add worker-safe claim/ack queue semantics needed by multi-process schedulers.

## 4) Concrete File-Level Task Map

- `src/core/scheduler/mod.rs`
  - Keep queue usage generic and prepare worker-safe queue claim hooks
- `src/core/queues/mod.rs`
  - Add trait-level claim/ack extensions needed for worker pools
- `src/core/queues/sqlite.rs`
  - Replace in-memory delegation with real persisted queue operations
- `src/core/store/mod.rs`
  - Add backend-neutral hooks for queue/state persistence needed by multi-worker orchestration
- `src/core/triage/mod.rs`
  - Tighten and document cross-engine collapse policy
- `src/core/queues/*` tests
  - Add in-memory vs SQLite parity tests and persistence-specific regressions

## 5) Validation Checklist

Run these after each phase:

```bash
RUSTFLAGS="-A dead_code -A unused" cargo check
RUSTFLAGS="-A dead_code -A unused" cargo test core::scheduler::tests:: -- --nocapture
RUSTFLAGS="-A dead_code -A unused" cargo run -- --hybrid fixtures/chatgpttestcases.sol
./scripts/score_modes.sh fixtures/chatgpttestcases.sol fixtures/ground_truth/chatgpttestcases.json
```

And verify in latest `runs/<run_id>/report.json`:

- `se_assists > 0` only when stall conditions are met
- `findings_unique` is stable (not inflated by tx-length variants)
- coverage metric semantics are consistent with field naming
