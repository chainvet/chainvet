# Hybrid Architecture: Target State (P1 -> P4)

## Scope

This document defines the target hybrid architecture only:

- P1: fuzz-first, SE-on-stall assist
- P4: parallel cooperative hybrid

## P1 Definition (Baseline)

P1 is a coordinator-led loop with bounded symbolic assists:

1. Static pass once -> `StaticHints`.
2. Fuzz in epochs with coverage/frontier outputs.
3. If stalled or high-priority goals remain unmet:
   - choose top frontier goals,
   - run symbolic solve with strict budget,
   - inject resulting seeds back into fuzzing.
4. Dedup/minimize findings centrally.
5. Persist all artifacts under `runs/<run_id>/`.

Required properties:

- Shared artifact schema across engines.
- Engine boundaries via stable interfaces.
- Reproducible run output (`report.json`, corpus, findings, assist history).

## P4 Definition (Parallel Cooperative)

P4 upgrades orchestration to concurrent workers while preserving P1 contracts:

- Multiple fuzz workers consume `SeedQueue`.
- Multiple symbolic workers consume `FrontierQueue`.
- Workers emit seeds/findings/coverage to shared services.
- Coordinator enforces budgets and fairness so SE does not starve fuzzing.

Required properties:

- Process-safe queue backend (replace in-memory queues).
- Shared coverage and findings state across workers.
- Central triage/dedup/minimization service.
- Quota-aware coordinator policy.

## Stable Contracts That Must Not Change

P1 and P4 must share these contracts:

- Artifacts: `ContractTarget`, `StaticHints`, `Seed`, `FrontierGoal`, `CoverageSummary`, `Finding`, `TracePrefix`, `HybridReport`
- Engine APIs:
  - `StaticEngine::analyze`
  - `FuzzEngine::run_epoch`
  - `SymbolicEngine::solve`

Reason: P4 should be an orchestration upgrade, not an engine rewrite.

## P1 -> P4 Upgrade Plan

1. Replace in-memory queues with shared backend.
2. Add worker runtime for fuzz and symbolic pools.
3. Introduce coordinator loop for:
   - quota control,
   - frontier prioritization,
   - assist scheduling,
   - global coverage merging.
4. Keep artifacts and engine interfaces unchanged.

## Acceptance Criteria for P4 Readiness

- Running N fuzz workers + M symbolic workers without API/schema changes.
- Deterministic artifact format remains compatible with P1 consumers.
- Coordinator can cap SE assist rate and preserve fuzz throughput.
- Findings dedup/minimization remains centralized and single-source-of-truth.
