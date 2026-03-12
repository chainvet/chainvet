# Hybrid Architecture: Current State (Pre-P4)

## Scope

This document only describes the hybrid orchestration architecture and its readiness for:

- P1: fuzz-first with symbolic assist on stall
- P4: parallel cooperative hybrid

## Current Hybrid Control Plane

- Hybrid entrypoint: `--hybrid` in `src/main.rs`
- Scheduler: `src/core/scheduler/mod.rs`
- Current execution model: single-process, coordinator-driven loop

Current loop shape:

1. Load target + frontend output.
2. Run static pass once and persist hints.
3. Bootstrap seed corpus.
4. Run fuzzing in bounded epochs.
5. Detect stall / unmet frontier goals.
6. Trigger symbolic assist for selected goals.
7. Inject SE-produced seeds back into fuzzing inputs.
8. Dedup/minimize findings.
9. Persist run artifacts and final report.

## Hybrid Contracts and Components In Place

- Artifacts schema: `src/core/artifacts/mod.rs`
  - `ContractTarget`, `StaticHints`, `Seed`, `FrontierGoal`, `CoverageSummary`, `Finding`, `TracePrefix`, `HybridReport`
- Engine interfaces + adapters: `src/core/engines/mod.rs`
  - `StaticEngine`, `FuzzEngine`, `SymbolicEngine`
- Artifact persistence: `src/core/store/mod.rs`
  - Run directory model under `runs/<run_id>/...`
- In-memory queues: `src/core/queues/mod.rs`
  - seed, frontier, finding queues
- Budget model: `src/core/budget/mod.rs`
- Triage (dedup/minimization): `src/core/triage/mod.rs`

## P1 Completeness Assessment

Implemented for P1:

- Static-once + hints handoff
- Epoch fuzzing
- Stall-triggered symbolic assist
- Seed reinjection
- Artifact persistence + report generation
- Centralized dedup/minimization

Known limitation:

- Coordination is still single-process and in-memory; this is expected for P1 and is the main blocker for P4-scale concurrency.

## Gaps to P4

Main remaining gaps are orchestration, not schema:

1. Queue backend is in-memory only (no shared process-safe backend).
2. No worker-pool runtime for fuzzing/SE concurrency.
3. No coordinator enforcing dynamic CPU/quota balancing across live workers.
4. No shared multi-worker coverage state service.

The architecture boundaries required to upgrade are already present.
