# Hybrid Approach Evolution

Date: 2026-03-25

This document explains how the hybrid approach changed from `refs/heads/main` to the current branch, what changed in the flow, what problems we faced, and how we fixed them.

## What The Main Branch Did

It did not have a real hybrid implementation.

In `refs/heads/main`, the CLI branch for `--hybrid` returned a placeholder error:

> `hybrid mode placeholder: not implemented yet (planned static + symbolic + fuzzing pipeline)`

So on `main`, hybrid was still an intention, not a running architecture.

## What The Current Branch Does

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

## Main Branch vs Current Branch

| Area | `refs/heads/main` | Current branch | Why it changed |
| --- | --- | --- | --- |
| Hybrid mode | placeholder only | real P1 orchestrator | the project needed more than three isolated engines |
| Runtime control loop | none | fuzz epochs + stall/frontier logic + symbolic assists | a naive union would not give better practical analysis |
| Shared artifacts | none | run directory with target, hints, epochs, assists, findings, report | reproducibility and presentation quality mattered |
| Cross-engine dedup | none | `FindingTriage` | hybrid needed to collapse duplicates and keep best evidence |
| Seed orchestration | none | bootstrap seeds + seed queues + assist injection | hybrid needed a real stateful exploration loop |
| Guidance model | none | `StaticHints` with hotspots, sinks, storage RW, arg domains, roles | hybrid needed static to act as a planner, not just a detector |

## Problems We Faced And How We Fixed Them

### Problem A: a naive union of engines would inflate output without solving the real problem

Just merging static + symbolic + fuzzing outputs would produce:

- duplicates
- inconsistent evidence quality
- noisy benchmark scoring
- unclear story in the presentation

### Fix

We built a scheduler and triage layer instead of a dumb union:

- `P1Scheduler`
- `FindingTriage`
- surfaced low-noise output

That made hybrid a real analysis workflow rather than a batch concatenation of tools.

### Problem B: fuzzing stalls on hard branches, but full symbolic is too expensive as the default

This is the central hybrid design problem.

### Fix

We made fuzzing the main engine and symbolic the assist engine.

The scheduler tracks:

- stagnant epochs
- edge-rate windows
- frontier goals
- unmet priority sinks

Only then does it ask symbolic execution to solve a targeted goal and inject useful seeds back into the fuzz loop.

That keeps symbolic power available without paying symbolic cost everywhere.

### Problem C: fuzzing needed better starting points than blind randomness

### Fix

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

### Problem D: hybrid needed reproducible, inspectable run artifacts

For evaluation and presentation, "the hybrid found X" is not enough. We needed to show:

- what the scheduler did
- what coverage changed
- what assists were requested
- what seeds were injected
- what findings survived dedup

### Fix

We added:

- artifact models in `src/core/artifacts/mod.rs`
- persistence in `src/core/store/mod.rs`
- structured run directories under `runs/`

That is what makes the hybrid results auditable and presentation-friendly.

### Problem E: hybrid precision was being hurt by extra families

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

## What Changed In Hybrid Flow

There was no old hybrid flow to tune. The current branch created it.

The main design decision is:

- static is the planner
- fuzzing is the main explorer
- symbolic is the selective solver/assist
- triage is the shared dedup/filter stage

That architecture is the core contribution of the current branch.

## Why The Hybrid Improvements Matter

Hybrid is where all earlier engine improvements start compounding:

- better frontend compatibility improves all engines
- better static hints improve fuzzing and hybrid bootstrap
- better fuzzing semantics improve hybrid runtime precision
- better symbolic state makes assists more useful
- surfaced output makes final results consistent

That is why hybrid became the strongest approach in the benchmark comparison.
