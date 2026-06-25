# Symbolic Execution Approach Evolution

Date: 2026-03-25

This document explains how the symbolic execution approach changed from `refs/heads/main` to the current branch, what changed in the flow, what problems we faced, and how we fixed them.

## What The Main Branch Did

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

## What The Current Branch Does

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

## Main Branch vs Current Branch

| Area | `refs/heads/main` | Current branch | Why it changed |
| --- | --- | --- | --- |
| State model | block/env/storage/path constraints | adds callback frames, value origins, pending calls, sender-checked, loop/order-sensitive state | old state was too weak to support many real bug classes |
| Bug model | `Underflow`, `Reentrancy` only | broad taxonomy-aligned runtime model | the old engine could not contribute meaningfully to full benchmark coverage |
| Output | raw vulnerability list | surfaced runtime findings + surfaced meta findings + raw views | symbolic needed the same normalized contract as the other engines |
| Confidence | none | explicit `VulnerabilityConfidence` mapping | important for UI and cross-engine comparison |
| Hybrid use | standalone only | also used as targeted assist engine | symbolic is powerful but too expensive to run as the main hybrid loop |
| Caching | limited | solver caches for feasibility and overflow/underflow checks | reduces repeated expensive solving |

## Problems We Faced And How We Fixed Them

### Problem A: the engine was too narrow to compete with the other approaches

The old symbolic engine could explore paths, but it only surfaced two bug families. That made it:

- hard to benchmark fairly against the rest of the taxonomy
- hard to justify in a hybrid system
- too limited for a presentation narrative

### Fix

We expanded the symbolic vulnerability model and added richer runtime reasoning. The new `VulnerabilityKind` and confidence mapping in `src/symbolic/mod.rs` turned symbolic from a demo engine into a full analysis engine.

### Problem B: path feasibility alone was not enough

A lot of security questions need more than branch feasibility. We also needed:

- whether an external callback was truly relevant
- whether storage was stale across a callback
- whether a sender check had happened
- whether order-sensitive storage reads happened before later writes

The old engine did not retain enough context for that.

### Fix

We made the state model more semantic:

- callback-aware tracking
- stale-read tracking
- value-origin tracking
- sender-check tracking
- pending low-level call tracking

That is what enabled more meaningful runtime bug classes without switching symbolic into a totally separate architecture.

### Problem C: path explosion made always-on symbolic unattractive

This was both a symbolic problem and a hybrid design problem.

If symbolic is run blindly across everything:

- it is expensive
- it plateaus badly
- it spends too much time where fuzzing would have been cheaper

### Fix

Two complementary changes were made:

1. the standalone symbolic engine gained solver caches and better signal extraction
2. hybrid stopped treating symbolic as the default engine and instead uses it as a targeted assist through:
   - `src/core/engines/mod.rs`
   - `src/core/scheduler/mod.rs`

That separation is one of the most important architectural decisions in the repository.

### Problem D: symbolic output needed the same signal discipline as static/fuzzing

Raw symbolic findings were not enough. We needed:

- comparable JSON
- confidence
- suppression counts
- meta/runtime split

### Fix

The symbolic engine now builds:

- `vulnerabilities_raw`
- `meta_findings_raw`
- surfaced runtime findings
- surfaced meta findings
- suppressed counts

It uses the same surfaced layer as the other approaches, which is exactly what made the UI and benchmark reporting stable.

## What Changed In Symbolic Flow

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

## Why The Symbolic Improvements Matter

These changes gave symbolic two roles instead of one:

- a stronger standalone engine
- a focused high-cost helper inside hybrid

That dual use is much more valuable than the older design, where symbolic existed but did not yet strongly influence the rest of the system.
