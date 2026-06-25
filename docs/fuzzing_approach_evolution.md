# Fuzzing Approach Evolution

Date: 2026-03-25

This document explains how the fuzzing approach changed from `refs/heads/main` to the current branch, what changed in the flow, what problems we faced, and how we fixed them.

## What The Main Branch Did

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

## What The Current Branch Does

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

## Main Branch vs Current Branch

| Area | `refs/heads/main` | Current branch | Why it changed |
| --- | --- | --- | --- |
| Input to fuzzing | `NormalizedAst` | `FrontendOutput` | fuzzing needed compiler-aware entrypoint semantics |
| ABI extraction | `extract_abis(ast)` | `extract_abis(ast, &output.compiler)` | legacy contracts were producing wrong callable sets |
| Static pre-pass | IR/CFG/ABI/deps only | adds call graph, taint, static findings, meta findings, FP guards, locked-Ether candidates | fuzzing needed guidance and noise control |
| Oracle interface | `check_all(trace, tx_sequence)` | `check_all(trace, tx_sequence, ast)` | several checks needed AST/context-sensitive suppression |
| Output | raw fuzz report | surfaced runtime + meta + raw + confidence + suppressed | benchmark/UI needed normalized output |
| Corpus diagnostics | none | `corpus_zero_reason` | necessary for explaining empty runs instead of silently failing |

## Problems We Faced And How We Fixed Them

### Problem A: legacy/odd contracts could lead to empty fuzzing without explanation

In the old flow, if ABI extraction or callable selection collapsed badly, fuzzing could effectively do little useful work and just look empty.

### Fix

We made ABI extraction compiler-aware and added callable logic that is more tolerant of legacy cases:

- `src/fuzzing/types.rs`
- `FunctionAbi::is_fuzz_callable(...)`
- `extract_abis(ast, &output.compiler)`

We also added `corpus_zero_reason` so empty fuzz runs are diagnosable instead of mysterious.

### Problem B: fuzzing was not making enough use of cheap static information

Pure runtime fuzzing wastes effort if static analysis already knows:

- which functions are suspicious
- which storage dependencies matter
- which address roles are relevant
- which bug families are plausible

### Fix

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

### Problem C: several runtime heuristics were too noisy

This was one of the biggest benchmark precision issues.

Examples of noise classes we reduced:

- caller-owned withdrawals being mislabeled as open withdrawals
- owner-guarded selfdestruct/privileged flows being mislabeled as open access-control failures
- `.send()` / `.transfer()` stipend flows being mislabeled as real reentrancy
- benign helper/logging patterns polluting tainted-call style output

### Fix

We tightened the fuzzing oracle in `src/fuzzing/oracle.rs`, and we also reused shared heuristics from the frontend layer.

Generalized runtime fixes included:

- authority/payout-aware access-control checks
- callback-capable distinction for reentrancy
- checked low-level wrapper suppression
- richer exception-disorder / unchecked-call context
- AST-aware suppression for clearly benign patterns

This was a direct precision improvement, not a UI/reporting change.

### Problem D: fuzzing output did not align well with the rest of the stack

Without surfaced output, confidence, and meta handling, fuzzing was harder to compare against:

- static
- symbolic
- hybrid
- benchmark scoring
- web UI summary cards

### Fix

Fuzzing now produces a normalized JSON report that mirrors the rest of the system:

- surfaced runtime findings
- raw runtime findings
- surfaced meta findings
- raw meta findings
- confidence
- suppressed counts

## What Changed In Fuzzing Flow

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

## Why The Fuzzing Improvements Matter

The current fuzzing engine is much more useful both:

- as a standalone runtime engine
- as the main exploration engine inside hybrid

That second role is especially important, because the hybrid architecture assumes fuzzing is the default runtime workhorse.
