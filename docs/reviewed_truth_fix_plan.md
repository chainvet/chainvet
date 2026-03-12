# Reviewed-Truth Fix Plan

Date: 2026-03-11

This plan targets the real problems exposed by `docs/not_so_smart_reviewed_truth.md`, not just taxonomy coverage.

## Problem Statement

The current engines have two separate issues:

1. They miss important root-cause vulnerabilities on the reviewed Not-so-smart baseline.
2. They emit too many low-signal or repeated findings, which inflates totals and hides true accuracy.

The reviewed baseline is:

- `26` validated issue instances

Current reviewed-truth coverage:

- `--static`: `8/26`
- `--symbolic`: `12/26`
- `--fuzzing`: `15/26`
- `--hybrid`: `15/26`

This means the next work should optimize for:

- reviewed root-cause hits
- reduction of low-value output noise
- benchmark regressions tied to specific missed contracts

## Goals

1. Raise reviewed-truth coverage to at least:
   - static: `16/26`
   - symbolic: `20/26`
   - fuzzing: `20/26`
   - hybrid: `23/26`
2. Separate runtime signal from meta/taxonomy signal in all evaluations.
3. Reduce benchmark-noise findings that are not the actual vulnerable behavior.

## Core Principles

1. Root-cause first
- A detector gets credit only if it identifies the reviewed issue family for that contract.
- Reporting side effects instead of causes is not enough.

2. Runtime and meta must stay separate
- Taxonomy-completion remains useful, but it must not be confused with native dynamic detection.
- Future benchmark tables must always show both:
  - runtime-only coverage
  - surfaced-output coverage

3. Benchmark-driven engineering
- Every major missed contract becomes a dedicated regression target.
- No new broad heuristic should be added without a benchmark target and an FP check.

## Main Failure Clusters

### Cluster A: DoS modeling is weak

Missed or poorly matched:

- `Benchmarks/Not-so-smart/not-so-smart-contracts-master/denial_of_service/auction.sol`
- `Benchmarks/Not-so-smart/not-so-smart-contracts-master/denial_of_service/list_dos.sol`

Why:

- Current engines do not strongly model push-payment failure semantics.
- Loop + external-call patterns are not mapped to the reviewed DoS root cause reliably.

Fixes:

1. Add a shared push-payment DoS detector
- Pattern:
  - external Ether send in a refund/payment path
  - failure of recipient blocks progress or reverts whole operation
- Map to:
  - `dos-with-failed-call`

2. Add a loop-payout DoS detector
- Pattern:
  - loop over user-controlled or dynamically growing collection
  - external send/transfer/call inside loop
- Map to:
  - `dos-block-gas-limit`
  - `dos-with-failed-call`

3. Fuzzing/runtime support
- Add recipient behaviors:
  - always-revert recipient
  - gas-griefing recipient
- Use them automatically on payout-like functions.

Acceptance:

- `auction.sol` is hit as DoS by static, symbolic, fuzzing, and hybrid.
- `list_dos.sol` is hit on both reviewed issues:
  - bulk refund revert DoS
  - still-griefable payout path

### Cluster B: TOD / front-running semantics are too weak

Missed:

- `Benchmarks/Not-so-smart/not-so-smart-contracts-master/race_condition/RaceCondition.sol`

Why:

- Current TOD rules are too generic and do not connect:
  - owner-controlled state update
  - victim transaction using stale expectation
  - profitable ordering dependency

Fixes:

1. Add a dedicated price/front-run detector
- Pattern:
  - one public function mutates a trade-critical variable
  - another public function consumes that variable for asset transfer
  - both are externally callable and order-sensitive

2. Symbolic sequence support
- Explore two-transaction sequences:
  - victim path
  - attacker-precedes-victim path

3. Fuzzing sequence templates
- Seed writer->reader transaction pairs from `storage_rw_map`.
- Explicitly test `changePrice -> buy`.

Acceptance:

- `RaceCondition.sol` is hit by symbolic, fuzzing, and hybrid as `transaction-order-dependency`.

### Cluster C: Reentrancy coverage is still incomplete on real benchmarks

Missed or incomplete:

- `Benchmarks/Not-so-smart/not-so-smart-contracts-master/honeypots/PrivateBank/PrivateBank.sol`
- `Benchmarks/Not-so-smart/not-so-smart-contracts-master/reentrancy/DAO_source_code/DAO.sol`

Why:

- Current callback support handles simple cases, but not the real DAO-style root cause.
- Reward withdrawal / split paths with external intermediate contracts are not modeled deeply enough.

Fixes:

1. Extend callback modeling beyond direct `msg.sender.call.value(...)`
- Model external value transfer through helper accounts/contracts such as `ManagedAccount.payOut`.
- Track “external control transfer before bookkeeping update” across one additional call boundary.

2. Add root-cause reentrancy detector for delayed bookkeeping
- Pattern:
  - user-controlled withdraw/split/reward path
  - external value transfer
  - balance/claim/payout state updated after call

3. Add reviewed benchmark regression cases
- `Reentrancy.sol`
- `PrivateBank.sol`
- `DAO.sol`
- `SpankChain_Payment.sol`

Acceptance:

- `PrivateBank.sol` hits reviewed reentrancy.
- `DAO.sol` hits both reviewed reentrancy instances:
  - `splitDAO()`
  - reward withdrawal path

### Cluster D: Unchecked external call detection misses real contracts

Missed:

- `Benchmarks/Not-so-smart/not-so-smart-contracts-master/unchecked_external_call/KotET_source_code/KingOfTheEtherThrone.sol`

Why:

- Existing unchecked-call logic is too narrow for old-style `send()` refund patterns.
- Some engines treat it as generic payout noise rather than unchecked external call root cause.

Fixes:

1. Expand unchecked-send rule
- Pattern:
  - `send()` / low-level call return ignored or not used to preserve correctness
  - state/protocol semantics assume success

2. Contract-specific acceptance target
- `KingOfTheEtherThrone.sol` must hit:
  - `unused-return-value` or canonical `unchecked-call`

3. Fuzzing support
- Use recipient contracts that intentionally fail on fallback.
- Confirm the state machine still advances incorrectly.

Acceptance:

- `KingOfTheEtherThrone.sol` is hit by at least static, fuzzing, and hybrid.

### Cluster E: Access-control takeover logic is under-modeled

Missed or weak:

- `Benchmarks/Not-so-smart/not-so-smart-contracts-master/unprotected_function/WalletLibrary_source_code/WalletLibrary.sol`
- `Benchmarks/Not-so-smart/not-so-smart-contracts-master/wrong_constructor_name/incorrect_constructor.sol`
- partially `Benchmarks/Not-so-smart/not-so-smart-contracts-master/wrong_constructor_name/Rubixi_source_code/Rubixi.sol`

Why:

- Generic access-control warnings do not connect to the actual takeover primitive.
- Public initializer / wrong-constructor / reinitializer flows need dedicated modeling.

Fixes:

1. Add explicit initializer-takeover detector
- Pattern:
  - public/external init-style function
  - writes privileged owner/owners/required state
  - callable after deployment

2. Add wrong-constructor detector parity across all modes
- Pattern:
  - function name resembles constructor but does not match contract name in old Solidity
  - initializes privileged state

3. Add privilege-escalation scoring
- Treat these as high-severity root-cause access-control bugs, not generic arbitrary-write.

Acceptance:

- `WalletLibrary.sol` hits for `initWallet()`.
- `incorrect_constructor.sol` and `Rubixi.sol` hit consistently as constructor/init takeover.

### Cluster F: Shadowing and storage-pointer bugs are reported as side effects, not causes

Missed:

- `Benchmarks/Not-so-smart/not-so-smart-contracts-master/variable shadowing/inherited_state.sol`
- `Benchmarks/Not-so-smart/not-so-smart-contracts-master/honeypots/Lottery/Lottery.sol`

Why:

- Engines often report the downstream effect:
  - `unprotected-selfdestruct`
  - generic storage/memory issue
- but not the root-cause class:
  - `shadowing`
  - storage-pointer corruption / uninitialized storage reference

Fixes:

1. Promote root-cause-first reporting
- If a dangerous sink is reached because of shadowing, emit `shadowing` as the primary finding.

2. Add a dedicated uninitialized-storage-pointer detector
- Pattern:
  - local struct/array reference without explicit memory/storage in legacy Solidity
  - subsequent writes alias storage unexpectedly

3. Keep sink side effects as secondary metadata, not the primary scored result.

Acceptance:

- `inherited_state.sol` hits as `shadowing`.
- `Lottery.sol` hits as storage-pointer / honeypot root cause.

## Noise Reduction Plan

The following finding types are currently dominating output without helping reviewed accuracy:

- `default-visibility`
- `storage-array-by-value`
- `missing-input-validation`
- repeated `shadowing` duplicates
- repeated `tainted-call` duplicates

Fixes:

1. Default-visibility policy
- Keep it available, but exclude it from benchmark-primary scoring by default.
- Mark it as informational unless it is the reviewed root cause for that target.

2. Repeated-site collapse
- Collapse repeated same-kind findings per function/root variable where they represent one root cause.

3. Root-cause priority ordering
- When multiple findings exist on the same path:
  - prefer root cause over side effect
  - prefer benchmark-matching finding over generic auxiliary warning

Acceptance:

- Top FP kinds in benchmark comparison no longer dominated by `default-visibility` and `storage-array-by-value`.

## Evaluation Changes

Current evaluation mixes too many things together.

Required changes:

1. Keep three benchmark views
- reviewed-truth coverage
- runtime-only coverage
- surfaced-output coverage

2. Add per-contract reviewed hit table
- one row per reviewed issue
- columns:
  - `file`
  - `reviewed_issue`
  - `static_hit`
  - `symbolic_hit`
  - `fuzzing_hit`
  - `hybrid_hit`

3. Fail regression if:
- reviewed-truth coverage drops for any mode
- a previously fixed reviewed issue becomes missed again

## Implementation Order

### Phase 1: Scoring and noise control

Tasks:

1. Add machine-readable reviewed truth artifact.
2. Add reviewed-truth scorer.
3. Add output filtering / root-cause prioritization in benchmark mode.

Expected gain:

- honest metrics
- clearer signal during detector work

### Phase 2: High-value root-cause detectors

Tasks:

1. DoS push-payment family
2. TOD price/front-run family
3. unchecked-send family
4. initWallet / wrong-constructor / init-takeover family
5. shadowing root-cause prioritization

Expected gain:

- should recover:
  - `auction.sol`
  - `list_dos.sol`
  - `RaceCondition.sol`
  - `KingOfTheEtherThrone.sol`
  - `WalletLibrary.sol`
  - `inherited_state.sol`

### Phase 3: Reentrancy deepening

Tasks:

1. DAO-style cross-contract payout path modeling
2. helper-account payout modeling
3. two-step reward-withdrawal reentrancy detection

Expected gain:

- should recover:
  - `PrivateBank.sol` reentrancy
  - `DAO.sol` reviewed issues

### Phase 4: Honeypot root-cause refinement

Tasks:

1. distinguish true honeypot traps from generic suspicious withdrawal patterns
2. connect specific trap families:
   - impossible branch
   - interface mismatch trap
   - storage-pointer trap
   - shadowing authority trap

Expected gain:

- better precision on honeypot subset
- fewer generic false positives

## Concrete Acceptance Targets

Minimum target after this plan:

- `auction.sol`: hit
- `list_dos.sol`: both reviewed issues hit
- `RaceCondition.sol`: hit
- `PrivateBank.sol`: honeypot + reentrancy both hit
- `DAO.sol`: both reviewed issues hit
- `KingOfTheEtherThrone.sol`: hit
- `WalletLibrary.sol`: hit
- `inherited_state.sol`: hit
- `Lottery.sol`: hit

Stretch target:

- reviewed-truth coverage:
  - static `>= 16/26`
  - symbolic `>= 20/26`
  - fuzzing `>= 20/26`
  - hybrid `>= 23/26`

## Immediate Next Step

Start with Phase 1 and Phase 2 together:

1. create machine-readable reviewed truth
2. add reviewed-truth scorer
3. implement the first batch of benchmark-driven root-cause detectors:
   - `auction.sol`
   - `list_dos.sol`
   - `RaceCondition.sol`
   - `WalletLibrary.sol`
   - `KingOfTheEtherThrone.sol`

## Progress Notes

### 2026-03-11: Batch 1 implemented

Implemented in the shared static detector layer:

- `auction.sol`: `dos-with-failed-call` now catches required push-payment refund patterns.
- `list_dos.sol`: source-resilient `dos-block-gas-limit` and `dos-with-failed-call` fallback logic now catches looped payout patterns even when parser structure is degraded.
- `RaceCondition.sol`: `transaction-order-dependency` now has a source fallback for token transfer calls such as `.transferFrom(...)`.
- `WalletLibrary.sol`: initializer-takeover detection now covers broader `init*` function names, including `initWallet`.
- `KingOfTheEtherThrone.sol`: `unused-return-value` now has a source fallback for ignored low-level calls such as `.send(...)`.

Regression tests added in `src/analysis/detectors/mod.rs` for all five targets.
