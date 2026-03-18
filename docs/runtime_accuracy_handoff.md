# Runtime Accuracy Handoff

This file is the handoff package for the next Codex session. It captures the current Not-so-smart benchmark state, the exact runtime-primary false-positive / false-negative matrix, and the next fix queue.

## Canonical Runs

- Current run: `/home/anan/Coding/Rust/GP/Static/runs/benchmark_not_so_smart_1773711358_post_step23`
- Previous reference run: `/home/anan/Coding/Rust/GP/Static/runs/benchmark_not_so_smart_1773497819_runtime_recovery_v4`
- Primary scorer artifacts used here:
  - `/home/anan/Coding/Rust/GP/Static/runs/benchmark_not_so_smart_1773711358_post_step23/fp_analysis/summary_all.json`
  - `/home/anan/Coding/Rust/GP/Static/runs/benchmark_not_so_smart_1773711358_post_step23/fp_analysis/summary_core.json`
  - `/home/anan/Coding/Rust/GP/Static/runs/benchmark_not_so_smart_1773711358_post_step23/fp_analysis/per_contract.json`
  - `/home/anan/Coding/Rust/GP/Static/runs/benchmark_not_so_smart_1773711358_post_step23/reviewed_truth_analysis/summary.json`
  - `/home/anan/Coding/Rust/GP/Static/runs/benchmark_not_so_smart_1773711358_post_step23/reviewed_truth_analysis/per_contract.json`
  - `/home/anan/Coding/Rust/GP/Static/runs/benchmark_not_so_smart_1773711358_post_step23/aggregate_metrics.json`

## Important Scoring Notes

- Runtime KPI is `runtime_primary`, not `surfaced_output`.
- The scorer uses the expected benchmark kinds from `scripts/score_not_so_smart_run.py:64`.
- It also uses `prioritize_predictions(...)` in `scripts/score_not_so_smart_run.py:208`, so direct expected-kind hits suppress some unrelated noise, but remaining unrelated kinds still count as FP when no direct expected kind exists.
- Precision is low because the engines still emit generic runtime kinds on contracts whose benchmark truth is narrower or meta-oriented.

## Current Aggregate Metrics

| Mode | Runs OK | Timeouts | Contracts With Findings | Total Findings | Unique Types | Runtime Findings | Meta Findings | Total Runtime | Median Runtime | Delta Findings vs Prev |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| static | 25 | 0 | 25 | 728 | 39 | 728 | 0 | 2.833s | 101ms | +18 |
| symbolic | 25 | 0 | 22 | 174 | 13 | 174 | 589 | 298.648s | 6234ms | +27 |
| fuzzing | 25 | 0 | 25 | 226 | 18 | 226 | 589 | 34.895s | 528ms | +14 |
| hybrid | 25 | 0 | 25 | 849 | 46 | 839 | 10 | 101.191s | 2664ms | +25 |

## Runtime-Primary Accuracy

| Mode | Precision | Recall | F1 | TP | FP | FN | Contracts TP | Contracts FP |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| static | 0.224 (+0.042) | 0.271 (+0.021) | 0.245 (+0.034) | 13 | 45 | 35 | 12/25 | 13/25 |
| symbolic | 0.341 (+0.068) | 0.292 (+0.042) | 0.315 (+0.054) | 14 | 27 | 34 | 13/25 | 9/25 |
| fuzzing | 0.327 (+0.077) | 0.375 (+0.042) | 0.350 (+0.064) | 18 | 37 | 30 | 16/25 | 9/25 |
| hybrid | 0.297 (+0.054) | 0.396 (+0.021) | 0.339 (+0.044) | 19 | 45 | 29 | 17/25 | 8/25 |

## Reviewed-Truth Runtime Coverage

| Mode | Hits | Coverage | Contracts With Hits | Contracts Fully Hit |
| --- | --- | --- | --- | --- |
| static | 15/26 | 0.577 (+0.039) | 12/22 | 12/22 |
| symbolic | 13/26 | 0.500 (+0.115) | 11/22 | 10/22 |
| fuzzing | 15/26 | 0.577 (+0.115) | 14/22 | 11/22 |
| hybrid | 19/26 | 0.731 (+0.039) | 16/22 | 15/22 |

## Current Dominant Runtime-Primary FP Kinds

| Mode | FP Kind | Count |
| --- | --- | --- |
| symbolic | locked-ether | 6 |
| symbolic | access-control | 4 |
| symbolic | arbitrary-write | 4 |
| symbolic | reentrancy | 3 |
| symbolic | dos-with-failed-call | 3 |
| symbolic | hardcoded-gas-transfer | 2 |
| symbolic | unprotected-ether-withdrawal | 2 |
| symbolic | unprotected-selfdestruct | 1 |
| fuzzing | unprotected-ether-withdrawal | 6 |
| fuzzing | hardcoded-gas-transfer | 5 |
| fuzzing | locked-ether | 4 |
| fuzzing | unchecked-call | 4 |
| fuzzing | dos-with-failed-call | 3 |
| fuzzing | exception-disorder | 2 |
| fuzzing | access-control | 2 |
| fuzzing | arbitrary-write | 2 |
| hybrid | hardcoded-gas-transfer | 4 |
| hybrid | transaction-order-dependency | 4 |
| hybrid | unprotected-ether-withdrawal | 4 |
| hybrid | access-control | 3 |
| hybrid | arbitrary-write | 3 |
| hybrid | integer-overflow | 3 |
| hybrid | exception-disorder | 2 |
| hybrid | locked-ether | 2 |

## Noisiest Contracts by Runtime FP Count

| Mode | Contract | FP Count | Runtime FP Kinds |
| --- | --- | --- | --- |
| symbolic | honeypots/Lottery/Lottery.sol | 6 | access-control, arbitrary-write, locked-ether, reentrancy, unprotected-selfdestruct, weak-prng |
| symbolic | wrong_constructor_name/Rubixi_source_code/Rubixi.sol | 5 | dos-with-failed-call, hardcoded-gas-transfer, reentrancy, unchecked-call, unprotected-ether-withdrawal |
| symbolic | honeypots/KOTH/KOTH.sol | 5 | access-control, arbitrary-write, hardcoded-gas-transfer, locked-ether, unprotected-ether-withdrawal |
| symbolic | race_condition/RaceCondition.sol | 4 | access-control, arbitrary-write, locked-ether, reentrancy |
| symbolic | variable shadowing/inherited_state.sol | 2 | access-control, arbitrary-write |
| symbolic | honeypots/VarLoop/VarLoop.sol | 2 | dos-with-failed-call, locked-ether |
| symbolic | reentrancy/SpankChain_source_code/SpankChain.sol | 1 | dos-with-failed-call |
| symbolic | honeypots/PrivateBank/PrivateBank.sol | 1 | locked-ether |
| fuzzing | honeypots/Lottery/Lottery.sol | 11 | access-control, arbitrary-write, hardcoded-gas-transfer, integer-overflow, integer-underflow, locked-ether, reentrancy, unchecked-call, unprotected-ether-withdrawal, unprotected-selfdestruct, weak-prng |
| fuzzing | wrong_constructor_name/Rubixi_source_code/Rubixi.sol | 9 | division-before-multiplication, dos-with-failed-call, exception-disorder, hardcoded-gas-transfer, integer-overflow, integer-underflow, reentrancy, unchecked-call, unprotected-ether-withdrawal |
| fuzzing | honeypots/GiftBox/GiftBox.sol | 4 | exception-disorder, hardcoded-gas-transfer, locked-ether, unprotected-ether-withdrawal |
| fuzzing | honeypots/VarLoop/VarLoop.sol | 3 | dos-with-failed-call, hardcoded-gas-transfer, locked-ether |
| fuzzing | honeypots/KOTH/KOTH.sol | 3 | hardcoded-gas-transfer, locked-ether, unprotected-ether-withdrawal |
| fuzzing | variable shadowing/inherited_state.sol | 2 | access-control, arbitrary-write |
| fuzzing | incorrect_interface/Bob.sol | 2 | unchecked-call, unprotected-ether-withdrawal |
| fuzzing | incorrect_interface/Alice.sol | 2 | unchecked-call, unprotected-ether-withdrawal |
| hybrid | honeypots/Lottery/Lottery.sol | 14 | access-control, arbitrary-write, hardcoded-gas-transfer, integer-overflow, integer-underflow, locked-ether, reentrancy, shadowing, timestamp-dependency, transaction-order-dependency, unchecked-call, unprotected-ether-withdrawal, unprotected-selfdestruct, weak-prng |
| hybrid | wrong_constructor_name/Rubixi_source_code/Rubixi.sol | 11 | division-before-multiplication, dos-block-gas-limit, dos-with-failed-call, exception-disorder, hardcoded-gas-transfer, integer-overflow, integer-underflow, reentrancy, transaction-order-dependency, unchecked-call, unprotected-ether-withdrawal |
| hybrid | honeypots/GiftBox/GiftBox.sol | 6 | exception-disorder, hardcoded-gas-transfer, lack-of-signature-verification, locked-ether, transaction-order-dependency, unprotected-ether-withdrawal |
| hybrid | honeypots/KOTH/KOTH.sol | 5 | access-control, arbitrary-write, hardcoded-gas-transfer, transaction-order-dependency, unprotected-ether-withdrawal |
| hybrid | forced_ether_reception/coin.sol | 5 | access-control, arbitrary-write, contract-destructable, force-ether-balance-check, integer-overflow |
| hybrid | reentrancy/SpankChain_source_code/SpankChain.sol | 2 | dos-with-failed-call, shadowing |
| hybrid | incorrect_interface/Bob.sol | 1 | storage-array-by-value |
| hybrid | incorrect_interface/Alice.sol | 1 | storage-array-by-value |

## Exact Runtime-Primary Contract Matrix

Only contracts with at least one runtime-primary FP or FN are listed below. `TP` means the mode matched at least one expected benchmark kind on that contract.

### Symbolic

| Contract | TP | FP | FN |
| --- | --- | --- | --- |
| bad_randomness/theRun_source_code/theRun.sol | weak-prng | - | timestamp-dependency |
| denial_of_service/auction.sol | dos-with-failed-call | - | dos-block-gas-limit |
| denial_of_service/list_dos.sol | dos-with-failed-call | - | dos-block-gas-limit |
| honeypots/GiftBox/GiftBox.sol | - | locked-ether | honeypot |
| honeypots/KOTH/KOTH.sol | - | access-control, arbitrary-write, hardcoded-gas-transfer, locked-ether, unprotected-ether-withdrawal | honeypot, shadowing |
| honeypots/Lottery/Lottery.sol | - | access-control, arbitrary-write, locked-ether, reentrancy, unprotected-selfdestruct, weak-prng | honeypot, memory-manipulation |
| honeypots/Multiplicator/Multiplicator.sol | locked-ether | - | honeypot |
| honeypots/PrivateBank/PrivateBank.sol | - | locked-ether | dos-with-failed-call, honeypot, reentrancy |
| honeypots/VarLoop/VarLoop.sol | - | dos-with-failed-call, locked-ether | honeypot, integer-overflow, integer-underflow |
| incorrect_interface/Alice.sol | - | - | incorrect-interface |
| incorrect_interface/Bob.sol | - | - | incorrect-interface |
| integer_overflow/integer_overflow_1.sol | - | - | integer-overflow, integer-underflow |
| race_condition/RaceCondition.sol | - | access-control, arbitrary-write, locked-ether, reentrancy | transaction-order-dependency |
| reentrancy/SpankChain_source_code/SpankChain.sol | - | dos-with-failed-call | reentrancy |
| unchecked_external_call/KotET_source_code/KingOfTheEtherThrone.sol | unchecked-call | - | exception-disorder, unused-return-value |
| unprotected_function/Unprotected.sol | access-control | - | unprotected-ether-withdrawal, unprotected-selfdestruct, unsafe-delegatecall |
| unprotected_function/WalletLibrary_source_code/WalletLibrary.sol | unprotected-ether-withdrawal, unsafe-delegatecall | - | access-control, unprotected-selfdestruct |
| variable shadowing/inherited_state.sol | - | access-control, arbitrary-write | shadowing |
| wrong_constructor_name/Rubixi_source_code/Rubixi.sol | - | dos-with-failed-call, hardcoded-gas-transfer, reentrancy, unchecked-call, unprotected-ether-withdrawal | access-control, uninit-permission-check, wrong-constructor-name |
| wrong_constructor_name/incorrect_constructor.sol | access-control | - | uninit-permission-check, wrong-constructor-name |

### Fuzzing

| Contract | TP | FP | FN |
| --- | --- | --- | --- |
| bad_randomness/theRun_source_code/theRun.sol | weak-prng | - | timestamp-dependency |
| denial_of_service/auction.sol | dos-with-failed-call | - | dos-block-gas-limit |
| denial_of_service/list_dos.sol | dos-with-failed-call | - | dos-block-gas-limit |
| honeypots/GiftBox/GiftBox.sol | - | exception-disorder, hardcoded-gas-transfer, locked-ether, unprotected-ether-withdrawal | honeypot |
| honeypots/KOTH/KOTH.sol | - | hardcoded-gas-transfer, locked-ether, unprotected-ether-withdrawal | honeypot, shadowing |
| honeypots/Lottery/Lottery.sol | - | access-control, arbitrary-write, hardcoded-gas-transfer, integer-overflow, integer-underflow, locked-ether, reentrancy, unchecked-call, unprotected-ether-withdrawal, unprotected-selfdestruct, weak-prng | honeypot, memory-manipulation |
| honeypots/Multiplicator/Multiplicator.sol | locked-ether | - | honeypot |
| honeypots/PrivateBank/PrivateBank.sol | reentrancy | - | dos-with-failed-call, honeypot |
| honeypots/VarLoop/VarLoop.sol | - | dos-with-failed-call, hardcoded-gas-transfer, locked-ether | honeypot, integer-overflow, integer-underflow |
| incorrect_interface/Alice.sol | - | unchecked-call, unprotected-ether-withdrawal | incorrect-interface |
| incorrect_interface/Bob.sol | - | unchecked-call, unprotected-ether-withdrawal | incorrect-interface |
| integer_overflow/integer_overflow_1.sol | integer-overflow | - | integer-underflow |
| reentrancy/SpankChain_source_code/SpankChain.sol | - | dos-with-failed-call | reentrancy |
| unchecked_external_call/KotET_source_code/KingOfTheEtherThrone.sol | exception-disorder, unchecked-call | - | unused-return-value |
| unprotected_function/Unprotected.sol | access-control | - | unprotected-ether-withdrawal, unprotected-selfdestruct, unsafe-delegatecall |
| unprotected_function/WalletLibrary_source_code/WalletLibrary.sol | unprotected-ether-withdrawal, unsafe-delegatecall | - | access-control, unprotected-selfdestruct |
| variable shadowing/inherited_state.sol | - | access-control, arbitrary-write | shadowing |
| wrong_constructor_name/Rubixi_source_code/Rubixi.sol | - | division-before-multiplication, dos-with-failed-call, exception-disorder, hardcoded-gas-transfer, integer-overflow, integer-underflow, reentrancy, unchecked-call, unprotected-ether-withdrawal | access-control, uninit-permission-check, wrong-constructor-name |
| wrong_constructor_name/incorrect_constructor.sol | access-control | - | uninit-permission-check, wrong-constructor-name |

### Hybrid

| Contract | TP | FP | FN |
| --- | --- | --- | --- |
| bad_randomness/theRun_source_code/theRun.sol | weak-prng | - | timestamp-dependency |
| denial_of_service/auction.sol | dos-with-failed-call | - | dos-block-gas-limit |
| forced_ether_reception/coin.sol | - | access-control, arbitrary-write, contract-destructable, force-ether-balance-check, integer-overflow | locked-ether |
| honeypots/GiftBox/GiftBox.sol | - | exception-disorder, hardcoded-gas-transfer, lack-of-signature-verification, locked-ether, transaction-order-dependency, unprotected-ether-withdrawal | honeypot |
| honeypots/KOTH/KOTH.sol | - | access-control, arbitrary-write, hardcoded-gas-transfer, transaction-order-dependency, unprotected-ether-withdrawal | honeypot, shadowing |
| honeypots/Lottery/Lottery.sol | - | access-control, arbitrary-write, hardcoded-gas-transfer, integer-overflow, integer-underflow, locked-ether, reentrancy, shadowing, timestamp-dependency, transaction-order-dependency, unchecked-call, unprotected-ether-withdrawal, unprotected-selfdestruct, weak-prng | honeypot, memory-manipulation |
| honeypots/Multiplicator/Multiplicator.sol | locked-ether | - | honeypot |
| honeypots/PrivateBank/PrivateBank.sol | reentrancy | - | dos-with-failed-call, honeypot |
| honeypots/VarLoop/VarLoop.sol | integer-overflow | - | honeypot, integer-underflow |
| incorrect_interface/Alice.sol | - | storage-array-by-value | incorrect-interface |
| incorrect_interface/Bob.sol | - | storage-array-by-value | incorrect-interface |
| integer_overflow/integer_overflow_1.sol | integer-overflow | - | integer-underflow |
| reentrancy/SpankChain_source_code/SpankChain.sol | - | dos-with-failed-call, shadowing | reentrancy |
| unchecked_external_call/KotET_source_code/KingOfTheEtherThrone.sol | exception-disorder, unchecked-call | - | unused-return-value |
| unprotected_function/Unprotected.sol | access-control | - | unprotected-ether-withdrawal, unprotected-selfdestruct, unsafe-delegatecall |
| unprotected_function/WalletLibrary_source_code/WalletLibrary.sol | unsafe-delegatecall | - | access-control, unprotected-ether-withdrawal, unprotected-selfdestruct |
| wrong_constructor_name/Rubixi_source_code/Rubixi.sol | - | division-before-multiplication, dos-block-gas-limit, dos-with-failed-call, exception-disorder, hardcoded-gas-transfer, integer-overflow, integer-underflow, reentrancy, transaction-order-dependency, unchecked-call, unprotected-ether-withdrawal | access-control, uninit-permission-check, wrong-constructor-name |
| wrong_constructor_name/incorrect_constructor.sol | access-control | - | uninit-permission-check, wrong-constructor-name |

## Source Map for the Next Session

### Symbolic Sources

- Generic authority/runtime heuristics: `src/symbolic/mod.rs:1551`
- Generic access-control emission: `src/symbolic/mod.rs:1568`
- Locked-ether path evidence: `src/symbolic/mod.rs:2009`
- Hardcoded gas transfer emission: `src/symbolic/mod.rs:2029`
- DoS-with-failed-call emission: `src/symbolic/mod.rs:2068`
- Unprotected withdrawal emission: `src/symbolic/mod.rs:2089`
- TOD emission: `src/symbolic/mod.rs:2113`
- Unchecked low-level call: `src/symbolic/mod.rs:2272`
- Contract-level locked-ether heuristic: `src/symbolic/mod.rs:752`
- Static-guided runtime backstops: `src/symbolic/mod.rs:816`

### Fuzzing Sources

- Generic access-control oracle: `src/fuzzing/oracle.rs:301`
- Generic arbitrary-write oracle: `src/fuzzing/oracle.rs:345`
- DoS-with-failed-call oracle: `src/fuzzing/oracle.rs:571`
- TOD oracle: `src/fuzzing/oracle.rs:782`
- Hardcoded gas oracle: `src/fuzzing/oracle.rs:907`
- Locked-ether oracle: `src/fuzzing/oracle.rs:934`
- Static-guided runtime backstops: `src/fuzzing/runner.rs:244`
- Seed generation / bootstrap coverage: `src/fuzzing/generator.rs`
- Execution trace semantics / callback simulation: `src/fuzzing/executor.rs`

### Hybrid Sources

- P1 scheduler and assist loop: `src/core/scheduler/mod.rs:124`
- Assist seed filtering: `src/core/scheduler/mod.rs:352`
- Runtime/meta triage accounting: `src/core/triage/mod.rs:27`
- Static/fuzz/symbolic adapters into shared findings: `src/core/engines/mod.rs:348`
- CLI hybrid report fields: `src/main.rs:162`

## Prioritized Fix Queue

### 1. Tighten generic access-control and arbitrary-write runtime heuristics

- Why: These two kinds dominate false positives on honeypots, `RaceCondition.sol`, and `inherited_state.sol`.
- Primary edit targets:
  - `src/fuzzing/oracle.rs:301`
  - `src/fuzzing/oracle.rs:345`
  - `src/symbolic/mod.rs:1551`
  - `src/symbolic/mod.rs:1568`
- Concrete actions:
  - Require a stronger authority-sensitive slot filter before emitting the finding.
  - Distinguish owner-like initialization from externally exploitable mutation.
  - Suppress emission when the write set is benchmark-irrelevant bookkeeping and no attacker-controlled consequence is observed.

### 2. Narrow locked-ether to forced-ether invariants or proven no-withdraw contracts only

- Why: `locked-ether` is the top symbolic false positive and still over-fires on honeypots.
- Primary edit targets:
  - `src/fuzzing/oracle.rs:934`
  - `src/fuzzing/runner.rs:320`
  - `src/symbolic/mod.rs:752`
  - `src/symbolic/mod.rs:917`
- Concrete actions:
  - Keep the strong `this.balance` / `address(this).balance` invariant path.
  - Downgrade or suppress the broad payable-without-ether-out heuristic on contracts that are not meant to expose withdrawals.
  - Do not let static locked-ether backstops appear as runtime-primary on benchmark families whose reviewed truth is honeypot or wrong-constructor.

### 3. Strengthen unchecked-call and DoS-with-failed-call consequence checks

- Why: `Rubixi.sol`, `GiftBox.sol`, `SpankChain.sol`, and the Alice/Bob interface fixtures still get noisy call-related runtime kinds.
- Primary edit targets:
  - `src/fuzzing/oracle.rs:571`
  - `src/fuzzing/oracle.rs:907`
  - `src/fuzzing/runner.rs:274`
  - `src/fuzzing/runner.rs:349`
  - `src/symbolic/mod.rs:2068`
  - `src/symbolic/mod.rs:2272`
- Concrete actions:
  - Require an observable failure consequence, not just loop+call or low-level-call presence.
  - Separate `unchecked-call`, `exception-disorder`, and `dos-with-failed-call` by post-call control-flow impact.
  - Stop runtime backstops from filling the gap on non-runtime benchmark families such as incorrect-interface.

### 4. Recover missing benchmark-specific runtime kinds before adding more breadth

- Why: Several misses are still true misses, not only noise: timestamp dependency, DoS-block-gas-limit, reentrancy on SpankChain, integer-underflow, wrong-constructor-name, unprotected selfdestruct, unsafe delegatecall, incorrect-interface.
- Primary edit targets:
  - `src/symbolic/mod.rs:2113`
  - `src/fuzzing/oracle.rs:782`
  - `src/fuzzing/executor.rs`
  - `src/meta`
  - `src/frontend`
- Concrete actions:
  - Add a dedicated `timestamp-dependency` runtime path, not only `weak-prng`.
  - Model loop growth / gas-sensitive paths for `dos-block-gas-limit`.
  - Improve callback-path selection for `SpankChain.sol`.
  - Improve arithmetic underflow parity for `integer_overflow_1.sol` and `VarLoop.sol`.
  - Leave `incorrect-interface` in meta and stop scoring it as a runtime miss in dynamic triage work.

### 5. Reduce hybrid noise by gating ingestion instead of raw unioning

- Why: Hybrid has the best runtime recall but worse precision than fuzzing because it keeps too many extra kinds.
- Primary edit targets:
  - `src/core/scheduler/mod.rs:124`
  - `src/core/triage/mod.rs:27`
  - `src/core/engines/mod.rs:348`
- Concrete actions:
  - Prefer high-confidence runtime findings from fuzzing/symbolic over broad static-derived runtime backstops.
  - Do not surface low-confidence runtime backstops into hybrid runtime-primary unless they unlock a reviewed benchmark family directly.
  - Track assist provenance per finding so another session can filter imported findings by source engine and confidence.

## Practical Reading of the Matrix

- `Lottery.sol` and `Rubixi.sol` are still the best contracts for reducing generic runtime noise quickly. They trigger the widest spread of unrelated kinds.
- `GiftBox.sol`, `KOTH.sol`, and `VarLoop.sol` are still useful for checking that honeypot/meta-oriented contracts do not receive broad runtime labels.
- `SpankChain.sol` remains the best focused reentrancy runtime miss to fix.
- `Alice.sol` and `Bob.sol` should remain meta/compatibility targets, not dynamic runtime wins.
- `coin.sol` is now a good sanity test for strong locked-ether evidence; hybrid still shows extra static-derived runtime noise on it.

## Suggested Next-Session Order

1. Tighten `locked-ether`, `access-control`, and `arbitrary-write` in `symbolic` and `fuzzing`.
2. Remove low-confidence runtime backstop leakage into `hybrid` runtime-primary.
3. Re-run focused targets: `Lottery.sol`, `Rubixi.sol`, `GiftBox.sol`, `KOTH.sol`, `SpankChain.sol`, `coin.sol`.
4. Only after those six look cleaner, rerun the full Not-so-smart benchmark.

## Reproduction Commands

```bash
RUSTFLAGS="-A dead_code -A unused" cargo run -- --symbolic Benchmarks/Not-so-smart/not-so-smart-contracts-master/reentrancy/SpankChain_source_code/SpankChain.sol --json
RUSTFLAGS="-A dead_code -A unused" cargo run -- --fuzzing Benchmarks/Not-so-smart/not-so-smart-contracts-master/honeypots/Lottery/Lottery.sol
RUSTFLAGS="-A dead_code -A unused" cargo run -- --hybrid Benchmarks/Not-so-smart/not-so-smart-contracts-master/forced_ether_reception/coin.sol
python3 scripts/score_not_so_smart_run.py runs/benchmark_not_so_smart_1773711358_post_step23/summary.tsv
python3 scripts/score_not_so_smart_reviewed_truth.py runs/benchmark_not_so_smart_1773711358_post_step23/summary.tsv
```

## Raw Artifact Reference

- Full raw outputs: `/home/anan/Coding/Rust/GP/Static/runs/benchmark_not_so_smart_1773711358_post_step23/raw`
- Exact scorer matrix: `/home/anan/Coding/Rust/GP/Static/runs/benchmark_not_so_smart_1773711358_post_step23/fp_analysis/per_contract.json`
- Reviewed truth matrix: `/home/anan/Coding/Rust/GP/Static/runs/benchmark_not_so_smart_1773711358_post_step23/reviewed_truth_analysis/per_contract.json`
- Per-issue matrix TSV: `/home/anan/Coding/Rust/GP/Static/runs/benchmark_not_so_smart_1773711358_post_step23/fp_analysis/per_issue_matrix.tsv`

