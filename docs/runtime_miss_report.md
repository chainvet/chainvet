# Runtime Miss Report (Symbolic + Fuzzing)

Based on:

- `runs/benchmark_not_so_smart_1773497819_runtime_recovery_v4/reviewed_truth_analysis/per_issue_matrix.tsv`
- `runs/benchmark_not_so_smart_1773497819_runtime_recovery_v4/fp_analysis/summary_all.json`
- `runs/benchmark_not_so_smart_1773497819_runtime_recovery_v4/aggregate_metrics.json`

Baseline for delta tracking:

- `runs/benchmark_not_so_smart_1773494043_runtime_recovery_v2/*`
- `runs/benchmark_not_so_smart_1773495810_runtime_recovery_v3/*`

## Runtime-primary Snapshot (Reviewed Truth, 26 issues)

- Static: `14/26` (unchanged)
- Symbolic: `10/26` (`+9` vs v2 `1/26`, `+5` vs v3 `5/26`)
- Fuzzing: `12/26` (`+12` vs v2 `0/26`, `+4` vs v3 `8/26`)
- Hybrid: `18/26` (`+2` vs v2 `16/26`, `+1` vs v3 `17/26`)

## Runtime-primary FP/TP/FN Delta (All 25 Contracts)

From `fp_analysis/summary_all.json`:

- Symbolic F1: `0.051 -> 0.174`
- Fuzzing F1: `0.029 -> 0.207`
- Hybrid F1: `0.252 -> 0.274`

Latest delta (v3 -> v4):

- Symbolic F1: `0.174 -> 0.261`
- Fuzzing F1: `0.207 -> 0.286`
- Hybrid F1: `0.274 -> 0.295`

## Highest-Impact Remaining Runtime Miss Buckets

Counts are reviewed-truth issues where runtime channel still missed.

### Symbolic runtime misses (`symbolic_runtime_hit=0`)

1. `honeypot`: 5
2. `weak-prng`: 1
3. `unchecked-call`: 1
4. `dos-with-failed-call`: 1
5. `locked-ether`: 1

### Fuzzing runtime misses (`fuzzing_runtime_hit=0`)

1. `honeypot`: 5
2. `weak-prng`: 1
3. `unchecked-call`: 1
4. `dos-with-failed-call`: 1
5. `locked-ether`: 1

## What Improved in This Batch

1. Legacy callable recovery:
   - `src/frontend/solc.rs` (`parse_function_kind`) now recovers missing legacy `kind` correctly.
   - `src/fuzzing/types.rs` (`FunctionAbi::is_fuzz_callable`) now allows fallback/legacy callable cases.
2. Symbolic taxonomy alignment:
   - `src/symbolic/mod.rs` now emits runtime `access-control` alongside `arbitrary-write` where applicable.
3. Value-transfer recognition hardened for dynamic call modeling:
   - `src/symbolic/mod.rs` and `src/fuzzing/executor.rs` now treat send/transfer/low-level value sends as value-bearing calls more consistently.

Measured effect:

- Symbolic runtime findings: `50 -> 122`
- Fuzzing runtime findings: `41 -> 193`
- Fuzzing contracts with runtime findings: `5 -> 23`
- Symbolic runtime findings (latest): `122 -> 147`
- Fuzzing runtime findings (latest): `193 -> 212`
- Fuzzing contracts with runtime findings (latest): `23 -> 25`

## Remaining Priority Contracts (Runtime Gap)

Still missed by both symbolic and fuzzing runtime channels in v4:

1. `Benchmarks/Not-so-smart/not-so-smart-contracts-master/bad_randomness/theRun_source_code/theRun.sol`
2. `Benchmarks/Not-so-smart/not-so-smart-contracts-master/forced_ether_reception/coin.sol`
3. `Benchmarks/Not-so-smart/not-so-smart-contracts-master/honeypots/GiftBox/GiftBox.sol`
4. `Benchmarks/Not-so-smart/not-so-smart-contracts-master/honeypots/KOTH/KOTH.sol`
5. `Benchmarks/Not-so-smart/not-so-smart-contracts-master/honeypots/Lottery/Lottery.sol`

## Next Runtime Fixes

1. Replace static-guided runtime backstops for `reentrancy` / `dos-with-failed-call` with stronger native evidence where possible (reduce low-confidence dependency).
2. Add runtime weak-PRNG/timestamp link evidence in sequence context for `theRun`-style patterns.
3. Improve forced-Ether/locked-ether dynamic state modeling (`coin.sol`) to reduce reliance on non-runtime layers.
