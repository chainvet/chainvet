# Not-so-smart Benchmark Comparison (4 Modes)

Date: 2026-03-18
Dataset: `Benchmarks/Not-so-smart/not-so-smart-contracts-master` (25 contracts)

Analysis artifacts used:

- `runs/benchmark_not_so_smart_1773870274_post_step34/summary.tsv`
- `runs/benchmark_not_so_smart_1773870274_post_step34/aggregate_metrics.json`
- `runs/benchmark_not_so_smart_1773870274_post_step34/fp_analysis/summary_all.json`
- `runs/benchmark_not_so_smart_1773870274_post_step34/fp_analysis/summary_core.json`
- `runs/benchmark_not_so_smart_1773870274_post_step34/reviewed_truth_analysis/summary.json`

Reference baseline for delta notes:

- `runs/benchmark_not_so_smart_1773865588_post_step32/*` for the pre-Step-34 delta

## Environment Note

- Completed with no mode timeouts (`0/25` for all modes).
- Same runtime/meta split scoring pipeline was used for all modes.
- The benchmark tables below still summarize raw benchmark artifacts. The CLI and JSON outputs now default to a lower-noise surfaced finding set, while preserving raw findings separately for scoring and debugging.

## Aggregate Comparison

| Mode | Runs OK | Timeouts | Contracts With Findings | Total Findings | Unique Finding Types |
| --- | ---: | ---: | ---: | ---: | ---: |
| `--static` | 25/25 | 0 | 25/25 | 744 | 41 |
| `--symbolic` | 25/25 | 0 | 25/25 | 812 | 20 |
| `--fuzzing` | 25/25 | 0 | 25/25 | 879 | 22 |
| `--hybrid` | 25/25 | 0 | 23/25 | 140 | 22 |

## Runtime vs Meta Split

| Mode | Total Findings | Runtime Findings | Meta Findings |
| --- | ---: | ---: | ---: |
| `--static` | 744 | 744 | 0 |
| `--symbolic` | 812 | 144 | 668 |
| `--fuzzing` | 879 | 211 | 668 |
| `--hybrid` | 140 | 129 | 11 |

## Runtime Cost

| Mode | Total Wall-Clock | Median Per Contract |
| --- | ---: | ---: |
| `--static` | 880 ms | 14 ms |
| `--symbolic` | 449,515 ms | 8,120 ms |
| `--fuzzing` | 262,832 ms | 2,651 ms |
| `--hybrid` | 262,549 ms | 2,436 ms |

## Benchmark-Relative Metrics (Runtime Primary, All 25)

| Mode | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `--static` | 27 | 1 | 21 | 0.964 | 0.562 | 0.711 |
| `--symbolic` | 25 | 0 | 23 | 1.000 | 0.521 | 0.685 |
| `--fuzzing` | 28 | 0 | 20 | 1.000 | 0.583 | 0.737 |
| `--hybrid` | 27 | 0 | 21 | 1.000 | 0.562 | 0.720 |

## Benchmark-Relative Metrics (Runtime Primary, Core Set)

Core set excludes honeypots and `ReentrancyExploit.sol`.

| Mode | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `--static` | 18 | 1 | 16 | 0.947 | 0.529 | 0.679 |
| `--symbolic` | 18 | 0 | 16 | 1.000 | 0.529 | 0.692 |
| `--fuzzing` | 21 | 0 | 13 | 1.000 | 0.618 | 0.764 |
| `--hybrid` | 20 | 0 | 14 | 1.000 | 0.588 | 0.741 |

## Top Runtime-Primary FP Kinds (Core)

| Mode | Top FP kinds |
| --- | --- |
| `--static` | `storage-array-by-value`(1) |
| `--symbolic` | `none` |
| `--fuzzing` | `none` |
| `--hybrid` | `none` |

## Reviewed-Truth Coverage (Runtime Primary, 26 issues)

| Mode | Hits | Misses | Coverage |
| --- | ---: | ---: | ---: |
| `--static` | 26 | 0 | 1.000 |
| `--symbolic` | 25 | 1 | 0.962 |
| `--fuzzing` | 25 | 1 | 0.962 |
| `--hybrid` | 25 | 1 | 0.962 |

Coverage is recall against the reviewed issue list. It does not penalize extra bug kinds.

## Reviewed-Truth Strict Metrics (Runtime Primary, Closest Proxy to Pure Accuracy)

True TN-based accuracy is not meaningful here because the space of possible extra bug kinds is open-ended. The strict reviewed-truth score below is the closest current proxy to "real state" because it penalizes both misses and extra predicted bug kinds:

`strict_score = hits / (hits + misses + extra_kinds)`

| Mode | Hits | Misses | Extra Kinds | Precision | Recall | F1 | Strict Score |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `--static` | 26 | 0 | 12 | 0.684 | 1.000 | 0.813 | 0.684 |
| `--symbolic` | 25 | 1 | 2 | 0.926 | 0.962 | 0.943 | 0.893 |
| `--fuzzing` | 25 | 1 | 7 | 0.781 | 0.962 | 0.862 | 0.758 |
| `--hybrid` | 25 | 1 | 0 | 1.000 | 0.962 | 0.980 | 0.962 |

## Interpretation

- Relative to `post_step32`, the Step 34 batch improved the reviewed-truth runtime-primary accuracy in every mode:
  - static strict score: `0.658 -> 0.684`
  - symbolic strict score: `0.862 -> 0.893`
  - fuzzing strict score: `0.735 -> 0.758`
  - hybrid strict score: `0.833 -> 0.962`
- The highest-value fixes in this batch were:
  - static recovery of `PrivateBank.sol` `CashOut()` reentrancy
  - suppression of the exploit-helper `ReentrancyExploit.sol` `unprotected-selfdestruct` runtime false positive in symbolic, fuzzing, and hybrid
  - removal of the hybrid `uninit-permission-check` carryover on takeover fixtures
- The closest current proxy to pure bug-level accuracy remains above the requested `0.60` threshold for all four modes:
  - static strict score: `0.684`
  - symbolic strict score: `0.893`
  - fuzzing strict score: `0.758`
  - hybrid strict score: `0.962`
- Benchmark-relative false positives are now zero in every dynamic mode:
  - static: `1` FP kind total, on `incorrect_interface/Alice.sol` via `storage-array-by-value`
  - symbolic: `0` FP kinds total
  - fuzzing: `0` FP kinds total
  - hybrid: `0` FP kinds total
- Remaining reviewed-truth misses are now minimal:
  - static: none
  - symbolic: `Bob.sol` incorrect-interface
  - fuzzing: `Bob.sol` incorrect-interface
  - hybrid: `Bob.sol` incorrect-interface
- Remaining reviewed-truth extra kinds are now:
  - static: `list_dos.sol` `dos-block-gas-limit`, `VarLoop.sol` `integer-overflow`, `Alice.sol` `storage-array-by-value`, plus helper-side extras on `ReentrancyExploit.sol` and `SpankChain.sol`
  - symbolic: `theRun.sol` `timestamp-dependency`, `list_dos.sol` `dos-block-gas-limit`
  - fuzzing: the same two plus `SpankChain.sol` helper noise
  - hybrid: none
- Benchmark-relative `runtime_primary` F1 is no longer perfectly aligned with reviewed-truth accuracy:
  - hybrid all-25 F1 moved `0.744 -> 0.720`
  - hybrid strict score moved `0.833 -> 0.962`
  - this is the expected tradeoff from removing helper-style runtime carryover that the benchmark package used to reward but the reviewed truth does not count as real target bugs
