# Not-so-smart Benchmark Comparison (4 Modes)

Date: 2026-03-18
Dataset: `Benchmarks/Not-so-smart/not-so-smart-contracts-master` (25 contracts)

Analysis artifacts used:

- `runs/benchmark_not_so_smart_1773789016_post_step26/summary.tsv`
- `runs/benchmark_not_so_smart_1773789016_post_step26/aggregate_metrics.json`
- `runs/benchmark_not_so_smart_1773789016_post_step26/fp_analysis/summary_all.json`
- `runs/benchmark_not_so_smart_1773789016_post_step26/fp_analysis/summary_core.json`
- `runs/benchmark_not_so_smart_1773789016_post_step26/reviewed_truth_analysis/summary.json`

Reference baseline for delta notes:

- `runs/benchmark_not_so_smart_1773773952_post_step24/*`

## Environment Note

- Completed with no mode timeouts (`0/25` for all modes).
- Same runtime/meta split scoring pipeline was used for all modes.

## Aggregate Comparison

| Mode | Runs OK | Timeouts | Contracts With Findings | Sum Findings | Unique Finding Types |
| --- | ---: | ---: | ---: | ---: | ---: |
| `--static` | 25/25 | 0 | 25/25 | 733 | 34 |
| `--symbolic` | 25/25 | 0 | 19/25 | 177 | 38 |
| `--fuzzing` | 25/25 | 0 | 24/25 | 246 | 39 |
| `--hybrid` | 25/25 | 0 | 24/25 | 144 (unique) | 23 |

## Runtime vs Meta Split

| Mode | Contracts With Runtime Findings | Contracts With Meta Findings | Runtime Findings | Meta Findings |
| --- | ---: | ---: | ---: | ---: |
| `--static` | 25 | 0 | 733 | 0 |
| `--symbolic` | 19 | 25 | 177 | 596 |
| `--fuzzing` | 24 | 25 | 246 | 596 |
| `--hybrid` | 22 | 10 | 134 (unique) | 10 (unique) |

## Runtime Cost

| Mode | Total Wall-Clock | Median Per Contract |
| --- | ---: | ---: |
| `--static` | 735 ms | 13 ms |
| `--symbolic` | 437,056 ms | 8,117 ms |
| `--fuzzing` | 89,552 ms | 698 ms |
| `--hybrid` | 108,580 ms | 2,409 ms |

## Benchmark-Relative Metrics (Runtime Primary, All 25)

| Mode | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `--static` | 18 | 27 | 30 | 0.400 | 0.375 | 0.387 |
| `--symbolic` | 17 | 10 | 31 | 0.630 | 0.354 | 0.453 |
| `--fuzzing` | 20 | 22 | 28 | 0.476 | 0.417 | 0.444 |
| `--hybrid` | 21 | 16 | 27 | 0.568 | 0.438 | 0.494 |

## Benchmark-Relative Metrics (Runtime Primary, Core Set)

Core set excludes honeypots and `ReentrancyExploit.sol`.

| Mode | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `--static` | 16 | 4 | 18 | 0.800 | 0.471 | 0.593 |
| `--symbolic` | 16 | 2 | 18 | 0.889 | 0.471 | 0.615 |
| `--fuzzing` | 18 | 4 | 16 | 0.818 | 0.529 | 0.643 |
| `--hybrid` | 19 | 0 | 15 | 1.000 | 0.559 | 0.717 |

## Top Runtime-Primary FP Kinds (Core)

| Mode | Top FP kinds |
| --- | --- |
| `--static` | `storage-array-by-value`(3), `missing-input-validation`(1) |
| `--symbolic` | `access-control`(1), `reentrancy`(1) |
| `--fuzzing` | `unchecked-call`(2), `unprotected-ether-withdrawal`(2) |
| `--hybrid` | `none` |

## Reviewed-Truth Coverage (Runtime Primary, 26 issues)

| Mode | Hits | Misses | Coverage |
| --- | ---: | ---: | ---: |
| `--static` | 18 | 8 | 0.692 |
| `--symbolic` | 16 | 10 | 0.615 |
| `--fuzzing` | 18 | 8 | 0.692 |
| `--hybrid` | 18 | 8 | 0.692 |

Coverage is recall against the reviewed issue list. It does not penalize extra bug kinds.

## Reviewed-Truth Strict Metrics (Runtime Primary, Closest Proxy to Pure Accuracy)

True TN-based accuracy is not meaningful here because the space of possible extra bug kinds is open-ended. The strict reviewed-truth score below is the closest current proxy to "real state" because it penalizes both misses and extra predicted bug kinds:

`strict_score = hits / (hits + misses + extra_kinds)`

| Mode | Hits | Misses | Extra Kinds | Precision | Recall | F1 | Strict Score |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `--static` | 18 | 8 | 37 | 0.327 | 0.692 | 0.444 | 0.286 |
| `--symbolic` | 16 | 10 | 18 | 0.471 | 0.615 | 0.533 | 0.364 |
| `--fuzzing` | 18 | 8 | 35 | 0.340 | 0.692 | 0.456 | 0.295 |
| `--hybrid` | 18 | 8 | 27 | 0.400 | 0.692 | 0.507 | 0.340 |

## Interpretation

- Runtime-primary reviewed-truth strict score improved across every mode versus `post_step24`:
  - static: `0.200 -> 0.286`
  - symbolic: `0.283 -> 0.364`
  - fuzzing: `0.221 -> 0.295`
  - hybrid: `0.260 -> 0.340`
- Runtime-primary reviewed-truth hits also improved across every mode:
  - static: `15 -> 18`
  - symbolic: `13 -> 16`
  - fuzzing: `15 -> 18`
  - hybrid: `13 -> 18`
- Static benefited the most from the constructor-name / authority-initialization cleanup:
  - all-25 F1: `0.294 -> 0.387`
  - core F1: `0.400 -> 0.593`
  - `theRun.sol` no longer emits a spurious constructor-style `uninit-permission-check`
  - `Rubixi.sol` recovered `uninit-permission-check` without reopening the `theRun.sol` false positive
- Symbolic remains the cleanest pure runtime engine by strict score, but recall is still capped by misses on:
  - `timestamp-dependency`
  - `dos-block-gas-limit`
  - `unused-return-value`
  - `shadowing`
  - the non-runtime honeypot families
- Fuzzing’s strict score improved even though benchmark-relative all-25 F1 dipped slightly:
  - all-25 F1: `0.449 -> 0.444`
  - strict score: `0.221 -> 0.295`
  - the drop comes from finding more true reviewed issues while still carrying extra runtime kinds on honeypots and payout-management functions
- Hybrid is now the best balanced runtime mode on this benchmark:
  - all-25 F1: `0.341 -> 0.494`
  - core F1: `0.456 -> 0.717`
  - core runtime-primary FP: `10 -> 0`
  - reviewed-truth strict score: `0.260 -> 0.340`
- The focused modifier/constructor pass removed the generic `theRun.sol` runtime noise that was previously polluting symbolic, fuzzing, and hybrid:
  - no more `access-control`
  - no more `arbitrary-write`
  - no more constructor-style `uninit-permission-check`
- Biggest remaining runtime-primary blockers:
  - `timestamp-dependency` on `theRun.sol`
  - `dos-block-gas-limit` on `auction.sol` and non-hybrid `list_dos.sol`
  - `unused-return-value` on `KingOfTheEtherThrone.sol`
  - `Unprotected.sol` secondary issue recovery
  - `WalletLibrary.sol` full takeover-path recovery in hybrid
  - `shadowing`, `incorrect-interface`, and honeypot families, which remain mostly meta-oriented or benchmark-specific
