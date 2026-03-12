# Not-so-smart Benchmark Comparison (4 Modes)

Date: 2026-03-11  
Dataset: `Benchmarks/Not-so-smart/not-so-smart-contracts-master` (25 contracts)

Analysis artifacts used:

- `runs/benchmark_not_so_smart_1773235777_taxonomy_complete/summary.tsv`
- `runs/benchmark_not_so_smart_1773235777_taxonomy_complete/aggregate_metrics.json`
- `runs/benchmark_not_so_smart_1773235777_taxonomy_complete/fp_analysis/summary_all.json`
- `runs/benchmark_not_so_smart_1773235777_taxonomy_complete/fp_analysis/summary_core.json`
- `runs/benchmark_not_so_smart_1773235777_taxonomy_complete/fp_analysis/top_fp_core_*.tsv`

## Environment Note

- This run completed with no mode timeouts (`0/25` for all modes).
- Binary execution was measured after a single pre-build, so runtime numbers below exclude compile time.
- Standalone `--symbolic` and `--fuzzing` now include taxonomy-completion `meta` findings in addition to native runtime findings.

## Aggregate Comparison

| Mode | Runs OK | Timeouts | Contracts With Findings | Sum Findings | Unique Finding Types |
| --- | ---: | ---: | ---: | ---: | ---: |
| `--static` | 25/25 | 0 | 25/25 | 685 | 30 |
| `--symbolic` | 25/25 | 0 | 24/25 | 537 | 33 |
| `--fuzzing` | 25/25 | 0 | 24/25 | 554 | 35 |
| `--hybrid` | 25/25 | 0 | 25/25 | 742 (unique) | 37 |

## Runtime vs Meta Split

This table is important now that symbolic and fuzzing expose exact taxonomy rows via `meta` findings.

| Mode | Contracts With Runtime Findings | Contracts With Meta Findings | Runtime Findings | Meta Findings |
| --- | ---: | ---: | ---: | ---: |
| `--static` | 25 | 0 | 685 | 0 |
| `--symbolic` | 18 | 24 | 56 | 481 |
| `--fuzzing` | 18 | 24 | 73 | 481 |
| `--hybrid` | 25 | 9 | 733 (unique) | 9 (unique) |

Hybrid-specific notes:

- `runtime_findings_total = 75,067` observed runtime finding events before dedup.
- `runtime_findings_unique = 733`
- `meta_findings_unique = 9`
- `se_assists = 9`
- `seeds_injected_by_se = 57`

## Runtime Cost

| Mode | Total Wall-Clock | Median Per Contract |
| --- | ---: | ---: |
| `--static` | 896 ms | 37 ms |
| `--symbolic` | 55,295 ms | 43 ms |
| `--fuzzing` | 18,052 ms | 306 ms |
| `--hybrid` | 55,217 ms | 2,132 ms |

## False-Positive (FP) Analysis

Method used here is benchmark-label mismatch, not exploit-level proof.

- Each contract gets an expected vulnerability family from benchmark category.
- Findings are canonically normalized before scoring:
  - `underflow` -> `integer-underflow`
  - `hardcoded-gas` -> `hardcoded-gas-transfer`
  - `storage-memory-issue` -> `memory-manipulation`
- For this rerun, symbolic and fuzzing are scored on their surfaced output, which now includes runtime plus `meta` taxonomy-completion findings.

### FP/TP/FN Metrics (All 25 Contracts)

| Mode | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `--static` | 11 | 131 | 62 | 0.077 | 0.151 | 0.102 |
| `--symbolic` | 19 | 127 | 54 | 0.130 | 0.260 | 0.174 |
| `--fuzzing` | 22 | 133 | 51 | 0.142 | 0.301 | 0.193 |
| `--hybrid` | 23 | 151 | 50 | 0.132 | 0.315 | 0.186 |

### FP/TP/FN Metrics (Core Set)

Core set excludes honeypots and `ReentrancyExploit.sol` to reduce benchmark-label ambiguity.

| Mode | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `--static` | 9 | 98 | 45 | 0.084 | 0.167 | 0.112 |
| `--symbolic` | 12 | 95 | 42 | 0.112 | 0.222 | 0.149 |
| `--fuzzing` | 15 | 97 | 39 | 0.134 | 0.278 | 0.181 |
| `--hybrid` | 15 | 109 | 39 | 0.121 | 0.278 | 0.169 |

### Top FP Kinds (Core Set)

| Mode | Top FP kinds |
| --- | --- |
| `--static` | `default-visibility`(14), `shadowing`(11), `storage-array-by-value`(11), `integer-overflow`(7), `tainted-call`(6), `hardcoded-gas-transfer`(5), `integer-underflow`(5), `missing-input-validation`(5) |
| `--symbolic` | `default-visibility`(14), `storage-array-by-value`(11), `integer-overflow`(7), `arbitrary-write`(6), `hardcoded-gas-transfer`(5), `integer-underflow`(5), `locked-ether`(5), `missing-input-validation`(5) |
| `--fuzzing` | `default-visibility`(14), `storage-array-by-value`(11), `integer-overflow`(7), `integer-underflow`(6), `hardcoded-gas-transfer`(5), `locked-ether`(5), `missing-input-validation`(5), `arbitrary-write`(4) |
| `--hybrid` | `default-visibility`(14), `shadowing`(11), `storage-array-by-value`(11), `integer-overflow`(7), `tainted-call`(6), `hardcoded-gas-transfer`(5), `integer-underflow`(5), `missing-input-validation`(5) |

## Interpretation

- Static still dominates raw runtime breadth because it emits many AST-level and detector-level findings directly.
- Symbolic and fuzzing now cover much more of the benchmark at the surfaced-output level because they expose taxonomy-completion `meta` findings.
- Runtime-only dynamic detection is still much smaller than surfaced-output detection:
  - symbolic: `56 runtime` vs `481 meta`
  - fuzzing: `73 runtime` vs `481 meta`
- Fuzzing now has the best benchmark-relative F1 in this rerun (`0.193` on all contracts, `0.181` on the core set).
- Hybrid has the best recall on all contracts (`0.315`) but not the best F1, because it carries static-style breadth and therefore more benchmark-mismatch FP.

## Important Caveat

These FP numbers are benchmark-relative FP against each contract's primary benchmark family. They are not semantic proof that every extra finding is a true false alarm in absolute terms.

They also now reflect surfaced engine output, not only native runtime detection, for `--symbolic` and `--fuzzing`.
