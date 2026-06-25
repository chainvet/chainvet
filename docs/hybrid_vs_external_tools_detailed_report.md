# Hybrid Vs External Tools Detailed Report

Date: 2026-03-25

This document compares the current repository's `hybrid` mode against the external tools used in the SmartBugs study lane:

- `Slither`
- `Smartcheck`
- `Securify2`
- `Mythril`
- `Manticore`

The current detailed benchmark source in the repository is:

- `docs/smartbugs_external_tools_comparison.md`

## Benchmark Scope

Current shared SmartBugs subset:

- `141` contracts

Compatibility-excluded fixture for this shared subset:

- `Benchmarks/smartbugs-curated/dataset/access_control/parity_wallet_bug_1.sol`
  - exact `solc 0.4.9` requirement could not be satisfied in the SmartBugs external-tool harness on this host

Truth sources used:

1. official SmartBugs truth:
   - `Benchmarks/smartbugs-curated/vulnerabilities.json`
2. reviewed-adjusted truth:
   - `fixtures/ground_truth/smartbugs_reviewed_overlay.json`

So the benchmark is intentionally reported in two ways:

- strict official truth
- reviewed-adjusted truth that credits audited unlabeled true positives

## Fair-Comparison Status

Not every tool result should be ranked in the same way.

| Tool | Status | Included In Fair Ranking | Reason |
| --- | --- | --- | --- |
| `hybrid` | `comparable` | yes | usable results on the shared subset |
| `slither` | `comparable` | yes | usable results on the shared subset |
| `smartcheck` | `comparable` | yes | usable results on the shared subset |
| `mythril` | `comparable` | yes | usable results on the shared subset |
| `securify2` | `incompatible_corpus` | no | declared support starts at Solidity `>= 0.5.8`, but the shared subset contains `0/141` compatible contracts |
| `manticore` | `budget_exhausted` | no | equal-budget harness produced `0/141` usable finding sets; tuned pilot still produced no useful parsed findings |

This matters for honesty. `Securify2` and `Manticore` are still reported in the raw appendix, but they should not be ranked as ordinary zero-score losers under this specific harness/corpus combination.

## Speed Metrics

The current runtime picture is:

| Tool | Avg / Contract (s) | Median (s) | P95 (s) | Max (s) | Approx Wall Time (s) |
| --- | ---: | ---: | ---: | ---: | ---: |
| `hybrid` | `22.190` | `8.275` | `121.467` | `139.805` | `3128.727` |
| `slither` | `0.642` | `0.567` | `0.743` | `4.432` | `22.901` |
| `smartcheck` | `1.793` | `1.743` | `2.165` | `3.714` | `64.051` |
| `securify2` | `0.445` | `0.428` | `0.529` | `0.783` | `15.948` |
| `mythril` | `25.349` | `29.407` | `40.355` | `40.438` | `916.883` |
| `manticore` | `30.787` | `40.271` | `40.354` | `40.414` | `1105.263` |

Interpretation:

- `slither` is by far the fastest meaningful baseline
- `smartcheck` is also very fast
- `hybrid` is much slower than static baselines, but still meaningfully faster end-to-end than a useful `manticore` lane would likely be
- `mythril` is slower than `slither`/`smartcheck` and weaker on this subset

## Official Truth Metrics

Fair-ranking view:

| Tool | TP | FP | FN | Precision | Recall | F1 | Issue Coverage | File Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `hybrid` | `101` | `124` | `40` | `0.449` | `0.716` | `0.552` | `149/204 (0.730)` | `101/141 (0.716)` |
| `slither` | `98` | `267` | `43` | `0.268` | `0.695` | `0.387` | `129/204 (0.632)` | `98/141 (0.695)` |
| `smartcheck` | `89` | `193` | `52` | `0.316` | `0.631` | `0.421` | `114/204 (0.559)` | `89/141 (0.631)` |
| `mythril` | `61` | `124` | `80` | `0.330` | `0.433` | `0.374` | `70/204 (0.343)` | `61/141 (0.433)` |

Key result:

- `hybrid` is the best comparable tool on official-truth F1

## Reviewed-Adjusted Metrics

Fair-ranking view:

| Tool | TP | FP | FN | Precision | Recall | F1 | Issue Coverage | File Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `hybrid` | `114` | `111` | `49` | `0.507` | `0.699` | `0.588` | `162/226 (0.717)` | `92/141 (0.652)` |
| `slither` | `106` | `259` | `57` | `0.290` | `0.650` | `0.402` | `137/226 (0.606)` | `86/141 (0.610)` |
| `smartcheck` | `98` | `184` | `65` | `0.348` | `0.601` | `0.440` | `123/226 (0.544)` | `79/141 (0.560)` |
| `mythril` | `64` | `121` | `99` | `0.346` | `0.393` | `0.368` | `73/226 (0.323)` | `59/141 (0.418)` |

Why this matters:

- the reviewed overlay prevents audited unlabeled true positives from unfairly counting as false positives
- even after that correction, `hybrid` remains clearly strongest on F1

## Official Labeled-Line Overlap

| Tool | Truth Issues | Located Predictions | Line Matches | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `hybrid` | `204` | `95` | `38` | `0.400` | `0.186` | `0.254` |
| `slither` | `204` | `1706` | `115` | `0.067` | `0.564` | `0.120` |
| `smartcheck` | `204` | `1417` | `96` | `0.068` | `0.471` | `0.118` |
| `securify2` | `204` | `0` | `0` | `0.000` | `0.000` | `0.000` |
| `mythril` | `204` | `249` | `52` | `0.209` | `0.255` | `0.230` |
| `manticore` | `204` | `0` | `0` | `0.000` | `0.000` | `0.000` |

Interpretation:

- `hybrid` is much more conservative in located predictions than `slither` and `smartcheck`
- `slither` and `smartcheck` locate many more lines, but with very low strict precision
- `mythril` is stronger than `hybrid` on strict line precision-to-recall balance than the huge static baselines, but weaker overall on category/file-level effectiveness

## Why `Securify2` And `Manticore` Look Like Zeros

### `Securify2`

`Securify2` is not a meaningful zero on this specific corpus. It is an incompatibility case.

Reason:

- the shared SmartBugs subset is overwhelmingly old Solidity
- the harness-compatible subset contains `0/141` contracts at Solidity `>= 0.5.8`
- `Securify2` therefore has no genuinely compatible contracts in this lane

So its zero is better read as:

- incompatible on this corpus

not:

- inherently useless

### `Manticore`

`Manticore` is a different case.

Its issue here is not corpus-version compatibility. It is practical usefulness under the harness:

- many timeouts
- symbolic execution failures
- empty completions
- even a tuned pilot still produced no parsed benchmark-mappable findings

So its current status is better read as:

- budget-exhausted
- not producing usable benchmark output under this setup

## What The Comparison Says Overall

The detailed comparison supports the following conclusions:

1. `hybrid` is the strongest comparable tool in this project's current SmartBugs lane.
2. `slither` remains the strongest external baseline in the fair ranking, especially given its speed.
3. `smartcheck` is a credible faster baseline, but below `hybrid` and below `slither` on recall.
4. `mythril` is slower and weaker than `hybrid` in this lane.
5. `Securify2` and `Manticore` should not be oversold or misread:
   - `Securify2` was not comparable on this corpus
   - `Manticore` was not practically informative under the benchmark budget
