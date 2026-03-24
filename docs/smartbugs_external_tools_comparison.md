# SmartBugs Hybrid vs External Tools

Date: 2026-03-24

Benchmark contracts: `141`

Tools: `hybrid`, `Slither`, `Smartcheck`, `Securify2`, `Mythril`, `Manticore`

Compatibility-excluded fixtures for this shared subset:

- `Benchmarks/smartbugs-curated/dataset/access_control/parity_wallet_bug_1.sol`: SmartBugs external-tool task collection requires exact solc 0.4.9 for this fixture, but the bundled solcx path cannot provide that compiler on this host.

## Fair-Comparison Status

Fair ranking excludes tools that were not comparable on this corpus under the current harness, while the raw equal-budget appendix still records what they actually returned.

| Tool | Status | Included In Fair Ranking | Notes |
| --- | --- | --- | --- |
| `hybrid` | `comparable` | yes | usable results on the shared benchmark subset |
| `slither` | `comparable` | yes | usable results on the shared benchmark subset |
| `smartcheck` | `comparable` | yes | usable results on the shared benchmark subset |
| `securify2` | `incompatible_corpus` | no | declared support starts at Solidity >= 0.5.8, but the selected subset contains 0/141 compatible contracts |
| `mythril` | `comparable` | yes | usable results on the shared benchmark subset |
| `manticore` | `budget_exhausted` | no | 0/141 tasks produced usable findings under the equal-budget harness; 98 timed out, 38 hit symbolic execution failures, and 28 finished empty |

## Tool-Tuned Manticore Pilot

I tested whether a best-effort `manticore` lane would materially improve the comparison before spending a full rerun on the 141-contract shared subset.

Pilot settings:

- timeout: `120s` per contract
- parallelism: `1`
- memory limit: `4g`

Pilot artifacts:

- single-file pilot: `runs/manticore_tuned_pilot`
- mixed 5-file pilot: `runs/manticore_tuned_pilot5`

Pilot files:

- `Benchmarks/smartbugs-curated/dataset/access_control/simple_suicide.sol`
- `Benchmarks/smartbugs-curated/dataset/access_control/phishable.sol`
- `Benchmarks/smartbugs-curated/dataset/reentrancy/reentrancy_simple.sol`
- `Benchmarks/smartbugs-curated/dataset/reentrancy/reentrancy_insecure.sol`
- `Benchmarks/smartbugs-curated/dataset/unchecked_low_level_calls/unchecked_return_value.sol`

Pilot outcome:

- `manticore` still produced `0` parsed findings
- single-file `simple_dao.sol` pilot: solver failure after `59.218s`
- mixed 5-file pilot: `0/5` usable finding sets
- mixed pilot failure shape:
  - `1` timeout
  - `1` explicit symbolic-execution failure bucket
  - `1` clean empty result
  - remaining tasks completed but still emitted no benchmark-mappable findings

Conclusion:

- I did not promote `manticore` to a full tool-tuned rerun on all `141` contracts.
- On this host and SmartBugs toolchain, a larger budget makes `manticore` run longer, but it still does not produce enough parsed output to become a fair, informative baseline.

## Speed Metrics

Speed is reported for all tools that were run. Non-comparable tools are still shown here because runtime is factual even when the accuracy result should not be ranked.

| Tool | Timed Contracts | Total Contract Time (s) | Avg / Contract (s) | Median (s) | P95 (s) | Max (s) | Approx Wall Time (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `hybrid` | 141 | 3128.727 | 22.190 | 8.275 | 121.467 | 139.805 | 3128.727 |
| `slither` | 141 | 90.533 | 0.642 | 0.567 | 0.743 | 4.432 | 22.901 |
| `smartcheck` | 141 | 252.823 | 1.793 | 1.743 | 2.165 | 3.714 | 64.051 |
| `securify2` | 141 | 62.700 | 0.445 | 0.428 | 0.529 | 0.783 | 15.948 |
| `mythril` | 141 | 3574.190 | 25.349 | 29.407 | 40.355 | 40.438 | 916.883 |
| `manticore` | 141 | 4340.972 | 30.787 | 40.271 | 40.354 | 40.414 | 1105.263 |

## Official Truth Metrics (Fair Ranking)

| Tool | TP | FP | FN | Precision | Recall | F1 | Issue Coverage | File Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `hybrid` | 101 | 124 | 40 | 0.449 | 0.716 | 0.552 | 149/204 (0.730) | 101/141 (0.716) |
| `slither` | 98 | 267 | 43 | 0.268 | 0.695 | 0.387 | 129/204 (0.632) | 98/141 (0.695) |
| `smartcheck` | 89 | 193 | 52 | 0.316 | 0.631 | 0.421 | 114/204 (0.559) | 89/141 (0.631) |
| `mythril` | 61 | 124 | 80 | 0.330 | 0.433 | 0.374 | 70/204 (0.343) | 61/141 (0.433) |

## Official Truth Metrics (Raw Equal-Budget Appendix)

| Tool | TP | FP | FN | Precision | Recall | F1 | Issue Coverage | File Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `hybrid` | 101 | 124 | 40 | 0.449 | 0.716 | 0.552 | 149/204 (0.730) | 101/141 (0.716) |
| `slither` | 98 | 267 | 43 | 0.268 | 0.695 | 0.387 | 129/204 (0.632) | 98/141 (0.695) |
| `smartcheck` | 89 | 193 | 52 | 0.316 | 0.631 | 0.421 | 114/204 (0.559) | 89/141 (0.631) |
| `securify2` | 0 | 0 | 141 | 0.000 | 0.000 | 0.000 | 0/204 (0.000) | 0/141 (0.000) |
| `mythril` | 61 | 124 | 80 | 0.330 | 0.433 | 0.374 | 70/204 (0.343) | 61/141 (0.433) |
| `manticore` | 0 | 0 | 141 | 0.000 | 0.000 | 0.000 | 0/204 (0.000) | 0/141 (0.000) |

## Reviewed-Adjusted Metrics (Fair Ranking)

| Tool | TP | FP | FN | Precision | Recall | F1 | Issue Coverage | File Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `hybrid` | 114 | 111 | 49 | 0.507 | 0.699 | 0.588 | 162/226 (0.717) | 92/141 (0.652) |
| `slither` | 106 | 259 | 57 | 0.290 | 0.650 | 0.402 | 137/226 (0.606) | 86/141 (0.610) |
| `smartcheck` | 98 | 184 | 65 | 0.348 | 0.601 | 0.440 | 123/226 (0.544) | 79/141 (0.560) |
| `mythril` | 64 | 121 | 99 | 0.346 | 0.393 | 0.368 | 73/226 (0.323) | 59/141 (0.418) |

## Reviewed-Adjusted Metrics (Raw Equal-Budget Appendix)

| Tool | TP | FP | FN | Precision | Recall | F1 | Issue Coverage | File Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `hybrid` | 114 | 111 | 49 | 0.507 | 0.699 | 0.588 | 162/226 (0.717) | 92/141 (0.652) |
| `slither` | 106 | 259 | 57 | 0.290 | 0.650 | 0.402 | 137/226 (0.606) | 86/141 (0.610) |
| `smartcheck` | 98 | 184 | 65 | 0.348 | 0.601 | 0.440 | 123/226 (0.544) | 79/141 (0.560) |
| `securify2` | 0 | 0 | 163 | 0.000 | 0.000 | 0.000 | 0/226 (0.000) | 0/141 (0.000) |
| `mythril` | 64 | 121 | 99 | 0.346 | 0.393 | 0.368 | 73/226 (0.323) | 59/141 (0.418) |
| `manticore` | 0 | 0 | 163 | 0.000 | 0.000 | 0.000 | 0/226 (0.000) | 0/141 (0.000) |

## Official Labeled-Line Overlap

| Tool | Truth Issues | Located Predictions | Line Matches | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `hybrid` | 204 | 95 | 38 | 0.400 | 0.186 | 0.254 |
| `slither` | 204 | 1706 | 115 | 0.067 | 0.564 | 0.120 |
| `smartcheck` | 204 | 1417 | 96 | 0.068 | 0.471 | 0.118 |
| `securify2` | 204 | 0 | 0 | 0.000 | 0.000 | 0.000 |
| `mythril` | 204 | 249 | 52 | 0.209 | 0.255 | 0.230 |
| `manticore` | 204 | 0 | 0 | 0.000 | 0.000 | 0.000 |
