# FSE 2024 Benchmark Alignment

This folder records the benchmark scope described on the FSE 2024 SC-SAST study website:

- Benchmark construction:
  `https://sites.google.com/view/sc-sast-study-fse2024/benchmark-construction?authuser=0`
- Evaluation data:
  `https://sites.google.com/view/sc-sast-study-fse2024/evaluation-data`

## Local benchmark suites

The repository now contains the benchmark sources referenced by that website:

- `Benchmarks/Not-so-smart/not-so-smart-contracts-master`
- `Benchmarks/Smart-Contract-Benchmark-Suites`
- `Benchmarks/smartbugs-curated`
- `Benchmarks/SolidiFI-benchmark`
- `Benchmarks/FSE2024/BNB-OFFICIAL.csv`

The active local default benchmark scope for the repository is now defined by:

- `Benchmarks/benchmark_scope.json`
- `Benchmarks/FSE2024/benchmark_manifest.json`
- `Benchmarks/FSE2024/all_approaches_manifest.json`
- `scripts/list_fse_benchmark_targets.py`

That manifest currently includes only the FSE 2024 source suites:

- `Benchmarks/Not-so-smart/not-so-smart-contracts-master`
- `Benchmarks/Smart-Contract-Benchmark-Suites/dataset`
- `Benchmarks/smartbugs-curated/dataset`
- `Benchmarks/SolidiFI-benchmark/buggy_contracts`

Useful commands:

```bash
python3 scripts/list_fse_benchmark_targets.py --format summary
python3 scripts/list_fse_benchmark_targets.py --preset all-approaches --format summary
python3 scripts/list_fse_benchmark_targets.py --suite not-so-smart --format paths
python3 scripts/list_fse_benchmark_targets.py --suite solidifi-benchmark --format json
```

Default policy for four-way comparisons:

- if comparing `static + symbolic + fuzzing + hybrid` together, use `--preset all-approaches`
- that preset intentionally includes only `Not-so-smart` plus `smartbugs-curated`

`BNB-OFFICIAL.csv` is the file currently provided by the Google Drive link on the benchmark-construction page. It contains `2941` BNB contract addresses, not a Solidity source archive.

## Paper-aligned exclusions

The benchmark-construction page explicitly excludes:

- `6` Not-so-smart contracts under `Benchmarks/Not-so-smart/not-so-smart-contracts-master/honeypots/`
  Reason: `honeypot` is treated there as an outdated vulnerability type.
- `50` SolidiFI contracts under `Benchmarks/SolidiFI-benchmark/buggy_contracts/Unhandled-Exceptions/`
  Reason: `Unhandled Exceptions` is treated there as code quality, not an in-scope vulnerability family.
- `1` SmartBugs-curated contract at `Benchmarks/smartbugs-curated/dataset/short_addresses/short_address_example.sol`
  Reason: `short addresses` is treated there as an obsolete vulnerability type.

The concrete exclusion list is in `Benchmarks/FSE2024/exclusions.csv`.

## Tool-side note

For our analyzer, the only clearly matching outdated family that was surfaced here was `honeypot`.

- `honeypot` has been removed from the current analyzer and should stay excluded from any FSE 2024-aligned benchmark scoring.
- `short-address` does not currently appear as a dedicated analyzer finding family, so there is no tool-side detector to disable.
- `unchecked-call` or `exception-disorder` should not be globally excluded just because SolidiFI has an `Unhandled-Exceptions` folder. The paper only excludes that specific benchmark subset, not every call-return misuse issue in general.
