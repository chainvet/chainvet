# Benchmarks

This folder is the local benchmark registry for the analyzer.

The existing benchmark paths are kept stable on purpose. Several scripts and docs already reference them directly, so this index organizes the tree without renaming the legacy roots.

Downloaded archives that are not part of the active source tree should live under `Benchmarks/_archives/`.

## Active benchmark scope

The current default benchmark scope is `fse2024`.

- Scope selector: `Benchmarks/benchmark_scope.json`
- Active manifest: `Benchmarks/FSE2024/benchmark_manifest.json`
- Target enumerator: `python3 scripts/list_fse_benchmark_targets.py`
- 4-approach default manifest: `Benchmarks/FSE2024/all_approaches_manifest.json`

Only the FSE 2024 benchmark suites should be used for default benchmarking unless a task explicitly opts into supplemental scenario or stress corpora.

When comparing all four analyzer approaches together, the default target set should be only:

- `Not-so-smart`
- `smartbugs-curated`

That narrower default is encoded in `Benchmarks/FSE2024/all_approaches_manifest.json` and can be selected with:

```bash
python3 scripts/list_fse_benchmark_targets.py --preset all-approaches --format summary
```

## FSE default accuracy suites

These are the suites included by the active FSE benchmark manifest:

| Suite | Local path | Role | Local size signal |
| --- | --- | --- | --- |
| Not-so-smart | `Benchmarks/Not-so-smart/not-so-smart-contracts-master` | Small curated regression benchmark | `25` Solidity files |
| SmartBugs Curated | `Benchmarks/smartbugs-curated/dataset` | Curated benchmark families | `143` Solidity files |
| SolidiFI Benchmark | `Benchmarks/SolidiFI-benchmark/buggy_contracts` | Injected bug benchmark | `350` Solidity files |
| SCRUBD | `Benchmarks/SCRUBD` | Labeled reentrancy / unhandled-exception dataset | `485` Solidity files |
| Web3Bugs | `Benchmarks/Web3Bugs` | Real-world exploitable bug dataset | `6564` Solidity files |
| Smart-Contract-Benchmark-Suites | `Benchmarks/Smart-Contract-Benchmark-Suites/dataset` | Broad benchmark collection | `46186` Solidity files |
| DAppSCAN | `Benchmarks/DAppSCAN` | Audit-report-grounded real-world corpus | `21457` Solidity files |

## Exploit and scenario suites

These are strong complements to the default accuracy suites. They are useful for exploitability, multi-step scenarios, DeFi patterns, and regression tests for runtime engines.

| Suite | Local path | Role | Local size signal |
| --- | --- | --- | --- |
| sb-heists | `Benchmarks/sb-heists` | Exploit coverage for SmartBugs Curated | `240` Solidity files |
| SCONE-bench | `Benchmarks/SCONE-bench` | Historical exploit benchmark and metadata | manifest-focused |
| DeFiVulnLabs | `Benchmarks/DeFiVulnLabs` | Compact modern vulnerability labs | `57` Solidity files |
| Damn Vulnerable DeFi | `Benchmarks/Damn-Vulnerable-DeFi` | Realistic DeFi challenge scenarios | `73` Solidity files |
| Ethernaut | `Benchmarks/Ethernaut` | Historical hack levels and training corpus | `417` Solidity files |

## Specialized suites

These are valuable, but should usually be scored separately because they focus on narrower domains or different evaluation goals.

| Suite | Local path | Role | Local size signal |
| --- | --- | --- | --- |
| USCHunt | `Benchmarks/USCHunt` | Upgradeable proxy / upgradeability corpus | `59074` Solidity files |
| FSE2024 alignment files | `Benchmarks/FSE2024` | Scope notes, exclusions, and BNB address list | `2941` addresses in `BNB-OFFICIAL.csv` |

## Recommended evaluation split

Use the benchmark tree in three layers:

1. Accuracy:
   `Not-so-smart`, `smartbugs-curated`, `SolidiFI-benchmark`, `SCRUBD`, `Web3Bugs`, and selected slices of `DAppSCAN`
2. Runtime scenario and exploit realism:
   `sb-heists`, `SCONE-bench`, `DeFiVulnLabs`, `Damn-Vulnerable-DeFi`, `Ethernaut`
3. Specialized stress:
   `USCHunt` for upgradeability and proxy behavior

## Exclusions and scope notes

- FSE 2024 scope notes and exclusions are recorded in `Benchmarks/FSE2024/`.
- `honeypot` is retired from the analyzer and should stay excluded from FSE 2024-aligned scoring.
- `SCONE-bench` is intentionally kept even though it is manifest-heavy, because it is useful for exploit-replay and exploitability evaluation.

## Not pulled by default

These are useful later for scale or false-positive stress, but they are intentionally not part of the default local benchmark tree because they are either huge, weakly labeled, or better treated as stress corpora than truth sets:

- `smartbugs-wild`
- `smart-contract-sanctuary`
- `verified-smart-contracts`
- `slither-audited-smart-contracts`

## Machine-readable catalog

See `Benchmarks/catalog.csv` for a flat index with categories, paths, counts, and intended use.
