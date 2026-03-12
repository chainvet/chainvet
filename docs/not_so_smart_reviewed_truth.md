# Not-so-smart Reviewed Truth Set

Date: 2026-03-11

## Counting Rule

This is a manual, source-reviewed baseline for the 25 Solidity files in `Benchmarks/Not-so-smart/not-so-smart-contracts-master`.

I count:

- one issue per materially distinct vulnerable behavior or root cause
- zero issues for helper/exploit contracts that are not themselves vulnerable targets
- honeypot traps as real issues when the contract is intentionally deceptive or structurally malicious

I do not count:

- every repeated omitted-visibility warning
- every repeated low-signal pattern occurrence
- incidental style warnings that are not the core exploitable behavior

Under this rule, the reviewed baseline is:

- `26` validated issue instances across `25` files

Machine-readable artifact:

- `fixtures/ground_truth/not_so_smart_reviewed_truth.json`

Scorer:

```bash
python3 scripts/score_not_so_smart_reviewed_truth.py \
  runs/benchmark_not_so_smart_1773235777_taxonomy_complete/summary.tsv
```

Safe/helper files in this review:

- `Benchmarks/Not-so-smart/not-so-smart-contracts-master/reentrancy/ReentrancyExploit.sol`: exploit helper, not the vulnerable target
- `Benchmarks/Not-so-smart/not-so-smart-contracts-master/reentrancy/SpankChain_source_code/SpankChain.sol`: preserved safe contract, not the hacked payment contract

## Reviewed Issues

| File | Count | Reviewed issues |
| --- | ---: | --- |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/bad_randomness/theRun_source_code/theRun.sol` | 2 | bad randomness in `random()`, unchecked-send payout/fee flow |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/denial_of_service/auction.sol` | 1 | push-refund DoS in `DosAuction.bid()` |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/denial_of_service/list_dos.sol` | 2 | revert-based bulk refund DoS in `refundDos()`, still-griefable payout in `refundSafe()` |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/forced_ether_reception/coin.sol` | 1 | forced-Ether invariant break in `migrate_and_destroy()` |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/honeypots/GiftBox/GiftBox.sol` | 1 | honeypot trap |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/honeypots/KOTH/KOTH.sol` | 1 | honeypot via owner shadowing / broken authority |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/honeypots/Lottery/Lottery.sol` | 1 | honeypot via uninitialized storage-pointer style state corruption |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/honeypots/Multiplicator/Multiplicator.sol` | 1 | honeypot via impossible `this.balance` branch |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/honeypots/PrivateBank/PrivateBank.sol` | 2 | honeypot trap, reentrancy in `CashOut()` |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/honeypots/VarLoop/VarLoop.sol` | 1 | honeypot via `var`-inferred narrow integer loop/payout bug |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/incorrect_interface/Bob.sol` | 1 | incorrect interface signature mismatch with `Alice.sol` |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/integer_overflow/integer_overflow_1.sol` | 1 | integer overflow in `add()` |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/race_condition/RaceCondition.sol` | 1 | transaction-order dependency in `buy()` / `changePrice()` |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/reentrancy/DAO_source_code/DAO.sol` | 2 | reentrancy in `splitDAO()`, reentrancy in reward-withdrawal path |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/reentrancy/Reentrancy.sol` | 1 | reentrancy in `withdrawBalance()` |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/reentrancy/ReentrancyExploit.sol` | 0 | exploit helper only |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/reentrancy/SpankChain_source_code/SpankChain.sol` | 0 | not the vulnerable contract |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/reentrancy/SpankChain_source_code/SpankChain_Payment.sol` | 1 | reentrancy in `LCOpenTimeout()` |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/unchecked_external_call/KotET_source_code/KingOfTheEtherThrone.sol` | 1 | unchecked external-call/send family in throne claim/refund flow |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/unprotected_function/Unprotected.sol` | 1 | unprotected `changeOwner()` |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/unprotected_function/WalletLibrary_source_code/WalletLibrary.sol` | 1 | public `initWallet()` reinitialization / ownership takeover |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/variable shadowing/inherited_state.sol` | 1 | inherited state shadowing breaks intended owner check |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/wrong_constructor_name/Rubixi_source_code/Rubixi.sol` | 1 | wrong constructor name `DynamicPyramid()` |
| `Benchmarks/Not-so-smart/not-so-smart-contracts-master/wrong_constructor_name/incorrect_constructor.sol` | 1 | wrong constructor name `IamMissing()` |

## Coverage Against Reviewed Truth

Scored against the latest run artifacts in `runs/benchmark_not_so_smart_1773235777_taxonomy_complete/summary.tsv`.

Generated artifacts:

- `runs/benchmark_not_so_smart_1773235777_taxonomy_complete/reviewed_truth_analysis/summary.json`
- `runs/benchmark_not_so_smart_1773235777_taxonomy_complete/reviewed_truth_analysis/per_contract.json`
- `runs/benchmark_not_so_smart_1773235777_taxonomy_complete/reviewed_truth_analysis/per_issue_matrix.tsv`

Hit rule:

- a mode gets credit for an issue only if it surfaced a finding type that matches the reviewed root cause for that file
- repeated extra findings do not increase score

| Mode | Hits | Misses | Coverage |
| --- | ---: | ---: | ---: |
| `--static` | 8 | 18 | 30.8% |
| `--symbolic` | 12 | 14 | 46.2% |
| `--fuzzing` | 15 | 11 | 57.7% |
| `--hybrid` | 15 | 11 | 57.7% |

## Interpretation

- The honest denominator is nowhere near `742` or `800`.
- On this reviewed baseline, the benchmark contains about `26` materially distinct issues, not hundreds.
- The large raw finding totals in the engine outputs are mostly repeated warnings, auxiliary patterns, or taxonomy-completion rows, not separate validated vulnerabilities.
