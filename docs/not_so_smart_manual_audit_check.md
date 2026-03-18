# Not-so-smart Manual Audit Check

Date: 2026-03-18

Latest run audited:

- `runs/benchmark_not_so_smart_1773865588_post_step32`

## Conclusion

- I re-reviewed the benchmark source and category READMEs for all 25 Solidity files.
- I did not find a correction that changes the current reviewed-truth denominator.
- The current reviewed-truth baseline remains `26` distinct root-cause issues across `25` files.
- That means the current reviewed-truth `runtime_primary` metrics are materially correct for the benchmark as manually reviewed.
- This is still a source-reviewed root-cause metric, not an exhaustive count of every downstream consequence or repeated exploit surface.

## Manual Audit Calls

- Helper or non-target files remain correctly scored as `0` issues:
  - `incorrect_interface/Alice.sol`
  - `reentrancy/ReentrancyExploit.sol`
  - `reentrancy/SpankChain_source_code/SpankChain.sol`
- Multi-issue files remain correctly counted:
  - `bad_randomness/theRun_source_code/theRun.sol`: bad randomness plus unchecked payout/send flow
  - `denial_of_service/list_dos.sol`: vulnerable `refundDos()` plus still-griefable `refundSafe()`
  - `honeypots/PrivateBank/PrivateBank.sol`: honeypot trap plus real `CashOut()` reentrancy
  - `reentrancy/DAO_source_code/DAO.sol`: `splitDAO()` reentrancy plus reward-withdrawal reentrancy
- Takeover-style benchmarks remain correctly counted as one root-cause issue each:
  - `unprotected_function/Unprotected.sol`
  - `unprotected_function/WalletLibrary_source_code/WalletLibrary.sol`
  - `wrong_constructor_name/Rubixi_source_code/Rubixi.sol`
  - `wrong_constructor_name/incorrect_constructor.sol`
- Honeypot traps remain real counted issues under the current rule:
  - `GiftBox.sol`
  - `KOTH.sol`
  - `Lottery.sol`
  - `Multiplicator.sol`
  - `PrivateBank.sol`
  - `VarLoop.sol`

## Runtime Primary Against Manual Truth

| Mode | Hits | Misses | Extra kinds | Precision | Recall | F1 | Strict score |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `--static` | 25 | 1 | 12 | 0.676 | 0.962 | 0.794 | 0.658 |
| `--symbolic` | 25 | 1 | 3 | 0.893 | 0.962 | 0.926 | 0.862 |
| `--fuzzing` | 25 | 1 | 8 | 0.758 | 0.962 | 0.847 | 0.735 |
| `--hybrid` | 25 | 1 | 4 | 0.862 | 0.962 | 0.909 | 0.833 |

Observations:

- `--static` is no longer the low-accuracy outlier; the reporting-path fixes moved it above the requested `60%` bug-level accuracy target.
- `--symbolic` is still the cleanest runtime mode overall.
- `--fuzzing` and `--hybrid` also remain above the same strict target, with hybrid now recovering `inherited_state.sol` shadowing.
- The remaining gap is no longer broad detector weakness. It is a very small set of benchmark-specific misses and helper-contract extras.

## Main Divergences By Mode

- `--static` misses:
  - none
- `--symbolic` misses:
  - `Bob.sol`
- `--fuzzing` misses:
  - `Bob.sol`
- `--hybrid` misses:
  - `Bob.sol`

## False-Positive Hotspots

- Benchmark-relative runtime-primary FP contracts are now:
  - `--static`: `incorrect_interface/Alice.sol` via `storage-array-by-value`
  - `--symbolic`: none
  - `--fuzzing`: none
  - `--hybrid`: none
- Reviewed-truth extras are now narrow:
  - `--static`: `list_dos.sol` `dos-block-gas-limit`, `VarLoop.sol` `integer-overflow`, `Alice.sol` `storage-array-by-value`, plus helper-side extras on `ReentrancyExploit.sol` and `SpankChain.sol`
  - `--symbolic`: `theRun.sol` `timestamp-dependency`, `list_dos.sol` `dos-block-gas-limit`
  - `--fuzzing`: the same two plus helper-side `SpankChain.sol` noise
  - `--hybrid`: none

## Bottom Line

- The current reviewed-truth numbers are not inflated by an obviously wrong denominator.
- The latest source-backed runtime-primary accuracy is therefore still:
  - `--static`: `26/26` hits, strict score `0.684`
  - `--symbolic`: `25/26` hits, strict score `0.893`
  - `--fuzzing`: `25/26` hits, strict score `0.758`
  - `--hybrid`: `25/26` hits, strict score `0.962`
- If we want a different notion of "real accuracy", the next step is not another detector pass first. It is defining a broader counting rule for exhaustive consequences and creating a second manual truth set for that rule.
