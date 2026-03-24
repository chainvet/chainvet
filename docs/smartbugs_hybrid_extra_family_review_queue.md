# SmartBugs Hybrid Extra-Family Review Queue

Date: 2026-03-24

Purpose:

- explain why hybrid precision is lower than its strongest recall numbers suggest
- build a concrete review queue for the cases where hybrid catches the benchmark family and also predicts extra families
- separate:
  - real unlabeled secondary bugs
  - genuine tool noise

Primary artifacts:

- `runs/benchmark_smartbugs_hybrid_vs_tools_shared141_t30/score/official_per_contract.json`
- `runs/benchmark_smartbugs_hybrid_vs_tools_shared141_t30/score/summary.json`
- `fixtures/ground_truth/smartbugs_reviewed_overlay.json`
- `docs/smartbugs_extra_findings_audit.md`

## Why Hybrid Precision Looks Low

Official family-level precision for hybrid is:

- `102 TP`
- `170 FP`
- `39 FN`
- precision `0.375`
- recall `0.723`

But those numbers can be misleading if read as "hybrid mostly fails". The main pattern is different:

- hybrid often catches the benchmark family in a file
- then it also predicts extra families on the same file
- benchmark scoring counts those extras as false positives unless they are present in the reviewed overlay

That is why hybrid can still have very high family recall on some categories:

- `reentrancy`: `31/32`
- `arithmetic`: `21/23`
- `bad_randomness`: `28/31`
- `denial_of_service`: `7/7`

while still taking a precision hit from extra families.

## Mixed-Case Totals

Files where hybrid had both at least one true positive family and at least one extra family:

- `63` mixed cases

Top extra-family buckets inside those mixed cases:

- `access_control`: `41`
- `unchecked_low_level_calls`: `28`
- `reentrancy`: `23`
- `denial_of_service`: `10`
- `arithmetic`: `8`
- `front_running`: `4`
- `time_manipulation`: `2`
- `bad_randomness`: `1`
- `other`: `1`

This means the next audit pass should start with:

1. `access_control`
2. `unchecked_low_level_calls`
3. `reentrancy`

## Review Method

For each mixed case:

1. Keep the official benchmark family fixed.
2. Review each extra family against the source.
3. Label each extra family as one of:
   - `confirmed_unlabeled_tp`
   - `likely_unlabeled_tp`
   - `unclear`
   - `confirmed_fp`
4. If the extra family is real, add it to the reviewed overlay.
5. If the extra family is not real, keep it as precision debt and use it to guide detector fixes.

## Priority Queue

### Tier 1: Highest Extra-Family Count

#### `Benchmarks/smartbugs-curated/dataset/access_control/rubixi.sol`

- Official family: `access_control`
- Hybrid predicted:
  - `access_control`
  - `arithmetic`
  - `denial_of_service`
  - `reentrancy`
  - `unchecked_low_level_calls`
- Extra families:
  - `arithmetic`
  - `denial_of_service`
  - `reentrancy`
  - `unchecked_low_level_calls`

#### `Benchmarks/smartbugs-curated/dataset/denial_of_service/list_dos.sol`

- Official family: `denial_of_service`
- Hybrid predicted:
  - `access_control`
  - `denial_of_service`
  - `reentrancy`
  - `time_manipulation`
  - `unchecked_low_level_calls`
- Extra families:
  - `access_control`
  - `reentrancy`
  - `time_manipulation`
  - `unchecked_low_level_calls`

#### `Benchmarks/smartbugs-curated/dataset/time_manipulation/governmental_survey.sol`

- Official family: `time_manipulation`
- Hybrid predicted:
  - `access_control`
  - `arithmetic`
  - `reentrancy`
  - `time_manipulation`
  - `unchecked_low_level_calls`
- Extra families:
  - `access_control`
  - `arithmetic`
  - `reentrancy`
  - `unchecked_low_level_calls`

#### `Benchmarks/smartbugs-curated/dataset/unchecked_low_level_calls/0xb620cee6b52f96f3c6b253e6eea556aa2d214a99.sol`

- Official family: `unchecked_low_level_calls`
- Hybrid predicted:
  - `access_control`
  - `arithmetic`
  - `front_running`
  - `reentrancy`
  - `unchecked_low_level_calls`
- Extra families:
  - `access_control`
  - `arithmetic`
  - `front_running`
  - `reentrancy`

### Tier 2: High-Value Mixed Cases Already Mentioned In Prior Audits

#### `Benchmarks/smartbugs-curated/dataset/access_control/FibonacciBalance.sol`

- Official family: `access_control`
- Hybrid predicted:
  - `access_control`
  - `denial_of_service`
  - `reentrancy`
  - `unchecked_low_level_calls`
- Extra families:
  - `denial_of_service`
  - `reentrancy`
  - `unchecked_low_level_calls`

#### `Benchmarks/smartbugs-curated/dataset/access_control/wallet_02_refund_nosub.sol`

- Official family: `access_control`
- Hybrid predicted:
  - `access_control`
  - `arithmetic`
  - `reentrancy`
  - `unchecked_low_level_calls`
- Extra families:
  - `arithmetic`
  - `reentrancy`
  - `unchecked_low_level_calls`

#### `Benchmarks/smartbugs-curated/dataset/access_control/wallet_03_wrong_constructor.sol`

- Official family: `access_control`
- Hybrid predicted:
  - `access_control`
  - `arithmetic`
  - `reentrancy`
  - `unchecked_low_level_calls`
- Extra families:
  - `arithmetic`
  - `reentrancy`
  - `unchecked_low_level_calls`

#### `Benchmarks/smartbugs-curated/dataset/bad_randomness/etheraffle.sol`

- Official family: `bad_randomness`
- Hybrid predicted:
  - `access_control`
  - `bad_randomness`
  - `denial_of_service`
  - `reentrancy`
- Extra families:
  - `access_control`
  - `denial_of_service`
  - `reentrancy`

#### `Benchmarks/smartbugs-curated/dataset/bad_randomness/lottery.sol`

- Official family: `bad_randomness`
- Hybrid predicted:
  - `access_control`
  - `bad_randomness`
  - `denial_of_service`
  - `unchecked_low_level_calls`
- Extra families:
  - `access_control`
  - `denial_of_service`
  - `unchecked_low_level_calls`

#### `Benchmarks/smartbugs-curated/dataset/bad_randomness/smart_billions.sol`

- Official family: `bad_randomness`
- Hybrid predicted:
  - `bad_randomness`
  - `denial_of_service`
  - `reentrancy`
  - `unchecked_low_level_calls`
- Extra families:
  - `denial_of_service`
  - `reentrancy`
  - `unchecked_low_level_calls`

#### `Benchmarks/smartbugs-curated/dataset/reentrancy/etherstore.sol`

- Official family: `reentrancy`
- Hybrid predicted:
  - `arithmetic`
  - `denial_of_service`
  - `reentrancy`
  - `unchecked_low_level_calls`
- Extra families:
  - `arithmetic`
  - `denial_of_service`
  - `unchecked_low_level_calls`

#### `Benchmarks/smartbugs-curated/dataset/reentrancy/spank_chain_payment.sol`

- Official family: `reentrancy`
- Hybrid predicted:
  - `access_control`
  - `denial_of_service`
  - `other`
  - `reentrancy`
- Extra families:
  - `access_control`
  - `denial_of_service`
  - `other`

#### `Benchmarks/smartbugs-curated/dataset/unchecked_low_level_calls/0x89c1b3807d4c67df034fffb62f3509561218d30b.sol`

- Official family: `unchecked_low_level_calls`
- Hybrid predicted:
  - `access_control`
  - `arithmetic`
  - `reentrancy`
  - `unchecked_low_level_calls`
- Extra families:
  - `access_control`
  - `arithmetic`
  - `reentrancy`

#### `Benchmarks/smartbugs-curated/dataset/unchecked_low_level_calls/king_of_the_ether_throne.sol`

- Official family: `unchecked_low_level_calls`
- Hybrid predicted:
  - `access_control`
  - `front_running`
  - `reentrancy`
  - `unchecked_low_level_calls`
- Extra families:
  - `access_control`
  - `front_running`
  - `reentrancy`

#### `Benchmarks/smartbugs-curated/dataset/front_running/eth_tx_order_dependence_minimal.sol`

- Official family: `front_running`
- Hybrid predicted:
  - `access_control`
  - `front_running`
  - `unchecked_low_level_calls`
- Extra families:
  - `access_control`
  - `unchecked_low_level_calls`

### Tier 3: Repeating Reentrancy Pattern

These files repeatedly show:

- official family: `reentrancy`
- hybrid prediction: `reentrancy` plus `access_control` and `unchecked_low_level_calls`

Examples:

- `Benchmarks/smartbugs-curated/dataset/reentrancy/0x01f8c4e3fa3edeb29e514cba738d87ce8c091d3f.sol`
- `Benchmarks/smartbugs-curated/dataset/reentrancy/0x23a91059fdc9579a9fbd0edc5f2ea0bfdb70deb4.sol`
- `Benchmarks/smartbugs-curated/dataset/reentrancy/0x4320e6f8c05b27ab4707cd1f6d5ce6f3e4b3a5a1.sol`
- `Benchmarks/smartbugs-curated/dataset/reentrancy/0x4e73b32ed6c35f570686b89848e5f39f20ecc106.sol`
- `Benchmarks/smartbugs-curated/dataset/reentrancy/0x561eac93c92360949ab1f1403323e6db345cbf31.sol`

These should be reviewed together because the extra-family pattern is likely coming from one shared heuristic rather than five independent source truths.

## Expected Output Of The Next Audit Pass

For each reviewed file, add a short verdict table:

| File | Extra Family | Verdict | Reason |
| --- | --- | --- | --- |

Then:

- add confirmed unlabeled true positives to `fixtures/ground_truth/smartbugs_reviewed_overlay.json`
- keep confirmed false positives out of the overlay
- use the false-positive cluster to guide detector refinement

## Status

- Queue closed.
- All `63` hybrid mixed cases from the current shared SmartBugs run have now been reviewed in `docs/smartbugs_extra_findings_audit.md`.
- Confirmed source-real extra families were promoted into `fixtures/ground_truth/smartbugs_reviewed_overlay.json`.
- Remaining extra families from the mixed-case set should currently be treated as real tool noise until detector behavior changes.
