# SmartBugs Extra Findings Audit

Date: 2026-03-24

Scope:

- Spot-audit of representative SmartBugs "false positives" from the current scored run
- Goal: determine whether the official `vulnerabilities.json` is exhaustive enough to treat every extra finding as a real false positive

Artifacts examined:

- `runs/benchmark_smartbugs_curated_1774302347_all4_default/smartbugs_score/per_contract.json`
- `runs/benchmark_smartbugs_curated_1774302347_all4_default/raw/*`
- `Benchmarks/smartbugs-curated/vulnerabilities.json`
- benchmark source files under `Benchmarks/smartbugs-curated/dataset/`

## Conclusion

- No, not all SmartBugs precision penalties are "real" false positives.
- The official `vulnerabilities.json` is a benchmark-intent label set, not an exhaustive audit of every vulnerability family in every contract.
- A meaningful subset of our extra findings are plausible real secondary issues that the benchmark does not count.
- But a meaningful subset are also genuine overfires or taxonomy drift, especially broad `access_control`, `front_running`, and some runtime backstops like helper-style `reentrancy` or `unprotected-selfdestruct`.

## Audited Examples

### 1. `front_running/FindThisHash.sol`

Official label:

- `front_running`

Observed extra finding:

- static surfaced `access_control` via `unprotected-ether-withdrawal`

Assessment:

- This looks like a real false positive.
- The contract is intentionally a public bounty claim contract:
  - `solve(string solution)` is supposed to be callable by anyone who knows the preimage
  - paying `msg.sender` is the intended behavior, not an access-control flaw

Bottom line:

- This extra finding should count as tool noise, not a real unlabeled benchmark bug.

### 2. `other/open_address_lottery.sol`

Official label:

- `other` (uninitialized storage in `forceReseed`)

Observed extra findings:

- symbolic surfaced `bad_randomness` and `access_control`
- fuzzing surfaced `bad_randomness`, `time_manipulation`, `front_running`, `reentrancy`, `arithmetic`, `access_control`

Assessment:

- `bad_randomness` is a real unlabeled issue here.
- The contract clearly uses miner-influenced values in randomness-related logic:
  - `block.coinbase`
  - `block.difficulty`
  - `block.timestamp`
  - `blockhash`
- So benchmark scoring treats `bad_randomness` as a false positive here, but source-wise it is a defensible secondary bug family.
- `access_control` via `unprotected-selfdestruct` is not a real bug here:
  - `kill()` is guarded by `require(msg.sender == owner)`
- The fuzzing-side `reentrancy` and `arithmetic` extras on this file look much weaker and are likely noise/backstop spillover rather than real target issues.

Bottom line:

- This file is a clean example of mixed behavior:
  - some "false positives" are real unlabeled issues
  - others are genuine tool overfires

### 3. `access_control/FibonacciBalance.sol`

Official label:

- `access_control`

Observed extra findings:

- static surfaced `arithmetic`, `denial_of_service`, `unchecked_low_level_calls`

Assessment:

- `arithmetic` is plausibly a real unlabeled issue.
- The library Fibonacci computation is unchecked Solidity `<0.8` arithmetic:
  - recursive `fibonacci(n - 1) + fibonacci(n - 2)`
  - payout uses `calculatedFibNumber * 1 ether`
- Those are credible overflow sites that the official benchmark does not count because the benchmark intent is access control via delegatecall.
- `denial_of_service` on the push-payment path is also defensible:
  - `msg.sender.transfer(...)` can fail and block progress
- `unchecked_low_level_calls` is less convincing on this file, because the benchmark source uses `require(fibonacciLibrary.delegatecall(...))`, so that part looks closer to overbroad classification than a real extra bug.

Bottom line:

- At least part of the precision penalty on this file is benchmark under-labeling, not tool error.

### 4. `access_control/rubixi.sol`

Official label:

- `access_control`

Observed extra findings:

- symbolic surfaced `arithmetic`, `denial_of_service`, `reentrancy`, `unchecked_low_level_calls`
- fuzzing surfaced `arithmetic`, `denial_of_service`, `unchecked_low_level_calls`

Assessment:

- `unchecked_low_level_calls` is plausibly real and unlabeled.
- The contract ignores `send()` return values in multiple places:
  - payout path in `addPayout`
  - fee collection paths like `collectAllFees`, `collectFeesInEther`, `collectPercentOfFees`
- That is a legitimate unchecked-call / exception-disorder family even though SmartBugs only labels the wrong-constructor takeover.
- `denial_of_service` is also plausible on the payout loop that mixes sends with queue advancement.
- `reentrancy` on this file is much less clear and looks more like an aggressive backstop than a clearly source-backed second bug.

Bottom line:

- This file is another example where SmartBugs undercounts real secondary issues.

### 5. `access_control/parity_wallet_bug_1.sol`

Official label:

- `access_control`

Observed extra findings:

- symbolic surfaced `arithmetic`, `reentrancy`, `unchecked_low_level_calls`

Assessment:

- `unchecked_low_level_calls` and `unsafe-delegatecall` are plausible real secondary issues here.
- The wallet code contains low-level `call` and delegatecall-heavy behavior, and the benchmark intentionally labels the public reinitialization path rather than every unsafe interaction pattern.
- `reentrancy` is less certain and likely over-reported in our current symbolic backstop path.

Bottom line:

- At least some of the extra precision penalty on Parity-style wallets is probably benchmark incompleteness, not pure noise.

### 6. `bad_randomness/lottery.sol`

Official label:

- `bad_randomness`

Observed extra findings:

- symbolic surfaced `access_control` and `unchecked_low_level_calls`

Assessment:

- These extras do not look strong.
- `destroy()` is guarded by `if (msg.sender != organizer) { throw; }`, so `unprotected-selfdestruct` is not a real additional issue.
- The payout path uses `if(!msg.sender.send(msg.value)) { throw; }`, so the send result is checked; that makes `unchecked-call` a weak classification here.

Bottom line:

- This file is a good example of genuine benchmark-relative false positives that should stay counted against precision.

## Overall Takeaway

- SmartBugs precision, as currently measured against `vulnerabilities.json`, is a pessimistic estimate of "real" precision.
- The main reason is that SmartBugs usually labels the benchmark's intended vulnerability family, not every additional issue family present in the same contract.
- But the gap is not entirely benchmark under-labeling:
  - some extra categories are clearly real unlabeled issues
  - some are clearly tool overfires
- So the correct interpretation is:
  - SmartBugs official precision is useful
  - but it is not the same thing as a fully source-reviewed real-world precision metric

## Practical Implication

- We should not treat every SmartBugs FP as a definite real false positive.
- We also should not discard the precision penalty entirely.
- The best next step, if we want a more honest "real precision" number, is a reviewed-truth pass for a selected subset of high-FP SmartBugs contracts, similar to what we did for Not-so-smart.

## Tier 1 Follow-Up Audit

This pass reviewed four of the highest-value hybrid mixed cases from the external-tools run and decided whether the extra families should be accepted into reviewed truth.

### 7. `denial_of_service/list_dos.sol`

Official label:

- `denial_of_service`

Hybrid extra families:

- `access_control`
- `reentrancy`
- `time_manipulation`
- `unchecked_low_level_calls`

Assessment:

- `unchecked_low_level_calls` is a real unlabeled issue.
- The contract repeatedly ignores `send()` return values in important payout paths:
  - refund on crash at line `37`
  - profit payout at lines `39-40`
  - fee distribution at lines `62`, `70`, and `75`
  - refund path at line `82`
- `access_control` does not hold up. `inheritToNextGeneration` is explicitly guarded by `if (msg.sender == corruptElite)`.
- `reentrancy` does not hold up. The contract uses `send()`, not a reentrancy-capable callback primitive with meaningful stateful reentry risk.
- `time_manipulation` is too weak here. The logic uses a broad twelve-hour threshold, not a miner-sensitive near-boundary condition worth accepting as a real secondary bug.

Bottom line:

- Add `unchecked_low_level_calls` to the reviewed overlay.
- Keep the other hybrid extras counted as noise.

### 8. `time_manipulation/governmental_survey.sol`

Official label:

- `time_manipulation`

Hybrid extra families:

- `access_control`
- `arithmetic`
- `reentrancy`
- `unchecked_low_level_calls`

Assessment:

- `access_control` does not hold up:
  - `owner` is set once in the constructor at line `18`
  - there is no public owner-reset or public privileged takeover path
- `reentrancy` does not hold up:
  - the payout path uses `send()` at lines `34-35`
  - that gives only the fixed stipend and is not a convincing reentrancy sink here
- `arithmetic` does not hold up:
  - there is no credible attacker-controlled overflow/underflow path worth accepting as a real secondary issue
- `unchecked_low_level_calls` is a real unlabeled issue:
  - `lastInvestor.send(jackpot)` at line `34`
  - `owner.send(this.balance-1 ether)` at line `35`
  - both ignore the boolean result and therefore fit the unchecked-call family cleanly

Bottom line:

- Add `unchecked_low_level_calls` to the reviewed overlay.
- Keep `access_control`, `arithmetic`, and `reentrancy` counted as noise.

### 9. `unchecked_low_level_calls/0xb620cee6b52f96f3c6b253e6eea556aa2d214a99.sol`

Official label:

- `unchecked_low_level_calls`

Hybrid extra families:

- `access_control`
- `arithmetic`
- `front_running`
- `reentrancy`

Assessment:

- `access_control` is a real unlabeled issue.
- The contract name is `DrainMe` at line `14`, but the would-be constructor is `DranMe()` at line `32`.
- That makes `DranMe()` an ordinary public function, so any caller can seize `owner` by calling it.
- This is a textbook wrong-constructor-name takeover and should count as an additional `access_control` issue.
- `arithmetic` does not hold up as a reviewed addition from this source pass.
- `front_running` does not hold up. The file has blockhash-based randomness and bad ownership, but not a convincing transaction-order dependency worth accepting.
- `reentrancy` does not hold up. The real issue family here is unchecked external calls, not a convincing state-after-call reentrancy flaw.

Bottom line:

- Add `access_control` to the reviewed overlay.
- Keep the other hybrid extras counted as noise.

### 10. `access_control/rubixi.sol`

Official label:

- `access_control`

Hybrid extra families:

- `arithmetic`
- `denial_of_service`
- `reentrancy`
- `unchecked_low_level_calls`

Assessment:

- `denial_of_service` remains accepted:
  - the payout loop at lines `72-78` can be griefed and is already part of the reviewed overlay
- `unchecked_low_level_calls` remains accepted:
  - ignored `send()` results appear at lines `74`, `85`, `95`, and `103`
- `reentrancy` does not hold up:
  - the contract uses `send()` rather than a reentrancy-capable low-level call with meaningful post-call mutation risk
- `arithmetic` is still not strong enough to promote in this overlay pass:
  - the file contains unchecked old-Solidity math, but the current source review did not establish a strong enough exploit-relevant secondary bug to count it as reviewed truth

Bottom line:

- Keep the existing overlay entries for this file.
- Do not add `arithmetic` or `reentrancy`.

### 11. `access_control/wallet_02_refund_nosub.sol`

Official label:

- `access_control`

Hybrid extra families:

- `arithmetic`
- `reentrancy`
- `unchecked_low_level_calls`

Assessment:

- None of the extras are strong enough to accept.
- `arithmetic` does not hold up:
  - the `assert` in `deposit()` is a defensive overflow check, not a convincing independent arithmetic bug
- `reentrancy` does not hold up:
  - both `withdraw()` and `refund()` use `transfer()`, not a reentrancy-capable low-level call
- `unchecked_low_level_calls` does not hold up:
  - `transfer()` reverts on failure and does not silently drop a boolean result

Bottom line:

- Keep this file unchanged in the reviewed overlay.
- Treat the hybrid extras on this file as false positives.

### 12. `access_control/wallet_03_wrong_constructor.sol`

Official label:

- `access_control`

Hybrid extra families:

- `arithmetic`
- `reentrancy`
- `unchecked_low_level_calls`

Assessment:

- None of the extras are strong enough to accept.
- `arithmetic` does not hold up:
  - again, the `assert` in `deposit()` is a defensive check rather than a second benchmark-worthy arithmetic flaw
- `reentrancy` does not hold up:
  - the Ether sends use `transfer()`
- `unchecked_low_level_calls` does not hold up:
  - there is no ignored boolean-returning low-level interaction here

Bottom line:

- Keep this file unchanged in the reviewed overlay.
- Treat the hybrid extras on this file as false positives.

### 13. `bad_randomness/etheraffle.sol`

Official label:

- `bad_randomness`

Hybrid extra families:

- `access_control`
- `denial_of_service`
- `reentrancy`

Assessment:

- `denial_of_service` is a real unlabeled issue.
- `endRaffle()` loops over contestants and executes `contestants[i].addr.transfer(pricePerTicket)` at line `150`.
- A reverting recipient can block the admin refund routine for the whole raffle, which is a real failed-call DOS pattern.
- `access_control` does not hold up:
  - `endRaffle()`, `togglePause()`, and `kill()` are all guarded by `if (msg.sender == feeAddress)`
- `reentrancy` does not hold up:
  - the contract uses `transfer()`, not a reentrancy-capable pattern worth promoting into reviewed truth

Bottom line:

- Add `denial_of_service` to the reviewed overlay.
- Keep `access_control` and `reentrancy` counted as noise.

### 14. `reentrancy/0x01f8c4e3fa3edeb29e514cba738d87ce8c091d3f.sol`

Official label:

- `reentrancy`

Hybrid extra families:

- `access_control`
- `unchecked_low_level_calls`

Assessment:

- `access_control` is a real unlabeled issue.
- The contract exposes public initialization-style functions with no owner gate:
  - `SetMinSum()` at lines `19-24`
  - `SetLogFile()` at lines `26-31`
  - `Initialized()` at lines `33-37`
- Any caller can set critical configuration before `intitalized` flips, which is a real permission problem beyond the official reentrancy bug.
- `unchecked_low_level_calls` does not hold up:
  - the external Ether send in `Collect()` is checked with `if (msg.sender.call.value(_am)())`
  - the remaining external interaction to `Log.AddMessage()` is not an ignored boolean-returning low-level call

Bottom line:

- Add `access_control` to the reviewed overlay.
- Keep `unchecked_low_level_calls` counted as noise.

### 15. `bad_randomness/smart_billions.sol`

Official label:

- `bad_randomness`

Hybrid extra families:

- `denial_of_service`
- `reentrancy`
- `unchecked_low_level_calls`

Assessment:

- None of these extras are strong enough to accept into reviewed truth.
- `reentrancy` does not hold up:
  - the payment path uses `transfer()` in `pay()` at lines `372` and `382`
  - `payWallet()` zeroes the caller's wallet balance before calling `pay()`
- `unchecked_low_level_calls` does not hold up:
  - the reviewed source pass did not find ignored boolean-returning low-level call sites in the relevant payout logic
- `denial_of_service` is not strong enough for overlay promotion:
  - there are loops in accounting code, but this review did not establish a clear exploit-grade failed-call DOS or locked-funds condition comparable to the accepted overlay cases

Bottom line:

- Keep this file unchanged in the reviewed overlay.
- Treat the hybrid extras on this file as false positives for now.

### 16. `reentrancy/etherstore.sol`

Official label:

- `reentrancy`

Hybrid extra families:

- `arithmetic`
- `denial_of_service`
- `unchecked_low_level_calls`

Assessment:

- None of the extras are strong enough to accept.
- `arithmetic` does not hold up:
  - the arithmetic here is simple balance bookkeeping, not a convincing secondary arithmetic bug
- `denial_of_service` does not hold up:
  - a failed external call only blocks the caller's own withdrawal attempt, not a shared payout queue or global contract path
- `unchecked_low_level_calls` does not hold up:
  - the risky call is wrapped in `require(msg.sender.call.value(_weiToWithdraw)())`, so it is checked rather than silently ignored

Bottom line:

- Keep this file unchanged in the reviewed overlay.
- Treat the hybrid extras on this file as false positives.

### 17. `unchecked_low_level_calls/king_of_the_ether_throne.sol`

Official label:

- `unchecked_low_level_calls`

Hybrid extra families:

- `access_control`
- `front_running`
- `reentrancy`

Assessment:

- `access_control` does not hold up:
  - the privileged paths use the `onlywizard` modifier at lines `45`, `172`, and `178`
  - there is no public ownership-reset or missing-owner check comparable to the accepted access-control overlay cases
- `reentrancy` does not hold up:
  - the Ether interaction sites use `send()` at lines `110`, `118`, `132`, and `174`
  - this is the contract's known unchecked-call issue, not a convincing reentrancy pattern
- `front_running` is not strong enough to accept:
  - transaction order affects who becomes monarch, but that behavior is the core open-competition mechanic of the game rather than a clearly distinct benchmark-worthy vulnerability family for reviewed truth

Bottom line:

- Keep this file unchanged in the reviewed overlay.
- Treat the hybrid extras on this file as false positives.

### 18. `reentrancy/0x23a91059fdc9579a9fbd0edc5f2ea0bfdb70deb4.sol`

Official label:

- `reentrancy`

Hybrid extra families:

- `access_control`
- `unchecked_low_level_calls`

Assessment:

- `access_control` does not hold up:
  - `PrivateBank(address _log)` is the constructor for this Solidity version and is not a public reinitializer
  - there is no exposed admin-reset or public initialization path like the accepted `PERSONAL_BANK` sample
- `unchecked_low_level_calls` does not hold up:
  - the Ether send in `CashOut()` is checked with `if(msg.sender.call.value(_am)())`
  - the remaining call to `TransferLog.AddMessage()` is not an ignored low-level boolean-returning call

Bottom line:

- Keep this file unchanged in the reviewed overlay.
- Treat the hybrid extras on this file as false positives.

### 19. `unchecked_low_level_calls/0x89c1b3807d4c67df034fffb62f3509561218d30b.sol`

Official label:

- `unchecked_low_level_calls`

Hybrid extra families:

- `access_control`
- `arithmetic`
- `reentrancy`

Assessment:

- `access_control` does not hold up:
  - the privileged identity is fixed in the constructor via `requests[0].requester = msg.sender` at line `57`
  - administrative paths like `upgrade`, `reset`, `suspend`, `restart`, and `withdraw` check against that stored requester
- `arithmetic` does not hold up:
  - this review did not find a convincing attacker-controlled overflow/underflow path worth promoting into reviewed truth
- `reentrancy` does not hold up:
  - the contract uses an `externalCallFlag` guard around the externally callable request/cancel/deliver paths
  - the source review did not establish a clean secondary reentrancy issue beyond the already-labeled unchecked-call family

Bottom line:

- Keep this file unchanged in the reviewed overlay.
- Treat the hybrid extras on this file as false positives.

## Completion Pass: Remaining Mixed Cases Closed

The remaining `48` hybrid mixed cases were reviewed in grouped source-pattern batches. This closes the extra-family queue for the current shared SmartBugs run.

### 20. Singleton completions outside the big reentrancy and unchecked-call clusters

Reviewed files:

- `access_control/arbitrary_location_write_simple.sol`
- `access_control/proxy.sol`
- `arithmetic/integer_overflow_mapping_sym_1.sol`
- `arithmetic/integer_overflow_multitx_multifunc_feasible.sol`
- `bad_randomness/blackjack.sol`
- `bad_randomness/random_number_generator.sol`
- `front_running/eth_tx_order_dependence_minimal.sol`

Verdicts:

- `access_control/arbitrary_location_write_simple.sol`
  - accept extra `arithmetic`
  - `bonusCodes.length--` at line `28` is a real unsigned underflow, so this file does contain a secondary arithmetic issue in addition to the official arbitrary-write access-control problem
- `access_control/proxy.sol`
  - reject extra `denial_of_service`
  - the source is a delegatecall access-control sample, not a failed-call DOS sample
- `arithmetic/integer_overflow_mapping_sym_1.sol`
  - reject extra `access_control`
  - `init(uint256,uint256)` is public, but there is no privileged ownership concept or protected admin path to hijack
- `arithmetic/integer_overflow_multitx_multifunc_feasible.sol`
  - reject extra `access_control`
  - `init()` just flips the benchmark precondition and does not represent a source-real authority failure
- `bad_randomness/blackjack.sol`
  - reject extra `denial_of_service`
  - the send sites are checked with `if (!msg.sender.send(...)) throw;`, and the review did not establish a stronger shared-payout DOS condition worth promoting into reviewed truth
- `bad_randomness/random_number_generator.sol`
  - reject extra `time_manipulation`
  - the timestamp use is part of weak randomness generation, not a distinct timestamp-gated control-flow bug family
- `front_running/eth_tx_order_dependence_minimal.sol`
  - reject extra `access_control`
  - reject extra `unchecked_low_level_calls`
  - `setReward()` is still owner-gated, and the payout paths use `transfer()`, not ignored low-level calls

Bottom line:

- Promote only `access_control/arbitrary_location_write_simple.sol -> arithmetic`.
- Keep the other singleton extras counted as noise.

### 21. Reentrancy contracts with real secondary access-control issues

Reviewed files:

- `reentrancy/0x4320e6f8c05b27ab4707cd1f6d5ce6f3e4b3a5a1.sol`
- `reentrancy/0x4e73b32ed6c35f570686b89848e5f39f20ecc106.sol`
- `reentrancy/0x561eac93c92360949ab1f1403323e6db345cbf31.sol`
- `reentrancy/0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839.sol`
- `reentrancy/0x7a8721a9d64c74da899424c1b52acbf58ddc9782.sol`
- `reentrancy/0x96edbe868531bd23a6c05e9d0c424ea64fb1b78b.sol`
- `reentrancy/0xaae1f51cf3339f18b6d3f3bdc75a5facd744b0b8.sol`
- `reentrancy/0xbe4041d55db380c5ae9d4a9b9703f1ed4e7e3888.sol`

Assessment:

- `reentrancy/0x4320e6f8c05b27ab4707cd1f6d5ce6f3e4b3a5a1.sol`
- `reentrancy/0x4e73b32ed6c35f570686b89848e5f39f20ecc106.sol`
- `reentrancy/0x561eac93c92360949ab1f1403323e6db345cbf31.sol`
- `reentrancy/0x96edbe868531bd23a6c05e9d0c424ea64fb1b78b.sol`
- `reentrancy/0xaae1f51cf3339f18b6d3f3bdc75a5facd744b0b8.sol`
- `reentrancy/0xbe4041d55db380c5ae9d4a9b9703f1ed4e7e3888.sol`
  - accept extra `access_control`
  - all six files expose public initialization-style functions such as `SetMinSum`, `SetLogFile`, and `Initialized` without an owner gate, so a caller can seize meaningful control before the configuration is frozen
  - reject extra `unchecked_low_level_calls` where present
  - the Ether transfer in the vulnerable withdrawal path is checked with `if (msg.sender.call.value(... )())`, so the extra unchecked-call classification does not hold up
- `reentrancy/0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839.sol`
  - accept extra `access_control`
  - `initTokenBank()` at lines `53-58` is a public owner-reset path that lets any caller seize privileged control before invoking owner-only withdrawal functions
- `reentrancy/0x7a8721a9d64c74da899424c1b52acbf58ddc9782.sol`
  - accept extra `access_control`
  - `onlyOwner` uses `tx.origin == owner`, which is a real authorization weakness beyond the official reentrancy bug
  - reject extra `unchecked_low_level_calls`
  - the low-level Ether send is checked rather than silently ignored

Bottom line:

- Add `access_control` to the reviewed overlay for all eight files in this group.
- Keep the companion `unchecked_low_level_calls` extras counted as noise.

### 22. Reentrancy contracts where the extra families remain tool noise

Reviewed files:

- `reentrancy/0x8c7777c45481dba411450c228cb692ac3d550344.sol`
- `reentrancy/0x941d225236464a25eb18076df7da6a91d0f95e9e.sol`
- `reentrancy/0xb5e1b1ee15c6fa0e48fce100125569d430f1bd12.sol`
- `reentrancy/0xb93430ce38ac4a6bb47fb1fc085ea669353fd89e.sol`
- `reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol`
- `reentrancy/etherbank.sol`
- `reentrancy/reentrance.sol`
- `reentrancy/reentrancy_bonus.sol`
- `reentrancy/reentrancy_cross_function.sol`
- `reentrancy/reentrancy_insecure.sol`
- `reentrancy/reentrancy_simple.sol`
- `reentrancy/simple_dao.sol`

Assessment:

- `reentrancy/0x8c7777c45481dba411450c228cb692ac3d550344.sol`
- `reentrancy/0xb5e1b1ee15c6fa0e48fce100125569d430f1bd12.sol`
- `reentrancy/0xb93430ce38ac4a6bb47fb1fc085ea669353fd89e.sol`
- `reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol`
  - reject extra `access_control`
  - reject extra `unchecked_low_level_calls`
  - these are plain reentrancy bank samples with valid constructors and checked low-level call control flow; there is no public admin reset and no ignored call result
- `reentrancy/0x941d225236464a25eb18076df7da6a91d0f95e9e.sol`
  - reject extra `bad_randomness`
  - the `block.number > lastBlock` guard is an anti-same-block condition, not a real randomness vulnerability family
- `reentrancy/etherbank.sol`
- `reentrancy/reentrance.sol`
- `reentrancy/reentrancy_bonus.sol`
- `reentrancy/reentrancy_cross_function.sol`
- `reentrancy/reentrancy_insecure.sol`
- `reentrancy/reentrancy_simple.sol`
- `reentrancy/simple_dao.sol`
  - reject extra `access_control`
  - reject extra `unchecked_low_level_calls`
  - these files are pure reentrancy samples; the external calls are the reentrancy sink itself, not a separate unchecked-call family, and there is no real authority bug

Bottom line:

- Keep all extra families on this reentrancy-noise group counted as false positives.

### 23. `reentrancy/spank_chain_payment.sol`

Official label:

- `reentrancy`

Hybrid extra families:

- `access_control`
- `denial_of_service`
- `other`

Assessment:

- accept extra `denial_of_service`
  - `consensusCloseChannel()` and `byzantineCloseChannel()` use `transfer()` to counterparties at lines `534-535` and `798-799`
  - a reverting recipient can block settlement finalization, which is a real payout-DOS condition beyond the official reentrancy label
- reject extra `access_control`
  - the channel-closing and update paths are controlled by signature verification and channel membership checks rather than a missing authority check
- reject extra `other`
  - the review did not establish a second distinct family outside the accepted DOS condition

Bottom line:

- Add `denial_of_service` to the reviewed overlay.
- Keep `access_control` and `other` counted as noise.

### 24. Unchecked-call contracts with reviewed secondary truth

Reviewed files:

- `unchecked_low_level_calls/0xb7c5c5aa4d42967efe906e1b66cb8df9cebf04f7.sol`
- `unchecked_low_level_calls/lotto.sol`

Assessment:

- `unchecked_low_level_calls/0xb7c5c5aa4d42967efe906e1b66cb8df9cebf04f7.sol`
  - accept extra `reentrancy`
  - `withdraw()` performs `msg.sender.call.value(balances[msg.sender])()` before zeroing `balances[msg.sender]`, so this file contains a real state-after-call reentrancy bug in addition to the official unchecked-call label
  - reject extra `access_control`
  - there is no privileged role or public admin-takeover path here
- `unchecked_low_level_calls/lotto.sol`
  - accept extra `access_control`
  - `withdrawLeftOver()` is public and lets any caller drain the remaining contract balance after `payedOut` flips, so the extra authority failure is real
  - reject extra `front_running`
  - the review did not establish a distinct transaction-order dependency beyond the already-labeled unchecked-send behavior

Bottom line:

- Add `reentrancy` for `unchecked_low_level_calls/0xb7c5c5aa4d42967efe906e1b66cb8df9cebf04f7.sol`.
- Add `access_control` for `unchecked_low_level_calls/lotto.sol`.

### 25. Remaining unchecked-call cluster reviewed as noise

Reviewed files:

- `unchecked_low_level_calls/0x3e013fc32a54c4c5b6991ba539dcd0ec4355c859.sol`
- `unchecked_low_level_calls/0x3f2ef511aa6e75231e4deafc7a3d2ecab3741de2.sol`
- `unchecked_low_level_calls/0x5aa88d2901c68fda244f1d0584400368d2c8e739.sol`
- `unchecked_low_level_calls/0x70f9eddb3931491aab1aeafbc1e7f1ca2a012db4.sol`
- `unchecked_low_level_calls/0x78c2a1e91b52bca4130b6ed9edd9fbcfd4671c37.sol`
- `unchecked_low_level_calls/0x7a4349a749e59a5736efb7826ee3496a2dfd5489.sol`
- `unchecked_low_level_calls/0x806a6bd219f162442d992bdc4ee6eba1f2c5a707.sol`
- `unchecked_low_level_calls/0x84d9ec85c9c568eb332b7226a8f826d897e0a4a8.sol`
- `unchecked_low_level_calls/0x958a8f594101d2c0485a52319f29b2647f2ebc06.sol`
- `unchecked_low_level_calls/0x9d06cbafa865037a01d322d3f4222fa3e04e5488.sol`
- `unchecked_low_level_calls/0xb0510d68f210b7db66e8c7c814f22680f2b8d1d6.sol`
- `unchecked_low_level_calls/0xd2018bfaa266a9ec0a1a84b061640faa009def76.sol`
- `unchecked_low_level_calls/0xdb1c55f6926e7d847ddf8678905ad871a68199d2.sol`
- `unchecked_low_level_calls/0xe4eabdca81e31d9acbc4af76b30f532b6ed7f3bf.sol`
- `unchecked_low_level_calls/0xe82f0742a71a02b9e9ffc142fdcb6eb1ed06fb87.sol`
- `unchecked_low_level_calls/0xec329ffc97d75fe03428ae155fc7793431487f63.sol`
- `unchecked_low_level_calls/0xf70d589d76eebdd7c12cc5eec99f8f6fa4233b9e.sol`
- `unchecked_low_level_calls/mishandled.sol`

Assessment:

- `unchecked_low_level_calls/0x3e013fc32a54c4c5b6991ba539dcd0ec4355c859.sol`
- `unchecked_low_level_calls/0x5aa88d2901c68fda244f1d0584400368d2c8e739.sol`
- `unchecked_low_level_calls/0x84d9ec85c9c568eb332b7226a8f826d897e0a4a8.sol`
- `unchecked_low_level_calls/0x958a8f594101d2c0485a52319f29b2647f2ebc06.sol`
- `unchecked_low_level_calls/mishandled.sol`
  - reject extra `access_control`
  - these contracts either have valid owner checks around the dangerous call or do not expose any privileged role at all
- `unchecked_low_level_calls/0x3f2ef511aa6e75231e4deafc7a3d2ecab3741de2.sol`
- `unchecked_low_level_calls/0x78c2a1e91b52bca4130b6ed9edd9fbcfd4671c37.sol`
  - reject extra `access_control`
  - reject extra `reentrancy`
  - these honeypot giveaway contracts do contain a hidden owner backdoor for a specific hardcoded address, but the reviewed source pass did not consider that enough to promote a generic secondary access-control family in this benchmark overlay, and there is no state-after-call reentrancy path
- `unchecked_low_level_calls/0x70f9eddb3931491aab1aeafbc1e7f1ca2a012db4.sol`
- `unchecked_low_level_calls/0x7a4349a749e59a5736efb7826ee3496a2dfd5489.sol`
- `unchecked_low_level_calls/0x806a6bd219f162442d992bdc4ee6eba1f2c5a707.sol`
- `unchecked_low_level_calls/0xd2018bfaa266a9ec0a1a84b061640faa009def76.sol`
- `unchecked_low_level_calls/0xdb1c55f6926e7d847ddf8678905ad871a68199d2.sol`
- `unchecked_low_level_calls/0xe4eabdca81e31d9acbc4af76b30f532b6ed7f3bf.sol`
- `unchecked_low_level_calls/0xe82f0742a71a02b9e9ffc142fdcb6eb1ed06fb87.sol`
- `unchecked_low_level_calls/0xf70d589d76eebdd7c12cc5eec99f8f6fa4233b9e.sol`
  - reject extra `reentrancy`
  - these samples make unchecked external calls but do not maintain a withdrawable balance state that is updated after the call, so the extra reentrancy family does not hold up
- `unchecked_low_level_calls/0x9d06cbafa865037a01d322d3f4222fa3e04e5488.sol`
  - reject extra `front_running`
  - the file is an unchecked-send/token-sale sample, not a transaction-order dependency sample
- `unchecked_low_level_calls/0xb0510d68f210b7db66e8c7c814f22680f2b8d1d6.sol`
  - reject extra `reentrancy`
  - `fundPuppets()` and the puppet fallback do chain unchecked calls, but the reviewed source pass did not establish a convincing exploit-grade state-after-call reentrancy issue beyond the official unchecked-call family
- `unchecked_low_level_calls/0xec329ffc97d75fe03428ae155fc7793431487f63.sol`
  - reject extra `denial_of_service`
  - the unchecked owner `execute()` call is real, but this review did not find a second distinct DOS condition worth promoting

Bottom line:

- Keep all extras in this remaining unchecked-call cluster counted as noise.

## Final Status

- All `63` hybrid mixed cases in the current shared SmartBugs run have now been reviewed.
- Confirmed unlabeled true positives were added to `fixtures/ground_truth/smartbugs_reviewed_overlay.json`.
- All remaining mixed-case extras should currently be treated as genuine precision debt until detector fixes change the underlying predictions.
