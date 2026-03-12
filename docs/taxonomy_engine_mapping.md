# Taxonomy Mapping (Static + Symbolic + Fuzzing + Hybrid)

Source of truth: `taxonomy.xlsx` (sheet: `taxonomy`)

This file tracks taxonomy label policy and runtime mapping across all approaches.

Operational matrix:

- `docs/coverage_matrix.md` (implementation and confidence status per rule)

Row-level parity update applied on 2026-03-11:

- Standalone `--symbolic` and `--fuzzing` now surface the full 45-row taxonomy by combining:
  - native runtime findings, and
  - engine-specific `meta` findings with `analysis_layer=meta` and `evidence_kind=taxonomy-completion`
- This keeps runtime evidence honest while still exposing exact spreadsheet rows for scoring, taxonomy coverage, and benchmark comparison.

## Canonical Label Policy

- Canonical labels follow static detector names where possible.
- Symbolic and fuzzing outputs should normalize aliases before cross-engine comparison.
- Hybrid stores normalized labels in `findings.json` for stable dedup and scoring.

Step 1 normalization applied on 2026-03-09:

- Symbolic:
  - `underflow` -> `integer-underflow`
- Fuzzing:
  - `tx-origin-auth` -> `tx-origin`
  - `hardcoded-gas` -> `hardcoded-gas-transfer`
  - `storage-memory-issue` -> `memory-manipulation`

Pattern expansion applied on 2026-03-09:

- Symbolic:
  - Added `weak-prng` detection (block.number/blockhash in branch logic).
  - Added `hardcoded-gas-transfer` detection (send/transfer), including lowered member-call patterns.
  - Added `unsafe-send-in-require` detection.
  - Added `unprotected-ether-withdrawal` detection for value transfers without sender-check evidence.
  - Added `dos-with-failed-call`, `transaction-order-dependency`, and `signature-malleability`.
  - TOD/CR-02 now use static-backed function gating to reduce false positives.
  - Tightened unchecked-call handling to avoid false positives on `transfer`.
- Fuzzing:
  - Enabled `exception-disorder`, `access-control`, and `locked-ether` in default `check_all`.
  - Added `unsafe-send-in-require` oracle from runtime trace events.
  - Added AST-level `public-mint-burn` pattern.
  - Added `dos-with-failed-call`, `transaction-order-dependency`, and `signature-malleability`.
  - TOD/CR-02 now use static-backed function gating to reduce false positives.
  - Note: these are useful for recall but can increase false positives on partial frontend traces.

Step 5 update applied on 2026-03-09:

- Fuzzing:
  - Added high-signal `arbitrary-write` oracle requiring:
    - storage write without sender-check, and
    - evidence of multi-sender execution for the same function.
  - Promoted `arbitrary-write` confidence to `high`.
  - Hybrid fuzz adapter now also emits AST-level `public-mint-burn` parity finding on epoch 1.
  - Added static `storage_rw_map` chain-aware scheduling for writer->reader transaction sequences.

## Implemented Now

- Access Control 4.0 / 13.0: contract destruction
  - canonical kind: `unprotected-selfdestruct`
  - engines: static, fuzzing, symbolic, hybrid
- Access Control 6.0: dangerous `tx.origin`
  - canonical kind: `tx-origin`
  - engines: static, fuzzing, symbolic, hybrid
- Access Control 15.0: unsafe delegatecall
  - canonical kind: `unsafe-delegatecall`
  - engines: static, fuzzing, symbolic, hybrid
- Access Control 16.0: unused return value
  - canonical kind: `unchecked-call`
  - engines: static, fuzzing, symbolic, hybrid
- Access Control 14.0: unprotected ether withdrawal
  - canonical kind: `unprotected-ether-withdrawal`
  - engines: static, fuzzing, symbolic, hybrid
- Access Control 17.0: public mint/burn
  - canonical kind: `public-mint-burn`
  - engines: static, fuzzing, symbolic, hybrid
- Access Control extension: arbitrary write
  - canonical kind: `arbitrary-write`
  - engines: symbolic, fuzzing, hybrid (static pending)
- Block Manipulation 1.0: dangerous `block.timestamp`
  - canonical kind: `timestamp-dependency`
  - engines: static, fuzzing, symbolic, hybrid
- Block Manipulation 2.0: transaction order dependency
  - canonical kind: `transaction-order-dependency`
  - engines: static, fuzzing, symbolic, hybrid
- Cryptographic 2.0: signature malleability
  - canonical kind: `signature-malleability`
  - engines: static, fuzzing, symbolic, hybrid
- Denial of Service 4.0: DoS with failed call
  - canonical kind: `dos-with-failed-call`
  - engines: static, fuzzing, symbolic, hybrid
- Denial of Service 6.0: unsafe send in require/assert
  - canonical kind: `unsafe-send-in-require`
  - engines: static, fuzzing, symbolic, hybrid
- Reentrancy 1.0..5.0 family (pattern-level)
  - canonical kind: `reentrancy*`
  - engines: static, fuzzing, symbolic, hybrid

## Project Extension (not from taxonomy.xlsx)

- `shadowing`
  - Used by current fixture scoring and retained for compatibility.
  - engines: static, fuzzing, symbolic, hybrid

## Precision Note

`exception-disorder`, `access-control`, and `locked-ether` are now enabled by default in fuzzing.
They should be kept behind confidence tags in reporting because they can raise false positives on partial traces.

Confidence tags are now emitted by both engines:

- Fuzzing: confidence derives from `FuzzFindingKind` (`high`/`medium`/`low`).
- Symbolic: confidence derives from `VulnerabilityKind` (`high`/`medium`/`low`).
