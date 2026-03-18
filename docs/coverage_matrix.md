# Coverage Matrix (Static / Symbolic / Fuzzing / Hybrid)

Source references:

- `taxonomy.xlsx` (sheet: `taxonomy`)
- `docs/taxonomy_engine_mapping.md`

Legend:

- `Y` = implemented and enabled
- `P` = partial / heuristic
- `N` = not implemented

Confidence legend:

- Symbolic confidence: `high|medium|low` from `VulnerabilityKind`
- Fuzzing confidence: `high|medium|low` from `FuzzFindingKind`

| Canonical Kind | Taxonomy Ref | Static | Symbolic | Fuzzing | Hybrid | Symbolic Confidence | Fuzzing Confidence | Notes |
|---|---|---|---|---|---|---|---|---|
| `tx-origin` | Access Control 6.0 | Y | Y | Y | Y | high | high | Canonical alias normalized from fuzz `tx-origin-auth`. |
| `unsafe-delegatecall` | Access Control 15.0 | Y | Y | Y | Y | high | high | Member-call lowered-temp forms handled. |
| `unchecked-call` | Access Control 16.0 | Y | Y | Y | Y | high | high | Symbolic excludes `.transfer(...)` from unchecked-return rule. |
| `unprotected-selfdestruct` | Access Control 4.0 / 13.0 | Y | Y | Y | Y | high | high |  |
| `unprotected-ether-withdrawal` | Access Control 14.0 | Y | Y | Y | Y | medium | high | Symbolic uses sender-check evidence heuristic. |
| `arbitrary-write` | Access Control (project extension) | N | Y | Y | Y | medium | high | Symbolic uses authority-sensitive storage write without sender-check heuristic. |
| `public-mint-burn` | Access Control 17.0 | Y | Y | Y | Y | medium | medium | Symbolic + fuzzing use AST-level public/external mint/burn rule. |
| `integer-underflow` | Arithmetic 3.0 | Y | Y | Y | Y | medium | medium |  |
| `timestamp-dependency` | Block Manipulation 1.0 | Y | Y | Y | Y | medium | medium |  |
| `transaction-order-dependency` | Block Manipulation 2.0 | Y | Y | Y | Y | medium | medium | Symbolic/Fuzzing use heuristic detection with static-backed function gating. |
| `weak-prng` | Block Manipulation 3.0 | Y | Y | Y | Y | medium | medium |  |
| `signature-malleability` | Cryptographic 2.0 | Y | Y | Y | Y | low | low | Symbolic/Fuzzing parity implemented via conservative heuristic with static-backed function gating. |
| `hardcoded-gas-transfer` | Denial of Services 1.0 | Y | Y | Y | Y | medium | medium | Canonical alias from fuzz `hardcoded-gas`. |
| `locked-ether` | Denial of Services 2.0 | Y | Y | Y | Y | low | low | Symbolic checks payable contract with no detected Ether-sending path. |
| `dos-with-failed-call` | Denial of Services 4.0 | Y | Y | Y | Y | medium | medium | Symbolic loop-context + external-call; fuzz loop+external-call heuristic. |
| `unsafe-send-in-require` | Denial of Services 6.0 | Y | Y | Y | Y | medium | high |  |
| `reentrancy` | Reentrancy 1.0..5.0 | Y | Y | Y | Y | high | high |  |
| `memory-manipulation` | Storage & Memory 5.0 | Y | Y | Y | Y | medium | medium | Symbolic covers inline assembly and delegatecall-in-loop patterns. |
| `shadowing` | Project extension | Y | Y | Y | Y | medium | medium | Not in taxonomy.xlsx; kept for benchmark compatibility. |

## Update Policy

- Update this file whenever a rule is added, removed, or confidence changes in any engine.
- Keep `docs/taxonomy_engine_mapping.md` as policy/reference text.
- Keep this matrix as the operational view for implementation status.

## Runtime vs Meta Channel Policy

- `runtime_primary`: findings directly produced by symbolic/fuzzing execution logic.
- `meta_secondary`: taxonomy-completion/static-lifted rows surfaced for parity.
- `surfaced_output`: union of runtime + meta.

Scoring policy for accuracy work:

- TP/FP/FN primary KPI is `runtime_primary`.
- `meta_secondary` remains reported, but does not define runtime maturity.

## Full Taxonomy Audit (45 Rows)

Audit date: `2026-03-11`

This section checks the exact 45 vulnerability rows in `taxonomy.xlsx`, not just the normalized canonical kinds above.

As of the latest update, standalone `--symbolic` and `--fuzzing` both expose all `45/45` taxonomy rows by combining:

- direct runtime findings where the engine already has a native detector or oracle
- `meta` findings with `evidence=taxonomy-completion`, generated from the shared static detector set for exact row-level parity

Current row-level totals for engine output:

- Symbolic: `45 Y / 0 P / 0 N`
- Fuzzing: `45 Y / 0 P / 0 N`

The detailed table below is kept as the runtime-only baseline that motivated the taxonomy-completion layer.

Row-level legend:

- `Y` = direct row-level support exists in the engine
- `P` = partial, collapsed into a broader family, or heuristic-only support
- `N` = no meaningful support for that taxonomy row today

Important interpretation:

- The engines now have full `45/45` row-level taxonomy parity in their standalone outputs.
- The condensed canonical matrix above is still correct for normalized cross-engine finding labels.
- Several spreadsheet rows are still collapsed at runtime into broader findings like `reentrancy`, `memory-manipulation`, or `unprotected-selfdestruct`.
- Exact row labels for those cases are now supplied through the `meta` layer rather than by overloading the runtime labels.

| Taxonomy Ref | Type | Symbolic | Fuzzing | Notes |
|---|---|---|---|---|
| Access Control 1.0 | Arbitrary `from` in transferFrom() without msg.sender Check | N | N | No transferFrom-specific semantic model in dynamic engines. |
| Access Control 2.0 | Call to Arbitrary Addresses with Unchecked Calldata | N | N | Engines detect unchecked low-level calls, but not arbitrary-target plus arbitrary-calldata taint as a dedicated rule. |
| Access Control 3.0 | Caller Not Checked | N | N | No extcodesize/caller-is-contract bypass modeling. |
| Access Control 4.0 | Contract Could be Destructed | Y | Y | Covered by selfdestruct/suicide detection, though normalized under `unprotected-selfdestruct`. |
| Access Control 5.0 | Dangerous Immediate Initialization of State Variables | N | N | Runtime engines do not analyze state initializers as a dedicated rule. |
| Access Control 6.0 | Dangerous Usage of `tx.origin` | Y | Y | Directly implemented. |
| Access Control 7.0 | Default Function Visibility | N | N | Legacy visibility is handled for reachability, but not emitted as a dynamic finding. |
| Access Control 8.0 | Initializing Method without Permission Check | N | N | No dedicated initializer-permission detector in dynamic engines. |
| Access Control 9.0 | Method permit() Used for Arbitrary `from` in transferFrom() | N | N | No permit/transferFrom semantic model. |
| Access Control 10.0 | Missing `msg.sender` Check for transferFrom() | N | N | No transferFrom-specific rule. |
| Access Control 11.0 | Missing Input Validation | N | N | No general zero-address/input-validation detector in dynamic engines. |
| Access Control 12.0 | Sending Ether to Arbitrary Destinations | N | N | `unprotected-ether-withdrawal` exists, but not arbitrary-destination taint as a dedicated row-level rule. |
| Access Control 13.0 | Unprotected Contract Destruction | Y | Y | Directly covered by selfdestruct detection. |
| Access Control 14.0 | Unprotected Ether Withdrawal | Y | Y | Directly covered. |
| Access Control 15.0 | Unsafe Delegatecall | Y | Y | Directly covered. |
| Access Control 16.0 | Unused Return Value | Y | Y | Directly covered as `unchecked-call`. |
| Access Control 17.0 | Usage of public mint or burn | Y | Y | Directly covered. |
| Access Control 18.0 | Write to Arbitrary Storage Location | P | P | Current `arbitrary-write` is a narrowed authority-sensitive heuristic, not full arbitrary-slot exploit modeling. |
| Arithmetic 1.0 | Inappropriate Integer Division before Multiplication | N | Y | Fuzzing has a dedicated oracle; symbolic does not yet implement this row. |
| Arithmetic 2.0 | Integer Overflow | N | Y | Fuzzing covers wrapping overflow; symbolic currently models underflow only. |
| Arithmetic 3.0 | Integer Underflow | Y | Y | Directly covered. |
| Arithmetic 4.0 | Unsafe Array Length Assignment | N | N | No dedicated array-length mutation detector in dynamic engines. |
| Block Manipulation 1.0 | Dangerous Usage of `block.timestamp` | Y | Y | Directly covered. |
| Block Manipulation 2.0 | Transaction Order Dependency | P | P | Implemented, but heuristic and statically gated. |
| Block Manipulation 3.0 | Weak PRNG (Pseudorandom Number Generator) | Y | Y | Covered via block.number/blockhash usage. |
| Cryptographic 1.0 | Lack of Proper Signature Verification | N | P | Fuzzing has a generic `ecrecover`-without-guard heuristic; symbolic lacks a dedicated row-level detector. |
| Cryptographic 2.0 | Signature Malleability | P | P | Implemented conservatively, low-confidence, and statically gated. |
| Denial of Services 1.0 | `transfer()` and `send()` with Hardcoded Gas Amount | Y | Y | Directly covered as `hardcoded-gas-transfer`. |
| Denial of Services 2.0 | Contract Could Lock Ether | P | P | Implemented as a contract-level heuristic, not full semantic proof. |
| Denial of Services 3.0 | DoS with Block Gas Limit | N | P | Fuzzing approximates via unbounded-loop behavior; symbolic has no dedicated block-gas-limit rule. |
| Denial of Services 4.0 | DoS With Failed Call | P | P | Implemented heuristically in both engines. |
| Denial of Services 5.0 | Force Sending Ether with this.balance check in require() or assert() | N | N | Not implemented in fuzzing or symbolic. |
| Denial of Services 6.0 | Unsafe send() in the require() Condition | Y | Y | Directly covered. |
| Reentrancy 1.0 | Reentrancy Vulnerability with Negative Events | N | N | No dynamic event-staleness detector. |
| Reentrancy 2.0 | Reentrancy Vulnerability with Transfer | N | N | Both engines intentionally exclude `send`/`transfer` from callback-capable reentrancy modeling. |
| Reentrancy 3.0 | Reentrancy Vulnerability with Same Effect | P | P | Generic callback-after-call reentrancy can hit this pattern, but stale-read equality is not checked as a dedicated rule. |
| Reentrancy 4.0 | Reentrancy Vulnerability with ETH Transfer | Y | Y | This is the current dynamic reentrancy rule both engines actually implement. |
| Reentrancy 5.0 | Reentrancy Vulnerability without ETH Transfer | N | N | Current dynamic reentrancy model requires value-carrying callback-capable calls. |
| Storage & Memory 1.0 | Arbitrary Function Jump via Inline Assembly | P | P | Folded into generic inline-assembly / memory-manipulation handling. |
| Storage & Memory 2.0 | Bytes Variables Risk | N | N | Not implemented. |
| Storage & Memory 3.0 | Dangerous Usage of `msg.value` inside a Loop | N | N | Not implemented in dynamic engines. |
| Storage & Memory 4.0 | Error-prone Assembly Usage | P | P | Folded into generic inline-assembly handling. |
| Storage & Memory 5.0 | Memory Manipulation | Y | Y | Directly covered through inline assembly / storage-memory patterns. |
| Storage & Memory 6.0 | Modifying storage array by value | N | N | Not implemented. |
| Storage & Memory 7.0 | Payable Functions using `delegatecall` inside a Loop | P | N | Symbolic partially covers delegatecall-in-loop under `memory-manipulation`; fuzzing does not currently emit this row. |
