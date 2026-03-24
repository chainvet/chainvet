# SmartBugs Curated Benchmark Comparison (4 Modes)

Date: 2026-03-24
Dataset: `Benchmarks/smartbugs-curated`

Analysis artifacts used:

- `runs/benchmark_smartbugs_curated_1774302347_all4_default/summary.tsv`
- `runs/benchmark_smartbugs_curated_1774302347_all4_default/smartbugs_score/summary.json`
- `runs/benchmark_smartbugs_curated_1774302347_all4_default/smartbugs_score/per_contract.json`
- `runs/benchmark_smartbugs_curated_1774302347_all4_default/smartbugs_score/per_truth_vulnerability.tsv`

Reference truth:

- `Benchmarks/smartbugs-curated/vulnerabilities.json`

## Environment Note

- The SmartBugs scorer uses the official `vulnerabilities.json` category labels as the benchmark truth.
- The current stable scored artifact covers `140` contracts and `203` labeled issues.
- The active FSE scope for SmartBugs is `142` contracts, but `2` unchecked-call fixtures are still missing from the saved `summary.tsv`:
  - `unchecked_low_level_calls/0xf2570186500a46986f3139f65afedc2afe4f445d.sol`
  - `unchecked_low_level_calls/etherpot_lotto.sol`
- The tables below therefore describe the current stable scored subset, not the full `142/142` active target list.
- I am intentionally not including runtime-cost tables here, because the current run directory was resumed/repaired and its timing columns were partially zeroed during recovery. The accuracy tables below remain valid because they are computed from the saved findings payloads and the official truth list.

## Official Truth Distribution (Current Stable Scored Subset)

| Category | Issues |
| --- | ---: |
| `access_control` | 21 |
| `arithmetic` | 23 |
| `bad_randomness` | 31 |
| `denial_of_service` | 7 |
| `front_running` | 7 |
| `other` | 3 |
| `reentrancy` | 32 |
| `time_manipulation` | 7 |
| `unchecked_low_level_calls` | 72 |
| **Total** | **203** |

## Benchmark Bugs Only (Ignoring FP)

If we ignore all extra findings and only ask "how many official benchmark bugs did each mode catch?", then this is recall/coverage, not full accuracy.

### Overall Issue Coverage

This counts each official labeled SmartBugs issue row once and only asks whether the mode surfaced the right benchmark family for that issue.

| Mode | Hits | Total Official Issues | Coverage |
| --- | ---: | ---: | ---: |
| `--static` | 139 | 203 | 0.685 |
| `--symbolic` | 148 | 203 | 0.729 |
| `--fuzzing` | 156 | 203 | 0.768 |
| `--hybrid` | 151 | 203 | 0.744 |

### File-Level Official Coverage

This is the file-relative version of the same idea: for each benchmark file, did the mode recover all official benchmark bug families that exist in that file?

| Mode | Files With Full Official Coverage | Files Missed | File-Level Accuracy |
| --- | ---: | ---: | ---: |
| `--static` | 93/140 | 47/140 | 0.664 |
| `--symbolic` | 102/140 | 38/140 | 0.729 |
| `--fuzzing` | 105/140 | 35/140 | 0.750 |
| `--hybrid` | 102/140 | 38/140 | 0.729 |

Important note:

- In the current stable SmartBugs scored subset, this family-level file metric has no partial-coverage files.
- That means each file is currently either:
  - fully covered at the official family level, or
  - fully missed at the official family level
- So this table is a clean answer to "how accurate are we relative to the official bugs in each file only?"

### Per-Category Issue Coverage

| Category | `--static` | `--symbolic` | `--fuzzing` | `--hybrid` |
| --- | ---: | ---: | ---: | ---: |
| `access_control` | `19/21` | `16/21` | `17/21` | `15/21` |
| `arithmetic` | `14/23` | `12/23` | `21/23` | `21/23` |
| `bad_randomness` | `22/31` | `21/31` | `26/31` | `28/31` |
| `denial_of_service` | `7/7` | `2/7` | `2/7` | `7/7` |
| `front_running` | `4/7` | `2/7` | `2/7` | `2/7` |
| `other` | `0/3` | `0/3` | `0/3` | `0/3` |
| `reentrancy` | `30/32` | `31/32` | `31/32` | `31/32` |
| `time_manipulation` | `6/7` | `1/7` | `1/7` | `1/7` |
| `unchecked_low_level_calls` | `37/72` | `63/72` | `56/72` | `46/72` |

Concrete example, using your reentrancy question:

- `--static`: `30/32`
- `--symbolic`: `31/32`
- `--fuzzing`: `31/32`
- `--hybrid`: `31/32`

### Stricter Labeled-Line Coverage

This is the harder version: the prediction must overlap the official labeled source lines, not just match the right bug family on the right benchmark contract.

| Mode | Hits | Total Official Issues | Coverage |
| --- | ---: | ---: | ---: |
| `--static` | 94 | 203 | 0.463 |
| `--symbolic` | 91 | 203 | 0.448 |
| `--fuzzing` | 0 | 203 | 0.000 |
| `--hybrid` | 41 | 203 | 0.202 |

For reentrancy at the stricter line-overlap level:

- `--static`: `29/32`
- `--symbolic`: `23/32`
- `--fuzzing`: `0/32`
- `--hybrid`: `29/32`

The `--fuzzing` line score is not a real semantic zero. It mainly reflects that fuzzing currently does not attach source-line locations in its surfaced findings.

## Family-Level Metrics (Surfaced Output vs Official Truth)

This is the closest SmartBugs analogue to the current user-facing output quality, because it scores the surfaced findings rather than the raw backend emissions.

| Mode | Contracts | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `--static` | 140 | 93 | 269 | 47 | 0.257 | 0.664 | 0.371 |
| `--symbolic` | 140 | 102 | 141 | 38 | 0.420 | 0.729 | 0.533 |
| `--fuzzing` | 140 | 105 | 177 | 35 | 0.372 | 0.750 | 0.498 |
| `--hybrid` | 140 | 102 | 168 | 38 | 0.378 | 0.729 | 0.498 |

## Family-Level Metrics (Raw Output vs Official Truth)

This shows what the engines produce before the surfaced-output cleanup path.

| Mode | Contracts | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `--static` | 140 | 93 | 269 | 47 | 0.257 | 0.664 | 0.371 |
| `--symbolic` | 140 | 122 | 310 | 18 | 0.282 | 0.871 | 0.427 |
| `--fuzzing` | 140 | 125 | 320 | 15 | 0.281 | 0.893 | 0.427 |
| `--hybrid` | 140 | 102 | 168 | 38 | 0.378 | 0.729 | 0.498 |

## Labeled-Line Overlap Metrics

This is the stricter metric: a prediction only counts if it overlaps the official labeled source lines.

| Mode | Truth Issues | Located Predictions | Line Matches | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `--static` | 203 | 652 | 94 | 0.144 | 0.463 | 0.220 |
| `--symbolic` | 203 | 317 | 91 | 0.287 | 0.448 | 0.350 |
| `--fuzzing` | 203 | 0 | 0 | 0.000 | 0.000 | 0.000 |
| `--hybrid` | 203 | 132 | 41 | 0.311 | 0.202 | 0.245 |

Important caveat:

- `--fuzzing` is not actually at zero semantic value here. Its current surfaced findings usually do not carry source-line locations, so the strict line-overlap metric is artificially harsh on fuzzing compared with the family-level benchmark-relative metric.

## Main Miss Categories By Mode (Surfaced Output)

| Mode | Main misses |
| --- | --- |
| `--static` | `unchecked_low_level_calls`(27), `arithmetic`(9), `other`(3), `bad_randomness`(2), `front_running`(2), `reentrancy`(2) |
| `--symbolic` | `arithmetic`(9), `unchecked_low_level_calls`(6), `access_control`(5), `denial_of_service`(4), `time_manipulation`(4) |
| `--fuzzing` | `unchecked_low_level_calls`(12), `access_control`(4), `denial_of_service`(4), `time_manipulation`(4), `front_running`(3) |
| `--hybrid` | `unchecked_low_level_calls`(18), `access_control`(5), `time_manipulation`(4), `front_running`(3), `other`(3) |

## Main FP Categories By Mode (Surfaced Output)

| Mode | Main false-positive categories |
| --- | --- |
| `--static` | `access_control`(58), `front_running`(55), `arithmetic`(42), `time_manipulation`(31), `reentrancy`(30) |
| `--symbolic` | `access_control`(45), `arithmetic`(40), `reentrancy`(21), `unchecked_low_level_calls`(13), `bad_randomness`(9) |
| `--fuzzing` | `access_control`(54), `unchecked_low_level_calls`(39), `reentrancy`(29), `arithmetic`(18), `bad_randomness`(17) |
| `--hybrid` | `access_control`(51), `reentrancy`(35), `unchecked_low_level_calls`(32), `denial_of_service`(22), `arithmetic`(14) |

## Interpretation

- On the official SmartBugs category labels, `--symbolic` is currently the strongest mode by surfaced-output F1:
  - symbolic: `0.533`
  - fuzzing: `0.498`
  - hybrid: `0.498`
  - static: `0.371`
- `--symbolic` and `--hybrid` tie on recall (`0.729`) at the surfaced-output layer, but symbolic is cleaner, so its precision is higher.
- `--fuzzing` has the highest surfaced-output recall (`0.750`), but it pays for that with more extra categories than symbolic.
- `--static` is the weakest SmartBugs mode in the current benchmark-relative scoring, mostly because it overfires broad families like `access_control`, `front_running`, and `arithmetic` while still missing many `unchecked_low_level_calls` cases.
- The dominant miss family across all four approaches is `unchecked_low_level_calls`.
- The dominant false-positive family across all four approaches is `access_control`.
- Raw-output recall is significantly higher for `--symbolic` and `--fuzzing`, but raw precision drops sharply:
  - symbolic raw recall: `0.871`, raw precision: `0.282`
  - fuzzing raw recall: `0.893`, raw precision: `0.281`
  - this mirrors the Not-so-smart lesson that surfaced-output quality matters more than raw finding volume.
- The strict line-overlap metric currently favors symbolic, but that is partly a location-attachment story rather than pure semantic detection quality:
  - symbolic: better line attachment and relatively precise spans
  - fuzzing: little to no current line attachment
  - hybrid: some line attachment, but still sparse compared with symbolic

## Bottom Line

- We now have a SmartBugs evaluation path that uses the official benchmark labels as truth, rather than an improvised manual mapping.
- The current stable SmartBugs benchmark-relative surfaced-output F1 is:
  - `--static`: `0.371`
  - `--symbolic`: `0.533`
  - `--fuzzing`: `0.498`
  - `--hybrid`: `0.498`
- The current best next improvement targets are:
  - recover `unchecked_low_level_calls` recall across all modes
  - reduce `access_control` overfiring across all modes
  - improve source-location attachment in fuzzing and hybrid so the labeled-line metric becomes meaningful
