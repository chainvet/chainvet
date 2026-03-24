# Grad Project Presentation Plan

## Goal

Present the analyzer as a practical, benchmarked smart-contract analysis platform with a clear technical contribution:

- one shared frontend and surfaced output
- four analysis modes with a hybrid scheduler
- benchmarked accuracy against reference truth
- a web UI that makes results inspectable

## Recommended Storyline

1. Problem

- Smart-contract analysis tools are fragmented.
- Single approaches miss bugs or overfire with noise.
- Existing tools also have compatibility and environment limitations.

2. Our Approach

- Shared Solidity frontend and normalized finding model
- Static analysis
- Symbolic execution
- Fuzzing
- Hybrid orchestration

3. Why Hybrid

- Uses static guidance to seed exploration
- Uses fuzzing for scalable behavior discovery
- Escalates to symbolic execution when coverage stalls or high-priority goals remain
- Produces one unified surfaced result format

4. Implementation Highlights

- Version-aware frontend for legacy Solidity
- Noise-reduction passes for access control, reentrancy, TOD, and unchecked-call families
- Unified web UI and summary model across all approaches
- Reviewed overlay for benchmark-underlabeling analysis

5. Evaluation

- Not-so-smart comparison
- SmartBugs curated comparison
- Hybrid vs external tools
- Official-truth scoring and reviewed-adjusted scoring

6. Demo

- Run the web UI
- Select a benchmark contract
- Show progress
- Show unified findings
- Show the benchmark docs/results already prepared

7. Limitations and Future Work

- External-tool comparability depends on corpus/tool compatibility
- Some families still have recall gaps
- Function-level/line-level grounding can improve further
- More scalable symbolic/runtime guidance is still possible

## Slide Deck Outline

### Slide 1: Title

- Project title
- team/member names
- one-sentence project summary

### Slide 2: Motivation

- why smart-contract bugs matter
- why existing tooling is not enough

### Slide 3: Problem Statement

- precision vs recall tradeoff
- fragmented outputs
- legacy compiler/tool compatibility issues

### Slide 4: System Overview

- architecture diagram
- frontend -> engines -> surfaced output -> web UI

### Slide 5: The Four Modes

- static
- symbolic
- fuzzing
- hybrid

### Slide 6: Hybrid Scheduler

- seed bootstrap
- frontier management
- stall detection
- symbolic escalation triggers

### Slide 7: Web UI

- file explorer
- progress strip
- normalized summary bubbles
- severity-grouped findings

### Slide 8: Benchmark Methodology

- datasets used
- official truth vs reviewed-adjusted truth
- why fair comparison matters

### Slide 9: Main Results

- hybrid vs static/symbolic/fuzzing
- hybrid vs external tools
- runtime/speed snapshot

### Slide 10: Noise Reduction Work

- examples of false-positive suppression
- examples of unlabeled-but-real findings from reviewed overlay

### Slide 11: Demo

- short live run or prerecorded sequence

### Slide 12: Limitations and Future Work

- unsupported corpus/tool combinations
- remaining noise buckets
- next engineering steps

### Slide 13: Conclusion

- recap contribution
- strongest quantitative result
- strongest practical takeaway

## Figures To Prepare

- hybrid pipeline Mermaid diagram from `docs/hybrid_approach.md`
- one clean architecture figure
- one benchmark table for internal modes
- one benchmark table for external tools
- one screenshot of the web UI
- one false-positive reduction example

## Tables To Reuse

- `docs/not_so_smart_comparison.md`
- `docs/smartbugs_curated_comparison.md`
- `docs/smartbugs_external_tools_comparison.md`

## Demo Plan

1. Start the web server.
2. Open a small benchmark folder.
3. Run `hybrid`.
4. Show progress and normalized findings.
5. Open the comparison docs and highlight benchmark numbers.

## Speaker Notes Checklist

- explain what is benchmark truth and what is reviewed-adjusted truth
- explain why `Securify2` and `Manticore` were excluded from the fair ranking
- explain why hybrid precision improved after noise-reduction passes
- avoid claiming all extra findings are false positives
- keep the live demo short and deterministic

## Immediate Prep Tasks

1. Freeze the benchmark numbers used in the presentation.
2. Build one final comparison table for slides.
3. Capture final UI screenshots.
4. Prepare one deterministic demo target.
5. Draft speaker notes for each slide.
