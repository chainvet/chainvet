# Hybrid Questions Answered

This file answers the follow-up questions about the hybrid approach using the current implementation in:

- `src/core/engines/mod.rs`
- `src/core/scheduler/mod.rs`
- `src/core/artifacts/mod.rs`
- `src/core/triage/mod.rs`
- `src/meta/mod.rs`
- `src/main.rs`

It is a companion to `docs/hybrid_approach.md`.

## 1. What Exactly Are These Static Hints?

These items are fields inside `StaticHints` in `src/core/artifacts/mod.rs`. They are built once by `StaticAdapter::analyze(...)` in `src/core/engines/mod.rs`, then reused by the hybrid scheduler and fuzz guidance.

### Function whitelist / blacklist

These are the static engine's first guess about which functions are callable targets.

- **whitelist**:
  the public/external entrypoints that the runtime engines are allowed to target directly
- **blacklist**:
  private/internal functions that should not be treated as direct user-callable targets

How they are built:

- whitelist:
  from functions that pass `frontend::is_public_entrypoint(...)`
- blacklist:
  from functions whose visibility is `private` or `internal`

How they are used:

- the fuzz guidance uses the whitelist to keep mutation and function selection focused on real callable entrypoints
- the blacklist prevents hybrid fuzzing from wasting time mutating toward functions that cannot actually be called from outside

So the whitelist/blacklist are not vulnerability findings. They are a **reachability and targeting filter**.

### Hotspots

A hotspot is a function that the static pass thinks is more interesting than average.

Each hotspot has:

- function id / name
- a numeric score
- reasons explaining why the score is high

The score is increased by things like:

- storage writes
- external calls
- low-level calls
- unresolved calls
- tainted calls
- using taint sources

How they are used:

- to bias fuzzing toward more security-relevant functions
- to create extra bootstrap seeds for the highest-priority functions
- to raise the priority of frontier goals in those functions

So a hotspot means:

> this function is structurally suspicious or high-impact, so spend more exploration budget on it

### Sinks

A sink is a statically identified risky location derived from detector output.

Each sink records:

- function id / name
- sink kind
- severity
- file
- span

Examples of sink kinds are detector kinds like reentrancy-related or DoS-related locations.

How they are used:

- to record where the static pass thinks important bug-relevant locations exist
- to help decide whether a high-priority risky area has still not been covered
- to raise the priority of frontier goals built for those functions

Important distinction:

- a **hotspot** says "this function looks important"
- a **sink** says "a detector found a specific risky location here"

### Callgraph summary

This is a coarse summary of the contract's call structure.

It records counts like:

- total call sites
- resolved internal calls
- ambiguous calls
- external calls
- unknown calls

What it is used for today:

- mainly persisted as structured context in `static_hints.json`
- useful for debugging, later policy decisions, and understanding how much of the contract is statically resolvable

It is not currently one of the strongest direct scheduler signals. It is more of a **structural summary** than a direct control input.

### Taint summary

This is the aggregated summary of taint-analysis results.

It records counts like:

- source functions
- tainted functions
- tainted vars
- tainted calls

How it is used:

- directly contributes to hotspot scoring
- preserved in static hints for later analysis/debugging

So taint summary is a compact answer to:

> how much attacker-controlled or source-derived flow does the static pass think exists in this target?

### Storage read/write mapping

This is a per-function map of:

- which storage variables a function reads
- which storage variables a function writes

Why it matters:

Hybrid fuzzing is not just trying random single calls. It also tries to discover stateful transaction sequences.

This mapping lets the hybrid build **writer -> reader chains** like:

- function A writes variable `x`
- function B later reads variable `x`

That is useful because many real vulnerabilities only appear after one function mutates state and another function consumes that mutated state.

How it is used:

- `build_fuzz_guidance(...)` constructs storage RW chains from this data
- the fuzz mutator can then force early transactions toward "write state first, then consume it" sequences

This is one of the key features that makes hybrid more than plain single-call fuzzing.

### Argument-domain hints

These are candidate values for each function parameter.

They are built from:

- the parameter name
- literal values found in the function body / IR

Examples:

- parameters like `deadline`, `timestamp`, `expiry` get timestamp-like values
- parameters like `amount`, `price`, `value` get amount-like values
- parameters like `owner`, `recipient`, `sender`, `spender` get address-pool-like values

How they are used:

- bootstrap seeds use them for initial argument values
- fuzz guidance uses them when mutating or constructing transactions

So argument-domain hints are the engine's first answer to:

> if I know nothing else, what values are more plausible than pure random noise for this parameter?

### Address-role hints

These define coarse address roles for the fuzz address pool.

The current implementation creates roles like:

- `owner`
- `attacker`
- `user`

Each role contains:

- the address-pool indices assigned to that role
- evidence for why the role exists
- target functions where that role is likely relevant

Current implementation detail:

- `owner` is inferred from things like `owner`, `admin`, or `governor` state vars and owner/admin/auth-like function names or modifiers
- `attacker` and `user` are default adversarial/general caller roles

How they are used:

- bootstrap seeds choose senders based on these roles
- guided fuzzing chooses sender identities based on the function being exercised

This is the hybrid's current way of asking:

> who should be calling this function if I want to test normal behavior, privileged behavior, and adversarial behavior?

## 2. What Is The Difference Between Static Findings, Meta Findings, And Runtime Meta Promotions?

This distinction is one of the most important parts of understanding hybrid output.

### Static findings

In hybrid, these are findings produced by the **static adapter** and then inserted into the hybrid finding stream as runtime-layer findings.

Source:

- `StaticAdapter::findings(...)`
- `hybrid_static_runtime_finding(...)`

Important detail:

- hybrid does **not** import every raw static detector finding
- it only imports the selected subset that the adapter maps into hybrid runtime findings

These findings usually have:

- `engine = "static"`
- `analysis_layer = "runtime"`
- `evidence_kind = "rule"` or `"rule-backstop"`

Meaning:

- they came from static reasoning
- but the hybrid treats them as valid runtime-layer findings or runtime backstops

Examples:

- `locked-ether`
- `unsafe-delegatecall`
- selected `reentrancy` backstops
- selected `dos-with-failed-call` backstops

So "static findings" in hybrid do **not** mean "all static detector output". They mean:

> the subset of static detector output that the hybrid runtime channel accepts as strong enough to keep

### Meta findings

Meta findings are findings that are useful for classification, compatibility, taxonomy completion, or context, but are **not treated as direct runtime evidence**.

Source:

- `meta::analyze(...)`
- in other paths also `analyze_taxonomy_completion(...)`

These findings usually have:

- `analysis_layer = "meta"`

Meaning:

- they are informative
- they may matter for benchmarking, taxonomy coverage, or explanation
- but they do not claim "the runtime engine directly witnessed this behavior"

Example:

- `incorrect-interface`

That is why meta findings are stored and surfaced separately from runtime findings.

### Runtime meta promotions

These start as meta findings, but a very small allowed subset is promoted into the runtime layer.

Source:

- `meta::runtime_promotions(...)`

Current implementation detail:

- this is intentionally narrow
- currently the important case is `shadowing` in the dedicated variable-shadowing benchmark family

Promoted findings are cloned and changed to:

- `analysis_layer = "runtime"`
- `evidence_kind = "meta-runtime-backstop"`

Meaning:

- the original source was meta
- but the tool intentionally mirrors it into the runtime channel as a controlled backstop

So the difference is:

- **static findings**:
  runtime-layer findings coming from the hybrid static adapter
- **meta findings**:
  non-runtime contextual/classification findings
- **runtime meta promotions**:
  selected meta findings copied into runtime on purpose

The easiest mental model is:

- runtime = "this counts as a primary finding channel"
- meta = "this is useful context, but not primary runtime evidence"
- runtime meta promotion = "this started as meta, but we intentionally allow it into runtime for narrow cases"

## 3. What Does "Seed Corpus" Mean?

A **seed** is one candidate transaction sequence stored in the hybrid runtime.

The data type is `Seed` in `src/core/artifacts/mod.rs`.

A seed contains:

- an id
- a list of transactions (`txs`)
- optional state snapshot id
- a score

Each transaction (`TxSeed`) contains:

- function id
- optional selector / calldata
- concrete arguments
- sender
- value
- environment fields like block timestamp and block number

So a seed is basically:

> a concrete candidate test input for the hybrid engine

The **seed corpus** is the current pool of these candidate inputs.

The fuzzer uses this corpus as its starting material:

- mutate it
- extend it
- replay it
- combine it
- keep the useful seeds
- throw away or deprioritize less useful ones

So when the docs say "seed corpus", they do **not** mean a code corpus or source corpus.
They mean:

> the current pool of concrete transaction sequences that the runtime exploration loop can build on

## 4. How Seed Corpus Bootstrap Actually Works

The code is in `bootstrap_seeds(...)` in `src/core/scheduler/mod.rs`.

The bootstrap phase creates the **initial** seeds before the fuzz loop starts.

It does this in two passes.

### Pass 1: one baseline seed per callable function

For every callable function, hybrid creates a simple one-transaction seed.

A function is considered callable here if it is:

- a public/external entrypoint, or
- a payable fallback/receive with no params

For each such function, the bootstrap code builds a transaction using:

- the function id
- the **first** argument-domain candidate for each parameter, else `0`
- sender:
  owner sender if the function is in owner-targets, otherwise sender `0`
- value:
  `1` if payable, else `0`
- a default block timestamp and block number

This produces seeds like:

- "call function A once with plausible default args"
- "call payable function B with a small nonzero value"
- "call owner-like function C as the owner role"

This pass gives the hybrid a broad baseline coverage start across the callable surface.

### Pass 2: extra aggressive seeds for top hotspots

Then the bootstrap code takes the top hotspot functions and creates extra seeds for them.

Current implementation detail:

- it takes up to the top `8` hotspots

These hotspot seeds differ from the baseline seeds:

- they prefer the **second** argument-domain candidate if available
- they use stronger values such as `1 ether` for payable hotspot calls
- they may flip the sender role:
  for owner-target hotspots, the bootstrap intentionally uses the attacker sender
- they use the hotspot score as the seed score

Why this matters:

The baseline seed says:

> try the obvious call

The hotspot seed says:

> now try a more adversarial or more stressed variant on the functions that static analysis thinks are dangerous

### Why this is different from plain fuzzing

Plain fuzzing often starts from:

- random ABI-generated calls
- generic random argument values
- generic random senders

Hybrid does not start blind. It already knows:

- which functions are callable
- which functions seem dangerous
- which arguments probably want special values
- which sender roles probably matter

So bootstrap seeding is the first place where the hybrid turns static analysis into runtime leverage.

## 5. What Happens In "Coverage, Frontier, And Stall Metrics Drive The Next Decision"?

This happens in the main loop in `src/core/scheduler/mod.rs`.

Each fuzz epoch returns an `EpochResult`.

That result contains several different kinds of information.

### Coverage summary

This tells the scheduler how much progress the epoch made in CFG coverage.

It includes things like:

- covered edge count
- total edges
- coverage percentage
- delta edges
- edge rate

This is the main "did fuzzing make progress?" metric.

### New seeds

These are newly discovered transaction sequences worth keeping.

In the current fuzz adapter, a seed may be kept because it:

- gained new coverage
- improved frontier distance
- produced a finding

These seeds are pushed back into the seed queue so later epochs can mutate them further.

### Findings

These are the runtime findings produced during that fuzz epoch.

They are usually emitted by the fuzzing oracle and added to the finding queue.

Important point:

- these epoch findings are runtime findings
- meta findings were already handled earlier in the scheduler

### Stall metrics

These summarize whether progress is slowing down.

They include things like:

- edge rate
- stagnant epoch count
- coverage delta

These are not findings. They are control signals for deciding whether fuzzing still deserves to keep searching alone.

### Candidate frontier goals

A frontier goal is a not-yet-covered target for future exploration.

In the current implementation, frontier goals are built from **uncovered CFG edges**.

Their priority is increased by:

- hotspot score
- whether the function is associated with a sink

So a frontier goal is basically:

> "here is a specific uncovered edge in a function that looks important"

This is what gives symbolic execution a concrete target later.

### Optional trace prefix

This is the best path prefix the fuzz epoch found for one of these cases:

- a coverage-gaining trace
- a near-miss that improved frontier distance
- a finding-producing trace

The symbolic assist can use this prefix as context when trying to solve a target.

So a trace prefix is:

> the best partial execution context the fuzzing side currently knows for getting closer to something interesting

## 6. What The Scheduler Does With The Epoch Result

After an epoch returns, the scheduler does four immediate things.

### It updates global coverage

It merges:

- covered blocks
- covered edges

into the global coverage state.

This is important because later epochs and later symbolic assists should know what is already covered and what is still frontier.

### It pushes new seeds

The new seeds are added to the seed queue.

That means the next fuzz epoch does not restart from scratch. It evolves from the best material found so far.

### It pushes frontier goals

The uncovered high-priority goals are added to the frontier queue.

That queue is the pool from which symbolic assist targets are later selected.

### It drains findings into triage

The fuzz findings go into a temporary finding queue and are then ingested by `FindingTriage`.

`FindingTriage` does three important things:

- counts everything seen
- deduplicates by signature
- keeps the shorter reproducer when duplicates collide

So the hybrid does not just append every new finding forever. It centralizes them and normalizes them.

## 7. How The Findings Are Separated

There are two separations here.

### Separation 1: runtime vs meta

Each `Finding` has an `analysis_layer` field.

That is how the hybrid knows whether something is:

- runtime
- meta

Examples:

- static runtime backstops:
  `analysis_layer = "runtime"`
- ordinary meta findings:
  `analysis_layer = "meta"`
- runtime meta promotions:
  originally meta, but copied into `runtime`

`FindingTriage` also keeps counts by layer.

The final `HybridReport` records:

- runtime findings total / unique
- meta findings total / unique

The CLI/JSON output in `src/main.rs` then splits them again into:

- `findings` / `findings_raw`
- `meta_findings` / `meta_findings_raw`

### Separation 2: raw vs surfaced

Even after triage, the raw unique findings can still be noisy.

So after the scheduler finishes, the surfaced layer:

- canonicalizes names
- deduplicates again at presentation level
- suppresses low-signal findings when stronger context exists
- suppresses some meta noise

So the pipeline is roughly:

1. generate findings
2. triage them into unique findings
3. split runtime vs meta
4. surface the low-noise output

## 8. Why This Makes Hybrid A Control System

If the tool only did:

1. fuzz
2. then symbolic

that would just be a fixed pipeline.

What makes it a control system is that the scheduler continuously watches progress signals and changes its behavior based on them.

It tracks:

- **stagnant epochs**:
  how many epochs recently failed to clear the minimum expected coverage gain
- **windowed edge-rate history**:
  the recent moving window of coverage growth
- **unmet priority goals**:
  whether statically important sink functions still have not been covered

That means the scheduler is not asking:

> "is fuzzing finished?"

It is asking:

> "is fuzzing still making enough progress on the right parts of the program?"

That is a much better decision rule for hybrid orchestration.

## 9. Exactly When Does Symbolic Execution Start?

This is the most important trigger logic in the scheduler.

In the current implementation, SE starts only if **all** of the following are true:

### Condition 1: there is a reason to assist

This reason is:

- fuzzing has stalled, **or**
- a high-priority sink is still unmet

In code this is the `if (stalled || unmet_priority_goal)` check.

### Condition 2: the SE assist budget is not exhausted

The scheduler also checks:

- `se_assists < budget.max_se_assists`

So even if the campaign keeps stalling, SE cannot be called forever.

### Condition 3: there is a valid frontier goal to target

The scheduler must be able to pull a goal from the frontier queue using `select_frontier_goal_for_assist(...)`.

That selection already filters out goals that are:

- over the max attempt count
- still in backoff

So symbolic execution does **not** start just because fuzzing looks slow. It also needs a concrete target worth aiming at.

## 10. How Does "Fuzzing Has Stalled" Happen Exactly?

This is more specific than "one epoch was bad".

There are two related signals.

### Stagnant epochs

If an epoch's `delta_edges` is lower than `budget.min_coverage_delta`, the scheduler increments `stagnant_epochs`.

That is a simple local signal:

> this epoch did not grow coverage enough

### Windowed stall detection

The stronger signal is `stalled = update_stall_window(...)`.

That function keeps a recent window of `edge_rate` values and computes whether their average falls below an epsilon threshold derived from the budget.

So "stalled" means something closer to:

> over the recent window, fuzzing is no longer discovering enough new edges per unit of effort

That is a much better trigger than a one-epoch dip.

## 11. How Does "A High-Priority Sink Is Still Unmet" Happen?

This comes from `has_unmet_sink_goal(...)`.

The scheduler compares:

- the statically recorded sink functions
- the set of functions that have already been covered

If a sink function has still never been covered, `unmet_priority_goal` becomes true.

So this condition means:

> static analysis says a function contains an important risky location, but fuzzing still has not reached that function

This is a direct reason to ask symbolic execution for help even if fuzzing is not globally stalled yet.

## 12. What Happens Right Before SE Starts?

When the trigger passes, the scheduler:

1. selects the highest-priority valid frontier goal
2. increments that goal's attempt count
3. calls symbolic assist with:
   - the goal
   - the best trace prefix from the current epoch or previous epoch
   - the SE budget

Then the symbolic engine tries to solve for that target.

Important detail:

- SE is not solving "find me any bug"
- SE is solving "help me reach this uncovered high-priority target"

That is why the hybrid symbolic engine is called an **assist** engine.

## 13. What Happens If SE Fails?

If SE does not inject useful seeds and does not produce findings:

- the goal is not immediately retried forever
- it is either requeued with reduced priority and backoff, or eventually dropped after enough failed attempts

So repeated symbolic misses do not permanently stall the whole hybrid loop.

This is another reason the design is practical: it prevents symbolic execution from dominating the schedule after repeated failures.

## 14. Short Answers

### What are those static hint fields?

They are the static pass's structured guidance for the hybrid runtime loop.

### What is a seed corpus?

It is the pool of concrete transaction sequences that fuzzing and symbolic assist build on.

### What are static findings vs meta findings vs runtime meta promotions?

- static findings:
  static-origin findings accepted into the runtime channel
- meta findings:
  contextual/classification findings kept outside runtime
- runtime meta promotions:
  selected meta findings intentionally copied into runtime as narrow backstops

### When does SE start?

Only when:

- fuzzing has stalled or an important sink is still uncovered
- the SE assist budget still allows another assist
- a valid frontier goal exists and is not exhausted/backed off

That is the exact reason hybrid is a **targeted assist loop** rather than "always run symbolic too".
