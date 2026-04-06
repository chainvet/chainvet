# P2: Static pre-filter → Targeted SE exploit trace generation → Fuzz broadening

## Flow
    1. Static analysis identifies a small set of suspicious sites: external calls, delegatecall usage, storage writes to privileged slots, etc.
    2. SE targets those sites, generating replayable traces and concrete values. Mythril outputs transaction sequences and initial state contexts per issue.
    3. Fuzzer uses those traces as seeds and explores variations around them (mutate args, callers, transaction order).

## Artifacts passed

    1. Static → SE: slice (backward slice from sink), path_goal (PC/location), constraint_hints derived from require conditions.
    2. SE → Fuzz: tx_trace_seed (sequence) plus minimized_constraints.
    3. Fuzz → Static: optional trace_features to refine heuristics (e.g., which warnings are reachable).

## Trigger

    Start SE only for findings above a static severity threshold.

## Expected benefits

    High signal: you invest SE where static already indicates risk.
    You get immediately replayable traces.

## Risks

    SE bounded-transaction limitations: Mythril notes default 3 tx and needing -t increases to catch deeper issues; scaling this can explode.
