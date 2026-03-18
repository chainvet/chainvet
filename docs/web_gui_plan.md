# Web GUI Plan

Status: `planned`

Priority shift on `2026-03-18`:

- Runtime-accuracy improvement work is paused temporarily.
- The active planning focus is a browser-based GUI for the analyzer.
- Runtime work should not continue until the GUI direction in this document is either approved as-is or adjusted.

## Goal

Build a local-first web GUI for the Solidity analyzer so a user can:

- provide Solidity input without using the CLI directly
- choose analysis mode and options from a clean control panel
- run the analyzer and track progress
- inspect findings, grouped output, raw JSON/text, and generated artifacts in one place

## Product Scope

The first GUI version should support:

- input by file upload
- input by paste-in editor
- mode selection:
  - `static`
  - `symbolic`
  - `fuzzing`
  - `hybrid`
- common options:
  - `json`
  - IR dump mode
  - basic budget/profile presets
- organized output views:
  - overview summary
  - findings table/cards
  - grouped by function / severity / kind
  - raw output
  - run artifacts
- local run history for recent analyses

Non-goals for V1:

- multi-user auth
- remote job orchestration
- benchmark dashboards
- collaborative editing

## Recommended Architecture

Recommended stack:

- Backend: Rust HTTP server inside this repo
- Frontend: small SPA in `webui/` using `React + TypeScript + Vite`
- Transport: JSON over HTTP for submission/results, SSE for live progress later

Why this is the recommended path:

- the repo is currently CLI-only and Rust-only; there is no existing web framework to extend
- the analyzer logic should be reused directly in-process instead of shelling out to the CLI
- a separate frontend keeps GUI concerns isolated from analyzer core logic
- React/Vite is the fastest way to get a modern, responsive results UI without fighting server-rendered interactivity

Fallback option if avoiding a Node frontend becomes a hard requirement:

- use `axum` + `askama` server-rendered templates
- this reduces toolchain sprawl
- but it will make the interactive results UX slower to evolve

## Proposed Repo Layout

```text
src/
  web/
    mod.rs
    server.rs
    api.rs
    models.rs
    run_manager.rs
    adapters.rs
webui/
  package.json
  vite.config.ts
  src/
    main.tsx
    app/
    components/
    features/analyzer/
    features/runs/
    lib/
docs/
  web_gui_plan.md
```

## Backend Plan

Add a new web layer that reuses the existing analyzer entrypoints directly.

Key backend responsibilities:

- accept uploaded Solidity files or pasted source
- map UI options into analyzer config
- run analysis jobs without blocking the HTTP server
- persist outputs in the existing `runs/` structure when appropriate
- expose normalized results for the frontend

Recommended dependencies to add:

- `tokio`
- `axum`
- `tower-http`
- `uuid`
- `tracing`
- `tracing-subscriber`

### Backend Endpoints

Phase 1 endpoints:

- `GET /api/health`
- `POST /api/analyze`
- `GET /api/runs`
- `GET /api/runs/:id`
- `GET /api/runs/:id/findings`
- `GET /api/runs/:id/artifacts/:name`

Phase 2 endpoint:

- `GET /api/runs/:id/events`
  - SSE stream for progress and state transitions

### Backend Data Model

Use a normalized response model so the GUI does not need mode-specific parsing everywhere.

Core response fields:

- `run_id`
- `status`
- `mode`
- `target`
- `started_at`
- `finished_at`
- `summary`
- `findings`
- `meta_findings`
- `raw_output`
- `artifacts`
- `errors`

### Backend Integration Strategy

Do not invoke `cargo run` or shell out to the binary from the web server.

Instead:

- extract reusable analyzer entrypoints from `src/main.rs`
- expose a programmatic API that accepts:
  - target source/path
  - selected mode
  - output format
  - execution options
- let both CLI and web server call the same internal API

This avoids:

- duplicated option parsing
- fragile subprocess output parsing
- mismatches between CLI and GUI behavior

## Frontend Plan

The GUI should feel simple, modern, and dense enough for technical users.

Recommended layout:

- left panel: input and run controls
- center panel: editor / uploaded file details / run state
- right panel: findings and result tabs

Primary UI sections:

- header
  - app name
  - mode badge
  - recent runs shortcut
- analysis form
  - upload area
  - paste editor
  - mode selector
  - advanced options drawer
  - run button
- results workspace
  - overview tab
  - findings tab
  - raw output tab
  - artifacts tab

### Results UX Requirements

Each finding should show:

- kind
- severity/confidence
- runtime vs meta classification
- function name / function id
- evidence message
- source location when available

Results organization should support:

- filter by kind
- filter by severity
- filter by runtime/meta
- search by function or message
- collapse duplicate findings

### Visual Direction

The interface should be:

- light theme first
- clean, modern, and not dashboard-cluttered
- code-centric
- card and tab based, with restrained motion

Suggested visual language:

- neutral background with strong contrast panels
- monospace for findings and raw output
- one accent color for active mode / run status
- sticky run controls

## Implementation Phases

### Phase 0: Pause and API Extraction

- freeze runtime-accuracy work temporarily
- extract reusable analyzer orchestration from `src/main.rs`
- define shared request/response models

### Phase 1: Backend Service

- add `src/web/`
- create HTTP server and basic routes
- implement `POST /api/analyze`
- return normalized run results

### Phase 2: Frontend Shell

- scaffold `webui/`
- build analyzer form
- wire API submission
- render run status and top-level summary

### Phase 3: Findings Workspace

- findings table/cards
- grouping and filtering
- raw JSON/text viewer
- artifact links and summaries

### Phase 4: Run History and Polish

- recent runs list
- rerun with same options
- better empty/loading/error states
- responsive layout cleanup

### Phase 5: Live Progress

- add SSE endpoint
- show running state, per-stage progress, and streaming logs

## First Implementation Slice

The first working slice should be:

1. start a local server
2. open a web page
3. upload or paste one Solidity file
4. choose one mode
5. run analysis
6. see normalized findings and raw output

If that slice works cleanly, expand from there.

## Immediate Next Tasks

1. Decide whether to accept the recommended `axum + React/Vite` stack.
2. Extract analyzer execution into a reusable internal API from `src/main.rs`.
3. Add a minimal web server with `POST /api/analyze`.
4. Build a mock frontend against fixture JSON before wiring every result detail.
5. Add run-history support using existing `runs/` artifacts.

## Pause Context For Runtime Accuracy Work

At the point this GUI plan became the priority, runtime work was paused with focused validation showing:

- symbolic exact `dos-block-gas-limit` recovery on `list_dos.sol`
- fuzzing exact `dos-block-gas-limit` recovery on `list_dos.sol`
- symbolic exact `timestamp-dependency` recovery on `theRun.sol`
- fuzzing exact `timestamp-dependency` backstop recovery on `theRun.sol`
- hybrid WalletLibrary takeover-path backstop unit coverage exists

Known unresolved items before the pause:

- no new full benchmark rerun yet for this latest focused batch
- `WalletLibrary.sol` still reports solc frontend parse errors in direct CLI runs
- symbolic/fuzzing `WalletLibrary.sol` still need exact `unprotected-selfdestruct` runtime recovery if benchmark-relative scoring remains important later
- `Unprotected.sol` should stay `access-control` only for real bug-level accuracy unless benchmark policy changes

Files with paused runtime-improvement work in progress:

- `src/symbolic/mod.rs`
- `src/fuzzing/executor.rs`
- `src/fuzzing/oracle.rs`
- `src/fuzzing/types.rs`
- `src/fuzzing/runner.rs`
- `src/core/engines/mod.rs`
