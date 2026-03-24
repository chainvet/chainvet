# Google Stitch Prompt For Analyzer GUI

Use this prompt in Google Stitch:

```text
Design a modern web app UI/UX template for a developer tool called "Hybrid Smart Contracts Analyzer".

This is not a marketing site. It is a serious desktop-first analysis workspace for security engineers and smart contract auditors. The interface should feel focused, technical, clean, and trustworthy.

Product context:
- The tool analyzes Solidity smart contracts.
- It runs locally on localhost.
- The workspace is rooted at the directory where the tool was launched.
- Users browse folders, pick a Solidity file or folder, choose an analysis mode, run analysis, watch progress, cancel long jobs, and inspect organized findings.
- There are 4 approaches: static, symbolic, fuzzing, and hybrid.
- The UI should present all approaches through the same output structure so the experience feels unified.

Visual direction:
- Use Catppuccin Mocha as the color theme.
- Dark mode only.
- Make it look modern, premium, and engineering-focused.
- Avoid generic SaaS dashboard styling.
- Use clear visual hierarchy, elegant spacing, rounded panels, and subtle gradients/glass surfaces.
- Typography should feel intentional and technical, not playful.
- The interface should be simple, fast to scan, and suitable for long analysis sessions.

Primary layout:
- Left sidebar: file browser rooted at the working directory.
- Main content area with:
  - top header with app name and rooted directory pill
  - run controls
  - live progress area
  - findings/results panel
  - raw JSON / raw report panel
  - artifacts/warnings area

Required UI sections:

1. Header
- Title: "Hybrid Smart Contracts Analyzer"
- Small subtitle indicating local Solidity security analysis
- A pill or status chip showing the current root directory

2. File Browser
- Breadcrumb navigation
- Folder list + Solidity file list
- Clear distinction between selecting a folder vs selecting a single `.sol` file
- Button like "Analyze This Folder"
- Show which target is currently selected

3. Analyzer Controls
- Read-only selected target field
- Mode selector with:
  - static
  - symbolic
  - fuzzing
  - hybrid
- Primary "Run Analysis" button
- Secondary/danger "Cancel Analysis" button
- Status line for current job state

4. Progress Area
- A real visible progress bar area for long-running jobs
- Should support:
  - running state
  - cancelling state
  - completed state
- Show elapsed time
- Show current phase text like:
  - Running symbolic analysis on auction.sol
  - Cancelling hybrid analysis
- Since actual backend progress may be approximate, design this area so indeterminate progress still feels intentional and trustworthy

5. Findings / Results
- This is the most important section
- Findings should be grouped visually by severity
- Each severity should feel like its own block/section
- Severity groups: high, medium, low, unknown
- Each finding card should include:
  - vulnerability kind
  - layer (static/runtime/meta/hybrid if relevant)
  - severity
  - confidence
  - category
  - message
  - file/function/location metadata
  - evidence tag if available
- Confidence must be visually visible, not hidden
- Show count of findings
- The design should handle both many findings and zero findings

6. Summary / Snapshot
- A clean summary card grid above the findings
- Use one shared format across all analysis modes
- Example cards:
  - Mode
  - Displayed Findings
  - Raw Findings
  - Suppressed
  - Unique Kinds
  - High Severity
  - High Confidence
  - Located Findings
  - Warnings
  - Artifacts

7. Raw Output
- A collapsible or dedicated panel for raw JSON
- Monospace code-like styling
- Easy to scan

8. Warnings and Artifacts
- Separate styled boxes for analyzer warnings and generated run artifacts
- Artifacts can be shown as a simple list with paths

Interaction and UX expectations:
- Desktop first, but still responsive for tablets and laptops
- Fast scanning is critical
- Avoid clutter
- Use subtle motion for loading/progress states
- Make long-running analysis feel alive and understandable
- Emphasize seriousness and precision
- No blockchain cliches, no neon hacker aesthetic, no cartoonish graphics

Design goals:
- Feels like a polished local security analysis workstation
- Better than a generic admin dashboard
- Suitable for auditors, researchers, and developers
- Strong information hierarchy
- Findings should be the visual focal point

Please generate:
- a full-page app layout
- key states for idle, running, completed, and empty findings
- a strong component system for severity cards, confidence badges, summary cards, file browser items, and progress panels
```

Optional shorter version:

```text
Design a Catppuccin Mocha dark-mode UI for a local developer tool called "Hybrid Smart Contracts Analyzer". It is a desktop-first Solidity security analysis workspace, not a marketing site. The app has a file browser, mode selector (static/symbolic/fuzzing/hybrid), run/cancel controls, a visible progress bar for long jobs, summary cards, severity-grouped findings with confidence badges, warnings/artifacts, and a raw JSON panel. Make it feel premium, technical, calm, and auditor-focused. Avoid generic SaaS dashboards and avoid crypto cliches. The findings area should be the visual center of the product.
```
