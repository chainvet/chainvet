# ChainVet — VS Code extension

Run the ChainVet smart-contract security analyzer directly inside VS Code. Findings appear as native diagnostics (squiggles + Problems panel) and in a dedicated Findings tree in the activity bar.

## What you get

- **Native diagnostics** — every finding shows as an inline squiggle in the Solidity source and in the Problems panel. Severities map to: High/Critical → Error, Medium/Low → Warning, Info → Information.
- **Findings sidebar** — a "ChainVet" activity-bar entry with the findings grouped by severity. Click a finding to jump to the exact range in the source.
- **Status sidebar** — current analyzer state and quick actions (analyze · cancel · clear).
- **Status bar item** — shows analyzer state at a glance, click to analyze or cancel.
- **Commands** — accessible from the Command Palette (`Ctrl/Cmd+Shift+P` → "ChainVet: …").
- **Context menus** — right-click a `.sol` file or folder in the Explorer to analyze it.
- **Run on save** (opt-in) — re-analyze a file every time you save.

## Prerequisites

1. Build the ChainVet analyzer (the Rust binary) from the repo root:

   ```bash
   cargo build --release   # produces target/release/ChainVet
   ```

   The extension auto-discovers the binary at `<workspace>/target/release/ChainVet`, then `target/debug/ChainVet`, then `chainvet` / `ChainVet` on `PATH`. It also accepts the older `Static` binary name during migration. To override, set `chainvet.binaryPath` in your settings.

2. Node.js 18+ and `npm`.

## Install / run from source

```bash
cd vscode-extension
npm install
npm run compile          # builds out/extension.js
```

Then, from VS Code:

- Open the `vscode-extension` folder
- Press <kbd>F5</kbd> → a new "Extension Development Host" window opens with ChainVet loaded
- Open a Solidity workspace inside it and run **ChainVet: Analyze Current File**

To package a `.vsix` for distribution:

```bash
npx @vscode/vsce package
```

Then `code --install-extension chainvet-0.1.0.vsix` (or use the VS Code UI: Extensions → "Install from VSIX…").

## Commands

| Command | What it does |
| --- | --- |
| `ChainVet: Analyze Current File` | Run the analyzer on the file in the active editor |
| `ChainVet: Analyze Workspace` | Run on the first workspace folder (every reachable `.sol`) |
| `ChainVet: Analyze Selected File/Folder…` | Pick a target via dialog or explorer context |
| `ChainVet: Cancel Running Analysis` | Stop the in-flight analyzer process |
| `ChainVet: Clear Findings` | Remove diagnostics and reset the Findings view |
| `ChainVet: Refresh Findings View` | Re-render the sidebar tree |
| `ChainVet: Open Settings` | Jump to extension settings |

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `chainvet.binaryPath` | `""` (auto-discover) | Absolute path to the analyzer binary |
| `chainvet.mode` | `"hybrid"` | One of `hybrid`, `static`, `symbolic`, `fuzzing` |
| `chainvet.runOnSave` | `false` | Re-analyze on file save |
| `chainvet.showInformationFindings` | `true` | Surface info-level findings as VS Code Information diagnostics |
| `chainvet.analysisTimeoutSeconds` | `600` | Maximum run time before the analyzer is aborted |

## How it works

The extension spawns the analyzer binary with `--<mode> <path> --json` and parses the JSON it writes to stdout. Findings are mapped to `vscode.Diagnostic`s using their byte offsets; if a finding has no usable span, the diagnostic falls at the top of the file. Warnings (from stderr) are surfaced in the dedicated "ChainVet" output channel.

The Findings tree groups results by severity (`high → medium → low → info → unknown`). Clicking a node opens the file and selects the offending range.

## Troubleshooting

- **"ChainVet analyzer binary not found"** — build the Rust crate, or set `chainvet.binaryPath` to an absolute path.
- **Findings show on line 1** — the analyzer didn't emit start/end offsets for that finding. The diagnostic still has the kind, severity, and message; check the Findings tree for context.
- **Open the "ChainVet" output channel** (`View → Output → ChainVet`) to see the exact command line, stderr, and parsed warnings.

## License

See the parent repository.
