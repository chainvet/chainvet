import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";
import { ChainVetFinding } from "./types";
import { resolveFindingRange } from "./locator";

/**
 * Webview panel that renders a rich, branded view of a selected finding.
 * Lives at the side of the editor and updates in place whenever the user
 * picks a different finding in the tree.
 */
export class DetailPanel {
  private static current: DetailPanel | null = null;
  private readonly panel: vscode.WebviewPanel;
  private readonly disposables: vscode.Disposable[] = [];
  private currentFinding: ChainVetFinding | null = null;

  static showOrUpdate(context: vscode.ExtensionContext, finding: ChainVetFinding): void {
    if (DetailPanel.current) {
      DetailPanel.current.update(finding);
      DetailPanel.current.panel.reveal(vscode.ViewColumn.Beside, true);
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      "chainvetFindingDetail",
      "ChainVet · Finding",
      { viewColumn: vscode.ViewColumn.Beside, preserveFocus: true },
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [vscode.Uri.file(path.join(context.extensionPath, "media"))],
      },
    );
    DetailPanel.current = new DetailPanel(context, panel);
    DetailPanel.current.update(finding);
  }

  static dispose(): void {
    DetailPanel.current?.panel.dispose();
  }

  private constructor(
    context: vscode.ExtensionContext,
    panel: vscode.WebviewPanel,
  ) {
    this.panel = panel;
    const iconUri = vscode.Uri.file(path.join(context.extensionPath, "media", "chainvet-sidebar.png"));
    this.panel.iconPath = { light: iconUri, dark: iconUri };
    this.panel.onDidDispose(() => {
      DetailPanel.current = null;
      for (const d of this.disposables) d.dispose();
    });
    this.panel.webview.onDidReceiveMessage(
      (message) => this.onMessage(message),
      undefined,
      this.disposables,
    );
  }

  private async update(finding: ChainVetFinding): Promise<void> {
    this.currentFinding = finding;
    const heading = titleCase(finding.kind || "Finding");
    this.panel.title = `ChainVet · ${heading}`;
    const html = await this.render(finding);
    this.panel.webview.html = html;
  }

  private async onMessage(message: { command?: string }): Promise<void> {
    if (!message?.command) return;
    const finding = this.currentFinding;
    if (!finding) return;
    if (message.command === "reveal") {
      await vscode.commands.executeCommand("chainvet.revealFinding", finding);
    } else if (message.command === "openFile" && finding.file) {
      const uri = await resolveFileUri(finding.file);
      if (uri) {
        await vscode.commands.executeCommand("vscode.open", uri);
      }
    }
  }

  private async render(finding: ChainVetFinding): Promise<string> {
    const sev = severityKey(finding.severity);
    const tone = severityTone(sev);
    const docText = finding.file ? await readFileBest(finding.file) : null;
    const resolution = docText ? resolveFindingRange(docText, finding) : null;

    const snippet = docText && resolution
      ? buildSnippet(docText, resolution.range.start.line, resolution.range.end.line)
      : null;

    const locationLine = (resolution?.range.start.line ?? -1) + 1;
    const locationHint = resolution
      ? resolution.source === "offset"
        ? `line ${locationLine}`
        : resolution.source === "function"
          ? `~line ${locationLine} (approx. function ${escapeHtml(finding.function ?? "")})`
          : resolution.source === "keyword"
            ? `~line ${locationLine} (approx. by kind ${escapeHtml(finding.kind ?? "")})`
            : "no precise location"
      : "no precise location";

    const meta: Array<[string, string | undefined]> = [
      ["file", finding.file],
      ["function", finding.function ? `${finding.function}()` : undefined],
      ["layer", finding.layer],
      ["category", finding.category],
      ["evidence", finding.evidence],
      ["confidence", finding.confidence],
    ];

    const metaRows = meta
      .filter(([, v]) => v && String(v).length > 0)
      .map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(String(v))}</dd>`)
      .join("");

    const heading = titleCase(finding.kind || "Finding");

    return /* html */ `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src ${this.panel.webview.cspSource};">
<style>
  :root {
    /* Catppuccin Mocha · Lavender accent */
    --ctp-base:     #1e1e2e;
    --ctp-mantle:   #181825;
    --ctp-surface0: #313244;
    --ctp-surface1: #45475a;
    --ctp-text:     #cdd6f4;
    --ctp-subtext0: #a6adc8;
    --ctp-overlay1: #7f849c;
    --ctp-overlay0: #6c7086;
    --ctp-lavender: #b4befe;
    --ctp-red:      #f38ba8;
    --ctp-peach:    #fab387;
    --ctp-yellow:   #f9e2af;
    --ctp-sky:      #89dceb;
    --ctp-green:    #a6e3a1;

    --tone:      var(${toneVar(sev)});
    --tone-soft: ${toneSoft(sev)};

    --line:        rgba(186, 194, 222, 0.10);
    --line-strong: rgba(186, 194, 222, 0.18);

    --font-sans: var(--vscode-font-family, "IBM Plex Sans", system-ui, sans-serif);
    --font-mono: var(--vscode-editor-font-family, "IBM Plex Mono", ui-monospace, monospace);
  }

  * { box-sizing: border-box; }

  html, body {
    margin: 0; padding: 0;
    background: var(--ctp-base);
    color: var(--ctp-text);
    font-family: var(--font-sans);
    font-size: 13px;
    line-height: 1.55;
  }

  body::before {
    content: "";
    position: fixed; inset: 0;
    pointer-events: none;
    background:
      radial-gradient(circle at 90% -10%, rgba(180, 190, 254, 0.06), transparent 45%),
      radial-gradient(circle at -10% 110%, rgba(203, 166, 247, 0.05), transparent 45%);
  }

  main {
    position: relative;
    padding: 1.5rem 1.5rem 2.5rem;
    max-width: 760px;
    margin: 0 auto;
  }

  header.lc-head {
    display: grid;
    grid-template-columns: 1fr auto;
    align-items: start;
    gap: 1rem;
    padding-bottom: 1.1rem;
    border-bottom: 1px solid var(--line);
  }

  .lc-eyebrow {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    font-family: var(--font-mono);
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: var(--ctp-overlay1);
    margin-bottom: 0.5rem;
  }

  .lc-eyebrow::before {
    content: "";
    display: inline-block;
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--tone);
    box-shadow: 0 0 8px var(--tone);
  }

  h1.lc-kind {
    margin: 0 0 0.55rem;
    font-size: 22px;
    font-weight: 600;
    letter-spacing: -0.02em;
    color: var(--ctp-text);
    line-height: 1.2;
  }

  .lc-loc {
    font-family: var(--font-mono);
    font-size: 11.5px;
    color: var(--ctp-subtext0);
  }
  .lc-loc .file { color: var(--ctp-subtext0); }
  .lc-loc .fn { color: var(--ctp-lavender); }
  .lc-loc .sep { color: var(--ctp-overlay0); margin: 0 0.25rem; }

  .lc-badges {
    display: flex; gap: 0.35rem; flex-wrap: wrap;
    justify-content: flex-end;
  }

  .lc-tag {
    display: inline-flex; align-items: center;
    padding: 3px 9px;
    border-radius: 999px;
    border: 1px solid transparent;
    background: var(--ctp-surface0);
    color: var(--ctp-subtext0);
    font-family: var(--font-mono);
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    white-space: nowrap;
  }

  .lc-tag-sev {
    background: var(--tone-soft);
    color: var(--tone);
    border-color: var(--tone-soft);
  }

  .lc-actions {
    margin-top: 0.85rem;
    display: flex; gap: 0.5rem; flex-wrap: wrap;
  }

  button {
    appearance: none;
    border: 1px solid var(--line-strong);
    background: var(--ctp-surface0);
    color: var(--ctp-text);
    font-family: var(--font-sans);
    font-size: 12px;
    font-weight: 500;
    padding: 6px 12px;
    border-radius: 6px;
    cursor: pointer;
    display: inline-flex; align-items: center; gap: 0.4rem;
    transition: background 0.12s ease, color 0.12s ease, border-color 0.12s ease, transform 0.05s ease;
  }
  button:hover { background: var(--ctp-surface1); border-color: var(--ctp-lavender); }
  button:active { transform: translateY(0.5px); }
  button.lc-primary {
    background: var(--ctp-lavender);
    color: var(--ctp-base);
    border-color: var(--ctp-lavender);
  }
  button.lc-primary:hover {
    background: #c5cdff; border-color: #c5cdff;
    box-shadow: 0 0 0 4px rgba(180, 190, 254, 0.18);
  }

  section.lc-section {
    margin-top: 1.5rem;
    padding-top: 1.2rem;
    border-top: 1px solid var(--line);
  }
  section.lc-section:first-of-type { border-top: 0; padding-top: 1.2rem; }

  .lc-section-label {
    display: block;
    margin-bottom: 0.55rem;
    font-family: var(--font-mono);
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--ctp-overlay1);
  }

  .lc-message {
    margin: 0;
    padding: 0.85rem 1rem;
    background: var(--ctp-mantle);
    border: 1px solid var(--line);
    border-left: 3px solid var(--tone);
    border-radius: 8px;
    color: var(--ctp-text);
    font-size: 13px;
    line-height: 1.6;
    white-space: pre-wrap;
    word-break: break-word;
  }

  dl.lc-meta {
    margin: 0;
    display: grid;
    grid-template-columns: max-content 1fr;
    column-gap: 1.5rem;
    row-gap: 0.45rem;
  }
  dl.lc-meta dt {
    font-family: var(--font-mono);
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--ctp-overlay1);
    padding-top: 2px;
  }
  dl.lc-meta dd {
    margin: 0;
    font-family: var(--font-mono);
    font-size: 11.5px;
    color: var(--ctp-text);
    word-break: break-word;
  }

  pre.lc-snippet {
    margin: 0;
    padding: 0;
    background: var(--ctp-mantle);
    border: 1px solid var(--line);
    border-radius: 8px;
    overflow: hidden;
    font-family: var(--font-mono);
    font-size: 12px;
    line-height: 1.55;
  }
  .lc-snippet table {
    width: 100%;
    border-collapse: collapse;
  }
  .lc-snippet td {
    padding: 1px 0;
    vertical-align: top;
  }
  .lc-snippet .ln {
    width: 3.5rem;
    text-align: right;
    padding: 1px 0.75rem 1px 0.75rem;
    color: var(--ctp-overlay0);
    user-select: none;
    border-right: 1px solid var(--line);
    background: rgba(0, 0, 0, 0.18);
  }
  .lc-snippet .code {
    padding: 1px 0.85rem;
    white-space: pre;
    color: var(--ctp-text);
    overflow-x: hidden;
  }
  .lc-snippet .hit .ln {
    color: var(--tone);
    background: var(--tone-soft);
    font-weight: 600;
  }
  .lc-snippet .hit .code {
    background: var(--tone-soft);
  }

  .lc-snippet-foot {
    padding: 0.4rem 0.85rem;
    color: var(--ctp-overlay1);
    font-family: var(--font-mono);
    font-size: 10px;
    border-top: 1px solid var(--line);
    text-align: right;
    background: var(--ctp-mantle);
  }

  .lc-empty {
    padding: 1rem;
    background: var(--ctp-mantle);
    border: 1px dashed var(--line-strong);
    border-radius: 8px;
    color: var(--ctp-overlay1);
    font-family: var(--font-mono);
    font-size: 11.5px;
  }
</style>
</head>
<body>
<main>
  <header class="lc-head">
    <div>
      <div class="lc-eyebrow">${escapeHtml(tone.label)} · finding</div>
      <h1 class="lc-kind">${escapeHtml(heading)}</h1>
      <div class="lc-loc">
        ${finding.file ? `<span class="file">${escapeHtml(path.basename(finding.file))}</span>` : ""}
        ${finding.function ? `<span class="sep">::</span><span class="fn">${escapeHtml(finding.function)}()</span>` : ""}
        ${locationHint ? `<span class="sep">·</span>${escapeHtml(locationHint)}` : ""}
      </div>
      <div class="lc-actions">
        <button class="lc-primary" type="button" data-cmd="reveal">
          $(arrow-right) Reveal in editor
        </button>
        ${finding.file ? `<button type="button" data-cmd="openFile">Open file</button>` : ""}
      </div>
    </div>
    <div class="lc-badges">
      <span class="lc-tag lc-tag-sev">${escapeHtml(String(finding.severity || "unspecified").toLowerCase())}</span>
      ${finding.confidence ? `<span class="lc-tag">conf · ${escapeHtml(String(finding.confidence).toLowerCase())}</span>` : ""}
      ${finding.layer ? `<span class="lc-tag">${escapeHtml(finding.layer)}</span>` : ""}
    </div>
  </header>

  ${finding.message ? `
    <section class="lc-section">
      <span class="lc-section-label">Message</span>
      <p class="lc-message">${escapeHtml(finding.message)}</p>
    </section>
  ` : ""}

  <section class="lc-section">
    <span class="lc-section-label">Source</span>
    ${snippet ? snippet : `<div class="lc-empty">Source preview unavailable.</div>`}
  </section>

  ${metaRows ? `
    <section class="lc-section">
      <span class="lc-section-label">Metadata</span>
      <dl class="lc-meta">${metaRows}</dl>
    </section>
  ` : ""}
</main>

<script>
  const vscode = acquireVsCodeApi();
  for (const button of document.querySelectorAll("button[data-cmd]")) {
    button.addEventListener("click", () => {
      vscode.postMessage({ command: button.dataset.cmd });
    });
  }
  // Replace $(name) codicon placeholders with simple unicode glyphs.
  document.body.innerHTML = document.body.innerHTML
    .replace(/\\$\\(arrow-right\\)/g, "→");
</script>
</body>
</html>
    `;
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────

type SeverityKey = "high" | "medium" | "low" | "info" | "unknown";

function severityKey(value?: string): SeverityKey {
  const v = String(value || "").toLowerCase();
  if (v.includes("critical") || v.includes("high")) return "high";
  if (v.includes("medium") || v.includes("moderate")) return "medium";
  if (v.includes("low")) return "low";
  if (v.includes("info")) return "info";
  return "unknown";
}

function severityTone(key: SeverityKey): { label: string } {
  switch (key) {
    case "high":     return { label: "high severity" };
    case "medium":   return { label: "medium severity" };
    case "low":      return { label: "low severity" };
    case "info":     return { label: "informational" };
    case "unknown":  return { label: "unspecified" };
  }
}

function toneVar(key: SeverityKey): string {
  switch (key) {
    case "high":     return "--ctp-red";
    case "medium":   return "--ctp-peach";
    case "low":      return "--ctp-yellow";
    case "info":     return "--ctp-sky";
    case "unknown":  return "--ctp-lavender";
  }
}

function toneSoft(key: SeverityKey): string {
  switch (key) {
    case "high":     return "rgba(243, 139, 168, 0.18)";
    case "medium":   return "rgba(250, 179, 135, 0.18)";
    case "low":      return "rgba(249, 226, 175, 0.16)";
    case "info":     return "rgba(137, 220, 235, 0.18)";
    case "unknown":  return "rgba(180, 190, 254, 0.16)";
  }
}

function titleCase(value: string): string {
  return String(value || "")
    .split("-")
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join(" ");
}

function escapeHtml(value: string): string {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function buildSnippet(text: string, startLine: number, endLine: number): string {
  const lines = text.split(/\r?\n/);
  const context = 4;
  const from = Math.max(0, startLine - context);
  const to = Math.min(lines.length - 1, endLine + context);
  const rows: string[] = [];
  for (let i = from; i <= to; i++) {
    const isHit = i >= startLine && i <= endLine;
    const lineNumber = i + 1;
    rows.push(
      `<tr class="${isHit ? "hit" : ""}"><td class="ln">${lineNumber}</td><td class="code">${escapeHtml(lines[i] || " ")}</td></tr>`,
    );
  }
  const totalLines = lines.length;
  return `<pre class="lc-snippet"><table>${rows.join("")}</table></pre><div class="lc-snippet-foot">${from + 1}–${to + 1} of ${totalLines}</div>`;
}

async function readFileBest(filePath: string): Promise<string | null> {
  try {
    if (path.isAbsolute(filePath) && fs.existsSync(filePath)) {
      return fs.readFileSync(filePath, "utf8");
    }
    const folders = vscode.workspace.workspaceFolders ?? [];
    for (const folder of folders) {
      const candidate = path.join(folder.uri.fsPath, filePath);
      if (fs.existsSync(candidate)) {
        return fs.readFileSync(candidate, "utf8");
      }
    }
    const matches = await vscode.workspace.findFiles(`**/${path.basename(filePath)}`, "**/node_modules/**", 5);
    if (matches[0]) return fs.readFileSync(matches[0].fsPath, "utf8");
  } catch {
    /* ignore */
  }
  return null;
}

async function resolveFileUri(filePath: string): Promise<vscode.Uri | null> {
  if (path.isAbsolute(filePath) && fs.existsSync(filePath)) {
    return vscode.Uri.file(filePath);
  }
  const folders = vscode.workspace.workspaceFolders ?? [];
  for (const folder of folders) {
    const candidate = path.join(folder.uri.fsPath, filePath);
    if (fs.existsSync(candidate)) {
      return vscode.Uri.file(candidate);
    }
  }
  const matches = await vscode.workspace.findFiles(`**/${path.basename(filePath)}`, "**/node_modules/**", 5);
  return matches[0] ?? null;
}
