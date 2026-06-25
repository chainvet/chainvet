import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import { Analyzer, AnalyzerResult } from "./analyzer";
import { FindingsProvider, SummaryProvider } from "./views";
import { applyDiagnostics, clearDiagnostics } from "./diagnostics";
import { resolveFindingRange } from "./locator";
import { DetailPanel } from "./detailPanel";
import { ChainVetFinding } from "./types";

let extensionContext: vscode.ExtensionContext;
let analyzer: Analyzer;
let diagnosticCollection: vscode.DiagnosticCollection;
let findingsProvider: FindingsProvider;
let summaryProvider: SummaryProvider;
let statusBar: vscode.StatusBarItem;
let outputChannel: vscode.OutputChannel;
let lastAnalysis: AnalyzerResult | null = null;

export function activate(context: vscode.ExtensionContext): void {
  extensionContext = context;
  outputChannel = vscode.window.createOutputChannel("ChainVet");
  context.subscriptions.push(outputChannel);

  diagnosticCollection = vscode.languages.createDiagnosticCollection("chainvet");
  context.subscriptions.push(diagnosticCollection);

  analyzer = new Analyzer(outputChannel);
  context.subscriptions.push({ dispose: () => analyzer.cancel() });

  findingsProvider = new FindingsProvider();
  summaryProvider = new SummaryProvider();

  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("chainvetFindings", findingsProvider),
    vscode.window.registerTreeDataProvider("chainvetSummary", summaryProvider),
  );

  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.command = "chainvet.analyzeFile";
  setStatus("idle");
  statusBar.show();
  context.subscriptions.push(statusBar);

  context.subscriptions.push(
    vscode.commands.registerCommand("chainvet.analyzeFile", analyzeActiveFile),
    vscode.commands.registerCommand("chainvet.analyzeWorkspace", analyzeWorkspace),
    vscode.commands.registerCommand("chainvet.analyzePath", analyzePathCommand),
    vscode.commands.registerCommand("chainvet.cancel", cancelAnalysis),
    vscode.commands.registerCommand("chainvet.clearFindings", clearFindings),
    vscode.commands.registerCommand("chainvet.refreshFindings", () => findingsProvider.refresh()),
    vscode.commands.registerCommand("chainvet.openSettings", () =>
      vscode.commands.executeCommand("workbench.action.openSettings", "@ext:chainvet.chainvet"),
    ),
    vscode.commands.registerCommand("chainvet.openFindingDetail", openFindingDetail),
    vscode.commands.registerCommand("chainvet.revealFinding", revealFinding),
    vscode.commands.registerCommand("chainvet.generateReport", (uriLike?: unknown) =>
      generateReportCommand(uriLike, "pdf"),
    ),
    vscode.commands.registerCommand("chainvet.generatePdfReport", (uriLike?: unknown) =>
      generateReportCommand(uriLike, "pdf"),
    ),
    vscode.commands.registerCommand("chainvet.generateMarkdownReport", (uriLike?: unknown) =>
      generateReportCommand(uriLike, "markdown"),
    ),
  );

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      if (doc.languageId !== "solidity" && !doc.fileName.endsWith(".sol")) return;
      const runOnSave = vscode.workspace.getConfiguration("chainvet").get<boolean>("runOnSave", false);
      if (!runOnSave) return;
      await analyzeFile(doc.uri);
    }),
  );

  outputChannel.appendLine("ChainVet extension activated.");
}

export function deactivate(): void {
  analyzer?.cancel();
  diagnosticCollection?.clear();
  DetailPanel.dispose();
}

// ─── Commands ─────────────────────────────────────────────────────────

async function analyzeActiveFile(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage("ChainVet: no active editor. Open a .sol file first.");
    return;
  }
  await analyzeFile(editor.document.uri);
}

async function analyzeWorkspace(): Promise<void> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showWarningMessage("ChainVet: open a workspace folder to analyze.");
    return;
  }
  await analyzePath(folders[0].uri, true);
}

async function analyzePathCommand(uri: vscode.Uri | undefined): Promise<void> {
  if (!uri) {
    const picked = await vscode.window.showOpenDialog({
      canSelectFiles: true,
      canSelectFolders: true,
      canSelectMany: false,
      title: "Pick a Solidity file or folder to analyze",
    });
    if (!picked || picked.length === 0) return;
    uri = picked[0];
  }
  const stat = await vscode.workspace.fs.stat(uri);
  await analyzePath(uri, (stat.type & vscode.FileType.Directory) !== 0);
}

type ReportFormat = "pdf" | "markdown";

async function generateReportCommand(uriLike: unknown, reportFormat: ReportFormat): Promise<void> {
  if (analyzer.isRunning()) {
    const choice = await vscode.window.showWarningMessage(
      "ChainVet: an analysis or report is already running. Cancel it?",
      { modal: false },
      "Cancel running",
    );
    if (choice === "Cancel running") {
      analyzer.cancel();
    }
    return;
  }

  const explicitTarget = fileUriFromCommandArg(uriLike);
  const cachedAnalysis = cachedAnalysisForReport(explicitTarget);
  const target = cachedAnalysis ? vscode.Uri.file(cachedAnalysis.targetPath) : await resolveReportTarget(uriLike);
  if (!target) return;

  let isDirectory = cachedAnalysis?.isDirectory ?? false;
  if (!cachedAnalysis) {
    let stat: vscode.FileStat;
    try {
      stat = await vscode.workspace.fs.stat(target);
    } catch (error) {
      vscode.window.showErrorMessage(`ChainVet: could not read report target. ${(error as Error).message}`);
      return;
    }
    isDirectory = (stat.type & vscode.FileType.Directory) !== 0;
  }
  const config = vscode.workspace.getConfiguration("chainvet");
  const mode = cachedAnalysis?.mode ?? config.get<string>("mode", "hybrid");
  const timeoutMs = reportGenerationTimeoutMs(config, cachedAnalysis?.findings.length);
  const label = reportFormat === "pdf" ? "PDF" : "Markdown";

  setStatus("running", `report ${path.basename(target.fsPath)}`);
  outputChannel.appendLine(
    cachedAnalysis
      ? `▶ Generating ${mode} ${label} report from cached analysis for ${target.fsPath}`
      : `▶ Generating ${mode} ${label} report for ${target.fsPath}`,
  );

  let reportBytes = new Uint8Array();
  try {
    const result = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `ChainVet · ${mode} ${label} report for ${path.basename(target.fsPath)}`,
        cancellable: true,
      },
      async (progress, token) => {
        token.onCancellationRequested(() => analyzer.cancel());
        const options = {
          targetPath: target.fsPath,
          mode,
          timeoutMs,
          isDirectory,
          progress,
        };
        if (cachedAnalysis) {
          const cachedOptions = { ...options, rawReport: cachedAnalysis.rawReport };
          return reportFormat === "pdf"
            ? analyzer.runCachedPdfReport(cachedOptions)
            : analyzer.runCachedMarkdownReport(cachedOptions);
        }
        return reportFormat === "pdf" ? analyzer.runPdfReport(options) : analyzer.runMarkdownReport(options);
      },
    );
    reportBytes = "pdf" in result
      ? new Uint8Array(result.pdf)
      : new TextEncoder().encode(result.markdown);
    if (result.warnings.length) {
      outputChannel.appendLine(`  ${result.warnings.length} warning(s):`);
      for (const warn of result.warnings) {
        outputChannel.appendLine(`    · ${warn.replace(/\n/g, "\n      ")}`);
      }
    }
  } catch (error) {
    const message = (error as Error).message;
    outputChannel.appendLine(`✗ Report generation failed: ${message}`);
    if (message.toLowerCase().includes("cancel")) {
      setStatus("cancelled");
      vscode.window.showInformationMessage("ChainVet: report generation cancelled.");
    } else {
      setStatus("failed");
      vscode.window.showErrorMessage(`ChainVet: ${message}`);
    }
    return;
  }

  const saveUri = await vscode.window.showSaveDialog({
    defaultUri: defaultReportUri(target, isDirectory, mode, reportFormat === "pdf" ? "pdf" : "md"),
    filters: reportFormat === "pdf"
      ? { PDF: ["pdf"], "All Files": ["*"] }
      : { Markdown: ["md"], "All Files": ["*"] },
    saveLabel: "Save Report",
    title: `Save ChainVet ${label} Report`,
  });
  if (!saveUri) {
    setStatus("complete", "report ready");
    return;
  }

  await vscode.workspace.fs.writeFile(saveUri, reportBytes);
  setStatus("complete", "report saved");
  outputChannel.appendLine(`✓ Report saved to ${saveUri.fsPath}`);
  if (reportFormat === "pdf") {
    await vscode.commands.executeCommand("vscode.open", saveUri);
  } else {
    const doc = await vscode.workspace.openTextDocument(saveUri);
    await vscode.window.showTextDocument(doc, { preview: false });
  }
}

async function cancelAnalysis(): Promise<void> {
  if (!analyzer.isRunning()) {
    vscode.window.showInformationMessage("ChainVet: no analysis is currently running.");
    return;
  }
  analyzer.cancel();
  setStatus("cancelled");
}

function clearFindings(): void {
  clearDiagnostics(diagnosticCollection);
  findingsProvider.setFindings([]);
  summaryProvider.clear();
  lastAnalysis = null;
  setStatus("idle");
  outputChannel.appendLine("Findings cleared.");
}

async function openFindingDetail(finding: ChainVetFinding): Promise<void> {
  if (!finding) return;
  DetailPanel.showOrUpdate(extensionContext, finding);
  showDetailMessage(finding);
}

async function revealFinding(finding: ChainVetFinding): Promise<void> {
  if (!finding?.file) return;
  const uri = await resolveFindingUri(finding.file);
  if (!uri) {
    vscode.window.showWarningMessage(`ChainVet: could not locate ${finding.file}.`);
    return;
  }
  try {
    const doc = await vscode.workspace.openTextDocument(uri);
    const editor = await vscode.window.showTextDocument(doc, { preview: false });
    const resolution = resolveFindingRange(doc.getText(), finding);
    editor.selection = new vscode.Selection(resolution.range.start, resolution.range.end);
    editor.revealRange(resolution.range, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
    if (resolution.source !== "offset") {
      const hint = resolution.source === "function"
        ? `(approximated to function ${finding.function ?? ""})`
        : resolution.source === "keyword"
          ? `(approximated by kind ${finding.kind ?? ""})`
          : "(no precise location available)";
      vscode.window.setStatusBarMessage(`ChainVet: ${hint}`, 4000);
    }
  } catch (error) {
    vscode.window.showErrorMessage(`ChainVet: failed to open file. ${(error as Error).message}`);
  }
}

// ─── Core analysis flow ──────────────────────────────────────────────

async function analyzeFile(uri: vscode.Uri): Promise<void> {
  await analyzePath(uri, false);
}

async function analyzePath(uri: vscode.Uri, isDirectory: boolean): Promise<void> {
  if (analyzer.isRunning()) {
    const choice = await vscode.window.showWarningMessage(
      "ChainVet: an analysis is already running. Cancel it?",
      { modal: false },
      "Cancel running",
    );
    if (choice === "Cancel running") {
      analyzer.cancel();
    }
    return;
  }

  const config = vscode.workspace.getConfiguration("chainvet");
  const mode = config.get<string>("mode", "hybrid");
  const timeoutMs = Math.max(30, config.get<number>("analysisTimeoutSeconds", 600)) * 1000;

  setStatus("running", path.basename(uri.fsPath));
  summaryProvider.beginRun(uri.fsPath, mode);
  outputChannel.appendLine(`▶ Running ${mode} analysis on ${uri.fsPath}`);

  let result: AnalyzerResult;
  try {
    result = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `ChainVet · ${mode} analysis on ${path.basename(uri.fsPath)}`,
        cancellable: true,
      },
      async (progress, token) => {
        token.onCancellationRequested(() => analyzer.cancel());
        return analyzer.run({
          targetPath: uri.fsPath,
          mode,
          timeoutMs,
          isDirectory,
          progress,
        });
      },
    );
  } catch (error) {
    const message = (error as Error).message;
    outputChannel.appendLine(`✗ Analysis failed: ${message}`);
    if (message.toLowerCase().includes("cancel")) {
      setStatus("cancelled");
      vscode.window.showInformationMessage("ChainVet: analysis cancelled.");
    } else {
      setStatus("failed");
      vscode.window.showErrorMessage(`ChainVet: ${message}`);
    }
    return;
  }

  const findings = result.findings;
  lastAnalysis = result;
  outputChannel.appendLine(`✓ Analysis complete: ${findings.length} finding(s).`);
  if (result.warnings.length) {
    outputChannel.appendLine(`  ${result.warnings.length} warning(s):`);
    for (const warn of result.warnings) {
      outputChannel.appendLine(`    · ${warn.replace(/\n/g, "\n      ")}`);
    }
  }

  await applyDiagnostics(diagnosticCollection, findings, config);
  findingsProvider.setFindings(findings);

  const counts = countBySeverity(findings);
  summaryProvider.setSummary({
    target: path.basename(uri.fsPath),
    targetPath: uri.fsPath,
    mode,
    counts,
    elapsedMs: Date.now() - (summaryProvider.runStartedAt ?? Date.now()),
  });
  setStatus("complete", formatSeverityBreakdown(counts));

  if (findings.length > 0) {
    vscode.commands.executeCommand("workbench.view.extension.chainvetContainer");
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────

async function resolveReportTarget(uriLike?: unknown): Promise<vscode.Uri | null> {
  const uri = fileUriFromCommandArg(uriLike);
  if (uri) return uri;

  const editor = vscode.window.activeTextEditor;
  if (isSolidityDocument(editor?.document) && isUsableFileUri(editor?.document.uri)) {
    return editor.document.uri;
  }

  const picked = await vscode.window.showOpenDialog({
    canSelectFiles: true,
    canSelectFolders: true,
    canSelectMany: false,
    title: "Pick a Solidity file or folder for the report",
    filters: { Solidity: ["sol"], "All Files": ["*"] },
  });
  return picked?.[0] ?? null;
}

function cachedAnalysisForReport(explicitTarget: vscode.Uri | null): AnalyzerResult | null {
  if (!lastAnalysis) return null;
  if (!explicitTarget) return lastAnalysis;
  return samePath(explicitTarget.fsPath, lastAnalysis.targetPath) ? lastAnalysis : null;
}

function samePath(left: string, right: string): boolean {
  const normalize = (value: string) => path.resolve(value);
  if (process.platform === "win32") {
    return normalize(left).toLowerCase() === normalize(right).toLowerCase();
  }
  return normalize(left) === normalize(right);
}

function isSolidityDocument(doc: vscode.TextDocument | undefined): boolean {
  if (!doc) return false;
  return doc.languageId === "solidity" || doc.fileName.endsWith(".sol");
}

function defaultReportUri(target: vscode.Uri, isDirectory: boolean, mode: string, extension = "pdf"): vscode.Uri {
  const baseDir = fallbackReportDir(isDirectory ? target.fsPath : path.dirname(target.fsPath));
  const targetBase = isDirectory
    ? path.basename(target.fsPath)
    : path.basename(target.fsPath, path.extname(target.fsPath));
  const name = `${slugify(targetBase || "chainvet")}-${slugify(mode || "hybrid")}-chainvet-report.${extension}`;
  return vscode.Uri.file(path.join(baseDir, name));
}

function fileUriFromCommandArg(value: unknown): vscode.Uri | null {
  if (isUsableFileUri(value)) return value;
  if (Array.isArray(value)) {
    return fileUriFromCommandArg(value[0]);
  }
  if (!value || typeof value !== "object") return null;

  const record = value as Record<string, unknown>;
  return (
    fileUriFromCommandArg(record.resourceUri) ??
    fileUriFromCommandArg(record.uri) ??
    fileUriFromFsPath(record.fsPath)
  );
}

function fileUriFromFsPath(value: unknown): vscode.Uri | null {
  if (typeof value !== "string" || !path.isAbsolute(value)) return null;
  return vscode.Uri.file(value);
}

function isUsableFileUri(value: unknown): value is vscode.Uri {
  if (!(value instanceof vscode.Uri)) return false;
  return value.scheme === "file" && path.isAbsolute(value.fsPath);
}

function fallbackReportDir(candidate: string): string {
  if (candidate && path.isAbsolute(candidate)) return candidate;
  const folder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (folder && path.isAbsolute(folder)) return folder;
  return os.homedir();
}

function slugify(value: string): string {
  const slug = String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug || "report";
}

function reportGenerationTimeoutMs(config: vscode.WorkspaceConfiguration, findingCount?: number): number {
  const baseTimeoutMs = Math.max(30, config.get<number>("analysisTimeoutSeconds", 600)) * 1000;
  if (!config.get<boolean>("aiReports.enabled", true)) {
    return baseTimeoutMs;
  }

  const perFindingTimeoutMs = Math.max(1000, config.get<number>("aiReports.timeoutMs", 60000));
  const configuredMaxFindings = Math.max(1, config.get<number>("aiReports.maxFindings", 1000));
  const reviewCount = Math.min(configuredMaxFindings, Math.max(1, findingCount ?? configuredMaxFindings));
  const startupBufferMs = 120000;
  const aiTimeoutMs = reviewCount * perFindingTimeoutMs + startupBufferMs;

  // Node clamps very large setTimeout values. Keep the cap slightly below its signed 32-bit limit.
  return Math.min(Math.max(baseTimeoutMs, aiTimeoutMs), 2147000000);
}

async function resolveFindingUri(filePath: string): Promise<vscode.Uri | null> {
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

function showDetailMessage(finding: ChainVetFinding): void {
  const lines: string[] = [];
  lines.push(`${titleCase(finding.kind || "Finding")} — ${(finding.severity || "unspecified").toLowerCase()}`);
  if (finding.function) lines.push(`Function: ${finding.function}()`);
  if (finding.file) lines.push(`File: ${finding.file}`);
  if (finding.confidence) lines.push(`Confidence: ${finding.confidence}`);
  if (finding.layer) lines.push(`Layer: ${finding.layer}`);
  if (finding.category) lines.push(`Category: ${finding.category}`);
  if (finding.evidence) lines.push(`Evidence: ${finding.evidence}`);
  if (finding.message) lines.push("", finding.message);

  outputChannel.appendLine("");
  outputChannel.appendLine("─── finding ───");
  for (const line of lines) outputChannel.appendLine(line);
  outputChannel.appendLine("───────────────");
}

function setStatus(stateName: "idle" | "running" | "complete" | "cancelled" | "failed", detail?: string): void {
  summaryProvider.setState(stateName, detail ?? "");
  switch (stateName) {
    case "running":
      statusBar.text = `$(sync~spin) ChainVet · ${detail ?? "running"}`;
      statusBar.tooltip = "Analysis running — click to cancel";
      statusBar.command = "chainvet.cancel";
      statusBar.backgroundColor = undefined;
      break;
    case "complete":
      statusBar.text = `$(shield) ChainVet · ${detail ?? "ready"}`;
      statusBar.tooltip = "ChainVet — click to re-analyze current file";
      statusBar.command = "chainvet.analyzeFile";
      statusBar.backgroundColor = undefined;
      break;
    case "cancelled":
      statusBar.text = `$(circle-slash) ChainVet · cancelled`;
      statusBar.tooltip = "Analysis cancelled";
      statusBar.command = "chainvet.analyzeFile";
      statusBar.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
      break;
    case "failed":
      statusBar.text = `$(error) ChainVet · failed`;
      statusBar.tooltip = "Analysis failed — open the ChainVet output channel";
      statusBar.command = "chainvet.analyzeFile";
      statusBar.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
      break;
    case "idle":
    default:
      statusBar.text = `$(shield) ChainVet`;
      statusBar.tooltip = "ChainVet — click to analyze current file";
      statusBar.command = "chainvet.analyzeFile";
      statusBar.backgroundColor = undefined;
      break;
  }
}

export interface SeverityCounts {
  high: number;
  medium: number;
  low: number;
  info: number;
  unknown: number;
  total: number;
}

function countBySeverity(findings: ChainVetFinding[]): SeverityCounts {
  const counts: SeverityCounts = { high: 0, medium: 0, low: 0, info: 0, unknown: 0, total: 0 };
  for (const f of findings) {
    counts.total += 1;
    counts[severityBucket(f.severity)] += 1;
  }
  return counts;
}

function severityBucket(severity?: string): "high" | "medium" | "low" | "info" | "unknown" {
  const value = String(severity || "").toLowerCase();
  if (value.includes("critical") || value.includes("high")) return "high";
  if (value.includes("medium") || value.includes("moderate")) return "medium";
  if (value.includes("low")) return "low";
  if (value.includes("info")) return "info";
  return "unknown";
}

function formatSeverityBreakdown(c: SeverityCounts): string {
  if (c.total === 0) return "no findings";
  const parts: string[] = [];
  if (c.high)    parts.push(`${c.high}H`);
  if (c.medium)  parts.push(`${c.medium}M`);
  if (c.low)     parts.push(`${c.low}L`);
  if (c.info)    parts.push(`${c.info}I`);
  if (c.unknown) parts.push(`${c.unknown}?`);
  return `${c.total} · ${parts.join(" ")}`;
}

function titleCase(value: string): string {
  return String(value || "unknown")
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}
