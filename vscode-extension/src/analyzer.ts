import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import { spawn, ChildProcess } from "child_process";
import { ChainVetFinding } from "./types";

export interface AnalyzerRunOptions {
  targetPath: string;
  mode: string;
  timeoutMs: number;
  isDirectory: boolean;
  progress?: vscode.Progress<{ message?: string; increment?: number }>;
}

export interface AnalyzerResult {
  findings: ChainVetFinding[];
  warnings: string[];
  rawReport: unknown;
  mode: string;
  targetPath: string;
  isDirectory: boolean;
}

export interface AnalyzerCachedReportOptions extends AnalyzerRunOptions {
  rawReport: unknown;
}

export interface AnalyzerPdfReport {
  pdf: Uint8Array;
  warnings: string[];
  mode: string;
  targetPath: string;
}

export interface AnalyzerMarkdownReport {
  markdown: string;
  warnings: string[];
  mode: string;
  targetPath: string;
}

export class Analyzer {
  private running: ChildProcess | null = null;
  private cancelled = false;

  constructor(private readonly output: vscode.OutputChannel) {}

  isRunning(): boolean {
    return this.running !== null;
  }

  cancel(): void {
    if (!this.running) return;
    this.cancelled = true;
    try {
      this.running.kill("SIGTERM");
    } catch {
      /* ignore */
    }
    setTimeout(() => {
      if (this.running) {
        try { this.running.kill("SIGKILL"); } catch { /* ignore */ }
      }
    }, 500);
  }

  async run(options: AnalyzerRunOptions): Promise<AnalyzerResult> {
    const binary = await this.resolveBinary();
    const mode = normalizeMode(options.mode);
    const args = [`--${mode}`, options.targetPath, "--json"];

    this.cancelled = false;
    this.output.appendLine(`$ ${binary} ${args.join(" ")}`);

    return new Promise<AnalyzerResult>((resolve, reject) => {
      const child = spawn(binary, args, {
        cwd: workspaceCwd(options.targetPath),
        env: analyzerEnv(false),
      });
      this.running = child;

      let stdout = "";
      let stderr = "";
      const startedAt = Date.now();

      const timeout = setTimeout(() => {
        if (this.running === child) {
          this.cancelled = true;
          try { child.kill("SIGTERM"); } catch { /* ignore */ }
        }
      }, options.timeoutMs);

      child.stdout?.on("data", (chunk: Buffer) => {
        stdout += chunk.toString("utf8");
      });

      child.stderr?.on("data", (chunk: Buffer) => {
        const text = chunk.toString("utf8");
        stderr += text;
        for (const line of text.split(/\r?\n/)) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          this.output.appendLine(`  · ${trimmed}`);
          if (options.progress) {
            options.progress.report({ message: progressMessageForStderr(trimmed) });
          }
        }
      });

      child.on("error", (error) => {
        clearTimeout(timeout);
        this.running = null;
        reject(new Error(`Failed to launch analyzer: ${error.message}`));
      });

      child.on("close", (code, signal) => {
        clearTimeout(timeout);
        this.running = null;
        const elapsed = Date.now() - startedAt;

        if (this.cancelled) {
          this.output.appendLine(`✗ analysis cancelled after ${formatElapsed(elapsed)}.`);
          reject(new Error("Analysis cancelled."));
          return;
        }

        if (code !== 0) {
          const detail = stderr.trim() || stdout.trim() || `exit code ${code} (${signal ?? "no signal"})`;
          this.output.appendLine(`✗ analyzer exited with error: ${detail}`);
          reject(new Error(`Analyzer exited with error: ${truncate(detail, 280)}`));
          return;
        }

        let parsed: unknown;
        try {
          parsed = JSON.parse(stdout);
        } catch (error) {
          reject(new Error(`Analyzer produced invalid JSON: ${(error as Error).message}`));
          return;
        }

        const findings = extractFindings(parsed, mode);
        const warnings = extractWarningBlocks(stderr);

        this.output.appendLine(`✓ analyzer finished in ${formatElapsed(elapsed)} · ${findings.length} finding(s).`);

        resolve({
          findings,
          warnings,
          rawReport: parsed,
          mode,
          targetPath: options.targetPath,
          isDirectory: options.isDirectory,
        });
      });
    });
  }

  async runCachedPdfReport(options: AnalyzerCachedReportOptions): Promise<AnalyzerPdfReport> {
    return this.runCachedReport(options, "pdf") as Promise<AnalyzerPdfReport>;
  }

  async runCachedMarkdownReport(options: AnalyzerCachedReportOptions): Promise<AnalyzerMarkdownReport> {
    return this.runCachedReport(options, "markdown") as Promise<AnalyzerMarkdownReport>;
  }

  async runPdfReport(options: AnalyzerRunOptions): Promise<AnalyzerPdfReport> {
    const binary = await this.resolveBinary();
    const mode = normalizeMode(options.mode);
    const args = [`--${mode}`, options.targetPath, "--format", "pdf"];

    this.cancelled = false;
    this.output.appendLine(`$ ${binary} ${args.join(" ")}`);

    return new Promise<AnalyzerPdfReport>((resolve, reject) => {
      const child = spawn(binary, args, {
        cwd: workspaceCwd(options.targetPath),
        env: analyzerEnv(true),
      });
      this.running = child;

      const stdoutChunks: Buffer[] = [];
      let stderr = "";
      const startedAt = Date.now();

      const timeout = setTimeout(() => {
        if (this.running === child) {
          this.cancelled = true;
          try { child.kill("SIGTERM"); } catch { /* ignore */ }
        }
      }, options.timeoutMs);

      child.stdout?.on("data", (chunk: Buffer) => {
        stdoutChunks.push(chunk);
      });

      child.stderr?.on("data", (chunk: Buffer) => {
        const text = chunk.toString("utf8");
        stderr += text;
        for (const line of text.split(/\r?\n/)) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          this.output.appendLine(`  · ${trimmed}`);
          if (options.progress) {
            options.progress.report({ message: progressMessageForStderr(trimmed) });
          }
        }
      });

      child.on("error", (error) => {
        clearTimeout(timeout);
        this.running = null;
        reject(new Error(`Failed to launch analyzer: ${error.message}`));
      });

      child.on("close", (code, signal) => {
        clearTimeout(timeout);
        this.running = null;
        const elapsed = Date.now() - startedAt;

        if (this.cancelled) {
          this.output.appendLine(`✗ report generation cancelled after ${formatElapsed(elapsed)}.`);
          reject(new Error("Report generation cancelled."));
          return;
        }

        if (code !== 0) {
          const stdout = Buffer.concat(stdoutChunks).toString("utf8");
          const detail = stderr.trim() || stdout.trim() || `exit code ${code} (${signal ?? "no signal"})`;
          this.output.appendLine(`✗ report generation failed: ${detail}`);
          reject(new Error(`Report generation failed: ${truncate(detail, 280)}`));
          return;
        }

        const warnings = extractWarningBlocks(stderr);
        this.output.appendLine(`✓ PDF report generated in ${formatElapsed(elapsed)}.`);

        resolve({
          pdf: Buffer.concat(stdoutChunks),
          warnings,
          mode,
          targetPath: options.targetPath,
        });
      });
    });
  }

  async runMarkdownReport(options: AnalyzerRunOptions): Promise<AnalyzerMarkdownReport> {
    const binary = await this.resolveBinary();
    const mode = normalizeMode(options.mode);
    const args = [`--${mode}`, options.targetPath, "--format", "markdown"];

    this.cancelled = false;
    this.output.appendLine(`$ ${binary} ${args.join(" ")}`);

    return new Promise<AnalyzerMarkdownReport>((resolve, reject) => {
      const child = spawn(binary, args, {
        cwd: workspaceCwd(options.targetPath),
        env: analyzerEnv(true),
      });
      this.running = child;

      let stdout = "";
      let stderr = "";
      const startedAt = Date.now();

      const timeout = setTimeout(() => {
        if (this.running === child) {
          this.cancelled = true;
          try { child.kill("SIGTERM"); } catch { /* ignore */ }
        }
      }, options.timeoutMs);

      child.stdout?.on("data", (chunk: Buffer) => {
        stdout += chunk.toString("utf8");
      });

      child.stderr?.on("data", (chunk: Buffer) => {
        const text = chunk.toString("utf8");
        stderr += text;
        for (const line of text.split(/\r?\n/)) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          this.output.appendLine(`  · ${trimmed}`);
          if (options.progress) {
            options.progress.report({ message: progressMessageForStderr(trimmed) });
          }
        }
      });

      child.on("error", (error) => {
        clearTimeout(timeout);
        this.running = null;
        reject(new Error(`Failed to launch analyzer: ${error.message}`));
      });

      child.on("close", (code, signal) => {
        clearTimeout(timeout);
        this.running = null;
        const elapsed = Date.now() - startedAt;

        if (this.cancelled) {
          this.output.appendLine(`✗ report generation cancelled after ${formatElapsed(elapsed)}.`);
          reject(new Error("Report generation cancelled."));
          return;
        }

        if (code !== 0) {
          const detail = stderr.trim() || stdout.trim() || `exit code ${code} (${signal ?? "no signal"})`;
          this.output.appendLine(`✗ report generation failed: ${detail}`);
          reject(new Error(`Report generation failed: ${truncate(detail, 280)}`));
          return;
        }

        const warnings = extractWarningBlocks(stderr);
        this.output.appendLine(`✓ Markdown report generated in ${formatElapsed(elapsed)}.`);

        resolve({
          markdown: stdout,
          warnings,
          mode,
          targetPath: options.targetPath,
        });
      });
    });
  }

  private async runCachedReport(
    options: AnalyzerCachedReportOptions,
    format: "pdf" | "markdown",
  ): Promise<AnalyzerPdfReport | AnalyzerMarkdownReport> {
    const binary = await this.resolveBinary();
    const mode = normalizeMode(options.mode);
    const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "chainvet-report-"));
    const jsonPath = path.join(tempDir, "analysis.json");
    await fs.promises.writeFile(jsonPath, JSON.stringify(options.rawReport), "utf8");
    const args = [
      "--report-from-json",
      jsonPath,
      "--report-target",
      options.targetPath,
      "--report-mode",
      mode,
      "--format",
      format,
    ];

    this.cancelled = false;
    this.output.appendLine(`$ ${binary} ${args.join(" ")}`);

    return new Promise<AnalyzerPdfReport | AnalyzerMarkdownReport>((resolve, reject) => {
      const cleanup = () => {
        fs.promises.rm(tempDir, { recursive: true, force: true }).catch(() => undefined);
      };
      const child = spawn(binary, args, {
        cwd: workspaceCwd(options.targetPath),
        env: analyzerEnv(true),
      });
      this.running = child;

      const stdoutChunks: Buffer[] = [];
      let stdout = "";
      let stderr = "";
      const startedAt = Date.now();

      const timeout = setTimeout(() => {
        if (this.running === child) {
          this.cancelled = true;
          try { child.kill("SIGTERM"); } catch { /* ignore */ }
        }
      }, options.timeoutMs);

      child.stdout?.on("data", (chunk: Buffer) => {
        if (format === "pdf") {
          stdoutChunks.push(chunk);
        } else {
          stdout += chunk.toString("utf8");
        }
      });

      child.stderr?.on("data", (chunk: Buffer) => {
        const text = chunk.toString("utf8");
        stderr += text;
        for (const line of text.split(/\r?\n/)) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          this.output.appendLine(`  · ${trimmed}`);
          if (options.progress) {
            options.progress.report({ message: progressMessageForStderr(trimmed) });
          }
        }
      });

      child.on("error", (error) => {
        clearTimeout(timeout);
        cleanup();
        this.running = null;
        reject(new Error(`Failed to launch report renderer: ${error.message}`));
      });

      child.on("close", (code, signal) => {
        clearTimeout(timeout);
        cleanup();
        this.running = null;
        const elapsed = Date.now() - startedAt;

        if (this.cancelled) {
          this.output.appendLine(`✗ report generation cancelled after ${formatElapsed(elapsed)}.`);
          reject(new Error("Report generation cancelled."));
          return;
        }

        if (code !== 0) {
          const stdoutText = format === "pdf" ? Buffer.concat(stdoutChunks).toString("utf8") : stdout;
          const detail = stderr.trim() || stdoutText.trim() || `exit code ${code} (${signal ?? "no signal"})`;
          this.output.appendLine(`✗ report generation failed: ${detail}`);
          reject(new Error(`Report generation failed: ${truncate(detail, 280)}`));
          return;
        }

        const warnings = extractWarningBlocks(stderr);
        const label = format === "pdf" ? "PDF" : "Markdown";
        this.output.appendLine(`✓ ${label} report generated from cached analysis in ${formatElapsed(elapsed)}.`);

        if (format === "pdf") {
          resolve({
            pdf: Buffer.concat(stdoutChunks),
            warnings,
            mode,
            targetPath: options.targetPath,
          });
        } else {
          resolve({
            markdown: stdout,
            warnings,
            mode,
            targetPath: options.targetPath,
          });
        }
      });
    });
  }

  private async resolveBinary(): Promise<string> {
    const config = vscode.workspace.getConfiguration("chainvet");
    const configured = config.get<string>("binaryPath", "").trim();
    if (configured) {
      if (!fs.existsSync(configured)) {
        throw new Error(`Configured \`chainvet.binaryPath\` does not exist: ${configured}`);
      }
      return configured;
    }

    const folders = vscode.workspace.workspaceFolders ?? [];
    const exeName = process.platform === "win32" ? "ChainVet.exe" : "ChainVet";
    const legacyExeName = process.platform === "win32" ? "Static.exe" : "Static";
    const candidates: string[] = [];
    for (const folder of folders) {
      candidates.push(
        path.join(folder.uri.fsPath, "target", "release", exeName),
        path.join(folder.uri.fsPath, "target", "debug", exeName),
        path.join(folder.uri.fsPath, "target", "release", legacyExeName),
        path.join(folder.uri.fsPath, "target", "debug", legacyExeName),
      );
    }
    candidates.push(...searchPath("chainvet"), ...searchPath(exeName), ...searchPath(legacyExeName));

    for (const candidate of candidates) {
      try {
        if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
          return candidate;
        }
      } catch { /* ignore */ }
    }

    throw new Error(
      "ChainVet analyzer binary not found. Build the Rust project (`cargo build --release`) " +
      "or set `chainvet.binaryPath` in settings.",
    );
  }
}

// ─── Output parsing ──────────────────────────────────────────────────

function extractFindings(report: unknown, mode: string): ChainVetFinding[] {
  if (!isObject(report)) return [];

  // Aggregate-report shape: contains nested per-target `reports`.
  if (Array.isArray((report as Record<string, unknown>).reports)) {
    const out: ChainVetFinding[] = [];
    for (const entry of (report as Record<string, unknown>).reports as unknown[]) {
      if (!isObject(entry)) continue;
      const targetReport = (entry as Record<string, unknown>).report;
      const inner = extractFindings(targetReport, mode);
      // Tag with target_path if file is missing.
      const targetPath = (entry as Record<string, unknown>).target_path;
      for (const finding of inner) {
        if (!finding.file && typeof targetPath === "string") {
          finding.file = targetPath;
        }
        out.push(finding);
      }
    }
    return out;
  }

  const findings: ChainVetFinding[] = [];

  // Single-report shapes:
  //   static  -> { findings: [{ kind, span: { start, end }, ... }] }
  //   symbolic-> { vulnerabilities: [...], meta_findings: [...] }
  //   fuzzing -> { findings: [...], meta_findings: [...] }
  //   hybrid  -> { findings: [...], meta_findings: [...] }
  if (mode === "static") {
    for (const f of arrayAt(report, "findings")) {
      findings.push(coerceStaticFinding(f));
    }
    return findings;
  }

  if (mode === "symbolic") {
    for (const f of arrayAt(report, "vulnerabilities")) {
      findings.push(coerceSurfacedFinding(f, "runtime"));
    }
    for (const f of arrayAt(report, "meta_findings")) {
      findings.push(coerceSurfacedFinding(f, "meta"));
    }
    return findings;
  }

  // fuzzing or hybrid
  for (const f of arrayAt(report, "findings")) {
    findings.push(coerceSurfacedFinding(f, "runtime"));
  }
  for (const f of arrayAt(report, "meta_findings")) {
    findings.push(coerceSurfacedFinding(f, "meta"));
  }
  return findings;
}

function coerceStaticFinding(value: unknown): ChainVetFinding {
  if (!isObject(value)) {
    return { kind: "finding", message: "Unrecognized finding payload" };
  }
  const span = (value.span ?? {}) as Record<string, unknown>;
  return {
    kind: str(value.kind, "finding"),
    layer: "static",
    severity: optStr(value.severity),
    confidence: optStr(value.confidence),
    category: optStr(value.category),
    function: optStr(value.function),
    file: optStr(value.file),
    start: optNum(span.start),
    end: optNum(span.end),
    message: str(value.message, ""),
  };
}

function coerceSurfacedFinding(value: unknown, defaultLayer: string): ChainVetFinding {
  if (!isObject(value)) {
    return { kind: "finding", message: "Unrecognized finding payload" };
  }
  return {
    kind: str(value.kind, "finding"),
    layer: optStr(value.analysis_layer) ?? defaultLayer,
    severity: optStr(value.severity),
    confidence: optStr(value.confidence),
    category: optStr(value.category),
    function: optStr(value.function_name) ?? optStr(value.function),
    file: optStr(value.file),
    start: optNum(value.start),
    end: optNum(value.end),
    message: str(value.message, ""),
    evidence: optStr(value.evidence_kind),
  };
}

function extractWarningBlocks(stderr: string): string[] {
  const blocks: string[] = [];
  let current = "";
  for (const line of stderr.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (startsNewWarning(trimmed) && current) {
      blocks.push(current.trim());
      current = "";
    }
    if (current) current += "\n";
    current += line.trimEnd();
  }
  if (current.trim()) blocks.push(current.trim());
  return blocks;
}

function startsNewWarning(line: string): boolean {
  return (
    line.startsWith("solc frontend unavailable; using tree-sitter fallback:") ||
    /^\[[^\]]+\]\s+solc frontend unavailable; using tree-sitter fallback:/.test(line) ||
    line.startsWith("solc frontend failed:") ||
    /^\[[^\]]+\]\s+solc frontend failed:/.test(line) ||
    line.startsWith("analysis command failed:") ||
    line.startsWith("analysis cancelled:")
  );
}

function progressMessageForStderr(line: string): string {
  if (
    line.startsWith("solc frontend unavailable; using tree-sitter fallback:") ||
    /^\[[^\]]+\]\s+solc frontend unavailable; using tree-sitter fallback:/.test(line) ||
    line.startsWith("solc frontend failed: no solc releases available") ||
    line.startsWith("solc frontend failed: solc release index is empty") ||
    line.startsWith("solc frontend failed: no solc release matches pragma requirements")
  ) {
    return "using tree-sitter fallback parser (solc unavailable)";
  }
  return truncate(line, 120);
}

// ─── Utilities ───────────────────────────────────────────────────────

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function arrayAt(value: unknown, key: string): unknown[] {
  if (!isObject(value)) return [];
  const inner = value[key];
  return Array.isArray(inner) ? inner : [];
}

function str(value: unknown, fallback: string): string {
  return typeof value === "string" ? value : fallback;
}

function optStr(value: unknown): string | undefined {
  return typeof value === "string" && value.length ? value : undefined;
}

function optNum(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function searchPath(name: string): string[] {
  const pathEnv = process.env.PATH || "";
  const sep = process.platform === "win32" ? ";" : ":";
  return pathEnv.split(sep).filter(Boolean).map((dir) => path.join(dir, name));
}

function workspaceCwd(targetPath: string): string {
  const folders = vscode.workspace.workspaceFolders ?? [];
  if (folders.length === 0) return path.dirname(targetPath) || os.homedir();
  return folders[0].uri.fsPath;
}

function analyzerEnv(forReport: boolean): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  const config = vscode.workspace.getConfiguration("chainvet");

  if (config.get<boolean>("aiFallbackParser.enabled", false)) {
    env.CHAINVET_AI_FALLBACK_PARSER = "1";
    env.CHAINVET_AI_MODEL = config.get<string>("aiReports.model", "qwen2.5-coder:7b");
    env.CHAINVET_AI_ENDPOINT = config.get<string>("aiReports.endpoint", "http://127.0.0.1:11434");
    env.CHAINVET_AI_FALLBACK_TIMEOUT_MS = String(config.get<number>("aiFallbackParser.timeoutMs", 60000));
    env.CHAINVET_AI_FALLBACK_NUM_PREDICT = String(config.get<number>("aiFallbackParser.maxTokens", 1536));
    env.CHAINVET_AI_FALLBACK_MAX_SOURCE_BYTES = String(
      config.get<number>("aiFallbackParser.maxSourceBytes", 24000),
    );
    env.CHAINVET_AI_FALLBACK_CHUNK_BYTES = String(config.get<number>("aiFallbackParser.chunkBytes", 18000));
    env.CHAINVET_AI_FALLBACK_MAX_CHUNKS = String(config.get<number>("aiFallbackParser.maxChunksPerFile", 24));
  } else {
    delete env.CHAINVET_AI_FALLBACK_PARSER;
  }

  if (!forReport) return env;

  const enabled = config.get<boolean>("aiReports.enabled", true);
  if (!enabled) {
    delete env.CHAINVET_AI_REPORT;
    return env;
  }

  env.CHAINVET_AI_REPORT = "1";
  env.CHAINVET_AI_MODEL = config.get<string>("aiReports.model", "qwen2.5-coder:7b");
  env.CHAINVET_AI_ENDPOINT = config.get<string>("aiReports.endpoint", "http://127.0.0.1:11434");
  env.CHAINVET_AI_TIMEOUT_MS = String(config.get<number>("aiReports.timeoutMs", 60000));
  env.CHAINVET_AI_MAX_FINDINGS = String(config.get<number>("aiReports.maxFindings", 1000));
  env.CHAINVET_AI_NUM_PREDICT = String(config.get<number>("aiReports.maxTokens", 512));
  return env;
}

function formatElapsed(ms: number): string {
  const seconds = Math.max(0, Math.floor(ms / 1000));
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  if (!minutes) return `${remainder}s`;
  return `${minutes}m ${remainder}s`;
}

function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function normalizeMode(mode: string): string {
  const value = (mode || "").trim().toLowerCase();
  if (["static", "symbolic", "fuzzing", "hybrid"].includes(value)) return value;
  return "hybrid";
}
