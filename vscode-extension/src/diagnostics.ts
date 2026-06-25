import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";
import { ChainVetFinding } from "./types";
import { resolveFindingRange, RangeResolution } from "./locator";

export async function applyDiagnostics(
  collection: vscode.DiagnosticCollection,
  findings: ChainVetFinding[],
  config: vscode.WorkspaceConfiguration,
): Promise<void> {
  collection.clear();
  const showInfo = config.get<boolean>("showInformationFindings", true);

  const byFile = new Map<string, ChainVetFinding[]>();
  const unlocated: ChainVetFinding[] = [];

  for (const finding of findings) {
    if (!finding.file) {
      unlocated.push(finding);
      continue;
    }
    const existing = byFile.get(finding.file);
    if (existing) {
      existing.push(finding);
    } else {
      byFile.set(finding.file, [finding]);
    }
  }

  for (const [filePath, group] of byFile) {
    const uri = await resolveUri(filePath);
    if (!uri) {
      unlocated.push(...group);
      continue;
    }

    let docText: string | null = null;
    try {
      const doc = await vscode.workspace.openTextDocument(uri);
      docText = doc.getText();
    } catch {
      docText = null;
    }

    const diagnostics: vscode.Diagnostic[] = [];
    for (const finding of group) {
      const severity = mapSeverity(finding.severity);
      if (!showInfo && severity === vscode.DiagnosticSeverity.Information) {
        continue;
      }
      diagnostics.push(buildDiagnostic(finding, docText, severity));
    }
    if (diagnostics.length) {
      collection.set(uri, diagnostics);
    }
  }

  if (unlocated.length) {
    // Surface unlocated findings in the output via a virtual URI so the
    // Problems panel still shows them.
    const virtualUri = vscode.Uri.parse("chainvet://unlocated/findings");
    const diagnostics = unlocated
      .filter((f) => {
        const sev = mapSeverity(f.severity);
        return showInfo || sev !== vscode.DiagnosticSeverity.Information;
      })
      .map((f) => buildDiagnostic(f, null, mapSeverity(f.severity)));
    if (diagnostics.length) {
      collection.set(virtualUri, diagnostics);
    }
  }
}

export function clearDiagnostics(collection: vscode.DiagnosticCollection): void {
  collection.clear();
}

function buildDiagnostic(
  finding: ChainVetFinding,
  docText: string | null,
  severity: vscode.DiagnosticSeverity,
): vscode.Diagnostic {
  const resolution = resolveFindingRange(docText, finding);
  const message = buildMessage(finding, resolution);

  const diagnostic = new vscode.Diagnostic(resolution.range, message, severity);
  diagnostic.source = "ChainVet";
  diagnostic.code = finding.kind || undefined;

  const tags: vscode.DiagnosticTag[] = [];
  if (finding.severity && /info/i.test(finding.severity)) {
    tags.push(vscode.DiagnosticTag.Unnecessary);
  }
  if (tags.length) diagnostic.tags = tags;

  return diagnostic;
}

function buildMessage(finding: ChainVetFinding, resolution: RangeResolution): string {
  const heading = titleCase(finding.kind || "Finding");
  const base = finding.message && finding.message.length
    ? `${heading}: ${finding.message}`
    : heading;

  switch (resolution.source) {
    case "function":
      return `${base}\n(location approximated to function ${finding.function ?? ""})`;
    case "keyword":
      return `${base}\n(location approximated by kind ${finding.kind ?? ""})`;
    case "fallback":
      return `${base}\n(no precise location available — see the ChainVet output channel)`;
    default:
      return base;
  }
}

function mapSeverity(severity?: string): vscode.DiagnosticSeverity {
  const value = String(severity || "").toLowerCase();
  if (value.includes("critical") || value.includes("high")) return vscode.DiagnosticSeverity.Error;
  if (value.includes("medium") || value.includes("moderate")) return vscode.DiagnosticSeverity.Warning;
  if (value.includes("low")) return vscode.DiagnosticSeverity.Warning;
  if (value.includes("info")) return vscode.DiagnosticSeverity.Information;
  return vscode.DiagnosticSeverity.Warning;
}

async function resolveUri(filePath: string): Promise<vscode.Uri | null> {
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

function titleCase(value: string): string {
  return String(value || "")
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}
