import * as vscode from "vscode";
import * as path from "path";
import { ChainVetFinding } from "./types";

type SeverityKey = "high" | "medium" | "low" | "info" | "unknown";

const SEVERITY_LABEL: Record<SeverityKey, string> = {
  high: "High severity",
  medium: "Medium severity",
  low: "Low severity",
  info: "Informational",
  unknown: "Unspecified",
};

const SEVERITY_ORDER: SeverityKey[] = ["high", "medium", "low", "info", "unknown"];

type StatusState = "idle" | "running" | "complete" | "cancelled" | "failed";

interface SummarySnapshot {
  target: string;
  targetPath: string;
  mode: string;
  counts: {
    high: number;
    medium: number;
    low: number;
    info: number;
    unknown: number;
    total: number;
  };
  elapsedMs: number;
}

// ─── Findings tree ───────────────────────────────────────────────────

export class FindingsProvider implements vscode.TreeDataProvider<FindingNode> {
  private findings: ChainVetFinding[] = [];
  private readonly emitter = new vscode.EventEmitter<FindingNode | undefined | null | void>();
  readonly onDidChangeTreeData = this.emitter.event;

  setFindings(findings: ChainVetFinding[]): void {
    this.findings = findings.slice();
    this.emitter.fire();
  }

  refresh(): void {
    this.emitter.fire();
  }

  getTreeItem(element: FindingNode): vscode.TreeItem {
    return element.toTreeItem();
  }

  getChildren(element?: FindingNode): vscode.ProviderResult<FindingNode[]> {
    if (!element) {
      if (this.findings.length === 0) {
        // Welcome view contributes the empty state — return nothing.
        return [];
      }
      const grouped = new Map<SeverityKey, ChainVetFinding[]>();
      for (const finding of this.findings) {
        const key = severityKey(finding.severity);
        const arr = grouped.get(key);
        if (arr) arr.push(finding);
        else grouped.set(key, [finding]);
      }
      const nodes: FindingNode[] = [];
      for (const key of SEVERITY_ORDER) {
        const group = grouped.get(key);
        if (!group || group.length === 0) continue;
        nodes.push(FindingNode.group(key, group));
      }
      return nodes;
    }

    if (element.kind === "group") {
      return element.children!.map((finding, index) => FindingNode.leaf(finding, index));
    }

    return [];
  }
}

class FindingNode {
  private constructor(
    readonly kind: "group" | "leaf",
    private readonly label: string,
    private readonly description: string | undefined,
    private readonly collapsible: vscode.TreeItemCollapsibleState,
    private readonly iconId: string,
    private readonly iconColor: string | undefined,
    private readonly tooltipText: string | vscode.MarkdownString | undefined,
    readonly children: ChainVetFinding[] | undefined,
    private readonly command: vscode.Command | undefined,
  ) {}

  toTreeItem(): vscode.TreeItem {
    const item = new vscode.TreeItem(this.label, this.collapsible);
    item.description = this.description;
    item.tooltip = this.tooltipText;
    item.iconPath = this.iconColor
      ? new vscode.ThemeIcon(this.iconId, new vscode.ThemeColor(this.iconColor))
      : new vscode.ThemeIcon(this.iconId);
    item.command = this.command;
    if (this.kind === "leaf") {
      item.contextValue = "chainvetFinding";
    } else {
      item.contextValue = "chainvetGroup";
    }
    return item;
  }

  static group(key: SeverityKey, items: ChainVetFinding[]): FindingNode {
    return new FindingNode(
      "group",
      SEVERITY_LABEL[key],
      `${items.length}`,
      vscode.TreeItemCollapsibleState.Expanded,
      severityIconId(key),
      severityIconColor(key),
      `${items.length} ${SEVERITY_LABEL[key].toLowerCase()} finding(s).`,
      items,
      undefined,
    );
  }

  static leaf(finding: ChainVetFinding, index: number): FindingNode {
    const heading = titleCase(finding.kind || `Finding ${index + 1}`);
    const locParts: string[] = [];
    if (finding.file) locParts.push(path.basename(finding.file));
    if (finding.function) locParts.push(`${finding.function}()`);
    const description = locParts.join(" · ");

    const tooltip = new vscode.MarkdownString();
    tooltip.isTrusted = false;
    tooltip.supportThemeIcons = true;
    tooltip.appendMarkdown(`**${heading}**\n\n`);
    if (finding.severity) tooltip.appendMarkdown(`Severity: \`${finding.severity}\`  \n`);
    if (finding.confidence) tooltip.appendMarkdown(`Confidence: \`${finding.confidence}\`  \n`);
    if (finding.file) tooltip.appendMarkdown(`File: \`${finding.file}\`  \n`);
    if (finding.function) tooltip.appendMarkdown(`Function: \`${finding.function}()\`  \n`);
    if (finding.layer) tooltip.appendMarkdown(`Layer: \`${finding.layer}\`  \n`);
    if (finding.category) tooltip.appendMarkdown(`Category: \`${finding.category}\`  \n`);
    if (finding.evidence) tooltip.appendMarkdown(`Evidence: \`${finding.evidence}\`  \n`);
    if (finding.message) {
      tooltip.appendMarkdown(`\n${finding.message}\n`);
    }

    return new FindingNode(
      "leaf",
      heading,
      description || undefined,
      vscode.TreeItemCollapsibleState.None,
      "circle-filled",
      severityIconColor(severityKey(finding.severity)),
      tooltip,
      undefined,
      {
        command: "chainvet.openFindingDetail",
        title: "Open finding",
        arguments: [finding],
      },
    );
  }
}

// ─── Summary tree ────────────────────────────────────────────────────

export class SummaryProvider implements vscode.TreeDataProvider<SummaryNode> {
  private state: StatusState = "idle";
  private detail = "";
  private summary: SummarySnapshot | null = null;
  runStartedAt: number | null = null;
  private readonly emitter = new vscode.EventEmitter<SummaryNode | undefined | null | void>();
  readonly onDidChangeTreeData = this.emitter.event;

  setState(state: StatusState, detail: string): void {
    this.state = state;
    this.detail = detail;
    this.emitter.fire();
  }

  beginRun(targetPath: string, mode: string): void {
    this.runStartedAt = Date.now();
    this.summary = {
      target: path.basename(targetPath),
      targetPath,
      mode,
      counts: { high: 0, medium: 0, low: 0, info: 0, unknown: 0, total: 0 },
      elapsedMs: 0,
    };
    this.emitter.fire();
  }

  setSummary(snapshot: SummarySnapshot): void {
    this.summary = snapshot;
    this.emitter.fire();
  }

  clear(): void {
    this.summary = null;
    this.runStartedAt = null;
    this.state = "idle";
    this.detail = "";
    this.emitter.fire();
  }

  getTreeItem(element: SummaryNode): vscode.TreeItem {
    return element.toTreeItem();
  }

  getChildren(element?: SummaryNode): vscode.ProviderResult<SummaryNode[]> {
    if (element) return [];

    if (!this.summary && this.state === "idle") {
      // Welcome view handles the empty state.
      return [];
    }

    const nodes: SummaryNode[] = [];

    nodes.push(
      new SummaryNode(
        statusLabel(this.state),
        this.detail || undefined,
        statusIconId(this.state),
        statusIconColor(this.state),
      ),
    );

    if (this.summary) {
      nodes.push(
        new SummaryNode(
          `Target · ${this.summary.target}`,
          this.summary.targetPath,
          "file-code",
          undefined,
          undefined,
          this.summary.targetPath,
        ),
      );
      nodes.push(
        new SummaryNode(
          `Engine · ${this.summary.mode}`,
          undefined,
          "circuit-board",
          undefined,
        ),
      );
      if (this.summary.elapsedMs > 0) {
        nodes.push(
          new SummaryNode(
            "Elapsed",
            formatElapsed(this.summary.elapsedMs),
            "clock",
            undefined,
          ),
        );
      }

      const c = this.summary.counts;
      nodes.push(SummaryNode.separator("Severity breakdown"));

      const sevRows: Array<[string, number, string, string | undefined]> = [
        ["High",          c.high,    "error",          "errorForeground"],
        ["Medium",        c.medium,  "warning",        "list.warningForeground"],
        ["Low",           c.low,     "info",           "list.warningForeground"],
        ["Informational", c.info,    "lightbulb",      "charts.blue"],
        ["Unspecified",   c.unknown, "circle-outline", undefined],
      ];

      for (const [label, count, icon, color] of sevRows) {
        if (count === 0) continue;
        nodes.push(new SummaryNode(label, String(count), icon, color));
      }
      if (c.total === 0 && (this.state === "complete" || this.state === "cancelled")) {
        nodes.push(new SummaryNode("No findings", "0", "pass-filled", "testing.iconPassed"));
      }
    }

    return nodes;
  }
}

class SummaryNode {
  constructor(
    private readonly label: string,
    private readonly description: string | undefined,
    private readonly iconId: string,
    private readonly iconColor: string | undefined,
    private readonly commandId?: string,
    private readonly commandArg?: string,
  ) {}

  static separator(label: string): SummaryNode {
    return new SummaryNode(label, undefined, "list-flat", undefined);
  }

  toTreeItem(): vscode.TreeItem {
    const item = new vscode.TreeItem(this.label, vscode.TreeItemCollapsibleState.None);
    item.description = this.description;
    item.iconPath = this.iconColor
      ? new vscode.ThemeIcon(this.iconId, new vscode.ThemeColor(this.iconColor))
      : new vscode.ThemeIcon(this.iconId);
    if (this.commandId) {
      item.command = {
        command: this.commandId,
        title: this.label,
        arguments: this.commandArg ? [this.commandArg] : undefined,
      };
    }
    return item;
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────

function severityKey(severity?: string): SeverityKey {
  const value = String(severity || "").toLowerCase();
  if (value.includes("critical") || value.includes("high")) return "high";
  if (value.includes("medium") || value.includes("moderate")) return "medium";
  if (value.includes("low")) return "low";
  if (value.includes("info")) return "info";
  return "unknown";
}

function severityIconId(key: SeverityKey): string {
  switch (key) {
    case "high":     return "error";
    case "medium":   return "warning";
    case "low":      return "info";
    case "info":     return "lightbulb";
    case "unknown":  return "circle-outline";
  }
}

function severityIconColor(key: SeverityKey): string | undefined {
  switch (key) {
    case "high":     return "errorForeground";
    case "medium":   return "list.warningForeground";
    case "low":      return "list.warningForeground";
    case "info":     return "charts.blue";
    default:         return undefined;
  }
}

function statusLabel(state: StatusState): string {
  switch (state) {
    case "running":   return "Analysis running";
    case "complete":  return "Analysis complete";
    case "cancelled": return "Analysis cancelled";
    case "failed":    return "Analysis failed";
    case "idle":
    default:          return "Idle";
  }
}

function statusIconId(state: StatusState): string {
  switch (state) {
    case "running":   return "sync~spin";
    case "complete":  return "pass-filled";
    case "cancelled": return "circle-slash";
    case "failed":    return "error";
    default:          return "shield";
  }
}

function statusIconColor(state: StatusState): string | undefined {
  switch (state) {
    case "running":   return "charts.blue";
    case "complete":  return "testing.iconPassed";
    case "cancelled": return "list.warningForeground";
    case "failed":    return "errorForeground";
    default:          return undefined;
  }
}

function titleCase(value: string): string {
  return String(value || "")
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function formatElapsed(ms: number): string {
  const seconds = Math.max(0, Math.floor(ms / 1000));
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  if (!minutes) return `${remainder}s`;
  return `${minutes}m ${remainder}s`;
}
