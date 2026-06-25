import * as vscode from "vscode";
import { ChainVetFinding } from "./types";

/**
 * Resolve the best source-code range for a finding.
 *
 * Order of preference:
 *   1. Byte offsets (start/end) emitted by the analyzer — when present and not (0,0).
 *   2. Function name → "function <name>(" / "modifier <name>" / constructor / fallback / receive.
 *   3. Finding kind as a Solidity keyword (selfdestruct, delegatecall, tx.origin, etc.).
 *   4. Top of file (line 1) — only as a last resort.
 *
 * Returns both the range and how it was resolved, so callers can surface a hint
 * to the user when the location is approximate.
 */
export type RangeResolution = {
  range: vscode.Range;
  source: "offset" | "function" | "keyword" | "fallback";
};

export function resolveFindingRange(text: string | null, finding: ChainVetFinding): RangeResolution {
  if (text != null && hasUsableOffset(finding)) {
    return { range: offsetRange(text, finding.start!, finding.end!), source: "offset" };
  }

  if (text != null && finding.function) {
    const found = locateFunction(text, finding.function);
    if (found) return { range: found, source: "function" };
  }

  if (text != null && finding.kind) {
    const found = locateKeyword(text, finding.kind);
    if (found) return { range: found, source: "keyword" };
  }

  return { range: new vscode.Range(0, 0, 0, 1), source: "fallback" };
}

function hasUsableOffset(finding: ChainVetFinding): boolean {
  if (finding.start == null || finding.end == null) return false;
  // Treat (0, 0) as "unknown" — the analyzer's sentinel for missing spans.
  if (finding.start === 0 && finding.end === 0) return false;
  return finding.end >= finding.start;
}

// ─── Function / modifier / constructor lookup ───────────────────────────

function locateFunction(text: string, name: string): vscode.Range | null {
  const safe = escapeRegExp(name);
  const lower = name.toLowerCase();

  // Special Solidity entry-points — match the keyword form (no name token).
  if (lower === "constructor") {
    const m = /\bconstructor\s*\(/.exec(text);
    if (m) return rangeForMatch(text, m.index, "constructor".length);
  }
  if (lower === "fallback") {
    const m = /\bfallback\s*\(/.exec(text) ?? /\bfunction\s*\(\s*\)\s*(?:external\s+)?payable/.exec(text);
    if (m) return rangeForMatch(text, m.index, Math.min(m[0].length, 12));
  }
  if (lower === "receive") {
    const m = /\breceive\s*\(/.exec(text);
    if (m) return rangeForMatch(text, m.index, "receive".length);
  }

  // Most accurate: "function <name>(" / "modifier <name>(" / "modifier <name> {"
  const patterns: RegExp[] = [
    new RegExp(`\\bfunction\\s+${safe}\\s*\\(`),
    new RegExp(`\\bmodifier\\s+${safe}\\s*[({]`),
    new RegExp(`\\bevent\\s+${safe}\\s*\\(`),
    new RegExp(`\\berror\\s+${safe}\\s*\\(`),
  ];

  for (const pat of patterns) {
    const m = pat.exec(text);
    if (m) {
      // Highlight just the name token, not the whole `function name(` slice.
      const nameOffset = m.index + m[0].lastIndexOf(name);
      return rangeForMatch(text, nameOffset >= m.index ? nameOffset : m.index, name.length);
    }
  }

  return null;
}

// ─── Generic keyword lookup (selfdestruct, delegatecall, tx.origin, ...) ─

const KEYWORD_HINTS: Record<string, string[]> = {
  "reentrancy": ["\\.call\\b", "\\.transfer\\b", "\\.send\\b"],
  "unchecked-call": ["\\.call\\b", "\\.send\\b"],
  "unchecked-send": ["\\.send\\b"],
  "selfdestruct": ["\\bselfdestruct\\b", "\\bsuicide\\b"],
  "delegatecall": ["\\bdelegatecall\\b"],
  "tx-origin": ["\\btx\\.origin\\b"],
  "tx.origin": ["\\btx\\.origin\\b"],
  "timestamp-dependence": ["\\bblock\\.timestamp\\b", "\\bnow\\b"],
  "block-timestamp": ["\\bblock\\.timestamp\\b"],
  "block-number": ["\\bblock\\.number\\b"],
  "weak-randomness": ["\\bblockhash\\b", "\\bblock\\.timestamp\\b", "\\bblock\\.difficulty\\b"],
  "integer-overflow": ["\\bunchecked\\s*\\{", "\\+\\+|\\-\\-"],
  "assembly": ["\\bassembly\\s*\\{"],
  "low-level-call": ["\\.call\\b"],
};

function locateKeyword(text: string, kind: string): vscode.Range | null {
  const key = kind.trim().toLowerCase();
  const hints = KEYWORD_HINTS[key] ?? KEYWORD_HINTS[key.replace(/_/g, "-")];
  if (!hints) return null;
  for (const pattern of hints) {
    const re = new RegExp(pattern, "i");
    const m = re.exec(text);
    if (m) {
      return rangeForMatch(text, m.index, m[0].length);
    }
  }
  return null;
}

// ─── Geometry helpers ───────────────────────────────────────────────────

function rangeForMatch(text: string, offset: number, length: number): vscode.Range {
  const start = clamp(offset, 0, text.length);
  const end = clamp(offset + Math.max(1, length), start + 1, text.length);
  return new vscode.Range(offsetToPosition(text, start), offsetToPosition(text, end));
}

function offsetRange(text: string, start: number, end: number): vscode.Range {
  const safeStart = clamp(start, 0, text.length);
  const safeEnd = clamp(end, safeStart, text.length);
  const startPos = offsetToPosition(text, safeStart);
  const endPos = safeEnd === safeStart
    ? new vscode.Position(startPos.line, startPos.character + 1)
    : offsetToPosition(text, safeEnd);
  return new vscode.Range(startPos, endPos);
}

function offsetToPosition(text: string, offset: number): vscode.Position {
  let line = 0;
  let lineStart = 0;
  for (let i = 0; i < offset; i++) {
    if (text.charCodeAt(i) === 10) {
      line += 1;
      lineStart = i + 1;
    }
  }
  return new vscode.Position(line, Math.max(0, offset - lineStart));
}

function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.max(min, Math.min(max, value));
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
