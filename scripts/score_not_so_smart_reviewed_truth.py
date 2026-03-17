#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Sequence, Tuple


MODE_SPECS = {
    "static": {"types_col": 2, "sep": ","},
    "symbolic": {"types_col": 5, "sep": ";"},
    "fuzzing": {"types_col": 8, "sep": ";"},
    "hybrid": {"types_col": 11, "sep": ";"},
}

KIND_ALIASES = {
    "dangerous-block-timestamp": "timestamp-dependency",
    "exception-disorder": "unchecked-call",
    "hardcoded-gas": "hardcoded-gas-transfer",
    "storage-memory-issue": "memory-manipulation",
    "underflow": "integer-underflow",
    "unused-return-value": "unchecked-call",
}

NOISE_KINDS = {
    "default-visibility",
    "storage-array-by-value",
    "missing-input-validation",
    "tainted-call",
}

FUZZ_RUNTIME_LINE_RE = re.compile(r"\[([a-z0-9-]+)\]\s+\[[a-z]+\]\s+\[(low|medium|high)\]")
FUZZ_META_KIND_RE = re.compile(r"\bkind=([a-z0-9-]+)")


def normalize_kind(kind: str) -> str:
    kind = kind.strip()
    if not kind:
        return ""
    kind = KIND_ALIASES.get(kind, kind)
    if kind.startswith("reentrancy"):
        return "reentrancy"
    return kind


def parse_counted_types(field: str, sep: str) -> Counter[str]:
    field = (field or "").strip()
    counts: Counter[str] = Counter()
    if not field or field == "-":
        return counts

    for part in field.split(sep):
        part = part.strip()
        if not part or part == "-":
            continue
        raw_kind, raw_count = (part.split("=", 1) + ["1"])[:2]
        kind = normalize_kind(raw_kind)
        if not kind:
            continue
        try:
            count = int(raw_count.strip())
        except ValueError:
            count = 1
        counts[kind] += count
    return counts


def normalize_raw_stem(file_path: str) -> str:
    return (
        file_path.replace("\\", "/")
        .replace("/", "_")
        .replace(" ", "_")
    )


def load_json(path: Path):
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def counts_from_static_json(path: Path) -> Counter[str]:
    data = load_json(path)
    if not data:
        return Counter()
    out: Counter[str] = Counter()
    for finding in data.get("findings", []):
        kind = normalize_kind(str(finding.get("kind", "")))
        if kind:
            out[kind] += 1
    return out


def counts_from_symbolic_json(path: Path) -> Tuple[Counter[str], Counter[str]]:
    data = load_json(path)
    if not data:
        return Counter(), Counter()
    runtime: Counter[str] = Counter()
    meta: Counter[str] = Counter()
    for vuln in data.get("vulnerabilities", []):
        kind = normalize_kind(str(vuln.get("kind", "")))
        if kind:
            runtime[kind] += 1
    for finding in data.get("meta_findings", []):
        kind = normalize_kind(str(finding.get("finding_type", "")))
        if kind:
            meta[kind] += 1
    return runtime, meta


def counts_from_hybrid_findings(path: Path) -> Tuple[Counter[str], Counter[str]]:
    data = load_json(path)
    if not isinstance(data, list):
        return Counter(), Counter()
    runtime: Counter[str] = Counter()
    meta: Counter[str] = Counter()
    for finding in data:
        kind = normalize_kind(str(finding.get("finding_type", "")))
        if not kind:
            continue
        layer = str(finding.get("analysis_layer", "runtime")).strip().lower()
        if layer == "meta":
            meta[kind] += 1
        else:
            runtime[kind] += 1
    return runtime, meta


def counts_from_fuzzing_out(path: Path) -> Tuple[Counter[str], Counter[str]]:
    if not path.is_file():
        return Counter(), Counter()
    runtime: Counter[str] = Counter()
    meta: Counter[str] = Counter()
    in_meta = False
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if "[Meta]" in line:
            in_meta = True
            continue
        if in_meta:
            m = FUZZ_META_KIND_RE.search(line)
            if m:
                kind = normalize_kind(m.group(1))
                if kind:
                    meta[kind] += 1
            continue
        m = FUZZ_RUNTIME_LINE_RE.search(line)
        if m:
            kind = normalize_kind(m.group(1))
            if kind:
                runtime[kind] += 1
    return runtime, meta


def prioritize_counts(counts: Counter[str], expected: Sequence[str]) -> Counter[str]:
    if not counts:
        return Counter()
    expected_set = set(expected)
    direct = Counter({k: v for k, v in counts.items() if k in expected_set and v > 0})
    if direct:
        return direct
    filtered = Counter({k: v for k, v in counts.items() if k not in NOISE_KINDS and v > 0})
    return filtered if filtered else counts


def load_truth(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    total_issues = 0
    for contract in data["contracts"]:
        issues = contract.get("reviewed_issues", [])
        total_issues += len(issues)
        for issue in issues:
            seen = set()
            normalized = []
            for kind in issue.get("match_any_of", []):
                mapped = normalize_kind(kind)
                if mapped and mapped not in seen:
                    normalized.append(mapped)
                    seen.add(mapped)
            issue["match_any_of"] = normalized

    data["total_reviewed_issues"] = total_issues
    return data


def read_summary(summary_tsv: Path) -> Dict[str, Dict[str, Counter[str]]]:
    rows: Dict[str, Dict[str, Counter[str]]] = {}
    with summary_tsv.open("r", encoding="utf-8") as f:
        reader = csv.reader(f, delimiter="\t")
        header = next(reader, None)
        if not header:
            raise ValueError(f"empty summary file: {summary_tsv}")
        for row in reader:
            if not row:
                continue
            file_path = row[0]
            rows[file_path] = {
                mode: parse_counted_types(row[spec["types_col"]], spec["sep"])
                for mode, spec in MODE_SPECS.items()
            }
    return rows


def extract_channel_counters(
    file_path: str,
    mode: str,
    summary_counts: Counter[str],
    raw_dir: Path,
    expected_union: Sequence[str],
) -> Dict[str, Counter[str]]:
    stem = normalize_raw_stem(file_path)

    if mode == "static":
        runtime = counts_from_static_json(raw_dir / f"{stem}.static.json")
        meta = Counter()
    elif mode == "symbolic":
        runtime, meta = counts_from_symbolic_json(raw_dir / f"{stem}.symbolic.json")
    elif mode == "fuzzing":
        runtime, meta = counts_from_fuzzing_out(raw_dir / f"{stem}.fuzzing.out")
    else:
        runtime, meta = counts_from_hybrid_findings(raw_dir / f"{stem}.hybrid.findings.json")

    if not runtime and not meta:
        runtime = Counter(summary_counts)

    runtime_primary = prioritize_counts(runtime, expected_union)
    surfaced_output = prioritize_counts(runtime + meta, expected_union)

    return {
        "runtime_primary": runtime_primary,
        "meta_secondary": meta,
        "surfaced_output": surfaced_output,
    }


def freeze_counts(counts: Counter[str], relevant_kinds: Sequence[str]) -> Tuple[int, ...]:
    return tuple(int(counts.get(kind, 0)) for kind in relevant_kinds)


def match_issues(
    issues: Sequence[dict], findings: Counter[str]
) -> Tuple[int, List[dict], set[str]]:
    relevant_kinds = sorted(
        {
            kind
            for issue in issues
            for kind in issue.get("match_any_of", [])
            if kind
        }
    )
    start_counts = freeze_counts(findings, relevant_kinds)

    @lru_cache(maxsize=None)
    def solve(
        issue_index: int, counts_tuple: Tuple[int, ...]
    ) -> Tuple[int, Tuple[Tuple[int, str], ...]]:
        if issue_index >= len(issues):
            return 0, ()

        best_hits, best_assignments = solve(issue_index + 1, counts_tuple)
        best_choice = ((issue_index, ""),) + best_assignments

        issue = issues[issue_index]
        for kind in issue.get("match_any_of", []):
            if kind not in relevant_kinds:
                continue
            pos = relevant_kinds.index(kind)
            if counts_tuple[pos] <= 0:
                continue
            next_counts = list(counts_tuple)
            next_counts[pos] -= 1
            child_hits, child_assignments = solve(issue_index + 1, tuple(next_counts))
            child_hits += 1
            candidate = ((issue_index, kind),) + child_assignments
            if child_hits > best_hits:
                best_hits = child_hits
                best_choice = candidate

        return best_hits, best_choice

    matched_count, assignments = solve(0, start_counts)
    chosen_kind_by_index = {issue_idx: kind for issue_idx, kind in assignments if kind}

    issue_results: List[dict] = []
    for issue_index, issue in enumerate(issues):
        matched_kind = chosen_kind_by_index.get(issue_index)
        issue_results.append(
            {
                "id": issue["id"],
                "summary": issue["summary"],
                "match_any_of": issue.get("match_any_of", []),
                "matched": matched_kind is not None,
                "matched_kind": matched_kind,
            }
        )
    used_kinds = {kind for kind in chosen_kind_by_index.values() if kind}
    return matched_count, issue_results, used_kinds


def build_records(
    truth: dict,
    summary_rows: Dict[str, Dict[str, Counter[str]]],
    raw_dir: Path,
) -> Tuple[List[dict], dict]:
    channels = ("runtime_primary", "meta_secondary", "surfaced_output")
    records: List[dict] = []
    per_channel_mode = {
        channel: {
            mode: {
                "hits": 0,
                "misses": 0,
                "contracts_with_hits": 0,
                "contracts_fully_hit": 0,
                "contracts_with_reviewed_issues": 0,
                "extra_kinds": 0,
            }
            for mode in MODE_SPECS
        }
        for channel in channels
    }

    for contract in truth["contracts"]:
        file_path = contract["file"]
        issues = contract.get("reviewed_issues", [])
        findings_by_mode = summary_rows.get(file_path)
        if findings_by_mode is None:
            raise SystemExit(f"summary missing benchmark file: {file_path}")

        expected_union = sorted({k for issue in issues for k in issue.get("match_any_of", [])})

        for mode in MODE_SPECS:
            channel_counts = extract_channel_counters(
                file_path,
                mode,
                findings_by_mode[mode],
                raw_dir,
                expected_union,
            )

            channel_results = {}
            for channel in channels:
                matched_count, issue_results, used_kinds = match_issues(
                    issues, channel_counts[channel]
                )
                misses = len(issues) - matched_count
                predicted_kinds = sorted(channel_counts[channel].keys())
                extra_predicted_kinds = sorted(set(predicted_kinds) - used_kinds)

                if issues:
                    per_channel_mode[channel][mode]["contracts_with_reviewed_issues"] += 1
                    if matched_count > 0:
                        per_channel_mode[channel][mode]["contracts_with_hits"] += 1
                    if matched_count == len(issues):
                        per_channel_mode[channel][mode]["contracts_fully_hit"] += 1

                per_channel_mode[channel][mode]["hits"] += matched_count
                per_channel_mode[channel][mode]["misses"] += misses
                per_channel_mode[channel][mode]["extra_kinds"] += len(extra_predicted_kinds)

                channel_results[channel] = {
                    "hits": matched_count,
                    "misses": misses,
                    "issues": issue_results,
                    "predicted_kinds": predicted_kinds,
                    "extra_predicted_kinds": extra_predicted_kinds,
                }

            records.append(
                {
                    "file": file_path,
                    "target_kind": contract["target_kind"],
                    "mode": mode,
                    "reviewed_issue_count": len(issues),
                    "channels": channel_results,
                }
            )

    total_reviewed_issues = truth["total_reviewed_issues"]
    summary = {channel: {} for channel in channels}
    for channel in channels:
        for mode, stats in per_channel_mode[channel].items():
            hits = stats["hits"]
            misses = stats["misses"]
            extra_kinds = stats["extra_kinds"]
            coverage = hits / total_reviewed_issues if total_reviewed_issues else 0.0
            precision = hits / (hits + extra_kinds) if (hits + extra_kinds) else 0.0
            recall = coverage
            f1 = (
                (2.0 * precision * recall / (precision + recall))
                if (precision + recall)
                else 0.0
            )
            strict_score = hits / (hits + misses + extra_kinds) if (hits + misses + extra_kinds) else 0.0
            stats = dict(stats)
            stats["coverage"] = round(coverage, 3)
            stats["precision"] = round(precision, 3)
            stats["recall"] = round(recall, 3)
            stats["f1"] = round(f1, 3)
            stats["strict_score"] = round(strict_score, 3)
            stats["total_reviewed_issues"] = total_reviewed_issues
            summary[channel][mode] = stats

    return records, summary


def write_outputs(out_dir: Path, records: List[dict], summary: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    with (out_dir / "summary.json").open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")

    with (out_dir / "per_contract.json").open("w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)
        f.write("\n")

    issue_matrix_rows: Dict[Tuple[str, str], dict] = {}
    for record in records:
        for channel in ("runtime_primary", "surfaced_output"):
            for issue in record["channels"][channel]["issues"]:
                key = (record["file"], issue["id"])
                row = issue_matrix_rows.setdefault(
                    key,
                    {
                        "file": record["file"],
                        "target_kind": record["target_kind"],
                        "issue_id": issue["id"],
                        "summary": issue["summary"],
                        "match_any_of": ",".join(issue["match_any_of"]),
                        "static_runtime_hit": 0,
                        "symbolic_runtime_hit": 0,
                        "fuzzing_runtime_hit": 0,
                        "hybrid_runtime_hit": 0,
                        "static_surfaced_hit": 0,
                        "symbolic_surfaced_hit": 0,
                        "fuzzing_surfaced_hit": 0,
                        "hybrid_surfaced_hit": 0,
                    },
                )
                suffix = "runtime" if channel == "runtime_primary" else "surfaced"
                row[f"{record['mode']}_{suffix}_hit"] = 1 if issue["matched"] else 0

    matrix_path = out_dir / "per_issue_matrix.tsv"
    with matrix_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(
            [
                "file",
                "target_kind",
                "issue_id",
                "summary",
                "match_any_of",
                "static_runtime_hit",
                "symbolic_runtime_hit",
                "fuzzing_runtime_hit",
                "hybrid_runtime_hit",
                "static_surfaced_hit",
                "symbolic_surfaced_hit",
                "fuzzing_surfaced_hit",
                "hybrid_surfaced_hit",
            ]
        )
        for row in sorted(issue_matrix_rows.values(), key=lambda r: (r["file"], r["issue_id"])):
            writer.writerow(
                [
                    row["file"],
                    row["target_kind"],
                    row["issue_id"],
                    row["summary"],
                    row["match_any_of"],
                    row["static_runtime_hit"],
                    row["symbolic_runtime_hit"],
                    row["fuzzing_runtime_hit"],
                    row["hybrid_runtime_hit"],
                    row["static_surfaced_hit"],
                    row["symbolic_surfaced_hit"],
                    row["fuzzing_surfaced_hit"],
                    row["hybrid_surfaced_hit"],
                ]
            )


def print_summary(summary: dict, truth_path: Path, summary_tsv: Path, out_dir: Path) -> None:
    print(f"truth: {truth_path}")
    print(f"summary: {summary_tsv}")
    print(f"out_dir: {out_dir}")
    total = next(iter(summary["runtime_primary"].values()))["total_reviewed_issues"]
    print(f"total_reviewed_issues={total}")
    print()

    for channel in ("runtime_primary", "meta_secondary", "surfaced_output"):
        print(f"[{channel}]")
        for mode in MODE_SPECS:
            stats = summary[channel][mode]
            print(
                f"{mode}: hits={stats['hits']} misses={stats['misses']} "
                f"extra_kinds={stats['extra_kinds']} "
                f"precision={stats['precision']:.3f} "
                f"recall={stats['recall']:.3f} "
                f"f1={stats['f1']:.3f} "
                f"strict_score={stats['strict_score']:.3f} "
                f"coverage={stats['coverage']:.3f} "
                f"contracts_with_hits={stats['contracts_with_hits']}/{stats['contracts_with_reviewed_issues']} "
                f"fully_hit={stats['contracts_fully_hit']}/{stats['contracts_with_reviewed_issues']}"
            )
        print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Score Not-so-smart benchmark runs against the reviewed truth set (runtime/meta split)."
    )
    parser.add_argument("summary_tsv", type=Path, help="Path to benchmark summary.tsv")
    parser.add_argument(
        "--truth",
        type=Path,
        default=Path("fixtures/ground_truth/not_so_smart_reviewed_truth.json"),
        help="Reviewed truth JSON artifact",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory (default: <summary_dir>/reviewed_truth_analysis)",
    )
    args = parser.parse_args()

    if not args.summary_tsv.is_file():
        raise SystemExit(f"summary file not found: {args.summary_tsv}")
    if not args.truth.is_file():
        raise SystemExit(f"truth file not found: {args.truth}")

    truth = load_truth(args.truth)
    summary_rows = read_summary(args.summary_tsv)
    raw_dir = args.summary_tsv.parent / "raw"
    records, summary = build_records(truth, summary_rows, raw_dir)

    out_dir = args.out_dir or (args.summary_tsv.parent / "reviewed_truth_analysis")
    write_outputs(out_dir, records, summary)
    print_summary(summary, args.truth, args.summary_tsv, out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
