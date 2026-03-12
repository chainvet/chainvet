#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
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


def normalize_kind(kind: str) -> str:
    kind = kind.strip()
    if not kind:
        return ""
    return KIND_ALIASES.get(kind, kind)


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


def freeze_counts(counts: Counter[str], relevant_kinds: Sequence[str]) -> Tuple[int, ...]:
    return tuple(int(counts.get(kind, 0)) for kind in relevant_kinds)


def match_issues(
    issues: Sequence[dict], findings: Counter[str]
) -> Tuple[int, List[dict]]:
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
    def solve(issue_index: int, counts_tuple: Tuple[int, ...]) -> Tuple[int, Tuple[Tuple[int, str], ...]]:
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
    return matched_count, issue_results


def build_records(truth: dict, summary_rows: Dict[str, Dict[str, Counter[str]]]) -> Tuple[List[dict], dict]:
    records: List[dict] = []
    per_mode = {
        mode: {
            "hits": 0,
            "misses": 0,
            "contracts_with_hits": 0,
            "contracts_fully_hit": 0,
            "contracts_with_reviewed_issues": 0,
        }
        for mode in MODE_SPECS
    }

    for contract in truth["contracts"]:
        file_path = contract["file"]
        issues = contract.get("reviewed_issues", [])
        findings_by_mode = summary_rows.get(file_path)
        if findings_by_mode is None:
            raise SystemExit(f"summary missing benchmark file: {file_path}")

        for mode in MODE_SPECS:
            matched_count, issue_results = match_issues(issues, findings_by_mode[mode])
            misses = len(issues) - matched_count
            if issues:
                per_mode[mode]["contracts_with_reviewed_issues"] += 1
                if matched_count > 0:
                    per_mode[mode]["contracts_with_hits"] += 1
                if matched_count == len(issues):
                    per_mode[mode]["contracts_fully_hit"] += 1
            per_mode[mode]["hits"] += matched_count
            per_mode[mode]["misses"] += misses

            records.append(
                {
                    "file": file_path,
                    "target_kind": contract["target_kind"],
                    "mode": mode,
                    "reviewed_issue_count": len(issues),
                    "hits": matched_count,
                    "misses": misses,
                    "issues": issue_results,
                }
            )

    total_reviewed_issues = truth["total_reviewed_issues"]
    for mode, stats in per_mode.items():
        coverage = stats["hits"] / total_reviewed_issues if total_reviewed_issues else 0.0
        stats["coverage"] = round(coverage, 3)
        stats["total_reviewed_issues"] = total_reviewed_issues

    return records, per_mode


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
        for issue in record["issues"]:
            key = (record["file"], issue["id"])
            row = issue_matrix_rows.setdefault(
                key,
                {
                    "file": record["file"],
                    "target_kind": record["target_kind"],
                    "issue_id": issue["id"],
                    "summary": issue["summary"],
                    "match_any_of": ",".join(issue["match_any_of"]),
                    "static_hit": 0,
                    "symbolic_hit": 0,
                    "fuzzing_hit": 0,
                    "hybrid_hit": 0,
                    "static_kind": "",
                    "symbolic_kind": "",
                    "fuzzing_kind": "",
                    "hybrid_kind": "",
                },
            )
            row[f"{record['mode']}_hit"] = 1 if issue["matched"] else 0
            row[f"{record['mode']}_kind"] = issue["matched_kind"] or ""

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
                "static_hit",
                "static_kind",
                "symbolic_hit",
                "symbolic_kind",
                "fuzzing_hit",
                "fuzzing_kind",
                "hybrid_hit",
                "hybrid_kind",
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
                    row["static_hit"],
                    row["static_kind"],
                    row["symbolic_hit"],
                    row["symbolic_kind"],
                    row["fuzzing_hit"],
                    row["fuzzing_kind"],
                    row["hybrid_hit"],
                    row["hybrid_kind"],
                ]
            )


def print_summary(summary: dict, truth_path: Path, summary_tsv: Path, out_dir: Path) -> None:
    print(f"truth: {truth_path}")
    print(f"summary: {summary_tsv}")
    print(f"out_dir: {out_dir}")
    print(f"total_reviewed_issues={next(iter(summary.values()))['total_reviewed_issues']}")
    print()
    for mode in MODE_SPECS:
        stats = summary[mode]
        print(
            f"{mode}: hits={stats['hits']} misses={stats['misses']} "
            f"coverage={stats['coverage']:.3f} "
            f"contracts_with_hits={stats['contracts_with_hits']}/{stats['contracts_with_reviewed_issues']} "
            f"fully_hit={stats['contracts_fully_hit']}/{stats['contracts_with_reviewed_issues']}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Score Not-so-smart benchmark runs against the reviewed truth set."
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
    records, summary = build_records(truth, summary_rows)

    out_dir = args.out_dir or (args.summary_tsv.parent / "reviewed_truth_analysis")
    write_outputs(out_dir, records, summary)
    print_summary(summary, args.truth, args.summary_tsv, out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
