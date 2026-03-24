#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from json import JSONDecodeError
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence


MODE_SPECS = {
    "static": {"payload_suffix": ".static.json", "timeout_col": 3},
    "symbolic": {"payload_suffix": ".symbolic.json", "timeout_col": 6},
    "fuzzing": {"payload_suffix": ".fuzzing.json", "timeout_col": 9},
    "hybrid": {"payload_suffix": ".hybrid.json", "timeout_col": 14},
}

KIND_ALIASES = {
    "underflow": "integer-underflow",
    "hardcoded-gas": "hardcoded-gas-transfer",
    "storage-memory-issue": "memory-manipulation",
    "unused-return-value": "unchecked-call",
    "dangerous-block-timestamp": "timestamp-dependency",
}

KIND_TO_SMARTBUGS = {
    "access-control": "access_control",
    "wrong-constructor-name": "access_control",
    "uninit-permission-check": "access_control",
    "unprotected-ether-withdrawal": "access_control",
    "unprotected-selfdestruct": "access_control",
    "unsafe-delegatecall": "access_control",
    "integer-overflow": "arithmetic",
    "integer-underflow": "arithmetic",
    "weak-prng": "bad_randomness",
    "dos-block-gas-limit": "denial_of_service",
    "dos-with-failed-call": "denial_of_service",
    "transaction-order-dependency": "front_running",
    "reentrancy": "reentrancy",
    "timestamp-dependency": "time_manipulation",
    "unchecked-call": "unchecked_low_level_calls",
    "unused-return-value": "unchecked_low_level_calls",
    "exception-disorder": "unchecked_low_level_calls",
    "memory-manipulation": "other",
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def normalize_kind(kind: str) -> str:
    kind = kind.strip()
    if not kind:
        return ""
    kind = KIND_ALIASES.get(kind, kind)
    if kind.startswith("reentrancy"):
        return "reentrancy"
    return kind


def map_kind_to_smartbugs(kind: str) -> str:
    normalized = normalize_kind(kind)
    return KIND_TO_SMARTBUGS.get(normalized, "")


def normalize_raw_stem(file_path: str) -> str:
    return file_path.replace("\\", "/").replace("/", "_").replace(" ", "_")


def load_json(path: Path) -> dict | list | None:
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except JSONDecodeError:
        return None


def normalize_file_path(path: str | None) -> str:
    if not path:
        return ""
    value = str(path).replace("\\", "/")
    root = str(repo_root()).replace("\\", "/")
    if value.startswith(root + "/"):
        return value[len(root) + 1 :]
    return value


def line_offsets_for_file(file_path: str) -> list[int]:
    abs_path = repo_root() / file_path
    text = abs_path.read_text(encoding="utf-8", errors="replace")
    offsets = [0]
    for index, char in enumerate(text):
        if char == "\n":
            offsets.append(index + 1)
    offsets.append(len(text) + 1)
    return offsets


def offset_to_line(offsets: list[int], offset: int | None) -> int | None:
    if offset is None:
        return None
    if offset < 0:
        return None
    lo = 0
    hi = len(offsets) - 1
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if offsets[mid] <= offset:
            lo = mid
        else:
            hi = mid
    return lo + 1


def range_from_item(item: dict, source_file: str) -> tuple[str, int | None, int | None]:
    file_path = normalize_file_path(item.get("file"))
    start = item.get("start")
    end = item.get("end")

    if not file_path and isinstance(item.get("location"), dict):
        location = item["location"]
        file_path = normalize_file_path(location.get("file"))
        start = location.get("start", start)
        end = location.get("end", end)

    if not file_path:
        file_path = source_file

    if isinstance(item.get("span"), dict):
        span = item["span"]
        start = span.get("start", start)
        end = span.get("end", end)

    if isinstance(start, dict):
        start = start.get("line")
    elif start is not None and not isinstance(start, int):
        start = None
    if isinstance(end, dict):
        end = end.get("line")
    elif end is not None and not isinstance(end, int):
        end = None

    if isinstance(start, int) and isinstance(end, int) and (start <= 0 or end <= 0):
        return file_path, None, None

    if isinstance(start, int) and isinstance(end, int) and ("span" in item or "file" in item or isinstance(item.get("location"), dict)):
        offsets = line_offsets_for_file(file_path)
        start_line = offset_to_line(offsets, start)
        end_line = offset_to_line(offsets, end)
        if start_line is not None or end_line is not None:
            return file_path, start_line, end_line or start_line
        return file_path, None, None

    return file_path, None, None


def normalize_prediction_item(
    item: dict,
    source_file: str,
    kind_key: str,
) -> dict | None:
    raw_kind = str(item.get(kind_key, "")).strip()
    if not raw_kind and kind_key != "finding_type":
        raw_kind = str(item.get("finding_type", "")).strip()
    if not raw_kind and kind_key != "kind":
        raw_kind = str(item.get("kind", "")).strip()
    category = map_kind_to_smartbugs(raw_kind)
    if not category:
        return None
    file_path, start_line, end_line = range_from_item(item, source_file)
    return {
        "category": category,
        "file": file_path,
        "start_line": start_line,
        "end_line": end_line,
    }


def extract_predictions(mode: str, source_file: str, raw_dir: Path) -> dict:
    stem = normalize_raw_stem(source_file)
    payload = load_json(raw_dir / f"{stem}{MODE_SPECS[mode]['payload_suffix']}")
    if not isinstance(payload, dict):
        return {
            "surfaced_items": [],
            "raw_items": [],
            "surfaced_categories": set(),
            "raw_categories": set(),
        }

    if mode == "static":
        surfaced_runtime = payload.get("findings", [])
        raw_runtime = payload.get("findings_raw", surfaced_runtime)
        surfaced_meta: list[dict] = []
        raw_meta: list[dict] = []
    elif mode == "symbolic":
        surfaced_runtime = payload.get("vulnerabilities", [])
        raw_runtime = payload.get("vulnerabilities_raw", surfaced_runtime)
        surfaced_meta = payload.get("meta_findings", [])
        raw_meta = payload.get("meta_findings_raw", surfaced_meta)
    else:
        surfaced_runtime = payload.get("findings", [])
        raw_runtime = payload.get("findings_raw", surfaced_runtime)
        surfaced_meta = payload.get("meta_findings", [])
        raw_meta = payload.get("meta_findings_raw", surfaced_meta)

    surfaced_items = [
        item
        for item in (
            [normalize_prediction_item(entry, source_file, "kind") for entry in surfaced_runtime]
            + [normalize_prediction_item(entry, source_file, "finding_type") for entry in surfaced_meta]
        )
        if item is not None
    ]
    raw_items = [
        item
        for item in (
            [normalize_prediction_item(entry, source_file, "kind") for entry in raw_runtime]
            + [normalize_prediction_item(entry, source_file, "finding_type") for entry in raw_meta]
        )
        if item is not None
    ]
    return {
        "surfaced_items": surfaced_items,
        "raw_items": raw_items,
        "surfaced_categories": {item["category"] for item in surfaced_items},
        "raw_categories": {item["category"] for item in raw_items},
    }


def load_truth(truth_json: Path) -> dict[str, list[dict]]:
    data = load_json(truth_json)
    if not isinstance(data, list):
        raise RuntimeError(f"unexpected SmartBugs truth payload in {truth_json}")
    out: dict[str, list[dict]] = {}
    for entry in data:
        rel = f"Benchmarks/smartbugs-curated/{str(entry['path']).replace('\\', '/')}"
        vulns = []
        for vuln in entry.get("vulnerabilities", []):
            lines = [int(line) for line in vuln.get("lines", [])]
            vulns.append(
                {
                    "category": str(vuln.get("category", "")).strip(),
                    "lines": sorted(set(lines)),
                }
            )
        out[rel] = vulns
    return out


def category_summary(records: Iterable[dict], field: str) -> dict:
    rows = list(records)
    tp = sum(len(row["tp"][field]) for row in rows)
    fp = sum(len(row["fp"][field]) for row in rows)
    fn = sum(len(row["fn"][field]) for row in rows)
    pred_count = tp + fp
    truth_count = tp + fn
    precision = tp / pred_count if pred_count else 0.0
    recall = tp / truth_count if truth_count else 0.0
    f1 = 2.0 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "contracts": len(rows),
        "contracts_with_hits": sum(1 for row in rows if row["tp"][field]),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }


def overlaps(truth_lines: Sequence[int], prediction: dict) -> bool:
    start_line = prediction.get("start_line")
    end_line = prediction.get("end_line")
    if start_line is None or end_line is None:
        return False
    if not truth_lines:
        return False
    low = min(start_line, end_line)
    high = max(start_line, end_line)
    return any(low <= line <= high for line in truth_lines)


def greedy_line_matches(truth_vulns: list[dict], predicted_items: list[dict]) -> tuple[int, list[int], list[int]]:
    unmatched_truth = list(range(len(truth_vulns)))
    unmatched_pred = list(range(len(predicted_items)))
    matched_truth: list[int] = []
    matched_pred: list[int] = []

    for truth_index in list(unmatched_truth):
        truth = truth_vulns[truth_index]
        for pred_index in list(unmatched_pred):
            pred = predicted_items[pred_index]
            if pred["category"] != truth["category"]:
                continue
            if not overlaps(truth["lines"], pred):
                continue
            matched_truth.append(truth_index)
            matched_pred.append(pred_index)
            unmatched_truth.remove(truth_index)
            unmatched_pred.remove(pred_index)
            break

    return len(matched_truth), matched_truth, matched_pred


def line_summary(records: Iterable[dict], mode: str) -> dict:
    rows = [row for row in records if row["mode"] == mode]
    tp = sum(row["line_matches"] for row in rows)
    pred_count = sum(row["located_prediction_count"] for row in rows)
    truth_count = sum(len(row["truth_vulnerabilities"]) for row in rows)
    precision = tp / pred_count if pred_count else 0.0
    recall = tp / truth_count if truth_count else 0.0
    f1 = 2.0 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "contracts": len(rows),
        "truth_issues": truth_count,
        "located_predictions": pred_count,
        "line_matches": tp,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }


def build_per_truth_rows(records: Iterable[dict]) -> list[dict]:
    rows: list[dict] = []
    for record in records:
        for index, truth in enumerate(record["truth_vulnerabilities"]):
            row = {
                "file": record["file"],
                "truth_index": index,
                "category": truth["category"],
                "lines": truth["lines"],
            }
            for field in ("surfaced", "raw"):
                row[f"{record['mode']}_{field}_family_hit"] = int(truth["category"] in record["pred"][field])
            row[f"{record['mode']}_line_hit"] = int(index in record["matched_truth_indexes"])
            rows.append(row)

    grouped: dict[tuple[str, int], dict] = {}
    for row in rows:
        key = (row["file"], row["truth_index"])
        existing = grouped.setdefault(
            key,
            {
                "file": row["file"],
                "truth_index": row["truth_index"],
                "category": row["category"],
                "lines": row["lines"],
            },
        )
        for mode in MODE_SPECS:
            for suffix in ("surfaced_family_hit", "raw_family_hit", "line_hit"):
                field = f"{mode}_{suffix}"
                if field in row:
                    existing[field] = row[field]
    return sorted(grouped.values(), key=lambda item: (item["file"], item["truth_index"]))


def write_per_truth_rows(rows: list[dict], path: Path) -> None:
    headers = [
        "file",
        "truth_index",
        "category",
        "lines",
        "static_surfaced_family_hit",
        "symbolic_surfaced_family_hit",
        "fuzzing_surfaced_family_hit",
        "hybrid_surfaced_family_hit",
        "static_raw_family_hit",
        "symbolic_raw_family_hit",
        "fuzzing_raw_family_hit",
        "hybrid_raw_family_hit",
        "static_line_hit",
        "symbolic_line_hit",
        "fuzzing_line_hit",
        "hybrid_line_hit",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(headers)
        for row in rows:
            writer.writerow([json.dumps(row.get(name)) if name == "lines" else row.get(name, 0) for name in headers])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Score SmartBugs Curated benchmark outputs against the official vulnerabilities.json reference."
    )
    parser.add_argument("summary_tsv", type=Path, help="Path to benchmark summary.tsv")
    parser.add_argument(
        "--truth-json",
        type=Path,
        default=Path("Benchmarks/smartbugs-curated/vulnerabilities.json"),
        help="Official SmartBugs vulnerability list.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory (default: <summary_dir>/smartbugs_score)",
    )
    args = parser.parse_args()

    summary_tsv = args.summary_tsv
    if not summary_tsv.is_file():
        raise SystemExit(f"summary file not found: {summary_tsv}")

    repo = repo_root()
    truth = load_truth(repo / args.truth_json)
    raw_dir = summary_tsv.parent / "raw"
    out_dir = args.out_dir or (summary_tsv.parent / "smartbugs_score")
    out_dir.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    with summary_tsv.open("r", encoding="utf-8") as f:
        reader = csv.reader(f, delimiter="\t")
        header = next(reader, None)
        if not header:
            raise RuntimeError(f"empty summary file: {summary_tsv}")
        for row in reader:
            if not row:
                continue
            file_path = row[0]
            truth_vulns = truth.get(file_path, [])
            truth_categories = {item["category"] for item in truth_vulns}
            for mode, spec in MODE_SPECS.items():
                predictions = extract_predictions(mode, file_path, raw_dir)
                line_matches, matched_truth, matched_pred = greedy_line_matches(
                    truth_vulns,
                    [item for item in predictions["surfaced_items"] if item["start_line"] is not None and item["end_line"] is not None],
                )
                timeout = int((row[spec["timeout_col"]] or "0").strip() or "0")
                pred = {
                    "surfaced": sorted(predictions["surfaced_categories"]),
                    "raw": sorted(predictions["raw_categories"]),
                }
                tp = {field: sorted(set(pred[field]) & truth_categories) for field in pred}
                fp = {field: sorted(set(pred[field]) - truth_categories) for field in pred}
                fn = {field: sorted(truth_categories - set(pred[field])) for field in pred}
                records.append(
                    {
                        "file": file_path,
                        "mode": mode,
                        "timeout": timeout,
                        "truth_categories": sorted(truth_categories),
                        "truth_vulnerabilities": truth_vulns,
                        "pred": pred,
                        "tp": tp,
                        "fp": fp,
                        "fn": fn,
                        "line_matches": line_matches,
                        "located_prediction_count": len(
                            [item for item in predictions["surfaced_items"] if item["start_line"] is not None and item["end_line"] is not None]
                        ),
                        "matched_truth_indexes": matched_truth,
                        "matched_prediction_indexes": matched_pred,
                        "surfaced_items": predictions["surfaced_items"],
                        "raw_items": predictions["raw_items"],
                    }
                )

    summary = {
        "surfaced_family": {},
        "raw_family": {},
        "line_overlap": {},
    }
    for mode in MODE_SPECS:
        mode_records = [record for record in records if record["mode"] == mode]
        summary["surfaced_family"][mode] = category_summary(mode_records, "surfaced")
        summary["raw_family"][mode] = category_summary(mode_records, "raw")
        summary["line_overlap"][mode] = line_summary(records, mode)

    per_truth_rows = build_per_truth_rows(records)

    with (out_dir / "summary.json").open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")
    with (out_dir / "per_contract.json").open("w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)
        f.write("\n")
    with (out_dir / "per_truth_vulnerability.json").open("w", encoding="utf-8") as f:
        json.dump(per_truth_rows, f, indent=2)
        f.write("\n")
    write_per_truth_rows(per_truth_rows, out_dir / "per_truth_vulnerability.tsv")

    top_fp: Dict[str, Dict[str, Counter[str]]] = defaultdict(lambda: defaultdict(Counter))
    for record in records:
        for channel in ("surfaced", "raw"):
            for category in record["fp"][channel]:
                top_fp[record["mode"]][channel][category] += 1
    for mode in MODE_SPECS:
        for channel in ("surfaced", "raw"):
            with (out_dir / f"top_fp_{channel}_{mode}.tsv").open("w", encoding="utf-8") as f:
                for category, count in sorted(top_fp[mode][channel].items(), key=lambda item: (-item[1], item[0])):
                    f.write(f"{category}\t{count}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
