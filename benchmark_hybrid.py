#!/usr/bin/env python3
"""Benchmark the hybrid analysis mode against SmartBugs Curated."""

from __future__ import annotations

import json
import subprocess
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).parent
BINARY = ROOT / "target" / "release" / "Static"
DATASET = ROOT / "smartbugs-curated" / "dataset"
VULN_JSON = ROOT / "smartbugs-curated" / "vulnerabilities.json"
TIMEOUT_SEC = 45

# SmartBugs category -> canonical hybrid kinds that count as a match.
CATEGORY_TO_KINDS = {
    "access_control": {
        "tx-origin",
        "unprotected-selfdestruct",
        "unprotected-ether-withdrawal",
        "arbitrary-storage-write",
        "arbitrary-write",
        "access-control",
        "unsafe-delegatecall",
        "public-mint-burn",
    },
    "arithmetic": {
        "integer-overflow",
        "integer-underflow",
        "division-before-multiplication",
        "unsafe-array-length",
    },
    "bad_randomness": {
        "weak-prng",
        "timestamp-dependency",
    },
    "denial_of_service": {
        "unchecked-call",
        "hardcoded-gas-transfer",
        "hardcoded-gas",
        "dos-block-gas-limit",
        "dos-with-failed-call",
        "unsafe-send-in-require",
        "locked-ether",
        "denial-of-service",
    },
    "front_running": {
        "transaction-order-dependency",
    },
    "reentrancy": {
        "reentrancy",
    },
    "time_manipulation": {
        "timestamp-dependency",
    },
    "unchecked_low_level_calls": {
        "unchecked-call",
    },
    "short_addresses": set(),
    "other": set(),
}

KIND_TO_CATEGORIES = defaultdict(set)
for category, kinds in CATEGORY_TO_KINDS.items():
    for kind in kinds:
        KIND_TO_CATEGORIES[kind].add(category)


def load_ground_truth():
    with open(VULN_JSON) as handle:
        entries = json.load(handle)

    issues_by_path = {}
    categories_by_path = {}
    for entry in entries:
        rel_path = entry["path"]
        vulnerabilities = entry.get("vulnerabilities", [])
        issues_by_path[rel_path] = vulnerabilities
        categories_by_path[rel_path] = {v["category"] for v in vulnerabilities}
    return issues_by_path, categories_by_path


def run_hybrid(sol_path: Path):
    start = time.time()
    try:
        result = subprocess.run(
            [str(BINARY), "--hybrid", str(sol_path), "--json"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SEC,
        )
        elapsed = time.time() - start
        if result.returncode != 0:
            return None, result.stderr.strip()[:300], elapsed
        data = json.loads(result.stdout)
        return data, None, elapsed
    except subprocess.TimeoutExpired:
        return None, "TIMEOUT", time.time() - start
    except json.JSONDecodeError as exc:
        return None, f"JSON parse error: {exc}", time.time() - start
    except Exception as exc:  # pragma: no cover - benchmark safety net
        return None, str(exc)[:300], time.time() - start


def extract_detected_kinds(report_json: dict) -> set[str]:
    findings = report_json.get("findings", [])
    detected = set()
    for finding in findings:
        provenance = finding.get("provenance")
        if provenance == "static":
            # Static-only targeting artifacts are orchestration metadata,
            # not final benchmark detections.
            continue
        kind = finding.get("kind")
        if kind:
            detected.add(kind)
    return detected


def compute_metrics(results, issues_by_path, categories_by_path):
    tp = fp = fn = 0
    issue_hits = 0
    supported_issue_total = 0
    file_hits = 0
    vulnerable_file_total = len(categories_by_path)

    for rel_path, detected_kinds in results.items():
        gt_categories = categories_by_path[rel_path]
        matched_file = False

        for vuln in issues_by_path[rel_path]:
            category = vuln["category"]
            relevant_kinds = CATEGORY_TO_KINDS.get(category, set())
            if not relevant_kinds:
                continue
            supported_issue_total += 1
            if detected_kinds & relevant_kinds:
                tp += 1
                issue_hits += 1
                matched_file = True
            else:
                fn += 1

        if matched_file:
            file_hits += 1

        for kind in detected_kinds:
            if kind not in KIND_TO_CATEGORIES:
                fp += 1
                continue
            if not (KIND_TO_CATEGORIES[kind] & gt_categories):
                fp += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    issue_coverage = issue_hits / supported_issue_total if supported_issue_total else 0.0
    file_accuracy = file_hits / vulnerable_file_total if vulnerable_file_total else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "issue_hits": issue_hits,
        "issue_total": supported_issue_total,
        "issue_coverage": issue_coverage,
        "file_hits": file_hits,
        "file_total": vulnerable_file_total,
        "file_accuracy": file_accuracy,
    }


def format_table(metrics):
    headers = [
        "Tool",
        "TP",
        "FP",
        "FN",
        "Precision",
        "Recall",
        "F1",
        "Issue Coverage",
        "File Accuracy",
    ]
    row = [
        "hybrid",
        str(metrics["tp"]),
        str(metrics["fp"]),
        str(metrics["fn"]),
        f"{metrics['precision']:.3f}",
        f"{metrics['recall']:.3f}",
        f"{metrics['f1']:.3f}",
        f"{metrics['issue_hits']}/{metrics['issue_total']} ({metrics['issue_coverage']:.3f})",
        f"{metrics['file_hits']}/{metrics['file_total']} ({metrics['file_accuracy']:.3f})",
    ]

    widths = [max(len(h), len(r)) for h, r in zip(headers, row)]
    line = "| " + " | ".join(h.ljust(w) for h, w in zip(headers, widths)) + " |"
    sep = "|-" + "-|-".join("-" * w for w in widths) + "-|"
    body = "| " + " | ".join(v.ljust(w) for v, w in zip(row, widths)) + " |"
    return "\n".join([line, sep, body])


def main():
    issues_by_path, categories_by_path = load_ground_truth()
    sol_files = sorted(DATASET.rglob("*.sol"))

    print(f"Running hybrid benchmark on {len(sol_files)} SmartBugs files...")
    total_time = 0.0
    benchmark_results = {}
    file_rows = []

    for index, sol_path in enumerate(sol_files, start=1):
        rel_dataset_path = str(sol_path.relative_to(ROOT / "smartbugs-curated"))
        report_json, error, elapsed = run_hybrid(sol_path)
        total_time += elapsed
        progress = f"[{index}/{len(sol_files)}]"

        if error:
            print(f"  {progress} ERROR: {sol_path.name} ({elapsed:.1f}s) {error}")
            benchmark_results[rel_dataset_path] = set()
            file_rows.append(
                {
                    "path": rel_dataset_path,
                    "status": "error",
                    "error": error,
                    "elapsed_sec": round(elapsed, 2),
                    "detected_kinds": [],
                    "expected_categories": sorted(categories_by_path.get(rel_dataset_path, [])),
                }
            )
            continue

        detected_kinds = extract_detected_kinds(report_json)
        benchmark_results[rel_dataset_path] = detected_kinds
        print(
            f"  {progress} OK: {sol_path.name} -> "
            f"{', '.join(sorted(detected_kinds)) if detected_kinds else 'none'} "
            f"({elapsed:.1f}s)"
        )
        file_rows.append(
            {
                "path": rel_dataset_path,
                "status": "ok",
                "elapsed_sec": round(elapsed, 2),
                "detected_kinds": sorted(detected_kinds),
                "expected_categories": sorted(categories_by_path.get(rel_dataset_path, [])),
            }
        )

    metrics = compute_metrics(benchmark_results, issues_by_path, categories_by_path)
    print("\n" + format_table(metrics))
    print(f"\nTotal files: {len(sol_files)}")
    print(f"Total runtime: {total_time:.1f}s")

    output = {
        "tool": "hybrid",
        "dataset": {
            "files_total": len(sol_files),
            "vulnerable_files_total": metrics["file_total"],
            "supported_issues_total": metrics["issue_total"],
            "timeout_sec": TIMEOUT_SEC,
        },
        "summary": metrics,
        "table": {
            "headers": [
                "Tool",
                "TP",
                "FP",
                "FN",
                "Precision",
                "Recall",
                "F1",
                "Issue Coverage",
                "File Accuracy",
            ],
            "row": [
                "hybrid",
                metrics["tp"],
                metrics["fp"],
                metrics["fn"],
                round(metrics["precision"], 3),
                round(metrics["recall"], 3),
                round(metrics["f1"], 3),
                {
                    "hits": metrics["issue_hits"],
                    "total": metrics["issue_total"],
                    "ratio": round(metrics["issue_coverage"], 3),
                },
                {
                    "hits": metrics["file_hits"],
                    "total": metrics["file_total"],
                    "ratio": round(metrics["file_accuracy"], 3),
                },
            ],
        },
        "total_runtime_sec": round(total_time, 2),
        "results": file_rows,
    }

    output_path = ROOT / "benchmark_hybrid_results.json"
    with open(output_path, "w") as handle:
        json.dump(output, handle, indent=2)
    print(f"Detailed results saved to: {output_path}")


if __name__ == "__main__":
    main()
