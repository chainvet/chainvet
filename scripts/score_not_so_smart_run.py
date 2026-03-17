#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Set, Tuple


MODE_SPECS = {
    "static": {"types_col": 2, "timeout_col": 3, "sep": ","},
    "symbolic": {"types_col": 5, "timeout_col": 6, "sep": ";"},
    "fuzzing": {"types_col": 8, "timeout_col": 9, "sep": ";"},
    "hybrid": {"types_col": 11, "timeout_col": 14, "sep": ";"},
}

KIND_ALIASES = {
    "underflow": "integer-underflow",
    "hardcoded-gas": "hardcoded-gas-transfer",
    "storage-memory-issue": "memory-manipulation",
    "unused-return-value": "unchecked-call",
    "dangerous-block-timestamp": "timestamp-dependency",
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


def parse_types(field: str, sep: str) -> Set[str]:
    field = (field or "").strip()
    if not field or field == "-":
        return set()
    out: Set[str] = set()
    for part in field.split(sep):
        part = part.strip()
        if not part or part == "-":
            continue
        kind = normalize_kind(part.split("=", 1)[0].strip())
        if kind:
            out.add(kind)
    return out


def expected_for_file(file_path: str) -> Tuple[Set[str], bool]:
    p = file_path.replace("\\", "/")
    core = True

    if "/bad_randomness/" in p:
        return {"timestamp-dependency", "weak-prng"}, core
    if "/denial_of_service/" in p:
        return {"dos-block-gas-limit", "dos-with-failed-call"}, core
    if "/forced_ether_reception/" in p:
        return {"locked-ether"}, core
    if "/incorrect_interface/" in p:
        return {"incorrect-interface"}, core
    if "/integer_overflow/" in p:
        return {"integer-overflow", "integer-underflow"}, core
    if "/race_condition/" in p:
        return {"transaction-order-dependency"}, core
    if "/unchecked_external_call/" in p:
        return {"exception-disorder", "unchecked-call", "unused-return-value"}, core
    if "/unprotected_function/" in p:
        return {
            "access-control",
            "unprotected-ether-withdrawal",
            "unprotected-selfdestruct",
            "unsafe-delegatecall",
        }, core
    if "/variable shadowing/" in p:
        return {"shadowing"}, core
    if "/wrong_constructor_name/" in p:
        return {"access-control", "uninit-permission-check", "wrong-constructor-name"}, core

    if "/reentrancy/" in p:
        if p.endswith("/ReentrancyExploit.sol"):
            core = False
        return {"reentrancy"}, core

    if "/honeypots/" in p:
        core = False
        if "/GiftBox/" in p:
            return {"honeypot"}, core
        if "/KOTH/" in p:
            return {"honeypot", "shadowing"}, core
        if "/Lottery/" in p:
            return {"honeypot", "memory-manipulation"}, core
        if "/Multiplicator/" in p:
            return {"honeypot", "locked-ether"}, core
        if "/PrivateBank/" in p:
            return {"honeypot", "dos-with-failed-call", "reentrancy"}, core
        if "/VarLoop/" in p:
            return {"honeypot", "integer-overflow", "integer-underflow"}, core
        return {"honeypot"}, core

    return set(), core


def normalize_raw_stem(file_path: str) -> str:
    return (
        file_path.replace("\\", "/")
        .replace("/", "_")
        .replace(" ", "_")
    )


def load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def kinds_from_static_json(path: Path) -> Set[str]:
    data = load_json(path)
    if not data:
        return set()
    out = set()
    for finding in data.get("findings", []):
        kind = normalize_kind(str(finding.get("kind", "")))
        if kind:
            out.add(kind)
    return out


def kinds_from_symbolic_json(path: Path) -> Tuple[Set[str], Set[str]]:
    data = load_json(path)
    if not data:
        return set(), set()
    runtime = {
        normalize_kind(str(item.get("kind", "")))
        for item in data.get("vulnerabilities", [])
    }
    runtime.discard("")
    meta = {
        normalize_kind(str(item.get("finding_type", "")))
        for item in data.get("meta_findings", [])
    }
    meta.discard("")
    return runtime, meta


def kinds_from_hybrid_findings(path: Path) -> Tuple[Set[str], Set[str]]:
    data = load_json(path)
    if not isinstance(data, list):
        return set(), set()
    runtime: Set[str] = set()
    meta: Set[str] = set()
    for item in data:
        kind = normalize_kind(str(item.get("finding_type", "")))
        if not kind:
            continue
        layer = str(item.get("analysis_layer", "runtime")).strip().lower()
        if layer == "meta":
            meta.add(kind)
        else:
            runtime.add(kind)
    return runtime, meta


def kinds_from_fuzzing_out(path: Path) -> Tuple[Set[str], Set[str]]:
    if not path.is_file():
        return set(), set()
    runtime: Set[str] = set()
    meta: Set[str] = set()
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
                    meta.add(kind)
            continue

        m = FUZZ_RUNTIME_LINE_RE.search(line)
        if m:
            kind = normalize_kind(m.group(1))
            if kind:
                runtime.add(kind)

    return runtime, meta


def prioritize_predictions(pred: Set[str], expected: Set[str]) -> Set[str]:
    if not pred:
        return set()
    direct = pred & expected
    if direct:
        return direct
    filtered = {k for k in pred if k not in NOISE_KINDS}
    return filtered if filtered else pred


def extract_mode_kinds(
    mode: str,
    row: List[str],
    file_path: str,
    raw_dir: Path,
) -> Tuple[Set[str], Set[str], Set[str], Set[str], Set[str]]:
    spec = MODE_SPECS[mode]
    summary_surfaced = parse_types(row[spec["types_col"]], spec["sep"])

    runtime: Set[str]
    meta: Set[str]

    stem = normalize_raw_stem(file_path)
    if mode == "static":
        runtime = kinds_from_static_json(raw_dir / f"{stem}.static.json")
        meta = set()
    elif mode == "symbolic":
        runtime, meta = kinds_from_symbolic_json(raw_dir / f"{stem}.symbolic.json")
    elif mode == "fuzzing":
        runtime, meta = kinds_from_fuzzing_out(raw_dir / f"{stem}.fuzzing.out")
    else:
        runtime, meta = kinds_from_hybrid_findings(raw_dir / f"{stem}.hybrid.findings.json")

    if not runtime and not meta:
        runtime = set(summary_surfaced)

    surfaced = set(runtime) | set(meta)
    return runtime, meta, surfaced, summary_surfaced, set(summary_surfaced)


def mode_summary(records: Iterable[dict], mode: str, pred_key: str) -> dict:
    entries = [r for r in records if r["mode"] == mode]
    contracts = len(entries)
    with_findings = sum(1 for r in entries if r["pred"][pred_key])
    contracts_tp = sum(1 for r in entries if r["tp"][pred_key])
    contracts_fp = sum(1 for r in entries if r["fp"][pred_key])
    tp = sum(len(r["tp"][pred_key]) for r in entries)
    fp = sum(len(r["fp"][pred_key]) for r in entries)
    fn = sum(len(r["fn"][pred_key]) for r in entries)
    pred_count = tp + fp
    truth_count = tp + fn
    precision = (tp / pred_count) if pred_count else 0.0
    recall = (tp / truth_count) if truth_count else 0.0
    f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    timeouts = sum(r.get("timeout", 0) for r in entries)
    return {
        "contracts": contracts,
        "with_findings": with_findings,
        "contracts_tp": contracts_tp,
        "contracts_fp": contracts_fp,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "timeouts": timeouts,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }


def write_top_fp(records: List[dict], out_dir: Path, scope: str, pred_key: str) -> None:
    for mode in MODE_SPECS.keys():
        counter = Counter()
        for r in records:
            if r["mode"] != mode:
                continue
            for k in r["fp"][pred_key]:
                counter[k] += 1
        out_path = out_dir / f"top_fp_{scope}_{pred_key}_{mode}.tsv"
        with out_path.open("w", encoding="utf-8") as f:
            for kind, count in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])):
                f.write(f"{kind}\t{count}\n")


def build_issue_matrix(records: List[dict]) -> List[dict]:
    rows: Dict[Tuple[str, str], dict] = {}
    for record in records:
        file_path = record["file"]
        expected = sorted(record["expected"])
        for expected_kind in expected:
            key = (file_path, expected_kind)
            row = rows.setdefault(
                key,
                {
                    "file": file_path,
                    "expected_kind": expected_kind,
                    "core": int(record["core"]),
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
            mode = record["mode"]
            if expected_kind in record["pred"]["runtime_primary"]:
                row[f"{mode}_runtime_hit"] = 1
            if expected_kind in record["pred"]["surfaced_output"]:
                row[f"{mode}_surfaced_hit"] = 1
    return sorted(rows.values(), key=lambda r: (r["file"], r["expected_kind"]))


def write_issue_matrix(rows: List[dict], path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(
            [
                "file",
                "expected_kind",
                "core",
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
        for row in rows:
            writer.writerow(
                [
                    row["file"],
                    row["expected_kind"],
                    row["core"],
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


def build_summary(records: List[dict], core_only: bool) -> dict:
    scoped = [r for r in records if (r["core"] if core_only else True)]
    out = {
        "runtime_primary": {},
        "meta_secondary": {},
        "surfaced_output": {},
    }
    for mode in MODE_SPECS.keys():
        out["runtime_primary"][mode] = mode_summary(scoped, mode, "runtime_primary")
        out["meta_secondary"][mode] = mode_summary(scoped, mode, "meta_secondary")
        out["surfaced_output"][mode] = mode_summary(scoped, mode, "surfaced_output")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Score Not-so-smart benchmark summary.tsv with runtime/meta split and issue matrix artifacts."
    )
    parser.add_argument("summary_tsv", type=Path, help="Path to benchmark summary.tsv")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory (default: <summary_dir>/fp_analysis)",
    )
    args = parser.parse_args()

    summary_tsv: Path = args.summary_tsv
    if not summary_tsv.is_file():
        raise SystemExit(f"summary file not found: {summary_tsv}")

    out_dir = args.out_dir or (summary_tsv.parent / "fp_analysis")
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = summary_tsv.parent / "raw"

    records: List[dict] = []
    timeout_totals: Dict[str, int] = defaultdict(int)

    with summary_tsv.open("r", encoding="utf-8") as f:
        reader = csv.reader(f, delimiter="\t")
        header = next(reader, None)
        if not header:
            raise ValueError(f"Empty summary file: {summary_tsv}")
        for row in reader:
            if not row:
                continue
            file_path = row[0]
            expected, core = expected_for_file(file_path)
            for mode, spec in MODE_SPECS.items():
                runtime_raw, meta_raw, surfaced_raw, summary_surfaced, _ = extract_mode_kinds(
                    mode, row, file_path, raw_dir
                )
                runtime_primary = prioritize_predictions(runtime_raw, expected)
                surfaced_output = prioritize_predictions(surfaced_raw, expected)
                meta_secondary = set(meta_raw)

                timeout = int((row[spec["timeout_col"]] or "0").strip() or "0")
                timeout_totals[mode] += timeout

                preds = {
                    "runtime_primary": sorted(runtime_primary),
                    "meta_secondary": sorted(meta_secondary),
                    "surfaced_output": sorted(surfaced_output),
                    "runtime_raw": sorted(runtime_raw),
                    "meta_raw": sorted(meta_raw),
                    "surfaced_raw": sorted(surfaced_raw),
                    "summary_surfaced": sorted(summary_surfaced),
                }
                tp = {
                    channel: sorted(set(preds[channel]) & expected)
                    for channel in ("runtime_primary", "meta_secondary", "surfaced_output")
                }
                fp = {
                    channel: sorted(set(preds[channel]) - expected)
                    for channel in ("runtime_primary", "meta_secondary", "surfaced_output")
                }
                fn = {
                    channel: sorted(expected - set(preds[channel]))
                    for channel in ("runtime_primary", "meta_secondary", "surfaced_output")
                }

                records.append(
                    {
                        "file": file_path,
                        "mode": mode,
                        "expected": sorted(expected),
                        "core": core,
                        "timeout": timeout,
                        "pred": preds,
                        "tp": tp,
                        "fp": fp,
                        "fn": fn,
                    }
                )

    summary_all = build_summary(records, core_only=False)
    summary_core = build_summary(records, core_only=True)

    with (out_dir / "per_contract.json").open("w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)
        f.write("\n")
    with (out_dir / "summary_all.json").open("w", encoding="utf-8") as f:
        json.dump(summary_all, f, indent=2)
        f.write("\n")
    with (out_dir / "summary_core.json").open("w", encoding="utf-8") as f:
        json.dump(summary_core, f, indent=2)
        f.write("\n")

    issue_rows = build_issue_matrix(records)
    write_issue_matrix(issue_rows, out_dir / "per_issue_matrix.tsv")

    for scope_name, scoped_records in (
        ("all", records),
        ("core", [r for r in records if r["core"]]),
    ):
        write_top_fp(scoped_records, out_dir, scope_name, "runtime_primary")
        write_top_fp(scoped_records, out_dir, scope_name, "surfaced_output")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
