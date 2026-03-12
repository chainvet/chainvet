#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple


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
}

REENTRANCY_EXPECTED = {
    "reentrancy",
    "reentrancy-eth-transfer",
    "reentrancy-negative-events",
    "reentrancy-no-eth-transfer",
    "reentrancy-same-effect",
    "reentrancy-transfer",
}


def normalize_kind(kind: str) -> str:
    kind = kind.strip()
    if not kind:
        return ""
    return KIND_ALIASES.get(kind, kind)


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
        return set(REENTRANCY_EXPECTED), core

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


def read_summary(summary_tsv: Path) -> Tuple[List[dict], Dict[str, int]]:
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
                pred = parse_types(row[spec["types_col"]], spec["sep"])
                tp = sorted(pred & expected)
                fp = sorted(pred - expected)
                fn = sorted(expected - pred)
                timeout = int((row[spec["timeout_col"]] or "0").strip() or "0")
                timeout_totals[mode] += timeout
                records.append(
                    {
                        "file": file_path,
                        "mode": mode,
                        "expected": sorted(expected),
                        "pred": sorted(pred),
                        "tp": tp,
                        "fp": fp,
                        "fn": fn,
                        "core": core,
                        "timeout": timeout,
                    }
                )
    return records, timeout_totals


def mode_summary(records: Iterable[dict], mode: str) -> dict:
    entries = [r for r in records if r["mode"] == mode]
    contracts = len(entries)
    with_findings = sum(1 for r in entries if r["pred"])
    contracts_tp = sum(1 for r in entries if r["tp"])
    contracts_fp = sum(1 for r in entries if r["fp"])
    tp = sum(len(r["tp"]) for r in entries)
    fp = sum(len(r["fp"]) for r in entries)
    fn = sum(len(r["fn"]) for r in entries)
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


def build_summary(records: List[dict], core_only: bool) -> dict:
    scoped = [r for r in records if (r["core"] if core_only else True)]
    out = {}
    for mode in MODE_SPECS.keys():
        out[mode] = mode_summary(scoped, mode)
    return out


def write_top_fp(records: List[dict], out_dir: Path, scope: str) -> None:
    for mode in MODE_SPECS.keys():
        counter = Counter()
        for r in records:
            if r["mode"] != mode:
                continue
            for k in r["fp"]:
                counter[k] += 1
        out_path = out_dir / f"top_fp_{scope}_{mode}.tsv"
        with out_path.open("w", encoding="utf-8") as f:
            for kind, count in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])):
                f.write(f"{kind}\t{count}\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Score Not-so-smart benchmark summary.tsv into FP/TP/FN artifacts."
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

    records, _ = read_summary(summary_tsv)
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

    write_top_fp(records, out_dir, "all")
    write_top_fp([r for r in records if r["core"]], out_dir, "core")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
