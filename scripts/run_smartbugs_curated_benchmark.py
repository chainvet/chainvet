#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import shutil
import statistics
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Iterable


SUMMARY_HEADER = [
    "file",
    "static_findings",
    "static_types",
    "static_timeout",
    "symbolic_vulns",
    "symbolic_types",
    "symbolic_timeout",
    "fuzz_findings",
    "fuzz_types",
    "fuzz_timeout",
    "hybrid_findings_unique",
    "hybrid_types",
    "hybrid_se_assists",
    "hybrid_se_injected",
    "hybrid_timeout",
    "static_ms",
    "symbolic_ms",
    "fuzzing_ms",
    "hybrid_ms",
    "symbolic_meta_findings",
    "fuzz_meta_findings",
    "hybrid_runtime_findings",
    "hybrid_meta_findings",
]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def normalize_raw_stem(file_path: str) -> str:
    return file_path.replace("\\", "/").replace("/", "_").replace(" ", "_")


def counts_to_field(counts: Counter[str], sep: str) -> str:
    if not counts:
        return "-"
    return sep.join(f"{kind}={counts[kind]}" for kind in sorted(counts))


def write_text(path: Path, data: str) -> None:
    path.write_text(data, encoding="utf-8")


def write_json(path: Path, data: object) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def run_command(
    cmd: list[str],
    cwd: Path,
    timeout_s: int,
) -> tuple[subprocess.CompletedProcess[str] | None, bool, int, str, str]:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return proc, False, elapsed_ms, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as err:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        stdout = ensure_text(err.stdout)
        stderr = ensure_text(err.stderr)
        return None, True, elapsed_ms, stdout, stderr


def ensure_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def parse_json_payload(stdout: str) -> dict:
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as err:
        raise RuntimeError(f"invalid JSON output: {err}") from err


def load_truth_entries(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise RuntimeError(f"unexpected truth payload in {path}")
    return data


def load_excluded_paths(path: Path, suite: str) -> set[str]:
    excluded: set[str] = set()
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if str(row.get("suite", "")).strip() != suite:
                continue
            rel = str(row.get("path", "")).strip().replace("\\", "/")
            if rel:
                excluded.add(rel)
    return excluded


def normalize_requested_path(path: str) -> str:
    normalized = path.strip().replace("\\", "/")
    if normalized.startswith("Benchmarks/smartbugs-curated/"):
        return normalized
    if normalized.startswith("dataset/"):
        return f"Benchmarks/smartbugs-curated/{normalized}"
    return normalized


def select_contracts(
    repo: Path,
    truth_entries: list[dict],
    excluded_paths: set[str],
    requested_paths: list[str],
    include_excluded: bool,
    limit: int | None,
) -> list[dict]:
    requested = {normalize_requested_path(path) for path in requested_paths}
    selected: list[dict] = []
    for entry in sorted(truth_entries, key=lambda item: str(item.get("path", "")).replace("\\", "/")):
        rel = f"Benchmarks/smartbugs-curated/{str(entry['path']).replace('\\', '/')}"
        abs_path = repo / rel
        if not abs_path.is_file():
            raise RuntimeError(f"smartbugs target missing: {abs_path}")
        if not include_excluded and rel in excluded_paths:
            continue
        if requested and rel not in requested:
            continue
        selected.append(
            {
                "file": rel,
                "truth": entry,
            }
        )
    if requested:
        seen = {item["file"] for item in selected}
        missing = sorted(requested.difference(seen))
        if missing:
            raise RuntimeError(f"requested SmartBugs target(s) not selected: {', '.join(missing)}")
    if limit is not None:
        selected = selected[:limit]
    return selected


def summarize_static(payload: dict) -> tuple[int, Counter[str]]:
    findings = payload.get("findings_raw", payload.get("findings", []))
    counts = Counter(str(item.get("kind", "")).strip() for item in findings)
    counts.pop("", None)
    return len(findings), counts


def summarize_symbolic(payload: dict) -> tuple[int, Counter[str], int]:
    vulns = payload.get("vulnerabilities_raw", payload.get("vulnerabilities", []))
    meta_findings = payload.get("meta_findings_raw", payload.get("meta_findings", []))
    counts = Counter(str(item.get("kind", "")).strip() for item in vulns)
    counts.pop("", None)
    return len(vulns), counts, len(meta_findings)


def summarize_fuzzing(payload: dict) -> tuple[int, Counter[str], int]:
    findings = payload.get("findings_raw", payload.get("findings", []))
    meta_findings = payload.get("meta_findings_raw", payload.get("meta_findings", []))
    counts = Counter(str(item.get("kind", "")).strip() for item in findings)
    counts.pop("", None)
    return len(findings), counts, len(meta_findings)


def summarize_hybrid(payload: dict) -> tuple[int, Counter[str], int, int, int, int]:
    runtime_raw = payload.get("findings_raw", payload.get("findings", []))
    meta_raw = payload.get("meta_findings_raw", payload.get("meta_findings", []))
    counts = Counter(
        (
            str(item.get("kind", "")).strip()
            or str(item.get("finding_type", "")).strip()
        )
        for item in runtime_raw
    )
    counts.update(str(item.get("finding_type", "")).strip() for item in meta_raw)
    counts.pop("", None)
    return (
        len(payload.get("findings", [])) + len(payload.get("meta_findings", [])),
        counts,
        int(payload.get("se_assists", 0)),
        int(payload.get("seeds_injected_by_se", 0)),
        len(runtime_raw),
        len(meta_raw),
    )


def aggregate_metrics(rows: list[dict]) -> dict:
    out: dict[str, dict] = {}
    mode_configs = {
        "static": {
            "finding_key": "static_findings",
            "types_key": "static_types",
            "timeout_key": "static_timeout",
            "ms_key": "static_ms",
            "runtime_total_key": "static_findings",
            "meta_total_key": None,
        },
        "symbolic": {
            "finding_key": "symbolic_vulns",
            "types_key": "symbolic_types",
            "timeout_key": "symbolic_timeout",
            "ms_key": "symbolic_ms",
            "runtime_total_key": "symbolic_vulns",
            "meta_total_key": "symbolic_meta_findings",
        },
        "fuzzing": {
            "finding_key": "fuzz_findings",
            "types_key": "fuzz_types",
            "timeout_key": "fuzz_timeout",
            "ms_key": "fuzzing_ms",
            "runtime_total_key": "fuzz_findings",
            "meta_total_key": "fuzz_meta_findings",
        },
        "hybrid": {
            "finding_key": "hybrid_findings_unique",
            "types_key": "hybrid_types",
            "timeout_key": "hybrid_timeout",
            "ms_key": "hybrid_ms",
            "runtime_total_key": "hybrid_runtime_findings",
            "meta_total_key": "hybrid_meta_findings",
        },
    }
    for mode, cfg in mode_configs.items():
        ms_values = [int(row[cfg["ms_key"]]) for row in rows]
        type_names = set()
        contracts_with_findings = 0
        total_findings = 0
        runtime_total = 0
        meta_total = 0
        for row in rows:
            runtime_count = int(row[cfg["runtime_total_key"]])
            meta_count = int(row[cfg["meta_total_key"]]) if cfg["meta_total_key"] is not None else 0
            finding_count = int(row[cfg["finding_key"]])
            total_count = runtime_count + meta_count if cfg["meta_total_key"] is not None else finding_count
            if total_count > 0:
                contracts_with_findings += 1
            total_findings += total_count
            runtime_total += runtime_count
            meta_total += meta_count
            field = str(row[cfg["types_key"]])
            if field and field != "-":
                for part in field.split(";" if mode != "static" else ","):
                    kind = part.split("=", 1)[0].strip()
                    if kind:
                        type_names.add(kind)
        out[mode] = {
            "runs_ok": sum(1 for row in rows if int(row[cfg["timeout_key"]]) == 0),
            "timeouts": sum(int(row[cfg["timeout_key"]]) for row in rows),
            "contracts_with_findings": contracts_with_findings,
            "total_findings": total_findings,
            "unique_types": len(type_names),
            "runtime_findings": runtime_total,
            "meta_findings": meta_total,
            "total_runtime_ms": sum(ms_values),
            "median_runtime_ms": int(statistics.median(ms_values)) if ms_values else 0,
        }
    return out


def build_row_from_saved_outputs(file_path: str, raw_dir: Path, modes: set[str]) -> dict[str, str | int] | None:
    stem = normalize_raw_stem(file_path)
    row: dict[str, str | int] = {name: 0 for name in SUMMARY_HEADER}
    row["file"] = file_path

    if "static" in modes:
        static_path = raw_dir / f"{stem}.static.json"
        if not static_path.is_file():
            return None
        try:
            static_payload = parse_json_payload(static_path.read_text(encoding="utf-8", errors="replace"))
        except RuntimeError:
            return None
        static_findings, static_types = summarize_static(static_payload)
        row["static_findings"] = static_findings
        row["static_types"] = counts_to_field(static_types, ",")
        row["static_timeout"] = 0
    else:
        row["static_types"] = "-"

    if "symbolic" in modes:
        sym_path = raw_dir / f"{stem}.symbolic.json"
        if not sym_path.is_file():
            return None
        try:
            sym_payload = parse_json_payload(sym_path.read_text(encoding="utf-8", errors="replace"))
        except RuntimeError:
            return None
        sym_vulns, sym_types, sym_meta = summarize_symbolic(sym_payload)
        row["symbolic_vulns"] = sym_vulns
        row["symbolic_types"] = counts_to_field(sym_types, ";")
        row["symbolic_meta_findings"] = sym_meta
        row["symbolic_timeout"] = 0
    else:
        row["symbolic_types"] = "-"

    if "fuzzing" in modes:
        fuzz_path = raw_dir / f"{stem}.fuzzing.json"
        if not fuzz_path.is_file():
            return None
        try:
            fuzz_payload = parse_json_payload(fuzz_path.read_text(encoding="utf-8", errors="replace"))
        except RuntimeError:
            return None
        fuzz_findings, fuzz_types, fuzz_meta = summarize_fuzzing(fuzz_payload)
        row["fuzz_findings"] = fuzz_findings
        row["fuzz_types"] = counts_to_field(fuzz_types, ";")
        row["fuzz_meta_findings"] = fuzz_meta
        row["fuzz_timeout"] = 0
    else:
        row["fuzz_types"] = "-"

    if "hybrid" in modes:
        hybrid_path = raw_dir / f"{stem}.hybrid.json"
        if not hybrid_path.is_file():
            return None
        try:
            hy_payload = parse_json_payload(hybrid_path.read_text(encoding="utf-8", errors="replace"))
        except RuntimeError:
            return None
        (
            hy_unique,
            hy_types,
            hy_assists,
            hy_injected,
            hy_runtime_findings,
            hy_meta_findings,
        ) = summarize_hybrid(hy_payload)
        row["hybrid_findings_unique"] = hy_unique
        row["hybrid_types"] = counts_to_field(hy_types, ";")
        row["hybrid_se_assists"] = hy_assists
        row["hybrid_se_injected"] = hy_injected
        row["hybrid_runtime_findings"] = hy_runtime_findings
        row["hybrid_meta_findings"] = hy_meta_findings
        row["hybrid_timeout"] = 0
    else:
        row["hybrid_types"] = "-"

    return row


def write_summary(out_dir: Path, rows: list[dict[str, str | int]]) -> None:
    with (out_dir / "summary.tsv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SUMMARY_HEADER, delimiter="\t")
        writer.writeheader()
        for row in rows:
            normalized = {
                key: ("-" if value == 0 and key.endswith("_types") else value)
                for key, value in row.items()
            }
            writer.writerow(normalized)


def run_benchmark(
    repo: Path,
    selected_contracts: list[dict],
    out_dir: Path,
    timeout_static: int,
    timeout_symbolic: int,
    timeout_fuzzing: int,
    timeout_hybrid: int,
    modes: set[str],
    existing_rows: list[dict[str, str | int]] | None = None,
) -> None:
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, str | int]] = list(existing_rows or [])

    for item in selected_contracts:
        file_path = str(item["file"])
        print(f"[run] {file_path}", flush=True)
        stem = normalize_raw_stem(file_path)
        row: dict[str, str | int] = {name: 0 for name in SUMMARY_HEADER}
        row["file"] = file_path

        if "static" in modes:
            static_proc, static_timeout, static_ms, static_stdout, static_stderr = run_command(
                ["target/debug/Static", "--static", file_path, "--json"],
                repo,
                timeout_s=timeout_static,
            )
            write_text(raw_dir / f"{stem}.static.err", static_stderr)
            write_text(raw_dir / f"{stem}.static.json", static_stdout)
            row["static_timeout"] = int(static_timeout)
            row["static_ms"] = static_ms
            if not static_timeout:
                static_payload = parse_json_payload(static_stdout)
                static_findings, static_types = summarize_static(static_payload)
                row["static_findings"] = static_findings
                row["static_types"] = counts_to_field(static_types, ",")
            else:
                row["static_types"] = "-"
        else:
            row["static_types"] = "-"

        if "symbolic" in modes:
            sym_proc, sym_timeout, sym_ms, sym_stdout, sym_stderr = run_command(
                ["target/debug/Static", "--symbolic", file_path, "--json"],
                repo,
                timeout_s=timeout_symbolic,
            )
            write_text(raw_dir / f"{stem}.symbolic.err", sym_stderr)
            write_text(raw_dir / f"{stem}.symbolic.json", sym_stdout)
            row["symbolic_timeout"] = int(sym_timeout)
            row["symbolic_ms"] = sym_ms
            if not sym_timeout:
                sym_payload = parse_json_payload(sym_stdout)
                sym_vulns, sym_types, sym_meta = summarize_symbolic(sym_payload)
                row["symbolic_vulns"] = sym_vulns
                row["symbolic_types"] = counts_to_field(sym_types, ";")
                row["symbolic_meta_findings"] = sym_meta
            else:
                row["symbolic_types"] = "-"
        else:
            row["symbolic_types"] = "-"

        if "fuzzing" in modes:
            fuzz_proc, fuzz_timeout, fuzz_ms, fuzz_stdout, fuzz_stderr = run_command(
                ["target/debug/Static", "--fuzzing", file_path, "--json"],
                repo,
                timeout_s=timeout_fuzzing,
            )
            write_text(raw_dir / f"{stem}.fuzzing.err", fuzz_stderr)
            write_text(raw_dir / f"{stem}.fuzzing.json", fuzz_stdout)
            row["fuzz_timeout"] = int(fuzz_timeout)
            row["fuzzing_ms"] = fuzz_ms
            if not fuzz_timeout:
                fuzz_payload = parse_json_payload(fuzz_stdout)
                fuzz_findings, fuzz_types, fuzz_meta = summarize_fuzzing(fuzz_payload)
                row["fuzz_findings"] = fuzz_findings
                row["fuzz_types"] = counts_to_field(fuzz_types, ";")
                row["fuzz_meta_findings"] = fuzz_meta
            else:
                row["fuzz_types"] = "-"
        else:
            row["fuzz_types"] = "-"

        if "hybrid" in modes:
            hy_proc, hy_timeout, hy_ms, hy_stdout, hy_stderr = run_command(
                ["target/debug/Static", "--hybrid", file_path, "--json"],
                repo,
                timeout_s=timeout_hybrid,
            )
            write_text(raw_dir / f"{stem}.hybrid.err", hy_stderr)
            write_text(raw_dir / f"{stem}.hybrid.json", hy_stdout)
            row["hybrid_timeout"] = int(hy_timeout)
            row["hybrid_ms"] = hy_ms
            if not hy_timeout:
                hy_payload = parse_json_payload(hy_stdout)
                (
                    hy_unique,
                    hy_types,
                    hy_assists,
                    hy_injected,
                    hy_runtime_findings,
                    hy_meta_findings,
                ) = summarize_hybrid(hy_payload)
                row["hybrid_findings_unique"] = hy_unique
                row["hybrid_types"] = counts_to_field(hy_types, ";")
                row["hybrid_se_assists"] = hy_assists
                row["hybrid_se_injected"] = hy_injected
                row["hybrid_runtime_findings"] = hy_runtime_findings
                row["hybrid_meta_findings"] = hy_meta_findings
            else:
                row["hybrid_types"] = "-"
        else:
            row["hybrid_types"] = "-"

        rows.append(row)
        write_summary(out_dir, rows)

    write_summary(out_dir, rows)
    write_json(out_dir / "aggregate_metrics.json", aggregate_metrics(rows))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run SmartBugs Curated across the analyzer approaches and emit scorer-compatible artifacts."
    )
    parser.add_argument(
        "--truth-json",
        type=Path,
        default=Path("Benchmarks/smartbugs-curated/vulnerabilities.json"),
        help="Official SmartBugs vulnerability list.",
    )
    parser.add_argument(
        "--exclusions-csv",
        type=Path,
        default=Path("Benchmarks/FSE2024/exclusions.csv"),
        help="CSV of benchmark exclusions.",
    )
    parser.add_argument(
        "--label",
        default="manual_rerun",
        help="Suffix label for the output run directory.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Run only the first N selected contracts.",
    )
    parser.add_argument(
        "--contract",
        action="append",
        default=[],
        help="Restrict to one or more repo-relative or dataset-relative contract paths.",
    )
    parser.add_argument(
        "--include-excluded",
        action="store_true",
        help="Include paths normally excluded by the FSE2024 exclusion policy.",
    )
    parser.add_argument(
        "--resume-dir",
        type=Path,
        default=None,
        help="Resume an existing SmartBugs benchmark run directory instead of starting a fresh one.",
    )
    parser.add_argument(
        "--mode",
        choices=("static", "symbolic", "fuzzing", "hybrid"),
        action="append",
        default=[],
        help="Restrict to one or more approaches. Defaults to all four.",
    )
    parser.add_argument("--timeout-static", type=int, default=60)
    parser.add_argument("--timeout-symbolic", type=int, default=240)
    parser.add_argument("--timeout-fuzzing", type=int, default=180)
    parser.add_argument("--timeout-hybrid", type=int, default=300)
    args = parser.parse_args()

    repo = repo_root()
    truth_json = repo / args.truth_json
    exclusions_csv = repo / args.exclusions_csv

    truth_entries = load_truth_entries(truth_json)
    excluded_paths = load_excluded_paths(exclusions_csv, "smartbugs-curated")
    modes = set(args.mode or ["static", "symbolic", "fuzzing", "hybrid"])

    if args.resume_dir is not None:
        out_dir = repo / args.resume_dir
        if not out_dir.is_dir():
            raise SystemExit(f"resume directory not found: {out_dir}")
        run_config = json.loads((out_dir / "run_config.json").read_text(encoding="utf-8"))
        configured_modes = set(run_config.get("modes", []))
        if configured_modes:
            modes = configured_modes
        selected = [
            {
                "file": file_path,
                "truth": next(entry for entry in truth_entries if f"Benchmarks/smartbugs-curated/{str(entry['path']).replace('\\', '/')}" == file_path),
            }
            for file_path in run_config["selected_contracts"]
        ]
        raw_dir = out_dir / "raw"
        existing_rows: list[dict[str, str | int]] = []
        completed_files: set[str] = set()
        for item in selected:
            row = build_row_from_saved_outputs(str(item["file"]), raw_dir, modes)
            if row is None:
                continue
            existing_rows.append(row)
            completed_files.add(str(item["file"]))
        pending = [item for item in selected if str(item["file"]) not in completed_files]
        print(f"resume_dir={out_dir}")
        print(f"resumed_completed={len(existing_rows)}")
        print(f"resumed_pending={len(pending)}")
        selected = pending
    else:
        selected = select_contracts(
            repo,
            truth_entries,
            excluded_paths,
            args.contract,
            args.include_excluded,
            args.limit,
        )
        if not selected:
            raise SystemExit("no SmartBugs contracts selected")
        out_dir = repo / "runs" / f"benchmark_smartbugs_curated_{int(time.time())}_{args.label}"
        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        write_json(
            out_dir / "run_config.json",
            {
                "truth_json": str(args.truth_json),
                "exclusions_csv": str(args.exclusions_csv),
                "selected_contracts": [item["file"] for item in selected],
                "modes": sorted(modes),
                "timeouts": {
                    "static": args.timeout_static,
                    "symbolic": args.timeout_symbolic,
                    "fuzzing": args.timeout_fuzzing,
                    "hybrid": args.timeout_hybrid,
                },
            },
        )
        write_json(
            out_dir / "truth_reference.json",
            [
                {
                    "file": item["file"],
                    "truth": item["truth"],
                }
                for item in selected
            ],
        )
        existing_rows = []

    print(f"out_dir={out_dir}")
    run_benchmark(
        repo,
        selected,
        out_dir,
        timeout_static=args.timeout_static,
        timeout_symbolic=args.timeout_symbolic,
        timeout_fuzzing=args.timeout_fuzzing,
        timeout_hybrid=args.timeout_hybrid,
        modes=modes,
        existing_rows=existing_rows,
    )
    print(f"summary={out_dir / 'summary.tsv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
