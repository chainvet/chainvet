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


def normalize_raw_stem(file_path: str) -> str:
    return file_path.replace("\\", "/").replace("/", "_").replace(" ", "_")


def counts_to_field(counts: Counter[str], sep: str) -> str:
    if not counts:
        return "-"
    return sep.join(f"{kind}={counts[kind]}" for kind in sorted(counts))


def read_contracts(summary_tsv: Path) -> list[str]:
    contracts: list[str] = []
    with summary_tsv.open("r", encoding="utf-8") as f:
        reader = csv.reader(f, delimiter="\t")
        next(reader, None)
        for row in reader:
            if row:
                contracts.append(row[0])
    return contracts


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
        stdout = err.stdout or ""
        stderr = err.stderr or ""
        return None, True, elapsed_ms, stdout, stderr


def parse_json_payload(stdout: str) -> dict:
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as err:
        raise RuntimeError(f"invalid JSON output: {err}") from err


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


def summarize_fuzzing(text: str) -> tuple[int, Counter[str], int]:
    runtime_findings = 0
    meta_findings = 0
    category_counts: Counter[str] = Counter()
    saw_runtime_types_raw = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("runtime_findings:"):
            runtime_findings = int(line.split(":", 1)[1].strip())
        elif line.startswith("runtime_findings_raw:"):
            runtime_findings = int(line.split(":", 1)[1].strip())
        elif line.startswith("runtime_types_raw:"):
            saw_runtime_types_raw = True
            field = line.split(":", 1)[1].strip()
            category_counts = Counter()
            if field and field != "-":
                for part in field.split(";"):
                    part = part.strip()
                    if not part:
                        continue
                    raw_kind, raw_count = (part.split("=", 1) + ["1"])[:2]
                    try:
                        count = int(raw_count.strip())
                    except ValueError:
                        count = 1
                    kind = raw_kind.strip()
                    if kind:
                        category_counts[kind] += count
        elif line.startswith("meta_findings:"):
            meta_findings = int(line.split(":", 1)[1].strip())
        elif line.startswith("meta_findings_raw:"):
            meta_findings = int(line.split(":", 1)[1].strip())
        elif line.startswith("[") and "finding(s):" in line:
            if saw_runtime_types_raw:
                continue
            category = line.split("]", 1)[0].strip("[")
            if category == "Meta":
                continue
            count_str = line.rsplit(" ", 2)[-2]
            try:
                category_counts[category] = int(count_str)
            except ValueError:
                continue
    return runtime_findings, category_counts, meta_findings


def summarize_hybrid_summary(payload: dict, findings: list[dict]) -> tuple[int, Counter[str], int, int, int, int]:
    all_counts = Counter(str(item.get("finding_type", "")).strip() for item in findings)
    all_counts.pop("", None)
    runtime_count = 0
    meta_count = 0
    for item in findings:
        if str(item.get("analysis_layer", "runtime")).strip().lower() == "meta":
            meta_count += 1
        else:
            runtime_count += 1
    return (
        int(payload.get("findings_unique", len(findings))),
        all_counts,
        int(payload.get("se_assists", 0)),
        int(payload.get("seeds_injected_by_se", 0)),
        runtime_count,
        meta_count,
    )


def load_hybrid_findings(run_id: str, repo_root: Path) -> list[dict]:
    findings_path = repo_root / "runs" / run_id / "findings.json"
    with findings_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise RuntimeError(f"unexpected hybrid findings payload at {findings_path}")
    return data


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
            runtime_total += int(row[cfg["runtime_total_key"]])
            meta_total += meta_count
            field = row[cfg["types_key"]]
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


def run_benchmark(repo_root: Path, contracts: Iterable[str], out_dir: Path) -> None:
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, str | int]] = []

    for file_path in contracts:
        print(f"[run] {file_path}", flush=True)
        stem = normalize_raw_stem(file_path)
        row: dict[str, str | int] = {name: 0 for name in SUMMARY_HEADER}
        row["file"] = file_path

        static_proc, static_timeout, static_ms, static_stdout, static_stderr = run_command(
            ["target/debug/Static", "--static", file_path, "--json"],
            repo_root,
            timeout_s=60,
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

        sym_proc, sym_timeout, sym_ms, sym_stdout, sym_stderr = run_command(
            ["target/debug/Static", "--symbolic", file_path, "--json"],
            repo_root,
            timeout_s=240,
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

        fuzz_proc, fuzz_timeout, fuzz_ms, fuzz_stdout, fuzz_stderr = run_command(
            ["target/debug/Static", "--fuzzing", file_path],
            repo_root,
            timeout_s=180,
        )
        write_text(raw_dir / f"{stem}.fuzzing.err", fuzz_stderr)
        write_text(raw_dir / f"{stem}.fuzzing.out", fuzz_stdout)
        row["fuzz_timeout"] = int(fuzz_timeout)
        row["fuzzing_ms"] = fuzz_ms
        if not fuzz_timeout:
            fuzz_findings, fuzz_types, fuzz_meta = summarize_fuzzing(fuzz_stdout)
            row["fuzz_findings"] = fuzz_findings
            row["fuzz_types"] = counts_to_field(fuzz_types, ";")
            row["fuzz_meta_findings"] = fuzz_meta
        else:
            row["fuzz_types"] = "-"

        hy_proc, hy_timeout, hy_ms, hy_stdout, hy_stderr = run_command(
            ["target/debug/Static", "--hybrid", file_path, "--json"],
            repo_root,
            timeout_s=300,
        )
        write_text(raw_dir / f"{stem}.hybrid.err", hy_stderr)
        write_text(raw_dir / f"{stem}.hybrid.summary.json", hy_stdout)
        row["hybrid_timeout"] = int(hy_timeout)
        row["hybrid_ms"] = hy_ms
        if not hy_timeout:
            hy_payload = parse_json_payload(hy_stdout)
            run_id = str(hy_payload.get("run_id", "")).strip()
            if not run_id:
                raise RuntimeError(f"hybrid run did not return run_id for {file_path}")
            findings = load_hybrid_findings(run_id, repo_root)
            write_json(raw_dir / f"{stem}.hybrid.findings.json", findings)
            (
                hy_unique,
                hy_types,
                hy_assists,
                hy_injected,
                hy_runtime_findings,
                hy_meta_findings,
            ) = summarize_hybrid_summary(hy_payload, findings)
            row["hybrid_findings_unique"] = hy_unique
            row["hybrid_types"] = counts_to_field(hy_types, ";")
            row["hybrid_se_assists"] = hy_assists
            row["hybrid_se_injected"] = hy_injected
            row["hybrid_runtime_findings"] = hy_runtime_findings
            row["hybrid_meta_findings"] = hy_meta_findings
        else:
            row["hybrid_types"] = "-"

        rows.append(row)

    with (out_dir / "summary.tsv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SUMMARY_HEADER, delimiter="\t")
        writer.writeheader()
        for row in rows:
            normalized = {
                key: ("-" if value == 0 and key.endswith("_types") else value)
                for key, value in row.items()
            }
            writer.writerow(normalized)

    write_json(out_dir / "aggregate_metrics.json", aggregate_metrics(rows))


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the full Not-so-smart benchmark and emit scorer-compatible artifacts.")
    parser.add_argument(
        "--contracts-from",
        type=Path,
        default=Path("runs/benchmark_not_so_smart_1773848521_post_step29/summary.tsv"),
        help="Existing summary.tsv used only as the canonical 25-contract file list.",
    )
    parser.add_argument(
        "--label",
        default="manual_rerun",
        help="Suffix label for the output run directory.",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    contracts = read_contracts(args.contracts_from)
    if not contracts:
        raise SystemExit(f"no contracts found in {args.contracts_from}")

    out_dir = repo_root / "runs" / f"benchmark_not_so_smart_{int(time.time())}_{args.label}"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"out_dir={out_dir}")
    run_benchmark(repo_root, contracts, out_dir)
    print(f"summary={out_dir / 'summary.tsv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
