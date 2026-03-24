#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import time
from pathlib import Path


TOOLS = ["slither", "smartcheck", "securify2", "mythril", "manticore"]
COMPATIBILITY_EXCLUDED = {
    "Benchmarks/smartbugs-curated/dataset/access_control/parity_wallet_bug_1.sol": (
        "SmartBugs external-tool task collection requires exact solc 0.4.9 for this fixture, "
        "but the bundled solcx path cannot provide that compiler on this host."
    ),
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def normalize_raw_stem(file_path: str) -> str:
    return file_path.replace("\\", "/").replace("/", "_").replace(" ", "_")


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


def select_contracts(
    repo: Path,
    truth_entries: list[dict],
    excluded_paths: set[str],
    include_excluded: bool,
    include_compatibility_excluded: bool,
    limit: int | None,
) -> list[str]:
    selected: list[str] = []
    for entry in sorted(truth_entries, key=lambda item: str(item.get("path", "")).replace("\\", "/")):
        rel = f"Benchmarks/smartbugs-curated/{str(entry['path']).replace('\\', '/')}"
        abs_path = repo / rel
        if not abs_path.is_file():
            raise RuntimeError(f"smartbugs target missing: {abs_path}")
        if not include_excluded and rel in excluded_paths:
            continue
        if not include_compatibility_excluded and rel in COMPATIBILITY_EXCLUDED:
            continue
        selected.append(rel)
    if limit is not None:
        selected = selected[:limit]
    return selected


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def run_command(
    cmd: list[str],
    cwd: Path,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, env=env, check=check, text=True)


def run_hybrid(repo: Path, out_dir: Path, files: list[str], timeout_s: int) -> None:
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    hybrid_manifest: list[dict] = []

    for index, file_path in enumerate(files, start=1):
        print(f"[hybrid {index}/{len(files)}] {file_path}", flush=True)
        stem = normalize_raw_stem(file_path)
        stdout_path = raw_dir / f"{stem}.hybrid.json"
        stderr_path = raw_dir / f"{stem}.hybrid.err"
        if stdout_path.is_file():
            hybrid_manifest.append({"file": file_path, "status": "existing"})
            continue

        start = time.perf_counter()
        try:
            proc = subprocess.run(
                ["target/debug/Static", "--hybrid", file_path, "--json"],
                cwd=repo,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            stdout_path.write_text(proc.stdout, encoding="utf-8")
            stderr_path.write_text(proc.stderr, encoding="utf-8")
            hybrid_manifest.append(
                {
                    "file": file_path,
                    "status": "ok" if proc.returncode == 0 else "failed",
                    "returncode": proc.returncode,
                    "elapsed_ms": elapsed_ms,
                }
            )
        except subprocess.TimeoutExpired as err:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            stdout_path.write_text((err.stdout or ""), encoding="utf-8")
            stderr_path.write_text((err.stderr or ""), encoding="utf-8")
            hybrid_manifest.append(
                {
                    "file": file_path,
                    "status": "timeout",
                    "elapsed_ms": elapsed_ms,
                }
            )

        write_json(out_dir / "hybrid_manifest.json", hybrid_manifest)


def run_external_tools(
    repo: Path,
    out_dir: Path,
    files: list[str],
    smartbugs_dir: Path,
    processes: int,
    timeout_s: int,
    mem_limit: str,
    home_dir: Path,
    tools: list[str],
) -> None:
    results_template = str((out_dir / "external_results" / "${TOOL}" / "${RUNID}" / "${RELDIR}" / "${FILENAME}").resolve())
    home_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["HOME"] = str(home_dir)

    smartbugs_bin = smartbugs_dir / ".venv" / "bin" / "smartbugs"
    if not smartbugs_bin.is_file():
        raise RuntimeError(f"smartbugs executable not found: {smartbugs_bin}")

    external_manifest: list[dict] = []
    for tool in tools:
        print(f"[external] {tool}", flush=True)
        cmd = [
            str(smartbugs_bin),
            "-t",
            tool,
            "-f",
            *files,
            "--processes",
            str(processes),
            "--timeout",
            str(timeout_s),
            "--mem-limit",
            mem_limit,
            "--runid",
            tool,
            "--results",
            results_template,
            "--json",
        ]
        proc = run_command(cmd, repo, env=env, check=False)
        external_manifest.append(
            {
                "tool": tool,
                "returncode": proc.returncode,
            }
        )
        write_json(out_dir / "external_manifest.json", external_manifest)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run hybrid plus Slither, Smartcheck, Securify2, Mythril, and Manticore on SmartBugs-curated."
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
        "--smartbugs-dir",
        type=Path,
        default=Path("/tmp/smartbugs"),
        help="Local SmartBugs checkout.",
    )
    parser.add_argument(
        "--label",
        type=str,
        default="default",
        help="Run label suffix.",
    )
    parser.add_argument(
        "--resume-dir",
        type=Path,
        default=None,
        help="Reuse an existing run directory instead of creating a new timestamped one.",
    )
    parser.add_argument(
        "--skip-hybrid",
        action="store_true",
        help="Do not run hybrid; useful when rerunning only external tools in an existing comparison lane.",
    )
    parser.add_argument(
        "--skip-external",
        action="store_true",
        help="Do not run external tools; useful for hybrid-only refreshes.",
    )
    parser.add_argument(
        "--external-tools",
        nargs="+",
        choices=TOOLS,
        default=TOOLS,
        help="Subset of external tools to run.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional limit for a smoke run.",
    )
    parser.add_argument(
        "--include-excluded",
        action="store_true",
        help="Include FSE-excluded SmartBugs fixtures.",
    )
    parser.add_argument(
        "--include-compatibility-excluded",
        action="store_true",
        help="Include fixtures that are excluded only because the external-tool framework cannot resolve their legacy compiler.",
    )
    parser.add_argument(
        "--hybrid-timeout",
        type=int,
        default=300,
        help="Timeout in seconds per hybrid run.",
    )
    parser.add_argument(
        "--tool-timeout",
        type=int,
        default=300,
        help="Timeout in seconds per SmartBugs external-tool run.",
    )
    parser.add_argument(
        "--processes",
        type=int,
        default=2,
        help="Parallel SmartBugs worker processes.",
    )
    parser.add_argument(
        "--mem-limit",
        type=str,
        default="4g",
        help="Per-container SmartBugs memory limit.",
    )
    args = parser.parse_args()

    repo = repo_root()
    if args.resume_dir is not None:
        out_dir = args.resume_dir
    else:
        timestamp = int(time.time())
        out_dir = repo / "runs" / f"benchmark_smartbugs_hybrid_vs_tools_{timestamp}_{args.label}"
    out_dir.mkdir(parents=True, exist_ok=True)

    selected_manifest_path = out_dir / "selected_contracts.json"
    if selected_manifest_path.is_file():
        selected_data = json.loads(selected_manifest_path.read_text(encoding="utf-8"))
        if not isinstance(selected_data, list) or not all(isinstance(item, str) for item in selected_data):
            raise RuntimeError(f"unexpected selected contracts manifest in {selected_manifest_path}")
        selected = [str(item) for item in selected_data]
    else:
        truth_entries = load_truth_entries(repo / args.truth_json)
        excluded = load_excluded_paths(repo / args.exclusions_csv, "smartbugs-curated")
        selected = select_contracts(
            repo,
            truth_entries,
            excluded,
            include_excluded=args.include_excluded,
            include_compatibility_excluded=args.include_compatibility_excluded,
            limit=args.limit,
        )
        write_json(selected_manifest_path, selected)

    write_json(
        out_dir / "compatibility_excluded_contracts.json",
        [
            {
                "file": file_path,
                "reason": reason,
            }
            for file_path, reason in sorted(COMPATIBILITY_EXCLUDED.items())
            if not args.include_compatibility_excluded
        ],
    )
    write_json(
        out_dir / "run_config.json",
        {
            "selected_contracts": len(selected),
            "tools": ["hybrid", *args.external_tools],
            "hybrid_timeout_s": args.hybrid_timeout,
            "tool_timeout_s": args.tool_timeout,
            "processes": args.processes,
            "mem_limit": args.mem_limit,
            "skip_hybrid": args.skip_hybrid,
            "skip_external": args.skip_external,
            "external_tools": args.external_tools,
            "compatibility_excluded": sorted(
                [] if args.include_compatibility_excluded else COMPATIBILITY_EXCLUDED.keys()
            ),
        },
    )

    if not args.skip_hybrid:
        run_hybrid(repo, out_dir, selected, timeout_s=args.hybrid_timeout)
    if not args.skip_external:
        run_external_tools(
            repo,
            out_dir,
            selected,
            smartbugs_dir=args.smartbugs_dir,
            processes=args.processes,
            timeout_s=args.tool_timeout,
            mem_limit=args.mem_limit,
            home_dir=out_dir / ".smartbugs_home",
            tools=args.external_tools,
        )

    run_command(
        [
            "python3",
            "scripts/score_smartbugs_hybrid_vs_tools.py",
            "--run-dir",
            str(out_dir),
            "--smartbugs-dir",
            str(args.smartbugs_dir),
        ],
        repo,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
