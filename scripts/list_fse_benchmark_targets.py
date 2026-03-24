#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Suite:
    name: str
    root: Path
    kind: str


@dataclass(frozen=True)
class Exclusion:
    suite: str
    pattern: str
    reason: str


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_scope(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_manifest(path: Path) -> tuple[list[Suite], Path]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    suites = [
        Suite(
            name=str(item["suite"]).strip(),
            root=repo_root() / str(item["root"]).strip(),
            kind=str(item.get("kind", "source")).strip(),
        )
        for item in raw.get("source_suites", [])
        if item.get("enabled", True)
    ]
    exclusions_csv = repo_root() / str(raw["exclusions_csv"]).strip()
    return suites, exclusions_csv


def load_exclusions(path: Path) -> list[Exclusion]:
    exclusions: list[Exclusion] = []
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            exclusions.append(
                Exclusion(
                    suite=str(row["suite"]).strip(),
                    pattern=str(row["path"]).strip(),
                    reason=str(row["reason"]).strip(),
                )
            )
    return exclusions


def iter_suite_targets(suite: Suite) -> Iterable[Path]:
    yield from sorted(path for path in suite.root.rglob("*.sol") if path.is_file())


def build_excluded_paths(exclusions: list[Exclusion], selected_suites: set[str]) -> set[Path]:
    root = repo_root()
    excluded: set[Path] = set()
    for exclusion in exclusions:
        if exclusion.suite not in selected_suites:
            continue
        for path in root.glob(exclusion.pattern):
            if path.is_file():
                excluded.add(path.resolve())
    return excluded


def relative(path: Path) -> str:
    return path.resolve().relative_to(repo_root()).as_posix()


def main() -> int:
    parser = argparse.ArgumentParser(description="List the active FSE 2024 benchmark Solidity targets with exclusions applied.")
    parser.add_argument(
        "--scope",
        type=Path,
        default=Path("Benchmarks/benchmark_scope.json"),
        help="Path to the benchmark scope config.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        help="Path to the FSE benchmark manifest. Overrides --preset when provided.",
    )
    parser.add_argument(
        "--preset",
        choices=("active", "all-approaches"),
        default="active",
        help="Benchmark preset. 'all-approaches' defaults to Not-so-smart plus smartbugs-curated only.",
    )
    parser.add_argument(
        "--suite",
        action="append",
        default=[],
        help="Restrict to one or more suite ids from the manifest.",
    )
    parser.add_argument(
        "--format",
        choices=("summary", "paths", "json"),
        default="summary",
        help="Output format.",
    )
    args = parser.parse_args()

    scope_path = repo_root() / args.scope
    scope = load_scope(scope_path)
    if args.manifest is not None:
        manifest_path = repo_root() / args.manifest
    elif args.preset == "all-approaches":
        manifest_path = repo_root() / str(scope["comparison_defaults"]["all_approaches_manifest"]).strip()
    else:
        manifest_path = repo_root() / str(scope["active_manifest"]).strip()
    suites, exclusions_csv = load_manifest(manifest_path)
    requested = {item.strip() for item in args.suite if item.strip()}
    if requested:
        suites = [suite for suite in suites if suite.name in requested]
        missing = sorted(requested.difference({suite.name for suite in suites}))
        if missing:
            raise SystemExit(f"unknown suite(s): {', '.join(missing)}")

    exclusions = load_exclusions(exclusions_csv)
    excluded_paths = build_excluded_paths(exclusions, {suite.name for suite in suites})

    per_suite: list[dict[str, object]] = []
    included_paths: list[str] = []

    for suite in suites:
        all_targets = list(iter_suite_targets(suite))
        suite_excluded = [path for path in all_targets if path.resolve() in excluded_paths]
        suite_included = [path for path in all_targets if path.resolve() not in excluded_paths]
        included_paths.extend(relative(path) for path in suite_included)
        per_suite.append(
            {
                "suite": suite.name,
                "kind": suite.kind,
                "root": relative(suite.root),
                "total_targets": len(all_targets),
                "excluded_targets": len(suite_excluded),
                "included_targets": len(suite_included),
            }
        )

    included_paths.sort()
    payload = {
        "scope": "fse2024",
        "preset": args.preset,
        "manifest": relative(manifest_path),
        "total_included_targets": len(included_paths),
        "suites": per_suite,
        "targets": included_paths,
    }

    if args.format == "paths":
        print("\n".join(included_paths))
        return 0
    if args.format == "json":
        print(json.dumps(payload, indent=2))
        return 0

    print(f"scope: {payload['scope']}")
    print(f"preset: {payload['preset']}")
    print(f"manifest: {payload['manifest']}")
    print(f"total_included_targets: {payload['total_included_targets']}")
    for suite in per_suite:
        print(
            f"{suite['suite']}: "
            f"included={suite['included_targets']} "
            f"excluded={suite['excluded_targets']} "
            f"total={suite['total_targets']} "
            f"root={suite['root']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
