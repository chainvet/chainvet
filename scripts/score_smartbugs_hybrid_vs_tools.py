#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Sequence


TOOL_ORDER = ["hybrid", "slither", "smartcheck", "securify2", "mythril", "manticore"]

TOOL_MIN_SOLIDITY = {
    "securify2": (0, 5, 8),
}

SMARTBUGS_TOOL_IDS = {
    "slither": "slither-0.11.3",
    "smartcheck": "smartcheck",
    "securify2": "securify2",
    "mythril": "mythril-0.24.8",
    "manticore": "manticore-0.3.7",
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

CLASSIFICATION_TO_CATEGORY = {
    "SWC-101": "arithmetic",
    "SWC-104": "unchecked_low_level_calls",
    "SWC-105": "access_control",
    "SWC-106": "access_control",
    "SWC-107": "reentrancy",
    "SWC-109": "other",
    "SWC-112": "access_control",
    "SWC-113": "denial_of_service",
    "SWC-114": "front_running",
    "SWC-115": "access_control",
    "SWC-116": "time_manipulation",
    "SWC-118": "access_control",
    "SWC-120": "bad_randomness",
    "SWC-124": "access_control",
    "DASP-1": "reentrancy",
    "DASP-4": "unchecked_low_level_calls",
    "DASP-7": "front_running",
    "DASP-8": "time_manipulation",
}

GLOBAL_NAME_HINTS = [
    ("reentrancy", "reentrancy"),
    ("delegatecall", "access_control"),
    ("selfdestruct", "access_control"),
    ("tx_origin", "access_control"),
    ("tx_origin", "access_control"),
    ("ether_withdrawal", "access_control"),
    ("arbitrary_storage", "access_control"),
    ("order_depend", "front_running"),
    ("tod", "front_running"),
    ("unchecked", "unchecked_low_level_calls"),
    ("unused_return", "unchecked_low_level_calls"),
    ("unhandled_exception", "unchecked_low_level_calls"),
    ("random", "bad_randomness"),
    ("prng", "bad_randomness"),
    ("blockhash", "bad_randomness"),
    ("timestamp", "time_manipulation"),
    ("exact_time", "time_manipulation"),
    ("overflow", "arithmetic"),
    ("underflow", "arithmetic"),
    ("gas_limit", "denial_of_service"),
    ("transfer_in_loop", "denial_of_service"),
]

NAME_OVERRIDES = {
    "slither": {
        "arbitrary_send": "access_control",
        "arbitrary_send_eth": "access_control",
        "arbitrary_send_erc20": "access_control",
        "arbitrary_send_erc20_permit": "access_control",
        "backdoor": "access_control",
        "controlled_delegatecall": "access_control",
        "multiple_constructors": "access_control",
        "name_reused": "access_control",
        "protected_vars": "access_control",
        "reused_constructor": "access_control",
        "suicidal": "access_control",
        "tx_origin": "access_control",
        "unprotected_upgrade": "access_control",
        "calls_loop": "denial_of_service",
        "delegatecall_loop": "denial_of_service",
        "msg_value_loop": "denial_of_service",
        "reentrancy_benign": "reentrancy",
        "reentrancy_eth": "reentrancy",
        "reentrancy_events": "reentrancy",
        "reentrancy_no_eth": "reentrancy",
        "reentrancy_unlimited_gas": "reentrancy",
        "token_reentrancy": "reentrancy",
        "unchecked_lowlevel": "unchecked_low_level_calls",
        "unchecked_send": "unchecked_low_level_calls",
        "unchecked_transfer": "unchecked_low_level_calls",
        "low_level_calls": "unchecked_low_level_calls",
        "unused_return": "unchecked_low_level_calls",
        "weak_prng": "bad_randomness",
        "gelato_unprotected_randomness": "bad_randomness",
        "timestamp": "time_manipulation",
        "uninitialized_local": "other",
        "uninitialized_state": "other",
        "uninitialized_storage": "other",
        "assembly": "other",
        "constable_states": "other",
        "constant_function_asm": "other",
        "constant_function_state": "other",
        "deprecated_standards": "other",
        "erc20_indexed": "other",
        "erc20_interface": "other",
        "external_function": "other",
        "incorrect_equality": "other",
        "locked_ether": "other",
        "naming_convention": "other",
        "shadowing_abstract": "other",
        "shadowing_builtin": "other",
        "shadowing_local": "other",
        "shadowing_state": "other",
        "solc_version": "other",
        "unused_state": "other",
    },
    "smartcheck": {
        "solidity_array_length_manipulation": "arithmetic",
        "solidity_div_mul": "arithmetic",
        "solidity_uint_cant_be_negative": "arithmetic",
        "solidity_var": "arithmetic",
        "solidity_var_in_loop_for": "arithmetic",
        "solidity_call_without_data": "reentrancy",
        "solidity_gas_limit_in_loops": "denial_of_service",
        "solidity_transfer_in_loop": "denial_of_service",
        "solidity_dos_with_throw": "denial_of_service",
        "solidity_send": "unchecked_low_level_calls",
        "solidity_unchecked_call": "unchecked_low_level_calls",
        "solidity_tx_origin": "access_control",
        "solidity_overpowered_role": "access_control",
        "solidity_exact_time": "time_manipulation",
        "solidity_incorrect_blockhash": "bad_randomness",
        "solidity_balance_equality": "other",
        "solidity_functions_returns_type_and_no_return": "other",
        "solidity_locked_money": "other",
        "solidity_address_hardcoded": "other",
        "solidity_byte_array_instead_bytes": "other",
        "solidity_deprecated_constructions": "other",
        "solidity_erc20_approve": "other",
        "solidity_erc20_functions_always_return_false": "other",
        "solidity_erc20_transfer_should_throw": "other",
        "solidity_extra_gas_in_loops": "other",
        "solidity_msgvalue_equals_zero": "other",
        "solidity_pragmas_version": "other",
        "solidity_private_modifier_dont_hide_data": "other",
        "solidity_private_modifier_does_not_hide_data": "other",
        "solidity_redundant_fallback_reject": "other",
        "solidity_revert_require": "other",
        "solidity_safemath": "other",
        "solidity_should_not_be_pure": "other",
        "solidity_should_not_be_view": "other",
        "solidity_should_return_struct": "other",
        "solidity_upgrade_to_050": "other",
        "solidity_using_inline_assembly": "other",
        "solidity_visibility": "other",
        "solidity_wrong_signature": "other",
    },
    "mythril": {
        "call_data_forwarded_with_delegatecall_swc_112": "access_control",
        "delegatecall_to_user_supplied_address_swc_112": "access_control",
        "dependence_on_tx_origin_swc_115": "access_control",
        "unprotected_ether_withdrawal_swc_105": "access_control",
        "unprotected_selfdestruct_swc_106": "access_control",
        "write_to_an_arbitrary_storage_location_swc_124": "access_control",
        "integer_arithmetic_bugs_swc_101": "arithmetic",
        "external_call_to_user_supplied_address_swc_107": "reentrancy",
        "state_access_after_external_call_swc_107": "reentrancy",
        "transaction_order_dependence_swc_114": "front_running",
        "unchecked_return_value_from_external_call_swc_104": "unchecked_low_level_calls",
        "dependence_on_predictable_environment_variable_swc_120": "bad_randomness",
        "dependence_on_predictable_environment_variable_swc_116": "time_manipulation",
        "exception_state_swc_110": "other",
        "multiple_calls_in_a_single_transaction_swc_113": "other",
        "requirement_violation_swc_123": "other",
        "strict_ether_balance_check_swc_132": "other",
    },
    "securify2": {
        "transaction_order_affects_ether_amount": "front_running",
        "transaction_order_affects_ether_receiver": "front_running",
        "transaction_order_affects_execution_of_ether_transfer": "front_running",
        "unrestricted_write_to_storage": "access_control",
        "unrestricted_call_to_selfdestruct": "access_control",
        "delegatecall_or_callcode_to_unrestricted_address": "access_control",
        "possibly_unsafe_usage_of_tx_origin": "access_control",
        "unrestricted_ether_flow": "access_control",
        "arbitrary_send": "access_control",
        "gas_dependent_reentrancy": "reentrancy",
        "reentrancy_with_constant_gas": "reentrancy",
        "no_ether_involved_reentrancy": "reentrancy",
        "benign_reentrancy": "reentrancy",
        "unhandled_exception": "unchecked_low_level_calls",
        "unused_return_pattern": "unchecked_low_level_calls",
        "low_level_calls": "unchecked_low_level_calls",
        "external_call_in_loop": "denial_of_service",
        "usage_of_block_timestamp": "time_manipulation",
        "dos_gas_limit_pattern": "denial_of_service",
        "uninitialized_state_variable": "other",
        "uninitialized_local_variables": "other",
        "locked_ether": "other",
        "repeated_call_to_untrusted_contract": "other",
        "right_to_left_override_pattern": "other",
        "state_variable_shadowing": "other",
        "assembly_usage": "other",
        "erc20_indexed_pattern": "other",
        "solidity_naming_convention": "other",
        "solidity_pragma_directives": "other",
        "unused_state_variable": "other",
        "too_many_digit_literals": "other",
        "constable_state_variables": "other",
        "external_calls_of_functions": "other",
        "state_variables_default_visibility": "other",
        "unused_variables_pattern": "other",
        "missing_input_validation": "other",
    },
    "manticore": {
        "delegatecall_to_user_controlled_address": "access_control",
        "delegatecall_to_user_controlled_function": "access_control",
        "reachable_ether_leak_to_sender": "access_control",
        "reachable_ether_leak_to_sender_via_argument": "access_control",
        "reachable_external_call_to_sender": "access_control",
        "reachable_external_call_to_sender_via_argument": "access_control",
        "reachable_selfdestruct": "access_control",
        "warning_origin_instruction_used": "access_control",
        "potential_reentrancy_vulnerability": "reentrancy",
        "reentrancy_multi_million_ether_bug": "reentrancy",
        "returned_value_at_call_instruction_is_not_used": "unchecked_low_level_calls",
        "unsigned_integer_overflow_at_add_instruction": "arithmetic",
        "unsigned_integer_overflow_at_mul_instruction": "arithmetic",
        "unsigned_integer_overflow_at_sub_instruction": "arithmetic",
        "warning_timestamp_instruction_used": "time_manipulation",
        "warning_blockhash_instruction_used": "bad_randomness",
        "invalid_instruction": "other",
        "potentially_reading_uninitialized_memory_at_instruction": "other",
        "potentially_reading_uninitialized_storage": "other",
        "warning_number_instruction_used": "other",
    },
}

FINDINGS_INFO_CACHE: dict[Path, dict[str, dict[str, str]]] = {}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def normalize_label(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


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


def parse_semver(value: str | None) -> tuple[int, int, int] | None:
    if not value:
        return None
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", str(value))
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def load_json(path: Path) -> dict | list | None:
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
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
    if offset is None or offset < 0:
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

    if isinstance(start, int) and isinstance(end, int) and ("span" in item or "file" in item or isinstance(item.get("location"), dict)):
        offsets = line_offsets_for_file(file_path)
        start_line = offset_to_line(offsets, start)
        end_line = offset_to_line(offsets, end)
        if start_line is not None or end_line is not None:
            return file_path, start_line, end_line or start_line
        return file_path, None, None

    return file_path, start if isinstance(start, int) else None, end if isinstance(end, int) else None


def normalize_internal_prediction_item(item: dict, source_file: str, kind_key: str) -> dict | None:
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


def extract_hybrid_predictions(source_file: str, raw_dir: Path) -> dict:
    stem = normalize_raw_stem(source_file)
    payload = load_json(raw_dir / f"{stem}.hybrid.json")
    if not isinstance(payload, dict):
        return {
            "items": [],
            "categories": set(),
        }

    runtime = payload.get("findings", [])
    meta = payload.get("meta_findings", [])
    items = [
        item
        for item in (
            [normalize_internal_prediction_item(entry, source_file, "kind") for entry in runtime]
            + [normalize_internal_prediction_item(entry, source_file, "finding_type") for entry in meta]
        )
        if item is not None
    ]
    return {
        "items": items,
        "categories": {item["category"] for item in items},
    }


def parse_simple_yaml(path: Path) -> dict[str, dict[str, str]]:
    cached = FINDINGS_INFO_CACHE.get(path)
    if cached is not None:
        return cached
    out: dict[str, dict[str, str]] = {}
    if not path.is_file():
        FINDINGS_INFO_CACHE[path] = out
        return out

    current: str | None = None
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if not raw_line.startswith((" ", "\t")) and ":" in line:
            key, _ = line.split(":", 1)
            current = key.strip()
            if current:
                out.setdefault(current, {})
            continue
        if current and raw_line.startswith((" ", "\t")) and ":" in line:
            stripped = line.strip()
            if not stripped or ":" not in stripped:
                continue
            field, value = stripped.split(":", 1)
            out[current][field.strip()] = value.strip()

    FINDINGS_INFO_CACHE[path] = out
    return out


def infer_category_from_classification(classification: str) -> str:
    tokens = [token.strip() for token in classification.split(",") if token.strip()]
    for token in tokens:
        category = CLASSIFICATION_TO_CATEGORY.get(token.upper())
        if category:
            return category
    return ""


def infer_category_from_name(tool_key: str, name: str) -> str:
    normalized = normalize_label(name)
    explicit = NAME_OVERRIDES.get(tool_key, {}).get(normalized, "")
    if explicit:
        return explicit
    for hint, category in GLOBAL_NAME_HINTS:
        if hint in normalized:
            return category
    return ""


def map_external_finding(tool_key: str, smartbugs_dir: Path, source_file: str, finding: dict) -> dict | None:
    name = str(finding.get("name", "")).strip()
    if not name:
        return None
    findings_yaml = smartbugs_dir / "tools" / SMARTBUGS_TOOL_IDS[tool_key] / "findings.yaml"
    info = parse_simple_yaml(findings_yaml).get(name, {})
    category = infer_category_from_name(tool_key, name)
    if not category:
        category = infer_category_from_classification(str(info.get("classification", "")))
    if not category:
        return None

    file_path = normalize_file_path(finding.get("filename")) or source_file
    start_line = finding.get("line")
    end_line = finding.get("line_end", start_line)
    if not isinstance(start_line, int):
        start_line = None
    if not isinstance(end_line, int):
        end_line = start_line

    return {
        "category": category,
        "file": file_path,
        "start_line": start_line,
        "end_line": end_line,
        "name": name,
    }


def extract_external_predictions(tool_key: str, smartbugs_dir: Path, results_root: Path) -> dict[str, dict]:
    tool_id = SMARTBUGS_TOOL_IDS[tool_key]
    out: dict[str, dict] = {}
    if not results_root.exists():
        return out

    for task_log_path in results_root.rglob("smartbugs.json"):
        task_log = load_json(task_log_path)
        if not isinstance(task_log, dict):
            continue
        tool = task_log.get("tool", {})
        if not isinstance(tool, dict) or tool.get("id") != tool_id:
            continue
        source_file = normalize_file_path(task_log.get("filename"))
        parser_output = load_json(task_log_path.with_name("result.json"))
        findings = []
        infos: list[str] = []
        errors: list[str] = []
        fails: list[str] = []
        if isinstance(parser_output, dict):
            findings = parser_output.get("findings", [])
            infos = list(parser_output.get("infos", []))
            errors = list(parser_output.get("errors", []))
            fails = list(parser_output.get("fails", []))

        items = [
            item
            for item in (map_external_finding(tool_key, smartbugs_dir, source_file, finding) for finding in findings)
            if item is not None
        ]
        out[source_file] = {
            "items": items,
            "categories": {item["category"] for item in items},
            "exit_code": task_log.get("result", {}).get("exit_code"),
            "duration_s": float(task_log.get("result", {}).get("duration", 0.0) or 0.0),
            "start_ts": float(task_log.get("result", {}).get("start", 0.0) or 0.0),
            "infos": infos,
            "errors": errors,
            "fails": fails,
        }
    return out


def percentile(values: Sequence[float], q: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    ordered = sorted(float(value) for value in values)
    pos = (len(ordered) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(ordered) - 1)
    frac = pos - lo
    return ordered[lo] * (1.0 - frac) + ordered[hi] * frac


def load_hybrid_speed(run_dir: Path, selected_files: Sequence[str]) -> dict:
    manifest = load_json(run_dir / "hybrid_manifest.json")
    if not isinstance(manifest, list):
        return {
            "contracts_timed": 0,
            "total_contract_time_s": 0.0,
            "avg_contract_time_s": 0.0,
            "median_contract_time_s": 0.0,
            "p95_contract_time_s": 0.0,
            "max_contract_time_s": 0.0,
            "approx_wall_time_s": 0.0,
            "status_counts": {},
        }

    selected = set(selected_files)
    durations = []
    status_counts = Counter()
    for entry in manifest:
        if not isinstance(entry, dict):
            continue
        file_path = normalize_file_path(entry.get("file"))
        if file_path not in selected:
            continue
        status = str(entry.get("status", "unknown"))
        status_counts[status] += 1
        elapsed_ms = entry.get("elapsed_ms")
        if isinstance(elapsed_ms, (int, float)):
            durations.append(float(elapsed_ms) / 1000.0)

    total = sum(durations)
    return {
        "contracts_timed": len(durations),
        "total_contract_time_s": round(total, 3),
        "avg_contract_time_s": round(total / len(durations), 3) if durations else 0.0,
        "median_contract_time_s": round(statistics.median(durations), 3) if durations else 0.0,
        "p95_contract_time_s": round(percentile(durations, 0.95), 3) if durations else 0.0,
        "max_contract_time_s": round(max(durations), 3) if durations else 0.0,
        "approx_wall_time_s": round(total, 3),
        "status_counts": dict(sorted(status_counts.items())),
    }


def load_external_speed(
    predictions_by_tool: dict[str, dict[str, dict]],
    selected_files: Sequence[str],
) -> dict[str, dict]:
    selected = list(selected_files)
    out: dict[str, dict] = {}
    for tool in TOOL_ORDER:
        if tool == "hybrid":
            continue
        task_entries = [
            predictions_by_tool.get(tool, {}).get(file_path, {})
            for file_path in selected
            if isinstance(predictions_by_tool.get(tool, {}).get(file_path, {}), dict)
        ]
        durations = [
            float(entry.get("duration_s", 0.0) or 0.0)
            for entry in task_entries
            if isinstance(entry.get("duration_s"), (int, float))
        ]
        start_finish = [
            (
                float(entry.get("start_ts", 0.0) or 0.0),
                float(entry.get("start_ts", 0.0) or 0.0) + float(entry.get("duration_s", 0.0) or 0.0),
            )
            for entry in task_entries
            if isinstance(entry.get("start_ts"), (int, float))
            and isinstance(entry.get("duration_s"), (int, float))
            and float(entry.get("start_ts", 0.0) or 0.0) > 0.0
        ]
        total = sum(durations)
        approx_wall = 0.0
        if start_finish:
            starts = [pair[0] for pair in start_finish]
            finishes = [pair[1] for pair in start_finish]
            approx_wall = max(finishes) - min(starts)

        out[tool] = {
            "contracts_timed": len(durations),
            "total_contract_time_s": round(total, 3),
            "avg_contract_time_s": round(total / len(durations), 3) if durations else 0.0,
            "median_contract_time_s": round(statistics.median(durations), 3) if durations else 0.0,
            "p95_contract_time_s": round(percentile(durations, 0.95), 3) if durations else 0.0,
            "max_contract_time_s": round(max(durations), 3) if durations else 0.0,
            "approx_wall_time_s": round(approx_wall, 3),
        }
    return out


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
                    "source": "official",
                }
            )
        out[rel] = vulns
    return out


def load_truth_pragmas(truth_json: Path) -> dict[str, str]:
    data = load_json(truth_json)
    if not isinstance(data, list):
        raise RuntimeError(f"unexpected SmartBugs truth payload in {truth_json}")
    out: dict[str, str] = {}
    for entry in data:
        rel = f"Benchmarks/smartbugs-curated/{str(entry['path']).replace('\\', '/')}"
        out[rel] = str(entry.get("pragma", "")).strip()
    return out


def apply_reviewed_overlay(truth: dict[str, list[dict]], overlay_json: Path | None) -> dict[str, list[dict]]:
    merged = {file_path: [dict(item) for item in vulns] for file_path, vulns in truth.items()}
    if overlay_json is None:
        return merged
    overlay = load_json(overlay_json)
    if not isinstance(overlay, dict):
        raise RuntimeError(f"unexpected reviewed overlay payload in {overlay_json}")
    for contract in overlay.get("contracts", []):
        file_path = normalize_file_path(contract.get("file"))
        if not file_path:
            continue
        existing = merged.setdefault(file_path, [])
        existing_categories = {item["category"] for item in existing}
        for category in contract.get("accepted_extra_categories", []):
            if str(category) in existing_categories:
                continue
            existing.append(
                {
                    "category": str(category),
                    "lines": [],
                    "source": "reviewed_overlay",
                }
            )
    return merged


def overlaps(truth_lines: Sequence[int], prediction: dict) -> bool:
    start_line = prediction.get("start_line")
    end_line = prediction.get("end_line")
    if start_line is None or end_line is None or not truth_lines:
        return False
    low = min(start_line, end_line)
    high = max(start_line, end_line)
    return any(low <= line <= high for line in truth_lines)


def greedy_line_matches(truth_vulns: list[dict], predicted_items: list[dict]) -> int:
    unmatched_truth = list(range(len(truth_vulns)))
    unmatched_pred = list(range(len(predicted_items)))
    matched_truth = 0

    for truth_index in list(unmatched_truth):
        truth = truth_vulns[truth_index]
        for pred_index in list(unmatched_pred):
            pred = predicted_items[pred_index]
            if pred["category"] != truth["category"]:
                continue
            if not overlaps(truth["lines"], pred):
                continue
            matched_truth += 1
            unmatched_truth.remove(truth_index)
            unmatched_pred.remove(pred_index)
            break
    return matched_truth


def precision(tp: int, fp: int) -> float:
    return tp / (tp + fp) if (tp + fp) else 0.0


def recall(tp: int, fn: int) -> float:
    return tp / (tp + fn) if (tp + fn) else 0.0


def f1_score(p: float, r: float) -> float:
    return 2.0 * p * r / (p + r) if (p + r) else 0.0


def score_scheme(
    truth: dict[str, list[dict]],
    selected_files: list[str],
    predictions_by_tool: dict[str, dict[str, dict]],
    include_line_metrics: bool,
) -> tuple[dict, list[dict]]:
    records: list[dict] = []

    for file_path in selected_files:
        truth_vulns = truth.get(file_path, [])
        truth_categories = {item["category"] for item in truth_vulns}
        official_line_truth = [item for item in truth_vulns if item.get("source") == "official" and item.get("lines")]

        for tool in TOOL_ORDER:
            pred = predictions_by_tool.get(tool, {}).get(file_path, {"items": [], "categories": set()})
            pred_categories = set(pred.get("categories", set()))
            tp = sorted(pred_categories & truth_categories)
            fp = sorted(pred_categories - truth_categories)
            fn = sorted(truth_categories - pred_categories)

            issue_hits = sum(1 for vuln in truth_vulns if vuln["category"] in pred_categories)
            per_category_hits = Counter(vuln["category"] for vuln in truth_vulns if vuln["category"] in pred_categories)

            located_items = [
                item for item in pred.get("items", [])
                if item.get("start_line") is not None and item.get("end_line") is not None
            ]
            line_matches = greedy_line_matches(official_line_truth, located_items) if include_line_metrics else 0

            records.append(
                {
                    "file": file_path,
                    "tool": tool,
                    "truth_categories": sorted(truth_categories),
                    "truth_vulnerabilities": truth_vulns,
                    "pred_categories": sorted(pred_categories),
                    "tp": tp,
                    "fp": fp,
                    "fn": fn,
                    "issue_hits": issue_hits,
                    "line_matches": line_matches,
                    "located_prediction_count": len(located_items),
                    "full_file_coverage": int(truth_categories <= pred_categories),
                    "per_category_hits": dict(per_category_hits),
                }
            )

    summary = {
        "family_metrics": {},
        "issue_coverage": {},
        "file_coverage": {},
        "per_category_issue_coverage": {},
    }
    if include_line_metrics:
        summary["line_overlap"] = {}

    for tool in TOOL_ORDER:
        tool_records = [record for record in records if record["tool"] == tool]
        tp_total = sum(len(record["tp"]) for record in tool_records)
        fp_total = sum(len(record["fp"]) for record in tool_records)
        fn_total = sum(len(record["fn"]) for record in tool_records)
        p = precision(tp_total, fp_total)
        r = recall(tp_total, fn_total)
        summary["family_metrics"][tool] = {
            "contracts": len(tool_records),
            "tp": tp_total,
            "fp": fp_total,
            "fn": fn_total,
            "precision": round(p, 3),
            "recall": round(r, 3),
            "f1": round(f1_score(p, r), 3),
        }

        total_truth_issues = sum(len(record["truth_vulnerabilities"]) for record in tool_records)
        issue_hits = sum(record["issue_hits"] for record in tool_records)
        summary["issue_coverage"][tool] = {
            "hits": issue_hits,
            "total": total_truth_issues,
            "coverage": round(issue_hits / total_truth_issues, 3) if total_truth_issues else 0.0,
        }

        files_total = len(tool_records)
        full_hits = sum(record["full_file_coverage"] for record in tool_records)
        summary["file_coverage"][tool] = {
            "files_with_full_coverage": full_hits,
            "total": files_total,
            "file_accuracy": round(full_hits / files_total, 3) if files_total else 0.0,
        }

        category_truth = Counter()
        category_hits = Counter()
        for record in tool_records:
            for vuln in record["truth_vulnerabilities"]:
                category_truth[vuln["category"]] += 1
            category_hits.update(record["per_category_hits"])
        summary["per_category_issue_coverage"][tool] = {
            category: {
                "hits": int(category_hits[category]),
                "total": int(category_truth[category]),
                "coverage": round(category_hits[category] / category_truth[category], 3) if category_truth[category] else 0.0,
            }
            for category in sorted(category_truth)
        }

        if include_line_metrics:
            truth_issues = sum(
                len([vuln for vuln in record["truth_vulnerabilities"] if vuln.get("source") == "official" and vuln.get("lines")])
                for record in tool_records
            )
            line_hits = sum(record["line_matches"] for record in tool_records)
            located_predictions = sum(record["located_prediction_count"] for record in tool_records)
            p_line = line_hits / located_predictions if located_predictions else 0.0
            r_line = line_hits / truth_issues if truth_issues else 0.0
            summary["line_overlap"][tool] = {
                "truth_issues": truth_issues,
                "located_predictions": located_predictions,
                "line_matches": line_hits,
                "precision": round(p_line, 3),
                "recall": round(r_line, 3),
                "f1": round(f1_score(p_line, r_line), 3),
            }

    return summary, records


def load_selected_files(truth_json: Path, exclusions_csv: Path) -> list[str]:
    data = load_json(truth_json)
    if not isinstance(data, list):
        raise RuntimeError(f"unexpected SmartBugs truth payload in {truth_json}")
    excluded = set()
    with exclusions_csv.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if str(row.get("suite", "")).strip() != "smartbugs-curated":
                continue
            rel = str(row.get("path", "")).strip().replace("\\", "/")
            if rel:
                excluded.add(rel)

    selected = []
    for entry in sorted(data, key=lambda item: str(item.get("path", ""))):
        rel = f"Benchmarks/smartbugs-curated/{str(entry['path']).replace('\\', '/')}"
        if rel in excluded:
            continue
        selected.append(rel)
    return selected


def load_selected_files_for_run(run_dir: Path, truth_json: Path, exclusions_csv: Path) -> list[str]:
    manifest_path = run_dir / "selected_contracts.json"
    manifest = load_json(manifest_path)
    if isinstance(manifest, list) and all(isinstance(item, str) for item in manifest):
        return [str(item) for item in manifest]
    return load_selected_files(truth_json, exclusions_csv)


def detect_tool_comparability(
    selected_files: Sequence[str],
    selected_pragmas: dict[str, str],
    predictions_by_tool: dict[str, dict[str, dict]],
) -> dict[str, dict]:
    selected = list(selected_files)
    summary: dict[str, dict] = {}

    for tool in TOOL_ORDER:
        tool_predictions = predictions_by_tool.get(tool, {})
        task_entries = [
            tool_predictions.get(file_path, {})
            for file_path in selected
            if isinstance(tool_predictions.get(file_path, {}), dict)
        ]

        tasks_total = len(selected)
        tasks_seen = len(task_entries)
        tasks_with_findings = sum(1 for entry in task_entries if entry.get("items"))
        tasks_with_errors = sum(1 for entry in task_entries if entry.get("errors"))
        tasks_with_fails = sum(1 for entry in task_entries if entry.get("fails"))
        tasks_with_exit_zero = sum(1 for entry in task_entries if entry.get("exit_code") == 0)
        tasks_empty_clean = sum(
            1
            for entry in task_entries
            if not entry.get("items") and not entry.get("errors") and not entry.get("fails")
        )
        timeout_tasks = sum(
            1
            for entry in task_entries
            if any("DOCKER_TIMEOUT" in str(fail) for fail in entry.get("fails", []))
        )
        solver_failure_tasks = sum(
            1
            for entry in task_entries
            if any(
                marker in str(fail)
                for fail in entry.get("fails", [])
                for marker in (
                    "Concretize",
                    "Forking on unfeasible constraint set",
                    "ManticoreError",
                )
            )
        )

        status = "comparable"
        fair_included = True
        reason = "usable results on the shared benchmark subset"

        min_supported = TOOL_MIN_SOLIDITY.get(tool)
        supported_contracts = None
        if min_supported is not None:
            supported_contracts = sum(
                1
                for file_path in selected
                if (
                    parse_semver(selected_pragmas.get(file_path)) is not None
                    and parse_semver(selected_pragmas.get(file_path)) >= min_supported
                )
            )
            if supported_contracts == 0:
                status = "incompatible_corpus"
                fair_included = False
                reason = (
                    f"declared support starts at Solidity >= {min_supported[0]}.{min_supported[1]}.{min_supported[2]}, "
                    f"but the selected subset contains 0/{tasks_total} compatible contracts"
                )

        if fair_included and tool != "hybrid" and tasks_with_findings == 0:
            if timeout_tasks >= max(1, tasks_total // 2) or tasks_with_fails >= int(tasks_total * 0.7):
                status = "budget_exhausted"
                fair_included = False
                reason = (
                    f"0/{tasks_total} tasks produced usable findings under the equal-budget harness; "
                    f"{timeout_tasks} timed out, {solver_failure_tasks} hit symbolic execution failures, "
                    f"and {tasks_empty_clean} finished empty"
                )
            elif tasks_with_errors + tasks_with_fails >= tasks_total:
                status = "harness_failure"
                fair_included = False
                reason = (
                    f"0/{tasks_total} tasks produced usable findings and {tasks_with_errors + tasks_with_fails}/{tasks_total} "
                    "tasks ended in parser or framework failures"
                )

        summary[tool] = {
            "status": status,
            "fair_included": fair_included,
            "reason": reason,
            "tasks_total": tasks_total,
            "tasks_seen": tasks_seen,
            "tasks_with_findings": tasks_with_findings,
            "tasks_with_errors": tasks_with_errors,
            "tasks_with_fails": tasks_with_fails,
            "tasks_with_exit_zero": tasks_with_exit_zero,
            "tasks_empty_clean": tasks_empty_clean,
            "timeout_tasks": timeout_tasks,
            "solver_failure_tasks": solver_failure_tasks,
            "supported_contracts": supported_contracts,
        }

    return summary


def write_markdown_report(path: Path, summary: dict) -> None:
    lines: list[str] = []
    lines.append("# SmartBugs Hybrid vs External Tools\n")
    lines.append(f"Date: {summary['metadata']['date']}\n")
    lines.append(f"Benchmark contracts: `{summary['metadata']['selected_contracts']}`\n")
    lines.append("Tools: `hybrid`, `Slither`, `Smartcheck`, `Securify2`, `Mythril`, `Manticore`\n")
    compatibility_excluded = summary["metadata"].get("compatibility_excluded", [])
    if compatibility_excluded:
        lines.append("Compatibility-excluded fixtures for this shared subset:\n")
        for item in compatibility_excluded:
            lines.append(f"- `{item['file']}`: {item['reason']}")
        lines.append("")

    comparability = summary.get("comparability", {})
    fair_tools = [tool for tool in TOOL_ORDER if comparability.get(tool, {}).get("fair_included", True)]
    non_comparable = [tool for tool in TOOL_ORDER if tool not in fair_tools]
    if comparability:
        lines.append("## Fair-Comparison Status\n")
        lines.append(
            "Fair ranking excludes tools that were not comparable on this corpus under the current harness, "
            "while the raw equal-budget appendix still records what they actually returned.\n"
        )
        lines.append("| Tool | Status | Included In Fair Ranking | Notes |")
        lines.append("| --- | --- | --- | --- |")
        for tool in TOOL_ORDER:
            item = comparability.get(tool, {})
            included = "yes" if item.get("fair_included", True) else "no"
            lines.append(
                f"| `{tool}` | `{item.get('status', 'unknown')}` | {included} | {item.get('reason', '')} |"
            )
        lines.append("")

    speed = summary.get("speed", {})
    if speed:
        lines.append("## Speed Metrics\n")
        lines.append(
            "Speed is reported for all tools that were run. Non-comparable tools are still shown here because "
            "runtime is factual even when the accuracy result should not be ranked.\n"
        )
        lines.append("| Tool | Timed Contracts | Total Contract Time (s) | Avg / Contract (s) | Median (s) | P95 (s) | Max (s) | Approx Wall Time (s) |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for tool in TOOL_ORDER:
            item = speed.get(tool, {})
            lines.append(
                f"| `{tool}` | {item.get('contracts_timed', 0)} | {item.get('total_contract_time_s', 0.0):.3f} | "
                f"{item.get('avg_contract_time_s', 0.0):.3f} | {item.get('median_contract_time_s', 0.0):.3f} | "
                f"{item.get('p95_contract_time_s', 0.0):.3f} | {item.get('max_contract_time_s', 0.0):.3f} | "
                f"{item.get('approx_wall_time_s', 0.0):.3f} |"
            )
        lines.append("")

    for scheme_key, scheme_title in (
        ("official_truth", "Official Truth Metrics"),
        ("reviewed_adjusted_truth", "Reviewed-Adjusted Metrics"),
    ):
        scheme = summary[scheme_key]
        lines.append(f"## {scheme_title} (Fair Ranking)\n")
        lines.append("| Tool | TP | FP | FN | Precision | Recall | F1 | Issue Coverage | File Accuracy |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for tool in fair_tools:
            family = scheme["family_metrics"][tool]
            issue = scheme["issue_coverage"][tool]
            files = scheme["file_coverage"][tool]
            lines.append(
                f"| `{tool}` | {family['tp']} | {family['fp']} | {family['fn']} | "
                f"{family['precision']:.3f} | {family['recall']:.3f} | {family['f1']:.3f} | "
                f"{issue['hits']}/{issue['total']} ({issue['coverage']:.3f}) | "
                f"{files['files_with_full_coverage']}/{files['total']} ({files['file_accuracy']:.3f}) |"
            )
        lines.append("")

        if non_comparable:
            lines.append(f"## {scheme_title} (Raw Equal-Budget Appendix)\n")
            lines.append("| Tool | TP | FP | FN | Precision | Recall | F1 | Issue Coverage | File Accuracy |")
            lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
            for tool in TOOL_ORDER:
                family = scheme["family_metrics"][tool]
                issue = scheme["issue_coverage"][tool]
                files = scheme["file_coverage"][tool]
                lines.append(
                    f"| `{tool}` | {family['tp']} | {family['fp']} | {family['fn']} | "
                    f"{family['precision']:.3f} | {family['recall']:.3f} | {family['f1']:.3f} | "
                    f"{issue['hits']}/{issue['total']} ({issue['coverage']:.3f}) | "
                    f"{files['files_with_full_coverage']}/{files['total']} ({files['file_accuracy']:.3f}) |"
                )
            lines.append("")

    if "line_overlap" in summary["official_truth"]:
        lines.append("## Official Labeled-Line Overlap\n")
        lines.append("| Tool | Truth Issues | Located Predictions | Line Matches | Precision | Recall | F1 |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
        for tool in TOOL_ORDER:
            line = summary["official_truth"]["line_overlap"][tool]
            lines.append(
                f"| `{tool}` | {line['truth_issues']} | {line['located_predictions']} | {line['line_matches']} | "
                f"{line['precision']:.3f} | {line['recall']:.3f} | {line['f1']:.3f} |"
            )
        lines.append("")

    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Score SmartBugs-curated for hybrid plus external SmartBugs tools."
    )
    parser.add_argument(
        "--run-dir",
        type=Path,
        required=True,
        help="Benchmark run directory created by run_smartbugs_hybrid_vs_tools.py",
    )
    parser.add_argument(
        "--truth-json",
        type=Path,
        default=Path("Benchmarks/smartbugs-curated/vulnerabilities.json"),
        help="Official SmartBugs vulnerability list.",
    )
    parser.add_argument(
        "--reviewed-overlay",
        type=Path,
        default=Path("fixtures/ground_truth/smartbugs_reviewed_overlay.json"),
        help="Reviewed overlay of accepted extra categories.",
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
        help="Local SmartBugs checkout used to resolve tool findings metadata.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory (default: <run-dir>/score)",
    )
    parser.add_argument(
        "--report-md",
        type=Path,
        default=None,
        help="Optional markdown report path (default: <run-dir>/smartbugs_hybrid_vs_external_tools.md)",
    )
    args = parser.parse_args()

    repo = repo_root()
    run_dir = args.run_dir
    if not run_dir.is_dir():
        raise SystemExit(f"run dir not found: {run_dir}")

    selected_files = load_selected_files_for_run(run_dir, repo / args.truth_json, repo / args.exclusions_csv)
    official_truth = load_truth(repo / args.truth_json)
    adjusted_truth = apply_reviewed_overlay(official_truth, repo / args.reviewed_overlay)
    selected_pragmas = load_truth_pragmas(repo / args.truth_json)

    predictions_by_tool: dict[str, dict[str, dict]] = {
        "hybrid": {},
        "slither": {},
        "smartcheck": {},
        "securify2": {},
        "mythril": {},
        "manticore": {},
    }
    predictions_by_tool["hybrid"] = {
        file_path: extract_hybrid_predictions(file_path, run_dir / "raw")
        for file_path in selected_files
    }
    external_results_root = run_dir / "external_results"
    for tool in TOOL_ORDER:
        if tool == "hybrid":
            continue
        predictions_by_tool[tool] = extract_external_predictions(
            tool,
            args.smartbugs_dir,
            external_results_root,
        )

    official_summary, official_records = score_scheme(
        official_truth,
        selected_files,
        predictions_by_tool,
        include_line_metrics=True,
    )
    adjusted_summary, adjusted_records = score_scheme(
        adjusted_truth,
        selected_files,
        predictions_by_tool,
        include_line_metrics=False,
    )
    speed_summary = {
        "hybrid": load_hybrid_speed(run_dir, selected_files),
        **load_external_speed(predictions_by_tool, selected_files),
    }
    comparability_summary = detect_tool_comparability(selected_files, selected_pragmas, predictions_by_tool)

    summary = {
        "metadata": {
            "date": time.strftime("%Y-%m-%d"),
            "selected_contracts": len(selected_files),
            "tools": TOOL_ORDER,
            "truth_json": str(args.truth_json),
            "reviewed_overlay": str(args.reviewed_overlay),
            "run_dir": str(run_dir),
            "compatibility_excluded": load_json(run_dir / "compatibility_excluded_contracts.json") or [],
        },
        "comparability": comparability_summary,
        "speed": speed_summary,
        "official_truth": official_summary,
        "reviewed_adjusted_truth": adjusted_summary,
    }

    out_dir = args.out_dir or (run_dir / "score")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (out_dir / "official_per_contract.json").write_text(json.dumps(official_records, indent=2) + "\n", encoding="utf-8")
    (out_dir / "adjusted_per_contract.json").write_text(json.dumps(adjusted_records, indent=2) + "\n", encoding="utf-8")

    report_md = args.report_md or (run_dir / "smartbugs_hybrid_vs_external_tools.md")
    write_markdown_report(report_md, summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
