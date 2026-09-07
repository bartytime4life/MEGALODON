"""Validated, privacy-bounded projection of one completed offline run."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat
from typing import Any

from .offline.analysis import MAX_CANDIDATES, PROTOCOLS
from .offline.common import Limits, OfflineError, open_directory, uint, version
from .offline.reports import REPORT_NAMES, case_id
from .offline.zeek import json_object


MANIFEST_NAME = "manifest.json"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_BASELINE_BYTES = 1024 * 1024
MAX_CANDIDATES_BYTES = 1024 * 1024
MAX_CANDIDATE_LINE_BYTES = 16 * 1024
MAX_PROJECTED_PORTS = 12
MAX_REPORT_SET_BYTES = 16 * 1024 * 1024

_COMPLETE_MANIFEST_FIELDS = {
    "schema",
    "run_id",
    "case_id",
    "source",
    "started_at",
    "ended_at",
    "status",
    "limits",
    "version_probe_limits",
    "accepted_records",
    "rejected_records",
    "scanned_records",
    "skipped_unsupported_records",
    "input_bytes",
    "candidate_count",
    "action_status",
    "egress",
    "capture_hash",
    "redaction",
    "reports",
    "adapter",
    "record_kind",
    "tool_version",
    "tool_version_basis",
    "byte_count_basis",
    "reference_baseline_used",
}
_SOURCE_CONTRACT = {
    "tshark": ("tshark-fields-v1", "packet", "frame_length"),
    "zeek-json": ("zeek-conn-json-v1", "flow", "orig_plus_resp_ip_bytes"),
    "zeek-tsv": ("zeek-conn-tsv-v1", "flow", "orig_plus_resp_ip_bytes"),
}
_CANDIDATE_RULES = (
    "NEW_DESTINATION_PORT",
    "REGULAR_INTERVAL",
    "PORT_53_BURST",
)
_BASELINE_FIELDS = {
    "schema",
    "adapter",
    "record_kind",
    "record_count",
    "total_bytes",
    "protocols",
    "destination_ports",
    "byte_bands",
    "relative_minutes",
}


def _fail(code: str) -> None:
    raise OfflineError(code)


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _read_private_file(directory: int, name: str, maximum: int, *, allow_empty: bool = False) -> bytes:
    fd = None
    try:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=directory,
        )
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o077
        ):
            _fail("PRIVATE_OFFLINE_REPORT_REQUIRED")
        if before.st_size > maximum or (before.st_size == 0 and not allow_empty):
            _fail("OFFLINE_REPORT_SIZE_LIMIT")
        data = bytearray()
        while True:
            chunk = os.read(fd, min(65536, maximum - len(data) + 1))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > maximum:
                _fail("OFFLINE_REPORT_SIZE_LIMIT")
        if _identity(os.fstat(fd)) != _identity(before):
            _fail("OFFLINE_REPORT_CHANGED")
        return bytes(data)
    except OSError:
        _fail("OFFLINE_REPORT_IO_ERROR")
    finally:
        if fd is not None:
            os.close(fd)


def _private_file_size(directory: int, name: str, maximum: int, *, allow_empty: bool = False) -> int:
    fd = None
    try:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=directory,
        )
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            _fail("PRIVATE_OFFLINE_REPORT_REQUIRED")
        if info.st_size > maximum or (info.st_size == 0 and not allow_empty):
            _fail("OFFLINE_REPORT_SIZE_LIMIT")
        return info.st_size
    except OSError:
        _fail("OFFLINE_REPORT_IO_ERROR")
    finally:
        if fd is not None:
            os.close(fd)


def _read_report_set(path: str | Path) -> tuple[dict[str, bytes], dict[str, int]]:
    value = os.fspath(path)
    if not os.path.isabs(value) or value == "/":
        _fail("ABSOLUTE_OFFLINE_RUN_REQUIRED")
    directory = None
    try:
        directory = open_directory(value)
        before = os.fstat(directory)
        if before.st_uid != os.geteuid() or before.st_mode & 0o077:
            _fail("PRIVATE_OFFLINE_RUN_REQUIRED")
        expected = {*REPORT_NAMES, MANIFEST_NAME}
        if set(os.listdir(directory)) != expected:
            _fail("COMPLETE_OFFLINE_REPORT_SET_REQUIRED")
        maxima = {
            "records.jsonl": MAX_REPORT_SET_BYTES,
            "records.csv": MAX_REPORT_SET_BYTES,
            "baseline.json": MAX_BASELINE_BYTES,
            "candidates.jsonl": MAX_CANDIDATES_BYTES,
            MANIFEST_NAME: MAX_MANIFEST_BYTES,
        }
        sizes = {
            name: _private_file_size(
                directory,
                name,
                maxima[name],
                allow_empty=name in {"records.jsonl", "candidates.jsonl"},
            )
            for name in expected
        }
        if sum(sizes.values()) > MAX_REPORT_SET_BYTES:
            _fail("OFFLINE_REPORT_SIZE_LIMIT")
        result = {
            MANIFEST_NAME: _read_private_file(directory, MANIFEST_NAME, MAX_MANIFEST_BYTES),
            "baseline.json": _read_private_file(directory, "baseline.json", MAX_BASELINE_BYTES),
            "candidates.jsonl": _read_private_file(
                directory,
                "candidates.jsonl",
                MAX_CANDIDATES_BYTES,
                allow_empty=True,
            ),
        }
        if _identity(os.fstat(directory)) != _identity(before):
            _fail("OFFLINE_REPORT_CHANGED")
        return result, sizes
    except OfflineError:
        raise
    except OSError:
        _fail("OFFLINE_REPORT_IO_ERROR")
    finally:
        if directory is not None:
            os.close(directory)


def _utc_timestamp(value: object) -> datetime:
    if (
        not isinstance(value, str)
        or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.[0-9]{1,6})?(?:Z|\+00:00)",
            value,
        )
    ):
        _fail("INVALID_OFFLINE_MANIFEST")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        _fail("INVALID_OFFLINE_MANIFEST")
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        _fail("INVALID_OFFLINE_MANIFEST")
    return parsed


def _manifest(value: dict[str, Any]) -> tuple[dict[str, Any], Limits]:
    if set(value) != _COMPLETE_MANIFEST_FIELDS:
        _fail("INVALID_OFFLINE_MANIFEST")
    source = value.get("source")
    if not isinstance(source, str):
        _fail("INVALID_OFFLINE_MANIFEST")
    contract = _SOURCE_CONTRACT.get(source)
    if (
        value.get("schema") != "offline-run-v1"
        or value.get("status") != "complete"
        or contract is None
        or tuple(value.get(key) for key in ("adapter", "record_kind", "byte_count_basis")) != contract
        or value.get("action_status") != "not_attempted"
        or value.get("egress") != "not_implemented_policy_required"
        or value.get("capture_hash") != "not_computed"
        or value.get("redaction") != "run_local_rank_labels_relative_time_v1"
        or value.get("rejected_records") != 0
        or value.get("reports") != list(REPORT_NAMES)
        or type(value.get("reference_baseline_used")) is not bool
    ):
        _fail("INVALID_OFFLINE_MANIFEST")
    run_id = value.get("run_id")
    if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id):
        _fail("INVALID_OFFLINE_MANIFEST")
    try:
        case_id(value.get("case_id"))
        tool_version = version(value.get("tool_version"))
    except OfflineError:
        _fail("INVALID_OFFLINE_MANIFEST")
    basis = value.get("tool_version_basis")
    if not isinstance(basis, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,47}", basis):
        _fail("INVALID_OFFLINE_MANIFEST")
    limits_value = value.get("limits")
    if not isinstance(limits_value, dict) or set(limits_value) != set(Limits.__dataclass_fields__):
        _fail("INVALID_OFFLINE_MANIFEST")
    try:
        limits = Limits(**limits_value)
        accepted = uint(value.get("accepted_records"), limits.records)
        scanned = uint(value.get("scanned_records"), limits.records)
        skipped = uint(value.get("skipped_unsupported_records"), limits.records)
        input_bytes = uint(value.get("input_bytes"), limits.input_bytes)
        candidate_count = uint(value.get("candidate_count"), MAX_CANDIDATES)
    except (OfflineError, TypeError):
        _fail("INVALID_OFFLINE_MANIFEST")
    if input_bytes == 0 or accepted + skipped != scanned:
        _fail("INVALID_OFFLINE_MANIFEST")
    started = _utc_timestamp(value.get("started_at"))
    ended = _utc_timestamp(value.get("ended_at"))
    if started > ended:
        _fail("INVALID_OFFLINE_MANIFEST")
    expected_probe = (
        {"timeout_seconds": 5, "stdout_bytes": 8192, "stderr_bytes": 4096}
        if source == "tshark"
        else None
    )
    if value.get("version_probe_limits") != expected_probe:
        _fail("INVALID_OFFLINE_MANIFEST")
    return {
        "run_id": run_id,
        "case_id": value["case_id"],
        "source": source,
        "adapter": contract[0],
        "record_kind": contract[1],
        "byte_count_basis": contract[2],
        "tool_version": tool_version,
        "tool_version_basis": basis,
        "started_at": value["started_at"],
        "ended_at": value["ended_at"],
        "accepted_records": accepted,
        "scanned_records": scanned,
        "skipped_unsupported_records": skipped,
        "input_bytes": input_bytes,
        "candidate_count": candidate_count,
        "reference_baseline_used": value["reference_baseline_used"],
        "action_status": "not_attempted",
        "egress": "not_implemented_policy_required",
    }, limits


def _baseline(value: dict[str, Any], run: dict[str, Any]) -> dict[str, Any]:
    if (
        set(value) != _BASELINE_FIELDS
        or value.get("schema") != "offline-baseline-v1"
        or value.get("adapter") != run["adapter"]
        or value.get("record_kind") != run["record_kind"]
    ):
        _fail("INVALID_OFFLINE_BASELINE")
    size = run["accepted_records"]
    try:
        if uint(value.get("record_count"), 10_000) != size:
            _fail("INVALID_OFFLINE_BASELINE")
        total_bytes = uint(value.get("total_bytes"), size * (2**41 - 2))
    except OfflineError:
        _fail("INVALID_OFFLINE_BASELINE")

    protocol_items = value.get("protocols")
    if not isinstance(protocol_items, list) or len(protocol_items) > len(PROTOCOLS):
        _fail("INVALID_OFFLINE_BASELINE")
    protocols: list[dict[str, int | str]] = []
    protocol_names: set[str] = set()
    protocol_total = 0
    for item in protocol_items:
        if not isinstance(item, dict) or set(item) != {"protocol", "count"}:
            _fail("INVALID_OFFLINE_BASELINE")
        protocol = item.get("protocol")
        if not isinstance(protocol, str) or protocol not in PROTOCOLS or protocol in protocol_names:
            _fail("INVALID_OFFLINE_BASELINE")
        try:
            count = uint(item.get("count"), size)
        except OfflineError:
            _fail("INVALID_OFFLINE_BASELINE")
        if count == 0:
            _fail("INVALID_OFFLINE_BASELINE")
        protocol_names.add(protocol)
        protocol_total += count
        protocols.append({"protocol": protocol, "count": count})
    if protocol_total != size:
        _fail("INVALID_OFFLINE_BASELINE")

    port_items = value.get("destination_ports")
    if not isinstance(port_items, list) or len(port_items) > size:
        _fail("INVALID_OFFLINE_BASELINE")
    ports: list[dict[str, int | str]] = []
    port_pairs: set[tuple[str, int]] = set()
    port_total = 0
    for item in port_items:
        if not isinstance(item, dict) or set(item) != {"protocol", "port", "count"}:
            _fail("INVALID_OFFLINE_BASELINE")
        protocol = item.get("protocol")
        if protocol not in {"TCP", "UDP"} or protocol not in protocol_names:
            _fail("INVALID_OFFLINE_BASELINE")
        try:
            port = uint(item.get("port"), 65535)
            count = uint(item.get("count"), size)
        except OfflineError:
            _fail("INVALID_OFFLINE_BASELINE")
        pair = protocol, port
        if pair in port_pairs or count == 0:
            _fail("INVALID_OFFLINE_BASELINE")
        port_pairs.add(pair)
        port_total += count
        ports.append({"protocol": protocol, "port": port, "count": count})
    if port_total > size:
        _fail("INVALID_OFFLINE_BASELINE")

    bands = value.get("byte_bands")
    if not isinstance(bands, dict) or set(bands) != {"small", "medium", "large"}:
        _fail("INVALID_OFFLINE_BASELINE")
    try:
        byte_bands = {name: uint(bands[name], size) for name in ("small", "medium", "large")}
    except OfflineError:
        _fail("INVALID_OFFLINE_BASELINE")
    if sum(byte_bands.values()) != size:
        _fail("INVALID_OFFLINE_BASELINE")

    minute_items = value.get("relative_minutes")
    if not isinstance(minute_items, list) or len(minute_items) > size:
        _fail("INVALID_OFFLINE_BASELINE")
    minute_total = 0
    minutes: set[int] = set()
    for item in minute_items:
        if not isinstance(item, dict) or set(item) != {"minute", "count"}:
            _fail("INVALID_OFFLINE_BASELINE")
        try:
            minute = uint(item.get("minute"), 68_374_080)
            count = uint(item.get("count"), size)
        except OfflineError:
            _fail("INVALID_OFFLINE_BASELINE")
        if minute in minutes or count == 0:
            _fail("INVALID_OFFLINE_BASELINE")
        minutes.add(minute)
        minute_total += count
    if minute_total != size:
        _fail("INVALID_OFFLINE_BASELINE")

    ranked_ports = sorted(ports, key=lambda item: (-int(item["count"]), str(item["protocol"]), int(item["port"])))
    return {
        "record_count": size,
        "total_bytes": total_bytes,
        "protocols": sorted(protocols, key=lambda item: (-int(item["count"]), str(item["protocol"]))),
        "destination_ports": ranked_ports[:MAX_PROJECTED_PORTS],
        "destination_ports_total": len(ranked_ports),
        "destination_ports_truncated": len(ranked_ports) > MAX_PROJECTED_PORTS,
        "byte_bands": byte_bands,
        "relative_window_minutes": max(minutes) + 1 if minutes else 0,
    }


def _candidate(value: dict[str, Any], run: dict[str, Any]) -> str:
    if (
        set(value) != {"rule", "status", "record_kind", "action_status", "evidence"}
        or value.get("status") != "candidate"
        or value.get("record_kind") != run["record_kind"]
        or value.get("action_status") != "not_attempted"
        or value.get("rule") not in _CANDIDATE_RULES
        or not isinstance(value.get("evidence"), dict)
    ):
        _fail("INVALID_OFFLINE_CANDIDATE")
    rule = value["rule"]
    evidence = value["evidence"]
    accepted = run["accepted_records"]
    try:
        if rule == "NEW_DESTINATION_PORT":
            protocol = evidence.get("protocol")
            if (
                set(evidence) != {"protocol", "port", "records"}
                or not isinstance(protocol, str)
                or protocol not in {"TCP", "UDP"}
                or not run["reference_baseline_used"]
            ):
                _fail("INVALID_OFFLINE_CANDIDATE")
            uint(evidence.get("port"), 65535)
            if uint(evidence.get("records"), accepted) == 0:
                _fail("INVALID_OFFLINE_CANDIDATE")
        elif rule == "REGULAR_INTERVAL":
            protocol = evidence.get("protocol")
            expected = {
                "src",
                "dst",
                "protocol",
                "port",
                "unique_observations",
                "median_interval_us",
                "interval_spread_us",
            }
            if (
                set(evidence) != expected
                or not isinstance(protocol, str)
                or protocol not in {"TCP", "UDP"}
                or any(
                    not isinstance(evidence.get(name), str)
                    or not re.fullmatch(r"host-[0-9]{5}", evidence[name])
                    for name in ("src", "dst")
                )
            ):
                _fail("INVALID_OFFLINE_CANDIDATE")
            uint(evidence.get("port"), 65535)
            if uint(evidence.get("unique_observations"), accepted) < 5:
                _fail("INVALID_OFFLINE_CANDIDATE")
            median = uint(evidence.get("median_interval_us"), 3_600_000_000)
            spread = uint(evidence.get("interval_spread_us"), 3_600_000_000)
            if median < 1_000_000 or spread > median // 20:
                _fail("INVALID_OFFLINE_CANDIDATE")
        else:
            if set(evidence) != {"src", "relative_minute", "records"}:
                _fail("INVALID_OFFLINE_CANDIDATE")
            src = evidence.get("src")
            if not isinstance(src, str) or not re.fullmatch(r"host-[0-9]{5}", src):
                _fail("INVALID_OFFLINE_CANDIDATE")
            uint(evidence.get("relative_minute"), 68_374_080)
            if uint(evidence.get("records"), accepted) < 20:
                _fail("INVALID_OFFLINE_CANDIDATE")
    except OfflineError:
        _fail("INVALID_OFFLINE_CANDIDATE")
    return rule


def _candidates(data: bytes, run: dict[str, Any]) -> list[dict[str, int | str]]:
    if not data:
        values: list[bytes] = []
    elif not data.endswith(b"\n"):
        _fail("INVALID_OFFLINE_CANDIDATES")
    else:
        values = data.splitlines()
    if len(values) != run["candidate_count"] or len(values) > MAX_CANDIDATES:
        _fail("INVALID_OFFLINE_CANDIDATES")
    counts: Counter[str] = Counter()
    for line in values:
        if not line or len(line) > MAX_CANDIDATE_LINE_BYTES:
            _fail("INVALID_OFFLINE_CANDIDATES")
        try:
            candidate = json_object(line.decode("ascii"))
        except (UnicodeDecodeError, OfflineError):
            _fail("INVALID_OFFLINE_CANDIDATES")
        counts[_candidate(candidate, run)] += 1
    return [
        {"rule": rule, "status": "candidate", "count": counts[rule]}
        for rule in _CANDIDATE_RULES
        if counts[rule]
    ]


def load_offline_projection(path: str | Path) -> dict[str, Any]:
    """Load one immutable dashboard snapshot from a complete private report set."""
    data, sizes = _read_report_set(path)
    try:
        manifest_value = json_object(data[MANIFEST_NAME].decode("ascii"))
        baseline_value = json_object(data["baseline.json"].decode("ascii"))
    except (UnicodeDecodeError, OfflineError):
        _fail("INVALID_OFFLINE_REPORT_JSON")
    run, limits = _manifest(manifest_value)
    if sum(sizes.values()) > limits.report_bytes:
        _fail("OFFLINE_REPORT_SIZE_LIMIT")
    summary = _baseline(baseline_value, run)
    candidate_summary = _candidates(data["candidates.jsonl"], run)
    return {
        "schema": "dashboard-offline-summary-v1",
        "run": run,
        "summary": summary,
        "candidates": candidate_summary,
        "limitations": [
            "Review candidates are not malware verdicts or response authorization.",
            "Counts preserve packet or flow units; runs from different sources are not joined.",
            "The snapshot excludes addresses, capture paths, packet bytes, and candidate evidence details.",
            "Reports remain local and private; external sharing still requires an approved egress policy.",
            "Startup checks detect ordinary changes but do not create an atomic filesystem snapshot.",
        ],
    }
