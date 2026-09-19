"""Pure SIEM projection functions and a bounded local-file writer.

`docs/external-exchange-contract.md`'s dependency-ordered adoption lists, as
its next open step: "Add pure projection functions for ECS and OCSF plus
golden fixtures; write only to a new private local file and fail before
partial publication." This module is exactly that slice, and nothing else.

`to_ecs_record` / `to_ocsf_record` project one already-accepted MEGALODON
`PacketEvent` + `DetectionResult` pair into a closed, versioned ECS 9.5.0 /
OCSF 1.9.0 record, matching the `ecsRecord`/`ocsfRecord` definitions in
`contracts/external-exchange/v1/schema.json`. `write_export` writes a bounded
batch of already-projected records to one brand-new local file (JSON Lines):
it validates the full record count and byte ceiling before creating
anything, so a failure never leaves a partially written export, and a single
buffered write plus `fsync` means there is no partial-record boundary to
land on mid-file either.

Neither profile claims full standard compliance. Each keeps to a minimal,
verifiable field subset and carries every MEGALODON-specific value inside
that standard's own sanctioned vendor-extension mechanism: ECS's free-form
top-level `megalodon` namespace, and OCSF's `unmapped` object plus the
generic `activity_id: 99` ("Other") sentinel for values this repository is
not confident map to a specific upstream enum. `event.original` and any raw
payload field are never produced, matching the contract's exclusion list;
neither is `network_delivery`, a credential, or an endpoint of any kind.

This module performs no network access, no credential handling, no SIEM
delivery, and no SOAR action. It is a standalone API a caller invokes with
already-accepted domain objects and an explicit destination path; it is not
wired into the CLI, the dashboard, or the storage layer.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any

from .models import DetectionResult, PacketEvent

MAX_RECORDS = 10_000
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
PROFILES = frozenset({"ecs-9.5.0", "ocsf-1.9.0"})
REQUIRED_MODE = 0o600

_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_COMPLETENESS = frozenset({"complete", "partial"})
_SOURCE_KINDS = frozenset({"sample", "jsonl", "scapy"})

_ECS_SEVERITY = {"LOW": 25, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 99}
_OCSF_SEVERITY = {
    "LOW": (2, "Low"), "MEDIUM": (3, "Medium"), "HIGH": (4, "High"), "CRITICAL": (5, "Critical"),
}

ERROR_CODES = frozenset({
    "INVALID_ID", "INVALID_COMPLETENESS", "INVALID_SOURCE_KIND", "INVALID_TIMESTAMP",
    "INVALID_PROFILE", "RECORD_LIMIT_EXCEEDED", "OUTPUT_BYTES_LIMIT_EXCEEDED",
    "DESTINATION_UNSAFE", "DESTINATION_EXISTS", "IO_ERROR",
})


class SiemExportError(ValueError):
    """A fixed, closed diagnostic for the bounded SIEM export boundary."""

    def __init__(self, code: str):
        if code not in ERROR_CODES:
            code = "IO_ERROR"
        super().__init__(f"SIEM_EXPORT_V1:{code}")
        self.code = code


def _fail(code: str) -> None:
    raise SiemExportError(code) from None


def _logical_id(value: object) -> str:
    if type(value) is not str or not _LOGICAL_ID.fullmatch(value):
        _fail("INVALID_ID")
    return value


def _completeness(value: object) -> str:
    if value not in _COMPLETENESS:
        _fail("INVALID_COMPLETENESS")
    return value


def _source_kind(value: object) -> str:
    if value not in _SOURCE_KINDS:
        _fail("INVALID_SOURCE_KIND")
    return value


def _utc_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("INVALID_TIMESTAMP")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch_millis(value: datetime) -> int:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("INVALID_TIMESTAMP")
    return int(value.astimezone(timezone.utc).timestamp() * 1000)


def _endpoint(ip: str, port: int | None) -> Mapping[str, Any]:
    result: dict[str, Any] = {"ip": ip}
    if port is not None:
        result["port"] = port
    return MappingProxyType(result)


def to_ecs_record(
    event: PacketEvent, detection: DetectionResult, *,
    run_id: str, event_id: str, detection_id: str, source_kind: str,
    ingested_at: datetime, completeness: str = "complete",
) -> Mapping[str, Any]:
    """Project one accepted event/detection pair into one bounded ECS record."""
    run_id = _logical_id(run_id)
    event_id = _logical_id(event_id)
    detection_id = _logical_id(detection_id)
    source_kind = _source_kind(source_kind)
    completeness = _completeness(completeness)

    megalodon: dict[str, Any] = {
        "schema_version": "megalodon-ecs-profile-v1",
        "run_id": run_id,
        "event_id": event_id,
        "detection_id": detection_id,
        "source_kind": source_kind,
        "recommendation": detection.recommendation,
        "completeness": completeness,
        "projection_version": "1",
    }
    if detection.suppressed_reason is not None:
        megalodon["suppressed_reason"] = detection.suppressed_reason

    return MappingProxyType({
        "@timestamp": _utc_timestamp(detection.detected_at),
        "event": MappingProxyType({
            "kind": "alert",
            "category": ("network", "intrusion_detection"),
            "type": ("info",),
            "severity": _ECS_SEVERITY[detection.severity],
            "id": detection_id,
            "dataset": "megalodon.detection",
            "ingested": _utc_timestamp(ingested_at),
        }),
        "source": _endpoint(detection.src_ip, event.src_port),
        "destination": _endpoint(detection.dst_ip, event.dst_port),
        "network": MappingProxyType({
            "transport": event.protocol.lower(),
            "bytes": event.byte_count,
        }),
        "message": detection.message,
        "rule": MappingProxyType({"id": detection.rule_id}),
        "megalodon": MappingProxyType(megalodon),
    })


def to_ocsf_record(
    event: PacketEvent, detection: DetectionResult, *,
    run_id: str, event_id: str, detection_id: str, source_kind: str,
    ingested_at: datetime, completeness: str = "complete",
) -> Mapping[str, Any]:
    """Project one accepted event/detection pair into one bounded OCSF record."""
    run_id = _logical_id(run_id)
    event_id = _logical_id(event_id)
    detection_id = _logical_id(detection_id)
    rule_id = _logical_id(detection.rule_id)
    source_kind = _source_kind(source_kind)
    completeness = _completeness(completeness)
    severity_id, severity_name = _OCSF_SEVERITY[detection.severity]

    unmapped: dict[str, Any] = {
        "schema_version": "megalodon-ocsf-profile-v1",
        "run_id": run_id,
        "event_id": event_id,
        "detection_id": detection_id,
        "rule_id": rule_id,
        "source_kind": source_kind,
        "recommendation": detection.recommendation,
        "byte_count": event.byte_count,
        "completeness": completeness,
        "projection_version": "1",
        "megalodon_activity": "detection",
    }
    if detection.suppressed_reason is not None:
        unmapped["suppressed_reason"] = detection.suppressed_reason

    return MappingProxyType({
        "class_uid": 4001,
        "class_name": "Network Activity",
        "category_uid": 4,
        "category_name": "Network Activity",
        "activity_id": 99,
        "activity_name": "Other",
        "severity_id": severity_id,
        "severity": severity_name,
        "time": _epoch_millis(detection.detected_at),
        "metadata": MappingProxyType({
            "version": "1.9.0",
            "product": MappingProxyType({"name": "MEGALODON", "vendor_name": "MEGALODON"}),
            "uid": detection_id,
        }),
        "src_endpoint": _endpoint(detection.src_ip, event.src_port),
        "dst_endpoint": _endpoint(detection.dst_ip, event.dst_port),
        "connection_info": MappingProxyType({"protocol_name": event.protocol.lower()}),
        "message": detection.message,
        "unmapped": MappingProxyType(unmapped),
    })


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _freeze(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_freeze(item) for item in value]
    return value


def _line_bytes(record: Mapping[str, Any]) -> bytes:
    plain = _freeze(record)
    return (json.dumps(plain, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def write_export(
    records: Sequence[Mapping[str, Any]], destination_path: str | os.PathLike[str], *, profile: str,
) -> Mapping[str, Any]:
    """Write an already-projected, bounded batch to one brand-new local file.

    Every record and the total byte ceiling are checked before any file is
    created: a rejected batch never creates or touches `destination_path`.
    The file is written with one buffered `write` plus `fsync`, so there is
    no partially written record for a mid-write failure to leave behind.
    """
    if profile not in PROFILES:
        _fail("INVALID_PROFILE")
    if len(records) > MAX_RECORDS:
        _fail("RECORD_LIMIT_EXCEEDED")

    lines = [_line_bytes(record) for record in records]
    payload = b"".join(lines)
    if len(payload) > MAX_OUTPUT_BYTES:
        _fail("OUTPUT_BYTES_LIMIT_EXCEEDED")

    destination = Path(os.fspath(destination_path))
    name = destination.name
    if not name or name in {".", ".."}:
        _fail("DESTINATION_UNSAFE")
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        parent_descriptor = os.open(destination.parent, flags)
    except OSError:
        _fail("DESTINATION_UNSAFE")
    try:
        write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            write_flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(name, write_flags, REQUIRED_MODE, dir_fd=parent_descriptor)
        except FileExistsError:
            _fail("DESTINATION_EXISTS")
        except OSError:
            _fail("IO_ERROR")
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError:
            _fail("IO_ERROR")
    finally:
        os.close(parent_descriptor)

    return MappingProxyType({
        "schema_version": "megalodon-siem-export-receipt-v1",
        "profile": profile,
        "record_count": len(records),
        "output_bytes": len(payload),
        "output_mode": "new_local_file_only",
        "network_delivery": False,
        "credentials": False,
    })
