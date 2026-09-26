"""Tests for the bounded SIEM projection/writer engine (external-exchange v1)."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import stat
import subprocess

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from megalodon.models import DetectionResult, PacketEvent
from megalodon import siem_export
from megalodon.siem_export import (
    MAX_OUTPUT_BYTES,
    MAX_RECORDS,
    SiemExportError,
    to_ecs_record,
    to_ocsf_record,
    write_export,
)

CONTRACT_ROOT = Path(__file__).parents[1] / "contracts" / "external-exchange" / "v1"
SCHEMA = json.loads((CONTRACT_ROOT / "schema.json").read_text(encoding="utf-8"))
RECORD_FIXTURES = CONTRACT_ROOT / "fixtures" / "siem-records"


def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(
        {"$ref": f"#/$defs/{name}", "$defs": SCHEMA["$defs"]}, format_checker=FormatChecker(),
    )


def _as_plain(value):
    if isinstance(value, Mapping):
        return {key: _as_plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_as_plain(item) for item in value]
    return value


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def no_network_or_process(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("SIEM export must remain inert")
    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)


def _sample_event(**overrides) -> PacketEvent:
    defaults = dict(
        observed_at=datetime(2026, 9, 19, 12, 0, 0, tzinfo=timezone.utc),
        src_ip="10.0.0.5", dst_ip="10.0.0.9", protocol="TCP",
        src_port=51000, dst_port=443, byte_count=1500,
    )
    defaults.update(overrides)
    return PacketEvent(**defaults)


def _sample_detection(**overrides) -> DetectionResult:
    defaults = dict(
        detected_at=datetime(2026, 9, 19, 12, 0, 1, tzinfo=timezone.utc),
        rule_id="SYN_FLOOD", severity="HIGH", src_ip="10.0.0.5", dst_ip="10.0.0.9",
        message="High rate of SYN packets observed", recommendation="ALERT",
    )
    defaults.update(overrides)
    return DetectionResult(**defaults)


# --- schema-level fixture coverage ------------------------------------------

@pytest.mark.parametrize("path", sorted((RECORD_FIXTURES / "accepted").glob("*.json")), ids=lambda p: p.name)
def test_accepted_record_fixtures_validate(path: Path) -> None:
    case = _load(path)
    _validator(case["schema"]).validate(case["value"])


@pytest.mark.parametrize("path", sorted((RECORD_FIXTURES / "rejected").glob("*.json")), ids=lambda p: p.name)
def test_rejected_record_fixtures_fail_closed(path: Path) -> None:
    case = _load(path)
    with pytest.raises(Exception) as caught:
        _validator(case["schema"]).validate(case["value"])
    assert caught.type.__module__.startswith("jsonschema")


# --- projection functions ----------------------------------------------------

def test_ecs_projection_matches_the_contract_schema() -> None:
    record = to_ecs_record(
        _sample_event(), _sample_detection(),
        run_id="run-1", event_id="event-1", detection_id="detection-1", source_kind="sample",
        ingested_at=datetime(2026, 9, 19, 12, 0, 5, tzinfo=timezone.utc),
    )
    errors = list(_validator("ecsRecord").iter_errors(_as_plain(record)))
    assert errors == []


def test_ocsf_projection_matches_the_contract_schema() -> None:
    record = to_ocsf_record(
        _sample_event(), _sample_detection(),
        run_id="run-1", event_id="event-1", detection_id="detection-1", source_kind="sample",
        ingested_at=datetime(2026, 9, 19, 12, 0, 5, tzinfo=timezone.utc),
    )
    errors = list(_validator("ocsfRecord").iter_errors(_as_plain(record)))
    assert errors == []


def test_neither_profile_ever_contains_event_original_or_payload() -> None:
    ecs = _as_plain(to_ecs_record(
        _sample_event(), _sample_detection(), run_id="r", event_id="e", detection_id="d", source_kind="sample",
        ingested_at=datetime.now(timezone.utc),
    ))
    ocsf = _as_plain(to_ocsf_record(
        _sample_event(), _sample_detection(), run_id="r", event_id="e", detection_id="d", source_kind="sample",
        ingested_at=datetime.now(timezone.utc),
    ))
    serialized = json.dumps(ecs) + json.dumps(ocsf)
    for forbidden in ("original", "payload", "raw_data", "endpoint_url", "credential", "token"):
        assert forbidden not in serialized


@pytest.mark.parametrize("severity,expected_ecs,expected_ocsf", [
    ("LOW", 25, (2, "Low")),
    ("MEDIUM", 50, (3, "Medium")),
    ("HIGH", 75, (4, "High")),
    ("CRITICAL", 99, (5, "Critical")),
])
def test_severity_mapping_is_monotonic_and_closed(severity, expected_ecs, expected_ocsf) -> None:
    detection = _sample_detection(severity=severity)
    ecs = to_ecs_record(
        _sample_event(), detection, run_id="r", event_id="e", detection_id="d", source_kind="sample",
        ingested_at=datetime.now(timezone.utc),
    )
    ocsf = to_ocsf_record(
        _sample_event(), detection, run_id="r", event_id="e", detection_id="d", source_kind="sample",
        ingested_at=datetime.now(timezone.utc),
    )
    assert ecs["event"]["severity"] == expected_ecs
    assert (ocsf["severity_id"], ocsf["severity"]) == expected_ocsf


def test_suppressed_reason_carries_through_when_present() -> None:
    detection = _sample_detection(suppressed_reason="cooldown active")
    ecs = to_ecs_record(
        _sample_event(), detection, run_id="r", event_id="e", detection_id="d", source_kind="sample",
        ingested_at=datetime.now(timezone.utc),
    )
    ocsf = to_ocsf_record(
        _sample_event(), detection, run_id="r", event_id="e", detection_id="d", source_kind="sample",
        ingested_at=datetime.now(timezone.utc),
    )
    assert ecs["megalodon"]["suppressed_reason"] == "cooldown active"
    assert ocsf["unmapped"]["suppressed_reason"] == "cooldown active"
    assert "suppressed_reason" not in to_ecs_record(
        _sample_event(), _sample_detection(), run_id="r", event_id="e", detection_id="d", source_kind="sample",
        ingested_at=datetime.now(timezone.utc),
    )["megalodon"]


@pytest.mark.parametrize("bad_id", ["", "has spaces", "..", "a" * 129])
def test_invalid_identifiers_are_rejected(bad_id) -> None:
    with pytest.raises(SiemExportError):
        to_ecs_record(
            _sample_event(), _sample_detection(), run_id=bad_id, event_id="e", detection_id="d", source_kind="sample",
            ingested_at=datetime.now(timezone.utc),
        )


def test_invalid_source_kind_is_rejected() -> None:
    with pytest.raises(SiemExportError) as caught:
        to_ecs_record(
            _sample_event(), _sample_detection(), run_id="r", event_id="e", detection_id="d",
            source_kind="webhook", ingested_at=datetime.now(timezone.utc),
        )
    assert caught.value.code == "INVALID_SOURCE_KIND"


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(SiemExportError):
        to_ecs_record(
            _sample_event(), _sample_detection(), run_id="r", event_id="e", detection_id="d", source_kind="sample",
            ingested_at=datetime(2026, 9, 19, 12, 0, 0),  # no tzinfo
        )


# --- write_export -------------------------------------------------------------

def test_write_export_produces_one_jsonl_record_per_line(tmp_path) -> None:
    records = [
        to_ecs_record(
            _sample_event(), _sample_detection(), run_id="r", event_id=f"e-{i}", detection_id=f"d-{i}", source_kind="sample",
            ingested_at=datetime.now(timezone.utc),
        )
        for i in range(5)
    ]
    destination = tmp_path / "export.jsonl"
    receipt = write_export(records, destination, profile="ecs-9.5.0")
    assert receipt["record_count"] == 5
    assert receipt["network_delivery"] is False
    assert receipt["credentials"] is False
    lines = destination.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 5
    assert receipt["output_bytes"] == destination.stat().st_size
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert list(tmp_path.iterdir()) == [destination]
    for line in lines:
        parsed = json.loads(line)
        _validator("ecsRecord").validate(parsed)


def test_write_export_refuses_an_existing_destination(tmp_path) -> None:
    destination = tmp_path / "export.jsonl"
    destination.write_text("not an export")
    with pytest.raises(SiemExportError) as caught:
        write_export([], destination, profile="ecs-9.5.0")
    assert caught.value.code == "DESTINATION_EXISTS"
    assert destination.read_text() == "not an export"  # untouched


@pytest.mark.parametrize("failure", ["write", "short_write", "flush", "close", "file_sync", "publish"])
def test_failed_export_never_publishes_partial_output(tmp_path, monkeypatch, failure) -> None:
    destination = tmp_path / "export.jsonl"
    original_fdopen = os.fdopen

    class FaultyStream:
        def __init__(self, descriptor, mode):
            self.stream = original_fdopen(descriptor, mode)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.stream.close()
            if failure == "close":
                raise OSError("synthetic close failure")

        def write(self, content):
            if failure in {"write", "short_write"}:
                count = self.stream.write(content[:5])
                self.stream.flush()
                if failure == "short_write":
                    return count
                raise OSError("synthetic partial write")
            return self.stream.write(content)

        def flush(self):
            if failure == "flush":
                raise OSError("synthetic flush failure")
            self.stream.flush()

        def fileno(self):
            return self.stream.fileno()

    def denied(*_args, **_kwargs):
        raise OSError("synthetic I/O failure")

    monkeypatch.setattr(siem_export.os, "fdopen", FaultyStream)
    if failure == "file_sync":
        monkeypatch.setattr(siem_export.os, "fsync", denied)
    if failure == "publish":
        monkeypatch.setattr(siem_export.os, "link", denied)
    with pytest.raises(SiemExportError) as caught:
        write_export([{"synthetic": "complete record"}], destination, profile="ecs-9.5.0")
    assert caught.value.code == "IO_ERROR"
    assert not destination.exists()
    assert list(tmp_path.iterdir()) == []


def test_export_is_complete_and_synced_before_publication(tmp_path, monkeypatch) -> None:
    destination = tmp_path / "export.jsonl"
    expected = b'{"synthetic":"complete record"}\n'
    original_link, original_fsync = os.link, os.fsync
    synced = []

    def sync(descriptor):
        synced.append("directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file")
        return original_fsync(descriptor)

    def publish(source, target, **kwargs):
        assert not destination.exists()
        assert (tmp_path / source).read_bytes() == expected
        assert stat.S_IMODE((tmp_path / source).stat().st_mode) == 0o600
        assert synced == ["file"]
        return original_link(source, target, **kwargs)

    monkeypatch.setattr(siem_export.os, "fsync", sync)
    monkeypatch.setattr(siem_export.os, "link", publish)
    write_export([{"synthetic": "complete record"}], destination, profile="ecs-9.5.0")
    assert synced == ["file", "directory"]
    assert destination.read_bytes() == expected
    assert list(tmp_path.iterdir()) == [destination]


@pytest.mark.parametrize("kind", ["file", "symlink", "directory"])
def test_destination_created_during_publication_is_preserved(tmp_path, monkeypatch, kind) -> None:
    destination = tmp_path / "export.jsonl"
    original_link = os.link

    def publish(source, target, **kwargs):
        if kind == "file":
            destination.write_bytes(b"other writer")
        elif kind == "symlink":
            destination.symlink_to("other-writer.jsonl")
        else:
            destination.mkdir()
        return original_link(source, target, **kwargs)

    monkeypatch.setattr(siem_export.os, "link", publish)
    with pytest.raises(SiemExportError) as caught:
        write_export([{"synthetic": "complete record"}], destination, profile="ecs-9.5.0")
    assert caught.value.code == "DESTINATION_EXISTS"
    if kind == "file":
        assert destination.read_bytes() == b"other writer"
    elif kind == "symlink":
        assert destination.is_symlink() and os.readlink(destination) == "other-writer.jsonl"
    else:
        assert destination.is_dir() and list(destination.iterdir()) == []
    assert list(tmp_path.iterdir()) == [destination]


def test_directory_sync_failure_retains_complete_export_without_success(tmp_path, monkeypatch) -> None:
    destination = tmp_path / "export.jsonl"
    original_fsync = os.fsync

    def sync(descriptor):
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("synthetic directory sync failure")
        return original_fsync(descriptor)

    monkeypatch.setattr(siem_export.os, "fsync", sync)
    with pytest.raises(SiemExportError) as caught:
        write_export([{"synthetic": "complete record"}], destination, profile="ecs-9.5.0")
    assert caught.value.code == "IO_ERROR"
    assert destination.read_bytes() == b'{"synthetic":"complete record"}\n'
    assert list(tmp_path.iterdir()) == [destination]


def test_temporary_cleanup_failure_is_bounded_and_keeps_final_absent(tmp_path, monkeypatch) -> None:
    destination = tmp_path / "export.jsonl"
    attempted = []

    def failed_sync(*_):
        raise OSError("synthetic file sync failure")

    def failed_cleanup(name, **_kwargs):
        attempted.append(name)
        raise OSError("synthetic cleanup failure")

    monkeypatch.setattr(siem_export.os, "fsync", failed_sync)
    monkeypatch.setattr(siem_export.os, "unlink", failed_cleanup)
    with pytest.raises(SiemExportError) as caught:
        write_export([{"synthetic": "complete record"}], destination, profile="ecs-9.5.0")
    assert caught.value.code == "IO_ERROR"
    assert caught.value.__notes__ == ["SIEM export temporary cleanup failed"]
    assert not destination.exists()
    assert len(attempted) == 1
    temporary, = tmp_path.iterdir()
    assert temporary.name == attempted[0] and temporary.name.endswith(".tmp")
    assert stat.S_IMODE(temporary.stat().st_mode) == 0o600


def test_shared_writable_parent_is_refused_before_creating_files(tmp_path) -> None:
    tmp_path.chmod(0o777)
    with pytest.raises(SiemExportError) as caught:
        write_export([], tmp_path / "export.jsonl", profile="ecs-9.5.0")
    assert caught.value.code == "DESTINATION_UNSAFE"
    assert list(tmp_path.iterdir()) == []


def test_trusted_sticky_parent_still_accepts_an_export(tmp_path) -> None:
    tmp_path.chmod(0o1777)
    destination = tmp_path / "export.jsonl"
    assert write_export([], destination, profile="ecs-9.5.0")["record_count"] == 0
    assert destination.read_bytes() == b""
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_temporary_name_collision_never_removes_existing_file(tmp_path, monkeypatch) -> None:
    identifier = siem_export.uuid.UUID(int=0)
    monkeypatch.setattr(siem_export.uuid, "uuid4", lambda: identifier)
    existing = tmp_path / f".megalodon-siem-{identifier.hex}.tmp"
    existing.write_bytes(b"another export")
    with pytest.raises(SiemExportError) as caught:
        write_export([], tmp_path / "export.jsonl", profile="ecs-9.5.0")
    assert caught.value.code == "IO_ERROR"
    assert existing.read_bytes() == b"another export"
    assert list(tmp_path.iterdir()) == [existing]


def test_stream_open_failure_closes_descriptor_and_cleans_temporary(tmp_path, monkeypatch) -> None:
    opened = []

    def failed_open(descriptor, _mode):
        opened.append(descriptor)
        raise OSError("synthetic stream open failure")

    monkeypatch.setattr(siem_export.os, "fdopen", failed_open)
    with pytest.raises(SiemExportError) as caught:
        write_export([], tmp_path / "export.jsonl", profile="ecs-9.5.0")
    assert caught.value.code == "IO_ERROR"
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])
    assert list(tmp_path.iterdir()) == []


def test_record_limit_exceeded_creates_no_file(tmp_path) -> None:
    destination = tmp_path / "export.jsonl"
    oversized = [{"x": i} for i in range(MAX_RECORDS + 1)]
    with pytest.raises(SiemExportError) as caught:
        write_export(oversized, destination, profile="ecs-9.5.0")
    assert caught.value.code == "RECORD_LIMIT_EXCEEDED"
    assert not destination.exists()


def test_output_bytes_limit_exceeded_creates_no_file(tmp_path) -> None:
    destination = tmp_path / "export.jsonl"
    big_record = {"padding": "x" * 5000}
    records = [big_record] * (MAX_OUTPUT_BYTES // len(json.dumps(big_record)) + 10)
    with pytest.raises(SiemExportError) as caught:
        write_export(records, destination, profile="ecs-9.5.0")
    assert caught.value.code == "OUTPUT_BYTES_LIMIT_EXCEEDED"
    assert not destination.exists()


@pytest.mark.parametrize("record", [
    {"value": float("nan")},
    {"value": float("inf")},
    {1: "integer key"},
    {"mixed": {1: "integer key", "name": "string key"}},
    ["not a record"],
])
def test_invalid_jsonl_record_creates_no_file(tmp_path, record) -> None:
    destination = tmp_path / "export.jsonl"
    with pytest.raises(SiemExportError) as caught:
        write_export([{"valid": True}, record], destination, profile="ecs-9.5.0")
    assert caught.value.code == "INVALID_RECORD"
    assert list(tmp_path.iterdir()) == []


def test_cyclic_record_creates_no_file(tmp_path) -> None:
    record = {}
    record["self"] = record
    destination = tmp_path / "export.jsonl"
    with pytest.raises(SiemExportError) as caught:
        write_export([record], destination, profile="ecs-9.5.0")
    assert caught.value.code == "INVALID_RECORD"
    assert list(tmp_path.iterdir()) == []


def test_invalid_profile_is_rejected(tmp_path) -> None:
    with pytest.raises(SiemExportError) as caught:
        write_export([], tmp_path / "export.jsonl", profile="splunk-hec")
    assert caught.value.code == "INVALID_PROFILE"


def test_symlinked_destination_parent_is_refused(tmp_path) -> None:
    import os
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    link_dir = tmp_path / "link_dir"
    os.symlink(real_dir, link_dir)
    with pytest.raises(SiemExportError) as caught:
        write_export([], link_dir / "export.jsonl", profile="ecs-9.5.0")
    assert caught.value.code == "DESTINATION_UNSAFE"


def test_engine_exposes_no_delivery_or_credential_surface() -> None:
    import megalodon.siem_export as module

    forbidden = ("deliver", "notify", "send", "endpoint", "socket", "http", "credential", "token")
    public_names = [name for name in dir(module) if not name.startswith("_")]
    for name in public_names:
        lowered = name.lower()
        assert not any(term in lowered for term in forbidden), name
