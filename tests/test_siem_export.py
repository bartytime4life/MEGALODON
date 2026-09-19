"""Tests for the bounded SIEM projection/writer engine (external-exchange v1)."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import subprocess

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from megalodon.models import DetectionResult, PacketEvent
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
