"""Adversarial tests for the bounded offline STIX context reader."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess

import pytest

from megalodon import threat_context


BUNDLE_ID = "bundle--11111111-1111-4111-8111-111111111111"
IDENTITY_ID = "identity--22222222-2222-4222-8222-222222222222"
MARKING_ID = "marking-definition--33333333-3333-4333-8333-333333333333"
INDICATOR_ID = "indicator--44444444-4444-4444-8444-444444444444"


@pytest.fixture(autouse=True)
def admitted_runtime(monkeypatch):
    monkeypatch.setattr(threat_context, "require_unprivileged_linux", lambda: None)


def _bundle() -> dict:
    return {
        "type": "bundle",
        "id": BUNDLE_ID,
        "objects": [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": IDENTITY_ID,
                "created": "2026-09-17T12:00:00Z",
                "modified": "2026-09-17T12:00:00Z",
                "name": "Synthetic producer",
                "labels": ["test-only"],
                "external_references": [{
                    "source_name": "synthetic-corpus",
                    "external_id": "fixture-1",
                }],
            },
            {
                "type": "marking-definition",
                "spec_version": "2.1",
                "id": MARKING_ID,
                "created": "2026-09-17T12:00:00Z",
                "definition_type": "tlp",
                "definition": {"tlp": "amber"},
            },
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": INDICATOR_ID,
                "created_by_ref": IDENTITY_ID,
                "created": "2026-09-17T12:00:00Z",
                "modified": "2026-09-17T12:00:00Z",
                "valid_from": "2026-09-17T12:00:00Z",
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "pattern": "[ipv4-addr:value = '198.51.100.7']",
                "confidence": 40,
                "object_marking_refs": [MARKING_ID],
            },
        ],
    }


def _write(path: Path, bundle: dict | None = None, *, raw: bytes | None = None) -> tuple[Path, str]:
    data = raw if raw is not None else json.dumps(bundle or _bundle(), separators=(",", ":")).encode()
    path.write_bytes(data)
    path.chmod(0o600)
    return path, "sha256:" + hashlib.sha256(data).hexdigest()


def _plain(value):
    if hasattr(value, "items"):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def test_completed_bundle_returns_immutable_inert_context_and_receipt(tmp_path):
    path, digest = _write(tmp_path / "context.json")

    objects, receipt = threat_context.read_completed_bundle(path, digest)

    assert len(objects) == 3
    indicator = _plain(objects[2])
    assert indicator["pattern"] == "[ipv4-addr:value = '198.51.100.7']"
    assert indicator["object_marking_refs"] == [MARKING_ID]
    assert _plain(receipt) == {
        "schema_version": "megalodon-threat-context-reader-v1",
        "status": "complete",
        "bundle_id": BUNDLE_ID,
        "artifact_digest": digest,
        "object_count": 3,
        "object_types": {"identity": 1, "indicator": 1, "marking-definition": 1},
        "marking_definition_count": 1,
        "indicator_pattern_count": 1,
        "normalized_context_bytes": receipt["normalized_context_bytes"],
        "source_snapshot_status": "metadata_unchanged_not_atomic",
        "pattern_handling": "untrusted_text_never_execute",
        "runtime_fetch": False,
        "taxii": False,
        "attribution_authority": False,
        "detection_authority": False,
        "action_authority": "none",
        "persistence_status": "not_attempted",
    }
    assert 0 < receipt["normalized_context_bytes"] <= threat_context.MAX_NORMALIZED_BYTES
    with pytest.raises(TypeError):
        objects[2]["confidence"] = 100
    with pytest.raises(TypeError):
        receipt["status"] = "trusted"


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b"", "EMPTY_INPUT"),
        (b"\xef\xbb\xbf{}", "UTF8"),
        (b'{"type":"bundle","type":"bundle","id":"x","objects":[]}', "DUPLICATE_KEY"),
        (b'{"type":"bundle","id":"x","objects":[],"score":1.5}', "JSON_NUMBER"),
        (b"not-json", "JSON"),
    ],
)
def test_fixed_decode_failures_expose_no_path(tmp_path, raw, code):
    path, digest = _write(tmp_path / "context.json", raw=raw)
    with pytest.raises(threat_context.ThreatContextError) as caught:
        threat_context.read_completed_bundle(path, digest)
    assert str(caught.value) == f"THREAT_CONTEXT_READER_V1:{code}"
    assert str(path) not in str(caught.value)


def test_digest_depth_object_count_and_duplicate_identity_fail_closed(tmp_path, monkeypatch):
    path, digest = _write(tmp_path / "context.json")
    with pytest.raises(threat_context.ThreatContextError, match="DIGEST$"):
        threat_context.read_completed_bundle(path, "sha256:" + "0" * 64)

    nested = "{}"
    for _ in range(threat_context.MAX_NESTING_DEPTH + 1):
        nested = '{"x":' + nested + "}"
    path, digest = _write(tmp_path / "deep.json", raw=nested.encode())
    with pytest.raises(threat_context.ThreatContextError, match="DEPTH$"):
        threat_context.read_completed_bundle(path, digest)

    monkeypatch.setattr(threat_context, "MAX_OBJECTS", 2)
    path, digest = _write(tmp_path / "many.json")
    with pytest.raises(threat_context.ThreatContextError, match="OBJECT_LIMIT$"):
        threat_context.read_completed_bundle(path, digest)

    monkeypatch.setattr(threat_context, "MAX_OBJECTS", 4_096)
    duplicate = _bundle()
    duplicate["objects"].append(dict(duplicate["objects"][0]))
    path, digest = _write(tmp_path / "duplicate.json", duplicate)
    with pytest.raises(threat_context.ThreatContextError, match="DUPLICATE_OBJECT$"):
        threat_context.read_completed_bundle(path, digest)


def test_schema_and_marking_references_are_closed(tmp_path):
    cases = []
    bad_id = _bundle()
    bad_id["objects"][2]["id"] = "indicator--not-a-uuid"
    cases.append((bad_id, "SCHEMA"))
    missing_marking = _bundle()
    missing_marking["objects"][2]["object_marking_refs"] = [
        "marking-definition--55555555-5555-4555-8555-555555555555"
    ]
    cases.append((missing_marking, "MARKING"))
    granular = _bundle()
    granular["objects"][2]["granular_markings"] = []
    cases.append((granular, "MARKING"))
    long_pattern = _bundle()
    long_pattern["objects"][2]["pattern"] = "x" * (threat_context.MAX_PATTERN_CHARS + 1)
    cases.append((long_pattern, "TEXT"))

    for index, (bundle, code) in enumerate(cases):
        path, digest = _write(tmp_path / f"case-{index}.json", bundle)
        with pytest.raises(threat_context.ThreatContextError, match=f"{code}$"):
            threat_context.read_completed_bundle(path, digest)


def test_file_policy_rejects_relative_public_linked_symlink_and_fifo(tmp_path):
    path, digest = _write(tmp_path / "context.json")
    with pytest.raises(threat_context.ThreatContextError, match="SOURCE_PATH$"):
        threat_context.read_completed_bundle("context.json", digest)

    path.chmod(0o644)
    with pytest.raises(threat_context.ThreatContextError, match="SOURCE_MODE$"):
        threat_context.read_completed_bundle(path, digest)

    target, digest = _write(tmp_path / "target.json")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(threat_context.ThreatContextError, match="SOURCE_SYMLINK$"):
        threat_context.read_completed_bundle(link, digest)

    linked = tmp_path / "linked.json"
    os.link(target, linked)
    with pytest.raises(threat_context.ThreatContextError, match="SOURCE_LINK$"):
        threat_context.read_completed_bundle(target, digest)

    fifo = tmp_path / "context.fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(threat_context.ThreatContextError, match="SOURCE_TYPE$"):
        threat_context.read_completed_bundle(fifo, digest)


def test_owner_change_deadline_and_output_limit_refuse_before_success(tmp_path, monkeypatch):
    path, digest = _write(tmp_path / "context.json")
    monkeypatch.setattr(threat_context.os, "geteuid", lambda: os.stat(path).st_uid + 1)
    with pytest.raises(threat_context.ThreatContextError, match="SOURCE_OWNER$"):
        threat_context.read_completed_bundle(path, digest)

    monkeypatch.setattr(threat_context.os, "geteuid", lambda: os.stat(path).st_uid)
    original = threat_context._verify_identities
    monkeypatch.setattr(
        threat_context,
        "_verify_identities",
        lambda descriptors, expected: (_ for _ in ()).throw(
            threat_context.ThreatContextError("SOURCE_CHANGED")
        ),
    )
    with pytest.raises(threat_context.ThreatContextError, match="SOURCE_CHANGED$"):
        threat_context.read_completed_bundle(path, digest)
    monkeypatch.setattr(threat_context, "_verify_identities", original)

    clock = iter((0.0, 0.0, 16.0))
    monkeypatch.setattr(threat_context.time, "monotonic", lambda: next(clock, 16.0))
    with pytest.raises(threat_context.ThreatContextError, match="TIME_LIMIT$"):
        threat_context.read_completed_bundle(path, digest)

    monkeypatch.setattr(threat_context.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(threat_context, "MAX_NORMALIZED_BYTES", 1)
    with pytest.raises(threat_context.ThreatContextError, match="OUTPUT_LIMIT$"):
        threat_context.read_completed_bundle(path, digest)


def test_reader_has_no_network_subprocess_persistence_or_pattern_execution(tmp_path, monkeypatch):
    path, digest = _write(tmp_path / "context.json")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("offline context must not perform external work")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    objects, receipt = threat_context.read_completed_bundle(path, digest)
    assert objects[2]["pattern"] == "[ipv4-addr:value = '198.51.100.7']"
    assert receipt["runtime_fetch"] is receipt["taxii"] is False
    assert receipt["persistence_status"] == "not_attempted"


def test_source_type_rejection_does_not_block_regular_file(tmp_path):
    path, digest = _write(tmp_path / "context.json")
    assert stat.S_ISREG(path.stat().st_mode)
    assert threat_context.read_completed_bundle(path, digest)[1]["status"] == "complete"
