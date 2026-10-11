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


def test_unrelated_entry_beside_the_path_is_not_a_source_change(tmp_path, monkeypatch):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    path, digest = _write(private / "context.json")
    read = os.read

    def read_with_ancestor_change(change):
        def wrapped(descriptor, size):
            change()
            return read(descriptor, size)
        return wrapped

    monkeypatch.setattr(threat_context.os, "read", read_with_ancestor_change(
        lambda: (tmp_path / "unrelated.txt").write_text("x")))
    threat_context.read_completed_bundle(path, digest)
    # An ancestor's mode is still part of its identity.
    monkeypatch.setattr(threat_context.os, "read", read_with_ancestor_change(lambda: private.chmod(0o750)))
    with pytest.raises(threat_context.ThreatContextError, match="SOURCE_CHANGED$"):
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


@pytest.mark.parametrize(
    "escape",
    ["\\ud800", "\\u202e", "\\u0085", "\\u009b", "\\u200b"],
    ids=["lone-surrogate", "bidi-override", "c1-next-line", "c1-csi", "zero-width-space"],
)
@pytest.mark.parametrize("field", ["name", "label", "hash-name", "hash-value"])
def test_surrogate_control_and_format_code_points_are_refused_as_text(tmp_path, escape, field):
    text = json.dumps(_bundle(), separators=(",", ":"))
    marker, replacement = {
        "name": ('"Synthetic producer"', f'"Synthetic{escape}producer"'),
        "label": ('"test-only"', f'"test{escape}only"'),
        "hash-name": ('"external_id":"fixture-1"', f'"external_id":"fixture-1","hashes":{{"SHA{escape}256":"00"}}'),
        "hash-value": ('"external_id":"fixture-1"', f'"external_id":"fixture-1","hashes":{{"SHA-256":"0{escape}0"}}'),
    }[field]
    assert text.count(marker) == 1
    path, digest = _write(tmp_path / "context.json", raw=text.replace(marker, replacement).encode())
    with pytest.raises(threat_context.ThreatContextError, match="TEXT$"):
        threat_context.read_completed_bundle(path, digest)


def test_normalized_output_is_measured_as_utf8_not_ascii_escapes(tmp_path, monkeypatch):
    bundle = _bundle()
    bundle["objects"][0]["name"] = "威胁情报报告" * 42
    bundle["objects"][0]["labels"] = ["威胁情报" * 60 + str(index) for index in range(32)]
    data = json.dumps(bundle, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    path, digest = _write(tmp_path / "context.json", raw=data)
    expected = sum(
        len(json.dumps(_plain(item), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        for item in threat_context.read_completed_bundle(path, digest)[0]
    )
    # Exactly at the ceiling the UTF-8 projection fits; \uXXXX escapes would not.
    monkeypatch.setattr(threat_context, "MAX_NORMALIZED_BYTES", expected)
    _, receipt = threat_context.read_completed_bundle(path, digest)
    assert receipt["normalized_context_bytes"] == expected
    monkeypatch.setattr(threat_context, "MAX_NORMALIZED_BYTES", expected - 1)
    with pytest.raises(threat_context.ThreatContextError, match="OUTPUT_LIMIT$"):
        threat_context.read_completed_bundle(path, digest)


def _structural_tokens(value) -> int:
    """Count opening brackets, commas, and colons outside strings."""
    if isinstance(value, dict):
        return 1 + len(value) + max(len(value) - 1, 0) + sum(map(_structural_tokens, value.values()))
    if isinstance(value, list):
        return 1 + max(len(value) - 1, 0) + sum(map(_structural_tokens, value))
    return 0


def test_json_structural_token_cap_refuses_before_parsing(tmp_path, monkeypatch):
    padded = _bundle()
    padded["objects"][0]["x_padding"] = [{} for _ in range(64)]
    path, digest = _write(tmp_path / "context.json", padded)
    tokens = _structural_tokens(padded)
    monkeypatch.setattr(threat_context, "MAX_JSON_TOKENS", tokens)
    assert threat_context.read_completed_bundle(path, digest)[1]["status"] == "complete"

    def parse_forbidden(*_args, **_kwargs):
        raise AssertionError("an over-cap bundle must be refused before json.loads")

    monkeypatch.setattr(threat_context, "MAX_JSON_TOKENS", tokens - 1)
    monkeypatch.setattr(threat_context.json, "loads", parse_forbidden)
    with pytest.raises(threat_context.ThreatContextError, match="TOKEN_LIMIT$"):
        threat_context.read_completed_bundle(path, digest)


def test_structural_scan_consults_the_deadline_while_scanning(monkeypatch):
    text = "[" + "0," * threat_context._SCAN_DEADLINE_INTERVAL + "0]"
    # The first check sees time left; a later in-scan check sees it expired.
    clock = iter((0.0,))
    monkeypatch.setattr(threat_context.time, "monotonic", lambda: next(clock, 16.0))
    with pytest.raises(threat_context.ThreatContextError, match="TIME_LIMIT$"):
        threat_context._scan_depth(text, 0.0)


@pytest.mark.parametrize(
    ("valid_from", "valid_until", "accepted"),
    [
        ("2026-09-17T12:00:00Z", "2026-09-17T12:00:00Z", False),
        ("2026-09-17T12:00:00.5Z", "2026-09-17T12:00:00.500000000Z", False),
        ("2026-09-17T12:00:00.0000009Z", "2026-09-17T12:00:00.0000001Z", False),
        ("2026-09-17T12:00:00.000000001Z", "2026-09-17T12:00:00Z", False),
        ("2026-09-17T12:00:00Z", "2026-09-17T12:00:00.000000001Z", True),
        ("2026-09-17T12:00:00.9Z", "2026-09-17T12:00:01Z", True),
    ],
)
def test_valid_until_must_be_strictly_later_at_full_precision(tmp_path, valid_from, valid_until, accepted):
    bundle = _bundle()
    bundle["objects"][2]["valid_from"] = valid_from
    bundle["objects"][2]["valid_until"] = valid_until
    path, digest = _write(tmp_path / "context.json", bundle)
    if accepted:
        objects, _ = threat_context.read_completed_bundle(path, digest)
        assert objects[2]["valid_until"] == valid_until
    else:
        with pytest.raises(threat_context.ThreatContextError, match="SCHEMA$"):
            threat_context.read_completed_bundle(path, digest)
