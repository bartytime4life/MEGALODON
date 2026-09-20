"""Contract and adversarial coverage for the Suricata 8.0.7 raw-EVE boundary."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import inspect
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
from types import MappingProxyType

import pytest
from jsonschema import Draft202012Validator

from megalodon.offline import common, suricata_consumer, suricata_eve
from megalodon.offline.suricata_eve import (
    PINNED_SURICATA_VERSION,
    PRODUCER_PROFILE,
    RawEveError,
    read_completed_raw_eve,
)


CONTRACT_ROOT = Path(__file__).parents[1] / "contracts" / "suricata-eve" / "v1" / "producer"
SCHEMA = json.loads((CONTRACT_ROOT / "schema.json").read_text(encoding="utf-8"))
ACCEPTED = json.loads((CONTRACT_ROOT / "fixtures" / "accepted.json").read_text(encoding="utf-8"))
REJECTED = json.loads((CONTRACT_ROOT / "fixtures" / "rejected.json").read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def unprivileged_runtime(monkeypatch):
    """Exercise parser contracts independently of the test runner's identity."""
    monkeypatch.setattr(suricata_eve, "require_unprivileged_linux", lambda: None)


@pytest.mark.parametrize("reason", ["NON_ROOT_REQUIRED", "CAPABILITY_FREE_PROCESS_REQUIRED"])
def test_native_admission_failure_precedes_source_access(monkeypatch, reason):
    def reject_runtime():
        raise common.OfflineError(reason)

    def unexpected_source_access(*_args, **_kwargs):
        pytest.fail("source access must follow native admission")

    monkeypatch.setattr(suricata_eve, "require_unprivileged_linux", reject_runtime)
    monkeypatch.setattr(suricata_eve.os, "open", unexpected_source_access)
    with pytest.raises(RawEveError) as caught:
        _read(Path("/not-opened/completed-eve.json"), "sha256:" + "a" * 64)
    assert caught.value.code == "SOURCE_PATH"


def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator({"$ref": f"#/$defs/{name}", "$defs": SCHEMA["$defs"]})


def _plain(value):
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def _minimal(**changes):
    value = {
        "timestamp": "2026-09-19T10:15:30.123456+0000",
        "event_type": "alert",
        "src_ip": "192.0.2.10",
        "src_port": 54321,
        "dest_ip": "198.51.100.20",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "action": "allowed", "gid": 1, "signature_id": 2100001,
            "rev": 2, "severity": 2,
        },
    }
    value.update(changes)
    return value


def _source(tmp_path: Path, records: list[dict] | None = None, raw: bytes | None = None):
    path = tmp_path / "completed-eve.json"
    if raw is None:
        raw = b"".join(
            (json.dumps(item, separators=(",", ":")) + "\n").encode("utf-8")
            for item in (records or [_minimal()])
        )
    path.write_bytes(raw)
    path.chmod(0o600)
    return path, f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _read(path: Path, digest: str, **changes):
    values = {
        "expected_digest": digest,
        "sensor_id": "sensor-a",
        "run_id": "run-a",
        "ruleset_id": "ruleset-a",
    }
    values.update(changes)
    return read_completed_raw_eve(str(path), **values)


@pytest.mark.parametrize("case", ACCEPTED, ids=lambda item: item["id"])
def test_accepted_contract_fixtures_validate(case) -> None:
    assert list(_validator("rawAlert").iter_errors(case["value"])) == []


@pytest.mark.parametrize("case", REJECTED, ids=lambda item: item["id"])
def test_rejected_contract_fixtures_fail_schema(case) -> None:
    assert list(_validator("rawAlert").iter_errors(case["value"]))


def test_admission_contract_pins_the_current_profile() -> None:
    value = {
        "producer_profile": PRODUCER_PROFILE,
        "declared_version": PINNED_SURICATA_VERSION,
        "expected_digest": "sha256:" + "0" * 64,
        "sensor_id": "sensor-a",
        "run_id": "run-a",
        "ruleset_id": "ruleset-a",
    }
    assert list(_validator("admission").iter_errors(value)) == []


def test_reader_returns_consumer_compatible_immutable_publication(tmp_path) -> None:
    second = _minimal(
        timestamp="2026-09-19T10:15:31.000000Z",
        src_ip="192.0.2.11",
        alert={
            "action": "blocked", "gid": 1, "signature_id": 2100002,
            "rev": 1, "severity": 1, "signature": "Bounded test",
        },
        flow_id=1676750115612680,
        community_id="1:hO+sN4H+MG5MY/8hIrXPqc4ZQz0=",
    )
    path, digest = _source(tmp_path, [_minimal(), second])

    publication = _read(path, digest)
    batch, receipt = publication
    assert type(batch) is tuple and len(batch) == 2
    assert all(isinstance(item, MappingProxyType) for item in batch)
    assert isinstance(receipt, MappingProxyType)
    assert receipt["record_count"] == 2
    assert receipt["producer_blocked_count"] == 1
    assert receipt["action_status"] == "not_attempted"
    assert [item["source_record_index"] for item in batch] == [1, 2]
    assert batch[0]["observed_at"] == "2026-09-19T10:15:30.123456Z"
    assert batch[1]["src_ip"] == "192.0.2.11"
    assert "flow_id" not in batch[1] and "community_id" not in batch[1]

    facts = suricata_consumer._validate_publication(publication)
    assert facts.record_count == 2
    assert facts.blocked_count == 1
    with pytest.raises(TypeError):
        batch[0]["src_ip"] = "203.0.113.1"


@pytest.mark.parametrize("case", REJECTED, ids=lambda item: item["id"])
def test_reader_rejects_forbidden_and_mixed_fixtures(tmp_path, case) -> None:
    path, digest = _source(tmp_path, [case["value"]])
    with pytest.raises(RawEveError) as caught:
        _read(path, digest)
    assert caught.value.code == case["code"]


def test_digest_and_version_are_checked_before_publication(tmp_path) -> None:
    path, digest = _source(tmp_path)
    with pytest.raises(RawEveError) as caught:
        _read(path, "sha256:" + "0" * 64)
    assert caught.value.code == "DIGEST"
    with pytest.raises(RawEveError) as caught:
        _read(path, digest, declared_version="8.0.6")
    assert caught.value.code == "PROFILE"


def test_duplicate_keys_floats_and_oversized_integers_fail_closed(tmp_path) -> None:
    duplicate = (
        b'{"timestamp":"2026-09-19T10:15:30Z","event_type":"alert",'
        b'"event_type":"alert","src_ip":"192.0.2.10","src_port":1,'
        b'"dest_ip":"198.51.100.20","dest_port":2,"proto":"TCP",'
        b'"alert":{"action":"allowed","gid":1,"signature_id":2,"rev":1,"severity":1}}\n'
    )
    path, digest = _source(tmp_path, raw=duplicate)
    with pytest.raises(RawEveError) as caught:
        _read(path, digest)
    assert caught.value.code == "DUPLICATE_KEY"

    for value in (1.25, 10**20):
        path, digest = _source(tmp_path, [_minimal(flow_id=value)])
        with pytest.raises(RawEveError) as caught:
            _read(path, digest)
        assert caught.value.code == "JSON_NUMBER"


def test_private_single_link_source_is_required(tmp_path) -> None:
    path, digest = _source(tmp_path)
    path.chmod(0o644)
    with pytest.raises(RawEveError) as caught:
        _read(path, digest)
    assert caught.value.code == "SOURCE_MODE"

    path.chmod(0o600)
    alias = tmp_path / "alias.json"
    os.link(path, alias)
    with pytest.raises(RawEveError) as caught:
        _read(path, digest)
    assert caught.value.code == "SOURCE_LINK"


def test_symlink_source_and_replayed_run_are_refused(tmp_path) -> None:
    path, digest = _source(tmp_path)
    link = tmp_path / "linked.json"
    link.symlink_to(path)
    with pytest.raises(RawEveError) as caught:
        _read(link, digest)
    assert caught.value.code == "SOURCE_SYMLINK"

    run_key = (
        "suricata", "suricata-eve-alert-v1", "8.0.7", "operator_declared",
        "sensor-a", "run-a", "ruleset-a", "operator_declared",
    )
    with pytest.raises(RawEveError) as caught:
        _read(path, digest, completed_run_keys={run_key})
    assert caught.value.code == "REPLAY"


def test_output_never_retains_raw_or_action_authority(tmp_path) -> None:
    event = _minimal(
        flow_id=1676750115612680,
        app_proto="tls",
        direction="to_server",
        pkt_src="wire/pcap",
        community_id="1:hO+sN4H+MG5MY/8hIrXPqc4ZQz0=",
    )
    path, digest = _source(tmp_path, [event])
    serialized = json.dumps(_plain(_read(path, digest)), sort_keys=True)
    for forbidden in (
        "payload", "packet", "flow_id", "community_id", "app_proto",
        "direction", "pkt_src", "source_path", "expected_digest",
    ):
        assert forbidden not in serialized
    assert '"action_status": "not_attempted"' in serialized


def test_reader_has_no_network_process_database_or_dashboard_surface(monkeypatch, tmp_path) -> None:
    path, digest = _source(tmp_path)

    def denied(*_args, **_kwargs):
        raise AssertionError("raw-EVE conversion must stay inert")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(sqlite3, "connect", denied)
    publication = _read(path, digest)
    assert publication[1]["durable_write_status"] == "not_attempted"

    source = inspect.getsource(read_completed_raw_eve)
    for forbidden in ("http", "urlopen", "requests", "subprocess", "sqlite", "dashboard", "firewall"):
        assert forbidden not in source.lower()
