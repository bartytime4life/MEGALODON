"""Runtime tests for the bounded, file-only Suricata reader."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import stat
import subprocess

import pytest

from megalodon.offline import suricata


ROOT = Path(__file__).parents[1] / "contracts" / "suricata-eve" / "v1"
CASES = json.loads((ROOT / "fixtures" / "accepted.json").read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def unprivileged_runtime(monkeypatch):
    monkeypatch.setattr(suricata, "require_unprivileged_linux", lambda: None)


def _write(path: Path, values: list[dict], *, terminator: bytes = b"\n") -> Path:
    raw = terminator.join(
        json.dumps(value, separators=(",", ":")).encode("utf-8") for value in values
    ) + terminator
    path.write_bytes(raw)
    path.chmod(0o600)
    return path


def _plain(value):
    if hasattr(value, "items"):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def _run_key(source: dict[str, str]):
    return tuple(source[key] for key in (
        "engine", "adapter_profile", "declared_version", "version_basis",
        "sensor_id", "run_id", "ruleset_id", "ruleset_basis",
    ))


def test_completed_file_returns_exact_immutable_batch_and_receipt(tmp_path):
    selected = CASES[:2]
    path = _write(tmp_path / "alerts.jsonl", [case["input"] for case in selected])

    batch, receipt = suricata.read_completed_file(str(path))

    assert [_plain(item) for item in batch] == [case["normalized"] for case in selected]
    assert _plain(receipt) == {
        "schema_version": "suricata-eve-reader-receipt-v1",
        "reader_policy_version": "suricata-eve-reader-policy-v1",
        "status": "complete",
        "run_identity": selected[0]["input"]["source"],
        "record_count": 2,
        "normalized_alert_count": 2,
        "producer_blocked_count": 1,
        "normalized_batch_bytes": sum(len(json.dumps(
            case["normalized"], sort_keys=True, separators=(",", ":")
        ).encode("utf-8")) for case in selected),
        "count_unit": "alert",
        "action_status": "not_attempted",
        "durable_write_status": "not_attempted",
        "source_snapshot_status": "metadata_unchanged_not_atomic",
        "replay_status": "fresh",
    }
    with pytest.raises(TypeError):
        batch[0]["src_ip"] = "203.0.113.1"
    with pytest.raises(TypeError):
        receipt["status"] = "partial"


def test_final_unterminated_record_is_accepted(tmp_path):
    value = CASES[0]["input"]
    path = tmp_path / "alerts.jsonl"
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o400)
    batch, receipt = suricata.read_completed_file(str(path))
    assert len(batch) == receipt["record_count"] == 1


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b"", "EMPTY_INPUT"),
        (b"\n", "EMPTY_RECORD"),
        (b"{}\r", "FRAMING"),
        (b'{"value":"line\nbreak"}\n', "FRAMING"),
        (b"\xef\xbb\xbf{}\n", "UTF8"),
        (b'{"schema_version":1,"schema_version":2}\n', "DUPLICATE_KEY"),
        (b'{"value":1.2}\n', "JSON_NUMBER"),
        (b'{"value":{"a":{"b":{"c":{"d":1}}}}}\n', "DEPTH"),
        (b"not-json\n", "JSON"),
    ],
)
def test_fixed_stream_failures_publish_nothing(tmp_path, raw, code):
    path = tmp_path / "alerts.jsonl"
    path.write_bytes(raw)
    path.chmod(0o600)
    with pytest.raises(suricata.ReaderError) as caught:
        suricata.read_completed_file(str(path))
    assert str(caught.value) == f"SURICATA_READER_V1:{code}"
    assert str(path) not in str(caught.value)


def test_sequence_run_identity_and_replay_fail_closed(tmp_path):
    first = CASES[0]["input"]
    second = json.loads(json.dumps(CASES[1]["input"]))
    second["source_record_index"] = 3
    path = _write(tmp_path / "sequence.jsonl", [first, second])
    with pytest.raises(suricata.ReaderError, match="RECORD_SEQUENCE$"):
        suricata.read_completed_file(str(path))

    second["source_record_index"] = 2
    second["source"]["run_id"] = "different-run"
    path = _write(tmp_path / "identity.jsonl", [first, second])
    with pytest.raises(suricata.ReaderError, match="RUN_IDENTITY$"):
        suricata.read_completed_file(str(path))

    path = _write(tmp_path / "replay.jsonl", [first])
    replay_view = frozenset({_run_key(first["source"])})
    with pytest.raises(suricata.ReaderError, match="REPLAY$"):
        suricata.read_completed_file(str(path), completed_run_keys=replay_view)


def test_file_policy_rejects_mode_symlink_and_fifo(tmp_path):
    path = _write(tmp_path / "mode.jsonl", [CASES[0]["input"]])
    path.chmod(0o644)
    with pytest.raises(suricata.ReaderError, match="SOURCE_MODE$"):
        suricata.read_completed_file(str(path))

    target = _write(tmp_path / "target.jsonl", [CASES[0]["input"]])
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)
    with pytest.raises(suricata.ReaderError, match="SOURCE_SYMLINK$"):
        suricata.read_completed_file(str(link))

    real_directory = tmp_path / "real"
    real_directory.mkdir()
    nested = _write(real_directory / "alerts.jsonl", [CASES[0]["input"]])
    linked_directory = tmp_path / "linked"
    linked_directory.symlink_to(real_directory, target_is_directory=True)
    with pytest.raises(suricata.ReaderError, match="SOURCE_SYMLINK$"):
        suricata.read_completed_file(str(linked_directory / nested.name))

    fifo = tmp_path / "alerts.fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(suricata.ReaderError, match="SOURCE_TYPE$"):
        suricata.read_completed_file(str(fifo))

    unix_socket = tmp_path / "alerts.sock"
    os.mknod(unix_socket, stat.S_IFSOCK | 0o600)
    with pytest.raises(suricata.ReaderError, match="SOURCE_TYPE$"):
        suricata.read_completed_file(str(unix_socket))


def test_file_and_record_budgets_fail_before_decoding(tmp_path):
    oversized_file = tmp_path / "oversized.jsonl"
    with oversized_file.open("wb") as stream:
        stream.truncate(suricata.MAX_TOTAL_BYTES + 1)
    oversized_file.chmod(0o600)
    with pytest.raises(suricata.ReaderError, match="TOTAL_BYTES$"):
        suricata.read_completed_file(str(oversized_file))

    oversized_record = tmp_path / "record.jsonl"
    oversized_record.write_bytes(b"a" * (suricata.MAX_RECORD_BYTES + 1))
    oversized_record.chmod(0o600)
    with pytest.raises(suricata.ReaderError, match="RECORD_BYTES$"):
        suricata.read_completed_file(str(oversized_record))


def test_owner_and_replay_view_types_are_closed(tmp_path, monkeypatch):
    path = _write(tmp_path / "alerts.jsonl", [CASES[0]["input"]])
    monkeypatch.setattr(suricata.os, "geteuid", lambda: os.stat(path).st_uid + 1)
    with pytest.raises(suricata.ReaderError, match="SOURCE_OWNER$"):
        suricata.read_completed_file(str(path))

    monkeypatch.setattr(suricata.os, "geteuid", lambda: os.stat(path).st_uid)
    with pytest.raises(suricata.ReaderError, match="REPLAY$"):
        suricata.read_completed_file(str(path), completed_run_keys=[])


def test_post_read_change_and_deadline_fail_before_publication(tmp_path, monkeypatch):
    path = _write(tmp_path / "alerts.jsonl", [CASES[0]["input"]])
    original = suricata._verify_identities
    calls = 0

    def changed(descriptors, expected):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise suricata.ReaderError("SOURCE_CHANGED")
        original(descriptors, expected)

    monkeypatch.setattr(suricata, "_verify_identities", changed)
    with pytest.raises(suricata.ReaderError, match="SOURCE_CHANGED$"):
        suricata.read_completed_file(str(path))

    ticks = iter((0.0, 31.0))
    monkeypatch.setattr(suricata.time, "monotonic", lambda: next(ticks))
    with pytest.raises(suricata.ReaderError, match="TIME_LIMIT$"):
        suricata.read_completed_file(str(path))


def test_reader_never_opens_network_or_launches_process(tmp_path, monkeypatch):
    path = _write(tmp_path / "alerts.jsonl", [CASES[0]["input"]])

    def denied(*args, **kwargs):
        raise AssertionError("runtime reader must not use network or processes")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    batch, receipt = suricata.read_completed_file(str(path))
    assert len(batch) == receipt["record_count"] == 1
