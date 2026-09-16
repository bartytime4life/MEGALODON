"""Bounded, side-effect-free Suricata projection acceptance tests."""

from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import socket
import sqlite3
import subprocess

import pytest

from megalodon import suricata_projection as projection, suricata_store
from megalodon.offline import suricata, suricata_consumer


CASES = json.loads((
    Path(__file__).parents[1] / "contracts/suricata-eve/v1/fixtures/accepted.json"
).read_text())


@pytest.fixture(autouse=True)
def isolated_runtime(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("projection cannot invoke network or subprocesses")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(suricata, "require_unprivileged_linux", lambda: None)


def _store(tmp_path):
    path = tmp_path / "store/suricata.db"
    suricata_store.initialize_suricata_store(path)
    return path


def _commit(tmp_path, path, run_id="fixture-run-a", count=2):
    records = []
    for index in range(count):
        value = deepcopy(CASES[index % 2]["input"])
        value["source"]["run_id"] = run_id
        value["source_record_index"] = index + 1
        records.append(value)
    source = tmp_path / f"{run_id}.jsonl"
    source.write_text("".join(json.dumps(value) + "\n" for value in records))
    source.chmod(0o600)
    publication = suricata.read_completed_file(str(source))
    result = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id=f"attempt-{run_id}",
    )
    assert result["status"] == "committed"


def _mutate(path, sql, parameters=()):
    with sqlite3.connect(path) as connection:
        connection.execute(sql, parameters)


def _assert_refusal(result, code=None):
    assert result["status"] == "unavailable"
    assert result["failure_code"]
    if code is not None:
        assert result["failure_code"] == code
    assert result["summary"] is None
    assert result["recent_runs"] == []
    assert result["recent_alerts"] == []
    assert result["action_status"] == "not_attempted"


def test_unconfigured_does_not_open_store_or_require_privilege(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("unconfigured projection must do no work")

    monkeypatch.setattr(projection, "_open_suricata_store_reader", forbidden)
    monkeypatch.setattr(suricata, "require_unprivileged_linux", forbidden)
    result = projection.read_suricata_projection(None)
    assert result["status"] == "not_configured"
    assert result["failure_code"] is None


def test_missing_store_is_not_created_and_refusal_has_no_path(tmp_path):
    selected = tmp_path / "private-missing/sensor.db"
    result = projection.read_suricata_projection(selected)
    _assert_refusal(result, "STORE_UNAVAILABLE")
    assert not selected.parent.exists()
    assert "private-missing" not in json.dumps(result)


def test_empty_store_is_available_and_closed_schema_is_bounded(tmp_path):
    path = _store(tmp_path)
    result = projection.read_suricata_projection(path)
    assert result["status"] == "available"
    assert set(result) == {
        "schema_version", "status", "failure_code", "provenance",
        "action_status", "limits", "summary", "recent_runs", "recent_alerts",
    }
    assert result["summary"] == {
        "stored_runs": 0, "stored_alerts": 0, "validated_recent_runs": 0,
        "validated_recent_alerts": 0, "shown_alerts": 0,
    }
    assert len(json.dumps(result).encode()) <= projection.MAX_RESPONSE_BYTES


def test_committed_run_has_external_provenance_and_no_writes(tmp_path):
    path = _store(tmp_path)
    _commit(tmp_path, path)
    before = path.read_bytes()
    before_stat = path.stat()
    result = projection.read_suricata_projection(path)
    assert result["status"] == "available"
    assert result["provenance"] == "external_suricata_signature_alerts"
    assert result["summary"]["stored_alerts"] == 2
    assert result["summary"]["validated_recent_alerts"] == 2
    assert result["recent_runs"][0]["producer_reported_blocked_count"] == 1
    assert result["recent_runs"][0]["version_basis"] == "operator_declared"
    assert result["recent_alerts"][0]["producer_reported_action"] == "blocked"
    assert all(a["action_status"] == "not_attempted" for a in result["recent_alerts"])
    assert path.read_bytes() == before
    assert path.stat().st_mtime_ns == before_stat.st_mtime_ns
    assert path.stat().st_mode == before_stat.st_mode
    assert list(path.parent.iterdir()) == [path]
    serialized = json.dumps(result)
    for forbidden in (str(path), "signature\"", "category\"", "SYNTHETIC contract", "record_json"):
        assert forbidden not in serialized


def test_recent_limits_are_by_publication_order_and_full_runs_are_validated(tmp_path):
    path = _store(tmp_path)
    for index in range(6):
        _commit(tmp_path, path, f"run-{index}", count=60 if index == 5 else 2)
    result = projection.read_suricata_projection(path)
    assert result["status"] == "available"
    assert result["summary"] == {
        "stored_runs": 6, "stored_alerts": 70, "validated_recent_runs": 5,
        "validated_recent_alerts": 68, "shown_alerts": 50,
    }
    assert [run["run_id"] for run in result["recent_runs"]] == [
        "run-5", "run-4", "run-3", "run-2", "run-1",
    ]
    assert [a["source_record_index"] for a in result["recent_alerts"]] == list(range(60, 10, -1))
    # Hidden alerts in selected runs must also validate; a 50-row output cap
    # must not conceal damage in an omitted earlier row.
    _mutate(path, "UPDATE consumer_alerts SET record_json='{}' WHERE run_row_id=6 AND source_record_index=1")
    _assert_refusal(projection.read_suricata_projection(path), "INVALID_EVIDENCE")


@pytest.mark.parametrize("sql,parameters", [
    ("DELETE FROM consumer_receipts", ()),
    ("DELETE FROM consumer_alerts WHERE source_record_index=1", ()),
    ("UPDATE consumer_alerts SET source_record_index=3 WHERE source_record_index=2", ()),
    ("UPDATE consumer_runs SET sensor_id=?", ("<script>alert(1)</script>",)),
    ("UPDATE consumer_runs SET run_id=?", ("a" * 1_000_000,)),
    ("UPDATE consumer_receipts SET receipt_json=?", ("x" * 1_000_000,)),
    ("UPDATE consumer_alerts SET record_json=?", ('{"a":1,"a":2}',)),
    ("UPDATE consumer_alerts SET record_json=?", ('{"a":NaN}',)),
    ("UPDATE consumer_alerts SET record_json=?", ('{"a":' + '[' * 1800 + '0' + ']' * 1800 + '}',)),
    ("UPDATE consumer_alerts SET record_json=?", ("x" * 1_000_000,)),
    ("UPDATE consumer_alerts SET record_json=CAST(x'ff' AS TEXT)", ()),
])
def test_malformed_or_partial_evidence_refuses_without_partial_output(tmp_path, sql, parameters):
    path = _store(tmp_path)
    _commit(tmp_path, path)
    _mutate(path, sql, parameters)
    before = path.read_bytes()
    _assert_refusal(projection.read_suricata_projection(path))
    assert path.read_bytes() == before
    assert list(path.parent.iterdir()) == [path]


def test_receipt_counter_corruption_is_detected(tmp_path):
    path = _store(tmp_path)
    _commit(tmp_path, path)
    with sqlite3.connect(path) as connection:
        receipt = json.loads(connection.execute("SELECT receipt_json FROM consumer_receipts").fetchone()[0])
        receipt["producer_blocked_count"] = 0
        connection.execute("UPDATE consumer_receipts SET receipt_json=?", (
            json.dumps(receipt, sort_keys=True, separators=(",", ":")),
        ))
    _assert_refusal(projection.read_suricata_projection(path), "INVALID_EVIDENCE")


@pytest.mark.parametrize("mode", ["public", "symlink", "sidecar", "schema", "bytes"])
def test_unsafe_store_refused_without_permission_repair(tmp_path, mode):
    path = _store(tmp_path)
    selected = path
    if mode == "public":
        path.chmod(0o644)
    elif mode == "symlink":
        selected = path.parent / "alias.db"
        selected.symlink_to(path)
    elif mode == "sidecar":
        sidecar = Path(str(path) + "-journal")
        sidecar.write_bytes(b"private coordination")
        sidecar.chmod(0o600)
    elif mode == "schema":
        _mutate(path, "CREATE TABLE private_stuff (secret TEXT)")
    else:
        path.write_bytes(b"not a database")
    before = path.read_bytes()
    before_mode = path.stat().st_mode
    before_files = set(path.parent.iterdir())
    _assert_refusal(projection.read_suricata_projection(selected), "STORE_UNAVAILABLE")
    assert path.read_bytes() == before
    assert path.stat().st_mode == before_mode
    assert set(path.parent.iterdir()) == before_files


def test_persistent_wal_is_refused_before_any_sidecar_creation(tmp_path):
    path = _store(tmp_path)
    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
    connection.close()
    assert list(path.parent.iterdir()) == [path]
    _assert_refusal(projection.read_suricata_projection(path), "STORE_UNAVAILABLE")
    assert list(path.parent.iterdir()) == [path]


def test_active_writer_refuses_snapshot_without_side_effects(tmp_path):
    path = _store(tmp_path)
    writer = sqlite3.connect(path, isolation_level=None)
    try:
        writer.execute("BEGIN IMMEDIATE")
        _assert_refusal(projection.read_suricata_projection(path), "STORE_UNAVAILABLE")
        assert writer.in_transaction
    finally:
        writer.rollback()
        writer.close()
    assert projection.read_suricata_projection(path)["status"] == "available"


def test_snapshot_lock_prevents_competing_writer_and_wal_transition(tmp_path, monkeypatch):
    path = _store(tmp_path)
    original = projection._open_suricata_store_reader
    attempts = []

    @contextmanager
    def observed(*args, **kwargs):
        with original(*args, **kwargs) as reader:
            for sql in ("BEGIN IMMEDIATE", "PRAGMA journal_mode=WAL"):
                competitor = sqlite3.connect(path, timeout=0, isolation_level=None)
                try:
                    with pytest.raises(sqlite3.OperationalError, match="locked"):
                        competitor.execute(sql)
                    attempts.append(sql)
                finally:
                    competitor.close()
            yield reader

    monkeypatch.setattr(projection, "_open_suricata_store_reader", observed)
    assert projection.read_suricata_projection(path)["status"] == "available"
    assert len(attempts) == 2
    assert list(path.parent.iterdir()) == [path]


def test_sql_authorizer_denies_writes_attach_and_arbitrary_functions(tmp_path, monkeypatch):
    path = _store(tmp_path)
    _commit(tmp_path, path)
    original = projection._read_run
    attempted = []

    def checked(connection, *args):
        for statement in (
            "DELETE FROM consumer_runs", "PRAGMA user_version=2",
            "ATTACH ':memory:' AS other", "SELECT randomblob(1000000)",
            "CREATE TEMP TABLE scratch (value)",
        ):
            with pytest.raises(sqlite3.DatabaseError):
                connection.execute(statement)
            attempted.append(statement)
        return original(connection, *args)

    monkeypatch.setattr(projection, "_read_run", checked)
    assert projection.read_suricata_projection(path)["status"] == "available"
    assert len(attempted) == 5


@pytest.mark.parametrize("stage", ["open", "final_identity", "close"])
def test_deadline_covers_open_final_verification_and_close(tmp_path, monkeypatch, stage):
    path = _store(tmp_path)
    clock = [0.0]
    original = projection._open_suricata_store_reader

    @contextmanager
    def delayed(*args, **kwargs):
        if stage == "open":
            clock[0] = projection.MAX_QUERY_SECONDS + 1
        with original(*args, **kwargs) as reader:
            if stage == "final_identity":
                def late_verify():
                    clock[0] = projection.MAX_QUERY_SECONDS + 1
                reader.verify_identity = late_verify
            yield reader
        if stage == "close":
            clock[0] = projection.MAX_QUERY_SECONDS + 1

    monkeypatch.setattr(projection.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(projection, "_open_suricata_store_reader", delayed)
    _assert_refusal(projection.read_suricata_projection(path), "QUERY_TIMEOUT")


def test_identity_replacement_fails_closed(tmp_path, monkeypatch):
    path = _store(tmp_path)
    _commit(tmp_path, path)
    original = projection._read_run

    def replaced(*args):
        result = original(*args)
        path.rename(path.with_suffix(".old"))
        path.write_bytes(b"replacement")
        return result

    monkeypatch.setattr(projection, "_read_run", replaced)
    _assert_refusal(projection.read_suricata_projection(path), "STORE_UNAVAILABLE")
    assert path.read_bytes() == b"replacement"


def test_actual_sqlite_progress_interrupt_is_reported_as_timeout(tmp_path, monkeypatch):
    path = _store(tmp_path)
    _commit(tmp_path, path, count=500)
    clock = [0.0]
    progress_calls = []
    original = projection._progress

    def expired(started):
        clock[0] = projection.MAX_QUERY_SECONDS + 1
        progress_calls.append(True)
        return original(started)

    monkeypatch.setattr(projection.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(projection, "_progress", expired)
    _assert_refusal(projection.read_suricata_projection(path), "QUERY_TIMEOUT")
    assert progress_calls


def test_runtime_refusal_precedes_store_access(tmp_path, monkeypatch):
    def unsupported():
        raise suricata.OfflineError("NON_ROOT_REQUIRED")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("runtime gate must precede store access")

    monkeypatch.setattr(suricata, "require_unprivileged_linux", unsupported)
    monkeypatch.setattr(projection, "_open_suricata_store_reader", forbidden)
    _assert_refusal(projection.read_suricata_projection(tmp_path / "anything"), "UNSUPPORTED_RUNTIME")


def test_response_limit_discards_all_evidence(tmp_path, monkeypatch):
    path = _store(tmp_path)
    _commit(tmp_path, path)
    monkeypatch.setattr(projection, "MAX_RESPONSE_BYTES", 1)
    _assert_refusal(projection.read_suricata_projection(path), "RESPONSE_LIMIT")
