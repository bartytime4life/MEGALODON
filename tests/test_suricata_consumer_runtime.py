"""Production Suricata durable-consumer acceptance tests."""

from __future__ import annotations

from copy import deepcopy
import inspect
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
from types import MappingProxyType

import pytest
from jsonschema import Draft202012Validator

from megalodon.offline import suricata, suricata_consumer
from megalodon.suricata_store import (
    initialize_suricata_store,
    validate_suricata_store,
)


ROOT = Path(__file__).parents[1] / "contracts" / "suricata-eve" / "v1"
CASES = json.loads((ROOT / "fixtures" / "accepted.json").read_text(encoding="utf-8"))
CONSUMER_SCHEMA = json.loads(
    (ROOT / "consumer" / "schema.json").read_text(encoding="utf-8")
)
CONSUMER_VALIDATOR = Draft202012Validator(CONSUMER_SCHEMA)


def _plain(value):
    if isinstance(value, MappingProxyType):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _publication(tmp_path: Path, *, run_id: str = "fixture-run-a"):
    records = []
    for case in CASES[:2]:
        record = deepcopy(case["input"])
        record["source"]["run_id"] = run_id
        records.append(record)
    source = tmp_path / f"{run_id}.jsonl"
    source.write_text(
        "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
        encoding="utf-8",
    )
    source.chmod(0o600)
    return suricata.read_completed_file(str(source))


def _store(tmp_path: Path) -> Path:
    path = tmp_path / "store" / "suricata.db"
    initialize_suricata_store(path)
    return path


def _counts(path: Path) -> tuple[int, int, int]:
    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    try:
        return tuple(
            connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("consumer_runs", "consumer_alerts", "consumer_receipts")
        )
    finally:
        connection.close()


def _assert_contract(receipt) -> None:
    CONSUMER_VALIDATOR.validate(_plain(receipt))


@pytest.fixture(autouse=True)
def isolated_runtime(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("consumer must not use network or subprocesses")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(suricata, "require_unprivileged_linux", lambda: None)


def test_one_publication_commits_atomically_and_reads_back_exactly(tmp_path):
    publication = _publication(tmp_path)
    path = _store(tmp_path)

    receipt = suricata_consumer.consume_publication(
        path,
        publication,
        consumer_attempt_id="runtime-attempt-a",
    )

    assert receipt["status"] == "committed"
    assert receipt["transaction_status"] == "committed"
    assert receipt["durable_write_status"] == "committed"
    assert receipt["action_status"] == "not_attempted"
    _assert_contract(receipt)
    assert _counts(path) == (1, 2, 1)
    assert validate_suricata_store(path)["status"] == "compatible"
    with pytest.raises(TypeError):
        receipt["status"] = "failed"

    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    try:
        stored = connection.execute(
            "SELECT record_json FROM consumer_alerts ORDER BY source_record_index"
        ).fetchall()
        assert [row[0] for row in stored] == [
            json.dumps(_plain(item), sort_keys=True, separators=(",", ":"))
            for item in publication[0]
        ]
        decoded = [json.loads(row[0]) for row in stored]
        combined = "".join(row[0] for row in stored)
        for record in decoded:
            assert set(record["rule"]) == {"gid", "signature_id", "rev", "severity"}
            assert "signature" not in record["rule"]
            assert "category" not in record["rule"]
        for forbidden in (
            "payload", "packet", "http", "tls", "source_path",
            "content_hash", "exception",
        ):
            assert forbidden not in combined
    finally:
        connection.close()


def test_replay_and_attempt_collision_write_no_new_rows(tmp_path):
    path = _store(tmp_path)
    first = _publication(tmp_path, run_id="fixture-run-a")
    second = _publication(tmp_path, run_id="fixture-run-b")
    committed = suricata_consumer.consume_publication(
        path, first, consumer_attempt_id="shared-attempt"
    )
    assert committed["status"] == "committed"

    replay = suricata_consumer.consume_publication(
        path, first, consumer_attempt_id="different-attempt"
    )
    assert replay["status"] == "rejected"
    assert replay["failure_code"] == "REPLAY"
    assert replay["transaction_status"] == "not_started"

    collision = suricata_consumer.consume_publication(
        path, second, consumer_attempt_id="shared-attempt"
    )
    assert collision["status"] == "failed"
    assert collision["failure_code"] == "DATABASE_IDENTITY"
    assert collision["transaction_status"] == "not_started"
    assert _counts(path) == (1, 2, 1)


def test_precommit_deadline_failure_rolls_back_every_row(tmp_path, monkeypatch):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    calls = 0

    def bounded(_started):
        nonlocal calls
        calls += 1
        if calls >= 4:
            raise suricata_consumer._TransactionTimeout
        return 30_000

    monkeypatch.setattr(suricata_consumer, "_remaining_milliseconds", bounded)
    receipt = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="deadline-attempt"
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_code"] == "TRANSACTION_TIMEOUT"
    assert receipt["transaction_status"] == "rolled_back"
    assert receipt["durable_write_status"] == "rolled_back"
    assert _counts(path) == (0, 0, 0)


def test_sqlite_progress_interrupt_is_timeout_and_leaves_store_usable(
    tmp_path, monkeypatch
):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("BEGIN IMMEDIATE")
        for index in range(500):
            cursor = connection.execute(
                """INSERT INTO consumer_runs (
                       engine, adapter_profile, declared_version, version_basis,
                       sensor_id, run_id, ruleset_id, ruleset_basis,
                       consumer_attempt_id
                   ) VALUES ('suricata', 'suricata-eve-alert-v1', '8.0.1',
                             'operator_declared', 'fixture-sensor', ?,
                             'synthetic-rules-v1', 'operator_declared', ?)""",
                (f"prior-run-{index}", f"prior-attempt-{index}"),
            )
            connection.execute(
                "INSERT INTO consumer_alerts VALUES (?, 1, '{}')",
                (cursor.lastrowid,),
            )
            connection.execute(
                "INSERT INTO consumer_receipts VALUES (?, ?, '{}')",
                (cursor.lastrowid, f"prior-attempt-{index}"),
            )
        connection.commit()
    finally:
        connection.close()
    before = _counts(path)

    clock_calls = 0

    def expired_clock():
        nonlocal clock_calls
        clock_calls += 1
        return 0.0 if clock_calls == 1 else 31.0

    progress_calls = 0
    real_progress = suricata_consumer._deadline_progress

    def observed_progress(started):
        nonlocal progress_calls
        progress_calls += 1
        return real_progress(started)

    monkeypatch.setattr(suricata_consumer.time, "monotonic", expired_clock)
    monkeypatch.setattr(suricata_consumer, "_deadline_progress", observed_progress)

    receipt = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="progress-timeout"
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_code"] == "TRANSACTION_TIMEOUT"
    assert receipt["transaction_status"] == "not_started"
    assert progress_calls >= 1
    assert _counts(path) == before
    assert validate_suricata_store(path)["status"] == "compatible"


def test_lost_commit_acknowledgement_requires_reconciliation(tmp_path, monkeypatch):
    path = _store(tmp_path)
    publication = _publication(tmp_path)

    def lose_acknowledgement(connection):
        connection.commit()
        raise sqlite3.OperationalError("synthetic acknowledgement loss")

    monkeypatch.setattr(suricata_consumer, "_commit", lose_acknowledgement)
    receipt = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="unknown-attempt"
    )

    assert receipt["status"] == "reconciliation_required"
    assert receipt["failure_code"] == "COMMIT_UNKNOWN"
    assert receipt["transaction_status"] == "unknown"
    assert receipt["reconciliation_status"] == "required"
    assert _counts(path) == (1, 2, 1)


def test_authoritative_replay_check_after_begin_rolls_back(tmp_path, monkeypatch):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    calls = 0

    def concurrent_run(_connection, _identity):
        nonlocal calls
        calls += 1
        return None if calls == 1 else (999, "concurrent-attempt")

    monkeypatch.setattr(suricata_consumer, "_find_run", concurrent_run)
    receipt = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="race-attempt"
    )

    assert receipt["status"] == "rejected"
    assert receipt["failure_code"] == "REPLAY"
    assert receipt["transaction_status"] == "rolled_back"
    assert receipt["durable_write_status"] == "rolled_back"
    _assert_contract(receipt)
    assert _counts(path) == (0, 0, 0)


def test_failed_postcommit_readback_requires_reconciliation(tmp_path, monkeypatch):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    monkeypatch.setattr(suricata_consumer, "_readback_matches", lambda *args: False)

    receipt = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="readback-attempt"
    )

    assert receipt["status"] == "reconciliation_required"
    assert receipt["failure_code"] == "COMMIT_UNKNOWN"
    assert receipt["transaction_status"] == "unknown"
    _assert_contract(receipt)
    assert _counts(path) == (1, 2, 1)

    retry = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="blind-retry"
    )
    assert retry["status"] == "rejected"
    assert retry["failure_code"] == "REPLAY"
    assert _counts(path) == (1, 2, 1)


def test_missing_store_is_not_created_and_schema_is_not_migrated(tmp_path):
    publication = _publication(tmp_path)
    ambiguous = suricata_consumer.consume_publication(
        Path("relative.db"), publication, consumer_attempt_id="ambiguous-store"
    )
    assert ambiguous["status"] == "failed"
    assert ambiguous["transaction_status"] == "not_started"

    missing = tmp_path / "missing" / "suricata.db"
    refusal = suricata_consumer.consume_publication(
        missing, publication, consumer_attempt_id="missing-store"
    )
    assert refusal["status"] == "failed"
    assert refusal["transaction_status"] == "not_started"
    assert not missing.exists()

    path = _store(tmp_path)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA user_version=2")
    connection.commit()
    connection.close()
    before = path.read_bytes()
    incompatible = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="future-schema"
    )
    assert incompatible["status"] == "failed"
    assert incompatible["failure_code"] == "SCHEMA_INCOMPATIBLE"
    assert path.read_bytes() == before


def test_constructed_frozen_garbage_and_mutable_input_fail_before_store(tmp_path):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    garbage = (
        (MappingProxyType({"garbage": "accepted-before-review"}),),
        publication[1],
    )
    with pytest.raises(
        suricata_consumer.ConsumerPreflightError,
        match="INPUT_CONTRACT$",
    ):
        suricata_consumer.consume_publication(
            path, garbage, consumer_attempt_id="garbage-attempt"
        )
    mutable = ([dict(_plain(publication[0][0]))], dict(_plain(publication[1])))
    with pytest.raises(
        suricata_consumer.ConsumerPreflightError,
        match="INPUT_CONTRACT$",
    ):
        suricata_consumer.consume_publication(
            path, mutable, consumer_attempt_id="mutable-attempt"
        )
    assert _counts(path) == (0, 0, 0)


def test_boolean_record_index_and_cyclic_proxy_fail_with_fixed_diagnostic(tmp_path):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    malformed = _plain(publication)
    malformed[0][0]["source_record_index"] = True
    malformed[1]["normalized_batch_bytes"] = sum(
        len(json.dumps(row, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        for row in malformed[0]
    )
    with pytest.raises(
        suricata_consumer.ConsumerPreflightError,
        match="INPUT_CONTRACT$",
    ):
        suricata_consumer.consume_publication(
            path, _freeze(malformed), consumer_attempt_id="boolean-index"
        )

    backing = {}
    cyclic = MappingProxyType(backing)
    backing["cycle"] = cyclic
    with pytest.raises(
        suricata_consumer.ConsumerPreflightError,
        match="INPUT_CONTRACT$",
    ):
        suricata_consumer.consume_publication(
            path,
            ((cyclic,), MappingProxyType({})),
            consumer_attempt_id="cyclic-input",
        )
    assert _counts(path) == (0, 0, 0)


def test_consumer_owns_validated_snapshot_before_any_store_work(tmp_path, monkeypatch):
    path = _store(tmp_path)
    plain_batch, plain_receipt = _plain(_publication(tmp_path))
    source_backings = []
    frozen_batch = []
    for record in plain_batch:
        source = record["source"]
        rule = record["rule"]
        source_backings.append(source)
        record["source"] = MappingProxyType(source)
        record["rule"] = MappingProxyType(rule)
        frozen_batch.append(MappingProxyType(record))
    receipt_source = plain_receipt["run_identity"]
    source_backings.append(receipt_source)
    plain_receipt["run_identity"] = MappingProxyType(receipt_source)
    publication = (tuple(frozen_batch), MappingProxyType(plain_receipt))

    real_preflight = suricata_consumer.preflight_publication

    def mutate_then_preflight(connection, snapshot, *, database_path):
        for source in source_backings:
            source["run_id"] = "mutated-after-validation"
        return real_preflight(connection, snapshot, database_path=database_path)

    monkeypatch.setattr(
        suricata_consumer, "preflight_publication", mutate_then_preflight,
    )
    receipt = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="owned-snapshot"
    )

    assert receipt["status"] == "committed"
    assert receipt["run_identity"]["run_id"] == "fixture-run-a"
    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    try:
        assert connection.execute(
            "SELECT run_id FROM consumer_runs"
        ).fetchone() == ("fixture-run-a",)
        stored_alerts = connection.execute(
            "SELECT record_json FROM consumer_alerts ORDER BY source_record_index"
        ).fetchall()
        assert {
            json.loads(row[0])["source"]["run_id"] for row in stored_alerts
        } == {"fixture-run-a"}
    finally:
        connection.close()


def test_runtime_limits_and_authority_are_not_caller_tunable():
    signature = inspect.signature(suricata_consumer.consume_publication)
    assert tuple(signature.parameters) == (
        "database_path", "publication", "consumer_attempt_id",
    )
    assert suricata_consumer.MAX_TRANSACTION_SECONDS == 30
    source = inspect.getsource(suricata_consumer)
    for forbidden in (
        "shell=True", "subprocess.", "socket.", "requests.", "urllib.",
        "firewall", "qwen", "ollama",
    ):
        assert forbidden not in source.lower()
