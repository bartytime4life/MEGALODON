"""Read-only Suricata consumer reconciliation acceptance tests."""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import inspect
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
from types import MappingProxyType

import pytest
from jsonschema import Draft202012Validator, ValidationError

from megalodon import suricata_store
from megalodon.offline import suricata, suricata_consumer
from megalodon.suricata_store import initialize_suricata_store


ROOT = Path(__file__).parents[1] / "contracts" / "suricata-eve" / "v1"
CASES = json.loads((ROOT / "fixtures" / "accepted.json").read_text(encoding="utf-8"))
RECONCILIATION = ROOT / "reconciliation"
SCHEMA = json.loads((RECONCILIATION / "schema.json").read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)


def _plain(value):
    if isinstance(value, MappingProxyType):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
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


def _reconcile(path: Path, publication, attempt: str = "unknown-attempt"):
    result = suricata_consumer.reconcile_publication(
        path, publication, consumer_attempt_id=attempt,
    )
    VALIDATOR.validate(_plain(result))
    return result


@pytest.fixture(autouse=True)
def isolated_runtime(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("reconciliation must not use network or subprocesses")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(suricata, "require_unprivileged_linux", lambda: None)


def test_contract_accepts_policy_and_all_terminal_receipts():
    accepted = json.loads(
        (RECONCILIATION / "fixtures" / "accepted.json").read_text(encoding="utf-8")
    )
    assert len(accepted) == 4
    for value in accepted:
        VALIDATOR.validate(value)


def test_contract_rejects_contradictions_limits_authority_and_extra_fields():
    accepted = json.loads(
        (RECONCILIATION / "fixtures" / "accepted.json").read_text(encoding="utf-8")
    )
    rejected = json.loads(
        (RECONCILIATION / "fixtures" / "rejected.json").read_text(encoding="utf-8")
    )
    for case in rejected:
        base = deepcopy(accepted[0] if set(case["patch"]) & {
            "max_reconciliation_ms", "read_only", "retry"
        } else accepted[1 if case["patch"].get("disposition") == "committed" else 2])
        base.update(case["patch"])
        with pytest.raises(ValidationError):
            VALIDATOR.validate(base)


def test_lost_commit_acknowledgement_reconciles_only_after_exact_readback(
    tmp_path, monkeypatch
):
    path = _store(tmp_path)
    publication = _publication(tmp_path)

    def lose_acknowledgement(connection):
        connection.commit()
        raise sqlite3.OperationalError("synthetic acknowledgement loss")

    monkeypatch.setattr(suricata_consumer, "_commit", lose_acknowledgement)
    unknown = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="unknown-attempt",
    )
    assert unknown["status"] == "reconciliation_required"

    result = _reconcile(path, publication)

    assert result["disposition"] == "committed"
    assert result["evidence_status"] == "exact_match"
    assert result["durable_write_status"] == "committed"
    assert result["failure_code"] is None
    assert _counts(path) == (1, 2, 1)


def test_proven_absence_is_not_committed_and_creates_no_rows(tmp_path):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    before = path.read_bytes()

    result = _reconcile(path, publication)

    assert result["disposition"] == "not_committed"
    assert result["evidence_status"] == "exact_absence"
    assert result["durable_write_status"] == "not_committed"
    assert result["failure_code"] is None
    assert _counts(path) == (0, 0, 0)
    assert path.read_bytes() == before


def test_proven_rollback_reconciles_to_not_committed(tmp_path, monkeypatch):
    path = _store(tmp_path)
    publication = _publication(tmp_path)

    def fail_before_commit(connection):
        raise sqlite3.OperationalError("synthetic pre-commit failure")

    monkeypatch.setattr(suricata_consumer, "_commit", fail_before_commit)
    failed = suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="unknown-attempt",
    )
    assert failed["durable_write_status"] == "rolled_back"
    assert _reconcile(path, publication)["disposition"] == "not_committed"
    assert _counts(path) == (0, 0, 0)


@pytest.mark.parametrize("collision", ["attempt", "identity"])
def test_partial_identity_or_attempt_collision_is_indeterminate(tmp_path, collision):
    path = _store(tmp_path)
    first = _publication(tmp_path, run_id="fixture-run-a")
    second = _publication(tmp_path, run_id="fixture-run-b")
    assert suricata_consumer.consume_publication(
        path, first, consumer_attempt_id="committed-attempt"
    )["status"] == "committed"

    if collision == "attempt":
        result = _reconcile(path, second, "committed-attempt")
    else:
        result = _reconcile(path, first, "different-attempt")

    assert result["disposition"] == "indeterminate"
    assert result["failure_code"] == "EVIDENCE_AMBIGUOUS"
    assert _counts(path) == (1, 2, 1)


@pytest.mark.parametrize("target", ["receipt", "alert"])
def test_changed_or_malformed_durable_evidence_is_indeterminate(tmp_path, target):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    assert suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="unknown-attempt"
    )["status"] == "committed"
    connection = sqlite3.connect(path)
    try:
        if target == "receipt":
            connection.execute(
                "UPDATE consumer_receipts SET receipt_json='{}'"
            )
        else:
            connection.execute(
                "UPDATE consumer_alerts SET record_json='{}' WHERE source_record_index=1"
            )
        connection.commit()
    finally:
        connection.close()

    result = _reconcile(path, publication)

    assert result["disposition"] == "indeterminate"
    assert result["durable_write_status"] == "unknown"
    assert result["failure_code"] == "EVIDENCE_AMBIGUOUS"


def test_schema_drift_is_indeterminate_and_never_repaired(tmp_path):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    connection = sqlite3.connect(path)
    connection.execute("DROP INDEX idx_consumer_runs_run_id")
    connection.commit()
    connection.close()
    before = path.read_bytes()

    result = _reconcile(path, publication)

    assert result["disposition"] == "indeterminate"
    assert result["failure_code"] == "SCHEMA_INCOMPATIBLE"
    assert path.read_bytes() == before


def test_active_lock_is_indeterminate_without_writes(tmp_path, monkeypatch):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    before = _counts(path)
    blocker = sqlite3.connect(path, isolation_level=None)
    blocker.execute("BEGIN EXCLUSIVE")
    monkeypatch.setattr(
        suricata_consumer,
        "_remaining_milliseconds",
        lambda _started: 1,
    )
    try:
        result = _reconcile(path, publication)
    finally:
        blocker.rollback()
        blocker.close()

    assert result["disposition"] == "indeterminate"
    assert result["failure_code"] in {
        "DATABASE_IDENTITY", "STORAGE_ERROR", "TRANSACTION_TIMEOUT",
    }
    assert _counts(path) == before


def test_deadline_expiry_is_indeterminate(tmp_path, monkeypatch):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    calls = 0

    def expire(_started):
        nonlocal calls
        calls += 1
        if calls >= 2:
            raise suricata_consumer._TransactionTimeout
        return 1

    monkeypatch.setattr(suricata_consumer, "_remaining_milliseconds", expire)
    result = _reconcile(path, publication)

    assert result["disposition"] == "indeterminate"
    assert result["failure_code"] == "TRANSACTION_TIMEOUT"
    assert _counts(path) == (0, 0, 0)


def test_path_replacement_during_readback_is_indeterminate(tmp_path, monkeypatch):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    real_open = suricata_consumer._open_suricata_store_reader

    @contextmanager
    def replaced(*args, **kwargs):
        with real_open(*args, **kwargs) as reader:
            reader.verify_identity = lambda: (_ for _ in ()).throw(
                suricata_consumer.SuricataStoreError(
                    "SURICATA_STORE:DATABASE_CHANGED"
                )
            )
            yield reader

    monkeypatch.setattr(suricata_consumer, "_open_suricata_store_reader", replaced)
    result = _reconcile(path, publication)

    assert result["disposition"] == "indeterminate"
    assert result["failure_code"] == "DATABASE_IDENTITY"


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode boundary")
def test_public_store_is_indeterminate_without_permission_repair(tmp_path):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    path.chmod(0o644)
    before = path.read_bytes()

    result = _reconcile(path, publication)

    assert result["disposition"] == "indeterminate"
    assert result["failure_code"] == "DATABASE_IDENTITY"
    assert path.stat().st_mode & 0o777 == 0o644
    assert path.read_bytes() == before


def test_missing_store_is_indeterminate_and_not_created(tmp_path):
    publication = _publication(tmp_path)
    path = tmp_path / "missing" / "suricata.db"

    result = _reconcile(path, publication)

    assert result["disposition"] == "indeterminate"
    assert result["failure_code"] == "DATABASE_IDENTITY"
    assert not path.exists()


def test_sidecar_is_indeterminate_and_not_removed(tmp_path):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    sidecar = Path(f"{path}-journal")
    sidecar.write_bytes(b"synthetic")
    sidecar.chmod(0o600)

    result = _reconcile(path, publication)

    assert result["disposition"] == "indeterminate"
    assert result["failure_code"] == "DATABASE_IDENTITY"
    assert sidecar.read_bytes() == b"synthetic"


def test_persistent_wal_mode_is_refused_before_sqlite_can_create_sidecars(tmp_path):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
    finally:
        connection.close()
    wal = Path(f"{path}-wal")
    shm = Path(f"{path}-shm")
    assert path.read_bytes()[18:20] == b"\x02\x02"
    assert not wal.exists()
    assert not shm.exists()

    result = _reconcile(path, publication)

    assert result["disposition"] == "indeterminate"
    assert result["failure_code"] == "DATABASE_IDENTITY"
    assert not wal.exists()
    assert not shm.exists()


def test_snapshot_lock_prevents_wal_conversion_race_before_sqlite_open(
    tmp_path, monkeypatch
):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    wal = Path(f"{path}-wal")
    shm = Path(f"{path}-shm")
    real_connect = suricata_store.sqlite3.connect
    attempted = False
    observed_mode = None

    def racing_connect(database, *args, **kwargs):
        nonlocal attempted, observed_mode
        if not attempted and "mode=ro" in str(database):
            attempted = True
            competitor = real_connect(path, timeout=0, isolation_level=None)
            try:
                competitor.execute("PRAGMA busy_timeout=0")
                try:
                    observed_mode = competitor.execute(
                        "PRAGMA journal_mode=WAL"
                    ).fetchone()
                except sqlite3.OperationalError:
                    observed_mode = ("locked",)
            finally:
                competitor.close()
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(suricata_store.sqlite3, "connect", racing_connect)

    result = _reconcile(path, publication)

    assert attempted is True
    assert observed_mode != ("wal",)
    assert result["disposition"] == "not_committed"
    assert path.read_bytes()[18:20] == b"\x01\x01"
    assert not wal.exists()
    assert not shm.exists()


@pytest.mark.parametrize("committed", [False, True])
def test_success_requires_deadline_check_after_final_identity_verification(
    tmp_path, monkeypatch, committed
):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    if committed:
        assert suricata_consumer.consume_publication(
            path, publication, consumer_attempt_id="unknown-attempt"
        )["status"] == "committed"
    events = []
    real_open = suricata_consumer._open_suricata_store_reader

    @contextmanager
    def observed(*args, **kwargs):
        with real_open(*args, **kwargs) as reader:
            real_verify = reader.verify_identity

            def verify():
                events.append("verify")
                real_verify()

            reader.verify_identity = verify
            yield reader

    def remaining(_started):
        events.append("remaining")
        return 30_000

    monkeypatch.setattr(suricata_consumer, "_open_suricata_store_reader", observed)
    monkeypatch.setattr(suricata_consumer, "_remaining_milliseconds", remaining)

    result = _reconcile(path, publication)

    assert result["disposition"] == ("committed" if committed else "not_committed")
    assert events[-2:] == ["verify", "remaining"]


@pytest.mark.parametrize("committed", [False, True])
def test_identity_verification_returning_after_deadline_is_indeterminate(
    tmp_path, monkeypatch, committed
):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    if committed:
        assert suricata_consumer.consume_publication(
            path, publication, consumer_attempt_id="unknown-attempt"
        )["status"] == "committed"
    real_open = suricata_consumer._open_suricata_store_reader
    expired = False
    verify_calls = 0
    final_verify_call = 4 if committed else 3

    @contextmanager
    def delayed_final_verify(*args, **kwargs):
        with real_open(*args, **kwargs) as reader:
            real_verify = reader.verify_identity

            def verify():
                nonlocal expired, verify_calls
                verify_calls += 1
                real_verify()
                if verify_calls == final_verify_call:
                    expired = True

            reader.verify_identity = verify
            yield reader

    real_remaining = suricata_consumer._remaining_milliseconds

    def remaining(started):
        if expired:
            raise suricata_consumer._TransactionTimeout
        return real_remaining(started)

    monkeypatch.setattr(
        suricata_consumer, "_open_suricata_store_reader", delayed_final_verify
    )
    monkeypatch.setattr(suricata_consumer, "_remaining_milliseconds", remaining)

    result = _reconcile(path, publication)

    assert result["disposition"] == "indeterminate"
    assert result["failure_code"] == "TRANSACTION_TIMEOUT"


def test_read_error_is_indeterminate_not_absent(tmp_path, monkeypatch):
    path = _store(tmp_path)
    publication = _publication(tmp_path)
    assert suricata_consumer.consume_publication(
        path, publication, consumer_attempt_id="unknown-attempt"
    )["status"] == "committed"
    monkeypatch.setattr(
        suricata_consumer,
        "_readback_matches",
        lambda *args: (_ for _ in ()).throw(sqlite3.OperationalError("read failed")),
    )

    result = _reconcile(path, publication)

    assert result["disposition"] == "indeterminate"
    assert result["failure_code"] == "STORAGE_ERROR"


def test_unsupported_runtime_refuses_before_store_access(tmp_path, monkeypatch):
    path = _store(tmp_path)
    publication = _publication(tmp_path)

    def unsupported():
        raise suricata.OfflineError("LINUX_REQUIRED")

    def opened_store(*args, **kwargs):
        raise AssertionError("unsupported runtime must not open the store")

    monkeypatch.setattr(suricata, "require_unprivileged_linux", unsupported)
    monkeypatch.setattr(
        suricata_consumer, "_open_suricata_store_reader", opened_store
    )
    result = _reconcile(path, publication)

    assert result["disposition"] == "indeterminate"
    assert result["failure_code"] == "STORAGE_ERROR"


def test_api_has_no_caller_limits_or_hidden_authority():
    signature = inspect.signature(suricata_consumer.reconcile_publication)
    assert tuple(signature.parameters) == (
        "database_path", "publication", "consumer_attempt_id",
    )
    assert signature.parameters["consumer_attempt_id"].kind is inspect.Parameter.KEYWORD_ONLY
    source = inspect.getsource(suricata_consumer.reconcile_publication)
    for forbidden in (
        "consume_publication(", "connection.execute(\"insert",
        "connection.execute(\"update", "connection.execute(\"delete",
        "connection.execute(\"create",
        "subprocess", "socket", "requests", "urllib", "firewall",
        "qwen", "ollama",
    ):
        assert forbidden not in source.lower()
