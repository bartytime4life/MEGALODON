"""Production-owned Suricata store schema and private writer-open tests."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import sqlite3

import pytest

from megalodon import suricata_store
from megalodon.suricata_store import (
    SCHEMA_VERSION,
    SuricataStoreError,
    initialize_suricata_store,
    validate_suricata_store,
)


IDENTITY = (
    "suricata",
    "suricata-eve-alert-v1",
    "7.0.3",
    "operator_declared",
    "sensor-a",
    "run-a",
    "ruleset-a",
    "operator_declared",
)


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def _insert_run(
    connection: sqlite3.Connection,
    *,
    identity: tuple[str, ...] = IDENTITY,
    attempt_id: str = "attempt-a",
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO consumer_runs (
            engine, adapter_profile, declared_version, version_basis,
            sensor_id, run_id, ruleset_id, ruleset_basis,
            consumer_attempt_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (*identity, attempt_id),
    )
    return int(cursor.lastrowid)


def test_explicit_initializer_creates_exact_private_v1_store(tmp_path):
    directory = tmp_path / "suricata"
    path = directory / "durable.db"

    assert initialize_suricata_store(path) == {
        "status": "created",
        "schema_version": SCHEMA_VERSION,
        "tables": ("consumer_runs", "consumer_alerts", "consumer_receipts"),
    }
    assert validate_suricata_store(path) == {
        "status": "compatible",
        "schema_version": SCHEMA_VERSION,
        "tables": ("consumer_runs", "consumer_alerts", "consumer_receipts"),
    }
    if os.name == "posix":
        assert directory.stat().st_mode & 0o777 == 0o700
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX umask and mode semantics")
def test_initializer_normalizes_owner_permissions_under_restrictive_umask(tmp_path):
    path = tmp_path / "durable.db"
    previous = os.umask(0o277)
    try:
        assert initialize_suricata_store(path)["status"] == "created"
    finally:
        os.umask(previous)

    assert path.stat().st_mode & 0o777 == 0o600
    assert validate_suricata_store(path)["status"] == "compatible"


@pytest.mark.parametrize("suffix", ("-wal", "-shm", "-journal"))
def test_initializer_refuses_orphaned_sqlite_sidecars(tmp_path, suffix):
    directory = tmp_path / "suricata"
    directory.mkdir(mode=0o700)
    path = directory / "durable.db"
    sidecar = path.with_name(path.name + suffix)
    sidecar.write_bytes(b"orphaned")
    if os.name == "posix":
        sidecar.chmod(0o600)

    with pytest.raises(SuricataStoreError, match="ORPHANED_SIDECAR_REFUSED"):
        initialize_suricata_store(path)

    assert not path.exists()
    assert sidecar.read_bytes() == b"orphaned"


def test_initializer_refuses_sidecar_created_during_exclusive_open(
    tmp_path, monkeypatch
):
    path = tmp_path / "durable.db"
    original = suricata_store._create_private_database

    def create_with_sidecar(database_path, directory_descriptor):
        descriptor = original(database_path, directory_descriptor)
        sidecar = database_path.with_name(database_path.name + "-wal")
        sidecar.write_bytes(b"raced")
        if os.name == "posix":
            sidecar.chmod(0o600)
        return descriptor

    monkeypatch.setattr(
        suricata_store, "_create_private_database", create_with_sidecar
    )
    with pytest.raises(SuricataStoreError, match="ORPHANED_SIDECAR_REFUSED"):
        initialize_suricata_store(path)

    assert not path.exists()
    assert path.with_name(path.name + "-wal").read_bytes() == b"raced"


def test_initializer_keeps_existing_database_classification_with_wal_sidecars(
    tmp_path,
):
    path = tmp_path / "durable.db"
    initialize_suricata_store(path)
    writer = _connect(path)
    try:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        writer.execute("CREATE TABLE live_marker (value INTEGER)")
        writer.commit()
        assert path.with_name(path.name + "-wal").exists()
        assert path.with_name(path.name + "-shm").exists()

        with pytest.raises(SuricataStoreError, match="EXISTING_DATABASE"):
            initialize_suricata_store(path)
    finally:
        writer.close()


def test_initializer_refuses_sidecar_created_during_sqlite_connect(
    tmp_path, monkeypatch
):
    path = tmp_path / "durable.db"
    sidecar = path.with_name(path.name + "-shm")
    original = suricata_store.sqlite3.connect

    def connect_with_sidecar(*args, **kwargs):
        connection = original(*args, **kwargs)
        sidecar.write_bytes(b"raced-during-connect")
        if os.name == "posix":
            sidecar.chmod(0o600)
        return connection

    monkeypatch.setattr(suricata_store.sqlite3, "connect", connect_with_sidecar)
    with pytest.raises(SuricataStoreError, match="ORPHANED_SIDECAR_REFUSED"):
        initialize_suricata_store(path)

    assert not path.exists()
    assert sidecar.read_bytes() == b"raced-during-connect"


def test_validation_is_read_only_and_initializer_refuses_existing_store(tmp_path):
    path = tmp_path / "durable.db"
    initialize_suricata_store(path)
    before = hashlib.sha256(path.read_bytes()).digest()
    before_stat = path.stat()
    before_entries = tuple(sorted(item.name for item in tmp_path.iterdir()))

    assert validate_suricata_store(path)["status"] == "compatible"
    after_stat = path.stat()
    assert hashlib.sha256(path.read_bytes()).digest() == before
    assert after_stat.st_size == before_stat.st_size
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns
    assert tuple(sorted(item.name for item in tmp_path.iterdir())) == before_entries

    with pytest.raises(SuricataStoreError, match="EXISTING_DATABASE"):
        initialize_suricata_store(path)
    assert hashlib.sha256(path.read_bytes()).digest() == before
    if os.name == "posix":
        path.chmod(0o640)
        with pytest.raises(SuricataStoreError, match="EXISTING_DATABASE"):
            initialize_suricata_store(path)
        assert path.stat().st_mode & 0o777 == 0o640


def test_validation_refuses_missing_future_partial_and_weakened_stores(tmp_path):
    missing = tmp_path / "missing" / "durable.db"
    with pytest.raises(SuricataStoreError, match="^SURICATA_STORE:NO_DIRECTORY$"):
        validate_suricata_store(missing)

    cases = ("future", "partial", "weakened")
    for case in cases:
        directory = tmp_path / case
        directory.mkdir(mode=0o700)
        path = directory / "durable.db"
        if case == "partial":
            with _connect(path) as connection:
                connection.execute("CREATE TABLE consumer_runs (id INTEGER PRIMARY KEY)")
                connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        else:
            initialize_suricata_store(path)
            with _connect(path) as connection:
                if case == "future":
                    connection.execute(f"PRAGMA user_version={SCHEMA_VERSION + 1}")
                else:
                    connection.execute("DROP INDEX idx_consumer_runs_run_id")
        path.chmod(0o600)
        with pytest.raises(SuricataStoreError, match="INCOMPATIBLE"):
            validate_suricata_store(path)


def test_validation_refuses_live_wal_sidecars_instead_of_reading_through(tmp_path):
    path = tmp_path / "durable.db"
    initialize_suricata_store(path)
    writer = _connect(path)
    try:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        writer.execute("PRAGMA foreign_keys=OFF")
        writer.execute(
            "INSERT INTO consumer_alerts VALUES (?, ?, ?)",
            (999, 1, "{}"),
        )
        writer.commit()
        assert path.with_name(path.name + "-wal").exists()

        with pytest.raises(SuricataStoreError, match="ACTIVE_SIDECAR_REFUSED$"):
            validate_suricata_store(path)
    finally:
        writer.close()


def _open_writer(path: Path) -> None:
    with suricata_store._open_suricata_store_writer(path):
        pass


def _persistent_wal_store(path: Path) -> list[str]:
    initialize_suricata_store(path)
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
    finally:
        connection.close()
    assert path.read_bytes()[18:20] == b"\x02\x02"
    entries = sorted(item.name for item in path.parent.iterdir())
    assert entries == [path.name]
    return entries


def test_persistent_wal_header_is_refused_before_sqlite_opens_it(tmp_path):
    path = tmp_path / "durable.db"
    entries = _persistent_wal_store(path)

    with pytest.raises(SuricataStoreError, match="ROLLBACK_JOURNAL_REQUIRED$"):
        validate_suricata_store(path)
    assert sorted(item.name for item in tmp_path.iterdir()) == entries

    with pytest.raises(SuricataStoreError, match="ROLLBACK_JOURNAL_REQUIRED$"):
        _open_writer(path)
    assert sorted(item.name for item in tmp_path.iterdir()) == entries


def test_foreign_page_size_and_oversized_header_are_refused_before_open(tmp_path):
    large_pages = tmp_path / "large-pages.db"
    initialize_suricata_store(large_pages)
    connection = sqlite3.connect(large_pages)
    try:
        connection.execute("PRAGMA page_size=8192")
        connection.execute("VACUUM")
    finally:
        connection.close()
    assert int.from_bytes(large_pages.read_bytes()[16:18], "big") == 8192
    with pytest.raises(SuricataStoreError, match="INCOMPATIBLE_PAGE_SIZE$"):
        validate_suricata_store(large_pages)
    with pytest.raises(SuricataStoreError, match="INCOMPATIBLE_PAGE_SIZE$"):
        _open_writer(large_pages)

    oversized = tmp_path / "oversized.db"
    initialize_suricata_store(oversized)
    header = bytearray(oversized.read_bytes())
    assert header[92:96] == header[24:28]
    header[28:32] = (suricata_store._STORE_MAX_PAGES + 1).to_bytes(4, "big")
    oversized.write_bytes(bytes(header))
    for open_store in (validate_suricata_store, _open_writer):
        with pytest.raises(SuricataStoreError, match="CAPACITY_EXCEEDED$"):
            open_store(oversized)
    assert sorted(item.name for item in tmp_path.iterdir()) == [
        "large-pages.db", "oversized.db",
    ]


def test_initializer_writes_the_fixed_rollback_journal_page_layout(tmp_path):
    path = tmp_path / "durable.db"
    initialize_suricata_store(path)
    header = path.read_bytes()[:20]
    assert int.from_bytes(header[16:18], "big") == suricata_store._STORE_PAGE_SIZE_BYTES
    assert header[18:20] == b"\x01\x01"


@pytest.mark.parametrize(
    "operation", (initialize_suricata_store, validate_suricata_store)
)
def test_ambiguous_path_refusal_keeps_the_store_error_contract(tmp_path, operation):
    with pytest.raises(SuricataStoreError, match="^SURICATA_STORE:AMBIGUOUS_PATH$"):
        operation(tmp_path / "x" / ".." / "durable.db")
    assert list(tmp_path.iterdir()) == []


def test_validation_rechecks_path_identity_after_schema_scan(tmp_path, monkeypatch):
    path = tmp_path / "durable.db"
    replacement = tmp_path / "replacement.db"
    initialize_suricata_store(path)
    original = suricata_store._validate_current

    def replace_after_validation(connection):
        original(connection)
        shutil.copyfile(path, replacement)
        replacement.chmod(0o600)
        os.replace(replacement, path)

    monkeypatch.setattr(suricata_store, "_validate_current", replace_after_validation)
    with pytest.raises(SuricataStoreError, match="DATABASE_CHANGED"):
        validate_suricata_store(path)


def test_writer_validation_never_inherits_a_fresh_lock_wait(tmp_path, monkeypatch):
    path = tmp_path / "durable.db"
    initialize_suricata_store(path)
    observed = []
    real_validate = suricata_store._validate_current

    def validate_without_wait(connection):
        observed.append(connection.execute("PRAGMA busy_timeout").fetchone()[0])
        real_validate(connection)

    monkeypatch.setattr(suricata_store, "_validate_current", validate_without_wait)
    with suricata_store._open_suricata_store_writer(path) as writer:
        assert writer.connection.execute("PRAGMA busy_timeout").fetchone() == (0,)

    assert observed == [0]


def test_schema_enforces_run_attempt_and_record_identity(tmp_path):
    path = tmp_path / "durable.db"
    initialize_suricata_store(path)
    with _connect(path) as connection:
        run_row_id = _insert_run(connection)
        connection.execute(
            "INSERT INTO consumer_alerts VALUES (?, ?, ?)",
            (run_row_id, 1, '{"schema_version":"external-alert-v1"}'),
        )
        connection.execute(
            "INSERT INTO consumer_receipts VALUES (?, ?, ?)",
            (run_row_id, "attempt-a", '{"status":"committed"}'),
        )

        with pytest.raises(sqlite3.IntegrityError):
            _insert_run(connection, attempt_id="attempt-b")
        changed = (*IDENTITY[:5], "run-b", *IDENTITY[6:])
        with pytest.raises(sqlite3.IntegrityError):
            _insert_run(connection, identity=changed, attempt_id="attempt-a")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO consumer_alerts VALUES (?, ?, ?)",
                (run_row_id, 1, "{}"),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO consumer_alerts VALUES (?, ?, ?)",
                (run_row_id, 0, "{}"),
            )

        second = _insert_run(
            connection,
            identity=changed,
            attempt_id="attempt-b",
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO consumer_receipts VALUES (?, ?, ?)",
                (second, "attempt-a", "{}"),
            )


def test_initialization_failure_rolls_back_and_removes_new_file(tmp_path, monkeypatch):
    path = tmp_path / "durable.db"
    monkeypatch.setattr(
        suricata_store,
        "SCHEMA_STATEMENTS",
        (*suricata_store.SCHEMA_STATEMENTS, "CREATE TABLE broken ("),
    )

    with pytest.raises(SuricataStoreError, match="INITIALIZATION_FAILED"):
        initialize_suricata_store(path)

    assert not path.exists()
    assert not path.with_name(path.name + "-journal").exists()
    assert not path.with_name(path.name + "-wal").exists()


def test_module_exposes_no_consumer_or_runtime_write_api():
    assert not hasattr(suricata_store, "consume")
    assert not hasattr(suricata_store, "insert_alert")
    assert suricata_store.__all__ == [
        "SCHEMA_VERSION",
        "SuricataStoreError",
        "initialize_suricata_store",
        "validate_suricata_store",
    ]
