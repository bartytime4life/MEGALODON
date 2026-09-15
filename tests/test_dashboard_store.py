"""Fail-closed boundaries for the dashboard's SQLite projection."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
import stat
from threading import Event, Thread

import pytest

import megalodon.storage as storage_module
from megalodon.models import ActionRecord, DetectionResult, PacketEvent
from megalodon.storage import (
    DashboardStore,
    migrate_database,
    SCHEMA_V1_STATEMENTS,
    SCHEMA_VERSION,
    StorageSchemaError,
    Store,
)


STAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _seed(path: Path) -> None:
    with Store(path) as store:
        event = PacketEvent(STAMP, "192.0.2.1", "198.51.100.2", "TCP")
        event_id = store.record_event(event)
        store.record_detection(
            event_id,
            DetectionResult(
                STAMP,
                "TEST_RULE",
                "HIGH",
                event.src_ip,
                event.dst_ip,
                "synthetic finding",
                evidence={"private_marker": "must-not-be-read"},
            ),
        )
        store.record_action(
            ActionRecord(
                STAMP,
                "test",
                event.src_ip,
                "not_attempted",
                "synthetic decision",
            )
        )


def _sidecars(path: Path) -> set[Path]:
    return {
        candidate
        for suffix in ("-wal", "-shm", "-journal")
        if (candidate := path.with_name(path.name + suffix)).exists()
    }


def test_reader_requires_existing_parent_and_database_without_creating_them(tmp_path):
    missing_parent = tmp_path / "missing" / "audit.db"
    with pytest.raises(StorageSchemaError, match="^DASHBOARD_STORE:NO_DIRECTORY$") as raised:
        DashboardStore(missing_parent)
    assert str(missing_parent) not in str(raised.value)
    assert not missing_parent.parent.exists()

    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    missing_database = private / "audit.db"
    with pytest.raises(StorageSchemaError, match="^DASHBOARD_STORE:NO_DATABASE$"):
        DashboardStore(missing_database)
    assert not missing_database.exists()
    assert _sidecars(missing_database) == set()


def test_reader_requires_sqlite_with_read_only_wal_support(tmp_path, monkeypatch):
    path = tmp_path / "untouched" / "audit.db"
    monkeypatch.setattr(sqlite3, "sqlite_version_info", (3, 21, 0))

    with pytest.raises(
        StorageSchemaError, match="^DASHBOARD_STORE:UNSUPPORTED_SQLITE$"
    ):
        DashboardStore(path)

    assert not path.parent.exists()


def test_writer_creates_an_owner_private_leaf_directory_and_database(tmp_path):
    path = tmp_path / "nested" / "private" / "audit.db"
    with Store(path):
        pass

    if os.name == "posix":
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and modes required")
def test_writer_refuses_public_parent_symlink_and_hardlink_targets(tmp_path):
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    public.chmod(0o755)
    with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:UNSAFE_DIRECTORY$"):
        Store(public / "audit.db")
    assert not (public / "audit.db").exists()

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir(mode=0o700)
    parent_alias = tmp_path / "parent-alias"
    parent_alias.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:UNSAFE_DIRECTORY$"):
        Store(parent_alias / "audit.db")
    assert not (real_parent / "audit.db").exists()

    private = tmp_path / "private"
    path = private / "audit.db"
    _seed(path)
    alias = private / "alias.db"
    alias.symlink_to(path)
    with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:SYMLINK_REFUSED$"):
        Store(alias)

    hardlink = private / "hardlink.db"
    os.link(path, hardlink)
    with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:UNSAFE_DATABASE$"):
        Store(hardlink)


@pytest.mark.parametrize(
    ("constructor", "prefix"),
    [
        (DashboardStore, "DASHBOARD_STORE"),
        (Store, "STORAGE_PATH"),
    ],
)
def test_database_paths_reject_dotdot_before_symlink_collapse(
    tmp_path, monkeypatch, constructor, prefix
):
    private = tmp_path / "private"
    canonical = private / "audit.db"
    _seed(canonical)
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    alias = private / "alias"
    try:
        alias.symlink_to(other, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    ambiguous = private / "alias" / ".." / "audit.db"

    def forbidden(*_args, **_kwargs):
        raise AssertionError("SQLite opened an ambiguous database path")

    monkeypatch.setattr(storage_module.sqlite3, "connect", forbidden)
    with pytest.raises(
        StorageSchemaError, match=rf"^{prefix}:AMBIGUOUS_PATH$"
    ):
        constructor(ambiguous)

    assert canonical.is_file()
    assert not (tmp_path / "audit.db").exists()
    assert _sidecars(canonical) == set()


@pytest.mark.skipif(os.name != "posix", reason="POSIX ancestor modes required")
def test_reader_and_writer_refuse_a_replaceable_ancestor_before_sqlite(
    tmp_path, monkeypatch
):
    safe = tmp_path / "safe" / "audit.db"
    _seed(safe)
    replaceable = tmp_path / "replaceable"
    replaceable.mkdir(mode=0o777)
    replaceable.chmod(0o777)
    private = replaceable / "private"
    private.mkdir(mode=0o700)
    candidate = private / "audit.db"
    candidate.write_bytes(safe.read_bytes())
    candidate.chmod(0o600)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("replaceable ancestor reached sqlite")

    monkeypatch.setattr(sqlite3, "connect", forbidden)
    with pytest.raises(StorageSchemaError, match="^DASHBOARD_STORE:UNSAFE_ANCESTOR$"):
        DashboardStore(candidate)
    with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:UNSAFE_ANCESTOR$"):
        Store(replaceable / "writer" / "audit.db")
    assert _sidecars(candidate) == set()


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor paths required")
def test_reader_and_writer_require_a_stable_descriptor_sqlite_path(
    tmp_path, monkeypatch
):
    reader_path = tmp_path / "reader" / "audit.db"
    _seed(reader_path)
    monkeypatch.setattr(
        storage_module,
        "_descriptor_database_path",
        lambda _descriptor, fallback: str(fallback),
    )

    with pytest.raises(
        StorageSchemaError,
        match="^DASHBOARD_STORE:DESCRIPTOR_PATH_UNAVAILABLE$",
    ):
        DashboardStore(reader_path)

    writer_path = tmp_path / "writer" / "audit.db"
    with pytest.raises(
        StorageSchemaError,
        match="^STORAGE_PATH:DESCRIPTOR_PATH_UNAVAILABLE$",
    ):
        Store(writer_path)
    assert not writer_path.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and modes required")
def test_migration_requires_private_source_and_repairs_nothing_implicitly(tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    path = private / "legacy.db"
    with sqlite3.connect(path) as connection:
        for statement in SCHEMA_V1_STATEMENTS:
            connection.execute(statement)
        connection.execute("PRAGMA user_version=1")
    path.chmod(0o644)
    assert stat.S_IMODE(path.stat().st_mode) == 0o644

    with pytest.raises(
        StorageSchemaError, match="^STORAGE_MIGRATION:UNSAFE_DATABASE$"
    ):
        migrate_database(path)

    assert stat.S_IMODE(path.stat().st_mode) & 0o077
    assert not path.with_name(path.name + ".pre-v3.bak").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership required")
def test_reader_refuses_a_foreign_owner_before_sqlite_connect(tmp_path, monkeypatch):
    path = tmp_path / "private" / "audit.db"
    _seed(path)
    original_fstat = os.fstat

    def foreign_regular_file(descriptor):
        info = original_fstat(descriptor)
        if stat.S_ISREG(info.st_mode):
            values = list(info)
            values[4] = os.geteuid() + 1
            return os.stat_result(values)
        return info

    def forbidden(*_args, **_kwargs):
        raise AssertionError("foreign-owned path reached sqlite")

    monkeypatch.setattr(storage_module.os, "fstat", foreign_regular_file)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    with pytest.raises(StorageSchemaError, match="^DASHBOARD_STORE:UNSAFE_DATABASE$"):
        DashboardStore(path)


def test_reader_uses_ro_uri_query_only_and_a_deny_by_default_authorizer(
    tmp_path, monkeypatch
):
    suffix = " #" if os.name == "nt" else " #?"
    path = tmp_path / f"private{suffix}" / f"audit{suffix}.db"
    _seed(path)
    original_connect = sqlite3.connect
    calls: list[tuple[object, dict[str, object]]] = []

    def tracked_connect(database, *args, **kwargs):
        calls.append((database, kwargs.copy()))
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", tracked_connect)
    escape = tmp_path / "attached.db"
    with DashboardStore(path) as reader:
        assert not hasattr(reader, "connection")
        assert reader._connection.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
            reader._connection.execute("CREATE TABLE forbidden (value TEXT)")
        with pytest.raises(sqlite3.DatabaseError):
            reader._connection.execute("PRAGMA user_version=99")
        with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
            reader._connection.execute("ATTACH ? AS escaped", (str(escape),))
        with pytest.raises(sqlite3.DatabaseError, match="prohibited"):
            reader._connection.execute("SELECT evidence_json FROM detections")
        with pytest.raises(sqlite3.DatabaseError, match="prohibited"):
            reader._connection.execute("SELECT id FROM detections")

    assert not escape.exists()
    assert calls
    assert all(call[1].get("uri") is True for call in calls)
    assert any("mode=ro&immutable=1" in str(call[0]) for call in calls)
    assert any(
        "mode=ro&cache=private" in str(call[0])
        and "immutable=1" not in str(call[0])
        for call in calls
    )
    if os.name == "posix":
        assert any(
            marker in str(calls[-1][0])
            for marker in ("/proc/self/fd/", "/dev/fd/")
        )
    else:
        assert "%23" in str(calls[-1][0])


def test_reader_leaves_the_main_database_and_schema_state_unchanged(tmp_path):
    path = tmp_path / "private" / "audit.db"
    _seed(path)
    before_bytes = path.read_bytes()
    before_stat = path.stat()
    with sqlite3.connect(
        f"{path.as_uri()}?mode=ro&immutable=1", uri=True
    ) as observer:
        before_version = observer.execute("PRAGMA user_version").fetchone()[0]
        before_journal = observer.execute("PRAGMA journal_mode").fetchone()[0]

    with DashboardStore(path) as reader:
        assert reader.summary() == {
            "events": 1,
            "detections": 1,
            "actions": 1,
            "high_or_critical": 1,
        }
        assert reader.recent() == [
            {
                "detected_at": STAMP.isoformat(),
                "rule_id": "TEST_RULE",
                "severity": "HIGH",
                "src_ip": "192.0.2.1",
                "message": "synthetic finding",
            }
        ]

    after_stat = path.stat()
    assert path.read_bytes() == before_bytes
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns
    with sqlite3.connect(
        f"{path.as_uri()}?mode=ro&immutable=1", uri=True
    ) as observer:
        assert observer.execute("PRAGMA user_version").fetchone()[0] == before_version
        assert observer.execute("PRAGMA journal_mode").fetchone()[0] == before_journal
    for sidecar in _sidecars(path):
        assert sidecar.parent == path.parent
        assert stat.S_ISREG(sidecar.stat().st_mode)
        if os.name == "posix":
            assert stat.S_IMODE(sidecar.stat().st_mode) & 0o077 == 0


def test_summary_is_one_statement_and_recent_selects_only_public_fields(tmp_path):
    path = tmp_path / "private" / "audit.db"
    _seed(path)
    with Store(path) as writer:
        writer.connection.execute(
            "UPDATE detections SET evidence_json = 'not-json'"
        )
        writer.connection.commit()

    statements: list[str] = []
    with DashboardStore(path) as reader:
        reader._connection.set_trace_callback(statements.append)
        reader.summary()
        summary_statements = [item for item in statements if item.lstrip().upper().startswith("SELECT")]
        assert len(summary_statements) == 1
        statements.clear()
        rows = reader.recent(1)

    assert set(rows[0]) == set(DashboardStore.EVENT_FIELDS)
    recent_sql = " ".join(statements[-1].lower().split())
    assert "select detected_at, rule_id, severity, src_ip, message" in recent_sql
    for private_column in (
        "dst_ip",
        "evidence_json",
        "recommendation",
        "suppressed_reason",
    ):
        assert private_column not in recent_sql

    with sqlite3.connect(path) as observer:
        plan = " ".join(
            str(row[3])
            for row in observer.execute(
                "EXPLAIN QUERY PLAN "
                "SELECT detected_at, rule_id, severity, src_ip, message "
                "FROM detections ORDER BY detected_at DESC LIMIT 1"
            )
        )
    assert "idx_detections_detected_at" in plan
    assert "TEMP B-TREE" not in plan


def test_summary_returns_consistent_counts_when_a_wal_commit_overlaps(tmp_path):
    path = tmp_path / "private" / "audit.db"
    _seed(path)
    entered = Event()
    release = Event()
    result: dict[str, int] = {}
    failure: list[BaseException] = []

    with Store(path) as writer, DashboardStore(path) as reader:
        paused = False

        def pause_statement() -> int:
            nonlocal paused
            if not paused:
                paused = True
                entered.set()
                release.wait(timeout=5)
            return 0

        def read_summary() -> None:
            try:
                result.update(reader.summary())
            except BaseException as exc:  # pragma: no cover - reported below
                failure.append(exc)

        reader._connection.set_progress_handler(pause_statement, 1)
        thread = Thread(target=read_summary)
        thread.start()
        assert entered.wait(timeout=5)
        try:
            writer.connection.execute("BEGIN IMMEDIATE")
            event = writer.connection.execute(
                """INSERT INTO events (
                    observed_at, src_ip, dst_ip, protocol, src_port, dst_port,
                    tcp_flags, dns_query_length, byte_count, interface,
                    metadata_json
                ) VALUES (?, ?, ?, ?, NULL, NULL, '', NULL, 0, NULL, '{}')""",
                (STAMP.isoformat(), "192.0.2.3", "198.51.100.4", "TCP"),
            )
            writer.connection.execute(
                """INSERT INTO detections (
                    event_id, detected_at, rule_id, severity, src_ip, dst_ip,
                    message, evidence_json, recommendation, suppressed_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, '{}', '', NULL)""",
                (
                    event.lastrowid,
                    STAMP.isoformat(),
                    "SECOND_RULE",
                    "HIGH",
                    "192.0.2.3",
                    "198.51.100.4",
                    "second finding",
                ),
            )
            writer.connection.execute(
                """INSERT INTO actions (
                    created_at, action, target, status, reason, expires_at,
                    details_json
                ) VALUES (?, 'test', ?, 'not_attempted', 'second', NULL, '{}')""",
                (STAMP.isoformat(), "192.0.2.3"),
            )
            writer.connection.commit()
        finally:
            release.set()
            thread.join(timeout=5)
            reader._connection.set_progress_handler(None, 0)

    assert not thread.is_alive()
    assert failure == []
    assert result in (
        {"events": 1, "detections": 1, "actions": 1, "high_or_critical": 1},
        {"events": 2, "detections": 2, "actions": 2, "high_or_critical": 2},
    )


@pytest.mark.parametrize("limit", (True, False, 0, 201, -1, 1.5, "10", None))
def test_recent_rejects_type_confused_or_out_of_range_limits(tmp_path, limit):
    path = tmp_path / "private" / "audit.db"
    _seed(path)
    with DashboardStore(path) as reader:
        with pytest.raises(ValueError, match="^DASHBOARD_STORE:INVALID_LIMIT$"):
            reader.recent(limit)


@pytest.mark.parametrize("contents", (b"not sqlite", b""))
def test_incompatible_wal_format_database_creates_no_sidecars(tmp_path, contents):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    path = private / "audit.db"
    if contents:
        path.write_bytes(contents)
    else:
        with sqlite3.connect(path) as connection:
            connection.execute("CREATE TABLE unexpected (value TEXT)")
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            connection.execute("PRAGMA journal_mode=WAL")
    if os.name == "posix":
        path.chmod(0o600)
    assert _sidecars(path) == set()
    before_bytes = path.read_bytes()
    before_stat = path.stat()

    with pytest.raises(
        StorageSchemaError, match="^DASHBOARD_STORE:INCOMPATIBLE_SCHEMA$"
    ):
        DashboardStore(path)

    assert _sidecars(path) == set()
    after_stat = path.stat()
    assert path.read_bytes() == before_bytes
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns


@pytest.mark.parametrize("version", (1, SCHEMA_VERSION + 1))
def test_reader_refuses_legacy_and_future_versions_without_mutation(tmp_path, version):
    path = tmp_path / "private" / "audit.db"
    with Store(path):
        pass
    connection = sqlite3.connect(path)
    try:
        connection.execute(f"PRAGMA user_version={version}")
        connection.commit()
    finally:
        connection.close()
    if os.name == "posix":
        path.chmod(0o600)
    before_bytes = path.read_bytes()
    before_stat = path.stat()

    with pytest.raises(
        StorageSchemaError, match="^DASHBOARD_STORE:INCOMPATIBLE_SCHEMA$"
    ):
        DashboardStore(path)

    assert _sidecars(path) == set()
    after_stat = path.stat()
    assert path.read_bytes() == before_bytes
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns


@pytest.mark.skipif(os.name != "posix", reason="POSIX file types and modes required")
@pytest.mark.parametrize("kind", ("symlink", "hardlink", "fifo", "directory"))
def test_reader_refuses_unsafe_database_objects_before_sqlite_connect(
    tmp_path, monkeypatch, kind
):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    valid = private / "valid.db"
    _seed(valid)
    path = private / "candidate.db"
    if kind == "symlink":
        path.symlink_to(valid)
    elif kind == "hardlink":
        os.link(valid, path)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
    else:
        path.mkdir(mode=0o700)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("unsafe object reached sqlite")

    monkeypatch.setattr(sqlite3, "connect", forbidden)
    with pytest.raises(StorageSchemaError):
        DashboardStore(path)
    assert _sidecars(path) == set()


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and modes required")
def test_reader_refuses_public_directory_database_and_sidecars_before_connect(
    tmp_path, monkeypatch
):
    path = tmp_path / "private" / "audit.db"
    _seed(path)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("unsafe path reached sqlite")

    path.chmod(0o644)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    with pytest.raises(StorageSchemaError, match="^DASHBOARD_STORE:UNSAFE_DATABASE$"):
        DashboardStore(path)

    path.chmod(0o600)
    path.parent.chmod(0o711)
    with pytest.raises(StorageSchemaError, match="^DASHBOARD_STORE:UNSAFE_DIRECTORY$"):
        DashboardStore(path)

    path.parent.chmod(0o700)
    victim = tmp_path / "victim"
    victim.write_bytes(b"operator-owned")
    path.with_name(path.name + "-wal").symlink_to(victim)
    with pytest.raises(StorageSchemaError, match="^DASHBOARD_STORE:SYMLINK_REFUSED$"):
        DashboardStore(path)
    assert victim.read_bytes() == b"operator-owned"


def test_reader_refuses_mixed_sqlite_sidecars_without_connecting(tmp_path, monkeypatch):
    path = tmp_path / "private" / "audit.db"
    _seed(path)
    wal = path.with_name(path.name + "-wal")
    wal.write_bytes(b"")
    if os.name == "posix":
        wal.chmod(0o600)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("mixed sidecars reached sqlite")

    monkeypatch.setattr(sqlite3, "connect", forbidden)
    with pytest.raises(
        StorageSchemaError, match="^DASHBOARD_STORE:UNSAFE_SIDECAR_STATE$"
    ):
        DashboardStore(path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO required")
def test_reader_refuses_a_sidecar_fifo_without_blocking_or_connecting(
    tmp_path, monkeypatch
):
    path = tmp_path / "private" / "audit.db"
    _seed(path)
    os.mkfifo(path.with_name(path.name + "-wal"), 0o600)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("sidecar FIFO reached sqlite")

    monkeypatch.setattr(sqlite3, "connect", forbidden)
    with pytest.raises(StorageSchemaError, match="^DASHBOARD_STORE:UNSAFE_DATABASE$"):
        DashboardStore(path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX open-file replacement semantics")
def test_reader_detects_database_replacement_during_open(tmp_path, monkeypatch):
    path = tmp_path / "private" / "audit.db"
    replacement = tmp_path / "replacement" / "audit.db"
    _seed(path)
    _seed(replacement)
    original_connect = sqlite3.connect
    replaced = False

    def replace_then_connect(database, *args, **kwargs):
        nonlocal replaced
        if not replaced:
            replaced = True
            os.replace(replacement, path)
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", replace_then_connect)
    with pytest.raises(
        StorageSchemaError,
        match="^DASHBOARD_STORE:(DATABASE_CHANGED|OPEN_FAILED)$",
    ):
        DashboardStore(path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX open-file rename semantics")
def test_reader_rejects_a_transient_public_sqlite_path_before_query(
    tmp_path, monkeypatch
):
    path = tmp_path / "private" / "audit.db"
    decoy = tmp_path / "decoy" / "audit.db"
    public = tmp_path / "public"
    transient = public / "moved.db"
    _seed(path)
    _seed(decoy)
    public.mkdir(mode=0o777)
    public.chmod(0o777)
    original_connect = sqlite3.connect
    normal_connects = 0

    def transient_then_connect(database, *args, **kwargs):
        nonlocal normal_connects
        if "immutable=1" not in str(database):
            normal_connects += 1
        if normal_connects != 2:
            return original_connect(database, *args, **kwargs)

        os.replace(path, transient)
        try:
            connection = original_connect(database, *args, **kwargs)
        except Exception:
            os.replace(transient, path)
            raise
        os.replace(transient, path)
        os.replace(decoy, transient)
        return connection

    monkeypatch.setattr(sqlite3, "connect", transient_then_connect)
    with pytest.raises(StorageSchemaError, match="^DASHBOARD_STORE:DATABASE_CHANGED$"):
        DashboardStore(path)

    assert path.exists()
    assert transient.exists()
    assert not transient.with_name(transient.name + "-wal").exists()
    assert not transient.with_name(transient.name + "-shm").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX open-file rename semantics")
def test_writer_rejects_a_transient_public_sqlite_path_before_query(
    tmp_path, monkeypatch
):
    path = tmp_path / "private" / "audit.db"
    decoy = tmp_path / "decoy" / "audit.db"
    public = tmp_path / "public"
    transient = public / "moved.db"
    _seed(path)
    _seed(decoy)
    public.mkdir(mode=0o777)
    public.chmod(0o777)
    original_connect = sqlite3.connect

    def transient_then_connect(database, *args, **kwargs):
        os.replace(path, transient)
        try:
            connection = original_connect(database, *args, **kwargs)
        except Exception:
            os.replace(transient, path)
            raise
        os.replace(transient, path)
        os.replace(decoy, transient)
        return connection

    monkeypatch.setattr(sqlite3, "connect", transient_then_connect)
    with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:DATABASE_CHANGED$"):
        Store(path)

    assert path.exists()
    assert transient.exists()
    assert not transient.with_name(transient.name + "-wal").exists()
    assert not transient.with_name(transient.name + "-shm").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory generation required")
def test_writer_start_during_immutable_preflight_fails_closed(tmp_path, monkeypatch):
    path = tmp_path / "private" / "audit.db"
    _seed(path)
    original_connect = sqlite3.connect
    concurrent_writer: sqlite3.Connection | None = None

    def start_writer_during_preflight(database, *args, **kwargs):
        nonlocal concurrent_writer
        connection = original_connect(database, *args, **kwargs)
        if "immutable=1" in str(database) and concurrent_writer is None:
            concurrent_writer = original_connect(path)
            concurrent_writer.execute("PRAGMA journal_mode=WAL")
            concurrent_writer.execute(
                """INSERT INTO actions (
                    created_at, action, target, status, reason, expires_at,
                    details_json
                ) VALUES (?, 'test', '192.0.2.9', 'not_attempted',
                          'concurrent', NULL, '{}')""",
                (STAMP.isoformat(),),
            )
            concurrent_writer.commit()
        return connection

    monkeypatch.setattr(sqlite3, "connect", start_writer_during_preflight)
    try:
        with pytest.raises(
            StorageSchemaError, match="^DASHBOARD_STORE:DIRECTORY_CHANGED$"
        ):
            DashboardStore(path)
    finally:
        if concurrent_writer is not None:
            concurrent_writer.close()


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory generation required")
def test_reader_rejects_sidecar_aba_between_requests(tmp_path):
    path = tmp_path / "private" / "audit.db"
    _seed(path)
    with DashboardStore(path) as reader:
        sidecars = _sidecars(path)
        assert sidecars
        sidecar = sorted(sidecars)[0]
        parked = sidecar.with_name(sidecar.name + ".parked")
        os.replace(sidecar, parked)
        os.replace(parked, sidecar)

        with pytest.raises(
            StorageSchemaError, match="^DASHBOARD_STORE:DIRECTORY_CHANGED$"
        ):
            reader.summary()


def test_reader_observes_commits_but_not_uncommitted_wal_rows(tmp_path):
    path = tmp_path / "private" / "audit.db"
    with Store(path) as writer:
        writer.connection.execute("PRAGMA wal_autocheckpoint=0")
        writer.record_action(
            ActionRecord(STAMP, "test", "192.0.2.1", "not_attempted", "first")
        )
        wal = path.with_name(path.name + "-wal")
        shm = path.with_name(path.name + "-shm")
        assert wal.exists() and shm.exists()

        with DashboardStore(path) as reader:
            assert reader.summary()["actions"] == 1
            writer.connection.execute("BEGIN IMMEDIATE")
            writer.connection.execute(
                "INSERT INTO actions (created_at, action, target, status, reason, "
                "expires_at, details_json) VALUES (?, ?, ?, ?, ?, NULL, '{}')",
                (STAMP.isoformat(), "test", "192.0.2.2", "not_attempted", "second"),
            )
            assert reader.summary()["actions"] == 1
            writer.connection.commit()
            assert reader.summary()["actions"] == 2

        for sidecar in (wal, shm):
            assert stat.S_ISREG(sidecar.stat().st_mode)
            if os.name == "posix":
                assert stat.S_IMODE(sidecar.stat().st_mode) & 0o077 == 0
