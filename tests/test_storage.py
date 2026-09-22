from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
import tempfile

import pytest

from megalodon import storage
from megalodon.models import ActionRecord, DetectionResult, PacketEvent
from megalodon.storage import DashboardStore, StorageSchemaError, Store


STAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _populate(store: Store) -> None:
    event = PacketEvent(STAMP, "192.0.2.1", "198.51.100.2", "TCP")
    event_id = store.record_event(event)
    store.record_detection(
        event_id,
        DetectionResult(STAMP, "TEST", "LOW", event.src_ip, event.dst_ip, "synthetic"),
    )
    store.record_action(
        ActionRecord(STAMP, "test", event.src_ip, "not_attempted", "synthetic")
    )


def test_dashboard_store_requires_existing_private_compatible_database(tmp_path):
    database = tmp_path / "audit.db"
    with pytest.raises(StorageSchemaError, match="NO_DATABASE"):
        DashboardStore(database)
    with Store(database) as store:
        _populate(store)
    with DashboardStore(database) as reader:
        assert reader.summary() == {
            "events": 1, "detections": 1, "actions": 1, "high_or_critical": 0,
        }
        assert reader.recent(1) == [{
            "detected_at": STAMP.isoformat(), "rule_id": "TEST", "severity": "LOW",
            "src_ip": "192.0.2.1", "message": "synthetic",
        }]
        assert not hasattr(reader, "connection")
        assert reader._connection.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
            reader._connection.execute("DELETE FROM events")


def test_validate_connection_path_accepts_a_verified_anchor_match(tmp_path):
    class _FakeRows:
        def fetchall(self):
            return [(0, "main", "/dev/fd/5")]

    class _FakeConnection:
        def execute(self, _sql):
            return _FakeRows()

    expected = tmp_path / "private" / "audit.db"
    storage._validate_connection_path(
        _FakeConnection(), expected, "STORAGE_PATH", anchor=Path("/dev/fd/5")
    )


def test_validate_connection_path_refuses_when_neither_expected_nor_anchor_match(
    tmp_path,
):
    class _FakeRows:
        def fetchall(self):
            return [(0, "main", "/dev/fd/5")]

    class _FakeConnection:
        def execute(self, _sql):
            return _FakeRows()

    expected = tmp_path / "private" / "audit.db"
    with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:DATABASE_CHANGED$"):
        storage._validate_connection_path(
            _FakeConnection(), expected, "STORAGE_PATH", anchor=Path("/dev/fd/9")
        )
    with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:DATABASE_CHANGED$"):
        storage._validate_connection_path(_FakeConnection(), expected, "STORAGE_PATH")


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink and mode semantics")
def test_dashboard_store_rejects_symlink_and_public_storage(tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    database = private / "audit.db"
    with Store(database):
        pass
    alias = private / "alias.db"
    alias.symlink_to(database)
    with pytest.raises(StorageSchemaError, match="SYMLINK_REFUSED"):
        DashboardStore(alias)
    private.chmod(0o755)
    with pytest.raises(StorageSchemaError, match="UNSAFE_DIRECTORY"):
        DashboardStore(database)


def test_resolve_top_level_system_alias_rewrites_verified_compat_link(monkeypatch):
    monkeypatch.setattr(
        storage.os.path,
        "realpath",
        lambda candidate: "/private/var" if candidate == "/var" else candidate,
    )
    rewritten = storage._resolve_top_level_system_alias(
        Path("/var/folders/xx/yyyy/private")
    )
    assert rewritten == Path("/private/var/folders/xx/yyyy/private")


@pytest.mark.parametrize(
    "path",
    [
        Path("/opt/megalodon/private"),
        Path("/opt/var/private"),
    ],
)
def test_resolve_top_level_system_alias_ignores_unrelated_or_nested_names(
    monkeypatch, path
):
    monkeypatch.setattr(
        storage.os.path,
        "realpath",
        lambda candidate: "/private/var" if candidate == "/var" else candidate,
    )
    assert storage._resolve_top_level_system_alias(path) == path


def test_resolve_top_level_system_alias_refuses_unverified_target(monkeypatch):
    monkeypatch.setattr(storage.os.path, "realpath", lambda candidate: candidate)
    unresolved = Path("/var/other")
    assert storage._resolve_top_level_system_alias(unresolved) == unresolved


@pytest.mark.skipif(
    os.name != "posix" or os.path.realpath("/tmp") == "/tmp",
    reason="requires a platform where /tmp is a top-level compatibility symlink",
)
def test_open_private_directory_accepts_real_top_level_compat_symlink():
    with tempfile.TemporaryDirectory() as root:
        private = Path(root) / "private"
        private.mkdir(mode=storage.PRIVATE_DIRECTORY_MODE)
        descriptor = storage._open_private_directory(
            private, create=False, prefix="STORAGE_PATH"
        )
        try:
            assert descriptor is not None
        finally:
            os.close(descriptor)


@pytest.mark.skipif(
    os.name != "posix" or os.path.realpath("/tmp") == "/tmp",
    reason="requires a platform where /tmp is a top-level compatibility symlink",
)
def test_store_opens_through_real_top_level_compat_symlink():
    # SQLite reports PRAGMA database_list's filename via its own
    # platform-dependent handling of the descriptor-anchored connection path
    # (fully realpath'd on some platforms, reported back literally on
    # others), so an unresolved self.path would otherwise spuriously fail
    # STORAGE_PATH:DATABASE_CHANGED's comparison the first time this path is
    # actually exercised through a real alias.
    with tempfile.TemporaryDirectory() as root:
        with Store(Path(root) / "audit.db") as store:
            _populate(store)
            assert store.summary()["events"] == 1


def test_purge_requires_a_timezone_aware_cutoff(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        _populate(store)
        before = store.summary()

        with pytest.raises(ValueError, match="timezone-aware"):
            store.preview_purge(datetime(2027, 1, 1))

        assert store.summary() == before


def test_purge_removes_all_matching_audit_rows(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        _populate(store)

        cutoff = datetime(2027, 1, 1, tzinfo=timezone.utc)
        preview = store.preview_purge(cutoff)
        receipt = store.purge_before(
            cutoff,
            batch_limit=preview["batch_limit"],
            preview_token=preview["preview_token"],
        )
        assert receipt["deleted"] == {
            "detections": 1,
            "events": 1,
            "actions": 1,
        }
        assert receipt["deleted_total"] == 3
        assert receipt["complete"] is True
        assert store.summary() == {
            "events": 0,
            "detections": 0,
            "actions": 0,
            "high_or_critical": 0,
        }


def test_purge_rolls_back_every_table_when_one_delete_fails(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        _populate(store)
        before = store.summary()
        cutoff = datetime(2027, 1, 1, tzinfo=timezone.utc)
        preview = store.preview_purge(cutoff)
        store.connection.execute(
            """
            CREATE TRIGGER stop_event_delete
            BEFORE DELETE ON events
            BEGIN
                SELECT RAISE(ABORT, 'synthetic failure');
            END
            """
        )
        store.connection.commit()

        with pytest.raises(sqlite3.IntegrityError):
            store.purge_before(
                cutoff,
                batch_limit=preview["batch_limit"],
                preview_token=preview["preview_token"],
            )

        assert store.connection.in_transaction is False
        assert store.summary() == before
