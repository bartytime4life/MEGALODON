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


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor semantics")
def test_darwin_writable_sqlite_path_uses_only_admitted_canonical_path(
    tmp_path, monkeypatch
):
    private = tmp_path / "private"
    private.mkdir(mode=storage.PRIVATE_DIRECTORY_MODE)
    database = private / "audit.db"
    directory_fd = storage._open_private_directory(
        private, create=False, prefix="STORAGE_PATH"
    )
    database_fd = None
    try:
        database_fd, _ = storage._open_private_database(
            database,
            directory_fd,
            writable=True,
            create=True,
            prefix="STORAGE_PATH",
        )
        monkeypatch.setattr(storage.sys, "platform", "darwin")
        sqlite_path, anchor = storage._writable_sqlite_connection_path(
            database_fd, database, "STORAGE_PATH"
        )
        assert sqlite_path == database
        assert anchor is None
        assert storage._path_matches_descriptor(database, database_fd)
    finally:
        if database_fd is not None:
            os.close(database_fd)
        os.close(directory_fd)


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor semantics")
def test_darwin_writable_sqlite_path_refuses_replaced_database(
    tmp_path, monkeypatch
):
    private = tmp_path / "private"
    private.mkdir(mode=storage.PRIVATE_DIRECTORY_MODE)
    database = private / "audit.db"
    moved = private / "original.db"
    directory_fd = storage._open_private_directory(
        private, create=False, prefix="STORAGE_PATH"
    )
    database_fd = None
    try:
        database_fd, _ = storage._open_private_database(
            database,
            directory_fd,
            writable=True,
            create=True,
            prefix="STORAGE_PATH",
        )
        database.rename(moved)
        database.write_bytes(b"replacement")
        database.chmod(storage.PRIVATE_DATABASE_MODE)
        monkeypatch.setattr(storage.sys, "platform", "darwin")
        with pytest.raises(
            StorageSchemaError, match="^STORAGE_PATH:DATABASE_CHANGED$"
        ):
            storage._writable_sqlite_connection_path(
                database_fd, database, "STORAGE_PATH"
            )
    finally:
        if database_fd is not None:
            os.close(database_fd)
        os.close(directory_fd)


@pytest.mark.skipif(os.name != "posix", reason="POSIX path and mode semantics")
def test_darwin_store_branch_creates_and_writes_without_descriptor_journal(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(storage.sys, "platform", "darwin")
    database = tmp_path / "audit.db"
    with Store(database) as store:
        _populate(store)
        assert store.summary()["events"] == 1
        assert store._database_descriptor is not None
        assert storage._path_matches_descriptor(
            store.path, store._database_descriptor
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX replacement semantics")
def test_darwin_store_refuses_runtime_database_replacement_before_write(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(storage.sys, "platform", "darwin")
    database = tmp_path / "audit.db"
    moved = tmp_path / "original.db"
    store = Store(database)
    replacement = b"replacement-sentinel"
    try:
        database.rename(moved)
        database.write_bytes(replacement)
        database.chmod(storage.PRIVATE_DATABASE_MODE)
        with pytest.raises(
            StorageSchemaError, match="^STORAGE_PATH:DATABASE_CHANGED$"
        ):
            store.start_ingestion_run("sample")
        assert database.read_bytes() == replacement
    finally:
        if database.exists():
            database.unlink()
        if moved.exists():
            moved.rename(database)
        store.close()


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink semantics")
def test_darwin_store_refuses_symlinked_sqlite_sidecar_before_connect(
    tmp_path, monkeypatch
):
    database = tmp_path / "audit.db"
    with Store(database):
        pass
    target = tmp_path / "outside"
    target.write_bytes(b"sidecar-target")
    target.chmod(storage.PRIVATE_DATABASE_MODE)
    sidecar = tmp_path / "audit.db-wal"
    sidecar.symlink_to(target)
    monkeypatch.setattr(storage.sys, "platform", "darwin")
    with pytest.raises(StorageSchemaError, match="SYMLINK_REFUSED"):
        Store(database, create=False)


def _swap_ancestor_during_connect(monkeypatch, admitted_root: Path, other_root: Path):
    held = admitted_root.with_name(admitted_root.name + "-held")
    real_connect = sqlite3.connect

    def swapping_connect(*args, **kwargs):
        admitted_root.rename(held)
        other_root.rename(admitted_root)
        try:
            return real_connect(*args, **kwargs)
        finally:
            admitted_root.rename(other_root)
            held.rename(admitted_root)

    monkeypatch.setattr(storage.sqlite3, "connect", swapping_connect)


@pytest.mark.skipif(os.name != "posix", reason="POSIX rename semantics")
def test_darwin_store_refuses_ancestor_swap_while_sqlite_resolves_path(
    tmp_path, monkeypatch
):
    admitted_root = tmp_path / "admitted"
    other_root = tmp_path / "other"
    for root in (admitted_root, other_root):
        (root / "private").mkdir(parents=True, mode=storage.PRIVATE_DIRECTORY_MODE)
    database = admitted_root / "private" / "audit.db"
    other = other_root / "private" / "audit.db"
    with Store(database):
        pass
    with Store(other) as store:
        _populate(store)
    other_bytes = other.read_bytes()
    monkeypatch.setattr(storage.sys, "platform", "darwin")
    _swap_ancestor_during_connect(monkeypatch, admitted_root, other_root)

    with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:DATABASE_CHANGED$"):
        Store(database, create=False)

    assert other.read_bytes() == other_bytes
    monkeypatch.undo()
    with Store(database, create=False) as store:
        assert store.summary()["events"] == 0


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor semantics")
def test_darwin_store_refuses_when_open_descriptors_cannot_be_listed(
    tmp_path, monkeypatch
):
    database = tmp_path / "audit.db"
    with Store(database):
        pass
    monkeypatch.setattr(storage.sys, "platform", "darwin")
    monkeypatch.setattr(storage, "_open_regular_file_identities", lambda: None)
    with pytest.raises(
        StorageSchemaError, match="^STORAGE_PATH:DESCRIPTOR_PATH_UNAVAILABLE$"
    ):
        Store(database, create=False)


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor semantics")
def test_darwin_store_accepts_reused_descriptor_only_with_unchanged_ancestors(
    tmp_path, monkeypatch
):
    database = tmp_path / "nested" / "audit.db"
    database.parent.mkdir(mode=storage.PRIVATE_DIRECTORY_MODE)
    with Store(database):
        pass
    monkeypatch.setattr(storage.sys, "platform", "darwin")
    frozen = storage._open_regular_file_identities()
    monkeypatch.setattr(storage, "_open_regular_file_identities", lambda: frozen)
    with Store(database, create=False) as store:
        assert store.summary()["events"] == 0

    real_connect = sqlite3.connect

    def touching_connect(*args, **kwargs):
        (tmp_path / "ancestor-entry").touch()
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(storage.sqlite3, "connect", touching_connect)
    with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:DATABASE_CHANGED$"):
        Store(database, create=False)


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor semantics")
def test_darwin_store_refuses_unattributed_open_without_admitted_descriptor(
    tmp_path, monkeypatch
):
    database = tmp_path / "audit.db"
    with Store(database):
        pass
    monkeypatch.setattr(storage.sys, "platform", "darwin")
    frozen = storage._open_regular_file_identities()
    snapshots = iter([frozen, {**frozen, 1_000_000: (0, 0)}])
    monkeypatch.setattr(
        storage, "_open_regular_file_identities", lambda: next(snapshots)
    )
    with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:DATABASE_CHANGED$"):
        Store(database, create=False)


@pytest.mark.skipif(os.name != "posix", reason="POSIX rename semantics")
def test_darwin_store_refuses_swap_to_file_with_reusable_sqlite_descriptor(
    tmp_path, monkeypatch
):
    # Keep one connection open per file so SQLite defers closing the next
    # connection's descriptor; a later open of that inode reuses it, so no
    # new descriptor reveals which file SQLite opened.
    admitted_root = tmp_path / "admitted"
    other_root = tmp_path / "other"
    for root in (admitted_root, other_root):
        (root / "private").mkdir(parents=True, mode=storage.PRIVATE_DIRECTORY_MODE)
    database = admitted_root / "private" / "audit.db"
    other = other_root / "private" / "audit.db"
    monkeypatch.setattr(storage.sys, "platform", "darwin")
    holders = [Store(database), Store(other)]
    try:
        _populate(holders[1])
        Store(other, create=False).close()
        _swap_ancestor_during_connect(monkeypatch, admitted_root, other_root)
        snapshots = []
        real_identities = storage._open_regular_file_identities

        def recording_identities():
            snapshots.append(real_identities())
            return snapshots[-1]

        monkeypatch.setattr(
            storage, "_open_regular_file_identities", recording_identities
        )
        with pytest.raises(
            StorageSchemaError, match="^STORAGE_PATH:DATABASE_CHANGED$"
        ):
            Store(database, create=False)
        before, after = snapshots
        assert not {fd for fd, identity in after.items() if before.get(fd) != identity}
    finally:
        for holder in holders:
            holder.close()


@pytest.mark.skipif(os.name != "posix", reason="POSIX rename semantics")
def test_darwin_store_refuses_swap_taken_before_ancestor_baseline(
    tmp_path, monkeypatch
):
    # The swap lands after the pre-connect path check but before the
    # verifier's ancestor baseline, so both ancestor samples see the same
    # swapped tree; it is restored only after the second sample.
    admitted_root = tmp_path / "admitted"
    other_root = tmp_path / "other"
    held_root = tmp_path / "held"
    for root in (admitted_root, other_root):
        (root / "private").mkdir(parents=True, mode=storage.PRIVATE_DIRECTORY_MODE)
    database = admitted_root / "private" / "audit.db"
    other = other_root / "private" / "audit.db"
    monkeypatch.setattr(storage.sys, "platform", "darwin")
    holders = [Store(database), Store(other)]
    try:
        _populate(holders[1])
        Store(other, create=False).close()
        real_generations = storage._ancestor_generations
        calls = []

        def swapping_generations(directory):
            calls.append(directory)
            if len(calls) == 1:
                admitted_root.rename(held_root)
                other_root.rename(admitted_root)
            generations = real_generations(directory)
            if len(calls) == 2:
                admitted_root.rename(other_root)
                held_root.rename(admitted_root)
            return generations

        monkeypatch.setattr(storage, "_ancestor_generations", swapping_generations)
        with pytest.raises(
            StorageSchemaError, match="^STORAGE_PATH:DATABASE_CHANGED$"
        ):
            Store(database, create=False)
        if held_root.exists():
            admitted_root.rename(other_root)
            held_root.rename(admitted_root)
    finally:
        for holder in holders:
            holder.close()


@pytest.mark.skipif(os.name != "posix", reason="POSIX link and rename semantics")
def test_darwin_store_refuses_swapped_parent_holding_admitted_hardlink(
    tmp_path, monkeypatch
):
    # Before the baseline, the ancestor swap installs a directory whose
    # audit.db is a temporary hard link to the admitted inode, so a pathname
    # identity check alone passes. The link is then replaced by an alternate
    # store with a reusable SQLite descriptor, and everything is restored
    # after the second ancestor sample.
    admitted_root = tmp_path / "admitted"
    swapped_root = tmp_path / "swapped"
    held_root = tmp_path / "held"
    alternate_root = tmp_path / "alternate"
    for root in (admitted_root, swapped_root, alternate_root):
        (root / "private").mkdir(parents=True, mode=storage.PRIVATE_DIRECTORY_MODE)
    database = admitted_root / "private" / "audit.db"
    alternate = alternate_root / "private" / "audit.db"
    monkeypatch.setattr(storage.sys, "platform", "darwin")
    holders = [Store(database), Store(alternate)]
    try:
        _populate(holders[1])
        Store(alternate, create=False).close()
        real_generations = storage._ancestor_generations
        real_connect = sqlite3.connect
        calls = []

        def swapping_generations(directory):
            calls.append(directory)
            if len(calls) == 1:
                os.link(database, swapped_root / "private" / "audit.db")
                admitted_root.rename(held_root)
                swapped_root.rename(admitted_root)
            generations = real_generations(directory)
            if len(calls) == 2:
                os.replace(database, alternate)
                admitted_root.rename(swapped_root)
                held_root.rename(admitted_root)
            return generations

        def replacing_connect(*args, **kwargs):
            os.replace(alternate, database)
            return real_connect(*args, **kwargs)

        monkeypatch.setattr(storage, "_ancestor_generations", swapping_generations)
        monkeypatch.setattr(storage.sqlite3, "connect", replacing_connect)
        with pytest.raises(
            StorageSchemaError, match="^STORAGE_PATH:DATABASE_CHANGED$"
        ):
            Store(database, create=False)
        assert calls and len(calls) == 1
    finally:
        monkeypatch.undo()
        if held_root.exists():
            admitted_root.rename(swapped_root)
            held_root.rename(admitted_root)
        link = swapped_root / "private" / "audit.db"
        if link.exists():
            link.unlink()
        for holder in holders:
            holder.close()


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor semantics")
def test_darwin_store_verification_tolerates_concurrent_admitted_opens(
    tmp_path, monkeypatch
):
    from concurrent.futures import ThreadPoolExecutor

    monkeypatch.setattr(storage.sys, "platform", "darwin")
    database = tmp_path / "audit.db"

    def open_and_read(index: int) -> int:
        if index % 2:
            with DashboardStore(database) as dashboard:
                return dashboard.summary()["events"]
        with Store(database, create=False) as store:
            return store.summary()["events"]

    # A long-lived writer keeps WAL sidecars in place, as the HUD does, and
    # makes SQLite defer and reuse closed connections' descriptors.
    with Store(database) as holder:
        _populate(holder)
        with ThreadPoolExecutor(max_workers=8) as pool:
            assert set(pool.map(open_and_read, range(96))) == {1}


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
