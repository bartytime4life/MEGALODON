"""MEGALODON's own descriptor checks must never release SQLite's POSIX locks.

On POSIX, closing any descriptor a process holds for a file releases all of
that process's fcntl locks on the file, including those a live SQLite
connection holds: its SHARED lock on the database and the -shm dead-man-switch
read lock at byte 128 that tells other processes the WAL index is in use.
These tests read /proc/locks, so they run only on Linux.
"""

from __future__ import annotations

from datetime import datetime, timezone
import errno
import os
from pathlib import Path
import socket
import sqlite3
import stat
import subprocess
import sys

import pytest

import megalodon.storage as storage_module
from megalodon.ai_broker import ReceiptStore
from megalodon.models import ActionRecord, PacketEvent
from megalodon.storage import DashboardStore, Store, StorageSchemaError

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux") or not os.access("/proc/locks", os.R_OK),
    reason="Linux /proc/locks required",
)

STAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)
# SQLite's unix VFS: the WAL-index dead-man switch and the database SHARED
# range (SHARED_FIRST = 0x40000002, SHARED_SIZE = 510).
SHM_DEAD_MAN_SWITCH = ("READ", 128, 128)
DATABASE_SHARED = ("READ", 0x40000002, 0x40000002 + 510 - 1)


def _locks(path: Path) -> set[tuple[str, int, int]]:
    inode = os.stat(path).st_ino
    held = set()
    with open("/proc/locks") as table:
        for line in table:
            fields = line.split()
            if len(fields) < 8 or fields[1] != "POSIX":
                continue
            if int(fields[4]) != os.getpid() or not fields[5].endswith(f":{inode}"):
                continue
            held.add((fields[3], int(fields[6]), int(fields[7])))
    return held


def _assert_sqlite_locks_held(path: Path) -> None:
    assert SHM_DEAD_MAN_SWITCH in _locks(path.with_name(path.name + "-shm"))
    assert DATABASE_SHARED in _locks(path)


def _private(tmp_path: Path) -> Path:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    return directory / "audit.db"


def _action(store: Store) -> None:
    store.record_action(ActionRecord(STAMP, "test", "192.0.2.1", "not_attempted", "x"))


def _wal_connection(path: Path) -> sqlite3.Connection:
    with Store(path) as store:
        _action(store)
    connection = sqlite3.connect(path)
    connection.execute("SELECT COUNT(*) FROM actions").fetchone()
    _assert_sqlite_locks_held(path)
    return connection


def test_premise_readable_close_drops_locks_and_o_path_close_does_not(tmp_path):
    path = _private(tmp_path)
    connection = _wal_connection(path)
    try:
        shm = path.with_name(path.name + "-shm")
        for target in (shm, path):
            os.close(os.open(target, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC))
        _assert_sqlite_locks_held(path)
        os.close(os.open(shm, os.O_RDONLY))
        assert SHM_DEAD_MAN_SWITCH not in _locks(shm)
        os.close(os.open(path, os.O_RDONLY))
        assert DATABASE_SHARED not in _locks(path)
    finally:
        connection.close()


def test_store_keeps_its_locks_through_open_write_and_capacity_check(tmp_path):
    path = _private(tmp_path)
    with Store(path) as store:
        store.summary()
        _assert_sqlite_locks_held(path)
        _action(store)
        store._ensure_capacity()
        _assert_sqlite_locks_held(path)
        _action(store)
        _assert_sqlite_locks_held(path)


def test_dashboard_read_and_close_keep_a_live_writers_locks(tmp_path):
    path = _private(tmp_path)
    with Store(path) as store:
        store.record_event(PacketEvent(STAMP, "192.0.2.1", "198.51.100.2", "TCP"))
        dashboard = DashboardStore(path)
        try:
            _assert_sqlite_locks_held(path)
            assert dashboard.summary()["events"] == 1
            _assert_sqlite_locks_held(path)
        finally:
            dashboard.close()
        _assert_sqlite_locks_held(path)
        store._ensure_capacity()
        _action(store)
        _assert_sqlite_locks_held(path)


def test_a_second_store_open_and_close_keeps_the_first_stores_locks(tmp_path):
    path = _private(tmp_path)
    with Store(path) as store:
        _action(store)
        with Store(path, create=False) as second:
            second.summary()
        _assert_sqlite_locks_held(path)
        _action(store)
        _assert_sqlite_locks_held(path)


def test_ai_receipt_store_keeps_its_locks(tmp_path):
    path = _private(tmp_path).with_name("receipts.db")
    with ReceiptStore(path):
        _assert_sqlite_locks_held(path)
        with ReceiptStore(path):
            pass
        _assert_sqlite_locks_held(path)


@pytest.mark.parametrize("writable", [True, False])
def test_validation_and_identity_helpers_keep_a_live_connections_locks(
    tmp_path, writable
):
    path = _private(tmp_path)
    connection = _wal_connection(path)
    directory = storage_module._open_private_directory(
        path.parent, create=False, prefix="STORAGE_PATH"
    )
    try:
        wal = path.with_name(path.name + "-wal")
        wal.chmod(0o644 if writable else 0o600)
        present = storage_module._validate_sqlite_sidecars(
            path, directory, writable=writable, prefix="STORAGE_PATH"
        )
        assert {"-wal", "-shm"} <= present
        # Normalisation still applies, without opening the file to do it.
        assert stat.S_IMODE(wal.stat().st_mode) == 0o600
        _assert_sqlite_locks_held(path)
        assert storage_module._validate_sqlite_sidecars(
            path, None, writable=writable, prefix="STORAGE_PATH"
        ) == present
        _assert_sqlite_locks_held(path)

        path.chmod(0o644 if writable else 0o600)
        descriptor, created = storage_module._open_private_database(
            path, directory, writable=writable, create=False, prefix="STORAGE_PATH"
        )
        try:
            assert not created
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            assert storage_module._path_matches_descriptor(path, descriptor)
            anchor = storage_module._anchored_database_path(
                descriptor, path, "STORAGE_PATH"
            )
            assert storage_module._writable_sqlite_connection_path(
                descriptor, path, "STORAGE_PATH"
            ) == (anchor, anchor)
            assert storage_module._sidecar_identities(path, directory)
            reader = sqlite3.connect(f"{anchor.as_uri()}?mode=ro", uri=True)
            assert reader.execute("SELECT COUNT(*) FROM actions").fetchone() == (1,)
            reader.close()
        finally:
            os.close(descriptor)
        _assert_sqlite_locks_held(path)
    finally:
        os.close(directory)
        connection.close()


@pytest.mark.parametrize("replacement", ["private", "hard_linked"])
def test_sidecar_relookup_keeps_live_connections_locks(
    tmp_path, monkeypatch, replacement
):
    path = _private(tmp_path)
    connection = _wal_connection(path)
    sidecar = path.with_name(path.name + "-journal")
    sidecar.write_bytes(b"")
    sidecar.chmod(0o600)
    original_open = storage_module._open_for_identity
    journal_opens = []

    def open_then_replace(target, flags, **kwargs):
        descriptor = original_open(target, flags, **kwargs)
        if str(target).endswith("-journal"):
            journal_opens.append(descriptor)
            if len(journal_opens) == 1:
                sidecar.unlink()
                other = path.parent / "replacement"
                other.write_bytes(b"")
                other.chmod(0o600)
                os.link(other, sidecar)
                if replacement == "private":
                    other.unlink()
        return descriptor

    monkeypatch.setattr(storage_module, "_open_for_identity", open_then_replace)
    try:
        if replacement == "hard_linked":
            with pytest.raises(
                StorageSchemaError, match="^STORAGE_PATH:UNSAFE_DATABASE$"
            ):
                storage_module._validate_sqlite_sidecars(
                    path, None, writable=True, prefix="STORAGE_PATH"
                )
        else:
            present = storage_module._validate_sqlite_sidecars(
                path, None, writable=True, prefix="STORAGE_PATH"
            )
            assert "-journal" in present
        assert len(journal_opens) == 2
        _assert_sqlite_locks_held(path)
    finally:
        connection.close()


def test_lock_preserving_open_fails_where_the_replaced_open_failed(tmp_path):
    path = _private(tmp_path)
    with Store(path) as store:
        store.summary()
    sidecar = path.with_name(path.name + "-journal")
    flags = os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW

    sidecar.symlink_to(path)
    with pytest.raises(OSError) as raised:
        storage_module._open_for_identity(sidecar, os.O_RDONLY | flags)
    assert raised.value.errno == errno.ELOOP
    with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:SYMLINK_REFUSED$"):
        storage_module._validate_sqlite_sidecars(
            path, None, writable=False, prefix="STORAGE_PATH"
        )
    sidecar.unlink()

    sidecar.mkdir(mode=0o700)
    with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:UNSAFE_SIDECAR$"):
        storage_module._validate_sqlite_sidecars(
            path, None, writable=True, prefix="STORAGE_PATH"
        )
    with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:UNSAFE_DATABASE$"):
        storage_module._validate_sqlite_sidecars(
            path, None, writable=False, prefix="STORAGE_PATH"
        )
    sidecar.rmdir()

    directory = os.open(sidecar.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    listener = socket.socket(socket.AF_UNIX)
    try:
        # Keep the socket address below Linux's sun_path limit even when the
        # owner-private pytest directory has a long absolute pathname.
        listener.bind(f"/proc/self/fd/{directory}/{sidecar.name}")
        with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:UNSAFE_SIDECAR$"):
            storage_module._validate_sqlite_sidecars(
                path, None, writable=False, prefix="STORAGE_PATH"
            )
    finally:
        listener.close()
        os.close(directory)
        sidecar.unlink(missing_ok=True)

    if os.geteuid() != 0:
        sidecar.write_bytes(b"")
        sidecar.chmod(0o400)
        with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:UNSAFE_SIDECAR$"):
            storage_module._validate_sqlite_sidecars(
                path, None, writable=True, prefix="STORAGE_PATH"
            )


_SECOND_PROCESS = r"""
import fcntl, os, sqlite3, sys
path = sys.argv[1]
def in_use(target, length, start):
    descriptor = os.open(target, os.O_RDWR)
    try:
        fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB, length, start)
    except OSError:
        return True
    finally:
        os.close(descriptor)
    return False
# SQLite reinitialises -shm when it can take this lock, and checkpoints and
# deletes the WAL when it can take this one.
print(in_use(path + "-shm", 1, 128), in_use(path, 510, 0x40000002))
reader = sqlite3.connect("file:" + path + "?mode=ro", uri=True)
print(reader.execute("SELECT COUNT(*) FROM actions").fetchone()[0])
reader.close()
"""


def test_another_process_sees_an_idle_stores_wal_index_in_use(tmp_path):
    path = _private(tmp_path)
    with Store(path) as store:
        _action(store)
        store._ensure_capacity()
        result = subprocess.run(
            [sys.executable, "-c", _SECOND_PROCESS, str(path)],
            capture_output=True, text=True, timeout=30, check=True,
        )
        assert result.stdout.split() == ["True", "True", "1"]
        _action(store)
        assert store.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert store.summary()["actions"] == 2
        _assert_sqlite_locks_held(path)


def test_managed_evidence_reader_keeps_the_writers_locks(tmp_path):
    from megalodon.config import Settings
    from megalodon.evidence_storage import GIB, EvidenceStorage, ManagedDashboardReader

    tmp_path.chmod(0o700)
    clock = [datetime.now(timezone.utc).timestamp()]
    manager = EvidenceStorage(
        Settings(db_path=tmp_path / "old.db"), home=tmp_path,
        clock=lambda: clock[0], monotonic=lambda: clock[0], segment_bytes=65536,
    )
    try:
        preview = manager.preview(
            dict(profile="home", retention_days=14, cap_bytes=20 * GIB)
        )
        manager.apply(preview["preview_id"])
        writer = manager.packet_writer()
        run = writer.start_ingestion_run("jsonl")
        event = PacketEvent(
            datetime.fromtimestamp(clock[0], timezone.utc), "10.0.0.2", "1.1.1.1", "TCP"
        )
        writer.record_event_bundle(event, [], [], run_id=run)
        path = writer.store.path
        _assert_sqlite_locks_held(path)
        assert ManagedDashboardReader(manager).summary()["events"] == 1
        _assert_sqlite_locks_held(path)
        writer.record_event_bundle(event, [], [], run_id=run)
        # The small segment size may rotate to a new unit on this write.
        _assert_sqlite_locks_held(writer.store.path)
        writer.finish_ingestion_run(run, "source_exhausted")
        writer.close()
    finally:
        manager.close()
