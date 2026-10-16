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
from types import SimpleNamespace

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


def _without_o_path(monkeypatch) -> None:
    """Run storage as on Darwin: no O_PATH, so closing any descriptor for an
    inode releases this process's locks on it. SQLite and /proc/locks still
    use the real OS, so the lock assertions below observe real locks."""
    monkeypatch.setattr(storage_module, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(storage_module, "_LOCK_PRESERVING_OPEN", False)


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


@pytest.mark.parametrize("o_path", [True, False], ids=["o_path", "stat_only"])
def test_lock_preserving_open_fails_where_the_replaced_open_failed(
    tmp_path, monkeypatch, o_path
):
    if not o_path:
        _without_o_path(monkeypatch)
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


def _hide_fd_aliases(monkeypatch, *, proc_directory, hide_dev=False):
    """Synthetic alias visibility; SQLite and /proc/locks use real OS calls."""
    real_stat, real_access, real_isdir = os.stat, os.access, os.path.isdir

    def hidden(path):
        value = os.fspath(path) if isinstance(path, (str, bytes, os.PathLike)) else ""
        return isinstance(value, str) and (
            value.startswith("/proc/self/fd/")
            or (hide_dev and value.startswith("/dev/fd/"))
        )

    def stat_(path, *args, **kwargs):
        if hidden(path):
            raise FileNotFoundError(errno.ENOENT, "synthetic unavailable alias", str(path))
        return real_stat(path, *args, **kwargs)

    def access(path, mode, *args, **kwargs):
        return False if hidden(path) else real_access(path, mode, *args, **kwargs)

    def isdir(path):
        if str(path) == "/proc/self/fd":
            return proc_directory
        return real_isdir(path)

    monkeypatch.setattr(os, "stat", stat_)
    monkeypatch.setattr(os, "access", access)
    monkeypatch.setattr(os.path, "isdir", isdir)


_TRANSACTION_PROBE = r"""
import sqlite3, sys
c = sqlite3.connect(sys.argv[1], timeout=0)
try:
    print(c.execute("SELECT group_concat(v) FROM probe").fetchone()[0])
    try:
        c.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError as exc:
        if exc.sqlite_errorcode != sqlite3.SQLITE_BUSY:
            raise
        print("busy")
    else:
        print("admitted")
        c.rollback()
finally:
    c.close()
"""


def _transaction_connection(path, journal):
    connection = sqlite3.connect(path, timeout=0)
    connection.execute(f"PRAGMA journal_mode={journal}")
    connection.execute("CREATE TABLE probe(v INTEGER)")
    connection.execute("INSERT INTO probe VALUES (1)")
    connection.commit()
    path.chmod(0o600)
    connection.execute("BEGIN IMMEDIATE")
    connection.execute("INSERT INTO probe VALUES (2)")
    assert connection.in_transaction
    assert _locks(path)
    return connection


def _assert_competing_writer_refused(path):
    result = subprocess.run(
        [sys.executable, "-c", _TRANSACTION_PROBE, str(path)],
        capture_output=True, text=True, timeout=30, check=True,
    )
    assert result.stdout.split() == ["1", "busy"]


@pytest.mark.parametrize("proc_directory", [False, True])
@pytest.mark.parametrize("journal", ["WAL", "DELETE"])
def test_dev_fd_identity_fallback_preserves_active_transaction(
    tmp_path, monkeypatch, proc_directory, journal
):
    # Real Linux locks and separate SQLite processes, synthetic alias denial.
    assert os.geteuid() != 0, "acceptance must run without root"
    path = _private(tmp_path)
    connection = _transaction_connection(path, journal)
    try:
        before = _locks(path)
        _assert_competing_writer_refused(path)
        _hide_fd_aliases(monkeypatch, proc_directory=proc_directory)
        path.chmod(0o644)
        descriptor, created = storage_module._open_private_database(
            path, None, writable=True, create=False, prefix="STORAGE_PATH"
        )
        try:
            assert not created
            assert storage_module._path_matches_descriptor(path, descriptor)
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            assert storage_module._anchored_database_path(
                descriptor, path, "STORAGE_PATH"
            ) == Path(f"/dev/fd/{descriptor}")
        finally:
            os.close(descriptor)
        storage_module._validate_sqlite_sidecars(
            path, None, writable=True, prefix="STORAGE_PATH"
        )
        assert _locks(path) == before
        if journal == "WAL":
            _assert_sqlite_locks_held(path)
        _assert_competing_writer_refused(path)
        connection.rollback()
        monkeypatch.undo()
        assert connection.execute("SELECT group_concat(v) FROM probe").fetchone() == ("1",)
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        other = sqlite3.connect(path, timeout=0)
        try:
            other.execute("INSERT INTO probe VALUES (3)")
            other.commit()
        finally:
            other.close()
        assert connection.execute("SELECT group_concat(v) FROM probe").fetchone() == ("1,3",)
    finally:
        connection.close()


@pytest.mark.parametrize("journal", ["WAL", "DELETE"])
def test_no_identity_alias_refuses_without_releasing_active_locks(
    tmp_path, monkeypatch, journal
):
    assert os.geteuid() != 0, "acceptance must run without root"
    path = _private(tmp_path)
    connection = _transaction_connection(path, journal)
    try:
        before = _locks(path)
        _hide_fd_aliases(monkeypatch, proc_directory=True, hide_dev=True)
        with pytest.raises(OSError) as raised:
            storage_module._open_for_identity(path, os.O_RDWR | os.O_NOFOLLOW)
        assert raised.value.errno == errno.ENOTSUP
        with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:OPEN_FAILED$"):
            storage_module._open_private_database(
                path, None, writable=True, create=False, prefix="STORAGE_PATH"
            )
        with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:UNSAFE_SIDECAR$"):
            storage_module._validate_sqlite_sidecars(
                path, None, writable=True, prefix="STORAGE_PATH"
            )
        assert _locks(path) == before
        if journal == "WAL":
            _assert_sqlite_locks_held(path)
        _assert_competing_writer_refused(path)
    finally:
        connection.rollback()
        connection.close()


def test_no_identity_alias_refuses_new_database_and_keeps_created_file(tmp_path, monkeypatch):
    path = _private(tmp_path)
    _hide_fd_aliases(monkeypatch, proc_directory=False, hide_dev=True)
    with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:OPEN_FAILED$"):
        Store(path)
    assert path.is_file()
    assert path.stat().st_size == 0
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_failed_reopen_refuses_without_leaking_created_descriptor(tmp_path, monkeypatch):
    path = _private(tmp_path)
    real_open = os.open
    created = []

    def refuse_reopen(target, flags, *args, **kwargs):
        if str(target).startswith(("/proc/self/fd/", "/dev/fd/")) and flags & os.O_PATH:
            raise OSError(errno.EACCES, "refused", str(target))
        descriptor = real_open(target, flags, *args, **kwargs)
        if flags & os.O_EXCL:
            created.append(descriptor)
        return descriptor

    monkeypatch.setattr(os, "open", refuse_reopen)
    with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:OPEN_FAILED$"):
        Store(path)
    assert len(created) == 1
    with pytest.raises(OSError) as raised:
        os.fstat(created[0])
    assert raised.value.errno == errno.EBADF
    assert path.is_file()


def test_dev_fd_fallback_preserves_permission_refusal(tmp_path, monkeypatch):
    assert os.geteuid() != 0, "permission acceptance must run without root"
    path = _private(tmp_path)
    path.write_bytes(b"")
    path.chmod(0o400)
    _hide_fd_aliases(monkeypatch, proc_directory=True)
    with pytest.raises(OSError) as raised:
        storage_module._open_for_identity(path, os.O_RDWR | os.O_NOFOLLOW)
    assert raised.value.errno == errno.EACCES
    descriptor = storage_module._open_for_identity(path, os.O_RDONLY | os.O_NOFOLLOW)
    os.close(descriptor)


def test_dev_fd_fallback_can_create_and_reopen_store(tmp_path, monkeypatch):
    path = _private(tmp_path)
    _hide_fd_aliases(monkeypatch, proc_directory=False)
    with Store(path) as store:
        _action(store)
        _assert_sqlite_locks_held(path)
    with Store(path, create=False) as store:
        assert store.summary()["actions"] == 1
        _assert_sqlite_locks_held(path)


def test_wrong_inode_alias_refuses_without_releasing_locks(tmp_path, monkeypatch):
    path = _private(tmp_path)
    connection = _transaction_connection(path, "WAL")
    other = path.parent / "other.db"
    other.write_bytes(b"")
    unrelated = other.stat()
    real_stat = os.stat

    def wrong_inode(target, *args, **kwargs):
        if str(target).startswith(("/proc/self/fd/", "/dev/fd/")):
            return unrelated
        return real_stat(target, *args, **kwargs)

    monkeypatch.setattr(os, "stat", wrong_inode)
    try:
        before = _locks(path)
        with pytest.raises(OSError) as raised:
            storage_module._open_for_identity(path, os.O_RDWR | os.O_NOFOLLOW)
        assert raised.value.errno == errno.ENOTSUP
        assert _locks(path) == before
        _assert_sqlite_locks_held(path)
    finally:
        connection.rollback()
        connection.close()


def test_store_without_o_path_keeps_its_own_locks_through_writes(
    tmp_path, monkeypatch
):
    # Every write runs the capacity check, which sizes -wal and -shm. Opening
    # and closing -shm for that released the Store's own dead-man switch, so a
    # second process could take it and reinitialise the live WAL index.
    _without_o_path(monkeypatch)
    path = _private(tmp_path)
    with Store(path) as store:
        _action(store)
        _assert_sqlite_locks_held(path)
        store._ensure_capacity()
        _action(store)
        _assert_sqlite_locks_held(path)
        result = subprocess.run(
            [sys.executable, "-c", _SECOND_PROCESS, str(path)],
            capture_output=True, text=True, timeout=30, check=True,
        )
        assert result.stdout.split() == ["True", "True", "2"]
        _assert_sqlite_locks_held(path)


@pytest.mark.parametrize("writable", [True, False])
def test_sidecar_validation_without_o_path_keeps_locks_and_normalises_mode(
    tmp_path, monkeypatch, writable
):
    _without_o_path(monkeypatch)
    path = _private(tmp_path)
    connection = _wal_connection(path)
    directory = storage_module._open_private_directory(
        path.parent, create=False, prefix="STORAGE_PATH"
    )
    real_open = os.open
    sidecar_opens = []

    def recording_open(target, *args, **kwargs):
        if str(target).endswith(("-wal", "-shm", "-journal")):
            sidecar_opens.append(target)
        return real_open(target, *args, **kwargs)

    monkeypatch.setattr(os, "open", recording_open)
    try:
        wal = path.with_name(path.name + "-wal")
        wal.chmod(0o644 if writable else 0o600)
        for descriptor in (directory, None):
            assert {"-wal", "-shm"} <= storage_module._validate_sqlite_sidecars(
                path, descriptor, writable=writable, prefix="STORAGE_PATH"
            )
            assert stat.S_IMODE(wal.stat().st_mode) == 0o600
            _assert_sqlite_locks_held(path)
        assert sidecar_opens == []
    finally:
        os.close(directory)
        connection.close()


def test_mode_restore_by_name_refuses_a_swapped_sidecar(tmp_path):
    path = _private(tmp_path)
    sidecar = path.with_name(path.name + "-wal")
    sidecar.write_bytes(b"")
    sidecar.chmod(0o644)
    admitted = os.stat(sidecar, follow_symlinks=False)
    # Keep the admitted inode linked so the replacement cannot reuse its number.
    sidecar.rename(path.parent / "admitted")
    sidecar.write_bytes(b"")
    sidecar.chmod(0o644)
    with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:UNSAFE_SIDECAR$"):
        storage_module._restore_private_mode_by_name(
            admitted, sidecar, "STORAGE_PATH"
        )


@pytest.mark.parametrize("o_path", [True, False], ids=["o_path", "stat_only"])
def test_capacity_sidecar_refusals_match_with_and_without_o_path(
    tmp_path, monkeypatch, o_path
):
    if not o_path:
        _without_o_path(monkeypatch)
    path = _private(tmp_path)
    with Store(path) as store:
        _action(store)
        journal = path.with_name(path.name + "-journal")
        journal.symlink_to(path)
        with pytest.raises(
            storage_module.StorageCapacityError,
            match="^STORAGE_CAPACITY:SIDECAR_UNREADABLE$",
        ):
            store._sidecar_size("-journal")
        journal.unlink()
        journal.mkdir(mode=0o700)
        with pytest.raises(
            storage_module.StorageCapacityError,
            match="^STORAGE_CAPACITY:UNSAFE_SIDECAR$",
        ):
            store._sidecar_size("-journal")
        journal.rmdir()
        assert store._sidecar_size("-journal") == 0
        assert store._sidecar_size("-wal") == path.with_name(
            path.name + "-wal"
        ).stat().st_size
        _assert_sqlite_locks_held(path)


@pytest.mark.parametrize("replacement", ["private", "hard_linked"])
def test_stat_inspection_relooks_up_a_sidecar_replaced_mid_check(
    tmp_path, monkeypatch, replacement
):
    # The stat-only counterpart of the descriptor re-lookup: a name replaced
    # between the stat and the access check must not be admitted on the
    # earlier inode's validation.
    _without_o_path(monkeypatch)
    path = _private(tmp_path)
    connection = _wal_connection(path)
    sidecar = path.with_name(path.name + "-journal")
    sidecar.write_bytes(b"")
    sidecar.chmod(0o600)
    real_access = os.access
    journal_checks = []

    def access_then_replace(target, *args, **kwargs):
        if str(target).endswith("-journal"):
            journal_checks.append(target)
            if len(journal_checks) == 1:
                sidecar.rename(path.parent / "admitted")
                other = path.parent / "replacement"
                other.write_bytes(b"")
                other.chmod(0o600)
                os.link(other, sidecar)
                if replacement == "private":
                    other.unlink()
        return real_access(target, *args, **kwargs)

    monkeypatch.setattr(os, "access", access_then_replace)
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
        assert len(journal_checks) == 2
        _assert_sqlite_locks_held(path)
    finally:
        connection.close()
