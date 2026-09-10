"""Fail-closed boundaries for the dashboard's existing-database reader."""

from __future__ import annotations

from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
from threading import Event, Thread
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import urlopen

import pytest

import megalodon.storage as storage_module
from megalodon.dashboard import DASHBOARD_EVENT_FIELDS, DashboardHandler
from megalodon.models import ActionRecord, DetectionResult, PacketEvent
from megalodon.storage import DashboardStore, StorageSchemaError, Store


STAMP = datetime(2026, 9, 10, tzinfo=timezone.utc)
SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


def _private_directory(tmp_path: Path, name: str = "private") -> Path:
    directory = tmp_path / name
    directory.mkdir(mode=0o700)
    if os.name == "posix":
        directory.chmod(0o700)
    return directory


def _sidecars(path: Path) -> tuple[Path, ...]:
    return tuple(Path(f"{path}{suffix}") for suffix in SIDECAR_SUFFIXES)


def _assert_no_sidecars(*paths: Path) -> None:
    unexpected = [
        sidecar
        for path in paths
        for sidecar in _sidecars(path)
        if os.path.lexists(sidecar)
    ]
    assert unexpected == []


def _seed(
    store: Store,
    *,
    suffix: str = "1",
    rule_id: str = "SYNTHETIC_TEST",
) -> None:
    event = PacketEvent(
        observed_at=STAMP,
        src_ip=f"192.0.2.{suffix}",
        dst_ip="198.51.100.20",
        protocol="TCP",
        src_port=40_000,
        dst_port=443,
        tcp_flags=frozenset({"SYN"}),
        byte_count=60,
    )
    event_id = store.record_event(event)
    store.record_detection(
        event_id,
        DetectionResult(
            detected_at=STAMP,
            rule_id=rule_id,
            severity="HIGH",
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            message="Synthetic dashboard reader acceptance record",
            evidence={"private_detail": "not selected"},
            recommendation="REVIEW",
            suppressed_reason="private suppression detail",
        ),
    )
    store.record_action(
        ActionRecord(
            created_at=STAMP,
            action="synthetic_test",
            target=event.src_ip,
            status="not_attempted",
            reason="Dashboard snapshot acceptance",
        )
    )


def _assert_http_503(reader: DashboardStore, route: str) -> None:
    handler = type(
        "UnavailableDashboardHandler",
        (DashboardHandler,),
        {"store": reader},
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with pytest.raises(HTTPError) as raised:
            urlopen(
                f"http://127.0.0.1:{server.server_port}{route}",
                timeout=2,
            )
        try:
            assert raised.value.code == 503
            assert json.loads(raised.value.read()) == {
                "error": "dashboard data unavailable"
            }
        finally:
            raised.value.close()
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
    assert not worker.is_alive()


def _install_sidecar_sentinel(
    directory: Path,
    database: Path,
    suffix: str,
    link_kind: str,
) -> tuple[Path, Path, bytes, tuple[int, int, int, int, int]]:
    sentinel = directory / f"sentinel{suffix}"
    sentinel_bytes = f"do-not-touch:{suffix}:{link_kind}".encode("ascii")
    sentinel.write_bytes(sentinel_bytes)
    if os.name == "posix":
        sentinel.chmod(0o600)
    sidecar = Path(f"{database}{suffix}")
    try:
        if link_kind == "symlink":
            sidecar.symlink_to(sentinel)
        else:
            os.link(sentinel, sidecar)
    except OSError:
        pytest.skip(f"{link_kind} creation is unavailable in this environment")
    details = sentinel.stat()
    identity = (
        details.st_dev,
        details.st_ino,
        details.st_nlink,
        details.st_size,
        stat.S_IMODE(details.st_mode),
    )
    return sidecar, sentinel, sentinel_bytes, identity


def _assert_sentinel_unchanged(
    sidecar: Path,
    sentinel: Path,
    expected_bytes: bytes,
    expected_identity: tuple[int, int, int, int, int],
    link_kind: str,
) -> None:
    assert sentinel.read_bytes() == expected_bytes
    details = sentinel.stat()
    assert (
        details.st_dev,
        details.st_ino,
        details.st_nlink,
        details.st_size,
        stat.S_IMODE(details.st_mode),
    ) == expected_identity
    if link_kind == "symlink":
        assert sidecar.is_symlink()
    else:
        assert not sidecar.is_symlink()
        assert os.path.samefile(sidecar, sentinel)


def test_missing_database_and_parent_refuse_without_creation_or_sidecars(tmp_path):
    missing_parent = tmp_path / "absent" / "audit.db"
    with pytest.raises(
        StorageSchemaError, match=r"^STORAGE_DASHBOARD:UNSAFE_DIRECTORY$"
    ):
        DashboardStore(missing_parent)
    assert not missing_parent.parent.exists()
    assert not missing_parent.exists()
    _assert_no_sidecars(missing_parent)

    path = _private_directory(tmp_path) / "audit.db"
    with pytest.raises(
        StorageSchemaError, match=r"^STORAGE_DASHBOARD:NO_DATABASE$"
    ):
        DashboardStore(path)
    assert not path.exists()
    _assert_no_sidecars(path)


def test_nonregular_database_refuses_before_sqlite_or_sidecars(tmp_path, monkeypatch):
    path = _private_directory(tmp_path) / "audit.db"
    path.mkdir(mode=0o700)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("SQLite must not open a non-regular dashboard input")

    monkeypatch.setattr(storage_module.sqlite3, "connect", forbidden)
    with pytest.raises(
        StorageSchemaError, match=r"^STORAGE_DASHBOARD:UNSAFE_DATABASE$"
    ):
        DashboardStore(path)
    assert path.is_dir()
    _assert_no_sidecars(path)


def test_symlink_database_refuses_without_opening_target_or_creating_sidecars(
    tmp_path, monkeypatch
):
    directory = _private_directory(tmp_path)
    target = directory / "target.db"
    alias = directory / "alias.db"
    with Store(target):
        pass
    try:
        alias.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable in this environment")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("SQLite must not follow a dashboard database symlink")

    monkeypatch.setattr(storage_module.sqlite3, "connect", forbidden)
    with pytest.raises(
        StorageSchemaError, match=r"^STORAGE_DASHBOARD:UNSAFE_DATABASE$"
    ):
        DashboardStore(alias)
    assert alias.is_symlink()
    _assert_no_sidecars(alias, target)


@pytest.mark.parametrize(
    ("store_type", "failure_code"),
    [
        ("dashboard", "STORAGE_DASHBOARD:UNSAFE_DIRECTORY"),
        ("writer", "STORAGE_PATH:UNSAFE_DIRECTORY"),
    ],
)
def test_dotdot_after_symlink_component_is_refused_before_path_collapse(
    tmp_path, monkeypatch, store_type, failure_code
):
    directory = _private_directory(tmp_path)
    other = _private_directory(tmp_path, "other")
    canonical = directory / "audit.db"
    with Store(canonical):
        pass
    alias = directory / "alias"
    try:
        alias.symlink_to(other, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable in this environment")
    ambiguous = directory / "alias" / ".." / "audit.db"

    def forbidden(*_args, **_kwargs):
        raise AssertionError("SQLite must not open an ambiguous storage path")

    monkeypatch.setattr(storage_module.sqlite3, "connect", forbidden)
    constructor = DashboardStore if store_type == "dashboard" else Store
    with pytest.raises(StorageSchemaError, match=rf"^{failure_code}$"):
        constructor(ambiguous)

    assert canonical.is_file()
    assert not (tmp_path / "audit.db").exists()
    _assert_no_sidecars(ambiguous, canonical, tmp_path / "audit.db")


def test_hardlinked_database_refuses_without_opening_or_creating_sidecars(
    tmp_path, monkeypatch
):
    directory = _private_directory(tmp_path)
    path = directory / "audit.db"
    alias = directory / "alias.db"
    with Store(path):
        pass
    try:
        os.link(path, alias)
    except OSError:
        pytest.skip("hardlink creation is unavailable in this environment")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("SQLite must not open a hardlinked dashboard database")

    monkeypatch.setattr(storage_module.sqlite3, "connect", forbidden)
    with pytest.raises(
        StorageSchemaError, match=r"^STORAGE_DASHBOARD:UNSAFE_DATABASE$"
    ):
        DashboardStore(path)
    assert os.path.samefile(path, alias)
    _assert_no_sidecars(path, alias)


@pytest.mark.parametrize("suffix", SIDECAR_SUFFIXES)
@pytest.mark.parametrize("link_kind", ("symlink", "hardlink"))
def test_dashboard_refuses_linked_sidecar_sentinel_before_sqlite(
    tmp_path, monkeypatch, suffix, link_kind
):
    directory = _private_directory(tmp_path)
    path = directory / "audit.db"
    with Store(path):
        pass
    sidecar, sentinel, expected_bytes, expected_identity = (
        _install_sidecar_sentinel(directory, path, suffix, link_kind)
    )

    def forbidden(*_args, **_kwargs):
        raise AssertionError("SQLite must not touch an unsafe dashboard sidecar")

    monkeypatch.setattr(storage_module.sqlite3, "connect", forbidden)
    with pytest.raises(
        StorageSchemaError, match=r"^STORAGE_DASHBOARD:UNSAFE_SIDECAR$"
    ):
        DashboardStore(path)
    _assert_sentinel_unchanged(
        sidecar,
        sentinel,
        expected_bytes,
        expected_identity,
        link_kind,
    )


@pytest.mark.parametrize("suffix", SIDECAR_SUFFIXES)
@pytest.mark.parametrize("link_kind", ("symlink", "hardlink"))
def test_writer_refuses_linked_sidecar_sentinel_before_sqlite(
    tmp_path, monkeypatch, suffix, link_kind
):
    directory = _private_directory(tmp_path)
    path = directory / "audit.db"
    with Store(path):
        pass
    sidecar, sentinel, expected_bytes, expected_identity = (
        _install_sidecar_sentinel(directory, path, suffix, link_kind)
    )

    def forbidden(*_args, **_kwargs):
        raise AssertionError("SQLite must not touch an unsafe writer sidecar")

    monkeypatch.setattr(storage_module.sqlite3, "connect", forbidden)
    with pytest.raises(
        StorageSchemaError, match=r"^STORAGE_PATH:UNSAFE_SIDECAR$"
    ):
        Store(path)
    _assert_sentinel_unchanged(
        sidecar,
        sentinel,
        expected_bytes,
        expected_identity,
        link_kind,
    )


def test_writer_accepts_sqlite_removal_of_recovered_hot_journal(tmp_path):
    path = _private_directory(tmp_path) / "audit.db"
    with Store(path) as store:
        store.connection.execute(
            "INSERT INTO actions(created_at, action, target, status, reason, details_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                STAMP.isoformat(),
                "test",
                "192.0.2.1",
                "planned",
                "original",
                "{}",
            ),
        )
        store.connection.commit()
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"

    child = r"""
import os
import sqlite3
import sys

path = sys.argv[1]
connection = sqlite3.connect(path)
connection.execute("PRAGMA journal_mode=DELETE")
connection.execute("PRAGMA synchronous=FULL")
connection.execute("PRAGMA cache_size=1")
connection.execute("BEGIN IMMEDIATE")
connection.execute("UPDATE actions SET reason = ?", ("uncommitted" * 1000,))
assert os.path.isfile(path + "-journal")
os._exit(0)
"""
    subprocess.run([sys.executable, "-c", child, str(path)], check=True)
    journal = Path(f"{path}-journal")
    assert journal.is_file()
    assert journal.stat().st_size > 512

    with Store(path) as recovered:
        reason = recovered.connection.execute(
            "SELECT reason FROM actions"
        ).fetchone()[0]
        assert reason == "original"
        assert recovered.connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert not os.path.lexists(journal)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and mode boundary")
def test_public_directory_and_database_refuse_without_sidecars(tmp_path):
    directory = _private_directory(tmp_path)
    path = directory / "audit.db"
    with Store(path):
        pass

    directory.chmod(0o755)
    with pytest.raises(
        StorageSchemaError, match=r"^STORAGE_DASHBOARD:UNSAFE_DIRECTORY$"
    ):
        DashboardStore(path)
    _assert_no_sidecars(path)

    directory.chmod(0o700)
    path.chmod(0o644)
    with pytest.raises(
        StorageSchemaError, match=r"^STORAGE_DASHBOARD:UNSAFE_DATABASE$"
    ):
        DashboardStore(path)
    _assert_no_sidecars(path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership boundary")
@pytest.mark.parametrize(
    ("foreign_path", "failure_code"),
    [
        ("directory", "STORAGE_DASHBOARD:UNSAFE_DIRECTORY"),
        ("database", "STORAGE_DASHBOARD:UNSAFE_DATABASE"),
    ],
)
def test_wrong_owner_refuses_before_sqlite_without_sidecars(
    tmp_path, monkeypatch, foreign_path, failure_code
):
    directory = _private_directory(tmp_path)
    path = directory / "audit.db"
    with Store(path):
        pass
    target = directory if foreign_path == "directory" else path
    original_lstat = Path.lstat

    def lstat_with_foreign_owner(candidate):
        details = original_lstat(candidate)
        if candidate == target:
            return SimpleNamespace(
                st_mode=details.st_mode,
                st_uid=os.geteuid() + 1,
                st_nlink=details.st_nlink,
            )
        return details

    def forbidden(*_args, **_kwargs):
        raise AssertionError("SQLite must not open storage owned by another user")

    monkeypatch.setattr(Path, "lstat", lstat_with_foreign_owner)
    monkeypatch.setattr(storage_module.sqlite3, "connect", forbidden)
    with pytest.raises(StorageSchemaError, match=rf"^{failure_code}$"):
        DashboardStore(path)
    _assert_no_sidecars(path)


def test_incompatible_database_refuses_without_schema_repair_or_sidecars(tmp_path):
    path = _private_directory(tmp_path) / "audit.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE unrelated (value TEXT)")
        connection.execute("INSERT INTO unrelated VALUES ('preserve me')")
        connection.execute("PRAGMA user_version = 2")
    if os.name == "posix":
        path.chmod(0o600)

    before = path.read_bytes()
    with pytest.raises(
        StorageSchemaError, match=r"^STORAGE_DASHBOARD:INCOMPATIBLE$"
    ):
        DashboardStore(path)

    assert path.read_bytes() == before
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert connection.execute("SELECT value FROM unrelated").fetchone()[0] == "preserve me"
    _assert_no_sidecars(path)


def test_wal_mode_incompatible_database_refuses_without_sidecars(tmp_path):
    path = _private_directory(tmp_path) / "audit.db"
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        connection.execute("CREATE TABLE unrelated (value TEXT)")
        connection.execute("INSERT INTO unrelated VALUES ('preserve me')")
        connection.execute("PRAGMA user_version = 2")
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        connection.close()
    if os.name == "posix":
        path.chmod(0o600)
    _assert_no_sidecars(path)
    before = path.read_bytes()

    with pytest.raises(
        StorageSchemaError, match=r"^STORAGE_DASHBOARD:INCOMPATIBLE$"
    ):
        DashboardStore(path)

    assert path.read_bytes() == before
    _assert_no_sidecars(path)


def test_incompatible_state_only_in_lone_wal_refuses_without_new_sidecar(tmp_path):
    directory = _private_directory(tmp_path)
    source = directory / "source.db"
    path = directory / "audit.db"
    with Store(source):
        pass
    source_connection = sqlite3.connect(source)
    try:
        source_connection.execute("PRAGMA wal_autocheckpoint=0")
        source_connection.execute("PRAGMA user_version=999")
        source_connection.commit()
        assert source_connection.execute("PRAGMA user_version").fetchone()[0] == 999
        source_wal = Path(f"{source}-wal")
        assert source_wal.is_file()
        shutil.copyfile(source, path)
        wal = Path(f"{path}-wal")
        shutil.copyfile(source_wal, wal)
    finally:
        source_connection.close()
    if os.name == "posix":
        path.chmod(0o600)
        wal.chmod(0o600)
    assert int.from_bytes(path.read_bytes()[60:64], "big") == 2
    assert not os.path.lexists(f"{path}-shm")
    assert not os.path.lexists(f"{path}-journal")
    database_before = path.read_bytes()
    wal_before = wal.read_bytes()
    wal_details = wal.stat()
    wal_identity = (wal_details.st_dev, wal_details.st_ino, wal_details.st_nlink)

    with pytest.raises(
        StorageSchemaError,
        match=r"^STORAGE_DASHBOARD:UNSAFE_SIDECAR_STATE$",
    ):
        DashboardStore(path)

    assert path.read_bytes() == database_before
    assert wal.read_bytes() == wal_before
    wal_details = wal.stat()
    assert (wal_details.st_dev, wal_details.st_ino, wal_details.st_nlink) == wal_identity
    assert not os.path.lexists(f"{path}-shm")
    assert not os.path.lexists(f"{path}-journal")


def test_database_replacement_during_open_fails_identity_check_without_sidecars(
    tmp_path, monkeypatch
):
    directory = _private_directory(tmp_path)
    path = directory / "audit.db"
    replacement = directory / "replacement.db"
    displaced = directory / "displaced.db"
    with Store(path):
        pass
    with Store(replacement):
        pass
    original_connect = sqlite3.connect
    replaced = False

    def replacing_connect(*args, **kwargs):
        nonlocal replaced
        if kwargs.get("uri") is True and not replaced:
            replaced = True
            os.replace(path, displaced)
            os.replace(replacement, path)
        return original_connect(*args, **kwargs)

    monkeypatch.setattr(storage_module.sqlite3, "connect", replacing_connect)
    with pytest.raises(
        StorageSchemaError, match=r"^STORAGE_DASHBOARD:DATABASE_CHANGED$"
    ):
        DashboardStore(path)

    assert replaced is True
    assert path.is_file()
    assert displaced.is_file()
    assert not replacement.exists()
    _assert_no_sidecars(path, replacement, displaced)


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor binding boundary")
def test_same_uid_aba_connect_hook_never_exposes_replacement_database(
    tmp_path, monkeypatch
):
    directory = _private_directory(tmp_path)
    path = directory / "audit.db"
    other = directory / "other.db"
    parked = directory / "parked.db"
    with Store(path) as writer:
        _seed(writer, suffix="10", rule_id="BOUND_A")
    with Store(other) as writer:
        _seed(writer, suffix="20", rule_id="REPLACEMENT_B")
    original_identity = path.stat().st_ino
    other_identity = other.stat().st_ino
    assert path.stat().st_uid == other.stat().st_uid == os.geteuid()
    original_connect = sqlite3.connect
    hook_calls = 0

    def connect_during_aba(*args, **kwargs):
        nonlocal hook_calls
        hook_calls += 1
        os.replace(path, parked)
        os.replace(other, path)
        try:
            return original_connect(*args, **kwargs)
        finally:
            os.replace(path, other)
            os.replace(parked, path)

    monkeypatch.setattr(storage_module.sqlite3, "connect", connect_during_aba)
    try:
        reader = DashboardStore(path)
    except StorageSchemaError as exc:
        assert str(exc) in {
            "STORAGE_DASHBOARD:DATABASE_CHANGED",
            "STORAGE_DASHBOARD:OPEN_FAILED",
        }
    else:
        with reader:
            rows = reader.recent(10)
            assert [row["rule_id"] for row in rows] == ["BOUND_A"]
            assert rows[0]["src_ip"] == "192.0.2.10"

    assert hook_calls >= 1
    assert not parked.exists()
    assert path.stat().st_ino == original_identity
    assert other.stat().st_ino == other_identity


@pytest.mark.skipif(os.name != "posix", reason="POSIX creation modes")
def test_writer_creates_private_parent_and_database(tmp_path):
    directory = tmp_path / "writer-private"
    path = directory / "audit.db"

    with Store(path):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX no-follow directory creation")
def test_writer_symlink_ancestor_with_missing_descendants_creates_nothing(
    tmp_path,
):
    target = _private_directory(tmp_path, "target")
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable in this environment")
    path = alias / "missing" / "nested" / "audit.db"

    with pytest.raises(
        StorageSchemaError, match=r"^STORAGE_PATH:UNSAFE_DIRECTORY$"
    ):
        Store(path)

    assert alias.is_symlink()
    assert list(target.iterdir()) == []
    assert not (target / "missing").exists()
    assert not path.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX creation modes")
def test_writer_creates_every_nested_directory_privately_under_open_umask(tmp_path):
    first = tmp_path / "one"
    second = first / "two"
    third = second / "three"
    directories = [first, second, third]
    path = directories[-1] / "audit.db"

    previous_umask = os.umask(0o000)
    try:
        with Store(path):
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            assert all(
                stat.S_IMODE(directory.stat().st_mode) == 0o700
                for directory in directories
            )
    finally:
        os.umask(previous_umask)

    assert all(
        stat.S_IMODE(directory.stat().st_mode) == 0o700
        for directory in directories
    )


def test_dashboard_connection_is_query_only_and_uri_read_only(tmp_path):
    path = _private_directory(tmp_path) / "audit.db"
    with Store(path):
        pass

    with DashboardStore(path) as reader:
        assert reader.connection.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError):
            reader.connection.execute("CREATE TABLE forbidden (value TEXT)")

        # Prove URI mode=ro remains a second boundary if query_only is weakened.
        reader.connection.execute("PRAGMA query_only=OFF")
        assert reader.connection.execute("PRAGMA query_only").fetchone()[0] == 0
        with pytest.raises(sqlite3.OperationalError, match=r"(?i)read.?only"):
            reader.connection.execute("DELETE FROM actions")
        reader.connection.rollback()

    with sqlite3.connect(path) as observer:
        assert observer.execute("SELECT COUNT(*) FROM actions").fetchone()[0] == 0


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor binding boundary")
def test_dashboard_refuses_when_descriptor_path_is_unavailable(
    tmp_path, monkeypatch
):
    path = _private_directory(tmp_path) / "audit.db"
    with Store(path):
        pass

    monkeypatch.setattr(
        storage_module,
        "_descriptor_database_path",
        lambda _descriptor, fallback: str(fallback),
    )
    with pytest.raises(
        StorageSchemaError,
        match=r"^STORAGE_DASHBOARD:DESCRIPTOR_PATH_REQUIRED$",
    ):
        DashboardStore(path)
    _assert_no_sidecars(path)


def test_dashboard_close_is_idempotent_and_does_not_close_reused_descriptor(tmp_path):
    directory = _private_directory(tmp_path)
    path = directory / "audit.db"
    sentinel = directory / "sentinel.txt"
    sentinel.write_text("descriptor must remain open", encoding="utf-8")
    if os.name == "posix":
        sentinel.chmod(0o600)
    with Store(path):
        pass

    reader = DashboardStore(path)
    reader.close()
    sentinel_descriptor = os.open(sentinel, os.O_RDONLY)
    try:
        reader.close()
        assert os.fstat(sentinel_descriptor).st_size == len("descriptor must remain open")
        with pytest.raises(
            StorageSchemaError, match=r"^STORAGE_DASHBOARD:CLOSED$"
        ):
            reader.summary()
    finally:
        os.close(sentinel_descriptor)


def test_reader_created_sidecars_are_private_regular_single_link_files(tmp_path):
    directory = _private_directory(tmp_path)
    path = directory / "audit.db"
    with Store(path):
        pass
    _assert_no_sidecars(path)

    with DashboardStore(path):
        present = [
            sidecar for sidecar in _sidecars(path) if os.path.lexists(sidecar)
        ]
        assert {sidecar.name for sidecar in present} == {
            f"{path.name}-wal",
            f"{path.name}-shm",
        }
        for sidecar in present:
            details = sidecar.lstat()
            assert sidecar.parent == directory
            assert not sidecar.is_symlink()
            assert stat.S_ISREG(details.st_mode)
            assert details.st_nlink == 1
            if os.name == "posix":
                assert details.st_uid == os.geteuid()
                assert stat.S_IMODE(details.st_mode) & 0o077 == 0


def test_recent_selects_only_the_five_dashboard_fields(tmp_path):
    path = _private_directory(tmp_path) / "audit.db"
    with Store(path) as writer:
        _seed(writer)

    with DashboardStore(path) as reader:
        reads: list[tuple[str | None, str | None]] = []

        def authorizer(action, table, column, _database, _trigger):
            if action == sqlite3.SQLITE_READ:
                reads.append((table, column))
            return sqlite3.SQLITE_OK

        reader.connection.set_authorizer(authorizer)
        rows = reader.recent(10)
        reader.connection.set_authorizer(None)

    assert len(rows) == 1
    assert tuple(rows[0]) == DASHBOARD_EVENT_FIELDS
    assert rows[0]["rule_id"] == "SYNTHETIC_TEST"
    detection_columns = {
        column for table, column in reads if table == "detections"
    }
    assert detection_columns == {*DASHBOARD_EVENT_FIELDS, "id"}
    assert not {
        "dst_ip", "evidence_json", "recommendation", "suppressed_reason"
    } & detection_columns


@pytest.mark.parametrize(
    ("column", "tampered_value"),
    [
        pytest.param("message", b"blob-not-text", id="blob"),
        pytest.param("severity", "EMERGENCY", id="invalid-severity"),
        pytest.param("src_ip", "not-an-ip", id="invalid-ip"),
        pytest.param(
            "detected_at",
            "2026-09-10T00:00:00",
            id="timestamp-without-offset",
        ),
        pytest.param("rule_id", "RULE\nCONTROL", id="control-text"),
        pytest.param("message", "x" * 513, id="over-limit-message"),
    ],
)
def test_tampered_public_field_returns_invalid_data_and_fixed_503(
    tmp_path, column, tampered_value
):
    path = _private_directory(tmp_path) / "audit.db"
    with Store(path) as writer:
        _seed(writer)

    connection = sqlite3.connect(path)
    try:
        connection.execute(
            f'UPDATE detections SET "{column}" = ?',
            (tampered_value,),
        )
        connection.commit()
    finally:
        connection.close()

    with DashboardStore(path) as reader:
        _assert_http_503(reader, "/api/events?limit=1")
        with pytest.raises(
            StorageSchemaError, match=r"^STORAGE_DASHBOARD:INVALID_DATA$"
        ):
            reader.recent(1)
        assert reader.summary() == {
            "events": 1,
            "detections": 1,
            "actions": 1,
            "high_or_critical": 0 if column == "severity" else 1,
        }


def test_summary_uses_one_snapshot_while_wal_writer_commits(tmp_path):
    path = _private_directory(tmp_path) / "audit.db"
    with Store(path) as writer, DashboardStore(path) as reader:
        write_requested = Event()
        write_finished = Event()
        writer_errors: list[BaseException] = []

        def write_after_first_count() -> None:
            if not write_requested.wait(timeout=5):
                writer_errors.append(AssertionError("summary never requested the writer"))
                return
            try:
                _seed(writer)
            except BaseException as exc:  # Preserve worker failure for the test thread.
                writer_errors.append(exc)
            finally:
                write_finished.set()

        worker = Thread(target=write_after_first_count, daemon=True)
        worker.start()
        triggered = False

        def trace(statement: str) -> None:
            nonlocal triggered
            normalized = " ".join(statement.split()).upper()
            if not triggered and "SELECT COUNT(*) FROM DETECTIONS" in normalized:
                triggered = True
                write_requested.set()
                write_finished.wait(timeout=5)

        reader.connection.set_trace_callback(trace)
        first = reader.summary()
        reader.connection.set_trace_callback(None)
        worker.join(timeout=5)

        assert triggered is True
        assert not worker.is_alive()
        assert writer_errors == []
        assert write_finished.is_set()
        assert first == {
            "events": 0,
            "detections": 0,
            "actions": 0,
            "high_or_critical": 0,
        }
        assert reader.summary() == {
            "events": 1,
            "detections": 1,
            "actions": 1,
            "high_or_critical": 1,
        }


def test_dashboard_reader_observes_committed_live_wal_state(tmp_path):
    path = _private_directory(tmp_path) / "audit.db"
    with Store(path) as writer:
        _seed(writer)
        wal = Path(f"{path}-wal")
        assert wal.is_file()

        with DashboardStore(path) as reader:
            assert reader.connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
            assert reader.connection.execute("PRAGMA query_only").fetchone()[0] == 1
            assert reader.summary() == {
                "events": 1,
                "detections": 1,
                "actions": 1,
                "high_or_critical": 1,
            }
            assert tuple(reader.recent(1)[0]) == DASHBOARD_EVENT_FIELDS

        assert wal.parent == path.parent


@pytest.mark.skipif(os.name != "posix", reason="POSIX live metadata boundaries")
@pytest.mark.parametrize(
    ("mutation", "failure_code"),
    [
        ("public_parent", "STORAGE_DASHBOARD:UNSAFE_DIRECTORY"),
        ("public_database", "STORAGE_DASHBOARD:UNSAFE_DATABASE"),
        ("database_hardlink", "STORAGE_DASHBOARD:UNSAFE_DATABASE"),
        ("sidecar_replacement", "STORAGE_DASHBOARD:SIDECAR_CHANGED"),
        ("rollback_journal", "STORAGE_DASHBOARD:UNSAFE_SIDECAR_STATE"),
    ],
)
def test_post_start_metadata_change_refuses_and_returns_fixed_503(
    tmp_path, mutation, failure_code
):
    directory = _private_directory(tmp_path)
    path = directory / "audit.db"
    with Store(path) as writer:
        _seed(writer)

    with DashboardStore(path) as reader:
        cleanup = lambda: None
        if mutation == "public_parent":
            directory.chmod(0o755)
            cleanup = lambda: directory.chmod(0o700)
        elif mutation == "public_database":
            path.chmod(0o644)
            cleanup = lambda: path.chmod(0o600)
        elif mutation == "database_hardlink":
            linked = directory / "linked-audit.db"
            try:
                os.link(path, linked)
            except OSError:
                pytest.skip("hardlink creation is unavailable in this environment")
            cleanup = linked.unlink
        elif mutation == "sidecar_replacement":
            sidecar = Path(f"{path}-wal")
            assert sidecar.is_file()
            saved_sidecar = directory / "saved-wal"
            replacement = directory / "replacement-wal"
            replacement.write_bytes(b"private replacement sidecar sentinel")
            replacement.chmod(0o600)
            os.replace(sidecar, saved_sidecar)
            os.replace(replacement, sidecar)

            def restore_sidecar() -> None:
                os.replace(sidecar, replacement)
                os.replace(saved_sidecar, sidecar)
                replacement.unlink()

            cleanup = restore_sidecar
        else:
            journal = Path(f"{path}-journal")
            journal.write_bytes(b"unexpected rollback journal")
            journal.chmod(0o600)
            cleanup = journal.unlink

        try:
            _assert_http_503(reader, "/api/summary")
            with pytest.raises(StorageSchemaError, match=rf"^{failure_code}$"):
                reader.summary()
        finally:
            cleanup()

        assert reader.summary() == {
            "events": 1,
            "detections": 1,
            "actions": 1,
            "high_or_critical": 1,
        }


def test_post_start_database_replacement_returns_fixed_503(tmp_path):
    directory = _private_directory(tmp_path)
    path = directory / "audit.db"
    replacement = directory / "replacement.db"
    displaced = directory / "displaced.db"
    with Store(path) as writer:
        _seed(writer)
    with Store(replacement):
        pass

    with DashboardStore(path) as reader:
        sidecars_before_replacement = {
            sidecar for sidecar in _sidecars(path) if os.path.lexists(sidecar)
        }
        try:
            os.replace(path, displaced)
            os.replace(replacement, path)
        except OSError:
            pytest.skip("replacing an open database is unavailable on this platform")

        handler = type(
            "ReplacedDatabaseDashboardHandler",
            (DashboardHandler,),
            {"store": reader},
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with pytest.raises(HTTPError) as raised:
                urlopen(
                    f"http://127.0.0.1:{server.server_port}/api/summary",
                    timeout=2,
                )
            assert raised.value.code == 503
            assert json.loads(raised.value.read()) == {
                "error": "dashboard data unavailable"
            }
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

        with pytest.raises(
            StorageSchemaError, match=r"^STORAGE_DASHBOARD:DATABASE_CHANGED$"
        ):
            reader.summary()
        assert {
            sidecar for sidecar in _sidecars(path) if os.path.lexists(sidecar)
        } == sidecars_before_replacement
        _assert_no_sidecars(replacement, displaced)
