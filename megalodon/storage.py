"""Small auditable SQLite store; no packet payloads are written."""

from __future__ import annotations

from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import sqlite3
import stat
from threading import RLock
from typing import Any

from .models import ActionRecord, DetectionResult, PacketEvent
from .validation import (
    parse_nonnegative_int,
    parse_timestamp,
    SQLITE_INTEGER_MAX,
    validate_metadata,
    validate_packet_metadata,
)


SCHEMA_VERSION = 2
MIGRATION_BACKUP_SUFFIX = ".pre-v2.bak"
MINIMUM_READ_ONLY_WAL_SQLITE = (3, 22, 0)

SCHEMA_V1_STATEMENTS = (
    """CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    protocol TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    tcp_flags TEXT NOT NULL,
    dns_query_length INTEGER,
    byte_count INTEGER NOT NULL,
    interface TEXT,
    metadata_json TEXT NOT NULL
)""",
    "CREATE INDEX idx_events_observed_at ON events(observed_at)",
    "CREATE INDEX idx_events_src_ip ON events(src_ip)",
    """CREATE TABLE detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES events(id),
    detected_at TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    message TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    suppressed_reason TEXT
)""",
    "CREATE INDEX idx_detections_detected_at ON detections(detected_at)",
    """CREATE TABLE actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires_at TEXT,
    details_json TEXT NOT NULL
)""",
    "CREATE INDEX idx_actions_created_at ON actions(created_at)",
)

SCHEMA_V2_STATEMENTS = (
    """CREATE TABLE ingestion_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    processed_count INTEGER NOT NULL,
    detection_count INTEGER NOT NULL,
    failure_code TEXT
)""",
    "CREATE INDEX idx_ingestion_runs_started_at ON ingestion_runs(started_at)",
    """CREATE TABLE ingestion_run_events (
    run_id INTEGER NOT NULL REFERENCES ingestion_runs(id),
    event_id INTEGER NOT NULL UNIQUE REFERENCES events(id) ON DELETE CASCADE,
    PRIMARY KEY (run_id, event_id)
)""",
)

_TABLE_COLUMNS_V1 = {
    "events": (
        ("id", "INTEGER", 0, 1),
        ("observed_at", "TEXT", 1, 0),
        ("src_ip", "TEXT", 1, 0),
        ("dst_ip", "TEXT", 1, 0),
        ("protocol", "TEXT", 1, 0),
        ("src_port", "INTEGER", 0, 0),
        ("dst_port", "INTEGER", 0, 0),
        ("tcp_flags", "TEXT", 1, 0),
        ("dns_query_length", "INTEGER", 0, 0),
        ("byte_count", "INTEGER", 1, 0),
        ("interface", "TEXT", 0, 0),
        ("metadata_json", "TEXT", 1, 0),
    ),
    "detections": (
        ("id", "INTEGER", 0, 1),
        ("event_id", "INTEGER", 1, 0),
        ("detected_at", "TEXT", 1, 0),
        ("rule_id", "TEXT", 1, 0),
        ("severity", "TEXT", 1, 0),
        ("src_ip", "TEXT", 1, 0),
        ("dst_ip", "TEXT", 1, 0),
        ("message", "TEXT", 1, 0),
        ("evidence_json", "TEXT", 1, 0),
        ("recommendation", "TEXT", 1, 0),
        ("suppressed_reason", "TEXT", 0, 0),
    ),
    "actions": (
        ("id", "INTEGER", 0, 1),
        ("created_at", "TEXT", 1, 0),
        ("action", "TEXT", 1, 0),
        ("target", "TEXT", 1, 0),
        ("status", "TEXT", 1, 0),
        ("reason", "TEXT", 1, 0),
        ("expires_at", "TEXT", 0, 0),
        ("details_json", "TEXT", 1, 0),
    ),
}

_TABLE_COLUMNS_V2 = {
    **_TABLE_COLUMNS_V1,
    "ingestion_runs": (
        ("id", "INTEGER", 0, 1),
        ("started_at", "TEXT", 1, 0),
        ("finished_at", "TEXT", 0, 0),
        ("source", "TEXT", 1, 0),
        ("status", "TEXT", 1, 0),
        ("processed_count", "INTEGER", 1, 0),
        ("detection_count", "INTEGER", 1, 0),
        ("failure_code", "TEXT", 0, 0),
    ),
    "ingestion_run_events": (
        ("run_id", "INTEGER", 1, 1),
        ("event_id", "INTEGER", 1, 2),
    ),
}

_INDEX_COLUMNS_V1 = {
    "idx_events_observed_at": ("events", ("observed_at",)),
    "idx_events_src_ip": ("events", ("src_ip",)),
    "idx_detections_detected_at": ("detections", ("detected_at",)),
    "idx_actions_created_at": ("actions", ("created_at",)),
}

_INDEX_COLUMNS_V2 = {
    **_INDEX_COLUMNS_V1,
    "idx_ingestion_runs_started_at": ("ingestion_runs", ("started_at",)),
}

_UNIQUE_INDEXES_V1 = {table: set() for table in _TABLE_COLUMNS_V1}

_UNIQUE_INDEXES_V2 = {
    **_UNIQUE_INDEXES_V1,
    "ingestion_runs": set(),
    "ingestion_run_events": {
        ("pk", ("run_id", "event_id")),
        ("u", ("event_id",)),
    },
}

_FOREIGN_KEYS_V1 = {
    "events": set(),
    "detections": {("events", "event_id", "id", "NO ACTION")},
    "actions": set(),
}

_FOREIGN_KEYS_V2 = {
    **_FOREIGN_KEYS_V1,
    "ingestion_runs": set(),
    "ingestion_run_events": {
        ("ingestion_runs", "run_id", "id", "NO ACTION"),
        ("events", "event_id", "id", "CASCADE"),
    },
}

INGESTION_SOURCES = frozenset({"sample", "jsonl", "scapy"})
INGESTION_FAILURE_CODES = frozenset(
    {"CAPTURE_ERROR", "INTERRUPTED", "IO_ERROR", "STORAGE_ERROR", "VALIDATION_ERROR"}
)

PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_DATABASE_MODE = 0o600
_SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


class StorageSchemaError(ValueError):
    """The selected database cannot safely satisfy this storage schema."""


class IngestionRunError(ValueError):
    """An ingestion run transition or association is invalid."""


def _validate_schema(
    connection,
    tables,
    indexes,
    foreign_keys,
    unique_indexes,
    schema_statements,
) -> None:
    expected_objects = {
        *(("table", table, table) for table in tables),
        *(("index", index, table) for index, (table, _) in indexes.items()),
    }
    actual_objects = {
        (str(row[0]), str(row[1]), str(row[2]))
        for row in connection.execute(
            "SELECT type, name, tbl_name FROM sqlite_schema"
        )
        if not str(row[1]).startswith("sqlite_")
    }
    if actual_objects != expected_objects:
        raise StorageSchemaError("STORAGE_SCHEMA:INCOMPATIBLE")

    expected_sql = {
        statement.split()[2]: " ".join(statement.split())
        for statement in schema_statements
    }
    actual_sql = {
        str(row[0]): " ".join(str(row[1]).split())
        for row in connection.execute(
            "SELECT name, sql FROM sqlite_schema WHERE sql IS NOT NULL"
        )
        if not str(row[0]).startswith("sqlite_")
    }
    if actual_sql != expected_sql:
        raise StorageSchemaError("STORAGE_SCHEMA:INCOMPATIBLE")

    for table, expected in tables.items():
        actual = tuple(
            (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5]))
            for row in connection.execute(f'PRAGMA table_info("{table}")')
        )
        if actual != expected:
            raise StorageSchemaError("STORAGE_SCHEMA:INCOMPATIBLE")

    for table, expected in foreign_keys.items():
        actual = {
            (str(row[2]), str(row[3]), str(row[4]), str(row[6]))
            for row in connection.execute(f'PRAGMA foreign_key_list("{table}")')
        }
        if actual != expected:
            raise StorageSchemaError("STORAGE_SCHEMA:INCOMPATIBLE")

    for index, (table, expected_columns) in indexes.items():
        actual_indexes = {
            str(row[1]): (int(row[2]), str(row[3]))
            for row in connection.execute(f'PRAGMA index_list("{table}")')
        }
        if actual_indexes.get(index) != (0, "c"):
            raise StorageSchemaError("STORAGE_SCHEMA:INCOMPATIBLE")
        columns = tuple(
            str(row[2])
            for row in connection.execute(f'PRAGMA index_info("{index}")')
        )
        if columns != expected_columns:
            raise StorageSchemaError("STORAGE_SCHEMA:INCOMPATIBLE")

    for table, expected in unique_indexes.items():
        actual = set()
        for row in connection.execute(f'PRAGMA index_list("{table}")'):
            if int(row[2]) != 1:
                continue
            columns = tuple(
                str(column[2])
                for column in connection.execute(
                    f'PRAGMA index_info("{str(row[1])}")'
                )
            )
            actual.add((str(row[3]), columns))
        if actual != expected:
            raise StorageSchemaError("STORAGE_SCHEMA:INCOMPATIBLE")


def _schema_objects(connection) -> set[tuple[str, str, str]]:
    return {
        (str(row[0]), str(row[1]), str(row[2]))
        for row in connection.execute(
            "SELECT type, name, tbl_name FROM sqlite_schema"
        )
        if not str(row[1]).startswith("sqlite_")
    }


def _descriptor_database_path(descriptor: int, fallback: Path) -> str:
    if os.name == "posix":
        for directory in ("/proc/self/fd", "/dev/fd"):
            candidate = Path(directory) / str(descriptor)
            if candidate.exists():
                return str(candidate)
    return str(fallback)


def _anchored_database_path(
    descriptor: int, fallback: Path, prefix: str
) -> Path:
    """Return an SQLite path bound to an already-open file where supported."""

    candidate = Path(_descriptor_database_path(descriptor, fallback))
    if os.name == "posix" and candidate == fallback:
        _raise_path_error(prefix, "DESCRIPTOR_PATH_UNAVAILABLE")
    return candidate


def _path_matches_descriptor(path: Path, descriptor: int) -> bool:
    try:
        return os.path.samestat(
            path.stat(follow_symlinks=False), os.fstat(descriptor)
        )
    except OSError:
        return False


def _directory_generation(descriptor: int | None) -> tuple[int, ...] | None:
    if descriptor is None:
        return None
    info = os.fstat(descriptor)
    return (
        info.st_dev,
        info.st_ino,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _validate_connection_path(
    connection: sqlite3.Connection, expected: Path, prefix: str
) -> None:
    """Require SQLite to derive journals beside the already-verified path."""

    try:
        rows = connection.execute("PRAGMA database_list").fetchall()
    except sqlite3.Error as exc:
        _raise_path_error(prefix, "DATABASE_CHANGED", exc)
    if len(rows) != 1:
        _raise_path_error(prefix, "DATABASE_CHANGED")
    sequence, name, filename = rows[0][:3]
    if int(sequence) != 0 or str(name) != "main" or not filename:
        _raise_path_error(prefix, "DATABASE_CHANGED")
    actual = _absolute_database_path(str(filename))
    if os.path.normcase(os.fspath(actual)) != os.path.normcase(os.fspath(expected)):
        _raise_path_error(prefix, "DATABASE_CHANGED")


def _open_regular_file(path: Path, flags: int, mode: int | None = None) -> int:
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = (
        os.open(path, flags, mode) if mode is not None else os.open(path, flags)
    )
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise StorageSchemaError("STORAGE_MIGRATION:SYMLINK_REFUSED")
    return descriptor


def _absolute_database_path(path: str | Path) -> Path:
    """Return an absolute lexical path without following a filesystem link."""

    return Path(os.path.abspath(os.fspath(path)))


def _raise_path_error(
    prefix: str, code: str, cause: BaseException | None = None
) -> None:
    error = StorageSchemaError(f"{prefix}:{code}")
    if cause is None:
        raise error
    raise error from cause


def _validate_private_directory_stat(info: os.stat_result, prefix: str) -> None:
    if not stat.S_ISDIR(info.st_mode):
        _raise_path_error(prefix, "UNSAFE_DIRECTORY")
    if os.name == "posix":
        mode = stat.S_IMODE(info.st_mode)
        if (
            info.st_uid != os.geteuid()
            or mode & 0o077
            or mode & stat.S_IRWXU != stat.S_IRWXU
        ):
            _raise_path_error(prefix, "UNSAFE_DIRECTORY")


def _validate_ancestor_directory_stat(
    info: os.stat_result, prefix: str
) -> None:
    """Reject ancestors whose entries an untrusted local user can rename."""

    if not stat.S_ISDIR(info.st_mode):
        _raise_path_error(prefix, "UNSAFE_ANCESTOR")
    if os.name != "posix":
        return
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid not in (0, os.geteuid()):
        _raise_path_error(prefix, "UNSAFE_ANCESTOR")
    if mode & (stat.S_IWGRP | stat.S_IWOTH) and not mode & stat.S_ISVTX:
        _raise_path_error(prefix, "UNSAFE_ANCESTOR")


def _open_private_directory(
    path: Path, *, create: bool, prefix: str
) -> int | None:
    """Open an owner-private directory without following POSIX path components."""

    if os.name != "posix":
        try:
            if create:
                path.mkdir(mode=PRIVATE_DIRECTORY_MODE, parents=True, exist_ok=True)
            info = path.lstat()
        except FileNotFoundError as exc:
            _raise_path_error(prefix, "NO_DIRECTORY", exc)
        except OSError as exc:
            _raise_path_error(prefix, "UNSAFE_DIRECTORY", exc)
        _validate_private_directory_stat(info, prefix)
        return None

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open("/", flags)
        components = path.parts[1:]
        if components:
            _validate_ancestor_directory_stat(os.fstat(descriptor), prefix)
        for index, component in enumerate(components):
            try:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    _raise_path_error(prefix, "NO_DIRECTORY")
                os.mkdir(component, PRIVATE_DIRECTORY_MODE, dir_fd=descriptor)
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            if index == len(components) - 1:
                _validate_private_directory_stat(os.fstat(descriptor), prefix)
            else:
                _validate_ancestor_directory_stat(os.fstat(descriptor), prefix)
        if not components:
            _validate_private_directory_stat(os.fstat(descriptor), prefix)
        return descriptor
    except StorageSchemaError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        _raise_path_error(prefix, "UNSAFE_DIRECTORY", exc)


def _validate_private_database_stat(
    info: os.stat_result, *, writable: bool, prefix: str
) -> None:
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        _raise_path_error(prefix, "UNSAFE_DATABASE")
    if os.name == "posix":
        if info.st_uid != os.geteuid():
            _raise_path_error(prefix, "UNSAFE_DATABASE")
        if not writable and stat.S_IMODE(info.st_mode) != PRIVATE_DATABASE_MODE:
            _raise_path_error(prefix, "UNSAFE_DATABASE")


def _open_private_database(
    path: Path,
    directory_descriptor: int | None,
    *,
    writable: bool,
    create: bool,
    prefix: str,
) -> tuple[int, bool]:
    flags = (os.O_RDWR if writable else os.O_RDONLY) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    target: str | Path = path.name if directory_descriptor is not None else path
    kwargs = {"dir_fd": directory_descriptor} if directory_descriptor is not None else {}
    descriptor: int | None = None
    created = False
    try:
        if os.name != "posix" and path.is_symlink():
            _raise_path_error(prefix, "SYMLINK_REFUSED")
        try:
            descriptor = os.open(target, flags, **kwargs)
        except FileNotFoundError:
            if not create:
                _raise_path_error(prefix, "NO_DATABASE")
            descriptor = os.open(
                target,
                flags | os.O_CREAT | os.O_EXCL,
                PRIVATE_DATABASE_MODE,
                **kwargs,
            )
            created = True
        info = os.fstat(descriptor)
        _validate_private_database_stat(info, writable=writable, prefix=prefix)
        if writable and os.name == "posix":
            os.fchmod(descriptor, PRIVATE_DATABASE_MODE)
            _validate_private_database_stat(
                os.fstat(descriptor), writable=False, prefix=prefix
            )
        return descriptor, created
    except StorageSchemaError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        code = (
            "SYMLINK_REFUSED"
            if getattr(exc, "errno", None) == errno.ELOOP
            else "OPEN_FAILED"
        )
        _raise_path_error(prefix, code, exc)


def _validate_sqlite_sidecars(
    path: Path,
    directory_descriptor: int | None,
    *,
    writable: bool,
    prefix: str,
) -> frozenset[str]:
    """Reject unsafe pre-existing SQLite coordination files before connect."""

    present: set[str] = set()
    for suffix in _SQLITE_SIDECAR_SUFFIXES:
        sidecar = path.with_name(path.name + suffix)
        flags = (os.O_RDWR if writable else os.O_RDONLY) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        target: str | Path = (
            sidecar.name if directory_descriptor is not None else sidecar
        )
        kwargs = (
            {"dir_fd": directory_descriptor}
            if directory_descriptor is not None
            else {}
        )
        descriptor: int | None = None
        try:
            if os.name != "posix" and sidecar.is_symlink():
                _raise_path_error(prefix, "SYMLINK_REFUSED")
            descriptor = os.open(target, flags, **kwargs)
        except FileNotFoundError:
            continue
        except OSError as exc:
            code = (
                "SYMLINK_REFUSED"
                if getattr(exc, "errno", None) == errno.ELOOP
                else "UNSAFE_SIDECAR"
            )
            _raise_path_error(prefix, code, exc)
        try:
            present.add(suffix)
            _validate_private_database_stat(
                os.fstat(descriptor), writable=writable, prefix=prefix
            )
            if writable and os.name == "posix":
                os.fchmod(descriptor, PRIVATE_DATABASE_MODE)
        finally:
            os.close(descriptor)
    return frozenset(present)


def _validate_migration_directory(path: Path) -> None:
    parent = path.parent
    try:
        parent_stat = parent.lstat()
    except OSError as exc:
        raise StorageSchemaError("STORAGE_MIGRATION:UNSAFE_DIRECTORY") from exc
    _validate_private_directory_stat(parent_stat, "STORAGE_MIGRATION")


def migrate_database(path: str | Path) -> dict[str, object]:
    """Explicitly migrate an exact v1 database after a verified local backup."""

    source_path = _absolute_database_path(path)
    if source_path.is_symlink():
        raise StorageSchemaError("STORAGE_MIGRATION:SYMLINK_REFUSED")
    if not source_path.is_file():
        raise StorageSchemaError("STORAGE_MIGRATION:NO_DATABASE")
    _validate_migration_directory(source_path)
    try:
        _validate_private_database_stat(
            source_path.stat(follow_symlinks=False),
            writable=False,
            prefix="STORAGE_MIGRATION",
        )
        _validate_sqlite_sidecars(
            source_path,
            None,
            writable=False,
            prefix="STORAGE_MIGRATION",
        )
    except StorageSchemaError:
        raise
    except OSError as exc:
        raise StorageSchemaError("STORAGE_MIGRATION:UNSAFE_DATABASE") from exc

    backup_path = source_path.with_name(source_path.name + MIGRATION_BACKUP_SUFFIX)
    source_descriptor: int | None = None
    backup_descriptor: int | None = None
    source: sqlite3.Connection | None = None
    backup: sqlite3.Connection | None = None
    backup_attempted = False
    backup_created = False
    migration_started = False

    def discard_unverified_backup() -> None:
        nonlocal backup, backup_descriptor
        if backup is not None:
            try:
                backup.close()
            except sqlite3.Error:
                pass
            backup = None
        matches_created_file = (
            backup_descriptor is not None
            and _path_matches_descriptor(backup_path, backup_descriptor)
        )
        if backup_descriptor is not None:
            try:
                os.close(backup_descriptor)
            except OSError:
                matches_created_file = False
            backup_descriptor = None
        if matches_created_file:
            try:
                backup_path.unlink(missing_ok=True)
            except OSError:
                pass

    try:
        try:
            source_descriptor = _open_regular_file(source_path, os.O_RDWR)
            source = sqlite3.connect(
                _descriptor_database_path(source_descriptor, source_path), timeout=10
            )
        except (OSError, sqlite3.Error) as exc:
            raise StorageSchemaError(
                "STORAGE_MIGRATION:SOURCE_OPEN_FAILED"
            ) from exc
        if not _path_matches_descriptor(source_path, source_descriptor):
            raise StorageSchemaError("STORAGE_MIGRATION:SOURCE_CHANGED")
        source.execute("PRAGMA foreign_keys=ON")
        version = int(source.execute("PRAGMA user_version").fetchone()[0])
        if version == SCHEMA_VERSION:
            _validate_schema(
                source,
                _TABLE_COLUMNS_V2,
                _INDEX_COLUMNS_V2,
                _FOREIGN_KEYS_V2,
                _UNIQUE_INDEXES_V2,
                (*SCHEMA_V1_STATEMENTS, *SCHEMA_V2_STATEMENTS),
            )
            return {
                "status": "already_current",
                "from_version": SCHEMA_VERSION,
                "to_version": SCHEMA_VERSION,
                "backup": None,
            }
        if version > SCHEMA_VERSION:
            raise StorageSchemaError("STORAGE_SCHEMA:FUTURE_VERSION")
        if version not in (0, 1):
            raise StorageSchemaError("STORAGE_SCHEMA:UNSUPPORTED_VERSION")
        _validate_schema(
            source,
            _TABLE_COLUMNS_V1,
            _INDEX_COLUMNS_V1,
            _FOREIGN_KEYS_V1,
            _UNIQUE_INDEXES_V1,
            SCHEMA_V1_STATEMENTS,
        )
        if os.path.lexists(backup_path):
            raise StorageSchemaError("STORAGE_MIGRATION:BACKUP_EXISTS")

        data_version = int(source.execute("PRAGMA data_version").fetchone()[0])
        backup_attempted = True
        backup_descriptor = _open_regular_file(
            backup_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600
        )
        backup_created = True
        backup = sqlite3.connect(
            _descriptor_database_path(backup_descriptor, backup_path)
        )
        source.backup(backup)
        backup.commit()
        if backup.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise StorageSchemaError("STORAGE_MIGRATION:BACKUP_INVALID")
        if int(backup.execute("PRAGMA user_version").fetchone()[0]) != version:
            raise StorageSchemaError("STORAGE_MIGRATION:BACKUP_INVALID")
        _validate_schema(
            backup,
            _TABLE_COLUMNS_V1,
            _INDEX_COLUMNS_V1,
            _FOREIGN_KEYS_V1,
            _UNIQUE_INDEXES_V1,
            SCHEMA_V1_STATEMENTS,
        )
        if not _path_matches_descriptor(backup_path, backup_descriptor):
            raise StorageSchemaError("STORAGE_MIGRATION:BACKUP_CHANGED")
        backup.close()
        backup = None
        os.fsync(backup_descriptor)
        if os.name == "posix":
            descriptor = os.open(
                backup_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

        source.execute("BEGIN EXCLUSIVE")
        if not _path_matches_descriptor(source_path, source_descriptor):
            source.rollback()
            raise StorageSchemaError("STORAGE_MIGRATION:SOURCE_CHANGED")
        if int(source.execute("PRAGMA data_version").fetchone()[0]) != data_version:
            source.rollback()
            raise StorageSchemaError("STORAGE_MIGRATION:SOURCE_CHANGED")
        if int(source.execute("PRAGMA user_version").fetchone()[0]) != version:
            source.rollback()
            raise StorageSchemaError("STORAGE_MIGRATION:SOURCE_CHANGED")
        try:
            _validate_schema(
                source,
                _TABLE_COLUMNS_V1,
                _INDEX_COLUMNS_V1,
                _FOREIGN_KEYS_V1,
                _UNIQUE_INDEXES_V1,
                SCHEMA_V1_STATEMENTS,
            )
        except StorageSchemaError as exc:
            source.rollback()
            raise StorageSchemaError("STORAGE_MIGRATION:SOURCE_CHANGED") from exc

        migration_started = True
        for statement in SCHEMA_V2_STATEMENTS:
            source.execute(statement)
        _validate_schema(
            source,
            _TABLE_COLUMNS_V2,
            _INDEX_COLUMNS_V2,
            _FOREIGN_KEYS_V2,
            _UNIQUE_INDEXES_V2,
            (*SCHEMA_V1_STATEMENTS, *SCHEMA_V2_STATEMENTS),
        )
        source.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        source.commit()
        return {
            "status": "migrated",
            "from_version": version,
            "to_version": SCHEMA_VERSION,
            "backup": "created",
        }
    except StorageSchemaError:
        if source is not None and source.in_transaction:
            source.rollback()
        if backup_created and not migration_started:
            discard_unverified_backup()
        raise
    except (OSError, sqlite3.Error) as exc:
        if source is not None and source.in_transaction:
            source.rollback()
        if backup_created and not migration_started:
            discard_unverified_backup()
        code = (
            "STORAGE_MIGRATION:MIGRATION_FAILED"
            if migration_started
            else (
                "STORAGE_MIGRATION:BACKUP_FAILED"
                if backup_attempted
                else "STORAGE_MIGRATION:SOURCE_FAILED"
            )
        )
        raise StorageSchemaError(code) from exc
    finally:
        if backup is not None:
            backup.close()
        if source is not None:
            source.close()
        if backup_descriptor is not None:
            os.close(backup_descriptor)
        if source_descriptor is not None:
            os.close(source_descriptor)


class Store:
    def __init__(self, path: str | Path):
        self.path = _absolute_database_path(path)
        self._lock = RLock()
        self._closed = False
        self._directory_descriptor: int | None = None
        self._database_descriptor: int | None = None
        database_created = False
        connection: sqlite3.Connection | None = None
        try:
            self._directory_descriptor = _open_private_directory(
                self.path.parent, create=True, prefix="STORAGE_PATH"
            )
            self._database_descriptor, database_created = _open_private_database(
                self.path,
                self._directory_descriptor,
                writable=True,
                create=True,
                prefix="STORAGE_PATH",
            )
            sqlite_path = _anchored_database_path(
                self._database_descriptor, self.path, "STORAGE_PATH"
            )
            _validate_sqlite_sidecars(
                self.path,
                self._directory_descriptor,
                writable=True,
                prefix="STORAGE_PATH",
            )
            opening_generation = _directory_generation(
                self._directory_descriptor
            )
            connection = sqlite3.connect(
                f"{sqlite_path.as_uri()}?mode=rw&cache=private",
                uri=True,
                timeout=10,
                check_same_thread=False,
            )
            _validate_connection_path(connection, self.path, "STORAGE_PATH")
            self._assert_path_identity()
            if _directory_generation(self._directory_descriptor) != opening_generation:
                _raise_path_error("STORAGE_PATH", "DIRECTORY_CHANGED")
            connection.row_factory = sqlite3.Row
            self.connection = connection
            with self._lock:
                self.connection.execute("PRAGMA foreign_keys=ON")
                self._initialize_schema()
                self.connection.execute("PRAGMA journal_mode=WAL")
            self._assert_path_identity()
            _validate_sqlite_sidecars(
                self.path,
                self._directory_descriptor,
                writable=True,
                prefix="STORAGE_PATH",
            )
        except Exception:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass
            if database_created and connection is None:
                self._discard_created_database()
            self._close_descriptors()
            raise

    def _assert_path_identity(self) -> None:
        if self._database_descriptor is None or not _path_matches_descriptor(
            self.path, self._database_descriptor
        ):
            _raise_path_error("STORAGE_PATH", "DATABASE_CHANGED")
        if self._directory_descriptor is not None and not _path_matches_descriptor(
            self.path.parent, self._directory_descriptor
        ):
            _raise_path_error("STORAGE_PATH", "DIRECTORY_CHANGED")
        _validate_private_database_stat(
            os.fstat(self._database_descriptor),
            writable=False,
            prefix="STORAGE_PATH",
        )
        if self._directory_descriptor is not None:
            _validate_private_directory_stat(
                os.fstat(self._directory_descriptor), "STORAGE_PATH"
            )

    def _close_descriptors(self) -> None:
        for attribute in ("_database_descriptor", "_directory_descriptor"):
            descriptor = getattr(self, attribute)
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, attribute, None)

    def _discard_created_database(self) -> None:
        if self._database_descriptor is None or not _path_matches_descriptor(
            self.path, self._database_descriptor
        ):
            return
        try:
            if self._directory_descriptor is None:
                self.path.unlink()
            else:
                os.unlink(self.path.name, dir_fd=self._directory_descriptor)
        except OSError:
            pass

    def _initialize_schema(self) -> None:
        try:
            version = int(self.connection.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise StorageSchemaError("STORAGE_SCHEMA:FUTURE_VERSION")
            if version not in (0, 1, SCHEMA_VERSION):
                raise StorageSchemaError("STORAGE_SCHEMA:UNSUPPORTED_VERSION")

            present = _schema_objects(self.connection)
            if version == 0 and not present:
                self._create_schema()
                return
            if version in (0, 1):
                self.connection.execute("BEGIN IMMEDIATE")
                try:
                    _validate_schema(
                        self.connection,
                        _TABLE_COLUMNS_V1,
                        _INDEX_COLUMNS_V1,
                        _FOREIGN_KEYS_V1,
                        _UNIQUE_INDEXES_V1,
                        SCHEMA_V1_STATEMENTS,
                    )
                finally:
                    self.connection.rollback()
                raise StorageSchemaError("STORAGE_SCHEMA:MIGRATION_REQUIRED")
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                _validate_schema(
                    self.connection,
                    _TABLE_COLUMNS_V2,
                    _INDEX_COLUMNS_V2,
                    _FOREIGN_KEYS_V2,
                    _UNIQUE_INDEXES_V2,
                    (*SCHEMA_V1_STATEMENTS, *SCHEMA_V2_STATEMENTS),
                )
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise
        except StorageSchemaError:
            raise
        except sqlite3.Error as exc:
            if self.connection.in_transaction:
                self.connection.rollback()
            raise StorageSchemaError("STORAGE_SCHEMA:INSPECTION_FAILED") from exc

    def _create_schema(self) -> None:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            for statement in (*SCHEMA_V1_STATEMENTS, *SCHEMA_V2_STATEMENTS):
                self.connection.execute(statement)
            _validate_schema(
                self.connection,
                _TABLE_COLUMNS_V2,
                _INDEX_COLUMNS_V2,
                _FOREIGN_KEYS_V2,
                _UNIQUE_INDEXES_V2,
                (*SCHEMA_V1_STATEMENTS, *SCHEMA_V2_STATEMENTS),
            )
            self.connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self.connection.commit()
        except Exception as exc:
            self.connection.rollback()
            if isinstance(exc, StorageSchemaError):
                raise
            raise StorageSchemaError("STORAGE_SCHEMA:MIGRATION_FAILED") from exc

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self.connection.close()
            finally:
                self._close_descriptors()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @staticmethod
    def _run_id(value: int) -> int:
        try:
            parsed = parse_nonnegative_int(
                value, "run_id", maximum=SQLITE_INTEGER_MAX
            )
        except ValueError as exc:
            raise IngestionRunError("INGESTION_RUN:INVALID_ID") from exc
        if parsed == 0:
            raise IngestionRunError("INGESTION_RUN:INVALID_ID")
        return parsed

    @staticmethod
    def _run_timestamp(value: datetime | None) -> datetime:
        try:
            candidate = datetime.now(timezone.utc) if value is None else value
            return parse_timestamp(candidate)
        except ValueError as exc:
            raise IngestionRunError("INGESTION_RUN:INVALID_TIMESTAMP") from exc

    def start_ingestion_run(
        self, source: str, *, started_at: datetime | None = None
    ) -> int:
        if not isinstance(source, str) or source not in INGESTION_SOURCES:
            raise IngestionRunError("INGESTION_RUN:INVALID_SOURCE")
        started = self._run_timestamp(started_at)
        with self._lock, self.connection:
            cursor = self.connection.execute(
                """
                INSERT INTO ingestion_runs (
                    started_at, finished_at, source, status,
                    processed_count, detection_count, failure_code
                ) VALUES (?, NULL, ?, 'running', 0, 0, NULL)
                """,
                (started.isoformat(), source),
            )
            return int(cursor.lastrowid)

    def finish_ingestion_run(
        self,
        run_id: int,
        status: str,
        *,
        failure_code: str | None = None,
        finished_at: datetime | None = None,
    ) -> dict[str, object]:
        safe_run_id = self._run_id(run_id)
        if not isinstance(status, str) or status not in {"completed", "failed"}:
            raise IngestionRunError("INGESTION_RUN:INVALID_STATUS")
        if status == "completed" and failure_code is not None:
            raise IngestionRunError("INGESTION_RUN:INVALID_FAILURE")
        if status == "failed" and (
            not isinstance(failure_code, str)
            or failure_code not in INGESTION_FAILURE_CODES
        ):
            raise IngestionRunError("INGESTION_RUN:INVALID_FAILURE")
        finished = self._run_timestamp(finished_at)

        with self._lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                row = self.connection.execute(
                    "SELECT started_at, source, status, detection_count "
                    "FROM ingestion_runs WHERE id = ?",
                    (safe_run_id,),
                ).fetchone()
                if row is None or row["status"] != "running":
                    raise IngestionRunError("INGESTION_RUN:NOT_ACTIVE")
                if finished < parse_timestamp(row["started_at"]):
                    raise IngestionRunError("INGESTION_RUN:INVALID_TIMESTAMP")
                processed_count = int(
                    self.connection.execute(
                        "SELECT COUNT(*) FROM ingestion_run_events WHERE run_id = ?",
                        (safe_run_id,),
                    ).fetchone()[0]
                )
                detection_count = int(row["detection_count"])
                cursor = self.connection.execute(
                    """
                    UPDATE ingestion_runs
                    SET finished_at = ?, status = ?, processed_count = ?,
                        detection_count = ?, failure_code = ?
                    WHERE id = ? AND status = 'running'
                    """,
                    (
                        finished.isoformat(),
                        status,
                        processed_count,
                        detection_count,
                        failure_code,
                        safe_run_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise IngestionRunError("INGESTION_RUN:NOT_ACTIVE")
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise
        return {
            "run_id": safe_run_id,
            "source": str(row["source"]),
            "status": status,
            "processed": processed_count,
            "detections": detection_count,
            "failure_code": failure_code,
        }

    def record_event(self, event: PacketEvent, *, run_id: int | None = None) -> int:
        byte_count = parse_nonnegative_int(
            event.byte_count, "byte_count", maximum=SQLITE_INTEGER_MAX
        )
        dns_query_length = (
            None
            if event.dns_query_length is None
            else parse_nonnegative_int(
                event.dns_query_length,
                "dns_query_length",
                maximum=SQLITE_INTEGER_MAX,
            )
        )
        metadata = validate_packet_metadata(event.metadata)
        safe_run_id = None if run_id is None else self._run_id(run_id)
        with self._lock, self.connection:
            cursor = self.connection.execute(
                """
                INSERT INTO events (
                    observed_at, src_ip, dst_ip, protocol, src_port, dst_port,
                    tcp_flags, dns_query_length, byte_count, interface, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.observed_at.isoformat(),
                    event.src_ip,
                    event.dst_ip,
                    event.protocol,
                    event.src_port,
                    event.dst_port,
                    json.dumps(sorted(event.tcp_flags)),
                    dns_query_length,
                    byte_count,
                    event.interface,
                    json.dumps(metadata, sort_keys=True, allow_nan=False),
                ),
            )
            event_id = int(cursor.lastrowid)
            if safe_run_id is not None:
                association = self.connection.execute(
                    """
                    INSERT INTO ingestion_run_events (run_id, event_id)
                    SELECT ?, ?
                    WHERE EXISTS (
                        SELECT 1 FROM ingestion_runs
                        WHERE id = ? AND status = 'running'
                    )
                    """,
                    (safe_run_id, event_id, safe_run_id),
                )
                if association.rowcount != 1:
                    raise IngestionRunError("INGESTION_RUN:NOT_ACTIVE")
            return event_id

    def record_detection(self, event_id: int, detection: DetectionResult) -> int:
        evidence = validate_metadata(detection.evidence)
        with self._lock, self.connection:
            cursor = self.connection.execute(
                """
                INSERT INTO detections (
                    event_id, detected_at, rule_id, severity, src_ip, dst_ip,
                    message, evidence_json, recommendation, suppressed_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    detection.detected_at.isoformat(),
                    detection.rule_id,
                    detection.severity,
                    detection.src_ip,
                    detection.dst_ip,
                    detection.message,
                    json.dumps(evidence, sort_keys=True, allow_nan=False),
                    detection.recommendation,
                    detection.suppressed_reason,
                ),
            )
            run = self.connection.execute(
                "SELECT run_id FROM ingestion_run_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if run is not None:
                counter = self.connection.execute(
                    """
                    UPDATE ingestion_runs
                    SET detection_count = detection_count + 1
                    WHERE id = ? AND status = 'running'
                    """,
                    (int(run["run_id"]),),
                )
                if counter.rowcount != 1:
                    raise IngestionRunError("INGESTION_RUN:NOT_ACTIVE")
            return int(cursor.lastrowid)

    def record_action(self, action: ActionRecord) -> int:
        details = validate_metadata(action.details)
        with self._lock, self.connection:
            cursor = self.connection.execute(
                """
                INSERT INTO actions (
                    created_at, action, target, status, reason, expires_at, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action.created_at.isoformat(),
                    action.action,
                    action.target,
                    action.status,
                    action.reason,
                    action.expires_at.isoformat() if action.expires_at else None,
                    json.dumps(details, sort_keys=True, allow_nan=False),
                ),
            )
            return int(cursor.lastrowid)

    def summary(self) -> dict[str, Any]:
        with self._lock:
            event_count = self.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            detection_count = self.connection.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
            action_count = self.connection.execute("SELECT COUNT(*) FROM actions").fetchone()[0]
            active_threats = self.connection.execute(
                "SELECT COUNT(*) FROM detections WHERE severity IN ('HIGH', 'CRITICAL')"
            ).fetchone()[0]
            return {
                "events": int(event_count),
                "detections": int(detection_count),
                "actions": int(action_count),
                "high_or_critical": int(active_threats),
            }

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 200))
        with self._lock:
            rows = self.connection.execute(
                """
                SELECT detected_at, rule_id, severity, src_ip, dst_ip, message,
                       evidence_json, recommendation, suppressed_reason
                FROM detections
                ORDER BY id DESC LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            result.append(
                {
                    "detected_at": row["detected_at"],
                    "rule_id": row["rule_id"],
                    "severity": row["severity"],
                    "src_ip": row["src_ip"],
                    "dst_ip": row["dst_ip"],
                    "message": row["message"],
                    "evidence": json.loads(row["evidence_json"]),
                    "recommendation": row["recommendation"],
                    "suppressed_reason": row["suppressed_reason"],
                }
            )
        return result

    def purge_before(self, before: datetime) -> dict[str, int]:
        if not isinstance(before, datetime) or before.tzinfo is None:
            raise ValueError("retention cutoff must be a timezone-aware datetime")
        try:
            offset = before.utcoffset()
        except (OverflowError, ValueError) as exc:
            raise ValueError("retention cutoff is outside the supported UTC range") from exc
        if offset is None:
            raise ValueError("retention cutoff must be a timezone-aware datetime")
        try:
            cutoff = before.astimezone(timezone.utc).isoformat()
        except (OverflowError, ValueError) as exc:
            raise ValueError("retention cutoff is outside the supported UTC range") from exc
        with self._lock:
            with self.connection:
                detections = self.connection.execute(
                    "DELETE FROM detections WHERE detected_at < ?", (cutoff,)
                )
                events = self.connection.execute("DELETE FROM events WHERE observed_at < ?", (cutoff,))
                actions = self.connection.execute("DELETE FROM actions WHERE created_at < ?", (cutoff,))
            return {
                "detections": detections.rowcount,
                "events": events.rowcount,
                "actions": actions.rowcount,
            }


class DashboardStore:
    """Read-only, least-data view of an existing private audit database."""

    EVENT_FIELDS = ("detected_at", "rule_id", "severity", "src_ip", "message")
    _AUTHORIZED_READS = {
        "events": frozenset({""}),
        "detections": frozenset({"", *EVENT_FIELDS}),
        "actions": frozenset({""}),
    }

    def __init__(self, path: str | Path):
        self.path = _absolute_database_path(path)
        self._lock = RLock()
        self._closed = False
        self._directory_descriptor: int | None = None
        self._database_descriptor: int | None = None
        if sqlite3.sqlite_version_info < MINIMUM_READ_ONLY_WAL_SQLITE:
            raise StorageSchemaError("DASHBOARD_STORE:UNSUPPORTED_SQLITE")
        connection: sqlite3.Connection | None = None
        preflight: sqlite3.Connection | None = None
        coordination: sqlite3.Connection | None = None
        try:
            self._directory_descriptor = _open_private_directory(
                self.path.parent, create=False, prefix="DASHBOARD_STORE"
            )
            self._database_descriptor, _ = _open_private_database(
                self.path,
                self._directory_descriptor,
                writable=False,
                create=False,
                prefix="DASHBOARD_STORE",
            )
            self._sqlite_path = _anchored_database_path(
                self._database_descriptor, self.path, "DASHBOARD_STORE"
            )
            sidecars = self._assert_path_identity()

            # Without live WAL coordination files, validate the immutable main
            # database first. This preflight cannot create WAL/SHM while refusing
            # a missing, corrupt, or incompatible database. Served reads never use
            # immutable mode because they must observe committed WAL records.
            if not sidecars:
                preflight = self._connect("mode=ro&immutable=1&cache=private")
                preflight_generation = _directory_generation(
                    self._directory_descriptor
                )
                self._enable_query_only(preflight)
                self._validate_current_schema(preflight)
                self._assert_path_identity()
                self._assert_directory_generation(preflight_generation)
                preflight.close()
                preflight = None

            # Establish and validate any required WAL coordination files on a
            # connection that is never served. Keeping it open makes the final
            # connection's directory-entry generation invariant strict.
            coordination = self._connect("mode=ro&cache=private")
            self._enable_query_only(coordination)
            self._validate_current_schema(coordination)
            self._assert_path_identity()
            served_generation = _directory_generation(
                self._directory_descriptor
            )

            connection = self._connect("mode=ro&cache=private")
            self._connection = connection
            self._enable_query_only(connection)
            self._validate_current_schema(connection)
            self._assert_path_identity()
            self._assert_directory_generation(served_generation)
            self._install_authorizer()
            coordination.close()
            coordination = None
            self._assert_path_identity()
            self._assert_directory_generation(served_generation)
            self._served_directory_generation = served_generation
        except StorageSchemaError:
            if preflight is not None:
                try:
                    preflight.close()
                except sqlite3.Error:
                    pass
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass
            if coordination is not None:
                try:
                    coordination.close()
                except sqlite3.Error:
                    pass
            self._close_descriptors()
            raise
        except (OSError, sqlite3.Error) as exc:
            if preflight is not None:
                try:
                    preflight.close()
                except sqlite3.Error:
                    pass
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass
            if coordination is not None:
                try:
                    coordination.close()
                except sqlite3.Error:
                    pass
            self._close_descriptors()
            raise StorageSchemaError("DASHBOARD_STORE:OPEN_FAILED") from exc

    def _connect(self, parameters: str) -> sqlite3.Connection:
        self._assert_path_identity()
        opening_generation = _directory_generation(self._directory_descriptor)
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                f"{self._sqlite_path.as_uri()}?{parameters}",
                uri=True,
                timeout=10,
                isolation_level=None,
                check_same_thread=False,
            )
            _validate_connection_path(
                connection, self.path, "DASHBOARD_STORE"
            )
            self._assert_path_identity()
            self._assert_directory_generation(opening_generation)
            connection.row_factory = sqlite3.Row
            return connection
        except Exception as exc:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass
            try:
                self._assert_path_identity()
            except StorageSchemaError as identity_error:
                raise identity_error from exc
            raise

    @staticmethod
    def _enable_query_only(connection: sqlite3.Connection) -> None:
        try:
            connection.execute("PRAGMA query_only=ON")
            enabled = int(connection.execute("PRAGMA query_only").fetchone()[0])
        except sqlite3.Error as exc:
            raise StorageSchemaError(
                "DASHBOARD_STORE:READ_ONLY_REQUIRED"
            ) from exc
        if enabled != 1:
            raise StorageSchemaError("DASHBOARD_STORE:READ_ONLY_REQUIRED")

    @staticmethod
    def _validate_current_schema(connection: sqlite3.Connection) -> None:
        try:
            connection.execute("BEGIN")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version != SCHEMA_VERSION:
                raise StorageSchemaError("DASHBOARD_STORE:INCOMPATIBLE_SCHEMA")
            _validate_schema(
                connection,
                _TABLE_COLUMNS_V2,
                _INDEX_COLUMNS_V2,
                _FOREIGN_KEYS_V2,
                _UNIQUE_INDEXES_V2,
                (*SCHEMA_V1_STATEMENTS, *SCHEMA_V2_STATEMENTS),
            )
        except StorageSchemaError as exc:
            raise StorageSchemaError(
                "DASHBOARD_STORE:INCOMPATIBLE_SCHEMA"
            ) from exc
        except (TypeError, ValueError, sqlite3.Error) as exc:
            raise StorageSchemaError(
                "DASHBOARD_STORE:INCOMPATIBLE_SCHEMA"
            ) from exc
        finally:
            if connection.in_transaction:
                connection.rollback()

    @classmethod
    def _authorize(
        cls,
        action: int,
        first: str | None,
        second: str | None,
        database: str | None,
        _source: str | None,
    ) -> int:
        if action == sqlite3.SQLITE_SELECT:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_FUNCTION and second == "count":
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_PRAGMA and first == "query_only" and second is None:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ and database in ("main", None):
            if second in cls._AUTHORIZED_READS.get(first or "", frozenset()):
                return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    def _install_authorizer(self) -> None:
        try:
            self._connection.set_authorizer(self._authorize)
        except sqlite3.Error as exc:
            raise StorageSchemaError(
                "DASHBOARD_STORE:READ_ONLY_REQUIRED"
            ) from exc

    @staticmethod
    def _validate_sidecar_state(sidecars: frozenset[str]) -> None:
        if "-journal" in sidecars or (("-wal" in sidecars) != ("-shm" in sidecars)):
            raise StorageSchemaError("DASHBOARD_STORE:UNSAFE_SIDECAR_STATE")

    def _assert_path_identity(self) -> frozenset[str]:
        if self._database_descriptor is None or not _path_matches_descriptor(
            self.path, self._database_descriptor
        ):
            _raise_path_error("DASHBOARD_STORE", "DATABASE_CHANGED")
        if self._directory_descriptor is not None and not _path_matches_descriptor(
            self.path.parent, self._directory_descriptor
        ):
            _raise_path_error("DASHBOARD_STORE", "DIRECTORY_CHANGED")
        _validate_private_database_stat(
            os.fstat(self._database_descriptor),
            writable=False,
            prefix="DASHBOARD_STORE",
        )
        if self._directory_descriptor is not None:
            _validate_private_directory_stat(
                os.fstat(self._directory_descriptor), "DASHBOARD_STORE"
            )
        sidecars = _validate_sqlite_sidecars(
            self.path,
            self._directory_descriptor,
            writable=False,
            prefix="DASHBOARD_STORE",
        )
        self._validate_sidecar_state(sidecars)
        return sidecars

    def _assert_directory_generation(
        self, expected: tuple[int, ...] | None
    ) -> None:
        if _directory_generation(self._directory_descriptor) != expected:
            _raise_path_error("DASHBOARD_STORE", "DIRECTORY_CHANGED")

    def _assert_served_identity(self) -> None:
        self._assert_path_identity()
        self._assert_directory_generation(self._served_directory_generation)

    def _close_descriptors(self) -> None:
        for attribute in ("_database_descriptor", "_directory_descriptor"):
            descriptor = getattr(self, attribute)
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, attribute, None)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._connection.close()
            finally:
                self._close_descriptors()

    def __enter__(self) -> "DashboardStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def summary(self) -> dict[str, int]:
        with self._lock:
            self._assert_served_identity()
            cursor: sqlite3.Cursor | None = None
            try:
                cursor = self._connection.execute(
                    """
                    SELECT
                        (SELECT COUNT(*) FROM events) AS events,
                        (SELECT COUNT(*) FROM detections) AS detections,
                        (SELECT COUNT(*) FROM actions) AS actions,
                        (SELECT COUNT(*) FROM detections
                         WHERE severity IN ('HIGH', 'CRITICAL'))
                            AS high_or_critical
                    """
                )
                row = cursor.fetchone()
                result = {
                    "events": int(row["events"]),
                    "detections": int(row["detections"]),
                    "actions": int(row["actions"]),
                    "high_or_critical": int(row["high_or_critical"]),
                }
            except (TypeError, ValueError, sqlite3.Error) as exc:
                raise StorageSchemaError("DASHBOARD_STORE:READ_FAILED") from exc
            finally:
                if cursor is not None:
                    cursor.close()
                self._assert_served_identity()
            return result

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ValueError("DASHBOARD_STORE:INVALID_LIMIT")
        with self._lock:
            self._assert_served_identity()
            cursor: sqlite3.Cursor | None = None
            try:
                cursor = self._connection.execute(
                    """
                    SELECT detected_at, rule_id, severity, src_ip, message
                    FROM detections
                    ORDER BY detected_at DESC LIMIT ?
                    """,
                    (limit,),
                )
                rows = cursor.fetchall()
                result = [
                    {field: row[field] for field in self.EVENT_FIELDS}
                    for row in rows
                ]
            except (KeyError, sqlite3.Error) as exc:
                raise StorageSchemaError("DASHBOARD_STORE:READ_FAILED") from exc
            finally:
                if cursor is not None:
                    cursor.close()
                self._assert_served_identity()
            return result
