"""Small auditable SQLite store; no packet payloads are written."""

from __future__ import annotations

from datetime import datetime, timezone
import errno
import hashlib
import hmac
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


SCHEMA_VERSION = 3
MIGRATION_BACKUP_SUFFIX = ".pre-v3.bak"
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

SCHEMA_V3_STATEMENTS = (
    "CREATE INDEX idx_detections_event_id ON detections(event_id)",
    """CREATE TABLE ingestion_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    processed_count INTEGER NOT NULL,
    detection_count INTEGER NOT NULL,
    action_count INTEGER NOT NULL DEFAULT 0 CHECK(action_count >= 0),
    receipt_version INTEGER NOT NULL DEFAULT 3 CHECK(receipt_version IN (2, 3)),
    failure_code TEXT,
    termination_reason TEXT CHECK(
        termination_reason IS NULL OR termination_reason IN (
            'source_exhausted', 'event_limit_reached', 'interrupted',
            'failed', 'reconciliation_required'
        )
    ),
    CHECK(source IN ('sample', 'jsonl', 'scapy')),
    CHECK(status IN (
        'running', 'completed', 'incomplete', 'failed',
        'reconciliation_required'
    )),
    CHECK(processed_count >= 0),
    CHECK(detection_count >= 0),
    CHECK(
        failure_code IS NULL OR failure_code IN (
            'CAPTURE_ERROR', 'INTERRUPTED', 'IO_ERROR', 'STORAGE_ERROR',
            'VALIDATION_ERROR'
        )
    ),
    CHECK(
        (
            receipt_version = 2 AND termination_reason IS NULL AND
            (
                (status = 'running' AND finished_at IS NULL AND failure_code IS NULL) OR
                (status = 'completed' AND finished_at IS NOT NULL AND failure_code IS NULL) OR
                (status = 'failed' AND finished_at IS NOT NULL AND failure_code IS NOT NULL)
            )
        ) OR
        (
            receipt_version = 3 AND
            (
                (status = 'running' AND finished_at IS NULL AND failure_code IS NULL AND termination_reason IS NULL) OR
                (status = 'completed' AND finished_at IS NOT NULL AND failure_code IS NULL AND termination_reason IS 'source_exhausted') OR
                (status = 'incomplete' AND finished_at IS NOT NULL AND failure_code IS NULL AND termination_reason IS 'event_limit_reached') OR
                (status = 'failed' AND finished_at IS NOT NULL AND failure_code IS 'INTERRUPTED' AND termination_reason IS 'interrupted') OR
                (status = 'failed' AND finished_at IS NOT NULL AND failure_code IS NOT NULL AND failure_code IN ('CAPTURE_ERROR', 'IO_ERROR', 'STORAGE_ERROR', 'VALIDATION_ERROR') AND termination_reason IS 'failed') OR
                (status = 'reconciliation_required' AND finished_at IS NULL AND failure_code IS NULL AND termination_reason IS 'reconciliation_required')
            )
        )
    )
)""",
    "CREATE INDEX idx_ingestion_runs_started_at ON ingestion_runs(started_at)",
    "CREATE INDEX idx_ingestion_runs_status ON ingestion_runs(status)",
    """CREATE TABLE ingestion_run_events (
    run_id INTEGER NOT NULL REFERENCES ingestion_runs(id),
    event_id INTEGER NOT NULL UNIQUE REFERENCES events(id) ON DELETE CASCADE,
    PRIMARY KEY (run_id, event_id)
)""",
    """CREATE TABLE detection_actions (
    detection_id INTEGER NOT NULL UNIQUE REFERENCES detections(id) ON DELETE CASCADE,
    action_id INTEGER NOT NULL UNIQUE REFERENCES actions(id) ON DELETE CASCADE,
    PRIMARY KEY (detection_id, action_id)
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

_TABLE_COLUMNS_V3 = {
    **_TABLE_COLUMNS_V1,
    "ingestion_runs": (
        ("id", "INTEGER", 0, 1),
        ("started_at", "TEXT", 1, 0),
        ("finished_at", "TEXT", 0, 0),
        ("source", "TEXT", 1, 0),
        ("status", "TEXT", 1, 0),
        ("processed_count", "INTEGER", 1, 0),
        ("detection_count", "INTEGER", 1, 0),
        ("action_count", "INTEGER", 1, 0),
        ("receipt_version", "INTEGER", 1, 0),
        ("failure_code", "TEXT", 0, 0),
        ("termination_reason", "TEXT", 0, 0),
    ),
    "ingestion_run_events": (
        ("run_id", "INTEGER", 1, 1),
        ("event_id", "INTEGER", 1, 2),
    ),
    "detection_actions": (
        ("detection_id", "INTEGER", 1, 1),
        ("action_id", "INTEGER", 1, 2),
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

_INDEX_COLUMNS_V3 = {
    **_INDEX_COLUMNS_V1,
    "idx_detections_event_id": ("detections", ("event_id",)),
    "idx_ingestion_runs_started_at": ("ingestion_runs", ("started_at",)),
    "idx_ingestion_runs_status": ("ingestion_runs", ("status",)),
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

_UNIQUE_INDEXES_V3 = {
    **_UNIQUE_INDEXES_V1,
    "ingestion_runs": set(),
    "ingestion_run_events": {
        ("pk", ("run_id", "event_id")),
        ("u", ("event_id",)),
    },
    "detection_actions": {
        ("pk", ("detection_id", "action_id")),
        ("u", ("detection_id",)),
        ("u", ("action_id",)),
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

_FOREIGN_KEYS_V3 = {
    **_FOREIGN_KEYS_V1,
    "ingestion_runs": set(),
    "ingestion_run_events": {
        ("ingestion_runs", "run_id", "id", "NO ACTION"),
        ("events", "event_id", "id", "CASCADE"),
    },
    "detection_actions": {
        ("detections", "detection_id", "id", "CASCADE"),
        ("actions", "action_id", "id", "CASCADE"),
    },
}

INGESTION_SOURCES = frozenset({"sample", "jsonl", "scapy"})
INGESTION_FAILURE_CODES = frozenset(
    {"CAPTURE_ERROR", "INTERRUPTED", "IO_ERROR", "STORAGE_ERROR", "VALIDATION_ERROR"}
)
INGESTION_TERMINATION_REASONS = frozenset(
    {
        "source_exhausted",
        "event_limit_reached",
        "interrupted",
        "failed",
        "reconciliation_required",
    }
)
MAX_DETECTIONS_PER_EVENT = 3
RECONCILIATION_REQUIRED = "INGESTION_RUN:RECONCILIATION_REQUIRED"

PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_DATABASE_MODE = 0o600
DEFAULT_MAX_DATABASE_BYTES = 256 * 1024 * 1024
MAX_MAX_DATABASE_BYTES = 4 * 1024 * 1024 * 1024
CAPACITY_RESERVE_BYTES = 256 * 1024
DEFAULT_RETENTION_BATCH_ROWS = 100
MAX_RETENTION_BATCH_ROWS = 256
RETENTION_RECEIPT_VERSION = "retention-purge-v1"
RETENTION_RECONCILIATION_REQUIRED = "RETENTION:RECONCILIATION_REQUIRED"
_SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


class StorageSchemaError(ValueError):
    """The selected database cannot safely satisfy this storage schema."""


class IngestionRunError(ValueError):
    """An ingestion run transition or association is invalid."""


class StorageCapacityError(sqlite3.OperationalError):
    """The configured storage high-water stop refused an intake write."""


class RetentionError(ValueError):
    """A retention preview or bounded purge request failed closed."""


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
    actual = _absolute_database_path(str(filename), prefix)
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


def _absolute_database_path(
    path: str | Path, prefix: str = "STORAGE_PATH"
) -> Path:
    """Return an absolute lexical path without following a filesystem link."""

    raw = Path(path)
    if ".." in raw.parts:
        _raise_path_error(prefix, "AMBIGUOUS_PATH")
    return Path(os.path.abspath(os.fspath(raw)))


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


def _schema_contract(version: int):
    if version in (0, 1):
        return (
            _TABLE_COLUMNS_V1,
            _INDEX_COLUMNS_V1,
            _FOREIGN_KEYS_V1,
            _UNIQUE_INDEXES_V1,
            SCHEMA_V1_STATEMENTS,
        )
    if version == 2:
        return (
            _TABLE_COLUMNS_V2,
            _INDEX_COLUMNS_V2,
            _FOREIGN_KEYS_V2,
            _UNIQUE_INDEXES_V2,
            (*SCHEMA_V1_STATEMENTS, *SCHEMA_V2_STATEMENTS),
        )
    if version == SCHEMA_VERSION:
        return (
            _TABLE_COLUMNS_V3,
            _INDEX_COLUMNS_V3,
            _FOREIGN_KEYS_V3,
            _UNIQUE_INDEXES_V3,
            (*SCHEMA_V1_STATEMENTS, *SCHEMA_V3_STATEMENTS),
        )
    raise StorageSchemaError("STORAGE_SCHEMA:UNSUPPORTED_VERSION")


def migrate_database(path: str | Path) -> dict[str, object]:
    """Explicitly migrate an exact v1/v2 database after a verified backup."""

    source_path = _absolute_database_path(path, "STORAGE_MIGRATION")
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
            _validate_schema(source, *_schema_contract(version))
            return {
                "status": "already_current",
                "from_version": SCHEMA_VERSION,
                "to_version": SCHEMA_VERSION,
                "backup": None,
            }
        if version > SCHEMA_VERSION:
            raise StorageSchemaError("STORAGE_SCHEMA:FUTURE_VERSION")
        if version not in (0, 1, 2):
            raise StorageSchemaError("STORAGE_SCHEMA:UNSUPPORTED_VERSION")
        _validate_schema(source, *_schema_contract(version))
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
        _validate_schema(backup, *_schema_contract(version))
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
            _validate_schema(source, *_schema_contract(version))
        except StorageSchemaError as exc:
            source.rollback()
            raise StorageSchemaError("STORAGE_MIGRATION:SOURCE_CHANGED") from exc

        migration_started = True
        if version == 2:
            source.execute(
                "CREATE TEMP TABLE migration_ingestion_runs AS "
                "SELECT * FROM ingestion_runs"
            )
            source.execute(
                "CREATE TEMP TABLE migration_ingestion_run_events AS "
                "SELECT * FROM ingestion_run_events"
            )
            source.execute("DROP TABLE ingestion_run_events")
            source.execute("DROP TABLE ingestion_runs")
        for statement in SCHEMA_V3_STATEMENTS:
            source.execute(statement)
        if version == 2:
            source.execute(
                """
                INSERT INTO ingestion_runs (
                    id, started_at, finished_at, source, status,
                    processed_count, detection_count, action_count,
                    receipt_version, failure_code, termination_reason
                )
                SELECT
                    id,
                    started_at,
                    finished_at,
                    source,
                    status,
                    processed_count,
                    detection_count,
                    0,
                    2,
                    failure_code,
                    NULL
                FROM migration_ingestion_runs
                """
            )
            source.execute(
                """
                INSERT INTO ingestion_run_events (run_id, event_id)
                SELECT run_id, event_id FROM migration_ingestion_run_events
                """
            )
            source.execute("DROP TABLE migration_ingestion_run_events")
            source.execute("DROP TABLE migration_ingestion_runs")
        if source.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise StorageSchemaError("STORAGE_MIGRATION:INCOMPATIBLE_DATA")
        _validate_schema(
            source,
            _TABLE_COLUMNS_V3,
            _INDEX_COLUMNS_V3,
            _FOREIGN_KEYS_V3,
            _UNIQUE_INDEXES_V3,
            (*SCHEMA_V1_STATEMENTS, *SCHEMA_V3_STATEMENTS),
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
    def __init__(
        self,
        path: str | Path,
        *,
        create: bool = True,
        max_database_bytes: int = DEFAULT_MAX_DATABASE_BYTES,
    ):
        if (
            isinstance(max_database_bytes, bool)
            or not isinstance(max_database_bytes, int)
            or not 1 <= max_database_bytes <= MAX_MAX_DATABASE_BYTES
        ):
            raise StorageCapacityError("STORAGE_CAPACITY:INVALID_LIMIT")
        self.max_database_bytes = max_database_bytes
        self.path = _absolute_database_path(path, "STORAGE_PATH")
        self._lock = RLock()
        self._closed = False
        self._write_poisoned = False
        self._directory_descriptor: int | None = None
        self._database_descriptor: int | None = None
        database_created = False
        connection: sqlite3.Connection | None = None
        try:
            self._directory_descriptor = _open_private_directory(
                self.path.parent, create=create, prefix="STORAGE_PATH"
            )
            self._database_descriptor, database_created = _open_private_database(
                self.path,
                self._directory_descriptor,
                writable=True,
                create=create,
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

    def _sidecar_size(self, suffix: str) -> int:
        sidecar = self.path.with_name(self.path.name + suffix)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        target: str | Path = (
            sidecar.name if self._directory_descriptor is not None else sidecar
        )
        kwargs = (
            {"dir_fd": self._directory_descriptor}
            if self._directory_descriptor is not None
            else {}
        )
        descriptor: int | None = None
        try:
            if os.name != "posix" and sidecar.is_symlink():
                raise StorageCapacityError("STORAGE_CAPACITY:UNSAFE_SIDECAR")
            try:
                descriptor = os.open(target, flags, **kwargs)
            except FileNotFoundError:
                return 0
            except OSError as exc:
                raise StorageCapacityError(
                    "STORAGE_CAPACITY:SIDECAR_UNREADABLE"
                ) from exc
            try:
                info = os.fstat(descriptor)
                try:
                    _validate_private_database_stat(
                        info, writable=True, prefix="STORAGE_CAPACITY"
                    )
                except StorageSchemaError as exc:
                    raise StorageCapacityError(
                        "STORAGE_CAPACITY:UNSAFE_SIDECAR"
                    ) from exc
                return int(info.st_size)
            except StorageCapacityError:
                raise
            except OSError as exc:
                raise StorageCapacityError(
                    "STORAGE_CAPACITY:SIDECAR_UNREADABLE"
                ) from exc
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def _observed_storage_bytes(self) -> int:
        try:
            self._assert_path_identity()
            if self._database_descriptor is None:
                raise StorageCapacityError("STORAGE_CAPACITY:IDENTITY_UNVERIFIED")
            total = int(os.fstat(self._database_descriptor).st_size)
            total += sum(
                self._sidecar_size(suffix) for suffix in _SQLITE_SIDECAR_SUFFIXES
            )
            return total
        except StorageCapacityError:
            raise
        except (OSError, StorageSchemaError) as exc:
            raise StorageCapacityError(
                "STORAGE_CAPACITY:IDENTITY_UNVERIFIED"
            ) from exc

    def _ensure_capacity(self) -> None:
        if (
            self._observed_storage_bytes() + CAPACITY_RESERVE_BYTES
            > self.max_database_bytes
        ):
            raise StorageCapacityError("STORAGE_CAPACITY:HIGH_WATER")

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
            if version not in (0, 1, 2, SCHEMA_VERSION):
                raise StorageSchemaError("STORAGE_SCHEMA:UNSUPPORTED_VERSION")

            present = _schema_objects(self.connection)
            if version == 0 and not present:
                self._create_schema()
                return
            if version in (0, 1, 2):
                self.connection.execute("BEGIN IMMEDIATE")
                try:
                    _validate_schema(self.connection, *_schema_contract(version))
                finally:
                    self.connection.rollback()
                raise StorageSchemaError("STORAGE_SCHEMA:MIGRATION_REQUIRED")
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                _validate_schema(
                    self.connection,
                    _TABLE_COLUMNS_V3,
                    _INDEX_COLUMNS_V3,
                    _FOREIGN_KEYS_V3,
                    _UNIQUE_INDEXES_V3,
                    (*SCHEMA_V1_STATEMENTS, *SCHEMA_V3_STATEMENTS),
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
            for statement in (*SCHEMA_V1_STATEMENTS, *SCHEMA_V3_STATEMENTS):
                self.connection.execute(statement)
            _validate_schema(
                self.connection,
                _TABLE_COLUMNS_V3,
                _INDEX_COLUMNS_V3,
                _FOREIGN_KEYS_V3,
                _UNIQUE_INDEXES_V3,
                (*SCHEMA_V1_STATEMENTS, *SCHEMA_V3_STATEMENTS),
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

    def _assert_write_trusted(self) -> None:
        if self._write_poisoned:
            raise IngestionRunError(RECONCILIATION_REQUIRED)

    def _connection_commit(self) -> None:
        self.connection.commit()

    def _connection_rollback(self) -> None:
        self.connection.rollback()

    def _rollback_run_write(self) -> None:
        try:
            self._connection_rollback()
        except BaseException as exc:
            self._write_poisoned = True
            raise IngestionRunError(RECONCILIATION_REQUIRED) from exc

    def _commit_run_write(self) -> None:
        try:
            self._connection_commit()
        except BaseException as exc:
            self._write_poisoned = True
            try:
                self.connection.rollback()
            except sqlite3.Error:
                pass
            raise IngestionRunError(RECONCILIATION_REQUIRED) from exc

    def _actual_run_counts(self, run_id: int) -> tuple[int, int, int]:
        processed = int(
            self.connection.execute(
                "SELECT COUNT(*) FROM ingestion_run_events WHERE run_id = ?",
                (run_id,),
            ).fetchone()[0]
        )
        detections = int(
            self.connection.execute(
                """
                SELECT COUNT(*)
                FROM detections AS detection
                JOIN ingestion_run_events AS run_event
                  ON run_event.event_id = detection.event_id
                WHERE run_event.run_id = ?
                """,
                (run_id,),
            ).fetchone()[0]
        )
        actions = int(
            self.connection.execute(
                """
                SELECT COUNT(*)
                FROM detection_actions AS link
                JOIN detections AS detection ON detection.id = link.detection_id
                JOIN ingestion_run_events AS run_event
                  ON run_event.event_id = detection.event_id
                WHERE run_event.run_id = ?
                """,
                (run_id,),
            ).fetchone()[0]
        )
        return processed, detections, actions

    def start_ingestion_run(
        self, source: str, *, started_at: datetime | None = None
    ) -> int:
        if not isinstance(source, str) or source not in INGESTION_SOURCES:
            raise IngestionRunError("INGESTION_RUN:INVALID_SOURCE")
        started = self._run_timestamp(started_at)
        with self._lock:
            self._assert_write_trusted()
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                if self.connection.execute(
                    "SELECT 1 FROM ingestion_runs WHERE status = 'running' LIMIT 1"
                ).fetchone() is not None:
                    raise IngestionRunError(RECONCILIATION_REQUIRED)
                cursor = self.connection.execute(
                    """
                    INSERT INTO ingestion_runs (
                        started_at, finished_at, source, status,
                        processed_count, detection_count, action_count,
                        receipt_version, failure_code, termination_reason
                    ) VALUES (?, NULL, ?, 'running', 0, 0, 0, 3, NULL, NULL)
                    """,
                    (started.isoformat(), source),
                )
            except BaseException:
                self._rollback_run_write()
                raise
            self._commit_run_write()
            return int(cursor.lastrowid)

    def finish_ingestion_run(
        self,
        run_id: int,
        termination_reason: str,
        *,
        failure_code: str | None = None,
        finished_at: datetime | None = None,
    ) -> dict[str, object]:
        safe_run_id = self._run_id(run_id)
        if (
            not isinstance(termination_reason, str)
            or termination_reason
            not in INGESTION_TERMINATION_REASONS - {"reconciliation_required"}
        ):
            raise IngestionRunError("INGESTION_RUN:INVALID_TERMINATION")
        if termination_reason in {"source_exhausted", "event_limit_reached"} and failure_code is not None:
            raise IngestionRunError("INGESTION_RUN:INVALID_FAILURE")
        if termination_reason == "interrupted":
            if failure_code not in (None, "INTERRUPTED"):
                raise IngestionRunError("INGESTION_RUN:INVALID_FAILURE")
            failure_code = "INTERRUPTED"
        if termination_reason == "failed" and (
            not isinstance(failure_code, str)
            or failure_code not in INGESTION_FAILURE_CODES - {"INTERRUPTED"}
        ):
            raise IngestionRunError("INGESTION_RUN:INVALID_FAILURE")
        status = {
            "source_exhausted": "completed",
            "event_limit_reached": "incomplete",
            "interrupted": "failed",
            "failed": "failed",
        }[termination_reason]
        finished = self._run_timestamp(finished_at)

        with self._lock:
            self._assert_write_trusted()
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                row = self.connection.execute(
                    "SELECT started_at, source, status, processed_count, "
                    "detection_count, action_count, receipt_version "
                    "FROM ingestion_runs WHERE id = ?",
                    (safe_run_id,),
                ).fetchone()
                if (
                    row is None
                    or row["status"] != "running"
                    or int(row["receipt_version"]) != 3
                ):
                    raise IngestionRunError("INGESTION_RUN:NOT_ACTIVE")
                if finished < parse_timestamp(row["started_at"]):
                    raise IngestionRunError("INGESTION_RUN:INVALID_TIMESTAMP")
                processed_count, detection_count, action_count = (
                    self._actual_run_counts(safe_run_id)
                )
                stored_counts = (
                    int(row["processed_count"]),
                    int(row["detection_count"]),
                    int(row["action_count"]),
                )
                if (
                    stored_counts != (processed_count, detection_count, action_count)
                    or action_count != detection_count
                ):
                    self.connection.execute(
                        """
                        UPDATE ingestion_runs
                        SET status = 'reconciliation_required',
                            processed_count = ?, detection_count = ?, action_count = ?,
                            failure_code = NULL,
                            termination_reason = 'reconciliation_required'
                        WHERE id = ? AND status = 'running' AND receipt_version = 3
                        """,
                        (
                            processed_count,
                            detection_count,
                            action_count,
                            safe_run_id,
                        ),
                    )
                    self._commit_run_write()
                    return {
                        "run_id": safe_run_id,
                        "source": str(row["source"]),
                        "status": "reconciliation_required",
                        "termination_reason": "reconciliation_required",
                        "processed": processed_count,
                        "detections": detection_count,
                        "actions": action_count,
                        "failure_code": None,
                    }
                cursor = self.connection.execute(
                    """
                    UPDATE ingestion_runs
                    SET finished_at = ?, status = ?, failure_code = ?,
                        termination_reason = ?
                    WHERE id = ? AND status = 'running' AND receipt_version = 3
                    """,
                    (
                        finished.isoformat(),
                        status,
                        failure_code,
                        termination_reason,
                        safe_run_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise IngestionRunError("INGESTION_RUN:NOT_ACTIVE")
            except BaseException:
                self._rollback_run_write()
                raise
            self._commit_run_write()
        return {
            "run_id": safe_run_id,
            "source": str(row["source"]),
            "status": status,
            "termination_reason": termination_reason,
            "processed": processed_count,
            "detections": detection_count,
            "actions": action_count,
            "failure_code": failure_code,
        }

    def pending_ingestion_reconciliation(
        self, limit: int = 100
    ) -> list[dict[str, object]]:
        try:
            safe_limit = parse_nonnegative_int(limit, "limit", maximum=100)
        except ValueError as exc:
            raise IngestionRunError("INGESTION_RUN:INVALID_LIMIT") from exc
        if safe_limit == 0:
            raise IngestionRunError("INGESTION_RUN:INVALID_LIMIT")
        with self._lock:
            rows = self.connection.execute(
                """
                SELECT id, started_at, source, status, processed_count,
                       detection_count, action_count, receipt_version,
                       termination_reason
                FROM ingestion_runs
                WHERE status IN ('running', 'reconciliation_required')
                ORDER BY status DESC, id DESC LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
        return [
            {
                "run_id": int(row["id"]),
                "started_at": str(row["started_at"]),
                "source": str(row["source"]),
                "status": str(row["status"]),
                "processed": int(row["processed_count"]),
                "detections": int(row["detection_count"]),
                "actions": int(row["action_count"]),
                "receipt_version": int(row["receipt_version"]),
                "termination_reason": row["termination_reason"],
            }
            for row in rows
        ]

    def mark_ingestion_run_reconciliation_required(
        self, run_id: int, *, expected_started_at: datetime
    ) -> dict[str, object]:
        safe_run_id = self._run_id(run_id)
        expected = self._run_timestamp(expected_started_at).isoformat()
        with self._lock:
            self._assert_write_trusted()
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                row = self.connection.execute(
                    """
                    SELECT started_at, source, status, processed_count,
                           detection_count, action_count, receipt_version,
                           termination_reason
                    FROM ingestion_runs WHERE id = ?
                    """,
                    (safe_run_id,),
                ).fetchone()
                if row is None or str(row["started_at"]) != expected:
                    raise IngestionRunError("INGESTION_RUN:STALE_RECONCILIATION")
                if row["status"] == "reconciliation_required":
                    self._rollback_run_write()
                    return {
                        "run_id": safe_run_id,
                        "source": str(row["source"]),
                        "status": "reconciliation_required",
                        "termination_reason": "reconciliation_required",
                        "processed": int(row["processed_count"]),
                        "detections": int(row["detection_count"]),
                        "actions": int(row["action_count"]),
                    }
                if row["status"] != "running":
                    raise IngestionRunError("INGESTION_RUN:NOT_ACTIVE")
                processed, detections, actions = self._actual_run_counts(safe_run_id)
                cursor = self.connection.execute(
                    """
                    UPDATE ingestion_runs
                    SET status = 'reconciliation_required',
                        processed_count = ?, detection_count = ?, action_count = ?,
                        receipt_version = 3, failure_code = NULL,
                        termination_reason = 'reconciliation_required'
                    WHERE id = ? AND started_at = ? AND status = 'running'
                    """,
                    (processed, detections, actions, safe_run_id, expected),
                )
                if cursor.rowcount != 1:
                    raise IngestionRunError("INGESTION_RUN:STALE_RECONCILIATION")
            except BaseException:
                self._rollback_run_write()
                raise
            self._commit_run_write()
        return {
            "run_id": safe_run_id,
            "source": str(row["source"]),
            "status": "reconciliation_required",
            "termination_reason": "reconciliation_required",
            "processed": processed,
            "detections": detections,
            "actions": actions,
        }

    @staticmethod
    def _event_values(event: PacketEvent) -> tuple[object, ...]:
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
        return (
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
        )

    @staticmethod
    def _detection_values(detection: DetectionResult) -> tuple[object, ...]:
        evidence = validate_metadata(detection.evidence)
        return (
            detection.detected_at.isoformat(),
            detection.rule_id,
            detection.severity,
            detection.src_ip,
            detection.dst_ip,
            detection.message,
            json.dumps(evidence, sort_keys=True, allow_nan=False),
            detection.recommendation,
            detection.suppressed_reason,
        )

    @staticmethod
    def _action_values(action: ActionRecord) -> tuple[object, ...]:
        details = validate_metadata(action.details)
        return (
            action.created_at.isoformat(),
            action.action,
            action.target,
            action.status,
            action.reason,
            action.expires_at.isoformat() if action.expires_at else None,
            json.dumps(details, sort_keys=True, allow_nan=False),
        )

    def _insert_event(self, values: tuple[object, ...]) -> int:
        cursor = self.connection.execute(
            """
            INSERT INTO events (
                observed_at, src_ip, dst_ip, protocol, src_port, dst_port,
                tcp_flags, dns_query_length, byte_count, interface, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        return int(cursor.lastrowid)

    def record_event_bundle(
        self,
        event: PacketEvent,
        detections: list[DetectionResult] | tuple[DetectionResult, ...],
        actions: list[ActionRecord] | tuple[ActionRecord, ...],
        *,
        run_id: int | None = None,
    ) -> int:
        """Commit one event and its complete Stage 0 decision ledger atomically."""

        safe_run_id = None if run_id is None else self._run_id(run_id)
        event_values = self._event_values(event)
        if type(detections) not in (list, tuple) or type(actions) not in (list, tuple):
            raise IngestionRunError("INGESTION_RUN:INVALID_BUNDLE")
        if (
            len(detections) != len(actions)
            or len(detections) > MAX_DETECTIONS_PER_EVENT
        ):
            raise IngestionRunError("INGESTION_RUN:INVALID_BUNDLE")
        if not all(isinstance(item, DetectionResult) for item in detections) or not all(
            isinstance(item, ActionRecord) for item in actions
        ):
            raise IngestionRunError("INGESTION_RUN:INVALID_BUNDLE")
        detection_items = tuple(detections)
        action_items = tuple(actions)
        detection_values = tuple(self._detection_values(item) for item in detection_items)
        action_values = tuple(self._action_values(item) for item in action_items)
        for detection in detection_items:
            if (
                detection.detected_at != event.observed_at
                or detection.src_ip != event.src_ip
                or detection.dst_ip != event.dst_ip
            ):
                raise IngestionRunError("INGESTION_RUN:INVALID_BUNDLE")

        with self._lock:
            self._assert_write_trusted()
            self._ensure_capacity()
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                event_id = self._insert_event(event_values)
                if safe_run_id is not None:
                    association = self.connection.execute(
                        """
                        INSERT INTO ingestion_run_events (run_id, event_id)
                        SELECT ?, ?
                        WHERE EXISTS (
                            SELECT 1 FROM ingestion_runs
                            WHERE id = ? AND status = 'running'
                              AND receipt_version = 3
                        )
                        """,
                        (safe_run_id, event_id, safe_run_id),
                    )
                    if association.rowcount != 1:
                        raise IngestionRunError("INGESTION_RUN:NOT_ACTIVE")
                for detection_row, action_row in zip(
                    detection_values, action_values, strict=True
                ):
                    detection_cursor = self.connection.execute(
                        """
                        INSERT INTO detections (
                            event_id, detected_at, rule_id, severity, src_ip, dst_ip,
                            message, evidence_json, recommendation, suppressed_reason
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (event_id, *detection_row),
                    )
                    action_cursor = self.connection.execute(
                        """
                        INSERT INTO actions (
                            created_at, action, target, status, reason, expires_at,
                            details_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        action_row,
                    )
                    self.connection.execute(
                        """
                        INSERT INTO detection_actions (detection_id, action_id)
                        VALUES (?, ?)
                        """,
                        (
                            int(detection_cursor.lastrowid),
                            int(action_cursor.lastrowid),
                        ),
                    )
                if safe_run_id is not None:
                    counter = self.connection.execute(
                        """
                        UPDATE ingestion_runs
                        SET processed_count = processed_count + 1,
                            detection_count = detection_count + ?,
                            action_count = action_count + ?
                        WHERE id = ? AND status = 'running'
                          AND receipt_version = 3
                        """,
                        (
                            len(detection_items),
                            len(action_items),
                            safe_run_id,
                        ),
                    )
                    if counter.rowcount != 1:
                        raise IngestionRunError("INGESTION_RUN:NOT_ACTIVE")
            except BaseException:
                self._rollback_run_write()
                raise
            self._commit_run_write()
            return event_id

    def record_event(self, event: PacketEvent, *, run_id: int | None = None) -> int:
        if run_id is not None:
            self._run_id(run_id)
            raise IngestionRunError("INGESTION_RUN:ATOMIC_WRITE_REQUIRED")
        values = self._event_values(event)
        with self._lock, self.connection:
            self._assert_write_trusted()
            self._ensure_capacity()
            return self._insert_event(values)

    def record_detection(self, event_id: int, detection: DetectionResult) -> int:
        values = self._detection_values(detection)
        with self._lock, self.connection:
            self._assert_write_trusted()
            self._ensure_capacity()
            if self.connection.execute(
                "SELECT 1 FROM ingestion_run_events WHERE event_id = ?",
                (event_id,),
            ).fetchone() is not None:
                raise IngestionRunError("INGESTION_RUN:ATOMIC_WRITE_REQUIRED")
            cursor = self.connection.execute(
                """
                INSERT INTO detections (
                    event_id, detected_at, rule_id, severity, src_ip, dst_ip,
                    message, evidence_json, recommendation, suppressed_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    *values,
                ),
            )
            return int(cursor.lastrowid)

    def record_action(self, action: ActionRecord) -> int:
        values = self._action_values(action)
        with self._lock, self.connection:
            self._assert_write_trusted()
            self._ensure_capacity()
            cursor = self.connection.execute(
                """
                INSERT INTO actions (
                    created_at, action, target, status, reason, expires_at, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                values,
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

    @staticmethod
    def _retention_cutoff(before: datetime) -> str:
        if not isinstance(before, datetime) or before.tzinfo is None:
            raise ValueError("retention cutoff must be a timezone-aware datetime")
        try:
            offset = before.utcoffset()
        except (OverflowError, ValueError) as exc:
            raise ValueError("retention cutoff is outside the supported UTC range") from exc
        if offset is None:
            raise ValueError("retention cutoff must be a timezone-aware datetime")
        try:
            return before.astimezone(timezone.utc).isoformat()
        except (OverflowError, ValueError) as exc:
            raise ValueError("retention cutoff is outside the supported UTC range") from exc

    @staticmethod
    def _retention_batch_limit(batch_limit: int) -> int:
        if isinstance(batch_limit, bool) or not isinstance(batch_limit, int):
            raise RetentionError("RETENTION:INVALID_BATCH_LIMIT")
        try:
            parsed = parse_nonnegative_int(
                batch_limit,
                "batch_limit",
                maximum=MAX_RETENTION_BATCH_ROWS,
            )
        except ValueError as exc:
            raise RetentionError("RETENTION:INVALID_BATCH_LIMIT") from exc
        if parsed == 0:
            raise RetentionError("RETENTION:INVALID_BATCH_LIMIT")
        return parsed

    @staticmethod
    def _valid_retention_token(preview_token: object) -> bool:
        if not isinstance(preview_token, str) or not preview_token.startswith(
            "sha256:"
        ):
            return False
        digest = preview_token.removeprefix("sha256:")
        return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)

    def _retention_store_identity(self) -> str:
        self._assert_path_identity()
        if self._database_descriptor is None:
            raise RetentionError("RETENTION:IDENTITY_UNVERIFIED")
        try:
            info = os.fstat(self._database_descriptor)
        except OSError as exc:
            raise RetentionError("RETENTION:IDENTITY_UNVERIFIED") from exc
        identity = f"{info.st_dev}:{info.st_ino}:{SCHEMA_VERSION}".encode("ascii")
        return f"sha256:{hashlib.sha256(identity).hexdigest()}"

    def _assert_retention_ready(self) -> None:
        if self.connection.in_transaction:
            raise RetentionError("RETENTION:ACTIVE_TRANSACTION")
        if self.connection.execute(
            "SELECT 1 FROM ingestion_runs "
            "WHERE status IN ('running', 'reconciliation_required') LIMIT 1"
        ).fetchone() is not None:
            raise RetentionError("RETENTION:ACTIVE_RUN")

    def _retention_candidates(
        self, cutoff: str, batch_limit: int
    ) -> tuple[tuple[str, tuple[int, ...]], ...]:
        remaining = batch_limit
        candidates: list[tuple[str, tuple[int, ...]]] = []
        detection_rows = self.connection.execute(
            "SELECT id FROM detections WHERE detected_at < ? "
            "ORDER BY detected_at, id LIMIT ?",
            (cutoff, remaining),
        ).fetchall()
        detection_ids = tuple(int(row[0]) for row in detection_rows)
        candidates.append(("detections", detection_ids))
        remaining -= len(detection_ids)

        event_ids: tuple[int, ...] = ()
        if remaining:
            if detection_ids:
                placeholders = ",".join("?" for _ in detection_ids)
                event_statement = (
                    "SELECT event.id FROM events AS event "
                    "WHERE event.observed_at < ? AND NOT EXISTS ("
                    "SELECT 1 FROM detections AS detection "
                    "WHERE detection.event_id = event.id "
                    f"AND detection.id NOT IN ({placeholders})) "
                    "ORDER BY event.observed_at, event.id LIMIT ?"
                )
                event_parameters = (cutoff, *detection_ids, remaining)
            else:
                event_statement = (
                    "SELECT event.id FROM events AS event "
                    "WHERE event.observed_at < ? AND NOT EXISTS ("
                    "SELECT 1 FROM detections AS detection "
                    "WHERE detection.event_id = event.id) "
                    "ORDER BY event.observed_at, event.id LIMIT ?"
                )
                event_parameters = (cutoff, remaining)
            event_rows = self.connection.execute(
                event_statement, event_parameters
            ).fetchall()
            event_ids = tuple(int(row[0]) for row in event_rows)
        candidates.append(("events", event_ids))
        remaining -= len(event_ids)

        action_ids: tuple[int, ...] = ()
        if remaining:
            if detection_ids:
                placeholders = ",".join("?" for _ in detection_ids)
                action_statement = (
                    "SELECT action.id FROM actions AS action "
                    "WHERE action.created_at < ? AND NOT EXISTS ("
                    "SELECT 1 FROM detection_actions AS link "
                    "WHERE link.action_id = action.id "
                    f"AND link.detection_id NOT IN ({placeholders})) "
                    "ORDER BY action.created_at, action.id LIMIT ?"
                )
                action_parameters = (cutoff, *detection_ids, remaining)
            else:
                action_statement = (
                    "SELECT action.id FROM actions AS action "
                    "WHERE action.created_at < ? AND NOT EXISTS ("
                    "SELECT 1 FROM detection_actions AS link "
                    "WHERE link.action_id = action.id) "
                    "ORDER BY action.created_at, action.id LIMIT ?"
                )
                action_parameters = (cutoff, remaining)
            action_rows = self.connection.execute(
                action_statement,
                action_parameters,
            ).fetchall()
            action_ids = tuple(int(row[0]) for row in action_rows)
        candidates.append(("actions", action_ids))
        return tuple(candidates)

    def _retention_candidates_exist(self, cutoff: str) -> bool:
        statements = (
            "SELECT 1 FROM detections WHERE detected_at < ? LIMIT 1",
            "SELECT 1 FROM events AS event WHERE event.observed_at < ? "
            "AND NOT EXISTS (SELECT 1 FROM detections AS detection "
            "WHERE detection.event_id = event.id) LIMIT 1",
            "SELECT 1 FROM actions AS action WHERE action.created_at < ? "
            "AND NOT EXISTS (SELECT 1 FROM detection_actions AS link "
            "WHERE link.action_id = action.id) LIMIT 1",
        )
        return any(
            self.connection.execute(statement, (cutoff,)).fetchone() is not None
            for statement in statements
        )

    @staticmethod
    def _retention_token(
        *,
        store_identity: str,
        cutoff: str,
        batch_limit: int,
        candidates: tuple[tuple[str, tuple[int, ...]], ...],
    ) -> str:
        payload = {
            "schema": RETENTION_RECEIPT_VERSION,
            "store_identity": store_identity,
            "cutoff": cutoff,
            "batch_limit": batch_limit,
            "candidates": {
                table: list(identifiers) for table, identifiers in candidates
            },
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return f"sha256:{hashlib.sha256(encoded).hexdigest()}"

    def _rollback_retention_write(self) -> None:
        try:
            self._connection_rollback()
        except BaseException as exc:
            self._write_poisoned = True
            raise RetentionError(RETENTION_RECONCILIATION_REQUIRED) from exc

    def _commit_retention_write(self) -> None:
        try:
            self._connection_commit()
        except BaseException as exc:
            self._write_poisoned = True
            try:
                self.connection.rollback()
            except sqlite3.Error:
                pass
            raise RetentionError(RETENTION_RECONCILIATION_REQUIRED) from exc

    def preview_purge(
        self,
        before: datetime,
        *,
        batch_limit: int = DEFAULT_RETENTION_BATCH_ROWS,
    ) -> dict[str, object]:
        """Describe one finite purge batch without changing audit evidence."""

        cutoff = self._retention_cutoff(before)
        safe_limit = self._retention_batch_limit(batch_limit)
        with self._lock:
            self._assert_write_trusted()
            self._assert_retention_ready()
            self.connection.execute("BEGIN")
            try:
                store_identity = self._retention_store_identity()
                if self.connection.execute(
                    "SELECT 1 FROM ingestion_runs "
                    "WHERE status IN ('running', 'reconciliation_required') LIMIT 1"
                ).fetchone() is not None:
                    raise RetentionError("RETENTION:ACTIVE_RUN")
                candidates = self._retention_candidates(cutoff, safe_limit)
                preview_token = self._retention_token(
                    store_identity=store_identity,
                    cutoff=cutoff,
                    batch_limit=safe_limit,
                    candidates=candidates,
                )
            except BaseException:
                self._rollback_retention_write()
                raise
            self._rollback_retention_write()

        counts = {
            table: len(identifiers) for table, identifiers in candidates
        }
        candidate_total = sum(counts.values())
        return {
            "receipt_version": RETENTION_RECEIPT_VERSION,
            "store_identity": store_identity,
            "cutoff": cutoff,
            "batch_limit": safe_limit,
            "candidate_counts": counts,
            "candidate_total": candidate_total,
            "batch_full": candidate_total == safe_limit,
            "preview_token": preview_token,
        }

    def purge_before(
        self,
        before: datetime,
        *,
        batch_limit: int = DEFAULT_RETENTION_BATCH_ROWS,
        preview_token: str | None = None,
    ) -> dict[str, object]:
        """Apply exactly one preview-bound, finite retention batch."""

        cutoff = self._retention_cutoff(before)
        safe_limit = self._retention_batch_limit(batch_limit)

        with self._lock:
            self._assert_write_trusted()
            if not self._valid_retention_token(preview_token):
                raise RetentionError("RETENTION:INVALID_PREVIEW_TOKEN")
            self._assert_retention_ready()
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                store_identity = self._retention_store_identity()
                if self.connection.execute(
                    "SELECT 1 FROM ingestion_runs "
                    "WHERE status IN ('running', 'reconciliation_required') LIMIT 1"
                ).fetchone() is not None:
                    raise RetentionError("RETENTION:ACTIVE_RUN")
                candidates = self._retention_candidates(cutoff, safe_limit)
                actual_token = self._retention_token(
                    store_identity=store_identity,
                    cutoff=cutoff,
                    batch_limit=safe_limit,
                    candidates=candidates,
                )
                if not hmac.compare_digest(preview_token, actual_token):
                    raise RetentionError("RETENTION:STALE_PREVIEW")

                deleted: dict[str, int] = {}
                for table, identifiers in candidates:
                    if not identifiers:
                        deleted[table] = 0
                        continue
                    placeholders = ",".join("?" for _ in identifiers)
                    cursor = self.connection.execute(
                        f"DELETE FROM {table} WHERE id IN ({placeholders})",
                        identifiers,
                    )
                    if cursor.rowcount != len(identifiers):
                        raise RetentionError("RETENTION:CANDIDATE_CHANGED")
                    deleted[table] = int(cursor.rowcount)
                self._assert_path_identity()
                complete = not self._retention_candidates_exist(cutoff)
            except BaseException:
                if self.connection.in_transaction:
                    self._rollback_retention_write()
                raise
            self._commit_retention_write()

        return {
            "receipt_version": RETENTION_RECEIPT_VERSION,
            "store_identity": store_identity,
            "cutoff": cutoff,
            "batch_limit": safe_limit,
            "preview_token": actual_token,
            "deleted": deleted,
            "deleted_total": sum(deleted.values()),
            "complete": complete,
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
        self.path = _absolute_database_path(path, "DASHBOARD_STORE")
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
                _TABLE_COLUMNS_V3,
                _INDEX_COLUMNS_V3,
                _FOREIGN_KEYS_V3,
                _UNIQUE_INDEXES_V3,
                (*SCHEMA_V1_STATEMENTS, *SCHEMA_V3_STATEMENTS),
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
