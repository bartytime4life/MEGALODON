"""Small auditable SQLite store; no packet payloads are written."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import stat
from threading import RLock
from typing import Any

from .models import ActionRecord, DetectionResult, PacketEvent
from .validation import (
    parse_ip,
    parse_nonnegative_int,
    parse_timestamp,
    safe_text,
    SQLITE_INTEGER_MAX,
    ValidationError,
    validate_metadata,
    validate_packet_metadata,
)


SCHEMA_VERSION = 2
MIGRATION_BACKUP_SUFFIX = ".pre-v2.bak"
DASHBOARD_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")

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


class StorageSchemaError(ValueError):
    """The selected database cannot safely satisfy this storage schema."""


class IngestionRunError(ValueError):
    """An ingestion run transition or association is invalid."""


def _absolute_database_path(
    path: str | Path, *, code: str = "STORAGE_PATH:UNSAFE_DATABASE"
) -> Path:
    """Return one unambiguous absolute path without resolving symlinks."""

    raw = Path(path)
    if ".." in raw.parts:
        raise StorageSchemaError(code)
    return Path(os.path.abspath(os.fspath(raw)))


def _has_symlink_component(path: Path) -> bool:
    """Reject path traversal through a symlink before opening SQLite."""

    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
    return False


def _validate_private_directory(path: Path, *, code: str) -> None:
    try:
        details = path.lstat()
    except OSError as exc:
        raise StorageSchemaError(code) from exc
    if not stat.S_ISDIR(details.st_mode) or path.is_symlink():
        raise StorageSchemaError(code)
    if os.name == "posix" and (
        details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077
    ):
        raise StorageSchemaError(code)


def _validate_private_database_details(details: os.stat_result, *, code: str) -> None:
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise StorageSchemaError(code)
    if os.name == "posix" and (
        details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077
    ):
        raise StorageSchemaError(code)


def _prepare_writer_directory(parent: Path) -> int | None:
    """Create a POSIX path one no-follow component at a time."""

    if os.name != "posix":
        try:
            parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        except OSError as exc:
            raise StorageSchemaError("STORAGE_PATH:UNSAFE_DIRECTORY") from exc
        if _has_symlink_component(parent):
            raise StorageSchemaError("STORAGE_PATH:UNSAFE_DIRECTORY")
        _validate_private_directory(parent, code="STORAGE_PATH:UNSAFE_DIRECTORY")
        return None

    required = ("O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required):
        raise StorageSchemaError("STORAGE_PATH:UNSAFE_DIRECTORY")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(parent.anchor or os.sep, flags)
    except OSError as exc:
        raise StorageSchemaError("STORAGE_PATH:UNSAFE_DIRECTORY") from exc
    try:
        for part in parent.parts[1:]:
            created = False
            try:
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                    created = True
                except FileExistsError:
                    pass
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            if created:
                os.fchmod(descriptor, 0o700)
        details = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(details.st_mode)
            or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) & 0o077
            or not _path_matches_descriptor(parent, descriptor)
        ):
            raise StorageSchemaError("STORAGE_PATH:UNSAFE_DIRECTORY")
        return descriptor
    except Exception as exc:
        os.close(descriptor)
        if isinstance(exc, StorageSchemaError):
            raise
        raise StorageSchemaError("STORAGE_PATH:UNSAFE_DIRECTORY") from exc


def _prepare_writer_database(path: str | Path) -> tuple[Path, int, bool, int | None]:
    """Create or open a private writer database while retaining its identity."""

    database = _absolute_database_path(path, code="STORAGE_PATH:UNSAFE_DIRECTORY")
    parent_descriptor = _prepare_writer_directory(database.parent)
    target: str | Path = database
    stat_kwargs: dict[str, Any] = {"follow_symlinks": False}
    open_kwargs: dict[str, Any] = {}
    if parent_descriptor is not None:
        target = database.name
        stat_kwargs["dir_fd"] = parent_descriptor
        open_kwargs["dir_fd"] = parent_descriptor
    try:
        existing = os.stat(target, **stat_kwargs)
        created_database = False
    except FileNotFoundError:
        existing = None
        created_database = True
    except OSError as exc:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        raise StorageSchemaError("STORAGE_PATH:UNSAFE_DATABASE") from exc
    flags = os.O_RDWR
    mode: int | None = None
    if created_database:
        flags |= os.O_CREAT | os.O_EXCL
        mode = 0o600
    else:
        assert existing is not None
        if not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1:
            if parent_descriptor is not None:
                os.close(parent_descriptor)
            raise StorageSchemaError("STORAGE_PATH:UNSAFE_DATABASE")
        if os.name == "posix" and existing.st_uid != os.geteuid():
            if parent_descriptor is not None:
                os.close(parent_descriptor)
            raise StorageSchemaError("STORAGE_PATH:UNSAFE_DATABASE")
    try:
        descriptor = _open_regular_file(target, flags, mode, **open_kwargs)
    except (OSError, StorageSchemaError) as exc:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        raise StorageSchemaError("STORAGE_PATH:UNSAFE_DATABASE") from exc
    try:
        details = os.fstat(descriptor)
        if os.name == "posix" and details.st_uid != os.geteuid():
            raise StorageSchemaError("STORAGE_PATH:UNSAFE_DATABASE")
        if details.st_nlink != 1:
            raise StorageSchemaError("STORAGE_PATH:UNSAFE_DATABASE")
        if not _path_matches_descriptor(database, descriptor):
            raise StorageSchemaError("STORAGE_PATH:DATABASE_CHANGED")
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        return database, descriptor, created_database, parent_descriptor
    except Exception:
        os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        raise


def _open_dashboard_database(path: str | Path) -> tuple[Path, int]:
    """Open one existing private database without following path substitutions."""

    database = _absolute_database_path(
        path, code="STORAGE_DASHBOARD:UNSAFE_DIRECTORY"
    )
    if _has_symlink_component(database.parent):
        raise StorageSchemaError("STORAGE_DASHBOARD:UNSAFE_DIRECTORY")
    _validate_private_directory(
        database.parent, code="STORAGE_DASHBOARD:UNSAFE_DIRECTORY"
    )
    if not os.path.lexists(database):
        raise StorageSchemaError("STORAGE_DASHBOARD:NO_DATABASE")
    try:
        initial = database.lstat()
    except OSError as exc:
        raise StorageSchemaError("STORAGE_DASHBOARD:OPEN_FAILED") from exc
    _validate_private_database_details(
        initial, code="STORAGE_DASHBOARD:UNSAFE_DATABASE"
    )
    try:
        descriptor = _open_regular_file(database, os.O_RDONLY)
    except (OSError, StorageSchemaError) as exc:
        raise StorageSchemaError("STORAGE_DASHBOARD:UNSAFE_DATABASE") from exc
    try:
        _validate_private_database_details(
            os.fstat(descriptor), code="STORAGE_DASHBOARD:UNSAFE_DATABASE"
        )
        if not _path_matches_descriptor(database, descriptor):
            raise StorageSchemaError("STORAGE_DASHBOARD:DATABASE_CHANGED")
        return database, descriptor
    except Exception:
        os.close(descriptor)
        raise


def _close_descriptors(
    descriptors: dict[str, tuple[Path, int]],
) -> None:
    for _path, descriptor in descriptors.values():
        os.close(descriptor)


def _inspect_sqlite_sidecars(
    database: Path, *, code: str
) -> dict[str, tuple[Path, int]]:
    """Open and validate any SQLite coordination files without following links."""

    result: dict[str, tuple[Path, int]] = {}
    try:
        for suffix in DASHBOARD_SIDECAR_SUFFIXES:
            sidecar = Path(f"{database}{suffix}")
            if not os.path.lexists(sidecar):
                continue
            descriptor: int | None = None
            try:
                initial = sidecar.lstat()
                _validate_private_database_details(initial, code=code)
                descriptor = _open_regular_file(sidecar, os.O_RDONLY)
                _validate_private_database_details(os.fstat(descriptor), code=code)
                if not os.path.samestat(initial, os.fstat(descriptor)) or not (
                    _path_matches_descriptor(sidecar, descriptor)
                ):
                    os.close(descriptor)
                    descriptor = None
                    raise StorageSchemaError(code)
            except (OSError, StorageSchemaError) as exc:
                if descriptor is not None:
                    os.close(descriptor)
                raise StorageSchemaError(code) from exc
            assert descriptor is not None
            result[suffix] = (sidecar, descriptor)
        return result
    except Exception:
        _close_descriptors(result)
        raise


def _compare_sidecar_sets(
    before: dict[str, tuple[Path, int]],
    after: dict[str, tuple[Path, int]],
    *,
    code: str,
    allow_removed: frozenset[str] = frozenset(),
) -> None:
    """Retain sidecar identity, except an explicitly recovered unlinked journal."""

    try:
        for suffix, (_path, descriptor) in before.items():
            candidate = after.get(suffix)
            if candidate is None:
                removed = os.fstat(descriptor)
                if (
                    suffix in allow_removed
                    and stat.S_ISREG(removed.st_mode)
                    and removed.st_nlink == 0
                    and (
                        os.name != "posix"
                        or (
                            removed.st_uid == os.geteuid()
                            and not stat.S_IMODE(removed.st_mode) & 0o077
                        )
                    )
                ):
                    continue
                raise StorageSchemaError(code)
            _validate_private_database_details(os.fstat(descriptor), code=code)
            if not os.path.samestat(os.fstat(descriptor), os.fstat(candidate[1])):
                raise StorageSchemaError(code)
    except OSError as exc:
        raise StorageSchemaError(code) from exc


def _validate_dashboard_sidecar_state(
    sidecars: dict[str, tuple[Path, int]],
) -> None:
    """Require a complete WAL pair and leave rollback recovery to the writer."""

    has_wal = "-wal" in sidecars
    has_shm = "-shm" in sidecars
    if has_wal != has_shm or "-journal" in sidecars:
        raise StorageSchemaError("STORAGE_DASHBOARD:UNSAFE_SIDECAR_STATE")


def _descriptor_change_signature(descriptor: int) -> tuple[int, ...]:
    details = os.fstat(descriptor)
    return (
        details.st_dev,
        details.st_ino,
        details.st_nlink,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )


def _validate_dashboard_path_identity(database: Path, descriptor: int) -> None:
    if _has_symlink_component(database.parent):
        raise StorageSchemaError("STORAGE_DASHBOARD:UNSAFE_DIRECTORY")
    _validate_private_directory(
        database.parent, code="STORAGE_DASHBOARD:UNSAFE_DIRECTORY"
    )
    if not _path_matches_descriptor(database, descriptor):
        raise StorageSchemaError("STORAGE_DASHBOARD:DATABASE_CHANGED")
    try:
        current = database.lstat()
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise StorageSchemaError("STORAGE_DASHBOARD:DATABASE_CHANGED") from exc
    _validate_private_database_details(
        current, code="STORAGE_DASHBOARD:UNSAFE_DATABASE"
    )
    _validate_private_database_details(
        opened, code="STORAGE_DASHBOARD:UNSAFE_DATABASE"
    )


def _dashboard_connection_uri(
    descriptor: int, fallback: Path, *, immutable: bool = False
) -> str:
    source = Path(
        _descriptor_bound_database_path(
            descriptor,
            fallback,
            code="STORAGE_DASHBOARD:DESCRIPTOR_PATH_REQUIRED",
        )
    ).as_uri()
    suffix = "&immutable=1" if immutable else ""
    return f"{source}?mode=ro&cache=private{suffix}"


def _validate_connection_path(
    connection: sqlite3.Connection, database: Path, *, code: str
) -> None:
    rows = connection.execute("PRAGMA database_list").fetchall()
    main_paths = [str(row[2]) for row in rows if str(row[1]) == "main"]
    if len(main_paths) != 1 or _absolute_database_path(
        main_paths[0], code=code
    ) != database:
        raise StorageSchemaError(code)


def _validate_dashboard_schema(connection: sqlite3.Connection) -> None:
    """Validate version and structure inside one stable read transaction."""

    try:
        connection.execute("BEGIN")
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version != SCHEMA_VERSION:
            raise StorageSchemaError("STORAGE_DASHBOARD:INCOMPATIBLE")
        _validate_schema(
            connection,
            _TABLE_COLUMNS_V2,
            _INDEX_COLUMNS_V2,
            _FOREIGN_KEYS_V2,
            _UNIQUE_INDEXES_V2,
            (*SCHEMA_V1_STATEMENTS, *SCHEMA_V2_STATEMENTS),
        )
        connection.commit()
    except Exception as exc:
        if connection.in_transaction:
            connection.rollback()
        if isinstance(exc, StorageSchemaError) and str(exc) == (
            "STORAGE_DASHBOARD:INCOMPATIBLE"
        ):
            raise
        raise StorageSchemaError("STORAGE_DASHBOARD:INCOMPATIBLE") from exc
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


def _descriptor_bound_database_path(
    descriptor: int, fallback: Path, *, code: str
) -> str:
    path = _descriptor_database_path(descriptor, fallback)
    if os.name == "posix" and path == str(fallback):
        raise StorageSchemaError(code)
    return path


def _path_matches_descriptor(path: Path, descriptor: int) -> bool:
    try:
        return os.path.samestat(
            path.stat(follow_symlinks=False), os.fstat(descriptor)
        )
    except OSError:
        return False


def _open_regular_file(
    path: str | Path,
    flags: int,
    mode: int | None = None,
    *,
    dir_fd: int | None = None,
) -> int:
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = (
        os.open(path, flags, mode, dir_fd=dir_fd)
        if mode is not None
        else os.open(path, flags, dir_fd=dir_fd)
    )
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise StorageSchemaError("STORAGE_MIGRATION:SYMLINK_REFUSED")
    return descriptor


def _validate_migration_directory(path: Path) -> None:
    if os.name != "posix":
        return
    parent = path.parent
    try:
        parent_stat = parent.lstat()
    except OSError as exc:
        raise StorageSchemaError("STORAGE_MIGRATION:UNSAFE_DIRECTORY") from exc
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.geteuid()
        or parent_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise StorageSchemaError("STORAGE_MIGRATION:UNSAFE_DIRECTORY")


def migrate_database(path: str | Path) -> dict[str, object]:
    """Explicitly migrate an exact v1 database after a verified local backup."""

    source_path = Path(path)
    if source_path.is_symlink():
        raise StorageSchemaError("STORAGE_MIGRATION:SYMLINK_REFUSED")
    if not source_path.is_file():
        raise StorageSchemaError("STORAGE_MIGRATION:NO_DATABASE")
    _validate_migration_directory(source_path)

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


def _dashboard_detection_row(row: sqlite3.Row) -> dict[str, str]:
    """Revalidate the bounded public projection from a potentially altered DB."""

    try:
        detected_at = safe_text(row["detected_at"], "detected_at", 64)
        if detected_at != parse_timestamp(detected_at).isoformat():
            raise ValidationError("detected_at is not canonical")
        rule_id = safe_text(row["rule_id"], "rule_id", 64)
        if not rule_id or rule_id != rule_id.strip():
            raise ValidationError("rule_id is not canonical")
        severity = safe_text(row["severity"], "severity", 16)
        if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValidationError("severity is not canonical")
        src_ip = safe_text(row["src_ip"], "src_ip", 45)
        if src_ip != parse_ip(src_ip):
            raise ValidationError("src_ip is not canonical")
        message = safe_text(row["message"], "message", 512)
        if not message or message != message.strip():
            raise ValidationError("message is not canonical")
    except (KeyError, TypeError, ValidationError) as exc:
        raise StorageSchemaError("STORAGE_DASHBOARD:INVALID_DATA") from exc
    return {
        "detected_at": detected_at,
        "rule_id": rule_id,
        "severity": severity,
        "src_ip": src_ip,
        "message": message,
    }


class Store:
    def __init__(self, path: str | Path):
        (
            self.path,
            descriptor,
            created_database,
            parent_descriptor,
        ) = _prepare_writer_database(path)
        self._lock = RLock()
        before_sidecars: dict[str, tuple[Path, int]] = {}
        after_sidecars: dict[str, tuple[Path, int]] = {}
        try:
            before_sidecars = _inspect_sqlite_sidecars(
                self.path, code="STORAGE_PATH:UNSAFE_SIDECAR"
            )
            self.connection = sqlite3.connect(
                _descriptor_bound_database_path(
                    descriptor,
                    self.path,
                    code="STORAGE_PATH:DESCRIPTOR_PATH_REQUIRED",
                ),
                timeout=10,
                check_same_thread=False,
            )
            _validate_connection_path(
                self.connection,
                self.path,
                code="STORAGE_PATH:DATABASE_CHANGED",
            )
            if not _path_matches_descriptor(self.path, descriptor):
                self.connection.close()
                raise StorageSchemaError("STORAGE_PATH:DATABASE_CHANGED")
            self.connection.row_factory = sqlite3.Row
            with self._lock:
                self.connection.execute("PRAGMA foreign_keys=ON")
                self._initialize_schema()
                self.connection.execute("PRAGMA journal_mode=WAL")
            after_sidecars = _inspect_sqlite_sidecars(
                self.path, code="STORAGE_PATH:UNSAFE_SIDECAR"
            )
            _compare_sidecar_sets(
                before_sidecars,
                after_sidecars,
                code="STORAGE_PATH:SIDECAR_CHANGED",
                allow_removed=frozenset({"-journal"}),
            )
        except Exception:
            connection = getattr(self, "connection", None)
            if connection is not None:
                connection.close()
            if created_database and _path_matches_descriptor(self.path, descriptor):
                try:
                    self.path.unlink()
                except OSError:
                    pass
            raise
        finally:
            _close_descriptors(after_sidecars)
            _close_descriptors(before_sidecars)
            os.close(descriptor)
            if parent_descriptor is not None:
                os.close(parent_descriptor)

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
            self.connection.close()

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
    """Read-only, existing-database projection for the loopback dashboard."""

    def __init__(self, path: str | Path):
        self.path, self._descriptor = _open_dashboard_database(path)
        self._lock = RLock()
        self._closed = False
        self._sidecar_descriptors: dict[str, tuple[Path, int]] = {}
        before_sidecars: dict[str, tuple[Path, int]] = {}
        after_sidecars: dict[str, tuple[Path, int]] = {}
        preflight: sqlite3.Connection | None = None
        try:
            before_sidecars = _inspect_sqlite_sidecars(
                self.path, code="STORAGE_DASHBOARD:UNSAFE_SIDECAR"
            )
            _validate_dashboard_sidecar_state(before_sidecars)
            if not before_sidecars:
                preflight_signature = _descriptor_change_signature(self._descriptor)
                preflight = sqlite3.connect(
                    _dashboard_connection_uri(
                        self._descriptor, self.path, immutable=True
                    ),
                    uri=True,
                    timeout=10,
                    check_same_thread=False,
                )
                preflight.row_factory = sqlite3.Row
                _validate_connection_path(
                    preflight,
                    self.path,
                    code="STORAGE_DASHBOARD:DATABASE_CHANGED",
                )
                preflight.execute("PRAGMA query_only=ON")
                if int(preflight.execute("PRAGMA query_only").fetchone()[0]) != 1:
                    raise StorageSchemaError("STORAGE_DASHBOARD:READ_ONLY_REQUIRED")
                _validate_dashboard_schema(preflight)
                if _descriptor_change_signature(self._descriptor) != (
                    preflight_signature
                ):
                    raise StorageSchemaError("STORAGE_DASHBOARD:DATABASE_CHANGED")
                preflight.close()
                preflight = None
            _validate_dashboard_path_identity(self.path, self._descriptor)

            self.connection = sqlite3.connect(
                _dashboard_connection_uri(self._descriptor, self.path),
                uri=True,
                timeout=10,
                check_same_thread=False,
            )
            self.connection.row_factory = sqlite3.Row
            _validate_connection_path(
                self.connection,
                self.path,
                code="STORAGE_DASHBOARD:DATABASE_CHANGED",
            )
            self.connection.execute("PRAGMA query_only=ON")
            if int(self.connection.execute("PRAGMA query_only").fetchone()[0]) != 1:
                raise StorageSchemaError("STORAGE_DASHBOARD:READ_ONLY_REQUIRED")
            _validate_dashboard_schema(self.connection)
            after_sidecars = _inspect_sqlite_sidecars(
                self.path, code="STORAGE_DASHBOARD:UNSAFE_SIDECAR"
            )
            _validate_dashboard_sidecar_state(after_sidecars)
            _compare_sidecar_sets(
                before_sidecars,
                after_sidecars,
                code="STORAGE_DASHBOARD:SIDECAR_CHANGED",
            )
            self._sidecar_descriptors = after_sidecars
            after_sidecars = {}
            self._assert_identity()
        except StorageSchemaError:
            if preflight is not None:
                preflight.close()
            connection = getattr(self, "connection", None)
            if connection is not None:
                connection.close()
            _close_descriptors(after_sidecars)
            _close_descriptors(self._sidecar_descriptors)
            os.close(self._descriptor)
            raise
        except (OSError, sqlite3.Error) as exc:
            if preflight is not None:
                preflight.close()
            connection = getattr(self, "connection", None)
            if connection is not None:
                connection.close()
            _close_descriptors(after_sidecars)
            _close_descriptors(self._sidecar_descriptors)
            os.close(self._descriptor)
            raise StorageSchemaError("STORAGE_DASHBOARD:OPEN_FAILED") from exc
        finally:
            _close_descriptors(before_sidecars)

    def _assert_identity(self) -> None:
        if self._closed:
            raise StorageSchemaError("STORAGE_DASHBOARD:CLOSED")
        _validate_dashboard_path_identity(self.path, self._descriptor)
        current = _inspect_sqlite_sidecars(
            self.path, code="STORAGE_DASHBOARD:UNSAFE_SIDECAR"
        )
        try:
            _validate_dashboard_sidecar_state(current)
            _compare_sidecar_sets(
                self._sidecar_descriptors,
                current,
                code="STORAGE_DASHBOARD:SIDECAR_CHANGED",
            )
            for suffix, value in current.items():
                if suffix in self._sidecar_descriptors:
                    os.close(value[1])
                else:
                    self._sidecar_descriptors[suffix] = value
            current = {}
        finally:
            _close_descriptors(current)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self.connection.close()
            finally:
                try:
                    _close_descriptors(self._sidecar_descriptors)
                finally:
                    self._sidecar_descriptors = {}
                    os.close(self._descriptor)

    def __enter__(self) -> "DashboardStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def summary(self) -> dict[str, Any]:
        """Return one summary from a single stable SQLite read snapshot."""

        with self._lock:
            self._assert_identity()
            self.connection.execute("BEGIN")
            try:
                event_count = self.connection.execute(
                    "SELECT COUNT(*) FROM events"
                ).fetchone()[0]
                detection_count = self.connection.execute(
                    "SELECT COUNT(*) FROM detections"
                ).fetchone()[0]
                action_count = self.connection.execute(
                    "SELECT COUNT(*) FROM actions"
                ).fetchone()[0]
                active_threats = self.connection.execute(
                    "SELECT COUNT(*) FROM detections "
                    "WHERE severity IN ('HIGH', 'CRITICAL')"
                ).fetchone()[0]
                result = {
                    "events": int(event_count),
                    "detections": int(detection_count),
                    "actions": int(action_count),
                    "high_or_critical": int(active_threats),
                }
                self._assert_identity()
                self.connection.commit()
                return result
            except Exception:
                self.connection.rollback()
                raise

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        """Select only the five fields admitted to the dashboard contract."""

        safe_limit = max(1, min(int(limit), 200))
        with self._lock:
            self._assert_identity()
            self.connection.execute("BEGIN")
            try:
                invalid = self.connection.execute(
                    """
                    SELECT 1 FROM (
                        SELECT detected_at, rule_id, severity, src_ip, message
                        FROM detections ORDER BY id DESC LIMIT ?
                    )
                    WHERE typeof(detected_at) != 'text'
                       OR length(detected_at) > 64
                       OR typeof(rule_id) != 'text' OR length(rule_id) > 64
                       OR typeof(severity) != 'text' OR length(severity) > 16
                       OR typeof(src_ip) != 'text' OR length(src_ip) > 45
                       OR typeof(message) != 'text' OR length(message) > 512
                    LIMIT 1
                    """,
                    (safe_limit,),
                ).fetchone()
                if invalid is not None:
                    raise StorageSchemaError("STORAGE_DASHBOARD:INVALID_DATA")
                rows = self.connection.execute(
                    """
                    SELECT detected_at, rule_id, severity, src_ip, message
                    FROM detections
                    ORDER BY id DESC LIMIT ?
                    """,
                    (safe_limit,),
                ).fetchall()
                result = [_dashboard_detection_row(row) for row in rows]
                self._assert_identity()
                self.connection.commit()
                return result
            except Exception:
                self.connection.rollback()
                raise
