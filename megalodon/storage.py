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
    parse_nonnegative_int,
    SQLITE_INTEGER_MAX,
    validate_metadata,
    validate_packet_metadata,
)


SCHEMA_VERSION = 2
MIGRATION_BACKUP_SUFFIX = ".pre-v2.bak"

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


class StorageSchemaError(ValueError):
    """The selected database cannot safely satisfy this storage schema."""


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


def _path_matches_descriptor(path: Path, descriptor: int) -> bool:
    try:
        return os.path.samestat(
            path.stat(follow_symlinks=False), os.fstat(descriptor)
        )
    except OSError:
        return False


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
                if backup_created
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
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self.connection = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        try:
            with self._lock:
                self.connection.execute("PRAGMA foreign_keys=ON")
                self._initialize_schema()
                self.connection.execute("PRAGMA journal_mode=WAL")
        except Exception:
            self.connection.close()
            raise

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

    def record_event(self, event: PacketEvent) -> int:
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
            return int(cursor.lastrowid)

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
