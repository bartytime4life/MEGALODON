"""Small auditable SQLite store; no packet payloads are written."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from threading import RLock
from typing import Any

from .models import ActionRecord, DetectionResult, PacketEvent
from .validation import (
    parse_nonnegative_int,
    SQLITE_INTEGER_MAX,
    validate_metadata,
    validate_packet_metadata,
)


SCHEMA_VERSION = 1

SCHEMA_STATEMENTS = (
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

_TABLE_COLUMNS = {
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

_INDEX_COLUMNS = {
    "idx_events_observed_at": ("events", ("observed_at",)),
    "idx_events_src_ip": ("events", ("src_ip",)),
    "idx_detections_detected_at": ("detections", ("detected_at",)),
    "idx_actions_created_at": ("actions", ("created_at",)),
}


class StorageSchemaError(ValueError):
    """The selected database cannot safely satisfy this storage schema."""


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
            if version not in (0, SCHEMA_VERSION):
                raise StorageSchemaError("STORAGE_SCHEMA:UNSUPPORTED_VERSION")

            present = {
                str(row[0])
                for row in self.connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type = 'table'"
                )
                if row[0] in _TABLE_COLUMNS
            }
            expected = set(_TABLE_COLUMNS)
            if version == 0 and not present:
                self._create_schema()
                return
            if present != expected:
                raise StorageSchemaError("STORAGE_SCHEMA:INCOMPATIBLE")

            self.connection.execute("BEGIN IMMEDIATE")
            try:
                self._validate_schema()
                if version == 0:
                    self.connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
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
            for statement in SCHEMA_STATEMENTS:
                self.connection.execute(statement)
            self._validate_schema()
            self.connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self.connection.commit()
        except Exception as exc:
            self.connection.rollback()
            if isinstance(exc, StorageSchemaError):
                raise
            raise StorageSchemaError("STORAGE_SCHEMA:MIGRATION_FAILED") from exc

    def _validate_schema(self) -> None:
        for table, expected in _TABLE_COLUMNS.items():
            actual = tuple(
                (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5]))
                for row in self.connection.execute(f'PRAGMA table_info("{table}")')
            )
            if actual != expected:
                raise StorageSchemaError("STORAGE_SCHEMA:INCOMPATIBLE")

        foreign_keys = tuple(
            (str(row[2]), str(row[3]), str(row[4]))
            for row in self.connection.execute('PRAGMA foreign_key_list("detections")')
        )
        if foreign_keys != (("events", "event_id", "id"),):
            raise StorageSchemaError("STORAGE_SCHEMA:INCOMPATIBLE")

        for index, (table, expected_columns) in _INDEX_COLUMNS.items():
            indexes = {
                str(row[1]): (int(row[2]), str(row[3]))
                for row in self.connection.execute(f'PRAGMA index_list("{table}")')
            }
            if indexes.get(index) != (0, "c"):
                raise StorageSchemaError("STORAGE_SCHEMA:INCOMPATIBLE")
            columns = tuple(
                str(row[2])
                for row in self.connection.execute(f'PRAGMA index_info("{index}")')
            )
            if columns != expected_columns:
                raise StorageSchemaError("STORAGE_SCHEMA:INCOMPATIBLE")

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
