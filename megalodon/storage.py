"""Small auditable SQLite store; no packet payloads are written."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from threading import RLock
from typing import Any

from .models import ActionRecord, DetectionResult, PacketEvent


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
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
);
CREATE INDEX IF NOT EXISTS idx_events_observed_at ON events(observed_at);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);

CREATE TABLE IF NOT EXISTS detections (
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
);
CREATE INDEX IF NOT EXISTS idx_detections_detected_at ON detections(detected_at);

CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires_at TEXT,
    details_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_created_at ON actions(created_at);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self.connection = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        with self._lock:
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA foreign_keys=ON")
            self.connection.executescript(SCHEMA)
            self.connection.commit()

    def close(self) -> None:
        with self._lock:
            self.connection.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def record_event(self, event: PacketEvent) -> int:
        with self._lock:
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
                    event.dns_query_length,
                    event.byte_count,
                    event.interface,
                    json.dumps(event.metadata, sort_keys=True),
                ),
            )
            self.connection.commit()
            return int(cursor.lastrowid)

    def record_detection(self, event_id: int, detection: DetectionResult) -> int:
        with self._lock:
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
                    json.dumps(detection.evidence, sort_keys=True),
                    detection.recommendation,
                    detection.suppressed_reason,
                ),
            )
            self.connection.commit()
            return int(cursor.lastrowid)

    def record_action(self, action: ActionRecord) -> int:
        with self._lock:
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
                    json.dumps(action.details, sort_keys=True),
                ),
            )
            self.connection.commit()
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
