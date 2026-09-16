"""Bounded read-only projection of explicitly selected Suricata evidence.

This is stored external signature-alert metadata, not a live sensor status,
MEGALODON detector result, commit reconciliation, or response authorization.
"""

from __future__ import annotations

from collections import deque
import json
import math
from pathlib import Path
import sqlite3
import time
from typing import Any

from .offline import suricata, suricata_consumer as consumer
from .offline.common import OfflineError
from .suricata_store import SuricataStoreError, _open_suricata_store_reader


MAX_RECENT_RUNS = 5
MAX_RECENT_ALERTS = 50
MAX_QUERY_SECONDS = 5
MAX_RESPONSE_BYTES = 65_536
_MAX_RECORD_BYTES = 4_096
_MAX_SAFE_INTEGER = (1 << 53) - 1
_READ_COLUMNS = {
    "consumer_runs": frozenset({"id", "consumer_attempt_id", *consumer._RUN_KEYS}),
    "consumer_alerts": frozenset({"run_row_id", "source_record_index", "record_json"}),
    "consumer_receipts": frozenset({"run_row_id", "consumer_attempt_id", "receipt_json"}),
}


class _ProjectionRefusal(ValueError):
    pass


def _envelope(status: str, failure_code: str | None = None) -> dict[str, Any]:
    return {
        "schema_version": "suricata-evidence-projection-v1",
        "status": status,
        "failure_code": failure_code,
        "provenance": "external_suricata_signature_alerts",
        "action_status": "not_attempted",
        "limits": {
            "max_recent_runs": MAX_RECENT_RUNS,
            "max_recent_alerts": MAX_RECENT_ALERTS,
            "max_query_ms": MAX_QUERY_SECONDS * 1_000,
            "max_response_bytes": MAX_RESPONSE_BYTES,
        },
        "summary": None,
        "recent_runs": [],
        "recent_alerts": [],
    }


def _remaining_ms(started: float) -> int:
    remaining = MAX_QUERY_SECONDS - (time.monotonic() - started)
    if not math.isfinite(remaining) or remaining <= 0:
        raise _ProjectionRefusal("QUERY_TIMEOUT")
    return max(1, math.ceil(remaining * 1_000))


def _progress(started: float) -> int:
    try:
        _remaining_ms(started)
        return 0
    except _ProjectionRefusal:
        return 1


def _authorize(action, argument1, argument2, database, _source) -> int:
    """Deny every SQL operation outside this projection's fixed queries."""
    if action == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ and (
        database == "main" or (database is None and argument2 == "")
    ):
        # SQLite's COUNT(*) authorization names the table but supplies an empty
        # column and no database. ATTACH and all other schemas remain denied.
        if argument1 in _READ_COLUMNS and (
            argument2 in _READ_COLUMNS[argument1] or argument2 == ""
        ):
            return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION and argument2 in {"count", "substr"}:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_TRANSACTION and argument1 in {"BEGIN", "ROLLBACK"}:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _integer(value: Any, *, positive: bool = False) -> int:
    if type(value) is not int or not int(positive) <= value <= _MAX_SAFE_INTEGER:
        raise _ProjectionRefusal("INVALID_EVIDENCE")
    return value


def _text(value: Any, maximum: int) -> str:
    # SQL returns a bounded BLOB slice, so a corrupt oversized cell cannot
    # allocate its entire text in Python before the length check.
    if type(value) is not bytes or not 1 <= len(value) <= maximum:
        raise _ProjectionRefusal("INVALID_EVIDENCE")
    return value.decode("utf-8", errors="strict")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _ProjectionRefusal("INVALID_EVIDENCE")
        result[key] = value
    return result


def _reject_constant(_value):
    raise _ProjectionRefusal("INVALID_EVIDENCE")


def _object(value: Any) -> tuple[dict, str]:
    raw = _text(value, _MAX_RECORD_BYTES)
    parsed = json.loads(
        raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant,
    )
    if type(parsed) is not dict:
        raise _ProjectionRefusal("INVALID_EVIDENCE")
    # Durable consumer rows are exactly canonical, not arbitrary JSON documents.
    if json.dumps(parsed, sort_keys=True, separators=(",", ":")) != raw:
        raise _ProjectionRefusal("INVALID_EVIDENCE")
    return parsed, raw


def _read_run(connection, row, started):
    row_id = _integer(row[0], positive=True)
    identity = {
        key: _text(value, 64)
        for key, value in zip(consumer._RUN_KEYS, row[1:9], strict=True)
    }
    consumer._validate_identity(identity)
    attempt = consumer._validate_attempt_id(_text(row[9], 64))
    receipts = connection.execute(
        """SELECT substr(CAST(consumer_attempt_id AS BLOB), 1, 65),
                  substr(CAST(receipt_json AS BLOB), 1, 4097)
           FROM consumer_receipts WHERE run_row_id=?""", (row_id,),
    ).fetchall()
    if len(receipts) != 1 or _text(receipts[0][0], 64) != attempt:
        raise _ProjectionRefusal("INVALID_EVIDENCE")
    _object(receipts[0][1])
    recent = deque(maxlen=MAX_RECENT_ALERTS)
    count = blocked = normalized_bytes = 0
    cursor = connection.execute(
        """SELECT source_record_index,
                  substr(CAST(record_json AS BLOB), 1, 4097)
           FROM consumer_alerts WHERE run_row_id=?
           ORDER BY source_record_index LIMIT 10001""", (row_id,),
    )
    for count, (record_index, encoded) in enumerate(cursor, start=1):
        _remaining_ms(started)
        if count > consumer.MAX_RECORDS or _integer(record_index, positive=True) != count:
            raise _ProjectionRefusal("INVALID_EVIDENCE")
        alert, raw = _object(encoded)
        consumer._validate_alert(alert, identity, count)
        normalized_bytes += len(raw.encode("utf-8"))
        if normalized_bytes > consumer.MAX_NORMALIZED_BATCH_BYTES:
            raise _ProjectionRefusal("INVALID_EVIDENCE")
        blocked += alert["producer_reported_action"] == "blocked"
        recent.append({
            "run_row_id": row_id,
            "run_id": identity["run_id"],
            "sensor_id": identity["sensor_id"],
            **{key: alert[key] for key in (
                "source_record_index", "observed_at", "src_ip", "src_port",
                "dst_ip", "dst_port", "protocol", "rule",
                "producer_reported_action", "action_status", "evidence_kind",
            )},
        })
    if count == 0:
        raise _ProjectionRefusal("INVALID_EVIDENCE")
    # Recompute the complete selected run, including omitted alert rows, before
    # trusting its durable receipt. Reuse the consumer's versioned receipt shape.
    facts = consumer._PublicationFacts(
        publication=((), {}), identity=identity, record_count=count,
        blocked_count=blocked, normalized_bytes=normalized_bytes, record_json=(),
    )
    expected = json.dumps(
        consumer._plain(consumer._receipt(facts, attempt, "committed")),
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    if receipts[0][1] != expected:
        raise _ProjectionRefusal("INVALID_EVIDENCE")
    run = {
        "run_row_id": row_id,
        **{key: identity[key] for key in (
            "run_id", "sensor_id", "ruleset_id", "declared_version",
            "version_basis", "ruleset_basis",
        )},
        "consumer_attempt_id": attempt,
        "alert_count": count,
        "producer_reported_blocked_count": blocked,
    }
    return run, list(reversed(recent))


def read_suricata_projection(database_path: str | Path | None) -> dict[str, Any]:
    """Return one bounded snapshot, or fixed path-free unavailable evidence.

    ``None`` is explicitly unconfigured. A selected missing/incompatible store
    is refused; this function never creates, migrates, repairs, or writes it.
    The deadline is cooperative: late filesystem calls cannot become success.
    """
    if database_path is None:
        return _envelope("not_configured")
    try:
        suricata.require_unprivileged_linux()
    except OfflineError:
        return _envelope("unavailable", "UNSUPPORTED_RUNTIME")
    started = time.monotonic()
    try:
        _remaining_ms(started)
        with _open_suricata_store_reader(
            database_path,
            progress_handler=lambda: _progress(started),
            remaining_milliseconds=lambda: _remaining_ms(started),
            require_sidecar_free=True,
        ) as reader:
            connection = reader.connection
            connection.set_authorizer(_authorize)
            connection.execute("BEGIN")
            counts = [
                _integer(connection.execute(statement).fetchone()[0])
                for statement in (
                    "SELECT count(*) FROM consumer_runs",
                    "SELECT count(*) FROM consumer_alerts",
                    "SELECT count(*) FROM consumer_receipts",
                )
            ]
            if counts[0] != counts[2] or (counts[0] == 0 and counts[1] != 0):
                raise _ProjectionRefusal("INVALID_EVIDENCE")
            # Every selected field is bounded before leaving SQLite, including
            # operator-declared run labels from a manually altered database.
            fields = ", ".join(
                f"substr(CAST({key} AS BLOB), 1, 65)"
                for key in (*consumer._RUN_KEYS, "consumer_attempt_id")
            )
            rows = connection.execute(
                f"SELECT id, {fields} FROM consumer_runs ORDER BY id DESC LIMIT 5"
            ).fetchall()
            result = _envelope("available")
            validated = 0
            for row in rows:
                _remaining_ms(started)
                run, alerts = _read_run(connection, row, started)
                result["recent_runs"].append(run)
                validated += run["alert_count"]
                available = MAX_RECENT_ALERTS - len(result["recent_alerts"])
                result["recent_alerts"].extend(alerts[:available])
            result["summary"] = {
                "stored_runs": counts[0],
                "stored_alerts": counts[1],
                "validated_recent_runs": len(rows),
                "validated_recent_alerts": validated,
                "shown_alerts": len(result["recent_alerts"]),
            }
            if len(json.dumps(result, separators=(",", ":")).encode("utf-8")) > MAX_RESPONSE_BYTES:
                raise _ProjectionRefusal("RESPONSE_LIMIT")
            reader.verify_identity()
            _remaining_ms(started)
            connection.execute("ROLLBACK")
            reader.verify_identity()
            _remaining_ms(started)
        _remaining_ms(started)
        return result
    except _ProjectionRefusal as exc:
        return _envelope("unavailable", str(exc))
    except SuricataStoreError:
        code = "STORE_UNAVAILABLE"
    except (sqlite3.Error, OSError, TypeError, ValueError, OverflowError, RecursionError):
        code = "INVALID_EVIDENCE"
    # A store-open failure from an interrupted SQLite VM must retain the shared
    # deadline's meaning rather than suggesting malformed durable evidence.
    try:
        _remaining_ms(started)
    except _ProjectionRefusal:
        code = "QUERY_TIMEOUT"
    return _envelope("unavailable", code)


__all__ = [
    "MAX_QUERY_SECONDS", "MAX_RECENT_ALERTS", "MAX_RECENT_RUNS",
    "MAX_RESPONSE_BYTES", "read_suricata_projection",
]
