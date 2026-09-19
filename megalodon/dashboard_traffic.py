"""Closed, bounded metadata projection for the local control room.

This reader deliberately does not expose raw JSON, messages, interfaces, paths,
or model output. Stored JSONL provenance is an operator declaration, not proof
of capture authenticity. Sample and unlinked records never become traffic.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import re
from pathlib import Path
import sqlite3

from . import __version__
from .storage import DashboardStore, StorageSchemaError
from .validation import parse_timestamp, parse_flags, parse_ip

MAX_EVENTS = 500
MAX_FINDINGS = 200
MAX_BYTES = 256 * 1024
MAX_SAFE_INTEGER = 2**53 - 1
SCHEMA = "dashboard-traffic-v1"
DETECTORS = ("SYN_FLOOD", "PORT_SCAN", "DNS_TUNNELING")
PROTOCOLS = ("TCP", "UDP", "ICMP", "ICMPV6", "DNS", "HTTP", "TLS", "OTHER")
LIMITATIONS = (
    "Newest 500 stored event candidates and 200 finding candidates only; not complete history.",
    "Sample, unlinked and reconciliation-required records are excluded.",
    "JSONL metadata and source receipts are operator supplied; capture authenticity is unverified.",
    "Vantage, local network scope, sensor liveness, drops, rejected records and clock uncertainty are unknown.",
    "Bytes are reported metadata counts, not measured link throughput; flags are not connection state.",
    "Ports and protocol labels do not establish observed application services.",
    "Findings support review, not proof of malware, attribution or authority to act.",
)


def _text(column: str, limit: int) -> str:
    # Called only with source-owned literals below. Bound bytes before decoding
    # a stored TEXT value, including deliberately damaged databases.
    return (f"CASE WHEN typeof({column})='text' AND "
            f"length(CAST({column} AS BLOB)) BETWEEN 1 AND {limit} "
            f"THEN {column} ELSE NULL END")


EVENT_COLUMNS = ("id", "observed_at", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "tcp_flags", "byte_count")
FINDING_COLUMNS = ("id", "event_id", "detected_at", "rule_id", "severity")
# One statement gives events, findings and their run receipts one SQLite snapshot.
QUERY = f"""
WITH newest_events AS (
 SELECT {', '.join(EVENT_COLUMNS)} FROM events ORDER BY id DESC LIMIT 501
), newest_findings AS (
 SELECT {', '.join(FINDING_COLUMNS)} FROM detections ORDER BY id DESC LIMIT 201
)
SELECT 'event' AS kind, e.id AS record_id, e.id AS event_id,
 {_text('e.observed_at', 40)} AS timestamp,
 {_text('e.src_ip', 45)} AS src_ip, {_text('e.dst_ip', 45)} AS dst_ip,
 {_text('e.protocol', 32)} AS protocol, e.src_port, e.dst_port,
 CASE WHEN typeof(e.tcp_flags)='text' AND length(CAST(e.tcp_flags AS BLOB))<=63
 THEN e.tcp_flags ELSE NULL END AS tcp_flags,
 e.byte_count, NULL AS rule_id, NULL AS severity,
 r.id AS run_id, {_text('r.source', 12)} AS source,
 {_text('r.status', 24)} AS run_status, r.receipt_version,
 {_text('r.termination_reason', 28)} AS termination_reason
FROM newest_events e LEFT JOIN ingestion_run_events l ON l.event_id=e.id
LEFT JOIN ingestion_runs r ON r.id=l.run_id
UNION ALL
SELECT 'finding', d.id, d.event_id, {_text('d.detected_at', 40)},
 NULL, NULL, NULL, NULL, NULL, NULL, NULL,
 {_text('d.rule_id', 32)}, {_text('d.severity', 8)},
 r.id, {_text('r.source', 12)}, {_text('r.status', 24)},
 r.receipt_version, {_text('r.termination_reason', 28)}
FROM newest_findings d LEFT JOIN ingestion_run_events l ON l.event_id=d.event_id
LEFT JOIN ingestion_runs r ON r.id=l.run_id
ORDER BY record_id DESC
"""

# The writer stores UTC ISO timestamps (including an offset and optional
# microseconds). Bind that same representation so the existing time index works.
# Each page is ordered by immutable record ID, independent of capture clocks.
HISTORY_QUERY = QUERY.replace(
    "FROM events ORDER BY id DESC LIMIT 501",
    "FROM events WHERE observed_at >= :start AND observed_at <= :end "
    "AND id < :before ORDER BY id DESC LIMIT 501",
).replace(
    "FROM detections ORDER BY id DESC LIMIT 201",
    "FROM detections WHERE detected_at >= :start AND detected_at <= :end "
    "AND event_id IN (SELECT id FROM newest_events ORDER BY id DESC LIMIT 500) "
    "ORDER BY id DESC LIMIT 201",
)


def history_parameters(start: str, end: str, before: str | None = None) -> dict:
    """Closed UTC range and keyset cursor; never a path or SQL expression."""
    for value in (start, end):
        if not isinstance(value, str) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", value
        ):
            raise ValueError("invalid UTC range")
    first, last = parse_timestamp(start), parse_timestamp(end)
    if first > last or last - first > timedelta(days=31) or last > datetime.now(timezone.utc) + timedelta(minutes=1):
        raise ValueError("invalid UTC range")
    if before is not None and (not isinstance(before, str) or not re.fullmatch(r"[1-9][0-9]{0,15}", before)
                               or int(before) > MAX_SAFE_INTEGER):
        raise ValueError("invalid history cursor")
    return {"start": first.isoformat(), "end": last.isoformat(),
            "before": int(before) if before is not None else MAX_SAFE_INTEGER + 1}


def _integer(value: object, *, minimum: int = 0, maximum: int = MAX_SAFE_INTEGER) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("invalid integer")
    return value


def _time(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 40:
        raise ValueError("invalid time")
    return parse_timestamp(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def unavailable() -> dict:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "schema": SCHEMA,
        "status": "unavailable",
        "reason": "No qualified data available. Import authorized metadata, then restart the HUD.",
        "generated_at": now,
        "unit": "metadata events; reported bytes",
        "vantage": "unknown; no qualified store projection",
        "quality": "unknown",
        "window": {"start": None, "end": None},
        "limits": {"events": MAX_EVENTS, "findings": MAX_FINDINGS, "bytes": MAX_BYTES},
        "truncated": False,
        "excluded_event_candidates": 0,
        "events": [],
        "findings": [],
        "limitations": list(LIMITATIONS),
        "build": {
            "package_version": __version__,
            "base_commit": "4971d85a2c56d932fda9053873a42985b4233371",
            "projection_sha256": PROJECTION_SHA256,
            "commit": "unknown; source component digest identifies this projection",
        },
    }


class TrafficDashboardStore(DashboardStore):
    """The new HUD projection adds only named metadata columns to the base reader."""

    _AUTHORIZED_READS = {
        **DashboardStore._AUTHORIZED_READS,
        "events": frozenset({"", *EVENT_COLUMNS}),
        "detections": frozenset({"", *DashboardStore.EVENT_FIELDS, *FINDING_COLUMNS}),
        "ingestion_run_events": frozenset({"run_id", "event_id"}),
    }

    @classmethod
    def _authorize(cls, action, first, second, database, source):
        if action == sqlite3.SQLITE_FUNCTION and second in {"length", "typeof"}:
            return sqlite3.SQLITE_OK
        return super()._authorize(action, first, second, database, source)

    def traffic(self) -> dict:
        return self._read_traffic(QUERY, {})

    def traffic_history(self, start: str, end: str, before: str | None = None) -> dict:
        parameters = history_parameters(start, end, before)
        return self._read_traffic(HISTORY_QUERY, parameters, history=True)

    def _read_traffic(self, query: str, parameters: dict, *, history: bool = False) -> dict:
        with self._bounded_read():
            cursor = self._connection.execute(query, parameters)
            try:
                rows = cursor.fetchmany(MAX_EVENTS + MAX_FINDINGS + 3)
                if len(rows) > MAX_EVENTS + MAX_FINDINGS + 2:
                    raise StorageSchemaError("DASHBOARD_STORE:READ_FAILED")
                result = self._project(rows)
                if not history:
                    return result
                candidates = [row for row in rows if row["kind"] == "event"]
                # Advance even when this entire page contains excluded samples.
                next_before = str(_integer(candidates[MAX_EVENTS - 1]["record_id"], minimum=1)) if len(candidates) > MAX_EVENTS else None
                result["limitations"][0] = "One page of up to 500 stored event candidates in the requested UTC range; linked finding candidates capped at 200."
                page = {"schema": "dashboard-traffic-history-v1", "traffic": result,
                        "range": {"start": _time(parameters["start"]), "end": _time(parameters["end"])},
                        "next_before": next_before, "candidate_count": min(len(candidates), MAX_EVENTS)}
                if len(json.dumps(page, separators=(",", ":"), allow_nan=False).encode()) > MAX_BYTES:
                    raise ValueError("response bound")
                return page
            except (ValueError, TypeError, KeyError, OverflowError, UnicodeError):
                raise StorageSchemaError("DASHBOARD_STORE:INVALID_TRAFFIC") from None
            finally:
                cursor.close()

    @staticmethod
    def _project(rows) -> dict:
        event_rows = [row for row in rows if row["kind"] == "event"]
        finding_rows = [row for row in rows if row["kind"] == "finding"]
        truncated = len(event_rows) > MAX_EVENTS or len(finding_rows) > MAX_FINDINGS
        events, findings = [], []
        excluded = 0
        for row in event_rows[:MAX_EVENTS]:
            if row["source"] not in {"jsonl", "scapy"} or row["run_status"] == "reconciliation_required" or row["receipt_version"] != 3:
                excluded += 1
                continue
            if row["run_status"] not in {"running", "completed", "incomplete", "failed"}:
                raise ValueError("invalid receipt")
            reasons = {"running": {None}, "completed": {"source_exhausted"},
                       "incomplete": {"event_limit_reached"}, "failed": {"failed", "interrupted"}}
            if row["termination_reason"] not in reasons[row["run_status"]]:
                raise ValueError("invalid receipt reason")
            if not isinstance(row["protocol"], str) or not row["protocol"].isascii() or not row["protocol"].isalnum():
                raise ValueError("invalid protocol")
            if row["tcp_flags"] is None:
                raise ValueError("invalid flags")
            flags = json.loads(row["tcp_flags"])
            if not isinstance(flags, list) or len(flags) > 8 or any(type(flag) is not str for flag in flags):
                raise ValueError("invalid flags")
            flags = sorted(parse_flags(flags))
            src, dst = parse_ip(row["src_ip"]), parse_ip(row["dst_ip"])
            events.append({
                "id": str(_integer(row["record_id"], minimum=1)),
                "observed_at": _time(row["timestamp"]), "src_ip": src, "dst_ip": dst,
                "protocol": row["protocol"] if row["protocol"] in PROTOCOLS else "OTHER",
                "src_port": None if row["src_port"] is None else _integer(row["src_port"], maximum=65535),
                "dst_port": None if row["dst_port"] is None else _integer(row["dst_port"], maximum=65535),
                "tcp_flags": flags,
                # JSON numbers cannot preserve all SQLite integers in browsers.
                "byte_count": str(_integer(row["byte_count"], maximum=2**63 - 1)),
                "run_id": str(_integer(row["run_id"], minimum=1)),
                "source": row["source"], "run_status": row["run_status"],
                "termination_reason": row["termination_reason"],
            })
        accepted = {event["id"] for event in events}
        for row in finding_rows[:MAX_FINDINGS]:
            if str(row["event_id"]) not in accepted:
                continue
            if row["rule_id"] not in DETECTORS or row["severity"] not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                raise ValueError("unknown detector")
            findings.append({"id": str(_integer(row["record_id"], minimum=1)),
                             "event_id": str(row["event_id"]), "detected_at": _time(row["timestamp"]),
                             "rule_id": row["rule_id"], "severity": row["severity"],
                             "detector_version": "unknown; not stored on historical finding"})
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        degraded = truncated or any(e["run_status"] != "completed" for e in events)
        result = {
            "schema": SCHEMA, "status": "available" if events else "unavailable",
            "reason": "Bounded stored metadata; source authenticity and coverage remain unverified." if events else "No qualified data available. Sample and unlinked records do not establish real traffic.",
            "generated_at": now, "unit": "metadata events; reported bytes",
            "vantage": "unknown; not recorded in this projection", "quality": "degraded" if degraded else "unknown",
            "window": {"start": min((e["observed_at"] for e in events), default=None),
                       "end": max((e["observed_at"] for e in events), default=None)},
            "limits": {"events": MAX_EVENTS, "findings": MAX_FINDINGS, "bytes": MAX_BYTES},
            "truncated": truncated, "excluded_event_candidates": excluded,
            "events": events, "findings": findings, "limitations": list(LIMITATIONS),
            "build": {"package_version": __version__, "base_commit": "4971d85a2c56d932fda9053873a42985b4233371",
                      "projection_sha256": PROJECTION_SHA256,
                      "commit": "unknown; source component digest identifies this projection"},
        }
        if len(json.dumps(result, separators=(",", ":"), allow_nan=False).encode()) > MAX_BYTES:
            raise ValueError("response bound")
        return result


# Digest code only, once at import. Never digest a packet, raw input or payload.
PROJECTION_SHA256 = sha256(Path(__file__).read_bytes()).hexdigest()
