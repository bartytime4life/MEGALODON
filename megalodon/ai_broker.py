"""Fixed MEGALODON AI tools. Model text never becomes OS authority."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from typing import Any, Protocol
from uuid import uuid4

from .config import AISettings, BlockingSettings
from .firewall import FirewallError, NftablesFirewall
from .hub import integration_plan
from .storage import (
    _absolute_database_path, _anchored_database_path, _open_private_database,
    _open_private_directory, _validate_connection_path, _validate_sqlite_sidecars,
)
from .validation import parse_timestamp


MAX_REQUEST_BYTES = 2048
MAX_RESULT_BYTES = 8192
MAX_LEDGER_BYTES = 16 * 1024 * 1024
STATES = frozenset({"not_attempted", "suppressed", "planned", "awaiting_confirmation",
                    "approved", "observed", "applied", "failed", "expired"})


@dataclass(frozen=True)
class Tool:
    name: str
    level: int
    timeout_seconds: int
    purpose: str


TOOLS = {
    tool.name: tool for tool in (
        Tool("megalodon.status", 0, 2, "Bounded stored counts"),
        Tool("megalodon.telemetry.summary", 0, 2, "Qualified recent metadata summary"),
        Tool("megalodon.alerts.query", 0, 2, "Qualified recent detector findings"),
        Tool("megalodon.integrations.status", 0, 2, "Static integration catalog"),
        Tool("megalodon.model.status", 0, 20, "Explicit local model health"),
        Tool("megalodon.action.status", 0, 2, "One AI action receipt"),
        Tool("megalodon.report.generate", 1, 2, "Bounded in-ledger report snapshot"),
        Tool("megalodon.firewall.block.plan", 2, 2, "Time-limited firewall proposal only"),
    )
}


class AIReader(Protocol):
    def summary(self) -> dict[str, Any]: ...
    def traffic(self) -> dict[str, Any]: ...


class BrokerError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False)


def _text(value: object, maximum: int) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum or not value.isprintable():
        raise BrokerError("INVALID_ARGUMENTS")
    return value


def _integer(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise BrokerError("INVALID_ARGUMENTS")
    return value


def _keys(value: object, allowed: set[str], required: set[str] = frozenset()) -> dict[str, Any]:
    if type(value) is not dict or not required <= set(value) or set(value) - allowed:
        raise BrokerError("INVALID_ARGUMENTS")
    return value


def _arguments(tool: str, value: object) -> dict[str, Any]:
    if tool in {"megalodon.status", "megalodon.integrations.status", "megalodon.model.status"}:
        return _keys(value, set())
    if tool in {"megalodon.telemetry.summary", "megalodon.alerts.query"}:
        args = _keys(value, {"window_minutes", "limit"})
        result = {"window_minutes": _integer(args.get("window_minutes", 60), 1, 1440)}
        if tool == "megalodon.alerts.query":
            result["limit"] = _integer(args.get("limit", 8), 1, 8)
        return result
    if tool == "megalodon.report.generate":
        args = _keys(value, {"report_type", "window_minutes"}, {"report_type"})
        if args["report_type"] not in {"security_summary", "ingestion_summary"}:
            raise BrokerError("INVALID_ARGUMENTS")
        return {"report_type": args["report_type"],
                "window_minutes": _integer(args.get("window_minutes", 60), 1, 1440)}
    if tool == "megalodon.firewall.block.plan":
        args = _keys(value, {"target", "duration_seconds"}, {"target", "duration_seconds"})
        target = _text(args["target"], 45)
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            raise BrokerError("INVALID_TARGET") from None
        if not address.is_global or address.is_multicast or address.is_unspecified:
            raise BrokerError("INVALID_TARGET")
        return {"target": str(address),
                "duration_seconds": _integer(args["duration_seconds"], 60, 3600)}
    if tool == "megalodon.action.status":
        args = _keys(value, {"receipt_id"}, {"receipt_id"})
        identifier = _text(args["receipt_id"], 36)
        if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", identifier) is None:
            raise BrokerError("INVALID_ARGUMENTS")
        return {"receipt_id": identifier}
    raise BrokerError("UNKNOWN_TOOL")


def validate_request(value: object) -> tuple[str, dict[str, Any], str, str]:
    """Closed model request; command/path/URL/permission fields are refused."""
    if type(value) is not dict or len(_json(value).encode("utf-8")) > MAX_REQUEST_BYTES:
        raise BrokerError("INVALID_REQUEST")
    request = _keys(value, {"tool", "arguments", "reason"}, {"tool", "arguments", "reason"})
    tool = _text(request["tool"], 96)
    if tool not in TOOLS:
        raise BrokerError("UNKNOWN_TOOL")
    reason = _text(request["reason"], 200)
    return tool, _arguments(tool, request["arguments"]), reason, sha256(_json(value).encode()).hexdigest()


class ReceiptStore:
    """Private append-only state events with a local SHA-256 chain.

    The chain detects accidental changes against a trusted head; it is not a
    signature or protection against an owner who can rewrite the database.
    """

    def __init__(self, path: str | Path):
        self.path = _absolute_database_path(path, "AI_RECEIPT")
        self._directory = _open_private_directory(self.path.parent, create=True, prefix="AI_RECEIPT")
        self._descriptor = None
        self.connection = None
        try:
            self._descriptor, _ = _open_private_database(
                self.path, self._directory, writable=True, create=True, prefix="AI_RECEIPT"
            )
            _validate_sqlite_sidecars(self.path, self._directory, writable=True, prefix="AI_RECEIPT")
            anchored = _anchored_database_path(self._descriptor, self.path, "AI_RECEIPT")
            self.connection = sqlite3.connect(
                f"{anchored.as_uri()}?mode=rw&cache=private", uri=True, timeout=2,
                check_same_thread=False,
            )
            _validate_connection_path(self.connection, self.path, "AI_RECEIPT")
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("""CREATE TABLE IF NOT EXISTS ai_receipt_events (
                sequence INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL,
                timestamp TEXT NOT NULL, payload_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL)""")
            self.connection.execute("CREATE INDEX IF NOT EXISTS ai_receipt_by_id ON ai_receipt_events(receipt_id, sequence)")
            self.connection.commit()
            _validate_sqlite_sidecars(self.path, self._directory, writable=True, prefix="AI_RECEIPT")
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None
        if self._directory is not None:
            os.close(self._directory)
            self._directory = None

    def __enter__(self) -> "ReceiptStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def append(self, receipt_id: str, payload: dict[str, object]) -> dict[str, object]:
        if payload.get("state") not in STATES:
            raise BrokerError("INVALID_RECEIPT_STATE")
        encoded = _json(payload)
        if len(encoded.encode()) > MAX_RESULT_BYTES:
            raise BrokerError("RESULT_TOO_LARGE")
        if self._descriptor is None or self.connection is None:
            raise BrokerError("AUDIT_UNAVAILABLE")
        occupied = os.fstat(self._descriptor).st_size
        for suffix in ("-wal", "-shm"):
            sidecar = self.path.name + suffix
            try:
                info = (os.stat(sidecar, dir_fd=self._directory, follow_symlinks=False)
                        if self._directory is not None else self.path.with_name(sidecar).lstat())
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode):
                raise BrokerError("AUDIT_UNAVAILABLE")
            occupied += info.st_size
        if occupied > MAX_LEDGER_BYTES:
            raise BrokerError("AUDIT_UNAVAILABLE")
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            last = self.connection.execute("SELECT event_hash FROM ai_receipt_events ORDER BY sequence DESC LIMIT 1").fetchone()
            previous = last[0] if last else "0" * 64
            event_hash = sha256((previous + receipt_id + now + encoded).encode()).hexdigest()
            self.connection.execute(
                "INSERT INTO ai_receipt_events(receipt_id,timestamp,payload_json,previous_hash,event_hash) VALUES(?,?,?,?,?)",
                (receipt_id, now, encoded, previous, event_hash),
            )
            self.connection.commit()
        except sqlite3.Error:
            self.connection.rollback()
            raise BrokerError("AUDIT_UNAVAILABLE") from None
        return {"receipt_id": receipt_id, "timestamp": now, "event_hash": event_hash,
                "previous_hash": previous, **payload}

    def latest(self, receipt_id: str) -> dict[str, object] | None:
        if self.connection is None:
            raise BrokerError("AUDIT_UNAVAILABLE")
        row = self.connection.execute(
            "SELECT timestamp,payload_json,previous_hash,event_hash FROM ai_receipt_events "
            "WHERE receipt_id=? ORDER BY sequence DESC LIMIT 1", (receipt_id,),
        ).fetchone()
        if row is None:
            return None
        return {"receipt_id": receipt_id, "timestamp": row[0], "previous_hash": row[2],
                "event_hash": row[3], **json.loads(row[1])}


def _qualified(reader: AIReader, window_minutes: int, limit: int) -> dict[str, object]:
    traffic = reader.traffic()
    if type(traffic) is not dict or traffic.get("schema") != "dashboard-traffic-v1":
        raise BrokerError("EVIDENCE_UNAVAILABLE")
    if traffic.get("quality") not in {"unknown", "degraded"} or type(traffic.get("truncated")) is not bool:
        raise BrokerError("EVIDENCE_INVALID")
    if type(traffic.get("findings")) is not list or len(traffic["findings"]) > 200:
        raise BrokerError("EVIDENCE_INVALID")
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=window_minutes)
    findings = []
    for item in traffic.get("findings", [])[:200]:
        if type(item) is not dict or set(item) - {"id", "event_id", "detected_at", "rule_id", "severity", "detector_version"}:
            raise BrokerError("EVIDENCE_INVALID")
        if item.get("rule_id") not in {"SYN_FLOOD", "PORT_SCAN", "DNS_TUNNELING"} or item.get("severity") not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise BrokerError("EVIDENCE_INVALID")
        try:
            when = parse_timestamp(item["detected_at"])
        except (KeyError, ValueError, TypeError):
            raise BrokerError("EVIDENCE_INVALID") from None
        if when > now + timedelta(minutes=1):
            raise BrokerError("EVIDENCE_INVALID")
        if when >= cutoff:
            identifier = _text(item["id"], 20)
            if re.fullmatch(r"[1-9][0-9]{0,15}", identifier) is None:
                raise BrokerError("EVIDENCE_INVALID")
            findings.append({"id": identifier, "detected_at": item["detected_at"],
                             "rule_id": item["rule_id"], "severity": item["severity"]})
    return {"window_minutes": window_minutes, "qualified_findings": findings[:limit],
            "returned_count": len(findings[:limit]), "truncated": bool(traffic.get("truncated")) or len(findings) > limit,
            "source_quality": traffic.get("quality"),
            "scope": "bounded qualified stored metadata; capture coverage and authenticity unproved"}


class Broker:
    def __init__(self, reader: AIReader, receipts: ReceiptStore, ai: AISettings,
                 blocking: BlockingSettings):
        self.reader, self.receipts, self.ai, self.blocking = reader, receipts, ai, blocking

    def dispatch(self, request: object, *, authorization_source: str = "model_request") -> dict[str, object]:
        receipt_id = str(uuid4())
        raw_tool = request.get("tool") if type(request) is dict else None
        tool_name = raw_tool if type(raw_tool) is str and len(raw_tool) <= 96 else "invalid"
        base: dict[str, object] = {"model": self.ai.model, "model_request": "unvalidated",
                                   "tool": tool_name, "validated_arguments": {}, "authority_level": 3,
                                   "authorization_source": authorization_source, "result": None,
                                   "error_code": None, "duration_ms": 0, "evidence_references": []}
        started = time.monotonic()
        self.receipts.append(receipt_id, {**base, "state": "not_attempted"})
        try:
            tool, arguments, reason, request_digest = validate_request(request)
            spec = TOOLS[tool]
            base.update(tool=tool, validated_arguments=arguments, authority_level=spec.level,
                        model_request=request_digest, reason=reason)
            if spec.level == 2:
                result = self._plan(tool, arguments, reason)
                state = "awaiting_confirmation"
            else:
                result = self._execute(tool, arguments)
                state = "observed" if spec.level == 0 else "applied"
            if len(_json(result).encode()) > MAX_RESULT_BYTES:
                raise BrokerError("RESULT_TOO_LARGE")
            references = ["finding:" + item["id"] for item in result.get("qualified_findings", [])] if type(result) is dict else []
            base.update(result=result, evidence_references=references[:8])
        except BrokerError as exc:
            state = "failed"
            base["error_code"] = exc.code
        except (OSError, sqlite3.Error, ValueError, TypeError, KeyError):
            state = "failed"
            base["error_code"] = "TOOL_UNAVAILABLE"
        base["duration_ms"] = min(60_000, int((time.monotonic() - started) * 1000))
        return self.receipts.append(receipt_id, {**base, "state": state})

    def _execute(self, tool: str, args: dict[str, Any]) -> dict[str, object]:
        if tool == "megalodon.status":
            summary = self.reader.summary()
            if type(summary) is not dict:
                raise BrokerError("EVIDENCE_INVALID")
            return {key: _integer(summary[key], 0, 2**53 - 1) for key in
                    ("events", "detections", "actions", "high_or_critical")}
        if tool == "megalodon.telemetry.summary":
            result = _qualified(self.reader, args["window_minutes"], 8)
            return {key: value for key, value in result.items() if key != "qualified_findings"} | {
                "finding_count_in_returned_window": result["returned_count"]}
        if tool == "megalodon.alerts.query":
            return _qualified(self.reader, args["window_minutes"], args["limit"])
        if tool == "megalodon.integrations.status":
            catalog = integration_plan("linux")
            return {"catalog": "static; installed and running state unverified",
                    "workflow_ids": [item["id"] for item in catalog["workflows"]][:20]}
        if tool == "megalodon.model.status":
            from .ai_provider import status
            return status(self.ai, probe=True)
        if tool == "megalodon.action.status":
            receipt = self.receipts.latest(args["receipt_id"])
            if receipt is None:
                raise BrokerError("RECEIPT_NOT_FOUND")
            return {"receipt_id": receipt["receipt_id"], "state": receipt["state"],
                    "tool": receipt["tool"], "event_hash": receipt["event_hash"]}
        if tool == "megalodon.report.generate":
            return {"schema": "megalodon-ai-report-v1", "type": args["report_type"],
                    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "summary": self._execute("megalodon.status", {}),
                    "alerts": _qualified(self.reader, args["window_minutes"], 8),
                    "scope": "stored qualified metadata only; no packet payload, coverage proof, or host action"}
        raise BrokerError("UNKNOWN_TOOL")

    def _plan(self, tool: str, args: dict[str, Any], reason: str) -> dict[str, object]:
        if tool != "megalodon.firewall.block.plan":
            raise BrokerError("UNKNOWN_TOOL")
        firewall = NftablesFirewall(allowlist=self.blocking.allowlist,
                                    public_only=True, timeout_seconds=args["duration_seconds"])
        try:
            operation = firewall.plan_block(args["target"], reason)
        except FirewallError:
            raise BrokerError("INVALID_TARGET") from None
        return {"action": "proposed time-limited firewall block", "target": operation.target,
                "reason": reason, "expected_effect": "would drop matching traffic if separately applied",
                "risk": "could interrupt legitimate connectivity", "rollback": "remove the exact set element",
                "exact_parameters": {"target": operation.target, "duration_seconds": args["duration_seconds"]},
                "expires_at": operation.expires_at.isoformat() if operation.expires_at else None,
                "approval_required": True, "application_supported": False}
