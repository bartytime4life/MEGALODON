"""Synthetic service-to-ledger receipts, never live firewall acceptance."""

from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
from unittest.mock import Mock

import pytest

import megalodon.firewall as firewall_module
import megalodon.service as service_module
from megalodon.config import BlockingSettings, Settings
from megalodon.firewall import NftablesFirewall
from megalodon.models import PacketEvent
from megalodon.service import MegalodonService
from megalodon.storage import Store


OBSERVED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)
AUDIT_AT = datetime(2026, 1, 2, tzinfo=timezone.utc)
EXPIRES_AT = AUDIT_AT + timedelta(seconds=900)
# Independent fixture expectations, not derived from detector settings/results.
RULES = (
    ("SYN_FLOOD", "HIGH", 100, {"count": 100, "window_seconds": 10},
     "100 TCP SYN packets from one source in 10s"),
    ("PORT_SCAN", "MEDIUM", 20, {"distinct_ports": 20, "window_seconds": 5},
     "20 destination ports targeted in 5s"),
    ("DNS_TUNNELING", "CRITICAL", 1, {"dns_query_length": 50, "threshold": 50},
     "DNS query metadata length 50 exceeds the configured threshold"),
)
POLICIES = (
    ("observe", "not_attempted", 0),
    ("disabled-auto", "not_attempted", 0),
    ("enabled-no-auto", "not_attempted", 0),
    ("plan", "planned", 1),
    ("direct-live-flags", "planned", 1),
    ("allowlisted", "suppressed", 0),
    ("non-global", "failed", 1),
    ("allowlisted-non-global", "suppressed", 0),
)
# Global literals are synthetic metadata, not contacted hosts or threat claims.
ADDRESSES = (
    ("8.8.8.8", "192.0.2.1", "198.51.100.2", "blocked_v4"),
    ("2001:4860:4860::8888", "2001:db8::1", "2001:db8::2", "blocked_v6"),
)
TABLES = ("events", "detections", "actions")


class AuditClock(datetime):
    @classmethod
    def now(cls, tz=None):
        assert tz is timezone.utc
        return AUDIT_AT


@pytest.fixture(autouse=True)
def no_host_operations(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("service evaluation must not apply, probe, launch or connect")

    for name in ("block", "install", "_run", "_require_apply", "available"):
        monkeypatch.setattr(NftablesFirewall, name, forbidden)
    for owner, name in ((subprocess, "run"), (subprocess, "Popen"), (os, "system"),
                        (shutil, "which"), (socket, "socket"),
                        (socket, "create_connection"), (socket, "getaddrinfo")):
        monkeypatch.setattr(owner, name, forbidden)
    monkeypatch.setattr(service_module, "datetime", AuditClock)
    monkeypatch.setattr(firewall_module, "datetime", AuditClock)


def _events(rule, count, source, destination):
    for index in range(count):
        fields = {"observed_at": OBSERVED_AT + timedelta(milliseconds=index),
                  "src_ip": source, "dst_ip": destination, "protocol": "TCP"}
        if rule == "SYN_FLOOD":
            fields["tcp_flags"] = ["SYN"]
        elif rule == "PORT_SCAN":
            fields["dst_port"] = 1000 + index
        else:
            assert rule == "DNS_TUNNELING"
            fields.update(protocol="DNS", dst_port=53, dns_query_length=50)
        yield PacketEvent.from_mapping(fields)


def _policy(name, source):
    if name == "observe":
        return BlockingSettings()
    if name == "disabled-auto":
        return BlockingSettings(auto_block=True, auto_block_min_severity="MEDIUM")
    if name == "enabled-no-auto":
        return BlockingSettings(enabled=True, auto_block_min_severity="MEDIUM")
    assert name in {case[0] for case in POLICIES}
    return BlockingSettings(
        enabled=True, auto_block=True, auto_block_min_severity="MEDIUM",
        # Direct construction bypasses TOML refusal; it must still never apply.
        dry_run=name != "direct-live-flags",
        allowlist=(ipaddress.ip_network(source),) if name.startswith("allowlisted") else (),
    )


def _service(settings, store, monkeypatch):
    service = MegalodonService(settings, store)
    # Spy on the real planner; its validation, argv and expiry are not replaced.
    planner = Mock(wraps=service.firewall.plan_block)
    monkeypatch.setattr(service.firewall, "plan_block", planner)
    return service, planner


def _read_ledger(path: Path):
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        # Identifiers come only from this closed test constant, never input.
        return {table: [dict(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY id")]
                for table in TABLES}


def _assert_action(row, status, source, rule, message, set_name):
    reason = {
        "not_attempted": "automatic block planning disabled by policy",
        "suppressed": "source_allowlisted",
        "failed": f"refusing to block non-global address {source} under public_only policy",
        "planned": f"{rule}: {message}",
    }[status]
    expiry = EXPIRES_AT.isoformat() if status == "planned" else None
    details = {}
    if status == "planned":
        details = {"status": "planned", "target": source, "reason": reason,
                   "command": ["nft", "add", "element", "inet", "megalodon", set_name,
                               "{", source, "timeout", "900s", "}"],
                   "message": "would add a time-limited set element", "expires_at": expiry}
    decoded = dict(row)
    decoded["details_json"] = json.loads(row["details_json"])
    assert decoded == {"id": 1, "created_at": AUDIT_AT.isoformat(), "action": "block",
                       "target": source, "status": status, "reason": reason,
                       "expires_at": expiry, "details_json": details}


@pytest.mark.parametrize("rule,severity,count,evidence,message", RULES, ids=[r[0] for r in RULES])
@pytest.mark.parametrize("policy,status,plan_calls", POLICIES, ids=[p[0] for p in POLICIES])
@pytest.mark.parametrize("global_ip,non_global_ip,destination,set_name", ADDRESSES, ids=["ipv4", "ipv6"])
def test_service_policy_receipt_survives_reopen(
    tmp_path, monkeypatch, rule, severity, count, evidence, message,
    policy, status, plan_calls, global_ip, non_global_ip, destination, set_name,
):
    source = non_global_ip if "non-global" in policy else global_ip
    settings = Settings(db_path=tmp_path / "synthetic.db", blocking=_policy(policy, source))
    events = list(_events(rule, count, source, destination))
    with Store(settings.db_path) as store:
        service, planner = _service(settings, store, monkeypatch)
        results = [result for event in events for result in service.process(event)]
        assert [result.rule_id for result in results] == [rule]
        assert service.process(events[-1]) == []  # Cooldown is not packet deduplication.
        assert planner.call_count == plan_calls
        if plan_calls:
            planner.assert_called_once_with(source, f"{rule}: {message}")
        assert store.connection.in_transaction is False

    ledger = _read_ledger(settings.db_path)
    assert len(ledger["events"]) == count + 1
    assert all(row["metadata_json"] == "{}" for row in ledger["events"])
    assert len(ledger["detections"]) == len(ledger["actions"]) == 1
    detection = dict(ledger["detections"][0])
    detection["evidence_json"] = json.loads(detection["evidence_json"])
    assert detection == {
        "id": 1, "event_id": count, "detected_at": events[-1].observed_at.isoformat(),
        "rule_id": rule, "severity": severity, "src_ip": source, "dst_ip": destination,
        "message": message, "evidence_json": evidence, "recommendation": "ALERT",
        "suppressed_reason": "source_allowlisted" if status == "suppressed" else None,
    }
    _assert_action(ledger["actions"][0], status, source, rule, message, set_name)


@pytest.mark.parametrize("rule,severity,count,evidence,message", RULES, ids=[r[0] for r in RULES])
def test_below_threshold_intake_has_no_detection_action_or_plan(
    tmp_path, monkeypatch, rule, severity, count, evidence, message,
):
    events = list(_events(rule, max(1, count - 1), "8.8.8.8", "198.51.100.2"))
    if rule == "DNS_TUNNELING":
        events = [replace(events[0], dns_query_length=49)]
    settings = Settings(db_path=tmp_path / "synthetic.db", blocking=_policy("plan", "8.8.8.8"))
    with Store(settings.db_path) as store:
        service, planner = _service(settings, store, monkeypatch)
        for event in events:
            assert service.process(event) == []
        planner.assert_not_called()
    ledger = _read_ledger(settings.db_path)
    assert len(ledger["events"]) == len(events)
    assert ledger["detections"] == ledger["actions"] == []


@pytest.mark.parametrize("rule,severity,count,evidence,message", RULES, ids=[r[0] for r in RULES])
def test_minimum_severity_does_not_turn_every_detection_into_a_plan(
    tmp_path, monkeypatch, rule, severity, count, evidence, message,
):
    settings = Settings(db_path=tmp_path / "synthetic.db",
                        blocking=BlockingSettings(enabled=True, auto_block=True))
    with Store(settings.db_path) as store:
        service, planner = _service(settings, store, monkeypatch)
        for event in _events(rule, count, "8.8.8.8", "198.51.100.2"):
            service.process(event)
        assert planner.call_count == (1 if rule == "DNS_TUNNELING" else 0)
    ledger = _read_ledger(settings.db_path)
    assert len(ledger["detections"]) == len(ledger["actions"]) == 1
    status = "planned" if rule == "DNS_TUNNELING" else "not_attempted"
    _assert_action(ledger["actions"][0], status, "8.8.8.8", rule, message, "blocked_v4")


@pytest.mark.parametrize("table,expected_counts,plan_calls", (
    ("events", (0, 0, 0), 0),
    ("detections", (1, 0, 0), 0),
    ("actions", (1, 1, 0), 1),
))
def test_failed_stage_propagates_without_a_success_receipt(
    tmp_path, monkeypatch, table, expected_counts, plan_calls,
):
    settings = Settings(db_path=tmp_path / "synthetic.db", blocking=_policy("plan", "8.8.8.8"))
    with Store(settings.db_path) as store:
        service, planner = _service(settings, store, monkeypatch)
        # Fixed temporary fixture: FAIL does not itself undo the tentative row.
        assert table in TABLES
        store.connection.execute(
            f"CREATE TRIGGER fail_stage AFTER INSERT ON {table} "
            "BEGIN SELECT RAISE(FAIL, 'synthetic audit failure'); END"
        )
        store.connection.commit()
        event = next(_events("DNS_TUNNELING", 1, "8.8.8.8", "198.51.100.2"))
        with pytest.raises(sqlite3.IntegrityError, match="synthetic audit failure"):
            service.process(event)
        assert store.connection.in_transaction is False
        assert planner.call_count == plan_calls
        # Earlier independently committed stages remain; no whole-service rollback.
        ledger = _read_ledger(settings.db_path)
        assert tuple(len(ledger[name]) for name in TABLES) == expected_counts
    assert _read_ledger(settings.db_path) == ledger
