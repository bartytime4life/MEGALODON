"""Synthetic service-to-ledger receipts, never live firewall acceptance."""

from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import logging
import os
from pathlib import Path
import shutil
import signal
import socket
import sqlite3
import subprocess
from threading import Event
from unittest.mock import Mock

import pytest

import megalodon.firewall as firewall_module
import megalodon.service as service_module
from megalodon.config import BlockingSettings, DetectionSettings, Settings
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
ATOMIC_TABLES = (*TABLES, "detection_actions")


class AuditClock(datetime):
    @classmethod
    def now(cls, tz=None):
        assert tz is timezone.utc
        return AUDIT_AT


@pytest.fixture(autouse=True)
def no_host_operations(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("service evaluation must not apply, probe, launch or connect")

    for name in ("block", "install", "available"):
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


@pytest.mark.parametrize("table", ATOMIC_TABLES)
def test_failed_stage_propagates_without_a_success_receipt(
    tmp_path, monkeypatch, table,
):
    settings = Settings(db_path=tmp_path / "synthetic.db", blocking=_policy("plan", "8.8.8.8"))
    with Store(settings.db_path) as store:
        service, planner = _service(settings, store, monkeypatch)
        run_id = store.start_ingestion_run("sample", started_at=OBSERVED_AT)
        assert table in ATOMIC_TABLES
        store.connection.execute(
            f"CREATE TRIGGER fail_stage AFTER INSERT ON {table} "
            "BEGIN SELECT RAISE(FAIL, 'synthetic audit failure'); END"
        )
        store.connection.commit()
        event = next(_events("DNS_TUNNELING", 1, "8.8.8.8", "198.51.100.2"))
        with pytest.raises(sqlite3.IntegrityError, match="synthetic audit failure"):
            service.process(event, run_id=run_id)
        assert store.connection.in_transaction is False
        # Planning is side-effect-free and happens before the single ledger write.
        assert planner.call_count == 1
        ledger = _read_ledger(settings.db_path)
        assert tuple(len(ledger[name]) for name in TABLES) == (0, 0, 0)
        assert tuple(
            store.connection.execute(
                "SELECT processed_count, detection_count, action_count "
                "FROM ingestion_runs WHERE id = ?",
                (run_id,),
            ).fetchone()
        ) == (0, 0, 0)

        # Removing the fault and retrying the same event must emit again: the
        # failed commit consumed neither the cooldown nor source high-water mark.
        store.connection.execute("DROP TRIGGER fail_stage")
        store.connection.commit()
        assert [item.rule_id for item in service.process(event, run_id=run_id)] == [
            "DNS_TUNNELING"
        ]
        assert planner.call_count == 2
        assert store.connection.in_transaction is False
        resumed = _read_ledger(settings.db_path)
        assert tuple(len(resumed[name]) for name in TABLES) == (1, 1, 1)
        assert tuple(
            store.connection.execute(
                "SELECT processed_count, detection_count, action_count "
                "FROM ingestion_runs WHERE id = ?",
                (run_id,),
            ).fetchone()
        ) == (1, 1, 1)
        store.finish_ingestion_run(
            run_id, "source_exhausted", finished_at=OBSERVED_AT + timedelta(seconds=1)
        )
        ledger = resumed
    assert _read_ledger(settings.db_path) == ledger


def test_planner_refusal_log_waits_for_atomic_ledger_commit(
    tmp_path, monkeypatch, caplog
):
    source = "192.0.2.1"
    settings = Settings(
        db_path=tmp_path / "synthetic.db",
        blocking=_policy("non-global", source),
    )
    event = next(_events("DNS_TUNNELING", 1, source, "198.51.100.2"))
    with Store(settings.db_path) as store:
        service, planner = _service(settings, store, monkeypatch)
        store.connection.execute(
            "CREATE TRIGGER fail_stage AFTER INSERT ON actions "
            "BEGIN SELECT RAISE(FAIL, 'synthetic audit failure'); END"
        )
        store.connection.commit()

        with caplog.at_level(logging.ERROR, logger="megalodon.service"):
            with pytest.raises(sqlite3.IntegrityError, match="synthetic audit failure"):
                service.process(event)
        assert planner.call_count == 1
        assert caplog.records == []

        store.connection.execute("DROP TRIGGER fail_stage")
        store.connection.commit()
        with caplog.at_level(logging.ERROR, logger="megalodon.service"):
            service.process(event)
        assert planner.call_count == 2
        assert [record.getMessage() for record in caplog.records] == [
            "firewall action refused: refusing to block non-global address "
            f"{source} under public_only policy"
        ]


@pytest.mark.parametrize("failure_stage", ("planner", "storage"))
@pytest.mark.parametrize(
    "scenario,prior,observed,port,window_seconds,capacity,expected",
    (
        ("new-source", (), 0.0, 21, 5, 3, ((0.0, 21),)),
        (
            "time-expiry-with-duplicates",
            ((0.0, 21), (0.25, 21), (0.5, 22)),
            2.0,
            23,
            1,
            10,
            ((2.0, 23),),
        ),
        (
            "capacity-with-duplicates",
            ((0.0, 21), (0.25, 21), (0.5, 22)),
            0.75,
            21,
            100,
            3,
            ((0.25, 21), (0.5, 22), (0.75, 21)),
        ),
    ),
)
def test_port_counter_journal_restores_failed_service_bundle_then_retries(
    tmp_path,
    monkeypatch,
    caplog,
    failure_stage,
    scenario,
    prior,
    observed,
    port,
    window_seconds,
    capacity,
    expected,
):
    source = "8.8.8.8"
    settings = Settings(
        db_path=tmp_path / f"{scenario}-{failure_stage}.db",
        detection=DetectionSettings(
            syn_flood_threshold=capacity,
            port_scan_window_seconds=window_seconds,
            port_scan_distinct_ports=1,
            max_events_per_source_window=capacity,
        ),
        blocking=_policy("plan", source),
    )
    candidate = PacketEvent.from_mapping(
        {
            "observed_at": OBSERVED_AT + timedelta(seconds=observed),
            "src_ip": source,
            "dst_ip": "198.51.100.2",
            "protocol": "TCP",
            "dst_port": port,
            "tcp_flags": ["ACK"],
        }
    )

    with Store(settings.db_path) as store:
        service, planner = _service(settings, store, monkeypatch)
        detector = service.detector
        if prior:
            window = deque(
                (OBSERVED_AT.timestamp() + seconds, prior_port)
                for seconds, prior_port in prior
            )
            counts = Counter(prior_port for _, prior_port in prior)
            detector.port_windows[source] = window
            detector.port_counts[source] = counts
            detector.source_high_watermarks[source] = window[-1][0]
            detector.source_order[source] = None
        else:
            window = counts = None

        before_window = tuple(detector.port_windows.get(source, ()))
        before_counts = dict(detector.port_counts.get(source, ()))
        before_order = tuple(detector.source_order)
        before_watermarks = dict(detector.source_high_watermarks)
        before_emitted = dict(detector.last_emitted)
        if failure_stage == "planner":
            planner.side_effect = RuntimeError("synthetic planner failure")
            expected_error = RuntimeError
        else:
            store.connection.execute(
                "CREATE TRIGGER fail_bundle AFTER INSERT ON events "
                "BEGIN SELECT RAISE(FAIL, 'synthetic bundle failure'); END"
            )
            store.connection.commit()
            expected_error = sqlite3.IntegrityError

        with caplog.at_level(logging.INFO, logger="megalodon.service"):
            with pytest.raises(expected_error, match="synthetic .* failure"):
                service.process(candidate)

        assert tuple(detector.port_windows.get(source, ())) == before_window
        assert dict(detector.port_counts.get(source, ())) == before_counts
        assert tuple(detector.source_order) == before_order
        assert detector.source_high_watermarks == before_watermarks
        assert detector.last_emitted == before_emitted
        assert detector._pending_token is None
        if prior:
            assert detector.port_windows[source] is window
            assert detector.port_counts[source] is counts
        else:
            assert source not in detector.port_windows
            assert source not in detector.port_counts
        assert store.summary() == {
            "events": 0,
            "detections": 0,
            "high_or_critical": 0,
            "actions": 0,
        }
        assert caplog.records == []

        if failure_stage == "planner":
            planner.side_effect = None
        else:
            store.connection.execute("DROP TRIGGER fail_bundle")
            store.connection.commit()
        assert [item.rule_id for item in service.process(candidate)] == ["PORT_SCAN"]

        expected_window = tuple(
            (OBSERVED_AT.timestamp() + seconds, expected_port)
            for seconds, expected_port in expected
        )
        assert tuple(detector.port_windows[source]) == expected_window
        expected_counts = Counter(
            expected_port for _, expected_port in expected
        )
        assert dict(detector.port_counts[source]) == dict(expected_counts)
        assert all(value > 0 for value in detector.port_counts[source].values())
        assert sum(detector.port_counts[source].values()) == len(
            detector.port_windows[source]
        )
        assert detector.source_high_watermarks[source] == candidate.observed_at.timestamp()
        assert tuple(detector.source_order) == (source,)
        assert detector._pending_token is None
        assert store.summary() == {
            "events": 1,
            "detections": 1,
            "high_or_critical": 0,
            "actions": 1,
        }


def test_reentrant_planner_process_is_refused_and_outer_state_rolls_back(
    tmp_path, monkeypatch, caplog
):
    source = "8.8.8.8"
    settings = Settings(
        db_path=tmp_path / "reentrant.db",
        detection=DetectionSettings(
            syn_flood_threshold=100,
            port_scan_distinct_ports=1,
        ),
        blocking=_policy("plan", source),
    )
    outer = next(_events("PORT_SCAN", 1, source, "198.51.100.2"))
    nested = replace(
        outer,
        observed_at=outer.observed_at + timedelta(milliseconds=1),
        src_ip="8.8.4.4",
        dst_port=2000,
    )

    with Store(settings.db_path) as store:
        service, planner = _service(settings, store, monkeypatch)
        planner.side_effect = lambda *_args, **_kwargs: service.process(nested)

        with caplog.at_level(logging.INFO, logger="megalodon.service"):
            with pytest.raises(RuntimeError, match="preparation already pending"):
                service.process(outer)

        assert store.summary() == {
            "events": 0,
            "detections": 0,
            "high_or_critical": 0,
            "actions": 0,
        }
        assert source not in service.detector.port_windows
        assert source not in service.detector.port_counts
        assert nested.src_ip not in service.detector.port_windows
        assert service.detector.source_high_watermarks == {}
        assert service.detector.last_emitted == {}
        assert service.detector._pending_token is None
        assert caplog.records == []

        planner.side_effect = None
        assert [item.rule_id for item in service.process(outer)] == ["PORT_SCAN"]
        assert service.detector.port_counts[source] == Counter({1000: 1})
        assert store.summary() == {
            "events": 1,
            "detections": 1,
            "high_or_critical": 0,
            "actions": 1,
        }


def test_signal_after_prepare_return_uses_detector_owned_rollback_handle(
    tmp_path, monkeypatch, caplog
):
    settings = Settings(
        db_path=tmp_path / "prepare-signal.db",
        detection=DetectionSettings(
            syn_flood_threshold=100,
            port_scan_distinct_ports=1,
        ),
    )
    event = next(_events("PORT_SCAN", 1, "8.8.8.8", "198.51.100.2"))

    with Store(settings.db_path) as store:
        service, _ = _service(settings, store, monkeypatch)
        original_prepare = service.detector.prepare

        def interrupt_after_prepare(candidate):
            prepared = original_prepare(candidate)
            signal.raise_signal(signal.SIGTERM)
            return prepared

        def interrupt(_signum, _frame):
            raise KeyboardInterrupt

        monkeypatch.setattr(service.detector, "prepare", interrupt_after_prepare)
        previous = signal.signal(signal.SIGTERM, interrupt)
        try:
            with caplog.at_level(logging.INFO, logger="megalodon.service"):
                with pytest.raises(KeyboardInterrupt):
                    service.process(event)
        finally:
            signal.signal(signal.SIGTERM, previous)

        assert store.summary() == {
            "events": 0,
            "detections": 0,
            "high_or_critical": 0,
            "actions": 0,
        }
        assert event.src_ip not in service.detector.port_windows
        assert event.src_ip not in service.detector.port_counts
        assert service.detector.source_high_watermarks == {}
        assert service.detector.last_emitted == {}
        assert service.detector._pending_token is None
        assert caplog.records == []


def test_interleaved_service_calls_serialize_prepare_through_resolution(tmp_path):
    first_entered = Event()
    release_first = Event()
    second_attempted = Event()
    second_entered = Event()

    class BlockingStore:
        def __init__(self):
            self.committed = []

        def record_event_bundle(self, event, detections, actions, *, run_id=None):
            assert detections == []
            assert actions == []
            assert run_id is None
            if event.dst_port == 21:
                first_entered.set()
                if not release_first.wait(timeout=2):
                    raise AssertionError("test did not release the first storage call")
                raise sqlite3.OperationalError("synthetic first-call failure")
            second_entered.set()
            self.committed.append(event)
            return len(self.committed)

    settings = Settings(
        db_path=tmp_path / "unused.db",
        detection=DetectionSettings(
            syn_flood_threshold=100,
            port_scan_distinct_ports=100,
        ),
    )
    store = BlockingStore()
    service = MegalodonService(settings, store)
    first = PacketEvent.from_mapping(
        {
            "observed_at": OBSERVED_AT,
            "src_ip": "8.8.8.8",
            "dst_ip": "198.51.100.2",
            "protocol": "TCP",
            "dst_port": 21,
            "tcp_flags": ["ACK"],
        }
    )
    second = replace(
        first,
        observed_at=first.observed_at + timedelta(milliseconds=1),
        dst_port=22,
    )

    def process_second():
        second_attempted.set()
        return service.process(second)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(service.process, first)
        assert first_entered.wait(timeout=2)
        second_future = executor.submit(process_second)
        assert second_attempted.wait(timeout=2)
        try:
            assert not second_entered.wait(timeout=0.05)
        finally:
            release_first.set()
        with pytest.raises(sqlite3.OperationalError, match="first-call failure"):
            first_future.result(timeout=2)
        assert second_future.result(timeout=2) == []

    assert store.committed == [second]
    assert tuple(service.detector.port_windows["8.8.8.8"]) == (
        (second.observed_at.timestamp(), 22),
    )
    assert service.detector.port_counts["8.8.8.8"] == Counter({22: 1})
    assert service.detector.source_high_watermarks["8.8.8.8"] == (
        second.observed_at.timestamp()
    )
    assert service.detector._pending_token is None
