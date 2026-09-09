"""Finite synthetic rule acceptance; not a malware-effectiveness benchmark."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import socket
import subprocess

import pytest

from megalodon.config import DetectionSettings, load_settings
from megalodon.detector import Detector
from megalodon.models import PacketEvent


BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
SOURCE_A = "192.0.2.1"
SOURCE_B = "192.0.2.2"
RULES = ("SYN_FLOOD", "PORT_SCAN", "DNS_TUNNELING")
# Fixed expectations are independent of the settings/implementation under test.
BOUNDARIES = (
    ("syn-below", "SYN_FLOOD", 99, 0),
    ("syn-at", "SYN_FLOOD", 100, 1),
    ("syn-above", "SYN_FLOOD", 101, 1),
    ("ports-below", "PORT_SCAN", 19, 0),
    ("ports-at", "PORT_SCAN", 20, 1),
    ("ports-above", "PORT_SCAN", 21, 1),
    ("dns-below", "DNS_TUNNELING", 49, 0),
    ("dns-at", "DNS_TUNNELING", 50, 1),
    ("dns-above", "DNS_TUNNELING", 51, 1),
)


@pytest.fixture(autouse=True)
def no_process_or_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("detector evaluation must not launch a process or use the network")

    for owner, name in ((subprocess, "run"), (subprocess, "Popen"),
                        (os, "system"), (socket, "socket"), (socket, "create_connection")):
        monkeypatch.setattr(owner, name, forbidden)


def _event(rule, index=0, *, seconds=0, source=SOURCE_A, length=50, **changes):
    value = dict(observed_at=BASE + timedelta(seconds=seconds), src_ip=source,
                 dst_ip="198.51.100.2", protocol="TCP")
    if rule == "SYN_FLOOD":
        value.update(tcp_flags=["SYN"])
    elif rule == "PORT_SCAN":
        value.update(dst_port=1000 + index)
    else:
        assert rule == "DNS_TUNNELING"
        value.update(protocol="DNS", dst_port=53, dns_query_length=length)
    value.update(changes)
    return PacketEvent.from_mapping(value)


def _settings(**changes):
    return replace(DetectionSettings(), **changes)


def _rules(detector, events):
    return [result.rule_id for event in events for result in detector.analyze(event)]


@pytest.mark.parametrize("case_id,rule,quantity,expected", BOUNDARIES,
                         ids=[case[0] for case in BOUNDARIES])
def test_default_threshold_receipt(case_id, rule, quantity, expected):
    detector = Detector(DetectionSettings())
    events = ([_event(rule, length=quantity)] if rule == "DNS_TUNNELING" else
              [_event(rule, index, seconds=index / 1000) for index in range(quantity)])
    results = [result for event in events for result in detector.analyze(event)]
    assert [result.rule_id for result in results] == [rule] * expected, case_id
    for result in results:
        assert result.recommendation == "ALERT"
        assert result.suppressed_reason is None
        assert result.evidence == {
            "SYN_FLOOD": {"count": 100, "window_seconds": 10},
            "PORT_SCAN": {"distinct_ports": 20, "window_seconds": 5},
            "DNS_TUNNELING": {"dns_query_length": quantity, "threshold": 50},
        }[rule]


@pytest.mark.parametrize("rule,window", (("SYN_FLOOD", 10), ("PORT_SCAN", 5)))
@pytest.mark.parametrize("delta,expected", ((-0.000001, 1), (0, 1), (0.000001, 0)))
def test_sliding_window_includes_exact_cutoff(rule, window, delta, expected):
    detector = Detector(_settings(syn_flood_threshold=2, port_scan_distinct_ports=2))
    assert detector.analyze(_event(rule)) == []
    assert _rules(detector, [_event(rule, 1, seconds=window + delta)]) == [rule] * expected


@pytest.mark.parametrize("rule", RULES)
def test_cooldown_reopens_at_exact_boundary(rule):
    detector = Detector(_settings(syn_flood_threshold=1, port_scan_distinct_ports=1))
    assert _rules(detector, [_event(rule)]) == [rule]
    assert detector.analyze(_event(rule, seconds=29.999999)) == []
    assert _rules(detector, [_event(rule, seconds=30)]) == [rule]


@pytest.mark.parametrize("rule", RULES)
def test_equivalent_offset_normalizes_evidence_time(rule):
    detector = Detector(_settings(syn_flood_threshold=1, port_scan_distinct_ports=1))
    local_time = BASE.astimezone(timezone(timedelta(hours=-5))).isoformat()
    result = detector.analyze(_event(rule, observed_at=local_time))[0]
    assert result.detected_at == BASE
    assert result.detected_at.tzinfo == timezone.utc
    assert detector.analyze(_event(rule)) == []


@pytest.mark.parametrize("rule", ("SYN_FLOOD", "PORT_SCAN"))
def test_sources_do_not_share_threshold_or_cooldown(rule):
    detector = Detector(_settings(syn_flood_threshold=2, port_scan_distinct_ports=2))
    for source in (SOURCE_A, SOURCE_B):
        assert detector.analyze(_event(rule, source=source)) == []
    for source in (SOURCE_A, SOURCE_B):
        result = detector.analyze(_event(rule, 1, source=source))[0]
        assert result.rule_id == rule
        assert result.src_ip == source


@pytest.mark.parametrize("rule,window", (("SYN_FLOOD", 10), ("PORT_SCAN", 5)))
def test_expired_event_does_not_complete_new_window(rule, window):
    detector = Detector(_settings(syn_flood_threshold=2, port_scan_distinct_ports=2))
    assert detector.analyze(_event(rule)) == []
    assert detector.analyze(_event(rule, 1, seconds=window + 0.000001)) == []
    assert _rules(detector, [_event(rule, 2, seconds=window + 1)]) == [rule]


def test_repeated_syn_metadata_counts_events_not_unique_packets():
    detector = Detector(DetectionSettings())
    repeated = _event("SYN_FLOOD")
    assert _rules(detector, [repeated] * 100) == ["SYN_FLOOD"]


def test_repeated_destination_port_does_not_count_as_distinct_ports():
    detector = Detector(DetectionSettings())
    assert _rules(detector, [_event("PORT_SCAN")] * 100) == []


@pytest.mark.parametrize("changes", ({"tcp_flags": ["SYN", "ACK"]},
                                     {"tcp_flags": []}, {"protocol": "UDP"}))
def test_non_qualifying_syn_metadata_does_not_trigger(changes):
    detector = Detector(_settings(syn_flood_threshold=1))
    assert detector.analyze(_event("SYN_FLOOD", **changes)) == []


@pytest.mark.parametrize("protocol,expected", (("DNS", 1), ("UDP", 1), ("TCP", 0)))
def test_long_query_rule_protocol_boundary(protocol, expected):
    detector = Detector(DetectionSettings())
    assert _rules(detector, [_event("DNS_TUNNELING", protocol=protocol)]) == ["DNS_TUNNELING"] * expected


@pytest.mark.parametrize("rule", RULES)
def test_source_eviction_discards_cooldown_without_unbounded_history(rule):
    detector = Detector(_settings(max_tracked_sources=1, syn_flood_threshold=1,
                                  port_scan_distinct_ports=1))
    for source in (SOURCE_A, SOURCE_B, SOURCE_A):
        assert _rules(detector, [_event(rule, source=source)]) == [rule]
        assert len(detector.source_order) == 1
        assert len(detector.last_emitted) == 1
        assert set(detector.source_high_watermarks) == {source}
        assert set(detector.syn_windows) <= {source}
        assert set(detector.port_windows) <= {source}


@pytest.mark.parametrize("rule", ("SYN_FLOOD", "PORT_SCAN"))
def test_window_cap_below_threshold_is_a_detection_limit(rule):
    detector = Detector(_settings(max_events_per_source_window=2, syn_flood_threshold=3,
                                  port_scan_distinct_ports=3))
    assert _rules(detector, [_event(rule, index) for index in range(10)]) == []
    window = (detector.syn_windows if rule == "SYN_FLOOD" else detector.port_windows)[SOURCE_A]
    assert len(window) == 2


def test_shipped_configuration_matches_evaluated_defaults_and_stays_observe_only():
    settings = load_settings(Path(__file__).resolve().parents[1] / "config/settings.toml")
    assert settings.detection == DetectionSettings()
    assert settings.capture_source == "sample"
    assert settings.blocking.enabled is False
    assert settings.blocking.auto_block is False
    assert settings.blocking.dry_run is True
