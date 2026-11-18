from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import tempfile

import pytest

from megalodon import rule_catalog
from megalodon.config import BlockingSettings, Settings, load_settings
from megalodon.detector_registry import RULE_IDS
from megalodon.models import PacketEvent
from megalodon.service import MegalodonService
from megalodon.storage import Store
from megalodon.threat_detector import (
    AUTH_SERVICES, ThreatDetectionSettings, ThreatDetector, is_internal, is_public,
    registry_document,
)
from megalodon.validation import ValidationError
from megalodon.watchlist import (
    Watchlist, load_watchlist, parse_indicator, parse_lines, render, stix_indicators,
    write_private,
)

T0 = datetime(2030, 1, 1, tzinfo=timezone.utc)
LAN_A, LAN_B = "192.168.1.10", "192.168.1.20"
PUBLIC = "8.8.4.4"


def syn(src, dst, port, at, flags=("SYN",), protocol="TCP", byte_count=60):
    return PacketEvent(at, src, dst, protocol, src_port=40000, dst_port=port,
                       tcp_flags=frozenset(flags), byte_count=byte_count)


def rules(results):
    return [item.rule_id for item in results]


def state(detector):
    return copy.deepcopy((detector.brute, dict(detector.sweep), detector.exfil,
                          detector.exfil_totals, detector.beacon, detector.last_emitted,
                          list(detector.lru)))


# --------------------------------------------------------------- catalog
def test_catalog_core_rules_match_the_specification_registry():
    assert set(rule_catalog.CORE_RULE_IDS) == set(RULE_IDS)
    assert set(rule_catalog.THREAT_RULE_IDS) == {
        "BRUTE_FORCE", "HOST_SWEEP", "DATA_EXFILTRATION", "BEACONING", "DECOY_TOUCH", "IOC_MATCH",
        "DGA_DOMAIN", "DNS_TUNNEL_CHURN", "TLS_WITHOUT_SNI"}
    assert not set(rule_catalog.THREAT_RULE_IDS) & set(RULE_IDS)
    assert '"BEACONING"' in rule_catalog.browser_constants()


def test_registry_document_is_descriptive_only():
    document = registry_document()
    assert document["network_access_performed"] is False
    assert [item["rule_id"] for item in document["rules"]] == list(rule_catalog.THREAT_RULE_IDS)
    assert document["auth_services"]["22"] == "ssh"


def test_address_classes_exclude_documentation_ranges():
    assert is_internal("10.1.2.3") and is_internal("fd00::1") and is_internal("100.64.0.9")
    assert is_internal("::ffff:192.168.0.4") and is_internal("fe80::1")
    assert not is_internal("192.0.2.1") and not is_internal("2001:db8::1")
    assert not is_internal("224.0.0.251") and not is_internal("255.255.255.255")
    assert is_public("8.8.8.8") and not is_public("192.0.2.1") and not is_public("10.0.0.1")


# ----------------------------------------------------------- brute force
def test_brute_force_threshold_window_and_cooldown():
    detector = ThreatDetector()
    for i in range(14):
        assert detector.analyze(syn("198.51.100.9", LAN_A, 22, T0 + timedelta(seconds=i))) == []
    found = detector.analyze(syn("198.51.100.9", LAN_A, 22, T0 + timedelta(seconds=14)))
    assert rules(found) == ["BRUTE_FORCE"]
    evidence = found[0].evidence
    assert evidence["attempts"] == 15 and evidence["service"] == "ssh"
    assert evidence["response_target"] == "198.51.100.9"
    assert found[0].severity == "HIGH"
    # Cooldown suppresses repeats for the same (source, host, service).
    assert detector.analyze(syn("198.51.100.9", LAN_A, 22, T0 + timedelta(seconds=15))) == []
    # A different service on the same host is a separate key.
    assert len(detector.brute) == 1


def test_brute_force_ignores_replies_other_ports_and_slow_attempts():
    detector = ThreatDetector()
    for i in range(30):
        at = T0 + timedelta(seconds=i)
        assert detector.analyze(syn("198.51.100.9", LAN_A, 22, at, flags=("SYN", "ACK"))) == []
        assert detector.analyze(syn("198.51.100.9", LAN_A, 8080, at)) == []
    slow = ThreatDetector()
    for i in range(40):
        # One attempt every 5 s: at most 13 inside any inclusive 60 s window.
        assert slow.analyze(syn("198.51.100.9", LAN_A, 3389, T0 + timedelta(seconds=5 * i))) == []


def test_brute_force_window_is_inclusive_and_bounded_by_threshold():
    detector = ThreatDetector(ThreatDetectionSettings(brute_force_attempts=3,
                                                      brute_force_window_seconds=10))
    detector.analyze(syn("198.51.100.9", LAN_A, 445, T0))
    detector.analyze(syn("198.51.100.9", LAN_A, 445, T0 + timedelta(seconds=5)))
    found = detector.analyze(syn("198.51.100.9", LAN_A, 445, T0 + timedelta(seconds=10)))
    assert rules(found) == ["BRUTE_FORCE"] and found[0].evidence["service"] == "smb"
    for i in range(50):
        detector.analyze(syn("198.51.100.9", LAN_A, 445, T0 + timedelta(seconds=11 + i)))
    assert max(len(window) for window in detector.brute.values()) <= 3


# -------------------------------------------------------------- host sweep
def test_host_sweep_counts_distinct_internal_hosts():
    detector = ThreatDetector()
    for i in range(23):
        event = syn(LAN_A, f"192.168.1.{100 + i}", 445, T0 + timedelta(milliseconds=100 * i))
        assert "HOST_SWEEP" not in rules(detector.analyze(event))
    found = detector.analyze(PacketEvent(T0 + timedelta(seconds=3), LAN_A, "192.168.1.200", "ICMP"))
    assert rules(found) == ["HOST_SWEEP"]
    assert found[0].evidence["distinct_hosts"] == 24
    assert found[0].suppressed_reason is None  # no allowlist configured here


def test_host_sweep_ignores_public_dns_multicast_and_repeats():
    detector = ThreatDetector()
    for i in range(60):
        at = T0 + timedelta(milliseconds=10 * i)
        detector.analyze(syn(LAN_A, f"8.8.{i}.8", 443, at))  # public: not a sweep
        detector.analyze(PacketEvent(at, LAN_A, f"10.0.0.{i + 1}", "UDP", dst_port=53))
        detector.analyze(PacketEvent(at, LAN_A, "224.0.0.251", "UDP", dst_port=9999))
        assert "HOST_SWEEP" not in rules(detector.analyze(syn(LAN_A, LAN_B, 80, at)))


def test_host_sweep_window_expires_old_hosts():
    detector = ThreatDetector(ThreatDetectionSettings(host_sweep_distinct_hosts=3,
                                                      host_sweep_window_seconds=5))
    detector.analyze(syn(LAN_A, "10.0.0.1", 22, T0))
    detector.analyze(syn(LAN_A, "10.0.0.2", 22, T0 + timedelta(seconds=1)))
    assert detector.analyze(syn(LAN_A, "10.0.0.3", 22, T0 + timedelta(seconds=7))) == []
    found = detector.analyze(syn(LAN_A, "10.0.0.4", 22, T0 + timedelta(seconds=8)))
    assert rules(found) == []  # 10.0.0.2 expired at t=8 > 1+5; only 3 and 4 remain
    assert rules(detector.analyze(syn(LAN_A, "10.0.0.5", 22, T0 + timedelta(seconds=9)))) == ["HOST_SWEEP"]


# ------------------------------------------------------------ exfiltration
def test_exfiltration_sums_outbound_bytes_to_one_public_address():
    detector = ThreatDetector(ThreatDetectionSettings(exfiltration_threshold_mib=10,
                                                      exfiltration_window_seconds=60))
    chunk = 1024 * 1024
    for i in range(9):
        event = PacketEvent(T0 + timedelta(seconds=i), LAN_A, PUBLIC, "TCP",
                            dst_port=443, tcp_flags=frozenset({"ACK", "PSH"}), byte_count=chunk)
        assert detector.analyze(event) == []
    # Downloads (public -> internal) never count.
    detector.analyze(PacketEvent(T0 + timedelta(seconds=9), PUBLIC, LAN_A, "TCP",
                                 byte_count=50 * chunk))
    found = detector.analyze(PacketEvent(T0 + timedelta(seconds=9, milliseconds=5), LAN_A,
                                         PUBLIC, "TCP", byte_count=chunk))
    assert rules(found) == ["DATA_EXFILTRATION"]
    assert found[0].evidence["mebibytes"] == 10
    assert found[0].evidence["bytes"] == str(10 * chunk)
    assert found[0].evidence["response_target"] == PUBLIC


def test_exfiltration_window_slides_and_buckets_stay_bounded():
    detector = ThreatDetector(ThreatDetectionSettings(exfiltration_threshold_mib=5,
                                                      exfiltration_window_seconds=10))
    for i in range(200):
        # 1 MiB every 3 s never reaches 5 MiB inside 10 s.
        event = PacketEvent(T0 + timedelta(seconds=3 * i), LAN_A, PUBLIC, "TCP",
                            byte_count=1024 * 1024)
        assert detector.analyze(event) == []
    assert max(len(buckets) for buckets in detector.exfil.values()) <= 10
    key = next(iter(detector.exfil))
    assert detector.exfil_totals[key] == sum(b for _, b in detector.exfil[key])


# --------------------------------------------------------------- beaconing
def test_beaconing_detects_regular_connection_starts():
    detector = ThreatDetector()
    found = []
    for i in range(9):
        at = T0 + timedelta(seconds=60 * i, milliseconds=(i % 3) * 200)
        found = detector.analyze(syn(LAN_A, PUBLIC, 8443, at))
        if i < 8:
            assert found == []
    assert rules(found) == ["BEACONING"]
    assert found[0].evidence["intervals"] == 8
    assert found[0].evidence["window_seconds"] == 60
    assert found[0].evidence["response_target"] == PUBLIC


def test_beaconing_rejects_jitter_retransmits_and_internal_peers():
    jittery = ThreatDetector()
    for i, offset in enumerate([0, 30, 95, 120, 200, 230, 330, 345, 420, 500]):
        assert jittery.analyze(syn(LAN_A, PUBLIC, 443, T0 + timedelta(seconds=offset))) == []
    retry = ThreatDetector()
    for i in range(9):
        base = T0 + timedelta(seconds=60 * i)
        retry.analyze(syn(LAN_A, PUBLIC, 443, base))
        # SYN retransmits 1 s and 3 s later collapse into the same contact.
        retry.analyze(syn(LAN_A, PUBLIC, 443, base + timedelta(seconds=1)))
        last = retry.analyze(syn(LAN_A, PUBLIC, 443, base + timedelta(seconds=3)))
    assert max(len(item) for item in retry.beacon.values()) == 9
    internal = ThreatDetector()
    for i in range(20):
        assert internal.analyze(syn(LAN_A, LAN_B, 443, T0 + timedelta(seconds=60 * i))) == []


# -------------------------------------------------------------- watchlist
def test_watchlist_longest_prefix_and_ipv4_mapped_folding():
    watchlist = Watchlist(parse_lines([
        "# header", "", "203.0.113.0/24  # scanner range",
        "203.0.113.7 # exact host", "::ffff:198.51.100.0/120 # mapped",
        "2001:db8:bad::/48",
    ]))
    assert len(watchlist) == 4
    assert watchlist.match("203.0.113.7") == ("203.0.113.7", "exact host")
    assert watchlist.match("203.0.113.8") == ("203.0.113.0/24", "scanner range")
    assert watchlist.match("198.51.100.200") == ("198.51.100.0/24", "mapped")
    assert watchlist.match("::ffff:203.0.113.9")[0] == "203.0.113.0/24"
    assert watchlist.match("2001:db8:bad:1::5") == ("2001:db8:bad::/48", "")
    assert watchlist.match("8.8.8.8") is None


@pytest.mark.parametrize("line", ["0.0.0.0/0", "10.0.0.0/7", "::/0", "2001::/15",
                                  "not-an-ip", "fe80::1%eth0", "1.2.3.4 5.6.7.8"])
def test_watchlist_refuses_broad_or_malformed_indicators(line):
    with pytest.raises(ValidationError, match="line 1"):
        parse_lines([line])


def test_ioc_match_on_either_direction_with_cooldown():
    watchlist = Watchlist(parse_lines(["203.0.113.66 # known c2"]), severity="CRITICAL")
    detector = ThreatDetector(watchlist=watchlist)
    outbound = detector.analyze(syn(LAN_A, "203.0.113.66", 443, T0))
    assert rules(outbound) == ["IOC_MATCH"]
    finding = outbound[0]
    assert finding.severity == "CRITICAL"
    assert finding.evidence["matched_direction"] == "destination"
    assert finding.evidence["indicator_label"] == "known c2"
    assert finding.evidence["response_target"] == "203.0.113.66"
    assert detector.analyze(syn("203.0.113.66", LAN_A, 22, T0 + timedelta(seconds=1))) == []
    later = detector.analyze(syn("203.0.113.66", LAN_A, 22, T0 + timedelta(seconds=601)))
    assert later[0].evidence["matched_direction"] == "source"


def test_allowlisted_response_target_is_suppressed_not_dropped():
    allow = (ipaddress.ip_network("203.0.113.0/24"),)
    watchlist = Watchlist(parse_lines(["203.0.113.66"]))
    detector = ThreatDetector(allowlist=allow, watchlist=watchlist)
    found = detector.analyze(syn(LAN_A, "203.0.113.66", 443, T0))
    assert found[0].suppressed_reason == "target_allowlisted"


def _private_file(directory, text, mode=0o600):
    path = Path(directory) / "watch.txt"
    path.write_text(text, encoding="utf-8")
    os.chmod(path, mode)
    return path


def test_watchlist_file_must_be_private_regular_and_bounded():
    with tempfile.TemporaryDirectory() as directory:
        path = _private_file(directory, "198.51.100.1 # lab\n")
        assert len(load_watchlist(path)) == 1
        os.chmod(path, 0o620)
        with pytest.raises(ValidationError, match="group- or world-writable"):
            load_watchlist(path)
        os.chmod(path, 0o600)
        link = Path(directory) / "link.txt"
        link.symlink_to(path)
        with pytest.raises(ValidationError, match="cannot be opened"):
            load_watchlist(link)
        with pytest.raises(ValidationError, match="regular file"):
            load_watchlist(directory)


def test_write_private_is_atomic_owner_only_and_refuses_overwrite():
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / "out.txt"
        entries = parse_lines(["198.51.100.1 # a", "198.51.100.1 # dup", "2001:db8::/64"])
        write_private(target, render(entries, "test header"))
        assert os.stat(target).st_mode & 0o777 == 0o600
        assert target.read_text().splitlines() == ["# test header", "198.51.100.1  # a",
                                                   "2001:db8::/64"]
        with pytest.raises(ValidationError, match="--replace"):
            write_private(target, "x\n")
        write_private(target, "203.0.113.1\n", replace=True)
        assert len(load_watchlist(target)) == 1


def test_stix_conversion_accepts_only_ip_equality_patterns():
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    objects = [
        {"type": "indicator", "id": "indicator--1", "name": "c2 host", "pattern_type": "stix",
         "pattern": "[ipv4-addr:value = '203.0.113.5' OR ipv4-addr:value = '198.51.100.0/24']"},
        {"type": "indicator", "id": "indicator--2", "pattern_type": "stix",
         "pattern": "[ipv6-addr:value = '2001:db8::5']"},
        {"type": "indicator", "id": "indicator--3", "pattern_type": "stix",
         "pattern": "[domain-name:value = 'example.com']"},
        {"type": "indicator", "id": "indicator--4", "pattern_type": "stix",
         "pattern": "[ipv4-addr:value = '203.0.113.5'] AND [file:name = 'x']"},
        {"type": "indicator", "id": "indicator--5", "pattern_type": "stix", "revoked": True,
         "pattern": "[ipv4-addr:value = '203.0.113.6']"},
        {"type": "indicator", "id": "indicator--6", "pattern_type": "stix",
         "valid_until": "2029-01-01T00:00:00Z", "pattern": "[ipv4-addr:value = '203.0.113.7']"},
        {"type": "indicator", "id": "indicator--7", "pattern_type": "stix",
         "pattern": "[ipv4-addr:value = '0.0.0.0/0']"},
        {"type": "indicator", "id": "indicator--8", "pattern_type": "stix",
         "pattern": "[ipv6-addr:value = '203.0.113.9']"},
        {"type": "malware", "id": "malware--1"},
    ]
    entries, counts = stix_indicators(objects, now=now)
    assert [str(network) for network, _ in entries] == [
        "203.0.113.5/32", "198.51.100.0/24", "2001:db8::5/128", "example.com"]
    assert entries[0][1] == "c2 host"
    assert counts == {"converted": 3, "skipped_pattern": 1, "skipped_revoked": 1,
                      "skipped_expired": 1, "skipped_invalid": 2}


# ------------------------------------------------------- atomicity/bounds
@pytest.mark.parametrize("events", [
    [syn("198.51.100.9", LAN_A, 22, T0 + timedelta(seconds=i)) for i in range(15)],
    [syn(LAN_A, f"10.0.0.{i + 1}", 22, T0 + timedelta(milliseconds=i)) for i in range(24)],
    [PacketEvent(T0 + timedelta(seconds=i), LAN_A, PUBLIC, "TCP", byte_count=60 * 1024 * 1024)
     for i in range(2)],
    [syn(LAN_A, PUBLIC, 443, T0 + timedelta(seconds=30 * i)) for i in range(9)],
    [syn(LAN_A, "203.0.113.66", 443, T0)],
])
def test_rollback_restores_exact_state_for_every_rule(events):
    detector = ThreatDetector(watchlist=Watchlist(parse_lines(["203.0.113.66"])))
    for event in events[:-1]:
        detector.analyze(event)
    before = state(detector)
    prepared = detector.prepare(events[-1])
    assert prepared.results, "the final event should produce a finding"
    with pytest.raises(RuntimeError, match="already pending"):
        detector.prepare(events[-1])
    prepared.rollback()
    assert state(detector) == before
    # And the same event still alerts after a rollback: no cooldown was consumed.
    assert detector.analyze(events[-1])


def test_lru_bounds_total_tracked_keys():
    detector = ThreatDetector(ThreatDetectionSettings(max_tracked_keys=64))
    for i in range(2000):
        detector.analyze(syn(f"198.51.{i // 250}.{i % 250 + 1}", LAN_A, 22,
                             T0 + timedelta(milliseconds=i)))
    assert len(detector.lru) <= 64
    assert detector.state_size() <= 64


def test_disabled_layer_emits_nothing():
    detector = ThreatDetector(ThreatDetectionSettings(enabled=False))
    for i in range(30):
        assert detector.analyze(syn("198.51.100.9", LAN_A, 22, T0 + timedelta(seconds=i))) == []


@pytest.mark.parametrize("field,value", [
    ("brute_force_attempts", 1), ("host_sweep_window_seconds", 0),
    ("exfiltration_threshold_mib", 70000), ("beacon_jitter_percent", 80),
    ("max_tracked_keys", True), ("beacon_min_interval_seconds", 4000),
])
def test_settings_are_bounded(field, value):
    with pytest.raises(ValueError):
        ThreatDetectionSettings(**{field: value})


def test_auth_services_are_fixed_well_known_ports():
    assert AUTH_SERVICES[22] == "ssh" and AUTH_SERVICES[3389] == "rdp"
    assert all(0 < port < 65536 for port in AUTH_SERVICES)


def test_lost_handle_is_unwound_by_rollback_pending():
    detector = ThreatDetector()
    events = [syn("198.51.100.9", LAN_A, 22, T0 + timedelta(seconds=i)) for i in range(15)]
    for event in events[:-1]:
        detector.analyze(event)
    before = state(detector)
    detector.prepare(events[-1])  # handle deliberately dropped
    assert detector.rollback_pending() is True
    assert state(detector) == before and detector._pending is None
    assert detector.rollback_pending() is False
    assert rules(detector.analyze(events[-1])) == ["BRUTE_FORCE"]


def test_cooled_down_source_does_not_hide_a_new_destination_indicator():
    watchlist = Watchlist(parse_lines(["203.0.113.66 # a", "198.51.100.77 # b"]))
    detector = ThreatDetector(watchlist=watchlist)
    first = detector.analyze(syn("203.0.113.66", LAN_A, 443, T0))
    assert first[0].evidence["matched_address"] == "203.0.113.66"
    second = detector.analyze(syn("203.0.113.66", "198.51.100.77", 443, T0 + timedelta(seconds=1)))
    assert rules(second) == ["IOC_MATCH"]
    assert second[0].evidence["matched_direction"] == "destination"
    assert second[0].evidence["response_target"] == "198.51.100.77"


def test_watchlist_fifo_is_refused_without_blocking():
    import threading
    with tempfile.TemporaryDirectory() as directory:
        fifo = Path(directory) / "pipe"
        os.mkfifo(fifo, 0o600)
        outcome = []

        def attempt():
            try:
                load_watchlist(fifo)
            except ValidationError as exc:
                outcome.append(str(exc))

        worker = threading.Thread(target=attempt, daemon=True)
        worker.start()
        worker.join(5)
        assert not worker.is_alive(), "opening a writer-less FIFO blocked"
        assert outcome == ["watchlist must be a regular file"]


# ------------------------------------------------------------------ decoys
def test_decoy_address_and_port_are_high_confidence_tripwires():
    settings = ThreatDetectionSettings(decoy_ports=(2222, 4455), decoy_addresses=("192.168.1.250",))
    detector = ThreatDetector(settings)
    found = detector.analyze(PacketEvent(T0, LAN_A, "192.168.1.250", "ICMP"))
    assert rules(found) == ["DECOY_TOUCH"]
    assert found[0].severity == "CRITICAL"
    assert found[0].evidence["decoy_kind"] == "address"
    assert found[0].evidence["response_target"] == LAN_A
    port = detector.analyze(syn("198.51.100.4", LAN_B, 2222, T0 + timedelta(seconds=1)))
    assert rules(port) == ["DECOY_TOUCH"] and port[0].evidence["decoy"] == "2222"
    udp = detector.analyze(PacketEvent(T0 + timedelta(seconds=2), "198.51.100.5", LAN_B, "UDP",
                                       dst_port=4455))
    assert rules(udp) == ["DECOY_TOUCH"]


def test_decoy_ignores_replies_and_cools_down_per_source_and_decoy():
    settings = ThreatDetectionSettings(decoy_ports=(2222,), decoy_addresses=("192.168.1.250",))
    detector = ThreatDetector(settings)
    # An established-session packet to the port is not a new contact attempt.
    assert detector.analyze(syn(LAN_A, LAN_B, 2222, T0, flags=("ACK",))) == []
    # Traffic from the decoy address itself (e.g. an operator test box) is not a touch.
    assert detector.analyze(syn("192.168.1.250", LAN_B, 2222, T0)) == []
    assert rules(detector.analyze(syn(LAN_A, LAN_B, 2222, T0 + timedelta(seconds=1)))) == ["DECOY_TOUCH"]
    assert detector.analyze(syn(LAN_A, LAN_B, 2222, T0 + timedelta(seconds=2))) == []
    # A different source is a separate tripwire event.
    assert rules(detector.analyze(syn(LAN_B, LAN_A, 2222, T0 + timedelta(seconds=3)))) == ["DECOY_TOUCH"]


def test_no_decoys_configured_means_no_decoy_findings():
    detector = ThreatDetector()
    for port in (2222, 4455, 23):
        assert "DECOY_TOUCH" not in rules(detector.analyze(syn(LAN_A, LAN_B, port, T0)))


@pytest.mark.parametrize("kwargs", [
    {"decoy_ports": (0,)}, {"decoy_ports": (22, 22)}, {"decoy_ports": tuple(range(1, 66))},
    {"decoy_addresses": ("224.0.0.251",)}, {"decoy_addresses": ("127.0.0.1",)},
    {"decoy_addresses": ("bogus",)}, {"decoy_addresses": ("10.0.0.1", "::ffff:10.0.0.1")},
])
def test_decoy_settings_are_validated(kwargs):
    with pytest.raises(ValueError):
        ThreatDetectionSettings(**kwargs)


def test_decoy_rollback_restores_cooldown():
    detector = ThreatDetector(ThreatDetectionSettings(decoy_ports=(2222,)))
    before = state(detector)
    prepared = detector.prepare(syn(LAN_A, LAN_B, 2222, T0))
    assert rules(prepared.results) == ["DECOY_TOUCH"]
    prepared.rollback()
    assert state(detector) == before
    assert rules(detector.analyze(syn(LAN_A, LAN_B, 2222, T0))) == ["DECOY_TOUCH"]
