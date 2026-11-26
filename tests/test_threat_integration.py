"""The threat-signal layer through the real service, store, projections and validators."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon import ai_context, rule_catalog
from megalodon.ai_broker import _recorded_measurement
from megalodon.config import Settings, load_settings
from megalodon.control_room_assets import ROOM_JS
from megalodon.dashboard_finding_evidence import FINDING_EVIDENCE_JS
from megalodon.dashboard_snapshot import SNAPSHOT_VALIDATOR_JS
from megalodon.dashboard_traffic import TrafficDashboardStore
from megalodon.hud_snapshot import snapshot_from_projection
from megalodon.models import PacketEvent
from megalodon.security_patterns import CONTEXT, REFERENCE_LINKS
from megalodon.service import MegalodonService
from megalodon.storage import Store
from megalodon.threat_detector import ThreatDetectionSettings
from megalodon.validation import ValidationError

LAN, PUBLIC = "192.168.7.10", "8.8.4.4"


def now():
    return datetime.now(timezone.utc) - timedelta(seconds=120)


def brute_events(start, count=15):
    return [PacketEvent(start + timedelta(seconds=i), "203.0.113.9", LAN, "TCP", src_port=50000 + i,
                        dst_port=22, tcp_flags=frozenset({"SYN"}), byte_count=60)
            for i in range(count)]


def exfil_events(start):
    return [PacketEvent(start + timedelta(seconds=i), LAN, PUBLIC, "TCP", src_port=40000, dst_port=443,
                        tcp_flags=frozenset({"ACK"}), byte_count=60 * 1024 * 1024) for i in range(2)]


def run_through(settings, events):
    with Store(settings.db_path) as store:
        service = MegalodonService(settings, store)
        run_id = store.start_ingestion_run("jsonl")
        found = []
        for event in events:
            found.extend(service.process(event, run_id=run_id))
        store.finish_ingestion_run(run_id, "source_exhausted")
        return found


def test_service_records_threat_findings_and_targets_the_response_party(tmp_path):
    settings = Settings(db_path=tmp_path / "audit.db")
    start = now()
    found = run_through(settings, brute_events(start) + exfil_events(start + timedelta(seconds=20)))
    assert [item.rule_id for item in found] == ["BRUTE_FORCE", "DATA_EXFILTRATION"]
    with Store(settings.db_path) as store:
        connection = store.connection if hasattr(store, "connection") else store._connection
        targets = [row[0] for row in connection.execute("SELECT target FROM actions ORDER BY id")]
    # Brute force targets the attacker; exfiltration targets the public receiver.
    assert targets == ["203.0.113.9", PUBLIC]


def test_one_packet_crossing_four_rules_at_once_is_recorded_not_a_failed_run(tmp_path):
    # A sweep's 24th host that is a decoy, reached on a scan's 20th port as a flood's 100th SYN: four rules at once.
    # The audit store once refused more than three, so one such packet, crafted or not, stopped the sensor.
    from dataclasses import replace
    from megalodon.rule_catalog import ALL_RULE_IDS
    from megalodon.storage import MAX_DETECTIONS_PER_EVENT
    hosts = [f"192.168.7.{n}" for n in range(1, 25)]
    start = now()
    events = [PacketEvent(start + timedelta(milliseconds=20 * i), "203.0.113.9", hosts[i % 23], "TCP",
                          src_port=40000 + i, dst_port=1000 + i % 19, tcp_flags=frozenset({"SYN"}), byte_count=60)
              for i in range(99)]
    events.append(PacketEvent(start + timedelta(milliseconds=1980), "203.0.113.9", hosts[-1], "TCP", src_port=41000,
                              dst_port=5000, tcp_flags=frozenset({"SYN"}), byte_count=60))
    settings = replace(Settings(db_path=tmp_path / "audit.db"), threat=ThreatDetectionSettings(decoy_addresses=(hosts[-1],)))
    found = run_through(settings, events)
    assert sorted(f.rule_id for f in found[-4:]) == ["DECOY_TOUCH", "HOST_SWEEP", "PORT_SCAN", "SYN_FLOOD"]
    assert len({f.detected_at for f in found[-4:]}) == 1, "all four on the same packet"
    with Store(settings.db_path) as store:
        assert store.summary()["detections"] == len(found)
    assert MAX_DETECTIONS_PER_EVENT == len(ALL_RULE_IDS), "each rule fires at most once per packet"


def test_failed_persistence_rolls_back_threat_state(tmp_path):
    settings = Settings(db_path=tmp_path / "audit.db")
    events = brute_events(now())
    with Store(settings.db_path) as store:
        service = MegalodonService(settings, store)
        for event in events[:-1]:
            service.process(event)
        original = store.record_event_bundle

        def fail(*args, **kwargs):
            raise OSError("disk unavailable")

        store.record_event_bundle = fail
        with pytest.raises(OSError):
            service.process(events[-1])
        store.record_event_bundle = original
        assert service.threat_detector._pending is None
        # The retried event still produces the finding: no attempt or cooldown leaked.
        assert [item.rule_id for item in service.process(events[-1])] == ["BRUTE_FORCE"]


def test_projection_ai_and_snapshot_accept_every_threat_rule(tmp_path):
    settings = Settings(db_path=tmp_path / "audit.db",
                        threat=ThreatDetectionSettings(host_sweep_distinct_hosts=3,
                                                       beacon_min_intervals=3))
    start = now()
    sweep = [PacketEvent(start + timedelta(seconds=30, milliseconds=i), LAN, f"192.168.7.{50 + i}",
                         "ICMP") for i in range(3)]
    beacon = [PacketEvent(start + timedelta(seconds=40 + 10 * i), LAN, "9.9.9.9", "TCP",
                          src_port=41000 + i, dst_port=8443, tcp_flags=frozenset({"SYN"}))
              for i in range(4)]
    found = run_through(settings, brute_events(start) + exfil_events(start + timedelta(seconds=20))
                        + sweep + beacon)
    assert {item.rule_id for item in found} == {"BRUTE_FORCE", "DATA_EXFILTRATION", "HOST_SWEEP",
                                                "BEACONING"}
    with TrafficDashboardStore(settings.db_path) as reader:
        traffic = reader.traffic()
    measured = {item["rule_id"]: item["measurement"] for item in traffic["findings"]}
    assert measured["BRUTE_FORCE"] == {"value": 15, "threshold": 15, "window_seconds": 60,
                                       "unit": "connection attempts"}
    assert measured["DATA_EXFILTRATION"]["unit"] == "MiB sent outbound"
    assert measured["BEACONING"]["window_seconds"] == 10
    for rule, measurement in measured.items():
        assert _recorded_measurement(rule, measurement) == measurement
    snapshot = snapshot_from_projection(traffic)
    assert len(snapshot["detectors"]) == len(rule_catalog.ALL_RULE_IDS)
    assert sum(snapshot["detectors"]) == snapshot["findings"]
    node = shutil.which("node")
    if node:
        legacy = dict(snapshot, detectors=[0, 0, 0], findings=0, severities=[0, 0, 0, 0],
                      lanes=[snapshot["events"], 0, 0])
        before_decoys = dict(legacy, detectors=[0] * 8)
        script = SNAPSHOT_VALIDATOR_JS + (
            "\nconst [a,b,c]=JSON.parse(require('fs').readFileSync(0,'utf8'));"
            "validateHudSnapshot(a);validateHudSnapshot(b);validateHudSnapshot(c);"
            "try{validateHudSnapshot(JSON.stringify(Object.assign(JSON.parse(a),{detectors:[1]})));"
            "process.exit(3)}catch(e){}")
        subprocess.run([node, "-e", script], check=True, timeout=10, text=True,
                       input=json.dumps([json.dumps(snapshot), json.dumps(legacy),
                                         json.dumps(before_decoys)]))


def test_every_catalog_rule_has_consumer_context():
    for rule in rule_catalog.ALL_RULE_IDS:
        assert rule in CONTEXT and rule in REFERENCE_LINKS
    assert ai_context.RULES == frozenset(rule_catalog.ALL_RULE_IDS)
    assert "__RULE_CATALOG__" not in ROOM_JS and "__RULE_CATALOG__" not in FINDING_EVIDENCE_JS
    assert '"IOC_MATCH"' in ROOM_JS and '"IOC_MATCH"' in FINDING_EVIDENCE_JS


def test_core_explanations_are_unchanged_by_the_catalog():
    summaries = json.loads(rule_catalog.browser_constants())["summaries"]
    assert summaries["DNS_TUNNELING"] == (
        "The recorded DNS_TUNNELING rule identifies DNS metadata for review. A long DNS query "
        "can be legitimate; this finding does not prove tunneling.")


def _toml(tmp_path, body):
    path = tmp_path / "settings.toml"
    path.write_text(body, encoding="utf-8")
    return path


def test_threat_settings_parse_refuse_unknown_and_bound(tmp_path):
    settings = load_settings(_toml(tmp_path, "[threat_detection]\nbrute_force_attempts = 5\n"
                                             'watchlist_severity = "critical"\n'))
    assert settings.threat.brute_force_attempts == 5
    assert settings.threat.watchlist_severity == "CRITICAL"
    for body in ("[threat_detection]\nbrute_force_attempt = 5\n",
                 "[threat_detection]\nbrute_force_attempts = 1\n",
                 '[threat_detection]\nbrute_force_attempts = "5"\n',
                 '[threat_detection]\nenabled = "yes"\n',
                 '[threat_detection]\nwatchlist_severity = "URGENT"\n'):
        with pytest.raises(ValidationError):
            load_settings(_toml(tmp_path, body))


def test_configured_watchlist_drives_ioc_and_unreadable_one_refuses_startup(tmp_path):
    watch = tmp_path / "watch.txt"
    watch.write_text("203.0.113.66 # lab c2\n", encoding="utf-8")
    os.chmod(watch, 0o600)
    settings = Settings(db_path=tmp_path / "audit.db",
                        threat=ThreatDetectionSettings(watchlist_path=str(watch),
                                                       watchlist_severity="CRITICAL"))
    found = run_through(settings, [PacketEvent(now(), LAN, "203.0.113.66", "TCP", dst_port=443,
                                               tcp_flags=frozenset({"SYN"}))])
    assert [(item.rule_id, item.severity) for item in found] == [("IOC_MATCH", "CRITICAL")]
    missing = Settings(db_path=tmp_path / "other.db",
                       threat=ThreatDetectionSettings(watchlist_path=str(tmp_path / "absent.txt")))
    with Store(missing.db_path) as store, pytest.raises(ValidationError, match="cannot be opened"):
        MegalodonService(missing, store)


def test_shipped_settings_file_matches_code_defaults():
    shipped = load_settings(Path(__file__).resolve().parents[1] / "config" / "settings.toml")
    assert shipped.threat == ThreatDetectionSettings()


def test_legacy_snapshot_detector_counts_keep_their_original_labels():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node unavailable")
    script = SNAPSHOT_VALIDATOR_JS + (
        "\nconst out={};for(const n of [3,8,9,11,12,14,16,17])out[n]=snapshotDetectorLabels(n);"
        "process.stdout.write(JSON.stringify(out));")
    labels = json.loads(subprocess.run([node, "-e", script], check=True, timeout=10, text=True,
                                       capture_output=True).stdout)
    assert labels["3"] == ["SYN_FLOOD", "PORT_SCAN", "DNS_TUNNELING"]
    assert labels["8"][-1] == "IOC_MATCH" and "DECOY_TOUCH" not in labels["8"]
    # DNS rules were appended, so a 9-count export is the catalog's prefix.
    assert labels["9"] == list(rule_catalog.ALL_RULE_IDS[:9]) and labels["9"][-1] == "IOC_MATCH"
    assert labels["11"] == list(rule_catalog.ALL_RULE_IDS[:11]) and labels["11"][-1] == "DNS_TUNNEL_CHURN"
    assert labels["12"] == list(rule_catalog.ALL_RULE_IDS[:12]) and labels["12"][-1] == "TLS_WITHOUT_SNI"
    assert labels["14"] == list(rule_catalog.ALL_RULE_IDS[:14]) and labels["14"][-1] == "ROGUE_DHCP"
    assert labels["16"] == list(rule_catalog.ALL_RULE_IDS[:16]) and labels["16"][-1] == "ROGUE_IPV6_ROUTER"
    assert labels["17"] == list(rule_catalog.ALL_RULE_IDS)
