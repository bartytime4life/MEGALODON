from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
import unittest

from megalodon.config import DetectionSettings
from megalodon.detector import Detector
from megalodon.models import PacketEvent


BASE = datetime(2026, 9, 6, tzinfo=timezone.utc)


def event(index: int, **overrides) -> PacketEvent:
    value = {
        "observed_at": BASE + timedelta(milliseconds=index * 100),
        "src_ip": "8.8.8.8",
        "dst_ip": "192.0.2.10",
        "protocol": "TCP",
        "src_port": 40000 + index,
        "dst_port": 22,
        "tcp_flags": ["SYN"],
    }
    value.update(overrides)
    return PacketEvent.from_mapping(value)


class DetectorTests(unittest.TestCase):
    def test_syn_flood_emits_at_threshold(self):
        detector = Detector(DetectionSettings(syn_flood_threshold=3, alert_cooldown_seconds=30))
        self.assertEqual(detector.analyze(event(0)), [])
        self.assertEqual(detector.analyze(event(1)), [])
        results = detector.analyze(event(2))
        self.assertEqual([result.rule_id for result in results], ["SYN_FLOOD"])

    def test_port_scan_counts_distinct_ports(self):
        detector = Detector(DetectionSettings(port_scan_distinct_ports=3, alert_cooldown_seconds=30))
        self.assertEqual(detector.analyze(event(0, dst_port=21)), [])
        self.assertEqual(detector.analyze(event(1, dst_port=22)), [])
        results = detector.analyze(event(2, dst_port=23))
        self.assertEqual([result.rule_id for result in results], ["PORT_SCAN"])

    def test_long_dns_query_is_critical(self):
        detector = Detector(DetectionSettings(dns_query_length=50))
        results = detector.analyze(
            event(0, protocol="DNS", dst_port=53, tcp_flags=[], dns_query_length=50)
        )
        self.assertEqual(results[0].rule_id, "DNS_TUNNELING")
        self.assertEqual(results[0].severity, "CRITICAL")

    def test_allowlisted_source_is_suppressed(self):
        detector = Detector(
            DetectionSettings(syn_flood_threshold=1),
            (ipaddress.ip_network("8.8.8.8/32"),),
        )
        result = detector.analyze(event(0))[0]
        self.assertEqual(result.suppressed_reason, "source_allowlisted")
