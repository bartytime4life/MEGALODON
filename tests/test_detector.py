from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
import unittest

from megalodon.config import DetectionSettings
from megalodon.detector import Detector, MAX_FUTURE_SKEW_SECONDS
from megalodon.models import PacketEvent
from megalodon.validation import ValidationError


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

    def test_detector_state_is_bounded(self):
        detector = Detector(
            DetectionSettings(
                max_tracked_sources=2,
                max_events_per_source_window=2,
                syn_flood_threshold=100,
            )
        )
        sources = ["8.8.8.1", "8.8.8.2", "8.8.8.3"]
        for index, source in enumerate(sources):
            detector.analyze(event(index, src_ip=source))
        self.assertNotIn("8.8.8.1", detector.syn_windows)
        self.assertLessEqual(len(detector.syn_windows), 2)
        self.assertLessEqual(len(detector.port_windows), 2)

        for index in range(3, 7):
            detector.analyze(event(index, src_ip="8.8.8.3"))
        self.assertLessEqual(len(detector.syn_windows["8.8.8.3"]), 2)
        self.assertLessEqual(len(detector.port_windows["8.8.8.3"]), 2)

    def test_out_of_order_event_is_rejected_without_poisoning_state(self):
        detector = Detector(
            DetectionSettings(syn_flood_threshold=3),
            clock=lambda: BASE + timedelta(days=1),
        )
        self.assertEqual(detector.analyze(event(100)), [])
        with self.assertRaisesRegex(ValidationError, "source high watermark"):
            detector.analyze(event(0))
        self.assertEqual(detector.analyze(event(101)), [])
        result = detector.analyze(event(102))
        self.assertEqual([item.rule_id for item in result], ["SYN_FLOOD"])
        self.assertEqual(len(detector.syn_windows["8.8.8.8"]), 3)

    def test_future_skew_boundary_is_explicit(self):
        detector = Detector(
            DetectionSettings(syn_flood_threshold=100),
            clock=lambda: BASE,
        )
        self.assertEqual(
            detector.analyze(
                event(0, observed_at=BASE + timedelta(seconds=MAX_FUTURE_SKEW_SECONDS))
            ),
            [],
        )
        other_source = "8.8.4.4"
        with self.assertRaisesRegex(ValidationError, "future skew"):
            detector.analyze(
                event(
                    0,
                    src_ip=other_source,
                    observed_at=BASE + timedelta(seconds=MAX_FUTURE_SKEW_SECONDS + 0.001),
                )
            )
        self.assertNotIn(other_source, detector.source_high_watermarks)
