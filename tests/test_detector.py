from __future__ import annotations

from collections import Counter, deque
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
        self.assertLessEqual(len(detector.port_counts), 2)

        for index in range(3, 7):
            detector.analyze(event(index, src_ip="8.8.8.3"))
        self.assertLessEqual(len(detector.syn_windows["8.8.8.3"]), 2)
        self.assertLessEqual(len(detector.port_windows["8.8.8.3"]), 2)
        self.assertLessEqual(len(detector.port_counts["8.8.8.3"]), 2)

    def test_port_counts_track_duplicate_expiry_without_window_iteration(self):
        class NoIterationDeque(deque):
            def __iter__(self):
                raise AssertionError("port-scan analysis must not rebuild a set from the window")

        detector = Detector(
            DetectionSettings(
                port_scan_window_seconds=5,
                port_scan_distinct_ports=3,
                alert_cooldown_seconds=30,
            )
        )
        source = "192.0.2.50"
        detector.port_windows[source] = NoIterationDeque()

        self.assertEqual(detector.analyze(event(0, src_ip=source, dst_port=21)), [])
        self.assertEqual(
            detector.analyze(
                event(0, src_ip=source, dst_port=21, observed_at=BASE + timedelta(seconds=1))
            ),
            [],
        )
        self.assertEqual(
            detector.analyze(
                event(0, src_ip=source, dst_port=22, observed_at=BASE + timedelta(seconds=2))
            ),
            [],
        )
        results = detector.analyze(
            event(0, src_ip=source, dst_port=23, observed_at=BASE + timedelta(seconds=5, milliseconds=500))
        )

        self.assertEqual([item.rule_id for item in results], ["PORT_SCAN"])
        self.assertEqual(detector.port_counts[source], Counter({21: 1, 22: 1, 23: 1}))

    def test_port_counts_remain_exact_when_window_capacity_evicts_duplicates(self):
        detector = Detector(
            DetectionSettings(
                port_scan_distinct_ports=3,
                max_events_per_source_window=3,
            )
        )
        source = "192.0.2.51"

        for index, port in enumerate((21, 21, 22, 23)):
            detector.analyze(event(index, src_ip=source, dst_port=port))

        self.assertEqual(len(detector.port_windows[source]), 3)
        self.assertEqual(detector.port_counts[source], Counter({21: 1, 22: 1, 23: 1}))

        detector.analyze(event(4, src_ip=source, dst_port=24))
        self.assertEqual(detector.port_counts[source], Counter({22: 1, 23: 1, 24: 1}))

    def test_port_counts_match_windows_through_expiry_capacity_and_source_churn(self):
        detector = Detector(
            DetectionSettings(
                port_scan_window_seconds=1,
                port_scan_distinct_ports=7,
                max_tracked_sources=3,
                max_events_per_source_window=7,
            ),
            clock=lambda: BASE + timedelta(days=1),
        )

        def assert_invariant() -> None:
            self.assertLessEqual(len(detector.source_order), 3)
            self.assertEqual(set(detector.port_windows), set(detector.port_counts))
            for tracked_source, window in detector.port_windows.items():
                self.assertLessEqual(len(window), 7)
                self.assertEqual(
                    detector.port_counts[tracked_source],
                    Counter(port for _, port in window),
                )

        source = "192.0.2.10"
        for index in range(12):
            detector.analyze(
                event(
                    index,
                    observed_at=BASE + timedelta(milliseconds=index * 50),
                    src_ip=source,
                    dst_port=20 + (index * 7) % 11,
                    tcp_flags=["ACK"],
                )
            )
            assert_invariant()
        self.assertEqual(len(detector.port_windows[source]), 7)

        detector.analyze(
            event(
                12,
                observed_at=BASE + timedelta(seconds=2),
                src_ip=source,
                dst_port=53,
                tcp_flags=["ACK"],
            )
        )
        assert_invariant()
        self.assertEqual(len(detector.port_windows[source]), 1)

        for offset, suffix in enumerate((11, 12, 13), start=1):
            detector.analyze(
                event(
                    12 + offset,
                    observed_at=BASE + timedelta(seconds=2, milliseconds=offset),
                    src_ip=f"192.0.2.{suffix}",
                    dst_port=53 + offset,
                    tcp_flags=["ACK"],
                )
            )
            assert_invariant()
        self.assertNotIn(source, detector.source_order)
        self.assertNotIn(source, detector.port_windows)
        self.assertNotIn(source, detector.port_counts)

        for index in range(600):
            detector.analyze(
                event(
                    20 + index,
                    observed_at=BASE
                    + timedelta(seconds=3, milliseconds=index * 10),
                    src_ip=f"192.0.2.{11 + index % 3}",
                    dst_port=20 + (index * 7) % 11,
                    tcp_flags=["ACK"],
                )
            )
            assert_invariant()
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
