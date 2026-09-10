from __future__ import annotations

from collections import Counter, deque
from datetime import datetime, timedelta, timezone
import inspect
import ipaddress
import sys
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
        detector.port_counts[source] = Counter()

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
                    dict(detector.port_counts[tracked_source]),
                    dict(Counter(port for _, port in window)),
                )
                self.assertTrue(
                    all(
                        value > 0
                        for value in detector.port_counts[tracked_source].values()
                    )
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

    def test_prepare_does_not_copy_existing_source_windows(self):
        class NonIterableDeque(deque):
            def __iter__(self):
                raise AssertionError("prepare must not copy an existing window")

        detector = Detector(
            DetectionSettings(), clock=lambda: BASE + timedelta(days=1)
        )
        source = "8.8.8.8"
        syn_window = NonIterableDeque([(BASE.timestamp(), "192.0.2.10")])
        port_window = NonIterableDeque([(BASE.timestamp(), 22)])
        detector.syn_windows[source] = syn_window
        detector.port_windows[source] = port_window

        prepared = detector.prepare(
            event(
                1,
                protocol="DNS",
                dst_port=53,
                tcp_flags=[],
                dns_query_length=50,
            )
        )
        prepared.rollback()

        self.assertIs(detector.syn_windows[source], syn_window)
        self.assertIs(detector.port_windows[source], port_window)
        self.assertNotIn(source, detector.source_high_watermarks)

    def test_prepare_rollback_restores_entries_trimmed_by_that_event(self):
        detector = Detector(
            DetectionSettings(
                syn_flood_threshold=100,
                syn_flood_window_seconds=1,
                port_scan_distinct_ports=100,
                port_scan_window_seconds=1,
            ),
            clock=lambda: BASE + timedelta(days=1),
        )
        detector.analyze(event(0))
        syn_before = list(detector.syn_windows["8.8.8.8"])
        port_before = list(detector.port_windows["8.8.8.8"])
        watermark_before = detector.source_high_watermarks["8.8.8.8"]

        prepared = detector.prepare(
            event(1, observed_at=BASE + timedelta(seconds=2))
        )
        prepared.rollback()

        self.assertEqual(list(detector.syn_windows["8.8.8.8"]), syn_before)
        self.assertEqual(list(detector.port_windows["8.8.8.8"]), port_before)
        self.assertEqual(
            detector.source_high_watermarks["8.8.8.8"], watermark_before
        )

    def test_prepare_refuses_overlap_until_the_matching_handle_resolves(self):
        detector = Detector(
            DetectionSettings(port_scan_distinct_ports=1),
            clock=lambda: BASE + timedelta(days=1),
        )
        first = detector.prepare(event(0, tcp_flags=["ACK"], dst_port=21))

        with self.assertRaisesRegex(RuntimeError, "preparation already pending"):
            detector.prepare(event(1, tcp_flags=["ACK"], dst_port=22))

        first.rollback()
        self.assertNotIn("8.8.8.8", detector.port_windows)
        self.assertNotIn("8.8.8.8", detector.port_counts)
        second = detector.prepare(event(1, tcp_flags=["ACK"], dst_port=22))
        second.commit()
        self.assertEqual(
            detector.port_counts["8.8.8.8"], Counter({22: 1})
        )
        self.assertIsNone(detector._pending_token)

    def test_detector_rejects_nonpositive_window_settings(self):
        for field in ("syn_flood_window_seconds", "port_scan_window_seconds"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, f"{field} must be positive"):
                    Detector(DetectionSettings(**{field: 0}))

    def test_syn_journal_recovers_interrupt_after_each_deque_mutation(self):
        class InterruptAfterDequeMutation(deque):
            def __init__(self, values, operation):
                super().__init__(values)
                self.operation = operation
                self.armed = True

            def append(self, item):
                super().append(item)
                if self.operation == "append" and self.armed:
                    self.armed = False
                    raise KeyboardInterrupt

            def popleft(self):
                item = super().popleft()
                if self.operation == "popleft" and self.armed:
                    self.armed = False
                    raise KeyboardInterrupt
                return item

        for operation in ("append", "popleft"):
            with self.subTest(operation=operation):
                detector = Detector(
                    DetectionSettings(
                        syn_flood_threshold=100,
                        syn_flood_window_seconds=1,
                    ),
                    clock=lambda: BASE + timedelta(days=1),
                )
                source = "8.8.8.8"
                original = [(BASE.timestamp(), "192.0.2.10")]
                window = InterruptAfterDequeMutation(original, operation)
                detector.syn_windows[source] = window
                detector.source_high_watermarks[source] = BASE.timestamp()
                detector.source_order[source] = None
                observed = BASE if operation == "append" else BASE + timedelta(seconds=2)

                with self.assertRaises(KeyboardInterrupt):
                    detector.prepare(
                        event(
                            1,
                            observed_at=observed,
                            dst_port=None,
                            tcp_flags=["SYN"],
                        )
                    )

                self.assertEqual(list(window), original)
                self.assertEqual(detector.source_high_watermarks[source], BASE.timestamp())
                self.assertEqual(tuple(detector.source_order), (source,))
                self.assertIsNone(detector._pending_token)

    def test_syn_journal_recovers_interrupt_between_removal_log_and_popleft(self):
        detector = Detector(
            DetectionSettings(
                syn_flood_threshold=100,
                syn_flood_window_seconds=1,
            ),
            clock=lambda: BASE + timedelta(days=1),
        )
        source = "8.8.8.8"
        original = [(BASE.timestamp(), "192.0.2.10")]
        detector.syn_windows[source] = deque(original)
        detector.source_high_watermarks[source] = BASE.timestamp()
        detector.source_order[source] = None
        lines, first_line = inspect.getsourcelines(Detector._stage_deque_removal)
        target_line = first_line + next(
            index
            for index, line in enumerate(lines)
            if "removed = undo.window.popleft()" in line
        )
        fired = False

        def interrupt_before_popleft(frame, trace_event, _arg):
            nonlocal fired
            if (
                not fired
                and trace_event == "line"
                and frame.f_code is Detector._stage_deque_removal.__code__
                and frame.f_lineno == target_line
            ):
                fired = True
                raise KeyboardInterrupt
            return interrupt_before_popleft

        sys.settrace(interrupt_before_popleft)
        try:
            with self.assertRaises(KeyboardInterrupt):
                detector.prepare(
                    event(
                        1,
                        observed_at=BASE + timedelta(seconds=2),
                        dst_port=None,
                        tcp_flags=["SYN"],
                    )
                )
        finally:
            sys.settrace(None)

        self.assertTrue(fired)
        self.assertEqual(list(detector.syn_windows[source]), original)
        self.assertIsNone(detector._pending_token)

    def test_port_journal_recovers_interrupt_after_each_deque_mutation(self):
        class InterruptAfterDequeMutation(deque):
            def __init__(self, values, operation):
                super().__init__(values)
                self.operation = operation
                self.armed = True

            def append(self, item):
                super().append(item)
                if self.operation == "append" and self.armed:
                    self.armed = False
                    raise KeyboardInterrupt

            def popleft(self):
                item = super().popleft()
                if self.operation == "popleft" and self.armed:
                    self.armed = False
                    raise KeyboardInterrupt
                return item

        for operation in ("append", "popleft"):
            with self.subTest(operation=operation):
                detector = Detector(
                    DetectionSettings(
                        port_scan_distinct_ports=100,
                        port_scan_window_seconds=1,
                    ),
                    clock=lambda: BASE + timedelta(days=1),
                )
                source = "8.8.8.8"
                original = [(BASE.timestamp(), 21)]
                window = InterruptAfterDequeMutation(original, operation)
                counts = Counter({21: 1})
                detector.port_windows[source] = window
                detector.port_counts[source] = counts
                detector.source_high_watermarks[source] = BASE.timestamp()
                detector.source_order[source] = None
                observed = BASE if operation == "append" else BASE + timedelta(seconds=2)

                with self.assertRaises(KeyboardInterrupt):
                    detector.prepare(
                        event(
                            1,
                            observed_at=observed,
                            dst_port=22,
                            tcp_flags=["ACK"],
                        )
                    )

                self.assertEqual(list(window), original)
                self.assertEqual(counts, Counter({21: 1}))
                self.assertIs(detector.port_windows[source], window)
                self.assertIs(detector.port_counts[source], counts)
                self.assertIsNone(detector._pending_token)

    def test_port_journal_recovers_interrupt_between_removal_log_and_popleft(self):
        detector = Detector(
            DetectionSettings(
                port_scan_distinct_ports=100,
                port_scan_window_seconds=1,
            ),
            clock=lambda: BASE + timedelta(days=1),
        )
        source = "8.8.8.8"
        original = [(BASE.timestamp(), 21)]
        counts = Counter({21: 1})
        detector.port_windows[source] = deque(original)
        detector.port_counts[source] = counts
        detector.source_high_watermarks[source] = BASE.timestamp()
        detector.source_order[source] = None
        lines, first_line = inspect.getsourcelines(Detector._stage_deque_removal)
        target_line = first_line + next(
            index
            for index, line in enumerate(lines)
            if "removed = undo.window.popleft()" in line
        )
        fired = False

        def interrupt_before_popleft(frame, trace_event, _arg):
            nonlocal fired
            if (
                not fired
                and trace_event == "line"
                and frame.f_code is Detector._stage_deque_removal.__code__
                and frame.f_lineno == target_line
            ):
                fired = True
                raise KeyboardInterrupt
            return interrupt_before_popleft

        sys.settrace(interrupt_before_popleft)
        try:
            with self.assertRaises(KeyboardInterrupt):
                detector.prepare(
                    event(
                        1,
                        observed_at=BASE + timedelta(seconds=2),
                        dst_port=22,
                        tcp_flags=["ACK"],
                    )
                )
        finally:
            sys.settrace(None)

        self.assertTrue(fired)
        self.assertEqual(tuple(detector.port_windows[source]), tuple(original))
        self.assertEqual(dict(counts), {21: 1})
        self.assertIsNone(detector._pending_token)

    def test_port_journal_restores_exact_counter_after_counter_interrupt(self):
        class InterruptAfterCounterMutation(Counter):
            def arm(self, operation, port):
                self.operation = operation
                self.port = port
                self.armed = True

            def __setitem__(self, key, value):
                super().__setitem__(key, value)
                if (
                    getattr(self, "armed", False)
                    and self.operation == "set"
                    and key == self.port
                ):
                    self.armed = False
                    raise KeyboardInterrupt

            def __delitem__(self, key):
                super().__delitem__(key)
                if (
                    getattr(self, "armed", False)
                    and self.operation == "delete"
                    and key == self.port
                ):
                    self.armed = False
                    raise KeyboardInterrupt

        cases = (
            ("increment", (), {}, BASE, "set", 22),
            (
                "decrement",
                ((BASE.timestamp(), 21),),
                {21: 1},
                BASE + timedelta(seconds=2),
                "delete",
                21,
            ),
        )
        for name, original, initial_counts, observed, operation, trigger_port in cases:
            with self.subTest(name=name):
                detector = Detector(
                    DetectionSettings(
                        port_scan_distinct_ports=100,
                        port_scan_window_seconds=1,
                    ),
                    clock=lambda: BASE + timedelta(days=1),
                )
                source = "8.8.8.8"
                window = deque(original)
                counts = InterruptAfterCounterMutation(initial_counts)
                counts.arm(operation, trigger_port)
                detector.port_windows[source] = window
                detector.port_counts[source] = counts
                if original:
                    detector.source_high_watermarks[source] = original[-1][0]
                    detector.source_order[source] = None

                with self.assertRaises(KeyboardInterrupt):
                    detector.prepare(
                        event(
                            1,
                            observed_at=observed,
                            dst_port=22,
                            tcp_flags=["ACK"],
                        )
                    )

                self.assertEqual(tuple(window), original)
                self.assertEqual(dict(counts), initial_counts)
                self.assertTrue(all(value > 0 for value in counts.values()))
                self.assertEqual(sum(counts.values()), len(window))
                self.assertIsNone(detector._pending_token)

    def test_failed_preparations_do_not_touch_lru_and_commit_evicts_counter(self):
        detector = Detector(
            DetectionSettings(
                port_scan_distinct_ports=1,
                max_tracked_sources=2,
                max_events_per_source_window=4,
            ),
            clock=lambda: BASE + timedelta(days=1),
        )
        source_a, source_b, source_c = "8.8.8.1", "8.8.8.2", "8.8.8.3"
        detector.analyze(event(0, src_ip=source_a, dst_port=21, tcp_flags=["ACK"]))
        detector.analyze(event(1, src_ip=source_b, dst_port=22, tcp_flags=["ACK"]))
        self.assertEqual(tuple(detector.source_order), (source_a, source_b))

        existing = detector.prepare(
            event(2, src_ip=source_a, dst_port=23, tcp_flags=["ACK"])
        )
        existing.rollback()
        self.assertEqual(tuple(detector.source_order), (source_a, source_b))

        new_source = detector.prepare(
            event(3, src_ip=source_c, dst_port=24, tcp_flags=["ACK"])
        )
        new_source.rollback()
        self.assertEqual(tuple(detector.source_order), (source_a, source_b))
        self.assertNotIn(source_c, detector.port_windows)
        self.assertNotIn(source_c, detector.port_counts)

        committed = detector.prepare(
            event(3, src_ip=source_c, dst_port=24, tcp_flags=["ACK"])
        )
        committed.commit()
        self.assertEqual(tuple(detector.source_order), (source_b, source_c))
        self.assertNotIn(source_a, detector.port_windows)
        self.assertNotIn(source_a, detector.port_counts)
        self.assertNotIn(source_a, detector.source_high_watermarks)
        self.assertNotIn(("PORT_SCAN", source_a), detector.last_emitted)
