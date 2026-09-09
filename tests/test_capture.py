from __future__ import annotations

from io import StringIO
import unittest

from megalodon.capture import (
    CaptureError,
    _BoundedCaptureQueue,
    _normalize_scapy_tcp_flags,
    iter_jsonl,
)
from megalodon.validation import ValidationError


class FakeScapyFlagValue:
    """Scapy-compatible shape whose string form uses compact flag letters."""

    def __init__(self, value: int, display: str):
        self.value = value
        self.display = display

    def __int__(self):
        return self.value

    def __str__(self):
        return self.display


class CaptureTests(unittest.TestCase):
    def test_capture_queue_fails_closed_after_first_overflow(self):
        events = _BoundedCaptureQueue(maximum=2)
        self.assertTrue(events.offer(object()))
        self.assertTrue(events.offer(object()))
        self.assertFalse(events.offer(object()))
        self.assertFalse(events.offer(object()))

        with self.assertRaisesRegex(CaptureError, "exceeded 2 events; capture stopped"):
            events.take()
        self.assertEqual(events._events.qsize(), 2)

    def test_capture_queue_capacity_is_a_strict_positive_integer(self):
        for value in (0, -1, True, 1.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                _BoundedCaptureQueue(value)

    def test_scapy_flagvalue_bitmask_maps_to_packet_event_names(self):
        cases = (
            (FakeScapyFlagValue(0x02, "S"), {"SYN"}),
            (FakeScapyFlagValue(0x12, "SA"), {"SYN", "ACK"}),
            (FakeScapyFlagValue(0x01, "F"), {"FIN"}),
            (FakeScapyFlagValue(0xD9, "FPAEC"), {"FIN", "PSH", "ACK", "ECE", "CWR"}),
            (FakeScapyFlagValue(0, ""), set()),
        )
        for value, expected in cases:
            with self.subTest(display=str(value)):
                self.assertEqual(_normalize_scapy_tcp_flags(value), expected)

    def test_scapy_flagvalue_rejects_unknown_or_malformed_bits(self):
        for value in (FakeScapyFlagValue(0x100, "N"), -1, True, "SA"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                _normalize_scapy_tcp_flags(value)

    def test_jsonl_rejects_non_object_records(self):
        with self.assertRaises(CaptureError):
            list(iter_jsonl(StringIO("[1, 2, 3]\n")))

    def test_jsonl_rejects_oversized_lines(self):
        with self.assertRaises(CaptureError):
            list(iter_jsonl(StringIO("x" * 33 + "\n"), max_line_bytes=32))
