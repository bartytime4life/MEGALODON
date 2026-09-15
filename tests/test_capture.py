from __future__ import annotations

from io import StringIO
import unittest

from megalodon.capture import (
    CaptureError,
    MAX_JSONL_INPUT_BYTES,
    MAX_JSONL_SKIPPED_LINES,
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
    EVENT = (
        '{"observed_at":"2026-01-01T00:00:00Z",'
        '"src_ip":"192.0.2.1","dst_ip":"198.51.100.2",'
        '"protocol":"TCP"}'
    )

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

    def test_jsonl_normalizes_parser_recursion_without_echoing_the_record(self):
        hostile = "[" * 1100 + "]" * 1100
        with self.assertRaisesRegex(CaptureError, "^invalid JSONL event at line 1$"):
            list(iter_jsonl(StringIO(hostile + "\n")))

    def test_jsonl_skipped_line_budget_counts_blank_and_comment_lines(self):
        stream = StringIO("\n# synthetic comment\n" + self.EVENT + "\n")

        events = list(iter_jsonl(stream, max_skipped_lines=2))

        self.assertEqual(len(events), 1)

    def test_jsonl_skipped_line_budget_refuses_before_reading_the_suffix(self):
        stream = StringIO("\n# second skip\n" + self.EVENT + "\n")

        with self.assertRaisesRegex(
            CaptureError, "^JSONL skipped-line limit exceeded at line 2$"
        ):
            list(iter_jsonl(stream, max_skipped_lines=1))

        self.assertEqual(stream.readline(), self.EVENT + "\n")

    def test_jsonl_skipped_line_budget_accepts_zero_but_refuses_first_skip(self):
        with self.assertRaisesRegex(
            CaptureError, "^JSONL skipped-line limit exceeded at line 1$"
        ):
            list(iter_jsonl(StringIO("# skip\n"), max_skipped_lines=0))

    def test_jsonl_skipped_line_budget_is_bounded(self):
        for value in (-1, True, 1.5, MAX_JSONL_SKIPPED_LINES + 1):
            with self.subTest(value=value), self.assertRaisesRegex(
                ValueError,
                "^max_skipped_lines must be an integer between 0 and 65536$",
            ):
                list(iter_jsonl(StringIO(self.EVENT + "\n"), max_skipped_lines=value))

    def test_jsonl_input_byte_budget_counts_events_comments_and_blank_lines(self):
        prefix = self.EVENT + "\n# note\n\n"
        stream = StringIO(prefix + self.EVENT + "\n")
        with self.assertRaisesRegex(
            CaptureError, "^JSONL input-byte limit exceeded at line 4$"
        ):
            list(iter_jsonl(stream, max_input_bytes=len(prefix.encode("utf-8"))))

    def test_jsonl_input_byte_budget_refuses_before_reading_suffix(self):
        class Guarded(StringIO):
            def readline(self, size=-1):
                if self.tell() > 0:
                    raise AssertionError("suffix was read")
                return super().readline(size)

        with self.assertRaisesRegex(
            CaptureError, "^JSONL input-byte limit exceeded at line 1$"
        ):
            list(iter_jsonl(Guarded(self.EVENT + "\nSECRET"), max_input_bytes=1))

    def test_jsonl_input_byte_budget_is_bounded(self):
        for value in (0, -1, True, 1.5, MAX_JSONL_INPUT_BYTES + 1):
            with self.subTest(value=value), self.assertRaisesRegex(
                ValueError,
                "^max_input_bytes must be an integer between 1 and 268435456$",
            ):
                list(iter_jsonl(StringIO(self.EVENT + "\n"), max_input_bytes=value))
