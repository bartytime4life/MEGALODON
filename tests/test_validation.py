from __future__ import annotations

from datetime import datetime, timezone
import unittest

from megalodon.models import PacketEvent
from megalodon.validation import ValidationError, parse_ip, parse_port, validate_metadata


class ValidationTests(unittest.TestCase):
    def test_ip_is_normalized(self):
        self.assertEqual(parse_ip(" 2001:0db8::1 "), "2001:db8::1")

    def test_invalid_ip_is_rejected(self):
        with self.assertRaises(ValidationError):
            parse_ip("1.2.3.4; touch /tmp/pwned")

    def test_port_bounds(self):
        self.assertEqual(parse_port("443"), 443)
        with self.assertRaises(ValidationError):
            parse_port(70000)

    def test_metadata_is_bounded_json(self):
        value = {"sensor": "lab", "signals": [1, True, None, {"label": "ok"}]}
        self.assertEqual(validate_metadata(value), value)

    def test_metadata_rejects_depth_and_control_text(self):
        with self.assertRaises(ValidationError):
            validate_metadata({"a": {"b": {"c": {"d": {"e": "too deep"}}}}})
        with self.assertRaises(ValidationError):
            validate_metadata({"sensor": "line\nbreak"})

    def test_packet_event_bounds_protocol_and_metadata(self):
        now = datetime.now(timezone.utc)
        with self.assertRaises(ValidationError):
            PacketEvent(now, "192.0.2.1", "198.51.100.2", "X" * 33)
        with self.assertRaises(ValidationError):
            PacketEvent(now, "192.0.2.1", "198.51.100.2", "TCP", metadata={"value": "x" * 300})
