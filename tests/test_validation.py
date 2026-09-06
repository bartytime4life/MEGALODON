from __future__ import annotations

import unittest

from megalodon.validation import ValidationError, parse_ip, parse_port


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
