from __future__ import annotations

import ipaddress
import unittest

from megalodon.firewall import FirewallError, NftablesFirewall


def firewall(**kwargs):
    return NftablesFirewall(
        allowlist=(ipaddress.ip_network("192.168.0.0/16"),),
        public_only=False,
        **kwargs,
    )


class FirewallTests(unittest.TestCase):
    def test_plan_does_not_apply_and_uses_argv(self):
        operation = firewall(timeout_seconds=600).plan_block("8.8.8.8", "test")
        self.assertEqual(operation.status, "planned")
        self.assertEqual(operation.command[0], "nft")
        self.assertIn("8.8.8.8", operation.command)
        self.assertNotIn("test", operation.command)

    def test_allowlist_wins(self):
        with self.assertRaises(FirewallError):
            firewall().plan_block("192.168.1.2", "test")

    def test_apply_requires_exact_confirmation(self):
        with self.assertRaises(FirewallError):
            firewall().block("8.8.8.8", "test", apply=True, confirm="8.8.8.9")

    def test_ipv6_uses_ipv6_set(self):
        operation = firewall().plan_block("2001:4860:4860::8888", "test")
        self.assertIn("blocked_v6", operation.command)
