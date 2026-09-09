from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
import os
import subprocess
import unittest
from unittest.mock import patch

from megalodon.firewall import (
    FirewallError,
    LIVE_APPLY_UNSUPPORTED,
    NFTABLES_TABLE,
    NftablesFirewall,
)


def firewall(**kwargs):
    return NftablesFirewall(
        allowlist=(ipaddress.ip_network("192.168.0.0/16"),),
        public_only=False,
        **kwargs,
    )


class FirewallTests(unittest.TestCase):
    def test_plan_does_not_apply_and_uses_argv(self):
        fixed = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        with patch("megalodon.firewall.datetime") as clock:
            clock.now.return_value = fixed
            operation = firewall(timeout_seconds=600).plan_block("8.8.8.8", "test")
        self.assertEqual(
            operation.to_dict(),
            {
                "status": "planned",
                "target": "8.8.8.8",
                "reason": "test",
                "command": [
                    "nft",
                    "add",
                    "element",
                    "inet",
                    "megalodon",
                    "blocked_v4",
                    "{",
                    "8.8.8.8",
                    "timeout",
                    "600s",
                    "}",
                ],
                "message": "would add a time-limited set element",
                "expires_at": "2026-01-02T03:14:05+00:00",
            },
        )

    def test_install_plan_contract_is_stable(self):
        self.assertEqual(
            firewall().install().to_dict(),
            {
                "status": "planned",
                "target": "table:megalodon",
                "reason": "install isolated table",
                "command": ["nft", "-f", "-"],
                "message": NFTABLES_TABLE,
                "expires_at": None,
            },
        )

    def test_block_plan_never_calls_subprocess(self):
        fixed = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        with patch("megalodon.firewall.datetime") as clock, patch.object(
            subprocess, "run"
        ) as run:
            clock.now.return_value = fixed
            planned = firewall().plan_block("8.8.8.8", "test")
            operation = firewall().block("8.8.8.8", "test", apply=False)
        self.assertEqual(operation, planned)
        run.assert_not_called()

    def test_allowlist_wins(self):
        with self.assertRaises(FirewallError):
            firewall().plan_block("192.168.1.2", "test")

    def test_direct_apply_routes_refuse_before_host_or_process_work(self):
        def forbidden(*_args, **_kwargs):
            raise AssertionError("live apply must refuse before host or process work")

        calls = (
            lambda: firewall().install(apply=True, confirm="WRONG"),
            lambda: firewall().block("not-an-ip", "", apply=True),
        )
        with (
            patch("megalodon.firewall.runtime_platform", side_effect=forbidden),
            patch("megalodon.firewall.shutil.which", side_effect=forbidden),
            patch.object(os, "geteuid", side_effect=forbidden, create=True),
            patch.object(os, "system", side_effect=forbidden),
            patch.object(subprocess, "run", side_effect=forbidden),
            patch.object(subprocess, "Popen", side_effect=forbidden),
        ):
            for call in calls:
                with self.subTest(call=call), self.assertRaises(FirewallError) as raised:
                    call()
                self.assertEqual(str(raised.exception), LIVE_APPLY_UNSUPPORTED)

        self.assertFalse(hasattr(NftablesFirewall, "_require_apply"))
        self.assertFalse(hasattr(NftablesFirewall, "_run"))

    def test_ipv6_uses_ipv6_set(self):
        operation = firewall().plan_block("2001:4860:4860::8888", "test")
        self.assertIn("blocked_v6", operation.command)
