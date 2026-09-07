from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from megalodon.config import load_settings
from megalodon.validation import ValidationError


class ConfigTests(unittest.TestCase):
    def test_automatic_live_firewall_configuration_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "settings.toml"
            config.write_text(
                "[blocking]\n"
                "enabled = true\n"
                "auto_block = true\n"
                "dry_run = false\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValidationError, "automatic firewall application is prohibited"):
                load_settings(config)

    def test_dashboard_polling_settings_are_bounded_integers(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "settings.toml"
            config.write_text("[dashboard]\nrefresh_seconds = 12\nevent_limit = 125\n", encoding="utf-8")
            settings = load_settings(config)
            self.assertEqual(settings.dashboard.refresh_seconds, 12)
            self.assertEqual(settings.dashboard.event_limit, 125)

            invalid_values = (
                "refresh_seconds = 1",
                "refresh_seconds = 301",
                'refresh_seconds = "5"',
                "event_limit = 0",
                "event_limit = 201",
                "event_limit = true",
            )
            for value in invalid_values:
                with self.subTest(value=value):
                    config.write_text(f"[dashboard]\n{value}\n", encoding="utf-8")
                    with self.assertRaises(ValidationError):
                        load_settings(config)
