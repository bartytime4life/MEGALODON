from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from megalodon.config import load_settings
from megalodon.validation import ValidationError


class ConfigTests(unittest.TestCase):
    def test_omitted_path_uses_complete_safe_defaults(self):
        settings = load_settings()
        self.assertEqual(settings.capture_source, "sample")
        self.assertEqual(settings.dashboard.host, "127.0.0.1")
        self.assertFalse(settings.blocking.enabled)
        self.assertTrue(settings.blocking.dry_run)
        self.assertFalse(settings.blocking.auto_block)
        self.assertEqual(
            tuple(str(network) for network in settings.blocking.allowlist),
            (
                "127.0.0.0/8",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "::1/128",
                "fc00::/7",
            ),
        )

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

            with self.assertRaisesRegex(
                ValidationError,
                "live firewall application is unsupported in this evaluation release",
            ):
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

    def test_detection_settings_reject_lossy_numeric_coercion_and_unsafe_caps(self):
        invalid_values = (
            "syn_flood_threshold = 1.9",
            'syn_flood_threshold = "100"',
            "syn_flood_threshold = true",
            "syn_flood_window_seconds = 3601",
            "dns_query_length = 65536",
            "max_tracked_sources = 65537",
            "max_events_per_source_window = 65537",
        )
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "settings.toml"
            for value in invalid_values:
                with self.subTest(value=value):
                    config.write_text(f"[detection]\n{value}\n", encoding="utf-8")
                    with self.assertRaises(ValidationError):
                        load_settings(config)

    def test_thresholds_must_fit_the_bounded_per_source_window(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "settings.toml"
            config.write_text(
                "[detection]\n"
                "syn_flood_threshold = 5\n"
                "max_events_per_source_window = 4\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValidationError, "must not exceed"):
                load_settings(config)

    def test_text_tables_and_allowlist_do_not_use_string_coercion(self):
        invalid_documents = (
            'app = "not-a-table"\n',
            '[app]\nlog_level = "VERBOSE"\n',
            '[capture]\nsource = "socket"\n',
            '[capture]\ninterface = "line\\nbreak"\n',
            '[blocking]\nallowlist = [1]\n',
            '[blocking]\ntimeout_seconds = 604801\n',
        )
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "settings.toml"
            for document in invalid_documents:
                with self.subTest(document=document):
                    config.write_text(document, encoding="utf-8")
                    with self.assertRaises(ValidationError):
                        load_settings(config)
