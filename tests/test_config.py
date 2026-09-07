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
