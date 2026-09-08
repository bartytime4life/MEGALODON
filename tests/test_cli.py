from __future__ import annotations

from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from megalodon.cli import build_parser, main
from megalodon.dashboard import serve
from megalodon.firewall import NftablesFirewall
from megalodon.storage import Store


def write_config(directory: str) -> tuple[Path, Path]:
    root = Path(directory)
    database = root / "events.db"
    config = root / "settings.toml"
    config.write_text(f'[app]\ndb_path = "{database.as_posix()}"\n', encoding="utf-8")
    return config, database


class CliTests(unittest.TestCase):
    def test_dashboard_parser_accepts_bounded_view_overrides(self):
        args = build_parser().parse_args(
            ["dashboard", "--refresh-seconds", "12", "--event-limit", "125"]
        )
        self.assertEqual(args.refresh_seconds, 12)
        self.assertEqual(args.event_limit, 125)

    def test_firewall_plan_is_logged_without_subprocess(self):
        with tempfile.TemporaryDirectory() as directory:
            config, database = write_config(directory)
            with patch("megalodon.firewall.subprocess.run") as run:
                with redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        main(["firewall-plan", "8.8.8.8", "--reason", "review", "--config", str(config)])
            self.assertEqual(raised.exception.code, 0)
            run.assert_not_called()
            with Store(database) as store:
                action = store.connection.execute(
                    "SELECT action, status, target FROM actions ORDER BY id DESC LIMIT 1"
                ).fetchone()
                self.assertEqual(tuple(action), ("block", "planned", "8.8.8.8"))

    def test_applied_block_is_logged(self):
        with tempfile.TemporaryDirectory() as directory:
            config, database = write_config(directory)
            with patch.object(NftablesFirewall, "_require_apply"), patch.object(NftablesFirewall, "_run") as run:
                with redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        main(
                            [
                                "block",
                                "8.8.8.8",
                                "--reason",
                                "approved",
                                "--apply",
                                "--confirm",
                                "8.8.8.8",
                                "--config",
                                str(config),
                            ]
                        )
            self.assertEqual(raised.exception.code, 0)
            run.assert_called_once()
            with Store(database) as store:
                action = store.connection.execute(
                    "SELECT action, status, target FROM actions ORDER BY id DESC LIMIT 1"
                ).fetchone()
                self.assertEqual(tuple(action), ("block", "applied", "8.8.8.8"))

    def test_remote_dashboard_requires_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            with Store(Path(directory) / "events.db") as store:
                with self.assertRaises(ValueError):
                    serve(store, "0.0.0.0", 8787)

    def test_disabled_dashboard_does_not_bind(self):
        with tempfile.TemporaryDirectory() as directory:
            with Store(Path(directory) / "events.db") as store:
                with self.assertRaises(ValueError):
                    serve(store, "127.0.0.1", 8787, enabled=False)
