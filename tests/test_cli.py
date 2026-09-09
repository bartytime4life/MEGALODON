from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
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

    def test_cli_integer_options_reject_coercion_and_out_of_range_values(self):
        invalid_argv = (
            ["run", "--max-events", "-1"],
            ["run", "--max-events", "1.9"],
            ["run", "--max-events", "10000001"],
            ["dashboard", "--port", "0"],
            ["dashboard", "--port", "65536"],
            ["dashboard", "--refresh-seconds", "1"],
            ["dashboard", "--event-limit", "201"],
        )
        for argv in invalid_argv:
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    build_parser().parse_args(argv)
                self.assertEqual(raised.exception.code, 2)

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

    def test_multiline_install_plan_is_safely_summarized_in_audit_details(self):
        with tempfile.TemporaryDirectory() as directory:
            config, database = write_config(directory)
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(["firewall-install", "--config", str(config)])
            self.assertEqual(raised.exception.code, 0)
            with Store(database) as store:
                details = store.connection.execute(
                    "SELECT details_json FROM actions ORDER BY id DESC LIMIT 1"
                ).fetchone()[0]
            self.assertIn("operation plan omitted from audit details", details)

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
