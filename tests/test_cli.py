from __future__ import annotations

from contextlib import chdir, ExitStack, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from megalodon import __version__
from megalodon.cli import build_parser, main
from megalodon.dashboard import serve
from megalodon.firewall import LIVE_APPLY_UNSUPPORTED
from megalodon.storage import (
    SCHEMA_V1_STATEMENTS,
    SCHEMA_VERSION,
    Store,
)


def write_config(directory: str) -> tuple[Path, Path]:
    root = Path(directory)
    database = root / "events.db"
    config = root / "settings.toml"
    config.write_text(f'[app]\ndb_path = "{database.as_posix()}"\n', encoding="utf-8")
    return config, database


class CliTests(unittest.TestCase):
    def test_version_is_available_without_selecting_a_command(self):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(output.getvalue(), f"megalodon {__version__}\n")

    def test_default_run_works_outside_the_source_checkout(self):
        with tempfile.TemporaryDirectory() as directory, chdir(directory):
            output = io.StringIO()
            with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
                main(["run", "--source", "sample", "--max-events", "1"])
            self.assertEqual(raised.exception.code, 0)
            self.assertTrue((Path(directory) / "data" / "megalodon.db").is_file())
            self.assertIn('"processed": 1', output.getvalue())

    def test_explicit_missing_config_fails_without_echoing_the_path(self):
        missing = "/private/SECRET/settings.toml"
        error = io.StringIO()
        with redirect_stderr(error), self.assertRaises(SystemExit) as raised:
            main(["run", "--config", missing, "--source", "sample", "--max-events", "1"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("configuration file could not be read", error.getvalue())
        self.assertNotIn(missing, error.getvalue())

    def test_future_database_schema_fails_with_a_fixed_cli_error(self):
        with tempfile.TemporaryDirectory() as directory:
            config, database = write_config(directory)
            with sqlite3.connect(database) as connection:
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")

            error = io.StringIO()
            with redirect_stderr(error), self.assertRaises(SystemExit) as raised:
                main(["run", "--config", str(config), "--source", "sample"])

            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(error.getvalue(), "megalodon: STORAGE_SCHEMA:FUTURE_VERSION\n")

    def test_database_migration_is_explicit_backed_up_and_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            config, database = write_config(directory)
            with sqlite3.connect(database) as connection:
                for statement in SCHEMA_V1_STATEMENTS:
                    connection.execute(statement)
                connection.execute("PRAGMA user_version = 1")
            if os.name == "posix":
                database.chmod(0o600)

            output = io.StringIO()
            with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
                main(["database-migrate", "--config", str(config)])

            self.assertEqual(raised.exception.code, 0)
            receipt = json.loads(output.getvalue())
            self.assertEqual(receipt["status"], "migrated")
            self.assertEqual(receipt["from_version"], 1)
            self.assertEqual(receipt["to_version"], SCHEMA_VERSION)
            self.assertEqual(receipt["backup"], "created")
            self.assertNotIn(str(database), output.getvalue())
            self.assertNotIn(directory, output.getvalue())
            with Store(database):
                pass

            output = io.StringIO()
            with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
                main(["database-migrate", "--config", str(config)])
            self.assertEqual(raised.exception.code, 0)
            self.assertEqual(json.loads(output.getvalue())["status"], "already_current")

    def test_dashboard_parser_accepts_bounded_view_overrides(self):
        args = build_parser().parse_args(
            ["dashboard", "--refresh-seconds", "12", "--event-limit", "125"]
        )
        self.assertEqual(args.refresh_seconds, 12)
        self.assertEqual(args.event_limit, 125)

    def test_run_parser_accepts_bounded_elapsed_deadline(self):
        args = build_parser().parse_args(["run", "--max-seconds", "120"])
        self.assertEqual(args.max_seconds, 120)

    def test_cli_integer_options_reject_coercion_and_out_of_range_values(self):
        invalid_argv = (
            ["run", "--max-events", "0"],
            ["run", "--max-events", "-1"],
            ["run", "--max-events", "1.9"],
            ["run", "--max-events", "10000001"],
            ["run", "--max-seconds", "0"],
            ["run", "--max-seconds", "-1"],
            ["run", "--max-seconds", "1.9"],
            ["run", "--max-seconds", "86401"],
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

    def test_non_sample_sources_require_limit_before_configuration_or_io(self):
        def forbidden(*_args, **_kwargs):
            raise AssertionError("unbounded source must refuse before I/O")

        patches = (
            patch("megalodon.cli._load", side_effect=forbidden),
            patch("megalodon.cli.Store", side_effect=forbidden),
            patch("megalodon.cli._events_for", side_effect=forbidden),
            patch("socket.socket", side_effect=forbidden),
            patch("socket.create_connection", side_effect=forbidden),
            patch("socket.getaddrinfo", side_effect=forbidden),
            patch.object(subprocess, "run", side_effect=forbidden),
            patch.object(subprocess, "Popen", side_effect=forbidden),
        )
        with ExitStack() as stack:
            for context in patches:
                stack.enter_context(context)
            for source in ("jsonl", "scapy"):
                output = io.StringIO()
                error = io.StringIO()
                with (
                    self.subTest(source=source),
                    redirect_stdout(output),
                    redirect_stderr(error),
                    self.assertRaises(SystemExit) as raised,
                ):
                    main(["run", "--source", source])
                self.assertEqual(raised.exception.code, 2)
                self.assertEqual(output.getvalue(), "")
                self.assertEqual(
                    error.getvalue(),
                    "megalodon: jsonl and scapy sources require --max-events "
                    "between 1 and 10000000\n",
                )

    def test_unsupported_deadline_refuses_before_configuration_or_io(self):
        def forbidden(*_args, **_kwargs):
            raise AssertionError("unsupported deadline must refuse before I/O")

        patches = (
            patch("megalodon.cli._run_deadline_supported", return_value=False),
            patch("megalodon.cli._load", side_effect=forbidden),
            patch("megalodon.cli.Store", side_effect=forbidden),
            patch("megalodon.cli._events_for", side_effect=forbidden),
            patch("socket.socket", side_effect=forbidden),
            patch("socket.create_connection", side_effect=forbidden),
            patch("socket.getaddrinfo", side_effect=forbidden),
            patch.object(subprocess, "run", side_effect=forbidden),
            patch.object(subprocess, "Popen", side_effect=forbidden),
        )
        with ExitStack() as stack:
            for context in patches:
                stack.enter_context(context)
            output, error = io.StringIO(), io.StringIO()
            with (
                redirect_stdout(output),
                redirect_stderr(error),
                self.assertRaises(SystemExit) as raised,
            ):
                main(["run", "--source", "sample", "--max-seconds", "1"])

        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(
            error.getvalue(),
            "megalodon: max-seconds requires a POSIX runtime with SIGALRM, "
            "ITIMER_REAL, and pthread_sigmask\n",
        )

    @unittest.skipUnless(
        hasattr(signal, "SIGALRM")
        and hasattr(signal, "ITIMER_REAL")
        and hasattr(signal, "setitimer")
        and hasattr(signal, "pthread_sigmask"),
        "POSIX interval timers required",
    )
    def test_blocked_deadline_signal_refuses_before_configuration_or_io(self):
        def forbidden(*_args, **_kwargs):
            raise AssertionError("blocked deadline signal must refuse before I/O")

        patches = (
            patch.object(signal, "pthread_sigmask", return_value={signal.SIGALRM}),
            patch("megalodon.cli._load", side_effect=forbidden),
            patch("megalodon.cli.Store", side_effect=forbidden),
            patch("megalodon.cli._events_for", side_effect=forbidden),
            patch("socket.socket", side_effect=forbidden),
            patch("socket.create_connection", side_effect=forbidden),
            patch("socket.getaddrinfo", side_effect=forbidden),
            patch.object(subprocess, "run", side_effect=forbidden),
            patch.object(subprocess, "Popen", side_effect=forbidden),
        )
        with ExitStack() as stack:
            for context in patches:
                stack.enter_context(context)
            output, error = io.StringIO(), io.StringIO()
            with (
                redirect_stdout(output),
                redirect_stderr(error),
                self.assertRaises(SystemExit) as raised,
            ):
                main(["run", "--source", "sample", "--max-seconds", "1"])

        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(
            error.getvalue(),
            "megalodon: max-seconds requires SIGALRM to be unblocked\n",
        )

    @unittest.skipUnless(
        hasattr(signal, "SIGALRM")
        and hasattr(signal, "ITIMER_REAL")
        and hasattr(signal, "setitimer")
        and hasattr(signal, "pthread_sigmask"),
        "POSIX interval timers required",
    )
    def test_posix_deadline_interrupts_blocked_stdin_and_preserves_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            config, database = write_config(directory)
            root = Path(__file__).resolve().parents[1]
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "megalodon",
                    "run",
                    "--config",
                    str(config),
                    "--source",
                    "jsonl",
                    "--max-events",
                    "100",
                    "--max-seconds",
                    "1",
                ],
                cwd=root,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertIsNotNone(process.stdin)
                process.stdin.write(
                    json.dumps(
                        {
                            "observed_at": "2026-01-01T00:00:00Z",
                            "src_ip": "192.0.2.1",
                            "dst_ip": "198.51.100.2",
                            "protocol": "TCP",
                        }
                    )
                    + "\n"
                )
                process.stdin.flush()
                self.assertEqual(process.wait(timeout=5), 2)
                output = process.stdout.read()
                error = process.stderr.read()
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                if process.stdin is not None:
                    process.stdin.close()
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()

            self.assertEqual(output, "")
            self.assertEqual(
                error, "megalodon: ingestion failed (CAPTURE_ERROR)\n"
            )
            with sqlite3.connect(database) as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT status, processed_count, failure_code, "
                        "termination_reason FROM ingestion_runs"
                    ).fetchone(),
                    ("failed", 1, "CAPTURE_ERROR", "failed"),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM ingestion_run_events"
                    ).fetchone()[0],
                    1,
                )

    def test_config_selected_non_sample_source_refuses_before_store(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "settings.toml"
            config.write_text('[capture]\nsource = "jsonl"\n', encoding="utf-8")
            output = io.StringIO()
            error = io.StringIO()
            with (
                patch("megalodon.cli.Store", side_effect=AssertionError("store opened")),
                patch("megalodon.cli._events_for", side_effect=AssertionError("source opened")),
                redirect_stdout(output),
                redirect_stderr(error),
                self.assertRaises(SystemExit) as raised,
            ):
                main(["run", "--config", str(config)])
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(output.getvalue(), "")
            self.assertIn("require --max-events", error.getvalue())
            self.assertFalse((Path(directory) / "data").exists())

    def test_firewall_plan_is_logged_without_subprocess(self):
        with tempfile.TemporaryDirectory() as directory:
            config, database = write_config(directory)
            with patch.object(subprocess, "run") as run:
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

    def test_live_apply_cli_routes_refuse_before_config_host_or_process_work(self):
        def forbidden(*_args, **_kwargs):
            raise AssertionError("live apply must refuse before config, host, or process work")

        commands = (
            [
                "block",
                "not-an-ip",
                "--reason",
                "",
                "--apply",
                "--confirm",
                "WRONG",
                "--config",
                "/private/SECRET/settings.toml",
            ],
            [
                "firewall-install",
                "--apply",
                "--confirm",
                "WRONG",
                "--config",
                "/private/SECRET/settings.toml",
            ],
        )
        patches = (
            patch("megalodon.cli._load", side_effect=forbidden),
            patch("megalodon.cli.NftablesFirewall", side_effect=forbidden),
            patch.object(os, "geteuid", side_effect=forbidden, create=True),
            patch.object(os, "system", side_effect=forbidden),
            patch.object(shutil, "which", side_effect=forbidden),
            patch.object(subprocess, "run", side_effect=forbidden),
            patch.object(subprocess, "Popen", side_effect=forbidden),
        )
        with ExitStack() as stack:
            for context in patches:
                stack.enter_context(context)
            for command in commands:
                output = io.StringIO()
                error = io.StringIO()
                with self.subTest(command=command), redirect_stdout(output), redirect_stderr(error):
                    with self.assertRaises(SystemExit) as raised:
                        main(command)
                self.assertEqual(raised.exception.code, 2)
                self.assertEqual(output.getvalue(), "")
                self.assertEqual(error.getvalue(), f"megalodon: {LIVE_APPLY_UNSUPPORTED}\n")
                self.assertNotIn("/private/SECRET", error.getvalue())

    def test_live_apply_refuses_before_required_block_argument_validation(self):
        commands = (
            ["block", "--apply"],
            ["block", "--app"],
            ["block", "8.8.8.8", "--apply"],
            ["block", "--reason", "review", "--apply"],
        )
        for command in commands:
            output = io.StringIO()
            error = io.StringIO()
            with self.subTest(command=command), redirect_stdout(output), redirect_stderr(error):
                with self.assertRaises(SystemExit) as raised:
                    main(command)
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(error.getvalue(), f"megalodon: {LIVE_APPLY_UNSUPPORTED}\n")

    def test_live_apply_preflight_uses_process_arguments(self):
        error = io.StringIO()
        with (
            patch.object(sys, "argv", ["megalodon", "block", "--apply"]),
            redirect_stderr(error),
            self.assertRaises(SystemExit) as raised,
        ):
            main()
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(error.getvalue(), f"megalodon: {LIVE_APPLY_UNSUPPORTED}\n")

    def test_top_level_option_terminator_does_not_bypass_live_apply_preflight(self):
        commands = (
            ["--", "block", "--apply"],
            ["--", "firewall-install", "--apply"],
        )
        for command in commands:
            output = io.StringIO()
            error = io.StringIO()
            with self.subTest(command=command), redirect_stdout(output), redirect_stderr(error):
                with self.assertRaises(SystemExit) as raised:
                    main(command)
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(error.getvalue(), f"megalodon: {LIVE_APPLY_UNSUPPORTED}\n")

    def test_non_apply_block_still_uses_normal_argument_validation(self):
        error = io.StringIO()
        with redirect_stderr(error), self.assertRaises(SystemExit) as raised:
            main(["block", "8.8.8.8"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("the following arguments are required: --reason", error.getvalue())
        self.assertNotIn(LIVE_APPLY_UNSUPPORTED, error.getvalue())

    def test_apply_text_after_subcommand_option_terminator_is_not_preflighted(self):
        commands = (
            ["block", "--", "--apply"],
            ["--", "block", "--", "--apply"],
            ["firewall-install", "--", "--apply"],
            ["--", "firewall-install", "--", "--apply"],
        )
        for command in commands:
            error = io.StringIO()
            with self.subTest(command=command), redirect_stderr(error):
                with self.assertRaises(SystemExit) as raised:
                    main(command)
            self.assertEqual(raised.exception.code, 2)
            self.assertIn("usage: megalodon", error.getvalue())
            self.assertNotIn(LIVE_APPLY_UNSUPPORTED, error.getvalue())

    def test_live_apply_refusal_creates_no_store_or_action_row(self):
        with tempfile.TemporaryDirectory() as directory, chdir(directory):
            error = io.StringIO()
            with redirect_stderr(error), self.assertRaises(SystemExit) as raised:
                main(["block", "not-an-ip", "--reason", "", "--apply"])
            self.assertEqual(raised.exception.code, 2)
            self.assertFalse((Path(directory) / "data").exists())

        with tempfile.TemporaryDirectory() as directory:
            config, database = write_config(directory)
            with Store(database) as store:
                before = store.connection.execute("SELECT COUNT(*) FROM actions").fetchone()[0]
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                main(["firewall-install", "--apply", "--config", str(config)])
            self.assertEqual(raised.exception.code, 2)
            with Store(database) as store:
                after = store.connection.execute("SELECT COUNT(*) FROM actions").fetchone()[0]
            self.assertEqual((before, after), (0, 0))

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
