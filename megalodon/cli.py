"""Command-line entry point."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import errno
import json
import logging
import os
from pathlib import Path
import re
import signal
import sqlite3
import sys
import time

from . import __version__, execution_boundary
from .capabilities import catalog
from .posture import local_posture
from .capture import CaptureError, iter_jsonl, iter_sample, iter_scapy
from .config import load_settings
from .firewall import FirewallError, LIVE_APPLY_UNSUPPORTED, NftablesFirewall
from .models import ActionRecord
from .service import MegalodonService
from .dashboard_traffic import TrafficDashboardStore as DashboardStore
from .storage import (
    StorageSchemaError,
    IngestionRunError,
    migrate_database,
    RECONCILIATION_REQUIRED,
    Store,
    StorageCapacityError,
    DEFAULT_MAX_DATABASE_BYTES,
)
from .validation import parse_timestamp, safe_text, ValidationError


MAX_RUN_EVENTS = 10_000_000
MAX_RUN_SECONDS = 86_400
_LIMITED_RUN_SOURCES = frozenset({"jsonl", "scapy"})
_AI_SUCCESS_STATES = frozenset({"observed", "applied", "awaiting_confirmation"})
_STORAGE_CAPACITY_CODE = re.compile(r"STORAGE_CAPACITY:[A-Z_]{1,64}")


def _ai_receipt_path(db_path: Path) -> Path:
    """Keep telemetry outside the AI ledger's main and SQLite sidecar namespace."""
    candidate = db_path.with_name("megalodon-ai-receipts.db")
    reserved_names = {
        candidate.name.casefold(),
        (candidate.name + "-wal").casefold(),
        (candidate.name + "-shm").casefold(),
        (candidate.name + "-journal").casefold(),
    }
    if db_path.name.casefold() in reserved_names:
        return db_path.with_name("megalodon-ai-receipts-ledger.db")
    return candidate


def _ai_result_succeeded(result: object) -> bool:
    """Treat a validated proposal as CLI success without implying application."""
    return type(result) is dict and result.get("state", result.get("execution_state")) in _AI_SUCCESS_STATES


def _bounded_cli_integer(name: str, minimum: int, maximum: int):
    def parse(value: str) -> int:
        candidate = value.strip()
        if not candidate.isascii() or not candidate.isdecimal():
            raise argparse.ArgumentTypeError(f"{name} must be a decimal integer")
        # Bound conversion independently of Python's configurable integer digit
        # limit, while retaining the existing acceptance of leading zeroes.
        digits = candidate.lstrip("0") or "0"
        if len(digits) > len(str(maximum)):
            raise argparse.ArgumentTypeError(
                f"{name} must be between {minimum} and {maximum}"
            )
        parsed = int(digits)
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(
                f"{name} must be between {minimum} and {maximum}"
            )
        return parsed

    return parse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="megalodon", description="Local-first defensive network telemetry")
    parser.add_argument("--stage0-offline", action="store_true",
                        help="one-way offline fence; only stage0-status is available in this initial slice")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("stage0-status", help="print the in-memory application boundary, not acceptance")

    ai = sub.add_parser("ai", help="bounded local AI doctor, question and tool broker")
    ai.add_argument("operation", choices=("doctor", "ask", "tool"))
    ai.add_argument("--config", help="explicit TOML settings file")
    ai.add_argument("--question", choices=("seeing", "changed", "alerts", "integrations", "model", "safe", "plan", "report"))
    ai.add_argument("--request", help="one closed JSON tool request; no commands or paths")

    capabilities = sub.add_parser("capabilities", help="print the static platform and free-software catalog")
    capabilities.add_argument(
        "--platform",
        choices=("linux", "windows", "other"),
        help="show one documented profile; defaults to the current runtime family",
    )

    sub.add_parser(
        "readiness",
        help="print a bounded local executable-presence receipt without running tools",
    )

    posture = sub.add_parser(
        "posture",
        help="print a bounded package-level posture receipt without probing the host",
    )
    posture.add_argument(
        "--platform",
        choices=("linux", "windows", "other"),
        help="select a documented static profile; defaults to the runtime platform family",
    )

    hub = sub.add_parser("hub-plan", help="print the static, non-executing integration workflow plan")
    hub.add_argument(
        "--platform",
        choices=("linux", "windows", "other"),
        help="show one documented profile; defaults to the current runtime family",
    )
    from .hub import WORKFLOW_IDS
    hub.add_argument("--workflow", choices=WORKFLOW_IDS, help="show one closed workflow")

    automation_preview = sub.add_parser(
        "automation-preview", help="preview a bounded recurrence without scheduling a job",
    )
    automation_preview.add_argument("--dtstart", required=True, help="local start time, YYYY-MM-DDTHH:MM:SS")
    automation_preview.add_argument("--timezone", required=True, help="IANA time zone for the local start time")
    automation_preview.add_argument("--rrule", required=True, help="bounded recurrence rule")
    automation_preview.add_argument(
        "--dst-policy", choices=("reject", "skip", "shift_forward", "fold_earlier", "fold_later"),
        default="reject", help="how to handle ambiguous or nonexistent local times",
    )
    automation_preview.add_argument(
        "--limit", type=_bounded_cli_integer("limit", 1, 366), default=10,
        help="maximum number of preview occurrences (1-366; default 10)",
    )

    sub.add_parser(
        "detectors",
        help="print the core specification and threat-signal detector registries",
    )
    watchlist = sub.add_parser(
        "watchlist", help="check, query or import a local IP/CIDR indicator watchlist"
    )
    watch_sub = watchlist.add_subparsers(dest="watchlist_command", required=True)
    watch_check = watch_sub.add_parser("check", help="validate a watchlist file and summarize it")
    watch_check.add_argument("--path", type=Path, required=True)
    watch_match = watch_sub.add_parser("match", help="look up one address in a watchlist")
    watch_match.add_argument("--path", type=Path, required=True)
    watch_match.add_argument("--address", required=True)
    watch_import = watch_sub.add_parser(
        "import-stix",
        help="convert IP equality indicators from a digest-pinned STIX 2.1 bundle",
    )
    watch_import.add_argument("--bundle", type=Path, required=True)
    watch_import.add_argument("--digest", required=True, help="sha256:<hex> of the bundle bytes")
    watch_import.add_argument("--output", type=Path, required=True)
    watch_import.add_argument("--replace", action="store_true", help="overwrite an existing output")

    canary = sub.add_parser(
        "canary", help="plant and check bait files that reveal reading, change or deletion"
    )
    canary_sub = canary.add_subparsers(dest="canary_command", required=True)
    canary_plant = canary_sub.add_parser("plant", help="create bait files and an owner-private manifest")
    canary_plant.add_argument("--dir", type=Path, required=True, help="existing directory for the bait")
    canary_plant.add_argument("--manifest", type=Path, required=True,
                              help="manifest path outside the bait directory")
    canary_plant.add_argument("--count", type=_bounded_cli_integer("count", 1, 5), default=3)
    canary_plant.add_argument("--replace", action="store_true", help="overwrite an existing manifest")
    for name, text in (("check", "report removed, changed or read canaries (exit 1 when tripped)"),
                       ("rearm", "after review, reset canaries so new reads are detected")):
        command = canary_sub.add_parser(name, help=text)
        command.add_argument("--manifest", type=Path, required=True)

    yara = sub.add_parser(
        "yara", help="your own YARA rules for the optional file inspector"
    )
    yara_sub = yara.add_subparsers(dest="yara_command", required=True)
    yara_check = yara_sub.add_parser(
        "check", help="check the rules folder and, when the YARA runtime is ready, compile it in the sandbox")
    yara_check.add_argument("--dir", type=Path,
                            help="rules folder (default ~/.config/megalodon/yara-rules)")
    yara_sub.add_parser("install", help="download and verify the pinned YARA runtime (non-root Linux)")
    feeds = sub.add_parser("feeds", help="refresh threat feeds into one local watchlist (run from a timer)")
    feeds_sub = feeds.add_subparsers(dest="feeds_command", required=True)
    feeds_refresh = feeds_sub.add_parser(
        "refresh", help="download each [[feeds.source]] and rebuild the feeds watchlist (exit 1 if any failed)")
    feeds_refresh.add_argument("--if-older", type=_bounded_cli_integer("minutes", 1, 525600), metavar="MINUTES",
                               help="skip sources checked within this many minutes")
    feeds_status = feeds_sub.add_parser("status", help="show each source's indicator count and age (exit 1 if stale)")
    for command in (feeds_refresh, feeds_status):
        command.add_argument("--config", type=Path,
                             help="settings file (default ~/.config/megalodon/settings.toml)")

    drill = sub.add_parser(
        "drill", help="self-test every detection layer end to end in throwaway places (exit 1 if one failed)")
    drill.add_argument("--alerts", action="store_true",
                       help="also send one labeled test notice to each configured alert destination")
    drill.add_argument("--config", type=Path,
                       help="settings file for --alerts (default ~/.config/megalodon/settings.toml)")

    logwatch = sub.add_parser(
        "logwatch", help="baseline and check system logs for wiping, truncation or rewriting (exit 1 on findings)")
    logwatch_sub = logwatch.add_subparsers(dest="logwatch_command", required=True)
    for name, text in (("baseline", "record each log file's identity"),
                       ("check", "report logs deleted, truncated, rewritten or replaced since the baseline"),
                       ("accept", "after review or rotation, record the current logs as the new baseline")):
        command = logwatch_sub.add_parser(name, help=text)
        command.add_argument("--manifest", type=Path,
                             help="baseline file (default ~/.config/megalodon/log-integrity.json)")
        if name == "baseline":
            command.add_argument("--replace", action="store_true", help="overwrite an existing baseline")
        if name == "check":
            command.add_argument("--alert", action="store_true",
                                 help="also send a summary to the [alerts] destinations in the settings file")
            command.add_argument("--config", type=Path,
                                 help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    persist = sub.add_parser(
        "persistence", help="baseline and check where attackers hide to survive reboots (exit 1 on changes)")
    persist_sub = persist.add_subparsers(dest="persistence_command", required=True)
    for name, text in (("baseline", "record the current state of every persistence location"),
                       ("check", "report what was added, changed or removed since the baseline"),
                       ("accept", "after review, record the current state as the new baseline")):
        command = persist_sub.add_parser(name, help=text)
        command.add_argument("--manifest", type=Path, help="baseline file (default ~/.config/megalodon/persistence.json)")
        if name == "baseline":
            command.add_argument("--replace", action="store_true", help="overwrite an existing baseline")
        if name == "check":
            command.add_argument("--alert", action="store_true",
                                 help="also send a summary to the [alerts] destinations in the settings file")
            command.add_argument("--config", type=Path,
                                 help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    listeners = sub.add_parser(
        "listeners", help="baseline and check which programs listen for connections (exit 1 on changes, Linux)")
    listeners_sub = listeners.add_subparsers(dest="listeners_command", required=True)
    for name, text in (("baseline", "record every listening port, where it is reachable and which program owns it"),
                       ("check", "report new listeners, ports taken over by another program and wider exposure"),
                       ("accept", "after review, record the current listeners as the new baseline")):
        command = listeners_sub.add_parser(name, help=text)
        command.add_argument("--manifest", type=Path, help="baseline file (default ~/.config/megalodon/listeners.json)")
        if name == "baseline":
            command.add_argument("--replace", action="store_true", help="overwrite an existing baseline")
        if name == "check":
            command.add_argument("--alert", action="store_true",
                                 help="also send a summary to the [alerts] destinations in the settings file")
            command.add_argument("--config", type=Path,
                                 help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    ancestry = sub.add_parser(
        "ancestry", help="catch web servers, databases and mail servers starting shells or attack tools (Linux)")
    ancestry_sub = ancestry.add_subparsers(dest="ancestry_command", required=True)
    for name, text in (("check", "review the processes running now (exit 1 on findings)"),
                       ("watch", "report each program a service starts, as it starts, as JSON lines"),
                       ("allow", "after review, allow one service program to start one program")):
        command = ancestry_sub.add_parser(name, help=text)
        command.add_argument("--allow-file", type=Path,
                             help="allowed pairs (default ~/.config/megalodon/ancestry-allow.json)")
        if name == "allow":
            command.add_argument("service", help="the service's executable path, e.g. /usr/lib/postgresql/16/bin/postgres")
            command.add_argument("program", help="the program it may start, e.g. /usr/bin/dash")
            continue
        if name == "watch":
            command.add_argument("--interval", type=float, default=0.25,
                                 help="seconds between /proc scans when not root (default 0.25)")
        command.add_argument("--alert", action="store_true",
                             help="also send findings to the [alerts] destinations in the settings file")
        command.add_argument("--config", type=Path,
                             help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    devices = sub.add_parser(
        "devices", help="baseline and check USB devices, keyboards, network adapters and removable disks (Linux)")
    devices_sub = devices.add_subparsers(dest="devices_command", required=True)
    for name, text in (("baseline", "record the devices attached now"),
                       ("check", "report new keyboards, network adapters, storage and Thunderbolt devices "
                                 "(exit 1 on findings)"),
                       ("watch", "check every few seconds and print each new device once, as JSON lines"),
                       ("accept", "after review, record the current devices as the new baseline")):
        command = devices_sub.add_parser(name, help=text)
        command.add_argument("--manifest", type=Path, help="baseline file (default ~/.config/megalodon/devices.json)")
        if name == "baseline":
            command.add_argument("--replace", action="store_true", help="overwrite an existing baseline")
        if name == "watch":
            command.add_argument("--interval", type=float, default=2.0, help="seconds between checks (default 2)")
        if name in ("check", "watch"):
            command.add_argument("--alert", action="store_true",
                                 help="also send findings to the [alerts] destinations in the settings file")
            command.add_argument("--config", type=Path,
                                 help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    rootkit = sub.add_parser(
        "rootkit", help="cross-check processes, kernel modules, ports and folders for hidden ones (Linux)")
    rootkit_sub = rootkit.add_subparsers(dest="rootkit_command", required=True)
    command = rootkit_sub.add_parser("check", help="report what one view of the system hides from another "
                                                   "(exit 1 on findings)")
    command.add_argument("--skip-ports", action="store_true",
                         help="do not test ports (the port test briefly binds every free port)")
    command.add_argument("--max-pid", type=int, help="highest process ID to probe (default: the kernel's pid_max)")
    command.add_argument("--alert", action="store_true",
                         help="also send findings to the [alerts] destinations in the settings file")
    command.add_argument("--config", type=Path,
                         help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    binaries = sub.add_parser(
        "binaries", help="detect trojaned system programs and libraries (exit 1 on findings)")
    binaries_sub = binaries.add_subparsers(dest="binaries_command", required=True)
    for name, text in (("verify", "compare installed programs with their package checksums now; no baseline needed"),
                       ("baseline", "record a SHA-256 of every program, packaged or not"),
                       ("check", "verify packages and report programs added or changed since the baseline"),
                       ("accept", "after review, record the current programs as the new baseline")):
        command = binaries_sub.add_parser(name, help=text)
        command.add_argument("--all-libraries", action="store_true",
                             help="verify every packaged shared library, not only the commonly backdoored ones")
        if name != "verify":
            command.add_argument("--manifest", type=Path,
                                 help="baseline file (default ~/.config/megalodon/binaries.json)")
        if name == "baseline":
            command.add_argument("--replace", action="store_true", help="overwrite an existing baseline")
        if name in ("verify", "check"):
            command.add_argument("--alert", action="store_true",
                                 help="also send a summary to the [alerts] destinations in the settings file")
            command.add_argument("--config", type=Path,
                                 help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    respond = sub.add_parser(
        "respond", help="automated response engine in shadow mode: decide and record, never carry out")
    respond_sub = respond.add_subparsers(dest="respond_command", required=True)
    for name, text in (("init", "write the default response policy (owner-only) to edit and review"),
                       ("run", "collect findings once, decide under the policy, and record the decisions"),
                       ("watch", "repeat run every --interval seconds until stopped"),
                       ("ingest", "decide on findings read as JSON lines from standard input"),
                       ("report", "summarize what would have been done")):
        command = respond_sub.add_parser(name, help=text)
        if name != "report":
            command.add_argument("--policy", type=Path,
                                 help="policy file (default ~/.config/megalodon/response-policy.toml)")
        if name == "init":
            command.add_argument("--replace", action="store_true", help="overwrite an existing policy")
            continue
        command.add_argument("--ledger", type=Path,
                             help="decision ledger (default ~/.local/state/megalodon/response-shadow.jsonl)")
        if name == "report":
            command.add_argument("--hours", type=_bounded_cli_integer("hours", 1, 8784), default=168,
                                 help="how far back to look (default 168, one week)")
            continue
        command.add_argument("--state", type=Path,
                             help="engine state (default ~/.local/state/megalodon/response-state.json)")
        if name == "watch":
            command.add_argument("--interval", type=_bounded_cli_integer("interval", 30, 86400), default=300,
                                 help="seconds between passes (default 300)")

    evidence = sub.add_parser(
        "evidence", help="collect a read-only, hashed evidence snapshot of this machine, or verify one")
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)
    collect = evidence_sub.add_parser(
        "collect", help="save processes, sockets, sessions, recent files and watch reports into a sealed bundle")
    collect.add_argument("--output", type=Path,
                         help="new bundle folder (default ~/.local/share/megalodon/evidence/<time>)")
    collect.add_argument("--hours", type=_bounded_cli_integer("hours", 1, 720), default=24,
                         help="list files changed in the last N hours (default 24)")
    collect.add_argument("--with-command-lines", action="store_true",
                         help="also record process command lines (they can contain passwords and tokens)")
    collect.add_argument("--skip-program-verification", action="store_true",
                         help="skip the package check of installed programs (faster)")
    collect.add_argument("--no-program-copies", action="store_true",
                         help="do not copy deleted, in-memory or temporary-folder programs into the bundle")
    collect.add_argument("--alert", action="store_true",
                         help="also send the bundle's manifest digest to the [alerts] destinations")
    collect.add_argument("--config", type=Path,
                         help="settings file for --alert (default ~/.config/megalodon/settings.toml)")
    verify_bundle = evidence_sub.add_parser("verify", help="re-check every file of a bundle against its manifest")
    verify_bundle.add_argument("bundle", type=Path)
    verify_bundle.add_argument("--expected", help="the manifest SHA-256 recorded when the bundle was collected")

    ransom = sub.add_parser("ransomware", help="watch folders for ransomware-style file encryption (Linux)")
    ransom_sub = ransom.add_subparsers(dest="ransomware_command", required=True)
    ransom_watch = ransom_sub.add_parser(
        "watch", help="watch folders until stopped; print each finding as JSON and send it to configured alerts")
    ransom_watch.add_argument("--dir", type=Path, action="append", required=True,
                              help="folder to watch, recursively (repeat for more)")
    ransom_watch.add_argument("--min-files", type=_bounded_cli_integer("min-files", 2, 10000), default=10,
                              help="encrypted files within the window that raise the alarm (default 10)")
    ransom_watch.add_argument("--window", type=_bounded_cli_integer("window", 5, 3600), default=60,
                              help="seconds (default 60)")
    ransom_watch.add_argument("--config", type=Path,
                              help="settings file whose [alerts] receive findings "
                                   "(default ~/.config/megalodon/settings.toml when present)")
    ransom_sub.add_parser("selftest", help="encrypt throwaway files in a temporary folder and confirm the alarm")

    alerts = sub.add_parser("alerts", help="off-machine alerts: webhooks (JSON, Slack, Discord, ntfy) and syslog")
    alerts_sub = alerts.add_subparsers(dest="alerts_command", required=True)
    alerts_test = alerts_sub.add_parser(
        "test", help="send one labeled test alert to every configured destination (exit 1 if any fails)")
    alerts_test.add_argument("--config", type=Path,
                             help="settings file (default ~/.config/megalodon/settings.toml)")

    auth = sub.add_parser(
        "auth-review",
        help="review an auth log for brute force, spraying and suspicious logins (exit 1 on HIGH+)",
    )
    auth.add_argument("--input", required=True,
                      help="auth log path (e.g. /var/log/auth.log), or - for journalctl -o short-iso on stdin")
    auth.add_argument("--utc", action="store_true",
                      help="classic syslog stamps are UTC rather than this computer's local time")
    auth.add_argument("--emit-watchlist", type=Path,
                      help="write attacking addresses to an owner-private IOC watchlist file")
    auth.add_argument("--replace", action="store_true", help="overwrite an existing watchlist output")

    run = sub.add_parser("run", help="process metadata events")
    run.add_argument("--config", help="explicit TOML settings file; safe built-in defaults are used when omitted")
    run.add_argument("--source", choices=("sample", "jsonl", "scapy"), default=None)
    run.add_argument("--input", type=Path, help="JSONL input file; stdin is used when omitted")
    run.add_argument("--interface", help="capture interface for --source scapy")
    run.add_argument("--demo-threat", action="store_true", help="add synthetic detections to sample data")
    run.add_argument(
        "--max-events",
        type=_bounded_cli_integer("max-events", 1, MAX_RUN_EVENTS),
        default=None,
        help=(
            "stop after N events; required for jsonl and scapy sources "
            f"(maximum {MAX_RUN_EVENTS})"
        ),
    )
    run.add_argument(
        "--max-seconds",
        type=_bounded_cli_integer("max-seconds", 1, MAX_RUN_SECONDS),
        default=None,
        help=(
            "fail closed after N seconds while acquiring, consuming, processing, "
            "or closing the event source on supported Linux runtimes "
            f"(maximum {MAX_RUN_SECONDS})"
        ),
    )

    migrate = sub.add_parser(
        "database-migrate",
        help="explicitly back up and migrate the configured audit database",
    )
    migrate.add_argument(
        "--config",
        help="explicit TOML settings file; safe built-in defaults are used when omitted",
    )

    backup = sub.add_parser(
        "database-backup",
        help="back up the configured audit database to a new local artifact",
    )
    backup.add_argument("destination", type=Path)
    backup.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="new path for the bounded recovery manifest",
    )
    backup.add_argument("--operation-id", required=True)
    backup.add_argument(
        "--config",
        help="explicit TOML settings file; safe built-in defaults are used when omitted",
    )

    restore = sub.add_parser(
        "database-restore",
        help="restore a reviewed backup into a new, inactive database",
    )
    restore.add_argument("source", type=Path)
    restore.add_argument("destination", type=Path)
    restore.add_argument("--manifest", type=Path, required=True)
    restore.add_argument("--artifact-sha256", required=True)
    restore.add_argument("--operation-id", required=True)

    reconciliation_status = sub.add_parser(
        "database-reconciliation-status",
        help="list bounded run receipts that require operator reconciliation",
    )
    reconciliation_status.add_argument("--config")

    reconcile = sub.add_parser(
        "database-reconcile",
        help="mark one pinned orphaned run as requiring reconciliation",
    )
    reconcile.add_argument("run_id", type=_bounded_cli_integer("run-id", 1, 2**63 - 1))
    reconcile.add_argument(
        "--started-at",
        required=True,
        help="exact started_at value shown by database-reconciliation-status",
    )
    reconcile.add_argument("--config")

    dashboard = sub.add_parser("dashboard", aliases=["hud"], help="serve the local dashboard; hud also checks tool presence and supports first launch")
    dashboard.add_argument("--config", help="explicit TOML settings file; safe built-in defaults are used when omitted")
    dashboard.add_argument("--companion-config", type=Path,
                           help="override automatic local companion scope and report-watch settings")
    dashboard.add_argument("--no-auto-companions", action="store_true",
                           help="disable automatic local companion collection and report watching")
    dashboard.add_argument("--host")
    dashboard.add_argument("--port", type=_bounded_cli_integer("port", 1, 65535))
    dashboard.add_argument("--allow-remote", action="store_true", help="removed unsafe option; supplying it refuses startup")
    dashboard.add_argument("--require-sign-in", action="store_true", help="require a local HUD password; off by default")
    dashboard.add_argument(
        "--enable-tool-management", action="store_true",
        help="hud only: enable token-gated fixed Install/Start/Open actions for a non-root Linux launch",
    )
    dashboard.add_argument(
        "--refresh-seconds",
        type=_bounded_cli_integer("refresh-seconds", 2, 300),
        help="live refresh interval from 2 to 300 seconds; overrides configuration",
    )
    dashboard.add_argument(
        "--event-limit",
        type=_bounded_cli_integer("event-limit", 1, 200),
        help="newest detections loaded per refresh, from 1 to 200; overrides configuration",
    )
    dashboard.add_argument(
        "--offline-run",
        type=Path,
        help="absolute path to one complete private offline run; loaded read-only at startup",
    )
    dashboard.add_argument(
        "--suricata-db",
        type=Path,
        help="existing private Suricata store; bounded read-only startup snapshot",
    )
    dashboard.add_argument(
        "--geoip-db",
        type=Path,
        help="optional owner-private offline MMDB region database; no IPs leave this PC",
    )
    dashboard.add_argument(
        "--open-browser",
        action="store_true",
        help="open the loopback HUD in the default browser after the server binds",
    )

    plan = sub.add_parser("firewall-plan", help="print a non-mutating nftables plan")
    plan.add_argument("ip")
    plan.add_argument("--reason", default="manual review")
    plan.add_argument("--config", help="explicit TOML settings file; safe built-in defaults are used when omitted")

    install = sub.add_parser("firewall-install", help="print MEGALODON's isolated nftables table plan")
    install.add_argument("--config", help="explicit TOML settings file; safe built-in defaults are used when omitted")
    install.add_argument(
        "--apply",
        action="store_true",
        help="unsupported compatibility flag; always fails closed without changing the host",
    )
    install.add_argument("--confirm", help="retained for compatibility; live application is unsupported")

    block = sub.add_parser("block", help="print one non-mutating, time-limited block plan")
    block.add_argument("ip")
    block.add_argument("--reason", required=True)
    block.add_argument("--config", help="explicit TOML settings file; safe built-in defaults are used when omitted")
    block.add_argument(
        "--apply",
        action="store_true",
        help="unsupported compatibility flag; always fails closed without changing the host",
    )
    block.add_argument("--confirm", help="retained for compatibility; live application is unsupported")

    return parser


def _configure_logging(level: str) -> None:
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format="%(levelname)s %(message)s")


def _capabilities(args: argparse.Namespace) -> int:
    print(json.dumps(catalog(args.platform), sort_keys=True))
    return 0


def _readiness(args: argparse.Namespace) -> int:
    from .readiness import readiness_json

    print(readiness_json())
    return 0


def _posture(args: argparse.Namespace) -> int:
    print(json.dumps(local_posture(args.platform), sort_keys=True))
    return 0


def _hub_plan(args: argparse.Namespace) -> int:
    from .hub import integration_plan

    print(json.dumps(integration_plan(args.platform, args.workflow), sort_keys=True))
    return 0


def _automation_preview(args: argparse.Namespace) -> int:
    from .automation_schedule import AutomationScheduleError, next_occurrences

    try:
        occurrences = next_occurrences(
            dtstart=args.dtstart, schedule_timezone=args.timezone,
            rrule=args.rrule, dst_policy=args.dst_policy, limit=args.limit,
        )
    except (AutomationScheduleError, ValueError, OverflowError) as exc:
        print(f"megalodon automation-preview: {getattr(exc, 'code', 'PREVIEW_UNAVAILABLE')}", file=sys.stderr)
        return 2
    print(json.dumps({
        "schema_version": "megalodon-automation-preview-v1",
        "status": "preview_only",
        "occurrences": [dict(item) for item in occurrences],
    }, sort_keys=True, allow_nan=False))
    return 0


def _load(config: str | None):
    try:
        settings = load_settings(config)
    except OSError as exc:
        raise ValueError("configuration file could not be read") from exc
    _configure_logging(settings.log_level)
    return settings


@contextmanager
def _owned_source(source):
    """Close a CLI-owned iterator/stream without hiding a primary failure."""

    primary_error: BaseException | None = None
    try:
        yield source
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        try:
            close = getattr(source, "close", None)
            if close is not None:
                close()
        except BaseException as exc:
            if primary_error is not None and not isinstance(primary_error, GeneratorExit):
                BaseException.add_note(
                    primary_error,
                    "event source cleanup failed; shutdown is unverified",
                )
            elif isinstance(exc, Exception):
                raise CaptureError(
                    "event source cleanup failed; shutdown is unverified"
                ) from None
            else:
                raise


def _jsonl_file_events(path: Path):
    # Lazy open: closing an unstarted iterator must not acquire a file.
    # Preserve terminators so CRLF bytes count toward both JSONL byte budgets.
    with _owned_source(path.open("r", encoding="utf-8", newline="")) as stream:
        yield from iter_jsonl(stream)


def _events_for(args: argparse.Namespace, settings):
    source = _source_for(args, settings)
    if source == "sample":
        return iter_sample(include_demo_threat=args.demo_threat)
    if source == "jsonl":
        if args.input:
            return _jsonl_file_events(args.input)
        return iter_jsonl(sys.stdin)
    if source == "scapy":
        return iter_scapy(args.interface or settings.interface, dns_names=settings.threat.dns_names)
    raise CaptureError(f"unsupported source: {source}")


def _source_for(args: argparse.Namespace, settings) -> str:
    return args.source or settings.capture_source


def _require_finite_run_limit(source: str | None, max_events: int | None) -> None:
    if source in _LIMITED_RUN_SOURCES and max_events is None:
        raise ValueError(
            "jsonl and scapy sources require --max-events between "
            f"1 and {MAX_RUN_EVENTS}"
        )


_SOURCE_ONLY_OPTIONS = (
    ("input", "jsonl", "--input is only valid with the jsonl source"),
    ("interface", "scapy", "--interface is only valid with the scapy source"),
    ("demo_threat", "sample", "--demo-threat is only valid with the sample source"),
)


def _require_source_options(source: str | None, args: argparse.Namespace) -> None:
    """Refuse a source-specific option the selected source would ignore."""
    for name, owner, message in _SOURCE_ONLY_OPTIONS:
        value = getattr(args, name, None)
        if value is not None and value is not False and source != owner:
            raise ValueError(message)


def _require_run_deadline_source(
    source: str | None, max_seconds: int | None
) -> None:
    if source == "scapy" and max_seconds is not None:
        raise ValueError(
            "max-seconds is unavailable for threaded scapy capture"
        )


def _run_deadline_supported() -> bool:
    return (
        sys.platform.startswith("linux")
        and hasattr(signal, "SIGALRM")
        and hasattr(signal, "ITIMER_REAL")
        and hasattr(signal, "SIG_BLOCK")
        and hasattr(signal, "SIG_SETMASK")
        and callable(getattr(signal, "getitimer", None))
        and callable(getattr(signal, "setitimer", None))
        and callable(getattr(signal, "pthread_sigmask", None))
        and callable(getattr(signal, "sigpending", None))
        and callable(getattr(os, "scandir", None))
    )


def _require_single_threaded_run_deadline() -> None:
    try:
        with os.scandir("/proc/self/task") as tasks:
            task_count = 0
            for _task in tasks:
                task_count += 1
                if task_count > 1:
                    raise ValueError(
                        "max-seconds requires a single-threaded process"
                    )
    except OSError:
        raise ValueError(
            "max-seconds could not inspect the OS thread set"
        ) from None
    if task_count != 1:
        raise ValueError("max-seconds could not inspect the OS thread set")


def _require_run_deadline_support(max_seconds: int | None) -> None:
    if max_seconds is None:
        return
    if not _run_deadline_supported():
        raise ValueError(
            "max-seconds requires a Linux runtime with SIGALRM, ITIMER_REAL, "
            "pthread_sigmask, sigpending, and procfs thread inspection"
        )
    _require_single_threaded_run_deadline()
    try:
        blocked_signals = signal.pthread_sigmask(signal.SIG_BLOCK, ())
    except (OSError, ValueError):
        raise ValueError(
            "max-seconds could not inspect the POSIX signal mask"
        ) from None
    if signal.SIGALRM in blocked_signals:
        raise ValueError("max-seconds requires SIGALRM to be unblocked")
    try:
        pending_signals = signal.sigpending()
    except (OSError, ValueError):
        raise ValueError(
            "max-seconds could not inspect pending POSIX signals"
        ) from None
    if signal.SIGALRM in pending_signals:
        raise ValueError("max-seconds cannot start with a pending SIGALRM")
    try:
        active_timer = signal.getitimer(signal.ITIMER_REAL)
    except (OSError, ValueError):
        raise ValueError("max-seconds could not inspect the POSIX run timer") from None
    if active_timer != (0.0, 0.0):
        raise ValueError("max-seconds cannot replace an active POSIX process timer")


def _storage_limit(settings) -> int:
    storage = getattr(settings, "storage", None)
    return getattr(storage, "max_database_bytes", DEFAULT_MAX_DATABASE_BYTES)


def _storage_failure_message(exc: BaseException) -> str:
    """Return a fixed, path-free diagnostic for a storage or I/O failure."""
    code = str(exc)
    if isinstance(exc, StorageCapacityError) and _STORAGE_CAPACITY_CODE.fullmatch(code):
        return f"megalodon: {code}"
    if isinstance(exc, sqlite3.Error):
        return "megalodon: storage operation failed"
    return "megalodon: I/O operation failed"


def _run_failure_code(exc: Exception) -> str:
    if isinstance(exc, CaptureError):
        return "CAPTURE_ERROR"
    if isinstance(exc, sqlite3.Error):
        return "STORAGE_ERROR"
    if isinstance(exc, OSError):
        return "IO_ERROR"
    return "VALIDATION_ERROR"


class _RunInterrupted(KeyboardInterrupt):
    def __init__(self, signum: int):
        super().__init__()
        self.signum = signum


@contextmanager
def _scoped_run_deadline(max_seconds: int | None):
    """Bound single-threaded Linux source ownership with a process alarm."""

    if max_seconds is None:
        yield
        return
    _require_run_deadline_support(max_seconds)

    alarm_signal = signal.SIGALRM
    timer_kind = signal.ITIMER_REAL
    previous_handler = signal.getsignal(alarm_signal)

    def deadline_exceeded(_signum, _frame):
        raise CaptureError("ingestion deadline exceeded")

    try:
        setup_previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
    except (OSError, ValueError):
        raise ValueError(
            "max-seconds could not inspect POSIX run deadline setup"
        ) from None
    try:
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {alarm_signal})
    except (OSError, ValueError):
        raise ValueError(
            "max-seconds could not protect POSIX run deadline setup"
        ) from None
    except BaseException:
        signal.pthread_sigmask(signal.SIG_SETMASK, setup_previous_mask)
        raise
    if alarm_signal in previous_mask:
        raise ValueError("max-seconds requires SIGALRM to be unblocked")
    try:
        pending_signals = signal.sigpending()
    except (OSError, ValueError):
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        raise ValueError(
            "max-seconds could not inspect pending POSIX signals"
        ) from None
    except BaseException:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        raise
    if alarm_signal in pending_signals:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        raise ValueError("max-seconds cannot start with a pending SIGALRM")

    handler_installed = False
    timer_started = False
    mask_restored = False
    competing_timer = None
    try:
        _require_single_threaded_run_deadline()
        try:
            signal.signal(alarm_signal, deadline_exceeded)
        except ValueError:
            raise ValueError(
                "max-seconds requires the interpreter main thread"
            ) from None
        except BaseException:
            # Python signal dispatch occurs after the handler swap returns from
            # the OS. Restore conservatively during cleanup before re-raising.
            handler_installed = True
            raise
        else:
            handler_installed = True
        # Treat an interrupted arming call as live until cleanup proves
        # otherwise; setitimer may have succeeded before Python dispatch.
        timer_started = True
        try:
            previous_timer = signal.setitimer(timer_kind, max_seconds)
        except (OSError, ValueError):
            raise ValueError(
                "max-seconds could not arm the POSIX run deadline"
            ) from None
        if previous_timer != (0.0, 0.0):
            competing_timer = previous_timer
            restore_started = time.monotonic()
            try:
                signal.setitimer(timer_kind, *previous_timer)
            except (OSError, ValueError):
                raise ValueError(
                    "max-seconds could not restore a competing POSIX process timer"
                ) from None
            except BaseException:
                # Dispatch can occur immediately before or after the timer
                # syscall. Read back the process timer instead of assuming
                # that the competing timer was restored. Cleanup will cancel
                # our timer and restore the displaced timer when it was not.
                try:
                    active_timer = signal.getitimer(timer_kind)
                except BaseException:
                    pass
                else:
                    elapsed = max(0.0, time.monotonic() - restore_started)
                    expected_delay, expected_interval = previous_timer
                    active_delay, active_interval = active_timer
                    tolerance = elapsed + 0.01
                    if (
                        active_interval == expected_interval
                        and max(0.0, expected_delay - tolerance)
                        <= active_delay
                        <= expected_delay + tolerance
                    ):
                        timer_started = False
                        competing_timer = None
                raise
            else:
                timer_started = False
                competing_timer = None
            raise ValueError(
                "max-seconds cannot replace an active POSIX process timer"
            )
        try:
            pending_signals = signal.sigpending()
        except (OSError, ValueError):
            raise ValueError(
                "max-seconds could not inspect pending POSIX signals"
            ) from None
        if alarm_signal in pending_signals:
            # The protected boundary was clear immediately before arming. Keep
            # our handler installed while releasing a post-arm pending alarm so
            # an already-expired deadline remains a CaptureError.
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            except (OSError, ValueError):
                raise ValueError(
                    "max-seconds could not restore the POSIX signal mask"
                ) from None
            except BaseException:
                mask_restored = True
                raise
            else:
                mask_restored = True
            raise CaptureError("ingestion deadline exceeded")
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        except (OSError, ValueError):
            raise ValueError(
                "max-seconds could not restore the POSIX signal mask"
            ) from None
        except BaseException:
            # Python dispatch occurs after the mask syscall returns. Record
            # the unblocked state so teardown first blocks the alarm again.
            mask_restored = True
            raise
        else:
            mask_restored = True
        yield
    finally:
        try:
            if handler_installed:
                cleanup_mask = None
                cleanup_mask_error = None
                cleanup_entry_error = None
                if mask_restored:
                    try:
                        cleanup_mask = signal.pthread_sigmask(
                            signal.SIG_BLOCK, {alarm_signal}
                        )
                    except (OSError, ValueError):
                        cleanup_mask_error = ValueError(
                            "max-seconds could not protect POSIX run deadline cleanup"
                        )
                    except BaseException as exc:
                        # Python signal dispatch occurs after the masking syscall
                        # completes. Preserve that interruption, finish teardown
                        # under the now-blocked mask, then re-raise it.
                        cleanup_mask = previous_mask
                        cleanup_entry_error = exc
                timer_inactive = not timer_started
                cancellation_error = None
                timer_inspection_error = None
                competing_restore_error = None
                try:
                    if timer_started:
                        signal.setitimer(timer_kind, 0.0)
                        timer_inactive = True
                except BaseException as exc:
                    cancellation_error = exc
                    try:
                        timer_inactive = (
                            signal.getitimer(timer_kind) == (0.0, 0.0)
                        )
                    except (OSError, ValueError):
                        timer_inactive = False
                    except BaseException as exc:
                        # Preserve signal dispatch from the inspection, but do
                        # not skip mask/handler restoration decisions.
                        timer_inactive = False
                        timer_inspection_error = exc
                if competing_timer is not None and timer_inactive:
                    try:
                        signal.setitimer(timer_kind, *competing_timer)
                    except BaseException as exc:
                        competing_restore_error = exc
                    else:
                        competing_timer = None
                try:
                    if cleanup_mask is not None:
                        # Keep the deadline handler installed while unblocking so
                        # a just-pending MEGALODON alarm cannot reach the prior
                        # handler. Python dispatches it here as CaptureError.
                        signal.pthread_sigmask(signal.SIG_SETMASK, cleanup_mask)
                finally:
                    if timer_inactive and competing_timer is None and (
                        not mask_restored or cleanup_mask is not None
                    ):
                        signal.signal(alarm_signal, previous_handler)
                if cleanup_entry_error is not None:
                    raise cleanup_entry_error
                if timer_inspection_error is not None:
                    raise timer_inspection_error
                if cancellation_error is not None:
                    raise cancellation_error
                if competing_restore_error is not None:
                    raise competing_restore_error
                if cleanup_mask_error is not None:
                    raise cleanup_mask_error
        finally:
            if not mask_restored:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


@contextmanager
def _scoped_sigterm_interrupt():
    """Turn SIGTERM into a bounded run receipt while this command is active."""

    previous = signal.getsignal(signal.SIGTERM)

    def interrupt(signum, _frame):
        raise _RunInterrupted(signum)

    try:
        signal.signal(signal.SIGTERM, interrupt)
    except ValueError:
        # Signal handlers can only be installed by the interpreter's main thread.
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


_TERMINAL_SIGNALS = tuple(
    signum
    for signum in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None))
    if signum is not None
)


def _interruption_signal(exc: KeyboardInterrupt) -> int:
    return exc.signum if isinstance(exc, _RunInterrupted) else signal.SIGINT


def _signal_exit_code(signum: int) -> int:
    return 143 if signum == getattr(signal, "SIGTERM", None) else 130


def _terminal_signals_deferrable() -> bool:
    return (
        hasattr(signal, "SIG_BLOCK")
        and hasattr(signal, "SIG_SETMASK")
        and callable(getattr(signal, "pthread_sigmask", None))
        and callable(getattr(signal, "sigpending", None))
        and callable(getattr(signal, "sigwait", None))
    )


def _release_terminal_signals(previous_mask) -> int | None:
    """Consume SIGINT/SIGTERM held during a terminal write, then unblock."""
    received = None
    try:
        pending = signal.sigpending()
    except (OSError, ValueError):
        pending = set()
    for signum in _TERMINAL_SIGNALS:
        if signum in pending and signum not in previous_mask:
            # Consume it while still blocked so neither its handler nor
            # SIGTERM's default action runs once the receipt is final. A
            # signal this process ignores is consumed but not reported.
            signal.sigwait({signum})
            if received is None and signal.getsignal(signum) != signal.SIG_IGN:
                received = signum
    try:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    except KeyboardInterrupt as exc:
        # A signal arriving after the pending check is dispatched as the mask
        # is restored; the receipt is already final.
        if received is None:
            received = _interruption_signal(exc)
    return received


_NO_PREVIOUS_HANDLER = object()


def _record_sigterm(deferred: list[int]):
    """Install a SIGTERM handler that only records; return the previous one.

    Returns _NO_PREVIOUS_HANDLER when nothing was installed: SIGTERM is
    ignored (an ignored signal is not reported) or this is not the main thread.
    """
    previous = signal.getsignal(signal.SIGTERM)
    if previous == signal.SIG_IGN:
        return _NO_PREVIOUS_HANDLER
    try:
        signal.signal(signal.SIGTERM, lambda signum, _frame: deferred.append(signum))
    except (ValueError, OSError):
        return _NO_PREVIOUS_HANDLER
    return previous


def _finish_run_receipt(store, run_id: int, reason: str, **kwargs):
    """Write a terminal run receipt that SIGINT/SIGTERM cannot abandon.

    On POSIX both signals are blocked for the write, so a second Ctrl-C or a
    SIGTERM cannot roll it back and leave a ``running`` receipt; only a hard
    kill can. Without masking, SIGTERM is recorded for the write and reported
    afterwards. If a signal still interrupts the write (SIGINT without
    masking, or a signal reaching another thread), the write has rolled back
    and is retried as ``interrupted``. Returns the receipt and the first terminating
    signal that arrived during the write, if any; the caller exits with that
    signal's code and never rewrites the recorded receipt.
    """
    received = None
    previous_mask = None
    if _terminal_signals_deferrable():
        try:
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, _TERMINAL_SIGNALS)
        except (OSError, ValueError):
            previous_mask = None
    # Without masking, the run's SIGTERM handler has already been restored by
    # the time a terminal write runs. Record SIGTERM for the write instead, as
    # masking would defer it: the handler never raises, so no signal can
    # escape between the write and the handler's removal, and the caller
    # still exits 143.
    deferred_terms: list[int] = []
    previous_term = _NO_PREVIOUS_HANDLER
    if previous_mask is None:
        previous_term = _record_sigterm(deferred_terms)
    try:
        while True:
            try:
                receipt = store.finish_ingestion_run(run_id, reason, **kwargs)
                break
            except KeyboardInterrupt as exc:
                if received is None:
                    received = _interruption_signal(exc)
                reason, kwargs = "interrupted", {}
    finally:
        if previous_term is not _NO_PREVIOUS_HANDLER:
            signal.signal(
                signal.SIGTERM,
                signal.SIG_DFL if previous_term is None else previous_term,
            )
            if deferred_terms and received is None:
                received = signal.SIGTERM
        if previous_mask is not None:
            deferred = _release_terminal_signals(previous_mask)
            if received is None:
                received = deferred
    return receipt, received


def _reconciliation_message() -> str:
    return (
        "megalodon: ingestion reconciliation required; stop all ingestion, "
        "then inspect database-reconciliation-status"
    )


def _canary(args: argparse.Namespace) -> int:
    from . import canary
    from .validation import ValidationError

    try:
        if args.canary_command == "plant":
            result = canary.plant(str(args.dir), str(args.manifest), count=args.count,
                                  replace=args.replace)
        elif args.canary_command == "check":
            result = canary.check(str(args.manifest))
        else:
            result = canary.rearm(str(args.manifest))
    except (ValidationError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result.get("tripped") else 0


def _yara(args: argparse.Namespace) -> int:
    if args.yara_command == "install":
        from .yara_runtime import main
        return main()
    from . import yara_rules

    try:
        result = yara_rules.check(args.dir)
    except (ValueError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    # Exit 1 when configured rules cannot be used; an unconfigured folder is not an error.
    return 0 if result["compile"] in ("completed", "not_configured") or result["runtime"] != "ready" else 1


def _feeds(args: argparse.Namespace) -> int:
    from . import threat_feeds
    from .validation import ValidationError

    path = args.config or Path.home() / ".config/megalodon/settings.toml"
    try:
        settings = load_settings(path).feeds
        if args.feeds_command == "status":
            result = threat_feeds.status(settings)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 1 if any(item["stale"] for item in result["sources"].values()) else 0
        result = threat_feeds.refresh(settings, only_if_older_minutes=args.if_older)
    except (ValidationError, threat_feeds.FeedError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if any(item["status"] == "failed" for item in result["sources"].values()) else 0


def _logwatch(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone

    from . import log_integrity
    from .validation import ValidationError

    manifest = args.manifest or Path(log_integrity.DEFAULT_MANIFEST).expanduser()
    try:
        if args.logwatch_command == "baseline":
            result = log_integrity.baseline(manifest, replace=args.replace)
        elif args.logwatch_command == "accept":
            result = log_integrity.accept(manifest)
        else:
            result = log_integrity.check(manifest)
    except (log_integrity.LogIntegrityError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    findings = result.get("findings", [])
    if args.logwatch_command == "check" and args.alert and findings:
        from .alerts import HostNotice, dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 1
        if dispatcher is not None:
            listed = "; ".join(f"{f['rule_id']} {f['log']}" for f in findings[:5])
            dispatcher.submit([HostNotice(
                findings[0]["rule_id"], findings[0]["severity"], datetime.now(timezone.utc),
                f"{len(findings)} log integrity findings: {listed}", (log_integrity.TECHNIQUE,),
                "A system log was deleted, cut short, replaced or rewritten since the baseline.")])
    return 1 if findings else 0


def _drill(args: argparse.Namespace) -> int:
    from . import drill
    from .validation import ValidationError

    alert_settings = None
    if args.alerts:
        try:
            alert_settings = load_settings(args.config or Path.home() / ".config/megalodon/settings.toml").alerts
        except (ValidationError, OSError) as exc:
            print(f"megalodon: {exc}", file=sys.stderr)
            return 2
    report = drill.run(alert_settings=alert_settings)
    for check in report["checks"]:
        missing = f" (missing: {', '.join(check['missing'])})" if check["missing"] and check["status"] == "failed" else ""
        print(f"{check['status'].upper():8} {check['name']:12} {check['detail']}{missing}", file=sys.stderr)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if report["failed"] else 0


def _persistence(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone

    from . import persistence_watch as watch
    from .validation import ValidationError

    manifest = args.manifest or Path(watch.DEFAULT_MANIFEST).expanduser()
    try:
        if args.persistence_command == "baseline":
            result = watch.baseline(manifest, replace=args.replace)
        elif args.persistence_command == "accept":
            result = watch.accept(manifest)
        else:
            result = watch.check(manifest)
    except (watch.PersistenceError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    findings = result.get("findings", [])
    if args.persistence_command == "check" and args.alert and findings:
        from .alerts import HostNotice, dispatcher_for
        try:
            settings = load_settings(args.config or Path.home() / ".config/megalodon/settings.toml")
            dispatcher = dispatcher_for(settings.alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 1
        if dispatcher is not None:
            top = findings[0]
            listed = "; ".join(f"{f['change']} {f['category']} {f['location']}" for f in findings[:5])
            dispatcher.submit([HostNotice(
                "PERSISTENCE_CHANGE", top["severity"], datetime.now(timezone.utc),
                f"{len(findings)} persistence changes since the baseline: {listed}",
                tuple(sorted({f['technique'] for f in findings}))[:8],
                "A place attackers use to survive reboots changed since the reviewed baseline.")])
    return 1 if findings else 0


def _listeners(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone

    from . import listener_watch as watch
    from .validation import ValidationError

    manifest = args.manifest or Path(watch.DEFAULT_MANIFEST).expanduser()
    try:
        if args.listeners_command == "baseline":
            result = watch.baseline(manifest, replace=args.replace)
        elif args.listeners_command == "accept":
            result = watch.accept(manifest)
        else:
            result = watch.check(manifest)
    except (watch.ListenerError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    findings = result.get("findings", [])
    if args.listeners_command == "check" and args.alert and findings:
        from .alerts import HostNotice, dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 1
        if dispatcher is not None:
            top = findings[0]
            listed = "; ".join(
                f"{f['rule_id']} {f['listener']} ({', '.join(p['path'] for p in f['programs'][:2]) or 'owner unknown'})"
                for f in findings[:5])
            dispatcher.submit([HostNotice(
                top["rule_id"], top["severity"], datetime.now(timezone.utc),
                f"{len(findings)} listener changes since the baseline: {listed}",
                tuple(sorted({t for f in findings for t in f['techniques']}))[:8],
                "A program started listening for connections, took over a port, or became reachable more widely.")])
    return 1 if findings else 0


def _ancestry(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone
    from threading import Event

    from . import process_ancestry as ancestry
    from .alerts import HostNotice, dispatcher_for
    from .validation import ValidationError

    allow_file = args.allow_file or Path.home() / ".config/megalodon/ancestry-allow.json"
    if args.ancestry_command == "allow":
        try:
            count = ancestry.allow(allow_file, args.service, args.program)
        except (ancestry.AncestryError, OSError) as exc:
            print(f"megalodon: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(dict(allow_file=str(allow_file), allowed=count), indent=2))
        return 0
    dispatcher = None
    if args.alert:
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 2

    def notify(found):
        if dispatcher is not None:
            dispatcher.submit([HostNotice(found["rule_id"], found["severity"], datetime.now(timezone.utc),
                                          found["message"], tuple(found["attack"]), found["summary"])])
    if args.ancestry_command == "check":
        try:
            report = ancestry.check(allow_path=allow_file)
        except (ancestry.AncestryError, OSError) as exc:
            print(f"megalodon: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(report, indent=2, sort_keys=True))
        for found in report["findings"][:10]:
            notify(found)
        return 1 if report["findings"] else 0

    def emit(found):
        print(json.dumps(found, sort_keys=True), flush=True)
        notify(found)
    try:
        watcher = ancestry.Watcher(emit, allow_path=allow_file, interval=args.interval)
    except (ancestry.AncestryError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(f"megalodon: watching programs that services start ({watcher.mode})"
          + (f"; alerts to {len(dispatcher.channels)} destinations" if dispatcher else ""), file=sys.stderr, flush=True)
    stop = Event()
    try:
        watcher.run(stop)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        watcher.close()
        print(f"megalodon: {json.dumps(watcher.stats, sort_keys=True)}", file=sys.stderr)
    return 0


def _devices(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone

    from . import device_watch as watch
    from .validation import ValidationError

    manifest = args.manifest or Path(watch.DEFAULT_MANIFEST).expanduser()
    dispatcher = None
    if getattr(args, "alert", False):
        from .alerts import dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 2

    def notify(found):
        if dispatcher is not None:
            from .alerts import HostNotice
            dispatcher.submit([HostNotice(found["rule_id"], found["severity"], datetime.now(timezone.utc),
                                          found["detail"], tuple(found["techniques"]), found["summary"])])
    try:
        if args.devices_command == "baseline":
            result = watch.baseline(manifest, replace=args.replace)
        elif args.devices_command == "accept":
            result = watch.accept(manifest)
        elif args.devices_command == "watch":
            def emit(found):
                print(json.dumps(found, sort_keys=True), flush=True)
                notify(found)
            try:
                watch.watch(manifest, emit, interval=args.interval)
            except KeyboardInterrupt:
                pass
            return 0
        else:
            result = watch.check(manifest)
    except (watch.DeviceError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    findings = result.get("findings", [])
    for found in findings[:10]:
        notify(found)
    return 1 if findings else 0


def _rootkit(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone

    from . import rootkit_check
    from .validation import ValidationError

    try:
        report = rootkit_check.check(ports=not args.skip_ports, max_pid=args.max_pid)
    except (rootkit_check.RootkitError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    findings = report["findings"]
    if args.alert and findings:
        from .alerts import HostNotice, dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 1
        if dispatcher is not None:
            listed = "; ".join(f["detail"] for f in findings[:5])
            dispatcher.submit([HostNotice(
                findings[0]["rule_id"], findings[0]["severity"], datetime.now(timezone.utc),
                f"{len(findings)} rootkit cross-check findings: {listed}",
                tuple(sorted({t for f in findings for t in f["techniques"]})),
                "One view of the system hides something another view still sees, as rootkits do.")])
    return 1 if findings else 0


def _binaries(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone

    from . import binary_integrity as integrity
    from .validation import ValidationError

    options = dict(all_libraries=args.all_libraries)
    try:
        if args.binaries_command == "verify":
            result = integrity.verify(**options)
        else:
            manifest = args.manifest or Path(integrity.DEFAULT_MANIFEST).expanduser()
            if args.binaries_command == "baseline":
                result = integrity.baseline(manifest, replace=args.replace, **options)
            elif args.binaries_command == "accept":
                result = integrity.accept(manifest, **options)
            else:
                result = integrity.check(manifest, **options)
    except (integrity.BinaryIntegrityError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    findings = result.get("findings", [])
    if args.binaries_command in ("verify", "check") and args.alert and findings:
        from .alerts import HostNotice, dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 1
        if dispatcher is not None:
            top = findings[0]
            listed = "; ".join(f"{f['rule_id']} {f['path']}" for f in findings[:5])
            dispatcher.submit([HostNotice(
                top["rule_id"], top["severity"], datetime.now(timezone.utc),
                f"{len(findings)} program integrity findings: {listed}",
                tuple(sorted({t for f in findings for t in f['techniques']}))[:8],
                "A system program or library no longer matches its package or the reviewed baseline.")])
    return 1 if findings else 0


def _respond(args: argparse.Namespace) -> int:
    from . import response_engine as engine

    def paths():
        return dict(policy_path=args.policy or Path(engine.DEFAULT_POLICY).expanduser(),
                    ledger=args.ledger or Path(engine.DEFAULT_LEDGER).expanduser(),
                    state_path=args.state or Path(engine.DEFAULT_STATE).expanduser())
    try:
        if args.respond_command == "init":
            result = engine.write_default_policy(args.policy or Path(engine.DEFAULT_POLICY).expanduser(),
                                                 replace=args.replace)
        elif args.respond_command == "report":
            result = engine.report(ledger=args.ledger or Path(engine.DEFAULT_LEDGER).expanduser(), hours=args.hours)
        elif args.respond_command == "ingest":
            # One decision pass per line, so a live pipe (the ransomware watch) is decided as it arrives.
            for line in sys.stdin:
                if line.strip():
                    print(json.dumps(engine.ingest([line], **paths()), sort_keys=True), flush=True)
            return 0
        elif args.respond_command == "run":
            result = engine.run(**paths())
        else:
            import time
            try:
                while True:
                    result = engine.run(**paths())
                    print(f"{result['decisions']} decisions, {result['would_apply']} actions would apply, "
                          f"{result['refused']} refused, {len(result['gaps'])} gaps (shadow mode: none carried out)",
                          file=sys.stderr, flush=True)
                    time.sleep(args.interval)
            except KeyboardInterrupt:
                return 0
    except (engine.ResponseError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _evidence(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone

    from . import evidence
    from .validation import ValidationError

    try:
        if args.evidence_command == "verify":
            result = evidence.verify(args.bundle, expected=args.expected)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["intact"] else 1
        result = evidence.collect(output=args.output, hours=args.hours, command_lines=args.with_command_lines,
                                  verify_programs=not args.skip_program_verification,
                                  copy_suspicious=not args.no_program_copies)
    except (evidence.EvidenceError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.alert:
        from .alerts import HostNotice, dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 1
        if dispatcher is None:
            print("megalodon: alerts are off in the settings; the digest was not sent", file=sys.stderr)
            return 1
        # An off-machine copy of the digest is what lets a later verify prove the bundle unchanged. It was
        # asked for by name, so it goes out whatever the alert minimum severity is.
        dispatcher.submit([HostNotice(
            "EVIDENCE_COLLECTED", "LOW", datetime.now(timezone.utc),
            f"Evidence bundle {result['bundle']} collected; manifest SHA-256 {result['manifest_sha256']}",
            # The digest field is rendered by every transport at every detail level; the message is not.
            (), "A read-only evidence snapshot was taken. Keep this digest to verify the bundle later.",
            digest=result["manifest_sha256"])], any_severity=True)
    return 0


def _ransomware(args: argparse.Namespace) -> int:
    from threading import Event
    import tempfile

    from . import ransomware_watch as watch
    from .alerts import HostNotice, dispatcher_for
    from .validation import ValidationError

    if args.ransomware_command == "selftest":
        with tempfile.TemporaryDirectory(prefix="megalodon-ransomware-selftest-") as base:
            try:
                found = watch.selftest(os.path.join(base, "files"))
            except watch.WatchError as exc:
                print(f"megalodon: {exc}", file=sys.stderr)
                return 2
        rules = sorted({item.rule_id for item in found})
        ok = {"RANSOMWARE_ENCRYPTION", "RANSOM_NOTE"} <= set(rules)
        print(json.dumps(dict(schema="megalodon-ransomware-selftest-v1", detected=rules, ok=ok), indent=2))
        return 0 if ok else 1
    path = args.config or Path.home() / ".config/megalodon/settings.toml"
    dispatcher = None
    try:
        if args.config or path.exists():
            dispatcher = dispatcher_for(load_settings(path).alerts)
        detector = watch.RansomwareDetector(min_files=args.min_files, window_seconds=args.window)
        roots = [str(item) for item in args.dir]
        seeded = 0
        for root in roots:
            seeded += detector.seed([root])
        watcher = watch.Watcher(roots, detector, lambda finding: None)
    except (ValidationError, watch.WatchError, OSError, ValueError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2

    def emit(finding):
        print(json.dumps(finding.to_dict(), sort_keys=True), flush=True)
        if dispatcher is not None:
            dispatcher.submit([HostNotice(finding.rule_id, finding.severity, finding.detected_at,
                                          finding.message, watch.ATTACK,
                                          "Files are being rewritten as encrypted data, as ransomware does.")])
    watcher.emit = emit
    print(f"megalodon: watching {watcher.watched} folders ({seeded} files recorded)"
          + ("; folder limit reached, some subfolders are not watched" if watcher.truncated else "")
          + (f"; alerts to {len(dispatcher.channels)} destinations" if dispatcher else "; no alerts configured"),
          file=sys.stderr, flush=True)
    stop = Event()
    try:
        watcher.run(stop)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        watcher.close()
    return 0


def _alerts(args: argparse.Namespace) -> int:
    from .alerts import test_destinations
    from .validation import ValidationError

    path = args.config or Path.home() / ".config/megalodon/settings.toml"
    try:
        settings = load_settings(path)
    except (ValidationError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    if not settings.alerts.destinations:
        print("megalodon: no [[alerts.destination]] is configured in " + str(path), file=sys.stderr)
        return 2
    results = test_destinations(settings.alerts)
    print(json.dumps(dict(enabled=settings.alerts.enabled, destinations=results), indent=2, sort_keys=True))
    return 0 if all(item["ok"] for item in results.values()) else 1


def _auth_review(args: argparse.Namespace) -> int:
    from datetime import timezone

    from .auth_review import read_lines, review
    from .validation import ValidationError
    from .watchlist import parse_indicator, render, write_private

    try:
        report, reviewer = review(read_lines(args.input), source=args.input,
                                  zone=timezone.utc if args.utc else None)
        if args.emit_watchlist is not None:
            entries = [(parse_indicator(address), label)
                       for address, label in reviewer.attacker_sources()]
            write_private(args.emit_watchlist,
                          render(entries, "attacking addresses from megalodon auth-review"),
                          replace=args.replace)
            report["watchlist_written"] = {"path": str(args.emit_watchlist),
                                           "indicators": len(entries)}
    except (ValidationError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if report["severity_counts"]["CRITICAL"] or report["severity_counts"]["HIGH"] else 0


def _detectors() -> int:
    from .detector_registry import registry_document as core_registry
    from .threat_detector import registry_document as threat_registry

    print(json.dumps(
        {"core": core_registry(), "threat_signals": threat_registry()},
        indent=2, sort_keys=True,
    ))
    return 0


def _watchlist(args: argparse.Namespace) -> int:
    from .offline.common import OfflineError
    from .threat_context import ThreatContextError, read_completed_bundle
    from .validation import ValidationError
    from .watchlist import Watchlist, load_watchlist, render, stix_indicators, write_private

    try:
        if args.watchlist_command == "check":
            result = load_watchlist(args.path).summary()
        elif args.watchlist_command == "match":
            from .validation import parse_ip

            address = parse_ip(args.address)
            hit = load_watchlist(args.path).match(address)
            result = {
                "schema": "megalodon-watchlist-match-v1",
                "address": address,
                "matched": hit is not None,
                "indicator": hit[0] if hit else None,
                "label": hit[1] if hit else None,
            }
        else:
            objects, receipt = read_completed_bundle(args.bundle, args.digest)
            entries, counts = stix_indicators(objects)
            Watchlist(entries)  # enforce indicator bounds before writing anything
            write_private(
                args.output,
                render(entries, f"imported from STIX bundle {receipt['bundle_id']}"),
                replace=args.replace,
            )
            result = {
                "schema": "megalodon-watchlist-import-v1",
                "bundle_id": receipt["bundle_id"],
                "artifact_digest": receipt["artifact_digest"],
                "indicators_written": len({str(network) for network, _ in entries}),
                **counts,
                "pattern_handling": "ip_equality_only_never_execute",
                "network_access_performed": False,
            }
    except ThreatContextError as exc:
        print(f"megalodon: STIX bundle refused: {exc}", file=sys.stderr)
        return 2
    except (ValidationError, OfflineError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _run(args: argparse.Namespace) -> int:
    try:
        # Refuse an explicit unbounded source before configuration, store, or
        # source acquisition. A configuration-selected source is checked again
        # immediately after the one necessary configuration read.
        _require_finite_run_limit(args.source, args.max_events)
        _require_run_deadline_source(args.source, args.max_seconds)
        _require_run_deadline_support(args.max_seconds)
        if args.source is not None:
            _require_source_options(args.source, args)
        settings = _load(args.config)
        source = _source_for(args, settings)
        _require_finite_run_limit(source, args.max_events)
        _require_run_deadline_source(source, args.max_seconds)
        # A source-specific option the resolved source would ignore (for
        # example --input with the sample source) refuses before the store
        # opens, so no synthetic rows reach the audit database by mistake.
        _require_source_options(source, args)
        try:
            store = Store(
                settings.db_path,
                max_database_bytes=_storage_limit(settings),
            )
        except KeyboardInterrupt:
            # Opening can wait out another writer's lock; no run exists yet.
            print("megalodon: interrupted before ingestion started", file=sys.stderr)
            return 130
        with store:
            service = MegalodonService(settings, store)
            run_id = store.start_ingestion_run(source)
            processed = 0
            termination_reason = "source_exhausted"
            try:
                with (
                    _scoped_sigterm_interrupt(),
                    _scoped_run_deadline(args.max_seconds),
                    _owned_source(_events_for(args, settings)) as events,
                ):
                    for event in events:
                        service.process(event, run_id=run_id)
                        processed += 1
                        if (
                            args.max_events is not None
                            and processed >= args.max_events
                        ):
                            termination_reason = "event_limit_reached"
                            break
            except KeyboardInterrupt as exc:
                try:
                    receipt, _ = _finish_run_receipt(store, run_id, "interrupted")
                except IngestionRunError as finish_error:
                    if str(finish_error) == RECONCILIATION_REQUIRED:
                        print(_reconciliation_message(), file=sys.stderr)
                        return 2
                    raise
                if receipt["status"] == "reconciliation_required":
                    print(_reconciliation_message(), file=sys.stderr)
                    return 2
                print("megalodon: ingestion interrupted", file=sys.stderr)
                return 143 if isinstance(exc, _RunInterrupted) else 130
            except (CaptureError, OSError, ValueError, sqlite3.Error) as exc:
                if isinstance(exc, IngestionRunError) and str(exc) == RECONCILIATION_REQUIRED:
                    print(_reconciliation_message(), file=sys.stderr)
                    return 2
                failure_code = _run_failure_code(exc)
                try:
                    receipt, received = _finish_run_receipt(
                        store, run_id, "failed", failure_code=failure_code
                    )
                except IngestionRunError as finish_error:
                    if str(finish_error) == RECONCILIATION_REQUIRED:
                        print(_reconciliation_message(), file=sys.stderr)
                        return 2
                    raise
                if receipt["status"] == "reconciliation_required":
                    print(_reconciliation_message(), file=sys.stderr)
                    return 2
                if receipt["termination_reason"] == "interrupted":
                    print("megalodon: ingestion interrupted", file=sys.stderr)
                else:
                    print(
                        f"megalodon: ingestion failed ({failure_code})",
                        file=sys.stderr,
                    )
                return 2 if received is None else _signal_exit_code(received)
            # A signal during this write keeps the receipt being written (the
            # source really ended), prints no success JSON, and exits 130/143.
            receipt, received = _finish_run_receipt(store, run_id, termination_reason)
            if receipt["status"] == "reconciliation_required":
                print(_reconciliation_message(), file=sys.stderr)
                return 2
            if received is None:
                try:
                    totals = store.summary()
                except KeyboardInterrupt:
                    received = signal.SIGINT
            if received is not None:
                print(
                    "megalodon: ingestion interrupted after its receipt was recorded",
                    file=sys.stderr,
                )
                return _signal_exit_code(received)
            print(json.dumps({**receipt, "totals": totals}, sort_keys=True))
    except sqlite3.Error:
        print("megalodon: storage operation failed", file=sys.stderr)
        return 2
    except OSError:
        print("megalodon: I/O operation failed", file=sys.stderr)
        return 2
    except IngestionRunError as exc:
        if str(exc) == RECONCILIATION_REQUIRED:
            print(_reconciliation_message(), file=sys.stderr)
        else:
            print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    except (CaptureError, ValueError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    return 0


def _dashboard(args: argparse.Namespace) -> int:
    from .dashboard import loopback_host, serve, UnconfiguredDashboardReader, validate_tool_management_mode
    from .local_install import InstallError, install_paths, load_hud_password_verifier
    from .offline_projection import load_offline_projection
    from .offline_locations import OfflineLocations
    from .config import AISettings, BlockingSettings
    from .companion_automation import load_config as load_companion_config, local_default_config

    try:
        settings = _load(args.config)
        host = args.host if args.host is not None else settings.dashboard.host
        port = args.port if args.port is not None else settings.dashboard.port
        host = loopback_host(host, allow_remote=args.allow_remote)
        enabled = getattr(settings.dashboard, "enabled", True)
        if not enabled:
            raise ValueError("dashboard is disabled by configuration")
        first_launch = getattr(args, "command", "dashboard") == "hud"
        if first_launch:
            from .process_privileges import drop_inherited_capabilities
            drop_inherited_capabilities()
        enable_tool_management = (getattr(args, "enable_tool_management", False)
                                  or (first_launch and settings.dashboard.tool_management))
        validate_tool_management_mode(enable_tool_management, inspect_tools=first_launch)
        http_password_verifier = None
        if getattr(args, "require_sign_in", False) and args.config is not None and Path(args.config) == install_paths().settings:
            try:
                http_password_verifier = load_hud_password_verifier()
            except InstallError as exc:
                raise ValueError(str(exc)) from exc
        offline_summary = load_offline_projection(args.offline_run) if args.offline_run else None
        companion_path = getattr(args, "companion_config", None)
        if companion_path and getattr(args, "no_auto_companions", False):
            raise ValueError("--companion-config and --no-auto-companions cannot be combined")
        companion_config = (load_companion_config(companion_path) if companion_path else
                            None if getattr(args, "no_auto_companions", False) or not first_launch else
                            local_default_config())
        with _dashboard_reader(settings.db_path, allow_missing=first_launch) as store:
            locations = OfflineLocations.open(args.geoip_db) if getattr(args, "geoip_db", None) else None
            try:
                serve(
                    store,
                    host,
                    port,
                    enabled=enabled,
                    allow_remote=args.allow_remote,
                    offline_summary=offline_summary,
                    suricata_db=getattr(args, "suricata_db", None),
                    inspect_tools=first_launch,
                    enable_tool_management=enable_tool_management,
                    source_available=not isinstance(store, UnconfiguredDashboardReader),
                    refresh_seconds=(
                        args.refresh_seconds if args.refresh_seconds is not None else settings.dashboard.refresh_seconds
                    ),
                    event_limit=args.event_limit if args.event_limit is not None else settings.dashboard.event_limit,
                    open_browser=getattr(args, "open_browser", False),
                    ai_settings=getattr(settings, "ai", AISettings()),
                    ai_receipt_path=_ai_receipt_path(settings.db_path),
                    ai_blocking=getattr(settings, "blocking", BlockingSettings()),
                    offline_locations=locations,
                    http_password_verifier=http_password_verifier,
                    require_sign_in=getattr(args, "require_sign_in", False),
                    companion_config=companion_config,
                    runtime_settings=settings if first_launch else None,
                )
            finally:
                if locations is not None:
                    locations.close()
    except KeyboardInterrupt:
        print("\nMEGALODON dashboard stopped.")
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            print(
                "megalodon: dashboard address is already in use by another program or "
                "HUD; this launch did not apply the requested settings or start companion "
                "collection. Existing sessions keep their settings. Choose an unused port "
                "once with --port 8798 (or another free port), or for every launch with "
                "port under [dashboard] in settings.toml. Stop a foreground HUD with "
                "Ctrl+C in its terminal.",
                file=sys.stderr,
            )
        else:
            print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    return 0


@contextmanager
def _dashboard_reader(path: Path, *, allow_missing: bool = False):
    """First launch may lack a store; an unsafe or invalid store still refuses."""
    from .dashboard import UnconfiguredDashboardReader

    try:
        store = DashboardStore(path)
    except StorageSchemaError as exc:
        if not allow_missing or str(exc) not in {
            "DASHBOARD_STORE:NO_DIRECTORY", "DASHBOARD_STORE:NO_DATABASE",
        }:
            raise
        yield UnconfiguredDashboardReader(path)
        return
    with store:
        yield store


def _ai(args: argparse.Namespace) -> int:
    from uuid import uuid4
    from .ai_broker import Broker, BrokerError, ReceiptStore
    from .ai_interface import ask
    from .ai_provider import AIProviderError, inventory, status, _require_enabled
    from .provider_containment import qwen_provider_posture
    import shutil
    import subprocess

    try:
        settings = _load(args.config)
        receipt_path = _ai_receipt_path(settings.db_path)
        if args.operation == "doctor":
            posture = qwen_provider_posture()
            bound_uids = [binding["uid"] for binding in posture["bindings"]]
            model_status = status(settings.ai, probe=True)
            model_inventory = inventory(settings.ai)
            try:
                gpu = subprocess.run(["/usr/bin/nvidia-smi", "--query-gpu=name,driver_version,compute_cap",
                                      "--format=csv,noheader"], capture_output=True, text=True,
                                     timeout=3, check=False)
                driver_usable = gpu.returncode == 0 and bool(gpu.stdout.strip())
            except (OSError, subprocess.TimeoutExpired):
                driver_usable = False
            try:
                unit = subprocess.run(["/usr/bin/systemctl", "show", "ollama",
                                       "-p", "IPAddressDeny", "-p", "IPAddressAllow",
                                       "--no-pager"], capture_output=True, text=True,
                                      timeout=3, check=False)
                unit_fields = dict(line.split("=", 1) for line in unit.stdout.splitlines() if "=" in line) if unit.returncode == 0 else {}
                deny = unit_fields.get("IPAddressDeny", "")
                allow = unit_fields.get("IPAddressAllow", "")
                egress_restricted = ("any" in deny or ("0.0.0.0/0" in deny and "::/0" in deny)) and "127.0.0.0/8" in allow
            except (OSError, subprocess.TimeoutExpired):
                egress_restricted = False
            checks = {
                "ollama_installed": shutil.which("ollama") is not None,
                "ollama_loopback_only": posture["loopback_only"] is True,
                "ollama_egress_restricted": egress_restricted,
                "ollama_service_non_root": bool(bound_uids) and all(uid != 0 for uid in bound_uids),
                "nvidia_gpu_detected": Path("/proc/driver/nvidia/version").exists() and Path("/dev/nvidia0").exists(),
                "nvidia_driver_usable": driver_usable,
                "qwen_model_installed": model_inventory["model_present"] is True and model_inventory["digest_matches"] is True,
                "qwen_inference_healthy": model_status["state"] == "model_ready",
                "adapter_connected": model_status["state"] == "model_ready",
                "tool_broker_available": True,
                "audit_database_writable": False,
                "firewall_authority_disabled": True,
            }
            try:
                with ReceiptStore(receipt_path) as receipts:
                    receipts.append(str(uuid4()), {"state": "observed", "tool": "megalodon.ai.doctor",
                                                  "authority_level": 0, "authorization_source": "operator_cli",
                                                  "model": settings.ai.model, "model_request": "none",
                                                  "validated_arguments": {}, "result": {"checked": True},
                                                  "error_code": None, "duration_ms": 0,
                                                  "evidence_references": []})
                checks["audit_database_writable"] = True
            except (OSError, ValueError, sqlite3.Error):
                pass
            print(json.dumps({"schema": "megalodon-ai-doctor-v1", "checks": checks,
                              "model_status": model_status, "model_inventory": model_inventory,
                              "operator_action": "Review the operator setup gates in docs/ai-control-plane.md; no host change was applied" if (posture["loopback_only"] is not True or not egress_restricted) else None},
                             sort_keys=True))
            return 0 if all(checks.values()) else 1
        if args.operation != "tool":
            _require_enabled(settings.ai)
        with ReceiptStore(receipt_path) as receipts, _dashboard_reader(settings.db_path, allow_missing=True) as reader:
            broker = Broker(reader, receipts, settings.ai, settings.blocking)
            if args.operation == "tool":
                if args.request is None or len(args.request.encode()) > 2048:
                    raise BrokerError("INVALID_REQUEST")
                try:
                    from .ai_provider import _strict_pairs
                    request = json.loads(args.request, object_pairs_hook=_strict_pairs)
                except (ValueError, RecursionError):
                    # Deep nesting within the byte bound is malformed input,
                    # not a crash: it takes the normal INVALID_REQUEST receipt.
                    request = None
                result = broker.dispatch(request, authorization_source="operator_cli")
            else:
                if args.question is None:
                    raise BrokerError("UNKNOWN_QUESTION")
                result = ask(args.question, broker)
            print(json.dumps(result, sort_keys=True, allow_nan=False))
            return 0 if _ai_result_succeeded(result) else 1
    except (AIProviderError, BrokerError, OSError, ValueError, sqlite3.Error) as exc:
        print(f"megalodon ai: {getattr(exc, 'code', 'UNAVAILABLE')}", file=sys.stderr)
        return 2


def _database_migrate(args: argparse.Namespace) -> int:
    try:
        settings = _load(args.config)
        print(json.dumps(migrate_database(settings.db_path), sort_keys=True))
    except (OSError, ValueError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    return 0


def _database_backup(args: argparse.Namespace) -> int:
    from .sqlite_recovery_workflow import backup_database

    try:
        settings = _load(args.config)
    except (OSError, ValueError):
        source: object = object()
    else:
        source = settings.db_path
    receipt = backup_database(
        source,
        args.destination,
        args.manifest,
        operation_id=args.operation_id,
    )
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["status"] == "completed" else 2


def _database_restore(args: argparse.Namespace) -> int:
    from .sqlite_recovery_workflow import restore_database

    receipt = restore_database(
        args.source,
        args.manifest,
        args.destination,
        artifact_sha256=args.artifact_sha256,
        operation_id=args.operation_id,
    )
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["status"] == "completed" else 2


def _database_reconciliation_status(args: argparse.Namespace) -> int:
    try:
        settings = _load(args.config)
        with Store(
            settings.db_path,
            create=False,
            max_database_bytes=_storage_limit(settings),
        ) as store:
            pending = store.pending_ingestion_reconciliation()
        print(json.dumps({"pending": pending}, sort_keys=True))
    except (OSError, sqlite3.Error) as exc:
        print(_storage_failure_message(exc), file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    return 0


def _database_reconcile(args: argparse.Namespace) -> int:
    try:
        settings = _load(args.config)
        started_at = parse_timestamp(args.started_at)
        with Store(
            settings.db_path,
            create=False,
            max_database_bytes=_storage_limit(settings),
        ) as store:
            receipt = store.mark_ingestion_run_reconciliation_required(
                args.run_id, expected_started_at=started_at
            )
        print(json.dumps(receipt, sort_keys=True))
    except (OSError, sqlite3.Error) as exc:
        print(_storage_failure_message(exc), file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    return 0


def _record_firewall_action(settings, mode: str, operation) -> None:
    action = "firewall_install" if mode == "install" else "block"
    details = operation.to_dict()
    try:
        safe_text(details["message"], "operation message", 256)
    except ValidationError:
        details["message"] = "multiline or oversized operation plan omitted from audit details"
    with Store(
        settings.db_path,
        max_database_bytes=_storage_limit(settings),
    ) as store:
        store.record_action(
            ActionRecord(
                created_at=datetime.now(timezone.utc),
                action=action,
                target=operation.target,
                status=operation.status,
                reason=operation.reason,
                expires_at=operation.expires_at,
                details=details,
            )
        )


def _firewall(args: argparse.Namespace, mode: str) -> int:
    if getattr(args, "apply", False):
        print(f"megalodon: {LIVE_APPLY_UNSUPPORTED}", file=sys.stderr)
        return 2
    try:
        settings = _load(args.config)
        firewall = NftablesFirewall(
            allowlist=settings.blocking.allowlist,
            public_only=settings.blocking.public_only,
            timeout_seconds=settings.blocking.timeout_seconds,
            dry_run=True,
        )
        if mode == "plan":
            operation = firewall.plan_block(args.ip, args.reason)
        elif mode == "install":
            operation = firewall.install(apply=args.apply, confirm=args.confirm)
        else:
            operation = firewall.block(args.ip, args.reason, apply=args.apply, confirm=args.confirm)
        _record_firewall_action(settings, mode, operation)
        print(json.dumps(operation.to_dict(), indent=2, sort_keys=True))
    except (FirewallError, ValueError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    except (OSError, sqlite3.Error) as exc:
        # The plan is printed only after its audit row commits; a refused or
        # failed audit write prints no plan.
        print(_storage_failure_message(exc), file=sys.stderr)
        return 2
    return 0


def _live_apply_requested(argv: list[str]) -> bool:
    """Detect the retained apply flag before argparse validates route arguments."""
    if not argv:
        return False
    command_index = 1 if argv[0] == "--" else 0
    if (
        command_index >= len(argv)
        or argv[command_index] not in {"block", "firewall-install"}
    ):
        return False
    for argument in argv[command_index + 1 :]:
        if argument == "--":
            break
        if argument.startswith("--a") and "--apply".startswith(argument):
            return True
    return False


def main(argv: list[str] | None = None) -> None:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if "--stage0-offline" in raw_argv:
        try:
            execution_boundary.select_stage0()
        except execution_boundary.Stage0Denied:
            print(execution_boundary.DENIAL, file=sys.stderr)
            raise SystemExit(2) from None
        # No abbreviations, repeated selectors, late selectors or extra inputs.
        if raw_argv != ["--stage0-offline", "stage0-status"]:
            print(execution_boundary.DENIAL, file=sys.stderr)
            raise SystemExit(2)
        raw_argv = ["stage0-status"]
    if execution_boundary.effects_denied():
        if raw_argv == ["stage0-status"]:
            print(json.dumps(execution_boundary.status(), sort_keys=True))
            raise SystemExit(0)
        print(execution_boundary.DENIAL, file=sys.stderr)
        raise SystemExit(2)
    if raw_argv != ["stage0-status"]:
        try:
            execution_boundary.require_effects_allowed()
        except execution_boundary.Stage0Denied:
            print(execution_boundary.DENIAL, file=sys.stderr)
            raise SystemExit(2) from None
    if _live_apply_requested(raw_argv):
        print(f"megalodon: {LIVE_APPLY_UNSUPPORTED}", file=sys.stderr)
        raise SystemExit(2)
    args = build_parser().parse_args(raw_argv)
    if args.stage0_offline:
        # argparse may recognize an abbreviated selector. It cannot dispatch.
        try:
            execution_boundary.select_stage0()
        except execution_boundary.Stage0Denied:
            pass  # The fixed refusal below also covers a poisoned/late mode.
        print(execution_boundary.DENIAL, file=sys.stderr)
        raise SystemExit(2)
    if args.command == "stage0-status":
        print(json.dumps(execution_boundary.status(), sort_keys=True))
        code = 0
    elif args.command == "capabilities":
        code = _capabilities(args)
    elif args.command == "ai":
        code = _ai(args)
    elif args.command == "readiness":
        code = _readiness(args)
    elif args.command == "posture":
        code = _posture(args)
    elif args.command == "hub-plan":
        code = _hub_plan(args)
    elif args.command == "automation-preview":
        code = _automation_preview(args)
    elif args.command == "run":
        code = _run(args)
    elif args.command == "canary":
        code = _canary(args)
    elif args.command == "auth-review":
        code = _auth_review(args)
    elif args.command == "yara":
        code = _yara(args)
    elif args.command == "alerts":
        code = _alerts(args)
    elif args.command == "ransomware":
        code = _ransomware(args)
    elif args.command == "persistence":
        code = _persistence(args)
    elif args.command == "listeners":
        code = _listeners(args)
    elif args.command == "respond":
        code = _respond(args)
    elif args.command == "evidence":
        code = _evidence(args)
    elif args.command == "binaries":
        code = _binaries(args)
    elif args.command == "ancestry":
        code = _ancestry(args)
    elif args.command == "rootkit":
        code = _rootkit(args)
    elif args.command == "devices":
        code = _devices(args)
    elif args.command == "drill":
        code = _drill(args)
    elif args.command == "logwatch":
        code = _logwatch(args)
    elif args.command == "feeds":
        code = _feeds(args)
    elif args.command == "detectors":
        code = _detectors()
    elif args.command == "watchlist":
        code = _watchlist(args)
    elif args.command in {"dashboard", "hud"}:
        code = _dashboard(args)
    elif args.command == "database-migrate":
        code = _database_migrate(args)
    elif args.command == "database-backup":
        code = _database_backup(args)
    elif args.command == "database-restore":
        code = _database_restore(args)
    elif args.command == "database-reconciliation-status":
        code = _database_reconciliation_status(args)
    elif args.command == "database-reconcile":
        code = _database_reconcile(args)
    elif args.command == "firewall-plan":
        args.reason = args.reason
        code = _firewall(args, "plan")
    elif args.command == "firewall-install":
        args.reason = "install isolated table"
        code = _firewall(args, "install")
    elif args.command == "block":
        code = _firewall(args, "block")
    else:
        code = 2
    raise SystemExit(code)
