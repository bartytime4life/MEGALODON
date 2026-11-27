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
    canary_plant.add_argument("--lure", action="store_true",
                              help="also plant an agent lure: a note to AI agents naming an account that does not "
                                   "exist; a login tried as it is LURE_FOLLOWED. Not in folders your own AI tools use")
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
            command.add_argument("--advance", action="store_true",
                                 help="afterwards record every log without a finding as it is now, so the next "
                                      "check covers what was written since and rotation needs no accept")

    persist = sub.add_parser(
        "persistence", help="baseline and check where attackers hide to survive reboots (exit 1 on changes)")
    persist_sub = persist.add_subparsers(dest="persistence_command", required=True)
    for name, text in (("baseline", "record the current state of every persistence location (exit 1 if an entry "
                                    "has signs of an intruder's)"),
                       ("check", "report what was added, changed or removed since the baseline"),
                       ("accept", "after review, record the current state as the new baseline"),
                       ("scan", "report entries with signs of an intruder's now, recording nothing (exit 1 if any)")):
        command = persist_sub.add_parser(name, help=text)
        if name == "scan":
            continue
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
                       ("watch", "check every few seconds and report each change once, and, as root, listeners that "
                                 "opened and closed in between, as JSON lines"),
                       ("accept", "after review, record the current listeners as the new baseline")):
        command = listeners_sub.add_parser(name, help=text)
        command.add_argument("--manifest", type=Path, help="baseline file (default ~/.config/megalodon/listeners.json)")
        if name == "baseline":
            command.add_argument("--replace", action="store_true", help="overwrite an existing baseline")
        if name == "watch":
            command.add_argument("--interval", type=float, default=10.0, help="seconds between checks (default 10)")
        if name in ("check", "watch"):
            command.add_argument("--alert", action="store_true",
                                 help="also send findings to the [alerts] destinations in the settings file")
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
            command.add_argument("--respond", action="store_true", help=RESPOND_HELP)
            command.add_argument("--trace-execs", action="store_true",
                                 help="as root, load a small eBPF program and judge each program from the kernel's "
                                      "own record of its start, so one gone before the watch reads it is still "
                                      "judged; it is removed when the watch stops")
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
            command.add_argument("--interval", type=float, default=2.0,
                                 help="seconds between checks when no device event arrives (default 2)")
            command.add_argument("--poll", action="store_true",
                                 help="check every interval only, without listening for the kernel's device events")
            command.add_argument("--respond", action="store_true",
                                 help="decide each new device at once with the response engine, and carry out what "
                                      "the enforcement policy allows (such as block_device)")
        if name in ("check", "watch"):
            command.add_argument("--alert", action="store_true",
                                 help="also send findings to the [alerts] destinations in the settings file")
            command.add_argument("--config", type=Path,
                                 help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    webroot = sub.add_parser(
        "webroot", help="baseline and check web roots for dropped scripts, hidden code and web shells")
    webroot_sub = webroot.add_subparsers(dest="webroot_command", required=True)
    for name, text in (("baseline", "record the server-side scripts under the web roots, reporting any web shell "
                                    "already there"),
                       ("check", "report new and changed scripts, hidden code and web-shell shapes (exit 1 on "
                                 "findings)"),
                       ("watch", "look at each file as it is written, and report scripts dropped and soon deleted, "
                                 "as JSON lines (Linux)"),
                       ("accept", "after review, record the current scripts as the new baseline")):
        command = webroot_sub.add_parser(name, help=text)
        command.add_argument("--manifest", type=Path, help="baseline file (default ~/.config/megalodon/webroot.json)")
        command.add_argument("--root", action="append", dest="roots",
                             help="a web document root (repeatable; default /var/www, /srv/www, /srv/http, ... "
                                  "or the baseline's roots)")
        if name == "baseline":
            command.add_argument("--replace", action="store_true", help="overwrite an existing baseline")
        if name in ("check", "watch"):
            command.add_argument("--alert", action="store_true",
                                 help="also send a summary to the [alerts] destinations in the settings file")
            command.add_argument("--config", type=Path,
                                 help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    egress = sub.add_parser(
        "egress", help="learn which programs connect out, and report new ones and dropped tools phoning home")
    egress_sub = egress.add_subparsers(dest="egress_command", required=True)
    for name, text in (("learn", "record the programs connecting out now, and for --minutes more"),
                       ("check", "report programs connecting out that are not in the baseline (exit 1 on findings)"),
                       ("watch", "report each new outgoing program as it connects, as JSON lines"),
                       ("allow", "after review, record a program (and optionally a port) as normal")):
        command = egress_sub.add_parser(name, help=text)
        command.add_argument("--manifest", type=Path, help="baseline file (default ~/.config/megalodon/egress.json)")
        if name == "learn":
            command.add_argument("--minutes", type=float, default=0, help="keep learning this long (default 0)")
            command.add_argument("--include-private", action="store_true",
                                 help="also learn and watch connections to private (LAN) addresses")
        if name == "allow":
            command.add_argument("program", nargs="?", help="the program as reported, e.g. /opt/vendor/agent")
            command.add_argument("--port", help="also allow this port, written tcp/443 or udp/53")
            command.add_argument("--destination",
                                 help="instead, allow a port and network for connections too short to name their "
                                      "program, written tcp/443@203.0.113.0/24")
        if name == "watch":
            command.add_argument("--interval", type=float, default=1.0, help="seconds between scans (default 1)")
            command.add_argument("--no-names", action="store_true",
                                 help="do not read DNS answers and TLS server names to name destinations")
            command.add_argument("--watchlist", type=Path,
                                 help="domain watchlist (default [threat_detection] watchlist_path in the settings)")
            command.add_argument("--respond", action="store_true", help=RESPOND_HELP)
            command.add_argument("--trace-connects", action="store_true",
                                 help="as root, load a small eBPF program that names the program behind every TCP "
                                      "connection, so ones too short for a scan are named too; it is removed when "
                                      "the watch stops")
        if name in ("check", "watch"):
            command.add_argument("--alert", action="store_true",
                                 help="also send findings to the [alerts] destinations in the settings file")
            command.add_argument("--config", type=Path,
                                 help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    ebpf = sub.add_parser(
        "ebpf", help="baseline and check loaded eBPF programs, the kernel code modern rootkits use (root)")
    ebpf_sub = ebpf.add_subparsers(dest="ebpf_command", required=True)
    for name, text in (("baseline", "record the loaded eBPF programs, pinned objects and the unprivileged setting"),
                       ("check", "report new, changed and hidden programs (exit 1 on findings)"),
                       ("accept", "after review, record the current programs")):
        command = ebpf_sub.add_parser(name, help=text)
        command.add_argument("--manifest", type=Path, help="baseline file (default ~/.config/megalodon/ebpf.json)")
        if name == "baseline":
            command.add_argument("--replace", action="store_true", help="overwrite an existing baseline")
        if name == "check":
            command.add_argument("--alert", action="store_true",
                                 help="also send findings to the [alerts] destinations in the settings file")
            command.add_argument("--config", type=Path,
                                 help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    memory = sub.add_parser(
        "memory", help="find code that lives only in process memory, and save it before the process is gone (root)")
    memory_sub = memory.add_subparsers(dest="memory_command", required=True)
    inspect_cmd = memory_sub.add_parser("inspect", help="list a process's executable memory and flag what is suspicious")
    inspect_cmd.add_argument("pid", type=int)
    memory_sub.add_parser("sweep", help="inspect every process (exit 1 on findings)")
    capture_cmd = memory_sub.add_parser("capture", help="save a process's suspicious memory into a sealed bundle")
    capture_cmd.add_argument("pid", type=int)
    capture_cmd.add_argument("--start", type=int,
                             help="the process's start time as reported; refuses if the PID now names another process")
    capture_cmd.add_argument("--output", type=Path, help="bundle folder (default under ~/.local/share/megalodon/evidence)")
    capture_cmd.add_argument("--all", action="store_true", help="save every readable region, not only suspicious ones")
    capture_cmd.add_argument("--limit-mb", type=int, default=256, help="stop saving after this much (default 256)")
    capture_cmd.add_argument("--with-command-line", action="store_true",
                             help="also save the command line, which can hold passwords and tokens")

    hardening = sub.add_parser(
        "hardening", help="baseline and check protections that get weaker, file capabilities and root's search path")
    hardening_sub = hardening.add_subparsers(dest="hardening_command", required=True)
    for name, text in (("baseline", "record the hardening review, file capabilities and root's search path"),
                       ("check", "report what got weaker or became a way to root (exit 1 on findings)"),
                       ("accept", "after review, record the current state")):
        command = hardening_sub.add_parser(name, help=text)
        command.add_argument("--manifest", type=Path,
                             help="baseline file (default ~/.config/megalodon/hardening.json)")
        if name == "baseline":
            command.add_argument("--replace", action="store_true", help="overwrite an existing baseline")
        if name == "check":
            command.add_argument("--alert", action="store_true",
                                 help="also send findings to the [alerts] destinations in the settings file")
            command.add_argument("--config", type=Path,
                                 help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    packages = sub.add_parser(
        "packages", help="baseline and check package sources, signing keys and package manager hooks")
    packages_sub = packages.add_subparsers(dest="packages_command", required=True)
    for name, text in (("baseline", "record the package sources, signing keys and hooks; report checks already off"),
                       ("check", "report keys, sources and hooks added and signature checks weakened (exit 1 on "
                                 "findings)"),
                       ("accept", "after review, record the current state")):
        command = packages_sub.add_parser(name, help=text)
        command.add_argument("--manifest", type=Path,
                             help="baseline file (default ~/.config/megalodon/packages.json)")
        if name == "baseline":
            command.add_argument("--replace", action="store_true", help="overwrite an existing baseline")
        if name == "check":
            command.add_argument("--alert", action="store_true",
                                 help="also send findings to the [alerts] destinations in the settings file")
            command.add_argument("--config", type=Path,
                                 help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    secrets = sub.add_parser(
        "secrets", help="find private keys, tokens and passwords other people can read, on command lines, or under "
                        "web roots")
    secrets_sub = secrets.add_subparsers(dest="secrets_command", required=True)
    for name, text in (("scan", "report every exposed secret now (exit 1 on findings); records nothing"),
                       ("baseline", "scan, report everything found, and record it as reviewed"),
                       ("check", "report exposed secrets not in the baseline (exit 1 on findings)"),
                       ("accept", "after review, record the current findings")):
        command = secrets_sub.add_parser(name, help=text)
        if name != "scan":
            command.add_argument("--manifest", type=Path,
                                 help="baseline file (default ~/.config/megalodon/secrets.json)")
        if name in ("scan", "baseline"):
            command.add_argument("--path", action="append", default=None,
                                 help="search this folder instead of the default ones (repeatable)")
        if name == "baseline":
            command.add_argument("--replace", action="store_true", help="overwrite an existing baseline")
        if name == "check":
            command.add_argument("--alert", action="store_true",
                                 help="also send findings to the [alerts] destinations in the settings file")
            command.add_argument("--config", type=Path,
                                 help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    report = sub.add_parser(
        "report", help="one security report for this machine in plain language: every check's latest result, "
                       "incidents, how the protection is set up, and your choices for each finding")
    report.add_argument("--format", choices=("text", "html", "json"), default="text",
                        help="text for the terminal (default), html for a page to open, json for programs")
    report.add_argument("--output", type=Path,
                        help="write the report to this file, mode 600, instead of printing it")
    report.add_argument("--hours", type=int, default=168, help="incidents of the last HOURS (default a week)")
    report.add_argument("--all", action="store_true",
                        help="list every kept finding of each check, not only the first 25")
    review = sub.add_parser(
        "review", help="go through the report's findings one at a time and choose what to do; a command runs only "
                       "after you confirm it")
    review.add_argument("--hours", type=int, default=168, help="incidents of the last HOURS (default a week)")
    timeline = sub.add_parser(
        "timeline", help="each incident's findings, decisions and actions in order, from every check")
    timeline_sub = timeline.add_subparsers(dest="timeline_command", required=True)
    command = timeline_sub.add_parser("push", help="send events not yet sent to the fleet collector, signed with this "
                                                   "machine's heartbeat key")
    command.add_argument("--config", type=Path, help="heartbeat configuration (default "
                                                     "~/.config/megalodon/heartbeat.json)")
    command.add_argument("--url", help="the collector's /events address (default: the heartbeat address with "
                                       "/events in place of /heartbeat)")
    command.add_argument("--dry-run", action="store_true", help="count what would be sent; send nothing")
    command.add_argument("--ledger", type=Path, help="the response engine's shadow ledger")
    command.add_argument("--journal", type=Path, help="the enforcement journal")
    for name, text in (("list", "incidents with activity in the last --hours, worst first"),
                       ("show", "one incident in order, or every incident that involved --entity")):
        command = timeline_sub.add_parser(name, help=text)
        if name == "list":
            command.add_argument("--hours", type=int, default=168, help="how far back (default 168)")
        else:
            command.add_argument("incident", nargs="?", help="incident ID, or the start of one")
            command.add_argument("--entity", help="KIND:VALUE, such as address:203.0.113.7, file:/tmp/x, "
                                                  "process:/usr/bin/curl or account:svc")
            command.add_argument("--output", type=Path, help="write the result to this file (mode 600)")
        command.add_argument("--format", choices=("json", "text") + (("html",) if name == "show" else ()),
                             default="text", help="output format (default text)")
        command.add_argument("--ledger", type=Path, help="the response engine's shadow ledger (the observation "
                                                         "log is read beside it)")
        command.add_argument("--journal", type=Path, help="the enforcement journal")

    commands = sub.add_parser(
        "commands", help="a signed log of every program started on this machine, that cannot be quietly rewritten")
    commands_sub = commands.add_subparsers(dest="commands_command", required=True)
    command = commands_sub.add_parser("init", help="start a log and print its first key once; keep the key off "
                                                   "this machine")
    command.add_argument("--key-file", type=Path, help="write the key to this file (mode 600) instead of printing "
                                                       "it, to move it off this machine")
    command.add_argument("--replace", action="store_true",
                         help="start a new log with a new key; the old log is kept under another name")
    command = commands_sub.add_parser("record", help="record every started program until stopped (root sees all)")
    command.add_argument("--keep-secrets", action="store_true",
                         help="do not blank passwords and tokens on command lines")
    command.add_argument("--trace-execs", action="store_true",
                         help="as root, load a small eBPF program and record each program from the kernel's own "
                              "record of its start, so one gone at once keeps its arguments and folder; it is "
                              "removed when recording stops")
    command = commands_sub.add_parser("verify", help="check every line against the first key (exit 1 on findings)")
    command.add_argument("--key-file", type=Path, required=True,
                         help="mode-600 file holding the key `commands init` printed; never pass the key on a "
                              "command line, where it would be recorded")
    command.add_argument("--expect-sequence", type=int,
                         help="the last line the heartbeat carried off the machine; a log ending earlier was cut")
    command.add_argument("--from-sequence", type=int, default=1,
                         help="start here: rotated files before this line were moved off the machine on purpose")
    command = commands_sub.add_parser("show", help="list recorded programs (does not verify: use verify)")
    command.add_argument("--since", help="only from this time on, such as 2026-11-19T12:00")
    command.add_argument("--uid", type=int, help="only this account, as it ran or as it logged in")
    command.add_argument("--contains", help="only commands containing this text")
    command.add_argument("--limit", type=int, default=500, help="the newest N (default 500)")
    command.add_argument("--format", choices=("text", "json"), default="text")
    commands_sub.add_parser("status", help="the last line written and the key's fingerprint")
    for command in commands_sub.choices.values():
        command.add_argument("--log", type=Path, help="the log (default ~/.local/state/megalodon/commands.jsonl)")
        command.add_argument("--state", type=Path,
                             help="the recorder's state (default ~/.local/state/megalodon/commands-state.json)")

    containers = sub.add_parser(
        "containers", help="baseline and check containers for escapes and for ways out to the host (root)")
    containers_sub = containers.add_subparsers(dest="containers_command", required=True)
    for name, text in (("baseline", "record the running containers, the escape hooks and the container exposures"),
                       ("check", "report escapes and containers that became riskier (exit 1 on findings)"),
                       ("accept", "after review, record the current containers"),
                       ("watch", "as root, load a small eBPF program and report each program started in the "
                                 "host's mount namespace from a container, as it starts, as JSON lines")):
        command = containers_sub.add_parser(name, help=text)
        if name != "watch":
            command.add_argument("--manifest", type=Path,
                                 help="baseline file (default ~/.config/megalodon/containers.json)")
        if name == "baseline":
            command.add_argument("--replace", action="store_true", help="overwrite an existing baseline")
        if name == "watch":
            command.add_argument("--respond", action="store_true", help=RESPOND_HELP)
        if name in ("check", "watch"):
            command.add_argument("--alert", action="store_true",
                                 help="also send findings to the [alerts] destinations in the settings file")
            command.add_argument("--config", type=Path,
                                 help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    boot = sub.add_parser(
        "boot", help="baseline and check the kernel, initramfs, bootloader and boot-time protections")
    boot_sub = boot.add_subparsers(dest="boot_command", required=True)
    for name, text in (("baseline", "record the boot files and the kernel's boot-time protections"),
                       ("check", "report boot changes no package update explains, and weakened protections "
                                 "(exit 1 on findings)"),
                       ("accept", "after a reviewed kernel or bootloader update, record the current state")):
        command = boot_sub.add_parser(name, help=text)
        command.add_argument("--manifest", type=Path, help="baseline file (default ~/.config/megalodon/boot.json)")
        if name == "baseline":
            command.add_argument("--replace", action="store_true", help="overwrite an existing baseline")
        if name == "check":
            command.add_argument("--alert", action="store_true",
                                 help="also send findings to the [alerts] destinations in the settings file")
            command.add_argument("--config", type=Path,
                                 help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    logins = sub.add_parser(
        "logins", help="learn who logs in from where, how and when, and report successful logins that do not fit")
    logins_sub = logins.add_subparsers(dest="logins_command", required=True)
    for name, text in (("learn", "build or extend the baseline from past logs (also how to accept reviewed logins)"),
                       ("check", "report new logins, sudo and su that do not fit the baseline (exit 1 on findings)")):
        command = logins_sub.add_parser(name, help=text)
        command.add_argument("--manifest", type=Path, help="baseline file (default ~/.config/megalodon/logins.json)")
        command.add_argument("--log", action="append", dest="logs",
                             help="auth log, wtmp file, or - for journal output on standard input (repeatable; "
                                  "default /var/log/auth.log, /var/log/secure, then /var/log/wtmp)")
        if name == "check":
            command.add_argument("--all", action="store_true", help="judge every event, not only those since the "
                                                                    "last check")
            command.add_argument("--alert", action="store_true",
                                 help="also send findings to the [alerts] destinations in the settings file")
            command.add_argument("--config", type=Path,
                                 help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    credentials = sub.add_parser(
        "credentials", help="report programs opening SSH keys, browser password stores, cloud tokens and wallets")
    credentials_sub = credentials.add_subparsers(dest="credentials_command", required=True)
    for name, text in (("watch", "report each unexpected open of a credential file as it happens, as JSON lines"),
                       ("check", "report unexpected programs holding credential files open now (exit 1 on findings)"),
                       ("allow", "after review, allow one program to read one kind of credential")):
        command = credentials_sub.add_parser(name, help=text)
        command.add_argument("--allow-file", type=Path,
                             help="reviewed readers (default ~/.config/megalodon/credential-allow.json)")
        if name == "watch":
            command.add_argument("--respond", action="store_true", help=RESPOND_HELP)
            command.add_argument("--trace-execs", action="store_true",
                                 help="as root, load a small eBPF program that remembers every program as it "
                                      "starts, so a reader gone within microseconds is still named; it is "
                                      "removed when the watch stops")
        if name == "allow":
            command.add_argument("program", help="the program as reported, e.g. /usr/bin/rsync")
            command.add_argument("--category", default="any",
                                 help="ssh, browser, cloud, keyring, wallet, system or any (default any)")
            continue
        command.add_argument("--alert", action="store_true",
                             help="also send findings to the [alerts] destinations in the settings file")
        command.add_argument("--config", type=Path,
                             help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    tamper = sub.add_parser(
        "tamper", help="notice when MEGALODON's code, schedule or configuration is changed or switched off")
    tamper_sub = tamper.add_subparsers(dest="tamper_command", required=True)
    for name, text in (("baseline", "record MEGALODON's code, scheduled units and configuration"),
                       ("check", "report changed code, removed, stopped or overdue watches and changed "
                                 "configuration (exit 1 on findings)"),
                       ("accept", "after an upgrade or a reviewed change, record the current state")):
        command = tamper_sub.add_parser(name, help=text)
        command.add_argument("--manifest", type=Path, help="baseline file (default ~/.config/megalodon/tamper.json)")
        if name == "baseline":
            command.add_argument("--replace", action="store_true", help="overwrite an existing baseline")
        if name == "check":
            command.add_argument("--alert", action="store_true",
                                 help="also send findings to the [alerts] destinations in the settings file")
            command.add_argument("--config", type=Path,
                                 help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    heartbeat = sub.add_parser(
        "heartbeat", help="send a signed heartbeat off the machine, and check received ones for silence or forgery")
    heartbeat_sub = heartbeat.add_subparsers(dest="heartbeat_command", required=True)
    command = heartbeat_sub.add_parser("init", help="record the heartbeat destination and a new signing key")
    command.add_argument("--url", required=True, action="append",
                         help="where heartbeats are posted (https, or http to a private address); give it again for "
                              "a second collector, which gets the same heartbeats, timelines and evidence")
    command.add_argument("--replace", action="store_true", help="set a new destination and key")
    for name, text in (("add-url", "add a heartbeat destination, keeping the key (e.g. a second collector)"),
                       ("remove-url", "remove a heartbeat destination other than the first")):
        command = heartbeat_sub.add_parser(name, help=text)
        command.add_argument("url", help="the destination, as given to `heartbeat init`")
    command = heartbeat_sub.add_parser("send", help="post one signed heartbeat (exit 2 if it could not be delivered)")
    command.add_argument("--print", action="store_true", dest="print_only",
                         help="print the heartbeat instead of posting it")
    command = heartbeat_sub.add_parser("monitor", help="on another machine: report heartbeats that went silent, "
                                                       "were replayed or forged, or changed state (exit 1 on findings)")
    command.add_argument("--input", type=Path, help="received heartbeats as JSON lines (default: standard input)")
    command.add_argument("--key-file", type=Path, required=True,
                         help="mode-600 file holding the key that `heartbeat init` printed")
    command.add_argument("--max-gap", type=int, default=900, help="seconds without a heartbeat before it is silent "
                                                                  "(default 900)")
    command.add_argument("--sensor", help="only heartbeats from this sensor name")
    command.add_argument("--alert", action="store_true", help="also send findings to this machine's alerts")
    command.add_argument("--config", type=Path, help="settings file for --alert")

    vulns = sub.add_parser(
        "vulns", help="security fixes waiting, kernels not booted and old code still running, exposed services first")
    vulns_sub = vulns.add_subparsers(dest="vulns_command", required=True)
    command = vulns_sub.add_parser("check", help="read the package manager's local lists (exit 1 on findings)")
    command.add_argument("--alert", action="store_true",
                         help="also send findings to the [alerts] destinations in the settings file")
    command.add_argument("--config", type=Path,
                         help="settings file for --alert (default ~/.config/megalodon/settings.toml)")

    enforce = sub.add_parser(
        "enforce", help="carry out the response engine's decisions you allowed, with a way to undo each (off by "
                        "default)")
    enforce_sub = enforce.add_subparsers(dest="enforce_command", required=True)
    command = enforce_sub.add_parser("init", help="write an enforcement policy that is off, pinned to the current "
                                                  "response policy")
    command.add_argument("--replace", action="store_true", help="pin the current response policy again")
    command = enforce_sub.add_parser("run", help="carry out the allowed decisions recorded since the last run")
    command.add_argument("--dry-run", action="store_true", help="show what would be carried out, and change nothing")
    enforce_sub.add_parser("list", help="applied actions that have not been undone")
    command = enforce_sub.add_parser("undo", help="undo one applied action")
    command.add_argument("id", help="the ID that run or list printed")
    for command in enforce_sub.choices.values():
        command.add_argument("--policy", type=Path, help="enforcement policy (default ~/.config/megalodon/enforce.toml)")

    fleet = sub.add_parser(
        "fleet", help="collect every machine's heartbeats and alerts in one place, and show them together")
    fleet_sub = fleet.add_subparsers(dest="fleet_command", required=True)
    command = fleet_sub.add_parser("enroll", help="record a machine and its heartbeat key; prints its alert token")
    command.add_argument("machine", help="a name for the machine")
    command.add_argument("--key-file", type=Path, required=True,
                         help="mode-600 file holding the key that machine's `heartbeat init` printed")
    command.add_argument("--sensor", help="the sensor name its heartbeats carry (default: the machine name)")
    command.add_argument("--replace", action="store_true", help="give an enrolled machine a new key and token")
    command = fleet_sub.add_parser("remove", help="stop accepting a machine (what it sent is kept)")
    command.add_argument("machine")
    command = fleet_sub.add_parser("serve", help="receive heartbeats at /heartbeat and alerts at /alert")
    command.add_argument("--listen", default="127.0.0.1:8650", help="address:port (default 127.0.0.1:8650)")
    command.add_argument("--certificate", type=Path, help="TLS certificate (needed off loopback)")
    command.add_argument("--private-key", type=Path, help="TLS private key")
    command.add_argument("--plain-http", action="store_true",
                         help="listen off loopback without TLS (only behind a TLS proxy on the same network)")
    command.add_argument("--max-gap", type=int, default=900, help="seconds without a heartbeat before a machine "
                                                                  "is silent (default 900)")
    command.add_argument("--view", default="127.0.0.1:8651",
                         help="loopback address:port for the view, / and /status (default 127.0.0.1:8651; "
                              "'off' for none)")
    command = fleet_sub.add_parser("status", help="every machine's heartbeats and recent alerts (exit 1 if any "
                                                  "needs attention)")
    command.add_argument("--max-gap", type=int, default=900, help="seconds without a heartbeat before a machine "
                                                                  "is silent (default 900)")
    command.add_argument("--hours", type=int, default=24, help="alerts from this many hours (default 24)")
    command.add_argument("--alert", action="store_true", help="also send heartbeat findings to this machine's alerts")
    command.add_argument("--config", type=Path, help="settings file for --alert")
    command = fleet_sub.add_parser("timeline", help="incidents across every machine, joined by shared addresses; "
                                                    "give an ID or --entity to tell one")
    command.add_argument("incident", nargs="?", help="a fleet incident ID, or the start of one")
    command.add_argument("--entity", help="KIND:VALUE, such as address:203.0.113.7")
    command.add_argument("--hours", type=int, default=168, help="for the list: how far back (default 168)")
    command.add_argument("--format", choices=("text", "json", "html"), default="text")
    command.add_argument("--output", type=Path, help="write the result to this file (mode 600)")
    command = fleet_sub.add_parser("evidence", help="what each machine's evidence push delivered; with --verify, "
                                                    "check the collector's copies (exit 1 on findings)")
    command.add_argument("machine", nargs="?", help="one machine (default: every machine)")
    command.add_argument("--verify", action="store_true",
                         help="check the copies: the command log with --key-file, every complete bundle against "
                              "the manifest digest recorded when it arrived")
    command.add_argument("--key-file", type=Path,
                         help="the command log key from `commands init`, to check the copy of the log with")
    command.add_argument("--from-sequence", type=_bounded_cli_integer("from-sequence", 1, 2**62), default=1,
                         help="check the log from this line: only for lines you let go of on purpose (default 1)")
    for command in fleet_sub.choices.values():
        command.add_argument("--data", type=Path, help="collector folder (default ~/.local/share/megalodon/fleet)")

    schedule = sub.add_parser(
        "schedule", help="run every host watch on a schedule with alerts (systemd timers; plan first)")
    schedule_sub = schedule.add_subparsers(dest="schedule_command", required=True)
    for name, text in (("plan", "show the timers and services that install would add, and missing baselines"),
                       ("install", "write and enable the timers and services (needs --yes)"),
                       ("remove", "disable and delete MEGALODON's timers and services (needs --yes)")):
        command = schedule_sub.add_parser(name, help=text)
        scope = command.add_mutually_exclusive_group()
        scope.add_argument("--system", action="store_true", default=None,
                           help="system units in /etc/systemd/system (the default as root)")
        scope.add_argument("--user", action="store_false", dest="system",
                           help="user units in ~/.config/systemd/user (the default otherwise)")
        command.add_argument("--unit-dir", type=Path, help="unit folder to use instead of the systemd default")
        if name != "remove":
            command.add_argument("--only", action="append", help="limit to these jobs (repeatable)")
        if name in ("install", "remove"):
            command.add_argument("--yes", action="store_true", help="confirm the change")
        if name == "install":
            command.add_argument("--take-baselines", action="store_true",
                                 help="take missing baselines first; do this only on a system you trust")

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
    push = evidence_sub.add_parser(
        "push", help="send command log lines and evidence bundles not yet sent to the fleet collector, signed "
                     "with the heartbeat key")
    push.add_argument("--config", type=Path, help="heartbeat configuration (default ~/.config/megalodon/heartbeat.json)")
    push.add_argument("--url", help="where to send (default: the heartbeat URL with /evidence for /heartbeat)")
    push.add_argument("--log", type=Path, help="the command log (default ~/.local/state/megalodon/commands.jsonl)")
    push.add_argument("--evidence-root", type=Path,
                      help="the folder of evidence bundles (default ~/.local/share/megalodon/evidence)")
    push.add_argument("--max-mib", type=_bounded_cli_integer("max-mib", 1, 4096), default=64,
                      help="file bytes to send in this run, in MiB; the rest goes next time (default 64)")
    push.add_argument("--cursor", type=Path,
                      help="the record of what was sent (default ~/.local/state/megalodon/evidence-push.json)")
    push.add_argument("--dry-run", action="store_true", help="count what would be sent; send nothing")

    ransom = sub.add_parser("ransomware", help="watch folders for ransomware-style file encryption (Linux)")
    ransom_sub = ransom.add_subparsers(dest="ransomware_command", required=True)
    ransom_watch = ransom_sub.add_parser(
        "watch", help="watch folders until stopped; print each finding as JSON and send it to configured alerts")
    ransom_watch.add_argument("--dir", type=Path, action="append",
                              help="folder to watch, recursively (repeat for more; default: the folders saved "
                                   "by `ransomware init`)")
    ransom_watch.add_argument("--min-files", type=_bounded_cli_integer("min-files", 2, 10000),
                              help="encrypted files within the window that raise the alarm (default 10)")
    ransom_watch.add_argument("--window", type=_bounded_cli_integer("window", 5, 3600),
                              help="seconds (default 60)")
    ransom_watch.add_argument("--folders-file", type=Path,
                              help="saved folders to watch when no --dir is given "
                                   "(default ~/.config/megalodon/ransomware.json)")
    ransom_watch.add_argument("--config", type=Path,
                              help="settings file whose [alerts] receive findings "
                                   "(default ~/.config/megalodon/settings.toml when present)")
    ransom_watch.add_argument("--respond", action="store_true",
                              help="decide each finding at once with the response engine, and carry out what "
                                   "the enforcement policy allows")
    ransom_init = ransom_sub.add_parser("init", help="save the folders for a scheduled watch")
    ransom_init.add_argument("--dir", type=Path, action="append", required=True,
                             help="folder to watch, recursively (repeat for more)")
    ransom_init.add_argument("--min-files", type=_bounded_cli_integer("min-files", 2, 10000), default=10,
                             help="encrypted files within the window that raise the alarm (default 10)")
    ransom_init.add_argument("--window", type=_bounded_cli_integer("window", 5, 3600), default=60,
                             help="seconds (default 60)")
    ransom_init.add_argument("--folders-file", type=Path,
                             help="where to save them (default ~/.config/megalodon/ransomware.json)")
    ransom_init.add_argument("--replace", action="store_true", help="replace folders saved before")
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
    auth_input = auth.add_mutually_exclusive_group(required=True)
    auth_input.add_argument("--input",
                            help="auth log path (e.g. /var/log/auth.log), or - for journalctl -o short-iso on stdin")
    auth_input.add_argument("--journal", action="store_true",
                            help="read the systemd journal's auth and authpriv messages (with journalctl)")
    auth.add_argument("--hours", type=_bounded_cli_integer("hours", 1, 720), default=24,
                      help="with --journal: how far back to read (default 24)")
    auth.add_argument("--utc", action="store_true",
                      help="classic syslog stamps are UTC rather than this computer's local time")
    auth.add_argument("--emit-watchlist", type=Path,
                      help="write attacking addresses to an owner-private IOC watchlist file")
    auth.add_argument("--replace", action="store_true", help="overwrite an existing watchlist output")
    auth.add_argument("--lures", type=Path,
                      help="canary manifest whose agent lures' accounts are watched (LURE_FOLLOWED)")

    web = sub.add_parser(
        "web-review",
        help="review a web server access log for requests for an agent lure's page (exit 1 if any)",
    )
    web.add_argument("--input", required=True,
                     help="access log path (e.g. /var/log/nginx/access.log), or - for stdin")
    web.add_argument("--lures", type=Path, required=True,
                     help="canary manifest whose agent lures' pages are watched (LURE_FOLLOWED)")

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
                                  replace=args.replace, lure=args.lure)
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
            result = log_integrity.check(manifest, advance=args.advance)
    except (log_integrity.LogIntegrityError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    _keep(args, result)
    findings = result.get("findings", [])
    if args.logwatch_command == "check" and args.alert and findings:
        from .alerts import HostNotice, dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 2
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

    manifest = getattr(args, "manifest", None) or Path(watch.DEFAULT_MANIFEST).expanduser()
    try:
        if args.persistence_command == "baseline":
            result = watch.baseline(manifest, replace=args.replace)
        elif args.persistence_command == "accept":
            result = watch.accept(manifest)
        elif args.persistence_command == "scan":
            result = watch.scan()
        else:
            result = watch.check(manifest)
    except (watch.PersistenceError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    _keep(args, result)
    findings = result.get("findings", [])
    if args.persistence_command == "check" and args.alert and findings:
        from .alerts import HostNotice, dispatcher_for
        try:
            settings = load_settings(args.config or Path.home() / ".config/megalodon/settings.toml")
            dispatcher = dispatcher_for(settings.alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 2
        if dispatcher is not None:
            top = findings[0]
            listed = "; ".join(f"{f['change']} {f['category']} {f['location']}" for f in findings[:5])
            dispatcher.submit([HostNotice(
                "PERSISTENCE_CHANGE", top["severity"], datetime.now(timezone.utc),
                f"{len(findings)} persistence changes since the baseline: {listed}",
                tuple(sorted({f['technique'] for f in findings}))[:8],
                "A place attackers use to survive reboots changed since the reviewed baseline.")])
    return 1 if findings or result.get("suspicious") else 0


def _listeners(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone

    from . import listener_watch as watch
    from .validation import ValidationError

    manifest = args.manifest or Path(watch.DEFAULT_MANIFEST).expanduser()
    if args.listeners_command == "watch":
        return _listeners_watch(args, manifest)
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
    _keep(args, result)
    findings = result.get("findings", [])
    if args.listeners_command == "check" and args.alert and findings:
        from .alerts import HostNotice, dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 2
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


def _listeners_watch(args: argparse.Namespace, manifest: Path) -> int:
    from datetime import datetime, timezone
    from threading import Event

    from . import listener_watch as watch
    from .validation import ValidationError

    dispatcher = None
    if args.alert:
        from .alerts import dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 2

    kept = _watch_keeper(args, "listeners")

    def emit(found):
        print(json.dumps(found, sort_keys=True), flush=True)
        kept(found)
        if dispatcher is not None:
            from .alerts import HostNotice
            programs = ", ".join(p["path"] for p in found["programs"][:2]) or "program unknown"
            dispatcher.submit([HostNotice(
                found["rule_id"], found["severity"], datetime.now(timezone.utc),
                f"{found['rule_id']} {found['listener']} ({programs})", tuple(found["techniques"])[:8],
                "A program started listening for connections, took over a port, or became reachable more widely.")])
    if args.interval <= 0:
        print("megalodon: --interval must be more than 0", file=sys.stderr)
        return 2
    try:
        watcher = watch.Watcher(manifest, emit, interval=args.interval)
    except (watch.ListenerError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    try:
        watcher.run(Event())
    except KeyboardInterrupt:
        pass
    return 0


RESPOND_HELP = ("decide each finding at once with the response engine, and carry out what the enforcement policy "
                "allows (such as pausing the process)")


def _answer_at_once(args, source):
    """With --respond, a function that decides one live finding at once and says so on standard error."""
    if not getattr(args, "respond", False):
        return lambda found: None
    from . import respond_now
    responder = respond_now.Responder()

    def answer(found):
        # Before the alert and before the next event: the process the finding names is still running.
        print("megalodon: response " + json.dumps(respond_now.answer(responder, source, found), sort_keys=True),
              file=sys.stderr, flush=True)
    return answer


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
        _keep(args, report)
        for found in report["findings"][:10]:
            notify(found)
        return 1 if report["findings"] else 0

    respond = _answer_at_once(args, "ancestry")

    def emit(found):
        print(json.dumps(found, sort_keys=True), flush=True)
        respond(found)
        notify(found)
    trace = None
    if args.trace_execs:
        from .connect_trace import TraceError
        from .exec_trace import ExecTrace
        try:
            trace = ExecTrace()
        except TraceError as exc:
            print(f"megalodon: exec tracing unavailable: {exc.strerror or exc}; using the kernel's process events, "
                  "where a program gone before it is read is not judged", file=sys.stderr)
    try:
        watcher = ancestry.Watcher(emit, allow_path=allow_file, interval=args.interval, trace=trace)
    except (ancestry.AncestryError, OSError) as exc:
        if trace is not None:
            trace.close()
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(f"megalodon: watching programs that services start ({watcher.mode})"
          + (f"; alerts to {len(dispatcher.channels)} destinations" if dispatcher else "")
          + ("; findings are decided at once" if args.respond else ""), file=sys.stderr, flush=True)
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
            responder = None
            if args.respond:
                from .respond_now import Responder
                responder = Responder()

            def emit(found):
                print(json.dumps(found, sort_keys=True), flush=True)
                if responder is not None:
                    # Decided and carried out before anything else: a keystroke-injection device types at once.
                    print("megalodon: response " + json.dumps(watch.respond(found, responder), sort_keys=True),
                          file=sys.stderr, flush=True)
                notify(found)
            events = None if args.poll else watch.uevents()
            watch.check(manifest)        # refuses a missing or unsafe baseline before anything starts
            print("megalodon: watching devices: " + (
                "the kernel's device events, and a check every " + f"{args.interval:g}s" if events is not None else
                f"a check every {args.interval:g}s" + ("" if args.poll else " (the kernel's device events are not "
                                                                         "available here)"))
                  + ("; new devices are decided at once" if responder else ""), file=sys.stderr, flush=True)
            try:
                watch.watch(manifest, emit, interval=args.interval, events=events)
            except KeyboardInterrupt:
                pass
            finally:
                if events is not None:
                    events.close()
            return 0
        else:
            result = watch.check(manifest)
    except (watch.DeviceError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    _keep(args, result)
    findings = result.get("findings", [])
    for found in findings[:10]:
        notify(found)
    return 1 if findings else 0


def _webroot(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone

    from . import webroot_watch as watch
    from .validation import ValidationError

    manifest = args.manifest or Path(watch.DEFAULT_MANIFEST).expanduser()
    if args.webroot_command == "watch":
        return _webroot_watch(args, manifest)
    try:
        if args.webroot_command == "baseline":
            result = watch.baseline(manifest, replace=args.replace, web_roots=args.roots)
        elif args.webroot_command == "accept":
            result = watch.accept(manifest, web_roots=args.roots)
        else:
            result = watch.check(manifest, web_roots=args.roots)
    except (watch.WebrootError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    _keep(args, result)
    findings = result.get("findings", [])
    if args.webroot_command == "check" and args.alert and findings:
        from .alerts import HostNotice, dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 2
        if dispatcher is not None:
            listed = "; ".join(f["detail"] for f in findings[:5])
            dispatcher.submit([HostNotice(findings[0]["rule_id"], findings[0]["severity"], datetime.now(timezone.utc),
                                          f"{len(findings)} web-root findings: {listed}", ("T1505.003",),
                                          "A server-side script was added, changed or hidden under a web root.")])
    # A baseline that finds a web shell already in place still records it, and says so with exit 1.
    return 1 if findings else 0


def _webroot_watch(args: argparse.Namespace, manifest: Path) -> int:
    from datetime import datetime, timezone
    from threading import Event

    from . import webroot_watch as watch
    from .ransomware_watch import WatchError
    from .validation import ValidationError

    dispatcher = None
    if args.alert:
        from .alerts import dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 2

    kept = _watch_keeper(args, "webroot")

    def emit(found):
        print(json.dumps(found, sort_keys=True), flush=True)
        kept(found)
        if dispatcher is not None:
            from .alerts import HostNotice
            dispatcher.submit([HostNotice(found["rule_id"], found["severity"], datetime.now(timezone.utc),
                                          found["detail"], tuple(found["techniques"]), found["summary"])])
    try:
        watcher = watch.Watcher(manifest, emit, web_roots=args.roots)
    except (watch.WebrootError, WatchError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    try:
        watcher.run(Event())
    except KeyboardInterrupt:
        pass
    return 0


def _egress(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone
    from threading import Event

    from . import egress_watch as egress
    from .validation import ValidationError

    manifest = args.manifest or Path(egress.DEFAULT_MANIFEST).expanduser()
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
        if args.egress_command == "learn":
            result = egress.learn(manifest, seconds=args.minutes * 60, include_private=args.include_private)
        elif args.egress_command == "allow":
            if (args.program is None) == (args.destination is None):
                print("megalodon: name a program, or a destination with --destination", file=sys.stderr)
                return 2
            result = egress.allow(manifest, args.program, args.port, args.destination)
        elif args.egress_command == "watch":
            respond = _answer_at_once(args, "egress")

            def emit(found):
                print(json.dumps(found, sort_keys=True), flush=True)
                respond(found)
                notify(found)
            names = watchlist = None
            if not args.no_names:
                from . import connection_names
                names, _, error = connection_names.start()
                if error:
                    print(f"megalodon: {error}; destinations are shown by address only", file=sys.stderr)
                    names = None
            listed = args.watchlist
            if listed is None:
                try:
                    configured = load_settings(args.config or Path.home() / ".config/megalodon/settings.toml")
                    listed = Path(configured.threat.watchlist_path).expanduser() \
                        if configured.threat.watchlist_path else None
                except (ValidationError, OSError):
                    listed = None
            if listed is not None:
                from .watchlist import load_watchlist
                try:
                    watchlist = load_watchlist(listed)
                except (ValueError, OSError) as exc:
                    print(f"megalodon: watchlist unavailable: {exc}", file=sys.stderr)
                    return 2
            naming = None
            if args.trace_connects:
                from .connect_trace import TraceError
                try:
                    naming = egress.Naming()
                except TraceError as exc:
                    print(f"megalodon: connect tracing unavailable: {exc.strerror or exc}; short connections are "
                          "reported by destination only", file=sys.stderr)
                else:
                    print("megalodon: connect tracing on: short connections are named by their program",
                          file=sys.stderr)
            watcher = egress.Watcher(manifest, emit, interval=args.interval, names=names, watchlist=watchlist,
                                     naming=naming)
            stop = Event()
            try:
                watcher.run(stop)
            except KeyboardInterrupt:
                pass
            return 0
        else:
            result = egress.check(manifest)
    except (egress.EgressError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    _keep(args, result)
    findings = result.get("findings", [])
    for found in findings[:10]:
        notify(found)
    return 1 if findings else 0


def _ebpf(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone

    from . import ebpf_watch as ebpf
    from .validation import ValidationError

    manifest = args.manifest or Path(ebpf.DEFAULT_MANIFEST).expanduser()
    try:
        if args.ebpf_command == "baseline":
            result = ebpf.baseline(manifest, replace=args.replace)
        elif args.ebpf_command == "accept":
            result = ebpf.accept(manifest)
        else:
            result = ebpf.check(manifest)
    except (ebpf.EbpfError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    _keep(args, result)
    findings = result.get("findings", [])
    if args.ebpf_command == "check" and args.alert and findings:
        from .alerts import HostNotice, dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 2
        if dispatcher is not None:
            listed = "; ".join(f["detail"] for f in findings[:5])
            dispatcher.submit([HostNotice(findings[0]["rule_id"], findings[0]["severity"], datetime.now(timezone.utc),
                                          f"{len(findings)} eBPF findings: {listed}",
                                          tuple(sorted({t for f in findings for t in f["techniques"]})),
                                          "New, changed or hidden eBPF programs are loaded in the kernel.")])
    return 1 if findings else 0


def _memory(args: argparse.Namespace) -> int:
    from . import memory_capture as mc

    try:
        if args.memory_command == "inspect":
            result = mc.inspect(args.pid)
        elif args.memory_command == "sweep":
            result = mc.sweep()
        else:
            result = mc.capture(args.pid, start=args.start, output=args.output, everything=args.all,
                                command_line=args.with_command_line, limit=max(1, args.limit_mb) * 1024 * 1024)
    except (mc.MemoryCaptureError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result.get("findings") else 0


def _hardening(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone

    from . import hardening_drift as hd
    from .validation import ValidationError

    manifest = args.manifest or Path(hd.DEFAULT_MANIFEST).expanduser()
    try:
        if args.hardening_command == "baseline":
            result = hd.baseline(manifest, replace=args.replace)
        elif args.hardening_command == "accept":
            result = hd.accept(manifest)
        else:
            result = hd.check(manifest)
    except (hd.HardeningError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    _keep(args, result)
    findings = result.get("findings", [])
    if args.hardening_command == "check" and args.alert and findings:
        from .alerts import HostNotice, dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 2
        if dispatcher is not None:
            listed = "; ".join(f["detail"] for f in findings[:5])
            dispatcher.submit([HostNotice(findings[0]["rule_id"], findings[0]["severity"], datetime.now(timezone.utc),
                                          f"{len(findings)} hardening findings: {listed}",
                                          tuple(sorted({t for f in findings for t in f["techniques"]})),
                                          "A protection got weaker, or a new way to root appeared.")])
    return 1 if findings else 0


def _packages(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone

    from . import package_sources as ps
    from .validation import ValidationError

    manifest = args.manifest or Path(ps.DEFAULT_MANIFEST).expanduser()
    try:
        if args.packages_command == "baseline":
            result = ps.baseline(manifest, replace=args.replace)
        elif args.packages_command == "accept":
            result = ps.accept(manifest)
        else:
            result = ps.check(manifest)
    except (ps.PackageSourcesError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    _keep(args, result)
    findings = result.get("findings", [])
    if args.packages_command == "check" and args.alert and findings:
        from .alerts import HostNotice, dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 2
        if dispatcher is not None:
            listed = "; ".join(f["detail"] for f in findings[:5])
            dispatcher.submit([HostNotice(findings[0]["rule_id"], findings[0]["severity"], datetime.now(timezone.utc),
                                          f"{len(findings)} package source findings: {listed}",
                                          tuple(sorted({t for f in findings for t in f["techniques"]})),
                                          "A signing key, package source or package manager hook changed, or "
                                          "signature checks were weakened.")])
    return 1 if findings else 0


def _secrets(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone

    from . import exposed_secrets as sc
    from .validation import ValidationError

    search = tuple(os.path.abspath(p) for p in args.path) if getattr(args, "path", None) else sc.SEARCH
    try:
        if args.secrets_command == "scan":
            findings, gaps = sc.scan(search=search)
            result = sc.report(findings, gaps, "scan")
        else:
            manifest = args.manifest or Path(sc.DEFAULT_MANIFEST).expanduser()
            if args.secrets_command == "baseline":
                result = sc.baseline(manifest, replace=args.replace, search=search)
            elif args.secrets_command == "accept":
                result = sc.accept(manifest)
            else:
                result = sc.check(manifest)
    except (sc.SecretsError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    _keep(args, result)
    findings = result.get("findings", [])
    if args.secrets_command == "check" and args.alert and findings:
        from .alerts import HostNotice, dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 2
        if dispatcher is not None:
            # The details name places and kinds of secrets, never their values.
            listed = "; ".join(f["detail"] for f in findings[:5])
            dispatcher.submit([HostNotice(findings[0]["rule_id"], findings[0]["severity"], datetime.now(timezone.utc),
                                          f"{len(findings)} exposed secrets: {listed}",
                                          tuple(sorted({t for f in findings for t in f["techniques"]})),
                                          "A key, token or password can be read by people it was not meant for.")])
    return 1 if findings else 0


def _timeline(args: argparse.Namespace) -> int:
    from . import response_engine as engine
    from . import timeline as tl

    paths = dict(ledger=args.ledger or engine.DEFAULT_LEDGER, journal=args.journal)
    if args.timeline_command == "push":
        import urllib.error
        from .tamper import TamperError
        try:
            result = tl.push(config=args.config, url=args.url, dry_run=args.dry_run, **paths)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                # A heartbeat monitor that is not a fleet collector takes no timelines: nothing to send it.
                print(json.dumps(dict(sent=0, note="the heartbeat destination takes no timelines (404); run a "
                                                   "fleet collector, or give --url"), sort_keys=True))
                return 0
            print(f"megalodon: the collector refused the timeline: HTTP {exc.code}", file=sys.stderr)
            return 2
        except (tl.TimelineError, engine.ResponseError, TamperError, OSError) as exc:
            print(f"megalodon: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(result, indent=2, sort_keys=True))
        return 2 if any("error" in r for r in result.get("collectors", ())) else 0
    try:
        if args.timeline_command == "list":
            result = tl.incidents(hours=args.hours, **paths)
        else:
            result = tl.show(args.incident, entity=args.entity, **paths)
    except (tl.TimelineError, engine.ResponseError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    elif args.format == "html":
        rendered = tl.page(result)
    else:
        rendered = tl.text(result)
    if getattr(args, "output", None):
        try:
            print(f"wrote {tl.write_private(args.output, rendered)}")
        except (tl.TimelineError, OSError) as exc:
            print(f"megalodon: {exc}", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(rendered)
    return 0


def _commands(args: argparse.Namespace) -> int:
    import threading

    from . import command_log as cl
    from .alerts import AlertConfigError, read_secret

    paths = dict(log=args.log or cl.DEFAULT_LOG, state=args.state or cl.DEFAULT_STATE)
    try:
        if args.commands_command == "init":
            result = cl.init(state=paths["state"], log=paths["log"], replace=args.replace, key_file=args.key_file)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.commands_command == "record":
            import signal as signals
            stop = threading.Event()
            for number in (signals.SIGTERM, signals.SIGINT):
                signals.signal(number, lambda *_: stop.set())
            trace = None
            if args.trace_execs:
                from .connect_trace import TraceError
                from .exec_trace import ExecTrace
                try:
                    trace = ExecTrace()
                except TraceError as exc:
                    print(f"megalodon: exec tracing unavailable: {exc.strerror or exc}; recording from the "
                          "kernel's process events, where a program gone at once loses its arguments",
                          file=sys.stderr)
            count = cl.record(stop, state=paths["state"], log=paths["log"], redact=not args.keep_secrets,
                              trace=trace)
            print(json.dumps(dict(recorded=count), sort_keys=True))
            return 0
        if args.commands_command == "verify":
            result = cl.verify(read_secret(str(args.key_file)), log=paths["log"], expect_sequence=args.expect_sequence,
                               from_sequence=args.from_sequence)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 1 if result["findings"] else 0
        if args.commands_command == "status":
            print(json.dumps(cl.head(paths["state"]) or dict(error="no command log is set up here"), indent=2,
                             sort_keys=True))
            return 0
        rows = cl.show(log=paths["log"], since=args.since, uid=args.uid, contains=args.contains, limit=args.limit)
    except (cl.CommandLogError, AlertConfigError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(rows, indent=2, sort_keys=True))
    else:
        for row in rows:
            who = f"uid {row['uid']}" + (f" (login {row['login_uid']})" if row["login_uid"] not in (None, row["uid"])
                                          else "")
            print(f"{row['at']}  #{row['seq']}  {who}  {row['cwd'] or '?'}$ {row['command']}")
    return 0


def _containers(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone

    from . import container_watch as cw
    from .validation import ValidationError

    if args.containers_command == "watch":
        return _containers_watch(args, cw)
    manifest = args.manifest or Path(cw.DEFAULT_MANIFEST).expanduser()
    try:
        if args.containers_command == "baseline":
            result = cw.baseline(manifest, replace=args.replace)
        elif args.containers_command == "accept":
            result = cw.accept(manifest)
        else:
            result = cw.check(manifest)
    except (cw.ContainerError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    _keep(args, result)
    findings = result.get("findings", [])
    if args.containers_command == "check" and args.alert and findings:
        from .alerts import HostNotice, dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 2
        if dispatcher is not None:
            listed = "; ".join(f["detail"] for f in findings[:5])
            dispatcher.submit([HostNotice(findings[0]["rule_id"], findings[0]["severity"], datetime.now(timezone.utc),
                                          f"{len(findings)} container findings: {listed}",
                                          tuple(sorted({t for f in findings for t in f["techniques"]})),
                                          "A container escaped or gained a way out to the host.")])
    return 1 if findings else 0


def _containers_watch(args, cw) -> int:
    from datetime import datetime, timezone
    from threading import Event

    from .connect_trace import TraceError
    from .exec_trace import ExecTrace
    from .validation import ValidationError

    dispatcher = None
    if args.alert:
        from .alerts import dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 2
    respond = _answer_at_once(args, "containers")

    def emit(found):
        print(json.dumps(found, sort_keys=True), flush=True)
        respond(found)
        if dispatcher is not None:
            from .alerts import HostNotice
            dispatcher.submit([HostNotice(found["rule_id"], found["severity"], datetime.now(timezone.utc),
                                          found["detail"], tuple(found["techniques"]), found["summary"])])
    try:
        trace = ExecTrace()
    except TraceError as exc:
        print(f"megalodon: exec tracing unavailable: {exc.strerror or exc}; `megalodon containers check` still "
              "reports escapes that last more than a second", file=sys.stderr)
        return 2
    try:
        watcher = cw.EscapeWatch(emit, trace, notice=lambda dropped: print(
            f"megalodon: the exec trace had no room for {dropped} execs and forks so far; an escape among them is "
            "not reported", file=sys.stderr, flush=True))
    except (cw.ContainerError, OSError) as exc:
        trace.close()
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(f"megalodon: watching for container escapes as programs start (the host's mount namespace is "
          f"{watcher.host_from}'s)" + ("; findings are decided at once" if args.respond else ""),
          file=sys.stderr, flush=True)
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


def _boot(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone

    from . import boot_integrity as boot
    from .validation import ValidationError

    manifest = args.manifest or Path(boot.DEFAULT_MANIFEST).expanduser()
    try:
        if args.boot_command == "baseline":
            result = boot.baseline(manifest, replace=args.replace)
        elif args.boot_command == "accept":
            result = boot.accept(manifest)
        else:
            result = boot.check(manifest)
    except (boot.BootError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    _keep(args, result)
    findings = result.get("findings", [])
    if args.boot_command == "check" and args.alert and findings:
        from .alerts import HostNotice, dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 2
        if dispatcher is not None:
            listed = "; ".join(f["detail"] for f in findings[:5])
            dispatcher.submit([HostNotice(findings[0]["rule_id"], findings[0]["severity"], datetime.now(timezone.utc),
                                          f"{len(findings)} boot integrity findings: {listed}",
                                          tuple(sorted({t for f in findings for t in f["techniques"]})),
                                          "The kernel, initramfs, bootloader or a boot-time protection changed.")])
    return 1 if findings else 0


def _logins(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone

    from . import login_watch as logins
    from .validation import ValidationError

    manifest = args.manifest or Path(logins.DEFAULT_MANIFEST).expanduser()
    try:
        if args.logins_command == "learn":
            result = logins.learn(manifest, logs=args.logs)
        else:
            result = logins.check(manifest, logs=args.logs, every=args.all)
    except (logins.LoginError, ValidationError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    _keep(args, result)
    findings = result.get("findings", [])
    if args.logins_command == "check" and args.alert and findings:
        from .alerts import HostNotice, dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 2
        if dispatcher is not None:
            dispatcher.submit([HostNotice(f["rule_id"], f["severity"], datetime.now(timezone.utc), f["detail"],
                                          tuple(f["techniques"]), f["summary"]) for f in findings[:10]])
    return 1 if findings else 0


def _credentials(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone
    from threading import Event

    from . import credential_watch as credentials
    from .validation import ValidationError

    allow_file = args.allow_file or Path(credentials.DEFAULT_ALLOW).expanduser()
    if args.credentials_command == "allow":
        try:
            count = credentials.allow(allow_file, args.program, args.category)
        except (credentials.CredentialError, OSError) as exc:
            print(f"megalodon: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(dict(allow_file=str(allow_file), allowed=count), indent=2))
        return 0
    dispatcher = None
    if args.alert:
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
        if args.credentials_command == "check":
            report = credentials.check(allow_path=allow_file)
            print(json.dumps(report, indent=2, sort_keys=True))
            _keep(args, report)
            for found in report["findings"][:10]:
                notify(found)
            return 1 if report["findings"] else 0

        respond = _answer_at_once(args, "credentials")

        def emit(found):
            print(json.dumps(found, sort_keys=True), flush=True)
            respond(found)
            notify(found)
        trace = None
        if args.trace_execs:
            from .connect_trace import TraceError
            from .exec_trace import ExecTrace
            try:
                trace = ExecTrace()
            except TraceError as exc:
                print(f"megalodon: exec tracing unavailable: {exc.strerror or exc}; a reader that exits at "
                      "once may go unnamed", file=sys.stderr)
        watcher = credentials.Watcher(emit, allow_path=allow_file, trace=trace)
        if trace is not None:
            print("megalodon: exec tracing " + ("on: readers that exit at once are named" if watcher.trace else
                                                "off: it needs file-access notifications"), file=sys.stderr)
    except (credentials.CredentialError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(f"megalodon: watching {len(watcher.files)} credential files and {len(watcher.folders)} folders "
          f"({watcher.mode})" + ("; findings are decided at once" if args.respond else ""),
          file=sys.stderr, flush=True)
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


def _tamper_alert(args, findings, summary):
    from datetime import datetime, timezone

    from .alerts import HostNotice, dispatcher_for
    from .validation import ValidationError
    try:
        dispatcher = dispatcher_for(load_settings(
            args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
    except (ValidationError, OSError) as exc:
        print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
        return False
    if dispatcher is not None:
        listed = "; ".join(f["detail"] for f in findings[:5])
        dispatcher.submit([HostNotice(findings[0]["rule_id"], findings[0]["severity"], datetime.now(timezone.utc),
                                      f"{len(findings)} findings: {listed}", ("T1562.001",), summary)],
                          any_severity=True)
    return True


def _sanitize_tamper_output(value: object) -> object:
    sensitive_keys = {
        "configs",
        "secrets",
        "secret",
        "password",
        "token",
        "api_key",
        "key",
    }
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            lowered = str(key).casefold()
            if lowered in sensitive_keys or any(marker in lowered for marker in ("secret", "password", "token", "key")):
                sanitized[key] = "[REDACTED]"
            elif lowered == "detail" and isinstance(item, str):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = _sanitize_tamper_output(item)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_tamper_output(item) for item in value]
    return value


def _tamper_findings_shown(findings: list) -> list[dict]:
    """Each finding as `tamper check` prints it: its rule, severity and summary, and the file or unit it is
    about. Its detail is left out, as it is in the kept result; `megalodon report` lists the same findings."""
    from . import tamper

    shown = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        rule = str(finding.get("rule_id") or "")
        severity, summary = tamper.RULES.get(rule, (str(finding.get("severity") or ""), ""))
        shown.append({"rule_id": rule, "severity": severity, "subject": str(finding.get("subject") or ""),
                      "summary": summary})
    return shown


def _tamper(args: argparse.Namespace) -> int:
    from . import tamper

    manifest = args.manifest or Path(tamper.DEFAULT_MANIFEST).expanduser()
    try:
        if args.tamper_command == "baseline":
            result = tamper.baseline(manifest, replace=args.replace)
        elif args.tamper_command == "accept":
            result = tamper.accept(manifest)
        else:
            result = tamper.check(manifest)
    except (tamper.TamperError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    sanitized_result = _sanitize_tamper_output(result)
    output = {
        "schema": sanitized_result.get("schema"),
        "action": sanitized_result.get("action"),
        "manifest": sanitized_result.get("manifest"),
        "state_digest": sanitized_result.get("state_digest"),
        "code_files": sanitized_result.get("code_files"),
        "findings_count": len(result.get("findings", [])),
        # A baseline lists its units; a check maps each to its state.
        "units_count": len(result["units"]) if isinstance(result.get("units"), (list, dict)) else None,
        "configs_count": len(result.get("configs", [])) if isinstance(result.get("configs"), list) else None,
    }
    if isinstance(result.get("findings"), list):
        output["findings"] = _tamper_findings_shown(result["findings"])
    # What a check could not look at, and when: a check that could not ask systemd is not a clean one.
    for name in ("baseline_recorded_at", "checked_at", "gaps", "note"):
        if name in sanitized_result:
            output[name] = sanitized_result[name]
    print(json.dumps(output, indent=2, sort_keys=True))
    _keep(args, sanitized_result)
    findings = result.get("findings", [])
    if args.tamper_command == "check" and args.alert and findings:
        if not _tamper_alert(args, findings, "MEGALODON's own code, schedule or configuration changed."):
            return 2
    return 1 if findings else 0


def _heartbeat(args: argparse.Namespace) -> int:
    import urllib.error

    from . import tamper
    from .alerts import AlertConfigError, read_secret

    try:
        if args.heartbeat_command == "init":
            result = tamper.init_heartbeat(args.url, replace=args.replace)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.heartbeat_command in ("add-url", "remove-url"):
            result = tamper.change_destinations(**{"add" if args.heartbeat_command == "add-url" else "remove": args.url})
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.heartbeat_command == "send":
            settings, body = tamper.heartbeat()
            if args.print_only:
                print(json.dumps(body, sort_keys=True))
                return 0
            # The same signed heartbeat goes to every destination; one that cannot be reached does not stop the rest.
            delivered = []
            for url in tamper.destinations(settings):
                try:
                    delivered.append(dict(destination=url, status=tamper.send(dict(settings, url=url), body)))
                except (urllib.error.URLError, OSError) as exc:
                    print(f"megalodon: heartbeat {body['sequence']} was not delivered to {url}: {exc}",
                          file=sys.stderr)
                    delivered.append(dict(destination=url, error=str(exc)[:300]))
            result = dict(sequence=body["sequence"], findings=len(body["findings"]))
            if len(delivered) == 1:
                if "error" in delivered[0]:
                    return 2
                result["status"] = delivered[0]["status"]
            else:
                result["destinations"] = delivered
            print(json.dumps(result, sort_keys=True))
            return 0 if all(200 <= d.get("status", 0) < 300 for d in delivered) else 2
        key = read_secret(str(args.key_file))
        if args.input:
            with open(args.input, encoding="utf-8", errors="replace") as stream:
                lines = stream.read().splitlines()
        else:
            lines = sys.stdin.read().splitlines()
        result = tamper.monitor(lines, key, max_gap=args.max_gap, sensor=args.sensor)
    except (tamper.TamperError, AlertConfigError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    findings = result["findings"]
    if args.alert and findings:
        _tamper_alert(args, findings, "A monitored machine's heartbeat went silent, was forged or replayed, or "
                                      "reported tampering.")
    return 1 if findings else 0


def _vulns(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone

    from . import vuln_check
    from .validation import ValidationError

    try:
        result = vuln_check.check()
    except OSError as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    _keep(args, result)
    findings = result["findings"]
    if args.alert and findings:
        from .alerts import HostNotice, dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 2
        if dispatcher is not None:
            listed = "; ".join(f["detail"] for f in findings[:5])
            dispatcher.submit([HostNotice(findings[0]["rule_id"], findings[0]["severity"], datetime.now(timezone.utc),
                                          f"{len(findings)} findings: {listed}",
                                          tuple(sorted({t for f in findings for t in f["techniques"]})),
                                          "Security fixes are waiting, or not in effect yet.")])
    return 1 if findings else 0


def _enforce(args: argparse.Namespace) -> int:
    from . import enforcement
    from . import response_engine

    policy = args.policy or Path(enforcement.DEFAULT_POLICY).expanduser()
    try:
        if args.enforce_command == "init":
            result = enforcement.init(policy, replace=args.replace)
        elif args.enforce_command == "run":
            result = enforcement.run(policy_path=policy, dry_run=args.dry_run)
        elif args.enforce_command == "list":
            result = dict(active=enforcement.active())
        else:
            result = enforcement.undo(args.id)
    except (enforcement.EnforcementError, response_engine.ResponseError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.enforce_command == "run" and result.get("policy_error") is not None:
        return 2
    failed = [r for r in result.get("refused", []) + result.get("expired", []) if r.get("status") == "failed"]
    return 1 if args.enforce_command == "run" and failed else 0


def _fleet(args: argparse.Namespace) -> int:
    from . import fleet
    from .alerts import AlertConfigError, read_secret

    data = args.data or Path(fleet.DEFAULT_DATA).expanduser()
    try:
        if args.fleet_command == "enroll":
            result = fleet.enroll(args.machine, read_secret(str(args.key_file)), sensor=args.sensor, data=data,
                                  replace=args.replace)
        elif args.fleet_command == "remove":
            result = fleet.remove(args.machine, data=data)
        elif args.fleet_command == "serve":
            host, _, port = args.listen.rpartition(":")
            if not host or not port.isdigit():
                raise fleet.FleetError("--listen is address:port, such as 0.0.0.0:8650")
            httpd = fleet.server(host.strip("[]"), int(port), data=data, certificate=args.certificate,
                                 private_key=args.private_key, max_gap=args.max_gap, plain_http=args.plain_http)
            view = None
            if args.view != "off":
                view_host, _, view_port = args.view.rpartition(":")
                if not view_host or not view_port.isdigit():
                    raise fleet.FleetError("--view is a loopback address:port, such as 127.0.0.1:8651, or off")
                view = fleet.view_server(view_host.strip("[]"), int(view_port), data=data, max_gap=args.max_gap)
                fleet.serve_in_background(view)
            print(json.dumps(dict(listening=args.listen, tls=bool(args.certificate), view=args.view, data=str(data)),
                             sort_keys=True), flush=True)
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass
            return 0
        elif args.fleet_command == "evidence":
            from . import evidence_shipping as shipping
            names = [args.machine] if args.machine else sorted(fleet.machines(data))
            if args.machine and args.machine not in fleet.machines(data):
                raise fleet.FleetError(f"{args.machine} is not enrolled")
            if args.key_file and not args.verify:
                raise fleet.FleetError("--key-file is for --verify")
            try:
                if args.verify:
                    key = read_secret(str(args.key_file)) if args.key_file else None
                    if key is not None and not args.machine:
                        raise fleet.FleetError("a command log key belongs to one machine: name it")
                    checked = [shipping.verify(data, n, key_hex=key, from_sequence=args.from_sequence)
                               for n in names]
                    result = dict(schema=shipping.SCHEMA, action="verify", machines=checked)
                    print(json.dumps(result, indent=2, sort_keys=True))
                    return 1 if any(c["findings"] for c in checked) else 0
            except (shipping.ShippingError, ValueError) as exc:
                print(f"megalodon: {exc}", file=sys.stderr)
                return 2
            result = dict(schema=shipping.SCHEMA, action="list", machines=[shipping.held(data, n) for n in names])
            print(json.dumps(result, indent=2, sort_keys=True))
            return 1 if any(m["findings"] for m in result["machines"]) else 0
        elif args.fleet_command == "timeline":
            from . import timeline as tl
            if args.incident or args.entity:
                result = fleet.fleet_show(args.incident, entity=args.entity, data=data)
                rendered = tl.page(result) if args.format == "html" else None
            else:
                result = fleet.fleet_timeline(data=data, hours=args.hours)
                rendered = tl.list_page(result) if args.format == "html" else None
            if args.format == "json":
                rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
            elif rendered is None:
                rendered = tl.text(result)
            if args.output:
                print(f"wrote {tl.write_private(args.output, rendered)}")
            else:
                sys.stdout.write(rendered)
            return 0
        else:
            result = fleet.status(data=data, max_gap=args.max_gap, hours=args.hours)
    except (fleet.FleetError, AlertConfigError, OSError, ValueError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.fleet_command != "status":
        return 0
    if args.alert and result["findings"]:
        _tamper_alert(args, result["findings"], "A machine in the fleet went silent, or its heartbeats were forged, "
                                                "replayed or reported tampering.")
    return 1 if any(row["state"] != "ok" for row in result["machines"]) else 0


def _schedule(args: argparse.Namespace) -> int:
    import subprocess

    from . import schedule

    try:
        if args.schedule_command == "plan":
            result = schedule.plan(system=args.system, only=args.only, directory=args.unit_dir)
        elif not args.yes:
            print("megalodon: this changes the machine's services; review `megalodon schedule plan`, then add --yes",
                  file=sys.stderr)
            return 2
        elif args.schedule_command == "install":
            result = schedule.install(system=args.system, only=args.only, directory=args.unit_dir,
                                      take_baselines=args.take_baselines)
        else:
            result = schedule.remove(system=args.system, directory=args.unit_dir)
    except (schedule.ScheduleError, OSError, subprocess.SubprocessError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("ok", True) else 1


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
    _keep(args, report)
    findings = report["findings"]
    if args.alert and findings:
        from .alerts import HostNotice, dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 2
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
    _keep(args, result)
    findings = result.get("findings", [])
    if args.binaries_command in ("verify", "check") and args.alert and findings:
        from .alerts import HostNotice, dispatcher_for
        try:
            dispatcher = dispatcher_for(load_settings(
                args.config or Path.home() / ".config/megalodon/settings.toml").alerts)
        except (ValidationError, OSError) as exc:
            print(f"megalodon: alerts unavailable: {exc}", file=sys.stderr)
            return 2
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

    if args.evidence_command == "push":
        import urllib.error

        from . import evidence_shipping as shipping
        from .tamper import TamperError
        try:
            result = shipping.push(config=args.config, url=args.url, dry_run=args.dry_run,
                                   log=args.log or shipping.command_log.DEFAULT_LOG,
                                   evidence_root=args.evidence_root or evidence.DEFAULT_ROOT,
                                   budget=args.max_mib * 1024 * 1024,
                                   cursor_path=args.cursor or shipping.DEFAULT_CURSOR)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                # A heartbeat monitor that is not a fleet collector keeps no evidence: nothing to send it.
                print(json.dumps(dict(sent=0, note="the heartbeat destination keeps no evidence (404); run a fleet "
                                                   "collector, or give --url"), sort_keys=True))
                return 0
            print(f"megalodon: the collector refused the evidence: HTTP {exc.code}", file=sys.stderr)
            return 2
        except (shipping.ShippingError, TamperError, OSError, ValueError) as exc:
            print(f"megalodon: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(result, indent=2, sort_keys=True))
        return 2 if any("error" in r for r in result.get("collectors", ())) else 0
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
            return 2
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
    folders_file = args.folders_file or watch.DEFAULT_FOLDERS_FILE
    if args.ransomware_command == "init":
        try:
            result = watch.save_folders(args.dir, path=folders_file, min_files=args.min_files,
                                        window_seconds=args.window, replace=args.replace)
        except (watch.WatchError, OSError, ValueError) as exc:
            print(f"megalodon: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    path = args.config or Path.home() / ".config/megalodon/settings.toml"
    dispatcher = None
    responder = None
    try:
        saved = dict(folders=[str(item) for item in args.dir], min_files=10, window_seconds=60) if args.dir \
            else watch.load_folders(folders_file)
        if args.config or path.exists():
            dispatcher = dispatcher_for(load_settings(path).alerts)
        detector = watch.RansomwareDetector(min_files=args.min_files or saved["min_files"],
                                            window_seconds=args.window or saved["window_seconds"])
        roots = saved["folders"]
        if args.respond:
            responder = watch.Responder()
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
        if responder is not None:
            # Decided and carried out before the next event is read; said on standard error, beside the
            # start message, so standard output stays one finding per line.
            print("megalodon: response " + json.dumps(responder(finding), sort_keys=True), file=sys.stderr,
                  flush=True)

    def recover():
        result = responder.recover()
        if result['expired'] or result.get('error'):
            print("megalodon: recovery " + json.dumps(result, sort_keys=True), file=sys.stderr, flush=True)

    watcher.emit = emit
    print(f"megalodon: watching {watcher.watched} folders ({seeded} files recorded)"
          + ("; folder limit reached, some subfolders are not watched" if watcher.truncated else "")
          + (f"; alerts to {len(dispatcher.channels)} destinations" if dispatcher else "; no alerts configured")
          + ("; findings are decided at once" if responder else ""),
          file=sys.stderr, flush=True)
    stop = Event()
    try:
        watcher.run(stop, maintenance=recover if responder is not None else None)
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

    from datetime import datetime, timedelta

    from .auth_review import read_journal, read_lines, review
    from .validation import ValidationError
    from .watchlist import parse_indicator, render, write_private

    try:
        from .canary import lures
        accounts = lures(str(args.lures)) if args.lures else {}
        notes: list[str] = []
        if args.journal:
            lines = read_journal(datetime.now(timezone.utc) - timedelta(hours=args.hours), notes)
        else:
            lines = read_lines(args.input)
        report, reviewer = review(lines, source="journal" if args.journal else args.input,
                                  zone=timezone.utc if args.utc else None, lure_users=accounts)
        if args.journal:
            report["gaps"] = notes
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


def _web_review(args: argparse.Namespace) -> int:
    from .canary import web_lures
    from .validation import ValidationError
    from .web_review import read_lines, review

    try:
        pages = web_lures(str(args.lures))
        if not pages:
            raise ValidationError("the canary manifest's lures name no page: plant one with "
                                  "`megalodon canary plant --lure`")
        report, _ = review(read_lines(args.input), source=args.input, lure_pages=pages)
    except (ValidationError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if report["findings"] else 0


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


_PRINTED: dict = {}


def _kept(args):
    """The check whose result `megalodon report` keeps for this run, or None: a `check` of the machine's own
    baseline, as the scheduler runs it (a check of another baseline, given with --manifest, is not this machine's
    state)."""
    from . import results
    if args.command not in results.NAMES or getattr(args, f"{args.command}_command", None) != "check":
        return None
    if getattr(args, "manifest", None) is not None:
        return None
    return args.command


def _keep(args, result):
    if _kept(args):
        _PRINTED[args.command] = result


def _record(args, code, reason=None):
    name = _kept(args)
    if name is None:
        return
    from . import results
    try:
        results.keep(name, _PRINTED.pop(name, None), code, reason=reason)
    except OSError as exc:
        print(f"megalodon: this check's result was not kept for `megalodon report`: {exc}", file=sys.stderr)


# The live watches whose findings reach neither a check's kept result nor the response engine: what they see is kept
# for `megalodon report` as they see it, until the next check, accept or baseline.
WATCHES_KEPT = ("listeners", "webroot")      # results.SEEN_CHECKS: the one list, checked by a test


def _watch_keeper(args, check):
    if getattr(args, "manifest", None) is not None:
        return lambda found: None
    from . import results

    def keep(found):
        try:
            results.add_seen(check, found)
        except OSError as exc:
            print(f"megalodon: what the watch saw was not kept for `megalodon report`: {exc}", file=sys.stderr)
    return keep


class _Said:
    """sys.stderr, also keeping the last `megalodon: ...` line: why a check could not run, for the report."""

    def __init__(self, stream):
        self._stream = stream
        self._line = ""
        self.reason = None

    def write(self, text):
        self._line += text
        *done, self._line = self._line.split("\n")
        for line in done:
            if line.startswith("megalodon: "):
                self.reason = line[len("megalodon: "):][:500]
        self._line = self._line[-2000:]
        return self._stream.write(text)

    def __getattr__(self, name):
        return getattr(self._stream, name)


def _run_and_keep(args) -> int:
    """Run the command. A check whose result is kept is kept however it ends: with what it found, with why it
    could not run, or with the error it stopped on, so the report never shows an older result as current."""
    if _kept(args) is None:
        code = _dispatch(args)
        if (code == 0 and args.command in WATCHES_KEPT and getattr(args, "manifest", None) is None
                and getattr(args, f"{args.command}_command", None) in ("accept", "baseline")):
            from . import results
            try:
                results.forget(args.command)
            except OSError as exc:
                print(f"megalodon: what the watch saw before is still in `megalodon report`: {exc}", file=sys.stderr)
        return code
    said = _Said(sys.stderr)
    sys.stderr = said
    try:
        code = _dispatch(args)
    except (Exception, KeyboardInterrupt) as exc:
        sys.stderr = said._stream
        _record(args, 2, reason=f"it stopped with an error: {type(exc).__name__}: {exc}"[:500])
        raise
    finally:
        sys.stderr = said._stream
    _record(args, code, reason=said.reason if code not in (0, 1) else None)
    return code


def _report(args: argparse.Namespace) -> int:
    from . import security_report as sr
    if not 1 <= args.hours <= 24 * 366:
        print("megalodon: --hours must be between 1 and 8784", file=sys.stderr)
        return 2
    try:
        report = sr.build(hours=args.hours, every=args.all)
        content = (sr.page(report) if args.format == "html" else
                   json.dumps(report, indent=2, sort_keys=True) + "\n" if args.format == "json" else sr.text(report))
        if args.output:
            sr.write(args.output, content)
            print(json.dumps(dict(report=str(args.output.expanduser()), verdict=report["verdict"],
                                  headline=report["headline"]), sort_keys=True))
        else:
            sys.stdout.write(content)
    except OSError as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    return 0


def _review(args: argparse.Namespace) -> int:
    from . import guided_review, security_report as sr
    if not sys.stdin.isatty():
        print("megalodon: review asks you what to do about each finding: run it in a terminal. "
              "`megalodon report` prints the same choices.", file=sys.stderr)
        return 2
    if not 1 <= args.hours <= 24 * 366:
        print("megalodon: --hours must be between 1 and 8784", file=sys.stderr)
        return 2
    try:
        guided_review.review(sr.build(hours=args.hours))
    except (EOFError, KeyboardInterrupt):
        print("\nmegalodon: review stopped; nothing more was run.", file=sys.stderr)
        return 0
    except OSError as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    return 0


def entry(argv: list[str] | None = None) -> None:
    """The `megalodon` command and `python -m megalodon`. Exit 1 means findings, 2 an error: the scheduler counts
    exit 1 as a successful run that found something (SuccessExitStatus=1), so an unexpected error, which Python
    would end with 1, exits 2. `main` still raises, for callers that run a command in-process."""
    try:
        main(argv)
    except Exception:
        import traceback
        traceback.print_exc()
        raise SystemExit(2) from None


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
    raise SystemExit(_run_and_keep(args))


def _dispatch(args: argparse.Namespace) -> int:
    """Run the chosen command; its exit code."""
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
    elif args.command == "web-review":
        code = _web_review(args)
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
    elif args.command == "webroot":
        code = _webroot(args)
    elif args.command == "schedule":
        code = _schedule(args)
    elif args.command == "tamper":
        code = _tamper(args)
    elif args.command == "egress":
        code = _egress(args)
    elif args.command == "credentials":
        code = _credentials(args)
    elif args.command == "logins":
        code = _logins(args)
    elif args.command == "boot":
        code = _boot(args)
    elif args.command == "ebpf":
        code = _ebpf(args)
    elif args.command == "containers":
        code = _containers(args)
    elif args.command == "hardening":
        code = _hardening(args)
    elif args.command == "packages":
        code = _packages(args)
    elif args.command == "secrets":
        code = _secrets(args)
    elif args.command == "report":
        code = _report(args)
    elif args.command == "review":
        code = _review(args)
    elif args.command == "timeline":
        code = _timeline(args)
    elif args.command == "commands":
        code = _commands(args)
    elif args.command == "memory":
        code = _memory(args)
    elif args.command == "fleet":
        code = _fleet(args)
    elif args.command == "enforce":
        code = _enforce(args)
    elif args.command == "vulns":
        code = _vulns(args)
    elif args.command == "heartbeat":
        code = _heartbeat(args)
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
    return code
