"""Offline HawkScan preparation; no installer, scanner, credential or result intake."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import re
import sys

from .capabilities import runtime_platform
from .readiness import _executable_status, _path_directories


SCHEMA = "megalodon-hawkscan-setup-v1"
RESEARCHED_VERSION = "6.5.0"
MAX_OUTPUT_BYTES = 4096
APPLICATION_ID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
GUIDE = "https://github.com/bartytime4life/MEGALODON/blob/main/docs/hawkscan-setup.md"


def setup_plan() -> dict:
    """Static preparation status, never a scanner authorization or host receipt."""
    return {
        "schema": SCHEMA,
        "mode": "offline_setup_only",
        "software": "StackHawk HawkScan",
        "software_class": "commercial_service",
        "researched_version": RESEARCHED_VERSION,
        "supported_setup_platform": "linux",
        "scan_status": "held",
        "action_status": "not_attempted",
        "installation_performed": False,
        "execution_performed": False,
        "network_access_performed": False,
        "host_change_performed": False,
        "guide": GUIDE,
        "next_gates": [
            "Review the publisher's exact Linux artifact and SHA-256 before manual installation.",
            "Select an owned disposable application with synthetic data, no host controls and no real telemetry.",
            "Approve StackHawk cloud data sharing, credentials, account and scan scope separately.",
            "Review the generated configuration and authorize one manual scan; preparation does not authorize it.",
        ],
        "limitations": [
            "DAST tests a running web application; it is not a malware or passive network scanner.",
            "HawkScan can change application data and send findings/request-response evidence to StackHawk.",
            "No scan runner, scheduler, CI scan, result import, AI tool or firewall action is implemented here.",
            "The root-only configuration is a wiring profile, not API, authenticated or whole-HUD coverage.",
        ],
    }


def presence_report() -> dict:
    """Inspect metadata for fixed name hawk using bounded PATH rules; never run it."""
    report = setup_plan()
    platform = runtime_platform()
    directories = _path_directories(os.environ.get("PATH")) if platform == "linux" else None
    report.update({
        "mode": "path_presence_only",
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platform": platform,
        "presence": _executable_status("hawk", directories) if directories is not None else "not_checked",
        "presence_limitation": "Presence does not verify version, integrity, configuration, account, target or scan readiness.",
    })
    return report


def render_config(application_id: str, port: int) -> str:
    """Print a fixed loopback wiring profile; accept no URL, script or credential."""
    if (not isinstance(application_id, str) or len(application_id) != 36
            or not APPLICATION_ID.fullmatch(application_id)
            or application_id.replace("-", "") == "0" * 32):
        raise ValueError("APPLICATION_ID")
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("PORT")
    # JSON string scalars are valid YAML; only a canonical UUID and integer vary.
    return f'''# MEGALODON preparation only. Scan authorization remains HELD.
# Owned disposable lab only; do not point at the working PC HUD or hosted Site.
# Root-only wiring profile. Exclusions/redaction are not containment or no-egress.
app:
  applicationId: {json.dumps(application_id.lower())}
  env: "MEGALODON-Disposable-Lab"
  host: "http://127.0.0.1:{port}"
  includePaths:
    - "^/$"
  excludePaths:
    - "^/api(?:/|$).*"
  waitForAppTarget:
    path: "/"
    requestMethod: "GET"
    waitTimeoutMillis: 30000
    pollDelay: 1000
  redact:
    headers:
      - "Authorization"
      - "Cookie"
      - "Set-Cookie"
      - "X-Megalodon-Install-Token"
      - "X-Megalodon-AI-Token"
      - "X-Megalodon-Intelligence-Token"
      - "X-Megalodon-Config-Token"
      - "X-Megalodon-Defense-Token"
      - "X-Megalodon-Network-Token"
      - "X-Megalodon-Reports-Token"
      - "X-Megalodon-Storage-Token"
      - "X-Megalodon-Support-Token"
hawk:
  startupTimeoutMinutes: 1
  failureThreshold: "low"
  spider:
    base: true
    ajax: false
    maxDurationMinutes: 1
  scan:
    maxDurationMinutes: 5
    maxRuleDurationMinutes: 1
    concurrentRequests: 1
    requestDelayMillis: 250
'''


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # Reject unsupported inputs without echoing a mistakenly supplied secret.
        self.exit(2, "HAWKSCAN_SETUP:INVALID_ARGUMENTS; use --help. No scanner action was attempted.\n")


def main(argv=None) -> int:
    parser = _Parser(description="Prepare HawkScan offline. No install, scan, authentication or cloud upload.")
    commands = parser.add_subparsers(dest="command", parser_class=_Parser)
    commands.add_parser("plan", help="Print static setup steps; default")
    commands.add_parser("check", help="Check fixed hawk executable metadata only; does not run hawk")
    config = commands.add_parser("config", help="Print root-only loopback lab YAML to stdout; writes no file")
    config.add_argument("--application-id", required=True, help="StackHawk application UUID; never an API key")
    config.add_argument("--port", type=int, default=18080, help="Disposable lab port, 1024–65535; default 18080")
    args = parser.parse_args(argv)
    try:
        if args.command == "config":
            output = render_config(args.application_id, args.port)
        else:
            report = presence_report() if args.command == "check" else setup_plan()
            output = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
        if len(output.encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise ValueError("OUTPUT_LIMIT")
    except ValueError:
        print("HAWKSCAN_SETUP:INVALID_INPUT; no scanner action was attempted.", file=sys.stderr)
        return 2
    print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
