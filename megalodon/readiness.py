"""Bounded, explicit Linux executable discovery; never executes a found tool."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import stat
from typing import Any

from .capabilities import runtime_platform


SCHEMA = "megalodon-tool-readiness-v2"
PROBE_MODE = "path_presence_only"
MAX_REPORT_BYTES = 8192
MAX_PATH_BYTES = 16_384
MAX_PATH_ENTRIES = 64
MAX_DIRECTORY_BYTES = 4096
STATUSES = frozenset({"executable_found", "not_found", "not_checked"})

# One fixed representative executable per tool. These are not complete product
# installation checks: for example, ollama says nothing about a Qwen artifact.
TOOL_EXECUTABLES = (
    ("python-sqlite", None),
    ("wireshark-tshark", "tshark"),
    ("zeek", "zeek"),
    ("suricata", "suricata"),
    ("scapy", None),
    ("nftables", "nft"),
    ("clamav", "clamscan"),
    ("osquery", "osqueryi"),
    ("qwen-ollama", "ollama"),
    ("nmap", "nmap"),
)
TOOL_IDS = tuple(tool_id for tool_id, _ in TOOL_EXECUTABLES)
BOUNDARIES = (
    "Executable presence only; installation, version, compatibility, trust and running state are not verified.",
    "Python/SQLite and Scapy availability are not checked by this executable-only report.",
    "No programs executed; no network, model, firewall, configuration changes or database operations performed.",
    "Paths, hostnames, usernames and version strings are omitted; this self-report is not authenticated.",
    "Only Linux PATH entries are probed; invalid or excessive PATH input yields not_checked.",
)


def _path_directories(value: str | None) -> tuple[str, ...] | None:
    """Validate the complete PATH before any probe; never fall back to cwd."""
    if not isinstance(value, str) or not value or len(value) > MAX_PATH_BYTES:
        return None
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if len(encoded) > MAX_PATH_BYTES or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    entries = value.split(":")
    if len(entries) > MAX_PATH_ENTRIES:
        return None
    directories: list[str] = []
    for entry in entries:
        if (
            not entry.startswith("/")
            or entry.startswith("//")
            or len(entry.encode("utf-8")) > MAX_DIRECTORY_BYTES
            or any(part in {".", ".."} for part in entry.split("/"))
        ):
            return None
        normalized = entry.rstrip("/") or "/"
        if normalized not in directories:
            directories.append(normalized)
    return tuple(directories)


def _executable_status(executable: str, directories: tuple[str, ...]) -> str:
    """Inspect metadata only; errors cannot become evidence of absence."""
    incomplete = False
    for directory in directories:
        candidate = os.path.join(directory, executable)
        try:
            metadata = os.stat(candidate)
            if stat.S_ISREG(metadata.st_mode) and os.access(candidate, os.X_OK, effective_ids=True):
                return "executable_found"
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError:
            incomplete = True
    return "not_checked" if incomplete else "not_found"


def readiness_report() -> dict[str, Any]:
    """Return an unauthenticated local presence receipt without external effects.

    Finite input and metadata-operation counts do not impose an OS/filesystem
    latency deadline. PATH entries may resolve through mounts or symlinks; no
    discovered location is executed, opened for content or included in output.
    """
    platform = runtime_platform()
    directories = _path_directories(os.environ.get("PATH")) if platform == "linux" else None
    tools = [
        {
            "id": tool_id,
            "status": (
                _executable_status(executable, directories)
                if directories is not None and executable is not None
                else "not_checked"
            ),
        }
        for tool_id, executable in TOOL_EXECUTABLES
    ]
    return {
        "schema": SCHEMA,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platform": platform,
        "probe_mode": PROBE_MODE,
        "tools": tools,
        "boundaries": list(BOUNDARIES),
    }


def readiness_json() -> str:
    """Serialize only the closed receipt, bounded including its stdout newline."""
    result = json.dumps(readiness_report(), separators=(",", ":"), sort_keys=True)
    if len(result.encode("utf-8")) + 1 > MAX_REPORT_BYTES:
        raise ValueError("tool readiness report exceeds its fixed output limit")
    return result


def local_readiness_report():
    """HUD presence uses the same fixed-prefix registry as its heartbeat.

    The exported v2 CLI contract stays PATH-only. No discovered executable is
    run, and the environment/package and process checks keep separate meanings.
    """
    from pathlib import Path
    from .tool_heartbeat import PROBES, _installed
    from .tool_locations import load_directories
    result = readiness_report()
    result['schema'] = 'megalodon-tool-readiness-v3'
    result['probe_mode'] = 'known_install_presence'
    result['boundaries'][-1] = 'Linux PATH, bounded known prefixes and owner-selected directories are checked; presence does not establish accepted telemetry.'
    directories = _path_directories(os.environ.get('PATH'))
    try:
        configured = load_directories(Path.home()) if result['platform'] == 'linux' else {}
    except ValueError:
        configured = {}
    names = {'wireshark-tshark':'tshark', 'qwen-ollama':'qwen'}
    if result['platform'] == 'linux':
        for row in result['tools']:
            if row['id'] in {'python-sqlite', 'scapy'}:
                continue
            tool_id = names.get(row['id'], row['id'])
            presence, _ = _installed(PROBES[tool_id], directories or (), Path.home(), configured.get(tool_id))
            row['status'] = {'yes':'executable_found','no':'not_found','unknown':'not_checked'}[presence]
    return result
