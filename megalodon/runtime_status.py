"""Bounded point-in-time observation of known local service process names."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any

from .capabilities import runtime_platform
from .readiness import TOOL_IDS


SCHEMA = "megalodon-tool-runtime-v1"
PROBE_MODE = "process_name_presence_only"
MAX_PROCESS_ENTRIES = 4096
MAX_COMM_BYTES = 128
STATUSES = frozenset({"running", "not_running", "not_applicable", "not_checked"})
_PID = re.compile(r"[1-9][0-9]{0,9}\Z")

# Linux ``comm`` values are intentionally matched against a fixed allowlist.
# Standalone tools are marked not_applicable because a missing process is not
# meaningful evidence about their installation or readiness.
_PROCESS_NAMES: dict[str, frozenset[str] | None] = {
    "python-sqlite": frozenset(),  # The serving MEGALODON process is running.
    "wireshark-tshark": frozenset({"tshark"}),
    "zeek": frozenset({"zeek"}),
    "suricata": frozenset({"suricata"}),
    "scapy": None,
    "nftables": None,
    "clamav": frozenset({"clamd", "freshclam"}),
    "osquery": frozenset({"osqueryd"}),
    "qwen-ollama": frozenset({"ollama"}),
    "nmap": None,
    "ossec": frozenset({"ossec-analysisd", "ossec-monitord", "wazuh-agentd"}),
    "greenbone": frozenset({"gvmd", "openvas", "ospd-openvas"}),
    "zabbix": frozenset({"zabbix_agentd", "zabbix_agent2", "zabbix_server"}),
    "nagios-core": frozenset({"nagios", "nagios4"}),
}

BOUNDARIES = (
    "One point-in-time process-name observation; service health, configuration and coverage are not verified.",
    "No programs executed; no process identifiers, command lines, paths, usernames or hostnames are returned.",
    "Standalone tools report not_applicable because process absence is not a meaningful runtime signal.",
    "Unreadable or excessive process metadata yields not_checked rather than a false stopped claim.",
)


def runtime_report(proc_root: Path = Path("/proc")) -> dict[str, Any]:
    """Return a closed, path-free runtime receipt for known long-running tools."""

    platform = runtime_platform()
    observed: set[str] = set()
    complete = platform == "linux"
    if complete:
        try:
            entries = []
            for entry in proc_root.iterdir():
                if _PID.fullmatch(entry.name):
                    entries.append(entry)
                    if len(entries) > MAX_PROCESS_ENTRIES:
                        complete = False
                        entries = []
                        break
            for entry in entries:
                try:
                    with (entry / "comm").open("rb") as source:
                        raw = source.read(MAX_COMM_BYTES + 1)
                    if not 1 <= len(raw) <= MAX_COMM_BYTES or b"\x00" in raw:
                        complete = False
                        continue
                    name = raw.decode("utf-8", errors="strict").strip()
                    if name:
                        observed.add(name)
                except (OSError, UnicodeError):
                    # Processes commonly exit during enumeration. Do not convert
                    # an incomplete snapshot into a false not-running result.
                    complete = False
        except OSError:
            complete = False

    tools = []
    for tool_id in TOOL_IDS:
        names = _PROCESS_NAMES[tool_id]
        if tool_id == "python-sqlite":
            status = "running"
        elif names is None:
            status = "not_applicable"
        elif not complete:
            status = "not_checked"
        else:
            status = "running" if observed.intersection(names) else "not_running"
        tools.append({"id": tool_id, "status": status})

    return {
        "schema": SCHEMA,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platform": platform,
        "probe_mode": PROBE_MODE,
        "tools": tools,
        "boundaries": list(BOUNDARIES),
    }
