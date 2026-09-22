"""Background tool heartbeat: installed, running and uptime per companion tool.

The heartbeat is a metadata-only observation. It never executes a discovered
tool, opens a network connection, or returns paths, PIDs or command lines. It
combines three signals into one status light per tool:

* installed  - a known executable (PATH or fixed install prefix), Python
  package, or matching process was found; its change time is the install hint;
* running    - a known long-running process name was observed in ``/proc``;
* uptime     - the earliest start time among matching processes.

Lights: ``green`` installed and healthy (service running, or a standalone tool
present), ``amber`` installed but its expected service is not running, ``red``
not installed, ``grey`` could not be determined on this platform.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import glob
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
from threading import Lock
from time import monotonic, time
from typing import Any

from .capabilities import runtime_platform


SCHEMA = "megalodon-tool-heartbeat-v1"
MAX_HEARTBEAT_BYTES = 16 * 1024
MAX_PROCESS_ENTRIES = 32_768
MAX_COMM_BYTES = 128
MAX_STAT_BYTES = 4096
HEARTBEAT_CACHE_SECONDS = 5
LIGHTS = frozenset({"green", "amber", "red", "grey"})
_PID = re.compile(r"[1-9][0-9]{0,9}\Z")


@dataclass(frozen=True)
class ToolProbe:
    executables: tuple[str, ...] = ()
    fixed_paths: tuple[str, ...] = ()
    home_globs: tuple[str, ...] = ()
    python_module: str | None = None
    processes: frozenset[str] = frozenset()
    service: bool = False


# Keys match the HUD control ids. Fixed paths cover installs that are
# normally off PATH (for example OSSEC in /var/ossec or a private Zeek prefix).
PROBES: dict[str, ToolProbe] = {
    "core": ToolProbe(),
    "tshark": ToolProbe(("tshark",), ("/usr/bin/tshark",), processes=frozenset({"tshark"})),
    "zeek": ToolProbe(("zeek",), ("/opt/zeek/bin/zeek", "/usr/local/zeek/bin/zeek"),
                      (".local/zeek-*/bin/zeek",), processes=frozenset({"zeek"})),
    "suricata": ToolProbe(("suricata",), ("/usr/bin/suricata",), processes=frozenset({"suricata", "Suricata-Main"}),
                          service=True),
    "scapy": ToolProbe(python_module="scapy"),
    "nftables": ToolProbe(("nft",), ("/usr/sbin/nft", "/sbin/nft")),
    "clamav": ToolProbe(("clamscan",), processes=frozenset({"clamd", "freshclam"})),
    "osquery": ToolProbe(("osqueryi", "osqueryd"), ("/opt/osquery/bin/osqueryd",), processes=frozenset({"osqueryd"})),
    "qwen": ToolProbe(("ollama",), ("/usr/local/bin/ollama", "/usr/bin/ollama"), processes=frozenset({"ollama"}),
                      service=True),
    "nmap": ToolProbe(("nmap",)),
    "ossec": ToolProbe((), ("/var/ossec/bin/ossec-control", "/var/ossec/bin/wazuh-control"),
                       processes=frozenset({"ossec-analysisd", "ossec-monitord", "ossec-agentd", "wazuh-agentd"}),
                       service=True),
    "greenbone": ToolProbe(("gvmd",), (), ("greenbone-community-edition/compose.yaml",),
                           processes=frozenset({"gvmd", "openvas", "ospd-openvas", "gsad"}), service=True),
    "zabbix": ToolProbe(("zabbix_agent2", "zabbix_agentd", "zabbix_server"),
                        processes=frozenset({"zabbix_agent2", "zabbix_agentd", "zabbix_server"}), service=True),
    "nagios": ToolProbe(("nagios4", "nagios"), ("/usr/local/nagios/bin/nagios",),
                        processes=frozenset({"nagios4", "nagios"}), service=True),
}
TOOL_IDS = tuple(PROBES)


def _iso(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _path_directories() -> tuple[str, ...]:
    value = os.environ.get("PATH") or ""
    directories: list[str] = []
    for entry in value.split(":")[:64]:
        if entry.startswith("/") and ".." not in entry.split("/") and entry not in directories:
            directories.append(entry.rstrip("/") or "/")
    return tuple(directories)


def _executable_ctime(candidate: str) -> tuple[str, float | None]:
    """Return ("yes"|"no"|"unknown", ctime) for one path; never executes it."""
    try:
        metadata = os.stat(candidate)
    except (FileNotFoundError, NotADirectoryError):
        return "no", None
    except OSError:
        return "unknown", None
    if stat.S_ISREG(metadata.st_mode) and os.access(candidate, os.X_OK, effective_ids=True):
        return "yes", metadata.st_ctime
    return "no", None


def _installed(probe: ToolProbe, directories: tuple[str, ...], home: Path | None) -> tuple[str, float | None]:
    uncertain = False
    candidates = [os.path.join(d, name) for name in probe.executables for d in directories]
    candidates += list(probe.fixed_paths)
    if home is not None:
        for pattern in probe.home_globs:
            candidates += sorted(glob.glob(str(home / pattern)))[:8]
    for candidate in candidates:
        found, ctime = _executable_ctime(candidate)
        if found == "yes":
            return "yes", ctime
        if found == "unknown":
            uncertain = True
        elif candidate.endswith(".yaml"):
            try:
                return "yes", os.stat(candidate).st_ctime
            except OSError:
                pass
    if probe.python_module is not None:
        try:
            spec = importlib.util.find_spec(probe.python_module)
        except (ImportError, ValueError):
            spec = None
        if spec is None or spec.origin is None:
            return "no", None
        try:
            return "yes", os.stat(spec.origin).st_ctime
        except OSError:
            return "yes", None
    return ("unknown" if uncertain else "no"), None


def _boot_time(proc_root: Path) -> float | None:
    try:
        with (proc_root / "stat").open("rb") as source:
            for line in source.read(65_536).splitlines():
                if line.startswith(b"btime "):
                    return float(int(line.split()[1]))
    except (OSError, ValueError, IndexError):
        return None
    return None


def _process_starts(proc_root: Path, wanted: frozenset[str]) -> tuple[dict[str, float], bool]:
    """Map wanted process names to their earliest start time (epoch seconds)."""
    starts: dict[str, float] = {}
    boot = _boot_time(proc_root)
    ticks = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    complete = True
    try:
        entries = [entry for entry in proc_root.iterdir() if _PID.fullmatch(entry.name)]
    except OSError:
        return starts, False
    if len(entries) > MAX_PROCESS_ENTRIES:
        return starts, False
    for entry in entries:
        try:
            with (entry / "comm").open("rb") as source:
                name = source.read(MAX_COMM_BYTES).decode("utf-8", errors="strict").strip()
            if name not in wanted:
                continue
            with (entry / "stat").open("rb") as source:
                raw = source.read(MAX_STAT_BYTES).decode("ascii", errors="strict")
            # Field 22 (starttime) follows the parenthesized command name.
            fields = raw[raw.rindex(")") + 2:].split()
            started = boot + int(fields[19]) / ticks if boot is not None else None
        except (OSError, UnicodeError, ValueError, IndexError):
            complete = False
            continue
        if started is None:
            starts.setdefault(name, 0.0)
        elif name not in starts or starts[name] == 0.0 or started < starts[name]:
            starts[name] = started
    return starts, complete


def _light(installed: str, service: str, expects_service: bool) -> str:
    if installed == "no":
        return "red"
    if installed == "unknown":
        return "grey"
    if expects_service and service == "stopped":
        return "amber"
    return "green"


def heartbeat_report(proc_root: Path = Path("/proc"), *, now: float | None = None) -> dict[str, Any]:
    """Return one closed heartbeat receipt for all fixed tools."""
    platform = runtime_platform()
    checked = time() if now is None else now
    linux = platform == "linux"
    directories = _path_directories() if linux else ()
    home = Path.home() if linux else None
    wanted = frozenset().union(*(probe.processes for probe in PROBES.values()))
    starts, complete = _process_starts(proc_root, wanted) if linux else ({}, False)
    own_start = None
    if linux:
        try:
            with (proc_root / "self" / "stat").open("rb") as source:
                raw = source.read(MAX_STAT_BYTES).decode("ascii")
            boot = _boot_time(proc_root)
            if boot is not None:
                own_start = boot + int(raw[raw.rindex(")") + 2:].split()[19]) / os.sysconf("SC_CLK_TCK")
        except (OSError, UnicodeError, ValueError, IndexError):
            own_start = None
    tools = []
    for tool_id, probe in PROBES.items():
        if tool_id == "core":
            try:
                installed_since = os.stat(Path(__file__).resolve().parent / "__init__.py").st_ctime
            except OSError:
                installed_since = None
            entry = {"installed": "yes", "installed_since": _iso(installed_since),
                     "service": "running", "running_since": _iso(own_start)}
        elif not linux and probe.python_module is None:
            entry = {"installed": "unknown", "installed_since": None, "service": "unknown", "running_since": None}
        else:
            installed, since = _installed(probe, directories, home) if linux else _installed(probe, (), None)
            observed = [starts[name] for name in probe.processes if name in starts]
            if observed:
                service = "running"
                if installed != "yes":
                    installed = "yes"
                earliest = min(observed)
                running_since = _iso(earliest) if earliest > 0 else None
            elif not probe.processes:
                service, running_since = "standalone", None
            else:
                service = "stopped" if complete else "unknown"
                running_since = None
            if installed == "no" and service != "running":
                service = "none"
            entry = {"installed": installed, "installed_since": _iso(since),
                     "service": service, "running_since": running_since}
        entry["light"] = _light(entry["installed"], entry["service"], probe.service)
        entry["expects_service"] = probe.service
        tools.append({"id": tool_id, **entry})
    return {
        "schema": SCHEMA,
        "checked_at": _iso(checked),
        "platform": platform,
        "tools": tools,
    }


class HeartbeatBusy(Exception):
    """Another heartbeat collection is in progress."""


class Heartbeat:
    """Server-owned collector with a short cache so polling stays cheap."""

    def __init__(self, proc_root: Path = Path("/proc")) -> None:
        self._proc_root = proc_root
        self._lock = Lock()
        self._cached: bytes | None = None
        self._expires = 0.0

    def invalidate(self) -> None:
        self._expires = 0.0

    def snapshot(self) -> bytes:
        if not self._lock.acquire(blocking=False):
            if self._cached is not None:
                return self._cached
            raise HeartbeatBusy
        try:
            if self._cached is not None and monotonic() < self._expires:
                return self._cached
            payload = json.dumps(heartbeat_report(self._proc_root), sort_keys=True,
                                 separators=(",", ":"), allow_nan=False).encode()
            if len(payload) > MAX_HEARTBEAT_BYTES:
                raise ValueError("heartbeat response exceeds limit")
            self._cached = payload
            self._expires = monotonic() + HEARTBEAT_CACHE_SECONDS
            return payload
        finally:
            self._lock.release()
