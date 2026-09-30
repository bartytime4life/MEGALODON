"""Bounded Linux PC counters for the local HUD, without accounts or subprocesses.

Only this process's network namespace is observed. Network counters and socket
counts are separate from qualified packet evidence. No DNS, capture, command
execution, disk persistence, or process command lines leave this module.
"""
from __future__ import annotations

from collections import Counter, deque
from copy import deepcopy
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import socket
import struct
from threading import Event, Lock, Thread
from time import monotonic

SCHEMA = "megalodon-host-telemetry-v1"
INTERVAL = 2
MAX_HISTORY = 300
MAX_INTERFACES = 32
MAX_PROCESSES = 32768
APPS = {
    "core": ("MEGALODON", frozenset()),
    "tshark": ("Wireshark / TShark", frozenset({"wireshark", "tshark", "dumpcap"})),
    "zeek": ("Zeek", frozenset({"zeek"})),
    "suricata": ("Suricata", frozenset({"suricata", "Suricata-Main"})),
    "clamav": ("ClamAV", frozenset({"clamscan", "clamd", "freshclam"})),
    "osquery": ("osquery", frozenset({"osqueryi", "osqueryd"})),
    "qwen": ("Ollama / Qwen", frozenset({"ollama", "ollama_llama_se", "ollama runner"})),
    "nmap": ("Nmap", frozenset({"nmap", "zenmap"})),
    "nftables": ("nftables", frozenset({"nft"})),
}
NOTES = [
    "CPU is a percentage of total PC capacity. Memory is summed resident memory; shared pages may be counted more than once.",
    "Companion totals cover recognized local processes, including work started outside MEGALODON. Embedded Python/SQLite/Scapy work is included in MEGALODON; browsers and their other tabs are excluded.",
    "Network rates are per interface; VPNs and bridges may count the same traffic. Receive/send does not establish Internet direction or application ownership.",
    "TCP/UDP values count sockets, not packets or application protocols. Remote peers count sockets and exclude listeners.",
    "CPU and network activity are concurrent observations, not proof that traffic caused resource use. GPU memory and utilization are not measured.",
    "History covers this HUD session only, up to ten minutes. Restricted processes and short-lived jobs may be missed.",
]


def _read(path: Path, limit: int = 65536) -> str:
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError("counter limit")
    return value.decode("utf-8", errors="strict")


def _delta(value: int, previous: int | None, elapsed: float) -> float | None:
    if previous is None or value < previous or not 0 < elapsed <= INTERVAL * 5:
        return None
    return round((value - previous) / elapsed, 3)


def _sum_known(values):
    values = list(values)
    return round(sum(values), 3) if all(value is not None for value in values) else None


def _address(value: str) -> str:
    if len(value) == 8:
        return socket.inet_ntop(socket.AF_INET, struct.pack("=I", int(value, 16)))
    if len(value) == 32:
        return socket.inet_ntop(socket.AF_INET6, b"".join(struct.pack("=I", int(value[i:i+8], 16)) for i in range(0, 32, 8)))
    raise ValueError("socket address")


def _sockets(root: Path) -> dict:
    counts = {"tcp": 0, "udp": 0, "established": 0, "listening": 0, "time_wait": 0}
    peers: Counter = Counter()
    complete = True
    for filename in ("tcp", "tcp6", "udp", "udp6"):
        try:
            lines = _read(root / "net" / filename, 2 * 1024 * 1024).splitlines()[1:]
            if len(lines) > 10000:
                raise ValueError("socket count limit")
            for line in lines:
                fields = line.split()
                state = fields[3]
                remote, port = fields[2].split(":")
                counts[filename[:3]] += 1
                if filename.startswith("tcp"):
                    for name, code in (("established", "01"), ("listening", "0A"), ("time_wait", "06")):
                        counts[name] += state == code
                if int(port, 16) and int(remote, 16):
                    peers[_address(remote)] += 1
        except (OSError, ValueError, IndexError, UnicodeError):
            complete = False
    # Partial socket tables must not silently become zero measured totals.
    return {"status": "ready" if complete else "unavailable",
            **(counts if complete else dict.fromkeys(counts)),
            "remote_peers": [{"address": address, "connections": count} for address, count in peers.most_common(10)] if complete else []}


class HostTelemetry:
    def __init__(self, proc_root: Path = Path("/proc"), *, own_pid: int | None = None):
        self.root = proc_root
        self.own_pid = os.getpid() if own_pid is None else own_pid
        self._lock = Lock()
        self._stop = Event()
        self._thread: Thread | None = None
        self._history: deque = deque(maxlen=MAX_HISTORY)
        self._previous: dict = {}
        self._payload = self._empty()

    @staticmethod
    def _empty() -> dict:
        return {"schema": SCHEMA, "status": "unavailable", "observed_at": None,
                "interval_seconds": INTERVAL, "history_seconds": INTERVAL * MAX_HISTORY,
                "system": {}, "suite": {}, "apps": [], "network": {"status": "unavailable", "interfaces": []},
                "sockets": {"status": "unavailable", "remote_peers": []}, "history": [],
                "coverage": {"processes": "partial"}, "notes": NOTES}

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = Thread(target=self._run, name="megalodon-pc-counters", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.sample()
            except (OSError, ValueError, IndexError, KeyError, UnicodeError, OverflowError):
                with self._lock:
                    self._payload = self._empty()
                self._previous = {}
            self._stop.wait(INTERVAL)

    def snapshot(self) -> dict:
        with self._lock:
            return deepcopy(self._payload)

    def _processes(self) -> tuple[dict, bool]:
        result = {}
        complete = True
        page_size = os.sysconf("SC_PAGE_SIZE")
        with os.scandir(self.root) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_PROCESSES:
                    complete = False
                    break
                if not entry.name.isdigit():
                    continue
                folder = self.root / entry.name
                try:
                    raw = _read(folder / "stat", 4096)
                    name = raw[raw.index("(") + 1:raw.rindex(")")]
                    fields = raw[raw.rindex(")") + 2:].split()
                    pid = int(entry.name)
                    app = next((key for key, (_, names) in APPS.items() if name in names), None)
                    if pid == self.own_pid:
                        app = "core"
                    elif name.startswith("python") or name.startswith("megalodon"):
                        args = _read(folder / "cmdline", 8192).split("\0")
                        if any(args[i:i+2] == ["-m", "megalodon"] or
                               (args[i] == "-m" and args[i+1].startswith("megalodon."))
                               for i in range(len(args)-1)) or (args and Path(args[0]).name in {"megalodon", "megalodon-hud"}):
                            app = "core"
                    io = None
                    if app:
                        try:
                            counters = dict(line.split(":", 1) for line in _read(folder / "io", 4096).splitlines())
                            io = (int(counters["read_bytes"]), int(counters["write_bytes"]))
                        except (OSError, ValueError, KeyError):
                            pass
                    result[pid] = {"app": app, "name": name, "parent": int(fields[1]), "start": int(fields[19]),
                                   "ticks": int(fields[11]) + int(fields[12]), "rss": max(0, int(fields[21])) * page_size, "io": io}
                except FileNotFoundError:
                    continue  # A process can exit between directory and counter reads.
                except (OSError, ValueError, IndexError, UnicodeError):
                    complete = False
        # Include Python worker descendants, never a browser the HUD opened:
        # browsers may contain unrelated tabs and would greatly inflate totals.
        # Named companions retain their own bucket. Chains never leave this module.
        for pid, item in result.items():
            if item["app"] is not None or not item["name"].startswith("python"):
                continue
            parent = item["parent"]
            seen = {pid}
            while parent in result and parent not in seen and len(seen) < 32:
                if result[parent]["name"] in {"chrome", "chromium", "firefox", "msedge", "brave"}:
                    break
                if result[parent]["app"] == "core":
                    item["app"] = "core"
                    break
                seen.add(parent)
                parent = result[parent]["parent"]
        return result, complete

    def sample(self, now: float | None = None) -> dict:
        now = monotonic() if now is None else now
        previous = self._previous
        elapsed = now - previous.get("now", now)
        observed_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        fields = _read(self.root / "stat").splitlines()[0].split()
        if fields[0] != "cpu" or len(fields) < 5:
            raise ValueError("CPU counters unavailable")
        cpu = [int(value) for value in fields[1:9]]  # guest ticks are already included
        total = sum(cpu)
        idle = cpu[3] + (cpu[4] if len(cpu) > 4 else 0)
        cpu_delta = total - previous.get("total", total)
        idle_delta = idle - previous.get("idle", idle)
        valid_interval = 0 < elapsed <= INTERVAL * 5 and cpu_delta > 0 and 0 <= idle_delta <= cpu_delta
        system_cpu = round(100 * (1 - idle_delta / cpu_delta), 3) if valid_interval else None
        memory = dict(line.split(":", 1) for line in _read(self.root / "meminfo").splitlines())
        memory_total = int(memory["MemTotal"].split()[0]) * 1024
        available = int(memory["MemAvailable"].split()[0]) * 1024
        if not 0 <= available <= memory_total or memory_total <= 0:
            raise ValueError("memory counters unavailable")
        processes, complete = self._processes()
        apps = []
        for key, (name, _) in APPS.items():
            matches = [(pid, item) for pid, item in processes.items() if item["app"] == key]
            cpu_values, reads, writes = [], [], []
            for pid, item in matches:
                old = previous.get("processes", {}).get(pid, {})
                same_process = old.get("start") == item["start"] and old.get("app") == item["app"]
                ticks = item["ticks"] - old.get("ticks", item["ticks"])
                cpu_values.append(round(100 * ticks / cpu_delta, 3) if same_process and valid_interval and 0 <= ticks <= cpu_delta else None)
                for values, offset in ((reads, 0), (writes, 1)):
                    old_io = old.get("io")
                    values.append(_delta(item["io"][offset], old_io[offset], elapsed) if item["io"] and old_io and same_process else None)
            apps.append({"id": key, "name": name, "process_count": len(matches),
                         "cpu_percent": _sum_known(cpu_values) if valid_interval else None,
                         "rss_bytes": sum(item["rss"] for _, item in matches),
                         "read_bps": _sum_known(reads) if valid_interval else None,
                         "write_bps": _sum_known(writes) if valid_interval else None,
                         "io_status": "ready" if valid_interval and all(value is not None for value in reads + writes) else "unavailable"})
        interfaces, network_raw = [], {}
        network_status = "ready"
        try:
            lines = _read(self.root / "net" / "dev").splitlines()[2:]
            for line in lines:
                name, values = line.rsplit(":", 1)
                name = name.strip()
                if not re.fullmatch(r"[\w.:-]{1,64}", name, re.ASCII):
                    continue
                counters = [int(value) for value in values.split()]
                if len(counters) != 16 or any(value < 0 for value in counters):
                    raise ValueError("interface counters")
                if len(interfaces) >= MAX_INTERFACES:
                    network_status = "partial"
                    break
                old = previous.get("network", {}).get(name)
                row = {"name": name}
                for key, index in (("rx_bps", 0), ("tx_bps", 8), ("rx_pps", 1), ("tx_pps", 9)):
                    row[key] = _delta(counters[index], old[index] if old else None, elapsed)
                for key, index in (("rx_errors", 2), ("tx_errors", 10), ("rx_drops", 3), ("tx_drops", 11)):
                    value = _delta(counters[index], old[index] if old else None, elapsed)
                    row[key] = round(value * elapsed) if value is not None else None
                interfaces.append(row)
                network_raw[name] = counters
        except (OSError, ValueError, IndexError, UnicodeError):
            network_status, interfaces, network_raw = "unavailable", [], {}
        rss = sum(app["rss_bytes"] for app in apps)
        suite_cpu = _sum_known(app["cpu_percent"] for app in apps)
        point = {"observed_at": observed_at, "system_cpu_percent": system_cpu,
                 "suite_cpu_percent": suite_cpu, "suite_rss_bytes": rss,
                 "interfaces": [{key: row[key] for key in ("name", "rx_bps", "tx_bps")} for row in interfaces]}
        self._history.append(point)
        self._previous = {"now": now, "total": total, "idle": idle, "processes": processes, "network": network_raw}
        sockets = _sockets(self.root)
        payload = {**self._empty(), "status": "warming" if system_cpu is None else ("ready" if complete and network_status == "ready" and sockets["status"] == "ready" else "partial"),
                   "observed_at": observed_at,
                   "system": {"cpu_percent": system_cpu, "memory_total_bytes": memory_total,
                              "memory_used_bytes": memory_total - available, "memory_percent": round(100 * (memory_total - available) / memory_total, 3)},
                   "suite": {"cpu_percent": suite_cpu, "rss_bytes": rss, "memory_percent": round(100 * rss / memory_total, 3), "process_count": sum(app["process_count"] for app in apps)},
                   "apps": apps, "network": {"status": network_status, "interfaces": interfaces},
                   "sockets": sockets, "history": list(self._history),
                   "coverage": {"processes": "complete" if complete else "partial", "network": network_status, "gpu": "unavailable", "attribution": "recognized process names and MEGALODON Python workers; browsers excluded"}}
        with self._lock:
            self._payload = payload
        return deepcopy(payload)
