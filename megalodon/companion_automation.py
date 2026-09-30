"""Local collection and report watching for aggregate HUD companions.

The model sees counts only. It never selects commands, targets or files.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_network
import json
import os
from pathlib import Path
import selectors
import shutil
import stat
import subprocess
from threading import Event, Lock, Thread
import time
import tomllib

from .clamav_summary import MAX_BYTES as CLAMAV_MAX, summarize_report as clamav_summary
from .config import AISettings
from .nmap_inventory import MAX_BYTES as NMAP_MAX, summarize_report as nmap_summary
from .osquery_inventory import MAX_BYTES as OSQUERY_MAX, summarize as osquery_summary

_KINDS = ("nmap", "clamav", "osquery")
_LIMITS = {"nmap": NMAP_MAX, "clamav": CLAMAV_MAX, "osquery": OSQUERY_MAX}
_ALLOWED_NETWORKS = tuple(ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
))


@dataclass(frozen=True)
class CompanionConfig:
    interval_seconds: int
    nmap_target: str | None
    clamav_paths: tuple[Path, ...]
    osquery_enabled: bool
    watch_nmap_xml: Path | None
    watch_clamscan_text: Path | None
    watch_clamscan_exit: Path | None
    watch_osquery_json: Path | None
    qwen_advisory: bool
    clamav_interval_seconds: int | None = None


def local_default_config(home: Path | None = None) -> CompanionConfig:
    """Bounded, host-only HUD defaults; an explicit file can widen the scope."""
    root = home if home is not None else Path.home()
    reports = root / ".local" / "share" / "megalodon" / "companion-reports"
    downloads = root / "Downloads"
    folders = (downloads,) if downloads.is_dir() and not downloads.is_symlink() else ()
    return CompanionConfig(
        3600, "127.0.0.1/32", folders, True,
        reports / "nmap.xml", reports / "clamscan.txt", reports / "clamscan.exit",
        reports / "osquery.json", True, 86400,
    )


def _absolute_file(value: object) -> Path | None:
    if value is None or value == "":
        return None
    if type(value) is not str or len(value) > 1024:
        raise ValueError("companion path must be a bounded absolute path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("companion path must be absolute without traversal")
    return path


def load_config(path: Path) -> CompanionConfig:
    """Read one explicit TOML override for local collection and watching."""
    path = _absolute_file(str(path))
    assert path is not None
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
        raise ValueError("companion configuration must be an existing small regular file")
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    if type(data) is not dict or set(data) - {"collection", "watch", "qwen"}:
        raise ValueError("unsupported companion configuration")
    collection, watch, qwen = (data.get(key, {}) for key in ("collection", "watch", "qwen"))
    if any(type(item) is not dict for item in (collection, watch, qwen)):
        raise ValueError("invalid companion configuration section")
    if (set(collection) - {"interval_seconds", "clamav_interval_seconds", "nmap_target", "clamav_paths", "osquery_enabled"}
            or set(watch) - {"nmap_xml", "clamscan_text", "clamscan_exit", "osquery_json"}
            or set(qwen) - {"advisory"}):
        raise ValueError("unsupported companion configuration key")
    interval = collection.get("interval_seconds", 3600)
    if type(interval) is not int or not 300 <= interval <= 86400:
        raise ValueError("collection interval must be 300 to 86400 seconds")
    clamav_interval = collection.get("clamav_interval_seconds")
    if clamav_interval is not None and (type(clamav_interval) is not int or not 300 <= clamav_interval <= 86400):
        raise ValueError("ClamAV interval must be 300 to 86400 seconds")
    target = collection.get("nmap_target")
    if target is not None:
        if type(target) is not str or len(target) > 64:
            raise ValueError("Nmap target must be one explicit private IPv4 host or CIDR")
        try:
            network = ip_network(target, strict=True)
        except ValueError:
            raise ValueError("Nmap target must be one explicit private IPv4 host or CIDR") from None
        if (network.version != 4 or network.num_addresses > 256
                or not any(network.subnet_of(allowed) for allowed in _ALLOWED_NETWORKS)):
            raise ValueError("Nmap target must be one private IPv4 host or range of at most 256 addresses")
        target = str(network)
    paths = collection.get("clamav_paths", [])
    if type(paths) is not list or len(paths) > 4 or any(type(item) is not str for item in paths):
        raise ValueError("ClamAV paths must be at most four explicit directories")
    folders = tuple(_absolute_file(item) for item in paths)
    if any(folder is None or folder == Path("/") or folder.is_symlink() or not folder.is_dir() for folder in folders):
        raise ValueError("ClamAV paths must name existing non-root directories")
    osquery = collection.get("osquery_enabled", False)
    advisory = qwen.get("advisory", False)
    if type(osquery) is not bool or type(advisory) is not bool:
        raise ValueError("companion options must be booleans")
    clamscan_text = _absolute_file(watch.get("clamscan_text"))
    clamscan_exit = _absolute_file(watch.get("clamscan_exit"))
    if (clamscan_text is None) != (clamscan_exit is None):
        raise ValueError("watched clamscan report and exit status must be configured together")
    return CompanionConfig(
        interval, target, folders, osquery,
        _absolute_file(watch.get("nmap_xml")), clamscan_text, clamscan_exit,
        _absolute_file(watch.get("osquery_json")), advisory, clamav_interval,
    )


def _read_bounded(path: Path, limit: int) -> bytes:
    """Reject symlinks and changing files; retain no raw report after projection."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError("report unavailable or outside size limit")
        raw = os.read(fd, limit + 1)
        after = os.fstat(fd)
        if (len(raw) != before.st_size or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ino != after.st_ino):
            raise ValueError("report changed while being read")
        return raw
    finally:
        os.close(fd)


def _run_fixed(argv: list[str], limit: int, timeout: int,
               cancel: Event | None = None) -> tuple[bytes, int]:
    """Run a fixed argv without shell interpretation or unbounded output."""
    binary = shutil.which(argv[0])
    if binary is None:
        raise ValueError("companion tool unavailable")
    deadline = time.monotonic() + timeout
    process = subprocess.Popen([binary, *argv[1:]], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = bytearray()
    error_count = 0
    try:
        with selectors.DefaultSelector() as selector:
            assert process.stdout is not None and process.stderr is not None
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                if cancel is not None and cancel.is_set():
                    raise ValueError("companion job stopped")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("companion tool timed out")
                for key, _ in selector.select(min(remaining, 1)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif key.data == "stdout":
                        output.extend(chunk)
                        if len(output) > limit:
                            raise ValueError("companion output exceeded limit")
                    else:
                        error_count += len(chunk)
                        if error_count > 4096:
                            raise ValueError("companion error output exceeded limit")
        while process.poll() is None:
            if cancel is not None and cancel.is_set():
                raise ValueError("companion job stopped")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("companion tool timed out")
            try:
                process.wait(timeout=min(remaining, 1))
            except subprocess.TimeoutExpired:
                continue
        return bytes(output), process.returncode
    except subprocess.TimeoutExpired:
        raise ValueError("companion tool timed out") from None
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


class CompanionAutomation:
    """One HUD-owned, bounded worker. Every successful update is counts only."""

    def __init__(self, config: CompanionConfig, ai: AISettings) -> None:
        self.config, self.ai = config, ai
        self._stop = Event()
        self._wake = Event()
        self._lock = Lock()
        self._threads: list[Thread] = []
        self._results: dict[str, dict] = {}
        self._status = {
            "nmap": "waiting" if config.nmap_target or config.watch_nmap_xml else "not configured",
            "clamav": "waiting" if config.clamav_paths or config.watch_clamscan_text else "not configured",
            "osquery": "waiting" if config.osquery_enabled or config.watch_osquery_json else "not configured",
        }
        self._advisory: dict[str, str] = {}
        self._seen: dict[str, tuple] = {}
        self._next_collection = {kind: 0.0 for kind in _KINDS}
        self._requested: set[str] = set()
        self._active: set[str] = set()

    def start(self) -> None:
        if self._threads:
            raise ValueError("companion worker already started")
        self._threads = [
            Thread(target=self._collection_loop, name="megalodon-companion-collection", daemon=True),
            Thread(target=self._watch_loop, name="megalodon-companion-watch", daemon=True),
        ]
        for thread in self._threads:
            thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        for thread in self._threads:
            thread.join(timeout=20)

    def request_collection(self) -> dict[str, str]:
        """Wake the existing worker; repeated requests never duplicate a scan."""
        configured = {"nmap": bool(self.config.nmap_target), "clamav": bool(self.config.clamav_paths),
                      "osquery": self.config.osquery_enabled}
        executables = {"nmap": "nmap", "clamav": "clamscan", "osquery": "osqueryi"}
        states = {}
        with self._lock:
            for kind in _KINDS:
                if not configured[kind]:
                    states[kind] = "needs_setup"
                elif shutil.which(executables[kind]) is None:
                    states[kind] = "missing"
                elif kind in self._active or kind in self._requested:
                    states[kind] = "running"
                else:
                    self._requested.add(kind)
                    states[kind] = "queued"
        self._wake.set()
        return states

    def snapshot(self) -> dict:
        with self._lock:
            return {"schema": "megalodon-companion-automation-v1",
                    "results": json.loads(json.dumps(self._results)),
                    "status": dict(self._status), "advisory": dict(self._advisory)}

    def _publish(self, kind: str, value: dict, source: str) -> None:
        with self._lock:
            self._results[kind] = value
            self._status[kind] = f"{source} · completed; saved aggregate"
        if self.config.qwen_advisory and not self.ai.enabled:
            with self._lock:
                self._advisory[kind] = "Qwen unavailable (DISABLED)."
        elif self.config.qwen_advisory:
            from .ai_provider import AIProviderError, generate
            try:
                prompt = ("Explain these completed security inventory counts in at most two sentences. "
                          "State that counts are not proof of safety or a threat. Do not propose commands, "
                          "targets or actions. Data: " + json.dumps({"kind": kind, "counts": value}, sort_keys=True))
                explanation = generate(self.ai, prompt, max_tokens=120)
            except (AIProviderError, ValueError) as exc:
                explanation = f"Qwen unavailable ({getattr(exc, 'code', 'INVALID_RESPONSE')})."
            with self._lock:
                self._advisory[kind] = explanation[:1024]

    def _fail(self, kind: str, message: str) -> None:
        with self._lock:
            self._status[kind] = message

    def _watch(self) -> None:
        sources = {"nmap": self.config.watch_nmap_xml,
                   "clamav": self.config.watch_clamscan_text,
                   "osquery": self.config.watch_osquery_json}
        for kind, path in sources.items():
            if path is None:
                continue
            try:
                parts = [path]
                if kind == "clamav":
                    assert self.config.watch_clamscan_exit is not None
                    parts.append(self.config.watch_clamscan_exit)
                signature = tuple((part.stat().st_ino, part.stat().st_mtime_ns, part.stat().st_size) for part in parts)
                if self._seen.get(kind) == signature:
                    continue
                raw = _read_bounded(path, _LIMITS[kind])
                if kind == "nmap":
                    value = nmap_summary(raw)
                elif kind == "clamav":
                    exit_raw = _read_bounded(parts[1], 2)
                    if exit_raw not in (b"0", b"1", b"0\n", b"1\n"):
                        raise ValueError("invalid ClamAV exit receipt")
                    value = clamav_summary(raw, int(exit_raw.strip()))
                else:
                    value = osquery_summary(raw)
                self._seen[kind] = signature
                self._publish(kind, value, "Watched report")
            except FileNotFoundError:
                # A producer has not written this optional report yet. Local
                # collection can still provide a current aggregate.
                continue
            except (OSError, ValueError, AssertionError):
                self._fail(kind, "Watched report unavailable or rejected; prior aggregate preserved")

    def _collect(self, due: set[str]) -> None:
        jobs = []
        if self.config.osquery_enabled and "osquery" in due:
            jobs.append(("osquery", ["osqueryi", "--json", "SELECT count(*) AS package_count FROM deb_packages;"], OSQUERY_MAX, 30))
        if self.config.nmap_target and "nmap" in due:
            jobs.append(("nmap", ["nmap", "-sT", "-Pn", "-n", "-p", "1-1024", "-oX", "-", self.config.nmap_target], NMAP_MAX, 300))
        if self.config.clamav_paths and "clamav" in due:
            jobs.append(("clamav", ["clamscan", "--recursive", "--infected", *map(str, self.config.clamav_paths)], CLAMAV_MAX, 900))
        for kind, argv, limit, timeout in jobs:
            if self._stop.is_set():
                return
            with self._lock:
                self._status[kind] = ("Scanning configured files; previous aggregate retained until complete" if kind == "clamav"
                                      else "Collecting local aggregate; previous aggregate retained until complete")
            try:
                raw, code = _run_fixed(argv, limit, timeout, self._stop)
                if kind == "nmap" and code == 0:
                    value = nmap_summary(raw)
                elif kind == "clamav" and code in (0, 1):
                    value = clamav_summary(raw, code)
                elif kind == "osquery" and code == 0:
                    # Only this fixed, completed local process establishes a
                    # collection time. Watched reports have no source clock.
                    value = osquery_summary(raw, collection_completed_at=datetime.now(timezone.utc))
                else:
                    raise ValueError("tool returned an unsuccessful status")
                scope = (self.config.nmap_target if kind == "nmap" else
                         "Downloads" if kind == "clamav" and self.config.clamav_paths == (Path.home() / "Downloads",) else
                         "configured folders" if kind == "clamav" else "this PC")
                self._publish(kind, value, f"Local collector ({scope})")
            except (OSError, ValueError) as exc:
                if str(exc) == "companion tool unavailable":
                    self._fail(kind, f"{argv[0]} is not installed; automatic collection unavailable")
                else:
                    self._fail(kind, "Local collector unavailable or rejected; prior aggregate preserved")

    def tick(self) -> None:
        self._watch()
        self._collect_due()

    def _collect_due(self) -> None:
        now = time.monotonic()
        with self._lock:
            due = ({kind for kind, next_at in self._next_collection.items() if now >= next_at} | self._requested) - self._active
            self._requested.difference_update(due)
            self._active.update(due)
            for kind in due:
                interval = self.config.interval_seconds
                if kind == "clamav" and self.config.clamav_interval_seconds is not None:
                    interval = self.config.clamav_interval_seconds
                self._next_collection[kind] = now + interval
        try:
            self._collect(due)
        finally:
            with self._lock:
                self._active.difference_update(due)

    def _collection_loop(self) -> None:
        while not self._stop.is_set():
            self._wake.clear()
            self._collect_due()
            self._wake.wait(15)

    def _watch_loop(self) -> None:
        while not self._stop.is_set():
            self._watch()
            self._stop.wait(15)
