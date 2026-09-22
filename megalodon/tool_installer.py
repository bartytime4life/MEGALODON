"""One-click companion installation and service start for the local HUD.

Requests select only a fixed tool id. Every command is a constant argv from the
closed ``RECIPES`` registry below; no request can supply a package, path, flag
or shell text. System packages are installed through ``pkexec`` so the
operating system asks the operator for their password in its own dialog; the
HUD never sees or stores a credential. A second fixed action starts a tool's
systemd service from ``SERVICE_UNITS`` so an amber light can go green. One job
runs at a time and its bounded
output tail is kept in memory only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
import shutil
import subprocess
import sys
from threading import Event, Lock, Thread, Timer
from typing import Any, Callable

from .capabilities import runtime_platform


MAX_OUTPUT_LINES = 40
MAX_LINE_BYTES = 240
INSTALL_TIMEOUT_SECONDS = 30 * 60
JOB_STATES = frozenset({"idle", "running", "succeeded", "failed"})
ACTIONS = frozenset({"install", "start"})


@dataclass(frozen=True)
class Recipe:
    kind: str  # "apt", "pip", "ollama" or "guided"
    summary: str
    packages: tuple[str, ...] = ()
    preseed: tuple[str, ...] = ()
    requires: str | None = None


# apt recipes use Ubuntu archive packages only. Guided tools need a vendor
# repository, a role decision or a multi-service deployment that one button
# cannot choose safely; the HUD links their official instructions instead.
RECIPES: dict[str, Recipe] = {
    "core": Recipe("guided", "MEGALODON is already installed; it is serving this HUD."),
    "tshark": Recipe("apt", "Installs the Ubuntu tshark package. Live-capture permission stays disabled.",
                     ("tshark",), ("wireshark-common wireshark-common/install-setuid boolean false",)),
    "zeek": Recipe("guided", "Zeek has no Ubuntu archive package; follow the private-prefix build guide."),
    "suricata": Recipe("apt", "Installs the Ubuntu suricata package. Its service may start after installation.",
                       ("suricata",)),
    "scapy": Recipe("pip", "Installs Scapy into the Python environment that runs this HUD.", ("scapy>=2.5,<3",)),
    "nftables": Recipe("apt", "Installs the Ubuntu nftables package. No firewall rules are changed.", ("nftables",)),
    "clamav": Recipe("apt", "Installs the Ubuntu clamav scanner. It may add a signature-update service.",
                     ("clamav",)),
    "osquery": Recipe("guided", "osquery ships from its signed vendor repository; use the official package."),
    "qwen": Recipe("ollama", "Downloads the example qwen2.5:7b model into the local Ollama provider (several GB).",
                   ("qwen2.5:7b",), requires="ollama"),
    "nmap": Recipe("apt", "Installs the Ubuntu nmap package. No scan is started.", ("nmap",)),
    "ossec": Recipe("guided", "OSSEC server and agent roles install differently; use the vendor guide."),
    "greenbone": Recipe("guided", "Greenbone is a multi-container deployment; use the official container guide."),
    "zabbix": Recipe("apt", "Installs the Ubuntu zabbix-agent package. Its service may start after installation.",
                     ("zabbix-agent",)),
    "nagios": Recipe("apt", "Installs the Ubuntu nagios4 package. Its web service may start after installation.",
                     ("nagios4",)),
}


def _apt_script(recipe: Recipe) -> str:
    # Constant text assembled only from the closed registry above.
    lines = ["set -e", "export DEBIAN_FRONTEND=noninteractive"]
    for selection in recipe.preseed:
        lines.append(f"printf '%s\\n' '{selection}' | debconf-set-selections")
    lines.append("apt-get update")
    lines.append("apt-get install -y --no-install-recommends " + " ".join(recipe.packages))
    return "\n".join(lines)


def install_command(tool_id: str, *, which: Callable[[str], str | None] = shutil.which,
                    is_root: bool | None = None) -> list[str] | None:
    """Return the fixed argv for one tool, or None when it cannot run here."""
    recipe = RECIPES[tool_id]
    if recipe.kind == "pip":
        return [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", *recipe.packages]
    if recipe.kind == "ollama":
        ollama = which("ollama")
        return [ollama, "pull", *recipe.packages] if ollama else None
    if recipe.kind == "apt":
        if runtime_platform() != "linux" or which("apt-get") is None:
            return None
        root = (os.geteuid() == 0) if is_root is None else is_root
        script = _apt_script(recipe)
        if root:
            return ["/bin/sh", "-c", script]
        pkexec = which("pkexec")
        return [pkexec, "/bin/sh", "-c", script] if pkexec else None
    return None


# Fixed systemd units for tools whose light expects a running service. The
# first unit file that exists on this host is started; nothing else is.
SERVICE_UNITS: dict[str, tuple[str, ...]] = {
    "suricata": ("suricata",),
    "qwen": ("ollama",),
    "ossec": ("ossec", "wazuh-agent"),
    "zabbix": ("zabbix-agent2", "zabbix-agent", "zabbix-server"),
    "nagios": ("nagios4", "nagios"),
}
UNIT_DIRECTORIES = ("/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system")


def service_unit(tool_id: str, *, directories: tuple[str, ...] = UNIT_DIRECTORIES) -> str | None:
    for unit in SERVICE_UNITS.get(tool_id, ()):
        for directory in directories:
            if os.path.isfile(os.path.join(directory, f"{unit}.service")):
                return unit
    return None


def start_command(tool_id: str, *, which: Callable[[str], str | None] = shutil.which,
                  is_root: bool | None = None,
                  directories: tuple[str, ...] = UNIT_DIRECTORIES) -> list[str] | None:
    """Return the fixed argv that starts one tool's service, or None."""
    if runtime_platform() != "linux":
        return None
    unit = service_unit(tool_id, directories=directories)
    systemctl = which("systemctl")
    if unit is None or systemctl is None:
        return None
    root = (os.geteuid() == 0) if is_root is None else is_root
    if root:
        return [systemctl, "start", f"{unit}.service"]
    pkexec = which("pkexec")
    return [pkexec, systemctl, "start", f"{unit}.service"] if pkexec else None


def terminal_command(tool_id: str) -> str | None:
    """Copyable equivalent for hosts without a graphical password prompt."""
    recipe = RECIPES[tool_id]
    if recipe.kind == "apt":
        preseed = "".join(f"echo '{s}' | sudo debconf-set-selections && " for s in recipe.preseed)
        return f"{preseed}sudo apt-get update && sudo apt-get install -y --no-install-recommends {' '.join(recipe.packages)}"
    if recipe.kind == "pip":
        return f"{sys.executable} -m pip install '{recipe.packages[0]}'"
    if recipe.kind == "ollama":
        return f"ollama pull {recipe.packages[0]}"
    return None


def catalog() -> dict[str, Any]:
    tools = []
    for tool_id, recipe in RECIPES.items():
        command = install_command(tool_id)
        tools.append({
            "id": tool_id,
            "method": recipe.kind,
            "summary": recipe.summary,
            "one_click": command is not None,
            "terminal": terminal_command(tool_id),
            "startable": start_command(tool_id) is not None,
            "start_terminal": f"sudo systemctl start {unit}.service" if (unit := service_unit(tool_id)) else None,
        })
    return {"schema": "megalodon-tool-install-catalog-v1", "tools": tools}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class _Job:
    tool: str | None = None
    action: str | None = None
    state: str = "idle"
    started_at: str | None = None
    finished_at: str | None = None
    exit_code: int | None = None
    output: list[str] = field(default_factory=list)


class InstallBusy(Exception):
    """Another installation is running."""


class InstallUnavailable(Exception):
    """The selected tool has no one-click recipe on this host."""


class Installer:
    """Runs at most one fixed recipe at a time in a background thread."""

    def __init__(self, *, on_finish: Callable[[], None] | None = None,
                 runner: Callable[..., subprocess.Popen[str]] = subprocess.Popen,
                 timeout: float = INSTALL_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout
        self._lock = Lock()
        self._job = _Job()
        self._on_finish = on_finish
        self._runner = runner

    def status(self) -> dict[str, Any]:
        with self._lock:
            job = self._job
            return {"schema": "megalodon-tool-install-v1", "tool": job.tool, "action": job.action, "state": job.state,
                    "started_at": job.started_at, "finished_at": job.finished_at,
                    "exit_code": job.exit_code, "output": list(job.output)}

    def start(self, tool_id: str, action: str = "install") -> dict[str, Any]:
        if tool_id not in RECIPES or action not in ACTIONS:
            raise KeyError(tool_id)
        command = install_command(tool_id) if action == "install" else start_command(tool_id)
        if command is None:
            raise InstallUnavailable(tool_id)
        with self._lock:
            if self._job.state == "running":
                raise InstallBusy
            self._job = _Job(tool=tool_id, action=action, state="running", started_at=_now())
        Thread(target=self._run, args=(command,), name=f"megalodon-install-{tool_id}", daemon=True).start()
        return self.status()

    def _append(self, line: str) -> None:
        text = line.rstrip("\r\n").encode("utf-8", errors="replace")[:MAX_LINE_BYTES].decode("utf-8", errors="ignore")
        with self._lock:
            self._job.output.append(text)
            del self._job.output[:-MAX_OUTPUT_LINES]

    def _run(self, command: list[str]) -> None:
        code: int | None = None
        timed_out = Event()
        try:
            process = self._runner(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, errors="replace",
                                   env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"})
            # Reading stdout blocks until exit, so enforce the deadline separately.
            def expire() -> None:
                timed_out.set()
                process.kill()
            deadline = Timer(self._timeout, expire)
            deadline.daemon = True
            deadline.start()
            try:
                assert process.stdout is not None
                for line in process.stdout:
                    self._append(line)
                code = process.wait()
            finally:
                deadline.cancel()
            if timed_out.is_set():
                code = None
                self._append("The job timed out and was stopped.")
        except OSError as exc:
            self._append(f"Installer could not start: {exc.strerror or type(exc).__name__}")
        if code in (126, 127) and command and command[0].endswith("pkexec"):
            self._append("Authorization was cancelled or no password prompt is available. Use the terminal command instead.")
        with self._lock:
            self._job.exit_code = code
            self._job.state = "succeeded" if code == 0 else "failed"
            self._job.finished_at = _now()
        if self._on_finish is not None:
            self._on_finish()
