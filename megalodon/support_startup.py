"""One explicit local action for fixed companion starts and existing collectors.

The HUD and terminal command share this workflow. No request supplies an
executable, service name, URL, scan target, configuration, or shell expression.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import sys
from threading import Lock, Thread
import time

from .tool_installer import service_unit

SCHEMA = "megalodon-support-startup-v1"
COMMAND = "~/.local/share/megalodon/current/venv/bin/python -I -m megalodon.support_startup"
SERVICES = (("suricata", "Suricata", "suricata"), ("qwen", "Ollama / Qwen", "ollama"))


def _trusted_system_executable(name):
    """Use only a root-owned system binary for an authorized service start."""
    if name not in {"systemctl", "pkexec"}:
        return None
    path = Path('/usr/bin') / name
    try:
        info = path.lstat()
    except OSError:
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022 or not info.st_mode & 0o111):
        return None
    return str(path)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class SupportBusy(Exception):
    pass


class SupportApps:
    def __init__(self, companions=None, *, installer=None, on_finish=None,
                 run=subprocess.run, which=shutil.which):
        self.companions, self.installer, self.on_finish = companions, installer, on_finish
        self.configuration = None
        self.run, self.which = run, which
        self.token = secrets.token_urlsafe(24)
        self._lock = Lock()
        self._thread = None
        self._last_start = -float("inf")
        self._job = {"schema": SCHEMA, "state": "idle", "started_at": None,
                     "finished_at": None, "items": [], "command": COMMAND}

    def snapshot(self, *, include_token=False):
        with self._lock:
            value = deepcopy(self._job)
            if include_token:
                value["token"] = self.token
            return value

    def start(self):
        with self._lock:
            if (self._job["state"] == "running" or time.monotonic() - self._last_start < 5
                    or (self.installer and self.installer.status()["state"] == "running")):
                raise SupportBusy
            self._last_start = time.monotonic()
            self._job.update(state="running", started_at=_now(), finished_at=None, items=[])
            self._thread = Thread(target=self._work, name="megalodon-support-start", daemon=True)
            self._thread.start()
        return self.snapshot()

    def _item(self, identifier, name, state, message):
        value = {"id": identifier, "name": name, "state": state, "message": message}
        with self._lock:
            existing = next((i for i, row in enumerate(self._job["items"]) if row["id"] == identifier), None)
            if existing is None:
                self._job["items"].append(value)
            else:
                self._job["items"][existing] = value

    def _command(self, argv, *, timeout=5, env=None):
        try:
            return self.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=timeout, check=False,
                            **({"env": env} if env is not None else {})).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _active(self, unit, *, user=False):
        systemctl = self.which("systemctl")
        return bool(systemctl and self._command([systemctl, *(["--user"] if user else []), "is-active", "--quiet", unit]))

    def _services(self):
        systemctl = _trusted_system_executable("systemctl")
        pkexec = _trusted_system_executable("pkexec")
        pending = []
        for identifier, name, unit in SERVICES:
            if self._active(unit + ".service"):
                self._item(identifier, name, "running", "Service is already active. Data and model readiness are checked separately.")
            elif identifier == 'suricata' and not Path('/etc/systemd/system/suricata.service.d/zz-megalodon-passive.conf').is_file():
                self._item(identifier,name,'needs_setup','Use Configure Suricata once to select the passive interface and allow HUD log access.')
            elif not systemctl or service_unit(identifier) is None:
                self._item(identifier, name, "missing", "No supported installed service was found; skipped.")
            elif not pkexec:
                self._item(identifier, name, "needs_setup", "System authorization is unavailable. Start the installed service from a terminal.")
            else:
                pending.append((identifier, name, unit))
                self._item(identifier, name, "checking", "Starting the installed service; a system authorization prompt may appear.")
        if pending:
            self._command([pkexec, systemctl, "start", *[unit + ".service" for _, _, unit in pending]], timeout=90)
            for identifier, name, unit in pending:
                active = self._active(unit + ".service")
                self._item(identifier, name, "running" if active else "failed",
                           "Service is active. Check its data connection separately." if active else
                           "Service did not become active. Authorization may have been cancelled or its configuration needs attention.")

    def _work(self):
        try:
            self._item("core", "MEGALODON / Python / SQLite", "running", "The local HUD and resource monitor are running.")
            states = self.companions.request_collection() if self.companions else {}
            for identifier, name in (("nmap", "Nmap inventory"), ("clamav", "ClamAV file scan"), ("osquery", "osquery package inventory")):
                state = states.get(identifier, "needs_setup")
                message = {"queued": "Queued with the existing collector. Results will update the HUD automatically.",
                           "running": "Already collecting or queued; a second job was not started.",
                           "missing": "The collector executable is not installed; skipped.",
                           "needs_setup": "Collection is not configured for this tool in the current HUD."}[state]
                self._item(identifier, name, state, message)
            if self.configuration:
                from .support_config import ConfigBusy
                try:
                    capture = self.configuration.start_background_tools()
                    self._item("tshark", "Wireshark / TShark", "running" if capture["state"]=="running" else "queued",
                               "Background packet metadata collection is enabled. No desktop window is opened.")
                except ConfigBusy:
                    self._item('tshark','Wireshark / TShark','needs_setup','A configuration action is still running. Retry background tools after it finishes.')
                    return
                except (ValueError, RuntimeError):
                    self._item("tshark", "Wireshark / TShark", "needs_setup", "Choose an interface and configure capture access in Configure apps.")
            self._services()
            enabled = bool(self.configuration and self.configuration.background.snapshot()["enabled"])
            zeek_state = self.configuration.sensors.snapshot()["zeek"]["state"] if enabled else "stopped"
            state = ("failed" if zeek_state == "error" else "needs_setup" if zeek_state == "needs_setup" or not enabled else "queued")
            message = ("Zeek sampling failed; review capture access and its executable directory, then retry background tools."
                       if state == "failed" else
                       "Zeek needs an executable directory and active background monitoring."
                       if state == "needs_setup" else
                       "Bounded background samples are scheduled; check Sensors for the latest sample. Zeek is not a continuous service.")
            self._item("zeek", "Zeek", state, message)
            self._item("scapy", "Scapy / alternate capture", "not_needed", "Standby alternative: the TShark feed supplies live packets, avoiding a redundant Python capture process.")
            self._item("nftables", "nftables", "not_needed", "Command-line tool; no app to open. Firewall rules are not changed by startup.")
        except Exception:
            # No subprocess error strings, paths or environment values escape.
            self._item("launcher", "Support startup", "failed", "Startup stopped unexpectedly; completed items remain shown. Retry after checking the local session.")
        finally:
            with self._lock:
                self._job.update(state="finished", finished_at=_now())
            if self.on_finish:
                self.on_finish()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Start background support tools and configured collectors inside the local MEGALODON HUD")
    parser.add_argument("--check", action="store_true", help="show current startup status without starting anything")
    parser.add_argument("--config", type=Path, help="local HUD settings (default: the installed app's settings)")
    args = parser.parse_args(argv)
    from .config import load_settings
    from .dashboard import loopback_host
    if sys.platform != "linux" or os.getuid() == 0 or os.geteuid() == 0:
        print("Run this command as your normal Linux desktop user.", file=sys.stderr)
        return 2
    config = args.config or Path.home() / ".config/megalodon/settings.toml"
    try:
        if args.config and not config.is_file():
            raise ValueError("The selected HUD settings file does not exist.")
        settings = load_settings(config if config.exists() else None)
        host = loopback_host(settings.dashboard.host)
        port = settings.dashboard.port
        origin = f"http://{host}:{port}"

        def request(method="GET", token=None):
            connection = HTTPConnection(host, port, timeout=5)
            headers = {"X-Megalodon-Check": "1"}
            body = None
            if method == "POST":
                headers.update({"X-Megalodon-Support-Token": token, "Origin": origin, "Content-Type": "application/json"})
                body = '{"action":"start"}'
            try:
                connection.request(method, "/api/support-start", body=body, headers=headers)
                response = connection.getresponse()
                raw = response.read(32769)
                if response.status not in (200, 202, 409) or len(raw) > 32768:
                    raise ValueError("Open the local HUD first; if sign-in is enabled, use its Start support apps button.")
                value = json.loads(raw)
                if response.status == 409:
                    return None
                if value.get("schema") != SCHEMA:
                    raise ValueError("Update the local HUD before starting support apps.")
                return value
            finally:
                connection.close()

        try:
            value = request()
        except OSError:
            if args.check:
                raise
            systemctl = shutil.which("systemctl")
            if not systemctl:
                raise ValueError("Open MEGALODON, then run this command again.")
            subprocess.run([systemctl, "--user", "start", "megalodon-hud.service"], check=True, timeout=15)
            for attempt in range(20):
                try:
                    value = request()
                    break
                except OSError:
                    if attempt == 19:
                        raise
                    time.sleep(.25)
        if not args.check:
            request("POST", value["token"])
            deadline = time.monotonic() + 120
            print("Starting background tools; no extra application windows will open.", flush=True)
            while time.monotonic() < deadline:
                value = request()
                if value["state"] != "running":
                    break
                time.sleep(1)
        print("Support startup:", value["state"])
        for item in value["items"]:
            print(f"- {item['name']}: {item['state']} — {item['message']}")
        return 1 if value["state"] == "running" or any(item["state"] == "failed" for item in value["items"]) else 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f"MEGALODON support startup unavailable: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
