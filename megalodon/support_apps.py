"""Fixed desktop support-app launch actions for the local HUD.

The catalog reports only whether a known GUI app can be launched in the
current Linux desktop session. A launch starts that app as the current user;
it never starts a scan, capture, sensor, or service.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import shutil
import subprocess
import sys
from threading import Lock
from time import monotonic
from typing import Any, Callable

from .capabilities import runtime_platform


SCHEMA = "megalodon-support-apps-v1"
_COOLDOWN_SECONDS = 1.0


@dataclass(frozen=True)
class SupportApp:
    id: str
    name: str
    executable: str


SUPPORT_APPS = (
    SupportApp("wireshark", "Wireshark", "wireshark"),
    SupportApp("zenmap", "Zenmap", "zenmap"),
    SupportApp("clamtk", "ClamTk", "clamtk"),
)
_APPS_BY_ID = {app.id: app for app in SUPPORT_APPS}


class SupportAppUnavailable(Exception):
    """The selected fixed application cannot be opened in this session."""


class SupportAppBusy(Exception):
    """A launch was requested too recently."""


class SupportAppLaunchFailed(Exception):
    """The operating system refused the fixed application launch."""


def _desktop_reason() -> str | None:
    if runtime_platform() != "linux" or not sys.platform.startswith("linux"):
        return "unsupported_platform"
    if not (os.environ.get("DISPLAY", "").strip()
            or os.environ.get("WAYLAND_DISPLAY", "").strip()):
        return "no_desktop_session"
    return None


class SupportAppLauncher:
    """Catalog and launch a closed list of desktop applications."""

    def __init__(self, *, which: Callable[[str], str | None] = shutil.which,
                 runner: Callable[..., subprocess.Popen[Any]] = subprocess.Popen) -> None:
        self._which = which
        self._runner = runner
        self._lock = Lock()
        self._last_launch: dict[str, float] = {}

    def catalog(self) -> dict[str, Any]:
        desktop_reason = _desktop_reason()
        apps = []
        for app in SUPPORT_APPS:
            reason = desktop_reason
            if reason is None:
                executable = self._which(app.executable)
                if not executable or not os.path.isabs(executable):
                    reason = "not_found"
            apps.append({
                "id": app.id,
                "name": app.name,
                "available": reason is None,
                "reason": reason or "available",
            })
        return {"schema": SCHEMA, "apps": apps}

    def launch(self, app_id: str) -> dict[str, Any]:
        app = _APPS_BY_ID.get(app_id)
        if app is None:
            raise SupportAppUnavailable
        if _desktop_reason() is not None:
            raise SupportAppUnavailable
        executable = self._which(app.executable)
        if not executable or not os.path.isabs(executable):
            raise SupportAppUnavailable
        now = monotonic()
        with self._lock:
            last_launch = self._last_launch.get(app.id)
            if last_launch is not None and now - last_launch < _COOLDOWN_SECONDS:
                raise SupportAppBusy
            self._last_launch[app.id] = now
        try:
            self._runner([executable], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         close_fds=True, start_new_session=True)
        except (OSError, ValueError):
            with self._lock:
                self._last_launch.pop(app.id, None)
            raise SupportAppLaunchFailed from None
        return {"app": app.id, "state": "launch_requested",
                "window_verified": False}
