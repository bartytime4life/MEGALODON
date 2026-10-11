"""Open an already-running user-service HUD from the application menu."""

from __future__ import annotations

import sys
import socket
import time
import webbrowser

from .config import load_settings
from .install_lifecycle import _listener_pid, service_running
from .local_install import InstallError, install_paths


def _wait_until_listening(host: str, port: int, timeout: float = 15) -> bool:
    """A user service is active before Python has finished opening its socket."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            with socket.create_connection((host, port), timeout=.5):
                return True
        except OSError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(.2)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        return 2
    try:
        dashboard = load_settings(args[0]).dashboard
        # The HUD server and upgrade verification are IPv4 loopback only.
        if dashboard.host != "127.0.0.1":
            print("MEGALODON's background HUD requires [dashboard] host = \"127.0.0.1\".", file=sys.stderr)
            return 2
        url = f"http://{dashboard.host}:{dashboard.port}/"
        if not _wait_until_listening(dashboard.host, dashboard.port):
            print("MEGALODON has not finished starting. Check the local service, then open the launcher again.", file=sys.stderr)
            return 2
        # MainPID below is only meaningful for the managed unit: same fragment, unmodified, no drop-ins.
        try:
            managed = service_running(install_paths())
        except InstallError:
            managed = False
        if not managed:
            print("The MEGALODON service is not ready: megalodon-hud.service is not the managed, unmodified unit, "
                  "so nothing was opened. Check the local service, then open the launcher again.", file=sys.stderr)
            return 2
        # Another local program can hold the port first; open only the managed service's own listener.
        if _listener_pid(dashboard.port, dashboard.host) is None:
            print(f"The MEGALODON service is not ready: {dashboard.host}:{dashboard.port} is not its listener, so nothing was opened. "
                  "Check the local service, then open the launcher again.", file=sys.stderr)
            return 2
        if not webbrowser.open_new_tab(url):
            print(f"Open {url} in your browser.")
    except (OSError, ValueError) as exc:
        print(f"MEGALODON could not open the local HUD: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
