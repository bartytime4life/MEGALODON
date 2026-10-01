"""Open an already-running user-service HUD from the application menu."""

from __future__ import annotations

import sys
import socket
import time
import webbrowser

from .config import load_settings


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
        if dashboard.host not in {"127.0.0.1", "::1"}:
            return 2
        address = f"[{dashboard.host}]" if dashboard.host == "::1" else dashboard.host
        url = f"http://{address}:{dashboard.port}/"
        if not _wait_until_listening(dashboard.host, dashboard.port):
            print("MEGALODON has not finished starting. Check the local service, then open the launcher again.", file=sys.stderr)
            return 2
        if not webbrowser.open_new_tab(url):
            print(f"Open {url} in your browser.")
    except (OSError, ValueError) as exc:
        print(f"MEGALODON could not open the local HUD: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
