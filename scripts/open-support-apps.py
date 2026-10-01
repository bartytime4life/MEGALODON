#!/usr/bin/env python3
"""Open available companion app interfaces without starting sensors or services.

Run: ./scripts/open-support-apps.py [--dry-run]

Optional web consoles can be set with MEGALODON_<ID>_URL, where ID is one of
SURICATA, OSQUERY, or QWEN. Local addresses
are opened only when their port accepts a connection. Remote configured URLs
are treated as operator choices and are not probed.
"""

import argparse
import http.client
import os
import shutil
import ssl
import subprocess
from urllib.parse import urlsplit


DESKTOP_APPS = (
    ("Wireshark", ("wireshark",)),
    ("Zenmap", ("zenmap",)),
    ("ClamTk", ("clamtk",)),
)

# Optional configured console addresses have no defaults.
WEB_CONSOLES = (
    ("Suricata", "SURICATA", None, ()),
    ("osquery", "OSQUERY", None, ()),
    ("Qwen/Ollama", "QWEN", None, ()),
)


def browser_command():
    for name, args in (("xdg-open", ()), ("gio", ("open",)), ("sensible-browser", ())):
        path = shutil.which(name)
        if path:
            return (path, *args)
    return None


def valid_console_url(raw):
    if not raw or len(raw) > 2048 or any(c.isspace() or c == "\\" for c in raw):
        return None
    try:
        url = urlsplit(raw)
        if (url.scheme not in ("http", "https") or not url.hostname or
                url.username or url.password or url.query or url.fragment):
            return None
        _ = url.port  # Reject malformed ports before a browser is launched.
    except ValueError:
        return None
    return url


def local_console_ready(url, signature=()):
    host = url.hostname
    if host not in ("127.0.0.1", "localhost", "::1"):
        return True  # An explicitly configured remote console is not probed.
    address = "::1" if host == "::1" else "127.0.0.1"
    port = url.port or (443 if url.scheme == "https" else 80)
    connection_type = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
    options = {"context": ssl._create_unverified_context()} if url.scheme == "https" else {}
    connection = connection_type(address, port, timeout=0.4, **options)
    try:
        connection.request("GET", url.path or "/", headers={"Host": host})
        response = connection.getresponse()
        if response.status not in (200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403):
            return False
        if signature:
            body = response.read(4096).lower()
            return any(marker in body for marker in signature)
        return True
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def request_launch(label, argv, dry_run):
    if dry_run:
        print(f"Would open: {label}")
        return True
    try:
        subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True,
        )
    except OSError as exc:
        print(f"Skipped: {label} (launcher unavailable: {exc.strerror or 'OS error'})")
        return False
    print(f"Launch requested: {label}")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="show what would open")
    args = parser.parse_args()

    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        print("Skipped: no graphical desktop session is available.")
        return 0

    opened = 0
    for label, names in DESKTOP_APPS:
        executable = next((path for name in names if (path := shutil.which(name))), None)
        if executable:
            opened += request_launch(label, (executable,), args.dry_run)
        else:
            print(f"Skipped: {label} (desktop app not installed)")

    browser = browser_command()
    for label, key, default, signature in WEB_CONSOLES:
        configured = os.environ.get(f"MEGALODON_{key}_URL")
        candidate = configured or default
        if not candidate:
            print(f"Skipped: {label} (no configured web console)")
            continue
        url = valid_console_url(candidate)
        if url is None:
            print(f"Skipped: {label} (invalid console URL)")
        elif browser is None:
            print(f"Skipped: {label} (no browser opener installed)")
        elif not local_console_ready(url, signature if not configured else ()):
            print(f"Skipped: {label} (console is unavailable at that address)")
        else:
            opened += request_launch(label, (*browser, candidate), args.dry_run)

    print(f"Done. {opened} interface{'s' if opened != 1 else ''} "
          f"{'would open' if args.dry_run else 'requested'}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
