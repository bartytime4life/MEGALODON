"""Read-only preflight for manually launching the local checkout."""

from __future__ import annotations

import argparse
import platform
import shlex
import sqlite3
import sys

from . import __version__
from .cli import _dashboard_reader
from .config import load_settings
from .dashboard import UnconfiguredDashboardReader


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(2, 'Local preflight accepts no options or positional arguments except --help; '
                  'it checks only the default data path.\n')


def main(argv: list[str] | None = None) -> int:
    """Check the actual reader boundary without creating data or probing tools."""
    parser = _Parser(description='Read-only check of the default local data path; no HUD options.',
                     allow_abbrev=False)
    parser.parse_args(argv)
    print(f"MEGALODON {__version__}")
    print(f"Python: {platform.python_version()} ({sys.executable})")
    print(f"Platform: {sys.platform}; SQLite: {sqlite3.sqlite_version}")
    if sys.platform != "linux":
        print("Local-PC launcher validation currently covers Linux only.", file=sys.stderr)
        return 2
    settings = load_settings()
    print(f"Default data path: {settings.db_path.absolute()}")
    try:
        with _dashboard_reader(settings.db_path, allow_missing=True) as reader:
            if isinstance(reader, UnconfiguredDashboardReader):
                print("Data: not configured. The HUD can open without telemetry.")
            else:
                # Exercise a bounded read, not only schema admission.
                reader.summary()
                print("Data: existing store passed a bounded read-only check.")
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"Local setup refused: {exc}", file=sys.stderr)
        print("See docs/local-pc-setup.md for data-path troubleshooting.", file=sys.stderr)
        return 2
    command = shlex.join([sys.executable, "-m", "megalodon", "hud"])
    print(f"Ready for manual HUD launch from this directory: {command}")
    print("This check does not verify port availability, sensor health or live capture.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
