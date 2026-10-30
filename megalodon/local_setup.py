"""Read-only preflight for manually launching the local checkout."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shlex
import sqlite3
import stat
import sys
import tomllib

from . import __version__
from .cli import _dashboard_reader
from .config import _settings_from_mapping
from .config_check import MAX_BYTES, check_configuration
from .dashboard import UnconfiguredDashboardReader


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(2, 'Local preflight accepts only --config FILE, --json and --help; '
                  'each option may be supplied once.\n')


class _Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest) is not None:
            parser.error('Repeated option')
        setattr(namespace, self.dest, True if self.nargs == 0 else values)


def _read_config(path):
    """Read one finite regular-file snapshot without following a leaf symlink."""
    name = os.fspath(path)
    if (not name or len(name.encode('utf-8')) > 4096
            or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise ValueError('Invalid configuration path')
    entry = os.stat(name, follow_symlinks=False)
    if not stat.S_ISREG(entry.st_mode) or entry.st_size > MAX_BYTES:
        raise ValueError('Configuration must be a bounded regular file')
    descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES:
            raise ValueError('Configuration must be a bounded regular file')
        chunks = []
        remaining = MAX_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(8192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode,
                                  value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        raw = b''.join(chunks)
        if (identity(entry) != identity(before) or identity(before) != identity(after)
                or identity(after) != identity(os.stat(name, follow_symlinks=False))
                or len(raw) > MAX_BYTES):
            raise ValueError('Configuration changed or exceeded its bound')
        return raw
    finally:
        os.close(descriptor)


def preflight(config=None):
    """Return a path-free receipt and settings for the local text renderer.

    The selected core audit store is checked, not the installed HUD's managed
    segment catalog, listener, collectors or running processes.
    """
    report = dict(schema='megalodon-local-preflight-v1', status='refused', code='unsupported_platform',
        configuration=dict(selection='explicit' if config is not None else 'defaults', status='not_checked'),
        data=dict(scope='configured_core_audit_store', status='not_checked'), runtime_verified=False,
        limits=['Core configuration and one bounded read-only audit-store summary only.',
                'A missing store is not configured; no store or sample is created.',
                'Managed history, running HUD identity, port availability, sensors and AI are not verified.',
                'No service, network, capture, model, installation or firewall action is started.'])
    if sys.platform != 'linux':
        return report, None
    try:
        raw = b'# built-in defaults\n' if config is None else _read_config(config)
    except (OSError, ValueError, UnicodeError):
        report['configuration']['status'] = 'refused'
        report['code'] = 'configuration_unavailable'
        return report, None
    checked = check_configuration(raw)
    if checked['status'] != 'valid':
        report['configuration']['status'] = 'refused'
        report['code'] = checked['code']
        return report, None
    # Parse the same admitted snapshot; never reopen a changing selected file.
    settings = _settings_from_mapping(tomllib.loads(raw.decode('utf-8')))
    report['configuration']['status'] = 'valid'
    try:
        with _dashboard_reader(settings.db_path, allow_missing=True) as reader:
            if isinstance(reader, UnconfiguredDashboardReader):
                report['data']['status'] = 'not_configured'
            else:
                reader.summary()
                report['data']['status'] = 'readable'
    except (OSError, ValueError, sqlite3.Error):
        report['data']['status'] = 'refused'
        report['code'] = 'database_unavailable'
        return report, settings
    report.update(status='passed', code='data_'+report['data']['status'])
    return report, settings


def main(argv: list[str] | None = None) -> int:
    """Check the selected reader boundary without creating data or probing tools."""
    parser = _Parser(description='Read-only core configuration and audit-store check; no HUD startup.',
                     allow_abbrev=False)
    parser.add_argument('--config', action=_Once, help='Explicit regular TOML file, at most 64 KiB; relative paths use this working directory')
    parser.add_argument('--json', action=_Once, nargs=0, help='Print one path-free JSON receipt; no telemetry or raw errors')
    args = parser.parse_args(argv)
    report, settings = preflight(args.config)
    code = 0 if report['status'] == 'passed' else 2
    if args.json:
        print(json.dumps(report, sort_keys=True, separators=(',', ':'), allow_nan=False))
        return code
    print(f"MEGALODON {__version__}")
    print(f"Python: {platform.python_version()} ({sys.executable})")
    print(f"Platform: {sys.platform}; SQLite: {sqlite3.sqlite_version}")
    if report['code'] == 'unsupported_platform':
        print("Local-PC launcher validation currently covers Linux only.", file=sys.stderr)
        return 2
    if settings is not None:
        print(f"{'Configured' if args.config is not None else 'Default'} data path: {settings.db_path.absolute()}")
    if code:
        print(f"Local setup refused: {report['code']}", file=sys.stderr)
        print("See docs/local-pc-setup.md for data-path troubleshooting.", file=sys.stderr)
        return code
    if report['data']['status'] == 'not_configured':
        print("Data: not configured. The HUD can open without telemetry.")
    else:
        print("Data: existing store passed a bounded read-only check.")
    arguments = [sys.executable, "-m", "megalodon", "hud"]
    if args.config is not None:
        arguments += ['--config', str(Path(args.config).absolute())]
    command = shlex.join(arguments)
    print(f"Ready for manual HUD launch from this directory: {command}")
    print("This check does not verify port availability, sensor health or live capture.")
    print("Managed history and installed/running package identity are not checked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
