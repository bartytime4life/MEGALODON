"""The latest result of each check, kept for `megalodon report`.

Each `megalodon CHECK check` writes what it found, and when, to
``~/.local/state/megalodon/results/CHECK.json`` (mode 600, in a mode-700
folder): its findings, gaps and exit code. The scheduled checks so keep the
report current without it running any check again. A check that could not
run is kept too, with its exit code and the reason it gave, so the report can
tell "clean" from "broken" and from "never run". A check that stops with an
error is kept as well, so an older result is never shown as current.

Only the latest run of each check is kept. Results are what the check printed;
nothing here decides or changes anything.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import tempfile

SCHEMA = 'megalodon-check-result-v1'
DEFAULT_FOLDER = '~/.local/state/megalodon/results'
MAX_BYTES = 4 * 1024 * 1024          # a result larger than this keeps its first findings only
MAX_FINDINGS = 500
NAMES = ('persistence', 'listeners', 'logwatch', 'devices', 'webroot', 'binaries', 'ebpf', 'containers',
         'hardening', 'packages', 'secrets', 'vulns', 'boot', 'rootkit', 'logins', 'egress', 'credentials',
         'ancestry', 'tamper')


class ResultError(OSError):
    pass


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _folder(folder=None):
    return Path(folder or DEFAULT_FOLDER).expanduser()


def _findings(result):
    found = result.get('findings') if isinstance(result, dict) else None
    return found if isinstance(found, list) else []


def keep(check, result, exit_code, *, folder=None, now=None, reason=None):
    """Record `check`'s latest result. `result` is what the check printed, or None when it could not run;
    `reason` is what it said when it could not."""
    if check not in NAMES:
        raise ResultError(f'{check} is not a check whose results are kept')
    findings = _findings(result)
    # Counted before a very large result is cut, so the report's totals stay exact.
    severities = {}
    for finding in findings:
        level = str(finding.get('severity') or '').upper() if isinstance(finding, dict) else ''
        severities[level] = severities.get(level, 0) + 1
    record = dict(schema=SCHEMA, check=check, at=now or _now(), exit_code=exit_code,
                  ran=result is not None, findings=len(findings), severities=severities, result=result)
    if reason:
        record['reason'] = str(reason)[:500]
    data = json.dumps(record, sort_keys=True, default=str)
    if len(data) > MAX_BYTES and isinstance(result, dict):
        # A very large report keeps its first findings and says so; the count stays exact.
        trimmed = {key: value for key, value in result.items() if key != 'findings'}
        trimmed['findings'] = findings[:MAX_FINDINGS]
        record.update(result=trimmed, truncated=True)
        data = json.dumps(record, sort_keys=True, default=str)
        if len(data) > MAX_BYTES:
            record.update(result=dict(findings=findings[:50]))
            data = json.dumps(record, sort_keys=True, default=str)
    target = _folder(folder)
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f'.{check}-', dir=target)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target / f'{check}.json')
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
    return target / f'{check}.json'


def _read(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        # Written by this account only: a result someone else could write could hide a finding.
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ResultError(f'{path} must be a mode-600 file owned by you')
        raw = os.read(fd, MAX_BYTES + 1)
    finally:
        os.close(fd)
    try:
        value = json.loads(raw)
    except ValueError:
        raise ResultError(f'{path} is not valid JSON') from None
    if type(value) is not dict or value.get('schema') != SCHEMA:
        raise ResultError(f'{path} has an unsupported format')
    return value


def latest(*, folder=None):
    """{check: its latest record, or dict(error=...) when the record cannot be trusted}; checks never run are
    absent."""
    found = {}
    for name in NAMES:
        try:
            record = _read(_folder(folder) / f'{name}.json')
        except ResultError as exc:
            found[name] = dict(check=name, error=str(exc))
            continue
        if record is not None:
            found[name] = record
    return found
