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


def keep(check, result, exit_code, *, folder=None, now=None, reason=None, counted=None):
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
    if counted:
        # A live watch keeps its latest findings and counts every one it saw (see `add_seen`).
        record.update(findings=counted['findings'], severities=counted['severities'])
        if counted['findings'] > len(findings):
            record['truncated'] = True
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


def add_seen(check, found, *, folder=None, now=None):
    """Add what a live watch just saw to its kept result.

    Nothing is held in the watch's memory: each finding is added to the result kept on disk now, so a restarted
    watch keeps what it saw before. A result a check kept, or none (after accept), starts a new list, so what was
    reviewed does not come back. The latest MAX_FINDINGS are kept in full and every finding is counted.

    What the last check found is kept too: the watch adds to it until the next check replaces the result, or
    accept or a new baseline clears it."""
    try:
        record = _read(_folder(folder) / f'{check}.json')
    except (ResultError, OSError):
        record = None
    prior = record if record and isinstance(record.get('result'), dict) else None
    findings = (prior['result'].get('findings', []) if prior else [])[-(MAX_FINDINGS - 1):] + [found]
    severities = dict(prior.get('severities') or {}) if prior else {}
    level = str(found.get('severity') or '').upper()
    severities[level] = severities.get(level, 0) + 1
    total = (prior.get('findings', 0) if prior else 0) + 1
    return keep(check, dict(findings=findings, gaps=[], seen_by_watch=True), 1, folder=folder, now=now,
                counted=dict(findings=total, severities=severities))


def keep_after_watch(check, result, exit_code, *, folder=None, now=None, reason=None):
    """Keep a check's result without losing what the live watch saw since the last accept.

    A check looks at what is there now; a listener or web script the watch saw may be gone, and the check cannot
    see it again. So what the watch kept stays, with the check's own findings after it, until accept or a new
    baseline clears it."""
    try:
        prior = _read(_folder(folder) / f'{check}.json')
    except (ResultError, OSError):
        prior = None
    seen = prior['result'] if (prior and isinstance(prior.get('result'), dict)
                               and prior['result'].get('seen_by_watch')) else None
    if not seen or not isinstance(result, dict):
        return keep(check, result, exit_code, folder=folder, now=now, reason=reason)
    before = [f for f in seen.get('findings', []) if isinstance(f, dict)]
    known = {json.dumps(f, sort_keys=True, default=str) for f in before}
    new = [f for f in _findings(result)
           if isinstance(f, dict) and json.dumps(f, sort_keys=True, default=str) not in known]
    severities = dict(prior.get('severities') or {})
    for finding in new:
        level = str(finding.get('severity') or '').upper()
        severities[level] = severities.get(level, 0) + 1
    merged = dict(result, findings=(before + new)[-MAX_FINDINGS:], seen_by_watch=True)
    return keep(check, merged, exit_code, folder=folder, now=now, reason=reason,
                counted=dict(findings=prior.get('findings', len(before)) + len(new), severities=severities))


def forget(check, *, folder=None):
    """Remove `check`'s kept result: after `accept` or a new baseline of a check a live watch adds to, what was
    kept is no longer what to review, and the watch would otherwise add to it."""
    try:
        os.unlink(_folder(folder) / f'{check}.json')
        return True
    except FileNotFoundError:
        return False


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
        except (ResultError, OSError) as exc:
            # One result that cannot be read (a link, no permission) is that check's error, not the report's end.
            found[name] = dict(check=name, error=str(exc) if isinstance(exc, ResultError)
                               else f'{name}.json cannot be read: {exc.strerror or exc}')
            continue
        if record is not None:
            found[name] = record
    return found
