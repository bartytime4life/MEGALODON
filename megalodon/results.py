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

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
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
    if check in SEEN_CHECKS:
        # Moving what an earlier version kept and replacing the result are one step: two checks at once, or one
        # run again after a failed write, move it once.
        with _locked(check, folder):
            _move_watch_record(check, folder)
            return _write(check, data, target)
    return _write(check, data, target)


def _write(check, data, target):
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


# The listener and web-root watches neither keep a check's result nor feed the response engine. What they see is
# appended to a log of its own beside the check's result: `CHECK-seen.jsonl`, one finding a line. Appending never
# reads or rewrites anything, so a check that runs meanwhile cannot lose it, and a check, failed or not, only ever
# replaces its own result. The report reads both. `accept` or a new baseline clears both.
SEEN_CHECKS = ('listeners', 'webroot')
MAX_SEEN_BYTES = 8 * 1024 * 1024        # beyond this a watch's findings are no longer added; the count says "at least"
_SEEN_FULL = MAX_SEEN_BYTES // 2       # beyond this only each finding's severity is added, so it is still counted
# Added by a watch when it sends a finding, not part of what was found: left out when telling findings apart.
EMISSION_KEYS = frozenset({'detected_at', 'live'})


def seen_path(check, folder=None):
    return _folder(folder) / f'{check}-seen.jsonl'


def identity(finding):
    """A finding as found, without what a watch adds when it sends it: the same finding from a check and a watch
    reads the same."""
    return json.dumps({k: v for k, v in finding.items() if k not in EMISSION_KEYS}, sort_keys=True, default=str)


def add_seen(check, found, *, folder=None, now=None):
    """Append what a live watch just saw to its log (one line, O_APPEND: atomic, and nothing is read first)."""
    if check not in SEEN_CHECKS:
        raise ResultError(f'{check} is not a watch whose findings are kept')
    _folder(folder).mkdir(mode=0o700, parents=True, exist_ok=True)
    return _append_seen(check, dict(at=now or _now(), finding=found), folder)


@contextmanager
def _locked(check, folder=None):
    """An exclusive lock for `check`'s result, held across reading, moving and replacing it."""
    fd = os.open(_folder(folder) / f'.{check}.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _append_seen(check, entry, folder=None):
    fd = os.open(seen_path(check, folder), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ResultError(f'{check}-seen.jsonl must be a mode-600 file owned by you')
        if info.st_size >= MAX_SEEN_BYTES:
            return False
        if info.st_size >= _SEEN_FULL and 'finding' in entry:
            entry = dict(at=entry['at'], severity=str(entry['finding'].get('severity') or '').upper())
        os.write(fd, (json.dumps(entry, sort_keys=True, default=str) + '\n').encode())
        return True
    finally:
        os.close(fd)


def _move_watch_record(check, folder=None):
    """Findings a watch kept, before its own log, in the check's result (marked seen_by_watch): moved to the log,
    with when, before a check replaces that result. They were not reviewed, so they are not dropped."""
    try:
        prior = _read(_folder(folder) / f'{check}.json')
    except (ResultError, OSError):
        return 0
    if not (prior and isinstance(prior.get('result'), dict) and prior['result'].get('seen_by_watch')):
        return 0
    at = prior.get('at') or _now()
    # A mark of what was moved: a result moved once (before a failed write) is not moved again.
    mark = hashlib.sha256(json.dumps(prior, sort_keys=True, default=str).encode()).hexdigest()
    try:
        with open(seen_path(check, folder), encoding='utf-8', errors='replace') as stream:
            if any(f'"moved": "{mark}"' in line for line in stream):
                return 0
    except FileNotFoundError:
        pass
    kept = [f for f in prior['result'].get('findings', []) if isinstance(f, dict)]
    moved = sum(1 for f in kept if _append_seen(check, dict(at=at, finding=f), folder))
    # Those it counted but no longer kept in full: their severities, so the count stays.
    listed = {}
    for f in kept:
        level = str(f.get('severity') or '').upper()
        listed[level] = listed.get(level, 0) + 1
    for level, count in (prior.get('severities') or {}).items():
        for _ in range(max(0, int(count) - listed.get(level, 0)) if isinstance(count, int) else 0):
            if not _append_seen(check, dict(at=at, severity=level), folder):
                break
            moved += 1
    _append_seen(check, dict(at=at, moved=mark), folder)
    return moved


def seen(check, *, folder=None):
    """What the watch saw since the last accept: the latest MAX_FINDINGS in full, every one counted; or None."""
    path = seen_path(check, folder)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ResultError(f'{path} must be a mode-600 file owned by you')
        raw = b''
        while len(raw) <= MAX_SEEN_BYTES:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(fd)
    entries = []
    for line in raw.decode('utf-8', 'replace').splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue                    # a line cut short by a full disk or a crash
        if isinstance(entry, dict) and ('finding' in entry or 'severity' in entry):     # not a mark of a move
            entries.append(entry)
    # In the order they were seen, not written: findings moved from an earlier version are older than what the
    # watch may have appended before the first check.
    entries.sort(key=lambda entry: str(entry.get('at') or ''))
    findings, severities, total, last = [], {}, 0, None
    for entry in entries:
        finding = entry.get('finding')
        level = str((finding.get('severity') if isinstance(finding, dict) else entry.get('severity')) or '').upper()
        severities[level] = severities.get(level, 0) + 1
        total += 1
        last = entry.get('at') or last
        if isinstance(finding, dict):
            findings.append(finding)
    if not total:
        return None
    return dict(findings=findings[-MAX_FINDINGS:], total=total, severities=severities, at=last,
                at_least=info.st_size >= MAX_SEEN_BYTES)


def forget(check, *, folder=None):
    """Clear `check`'s kept result and what its watch saw: after `accept` or a new baseline, neither is what to
    review now."""
    removed = False
    for path in (_folder(folder) / f'{check}.json', seen_path(check, folder)):
        try:
            os.unlink(path)
            removed = True
        except FileNotFoundError:
            pass
    return removed


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
            record = dict(check=name, error=str(exc) if isinstance(exc, ResultError)
                          else f'{name}.json cannot be read: {exc.strerror or exc}')
        if name in SEEN_CHECKS:
            try:
                watched = seen(name, folder=folder)
            except (ResultError, OSError) as exc:
                watched = dict(error=str(exc) if isinstance(exc, ResultError) else f'{name}-seen.jsonl cannot be read')
            if watched is not None:
                record = dict(record) if record is not None else dict(schema=SCHEMA, check=name, at=watched.get('at'),
                                                                     exit_code=None, ran=None, findings=0, result=None)
                record['seen'] = watched
        if record is not None:
            found[name] = record
    return found
