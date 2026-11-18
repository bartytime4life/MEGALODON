"""Notice when system logs are wiped, cut short, swapped out or rewritten.

Logs are the record of what happened, so an intruder's last step is often to
erase them (ATT&CK T1070.002, Clear Linux or Mac System Logs). ``megalodon
logwatch baseline`` records each log file's identity: inode, size, owner,
mode and a digest of its first 4 KiB, which stays fixed while a log only grows.
``megalodon logwatch check`` compares the logs with that record:

``LOG_DELETED`` (HIGH)
    A recorded log is gone, and no rotated copy holds its earlier content.
``LOG_TRUNCATED`` (HIGH)
    The same file got smaller, and no rotated copy holds its earlier content.
``LOG_REWRITTEN`` (HIGH)
    The same file kept or grew its size, but its beginning changed. Logs only append.
``LOG_REPLACED`` (MEDIUM)
    A different file now has the log's name, and no rotated copy explains it.
``LOG_PERMISSIONS`` (MEDIUM)
    The log became writable by others, or changed owner.

Normal rotation stays quiet. When a sibling such as ``auth.log.1`` (or a
compressed ``.1.gz``) starts with the recorded content, or is the recorded
file itself, the change is reported as ``rotated``, not as a finding. The
baseline is refreshed by ``accept``. Only metadata and digests are stored,
never log content.
"""
from __future__ import annotations

from datetime import datetime, timezone
import glob
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

SCHEMA = 'megalodon-log-integrity-v1'
REPORT_SCHEMA = 'megalodon-log-integrity-check-v1'
HEAD_BYTES = 4096
DEFAULT_MANIFEST = '~/.config/megalodon/log-integrity.json'
MAX_LOGS = 2000
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
TECHNIQUE = 'T1070.002'
LOGS = (
    '/var/log/auth.log', '/var/log/secure', '/var/log/syslog', '/var/log/messages', '/var/log/kern.log',
    '/var/log/daemon.log', '/var/log/user.log', '/var/log/audit/audit.log', '/var/log/sudo.log',
    '/var/log/wtmp', '/var/log/btmp', '/var/log/lastlog', '/var/log/faillog', '/var/log/dpkg.log',
    '/var/log/apt/history.log', '/var/log/yum.log', '/var/log/dnf.log', '/var/log/cron', '/var/log/cron.log',
)
# Updated in place by design (one record per account), so only identity and size are compared.
IN_PLACE = frozenset({'lastlog', 'faillog'})
SEVERITY = {'LOG_DELETED': 'HIGH', 'LOG_TRUNCATED': 'HIGH', 'LOG_REWRITTEN': 'HIGH',
            'LOG_REPLACED': 'MEDIUM', 'LOG_PERMISSIONS': 'MEDIUM'}
RANK = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}


class LogIntegrityError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _head(path):
    """Digest of the first 4 KiB, reading compressed rotations transparently; None if unreadable."""
    try:
        if path.endswith('.gz'):
            with gzip.open(path, 'rb') as stream:
                data = stream.read(HEAD_BYTES)
        else:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                data = os.read(fd, HEAD_BYTES)
            finally:
                os.close(fd)
    except (OSError, EOFError):
        return None
    return hashlib.sha256(data).hexdigest(), len(data)


def _identity(path):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        return 'unreadable'
    if not stat.S_ISREG(info.st_mode):
        return dict(kind='special', inode=info.st_ino, device=info.st_dev)
    head = _head(path)
    if head is None:
        return 'unreadable'
    return dict(kind='file', inode=info.st_ino, device=info.st_dev, size=info.st_size, uid=info.st_uid,
                mode=oct(stat.S_IMODE(info.st_mode)), head=head[0], head_bytes=head[1])


def _expand(pattern, root):
    return pattern if root == '/' else os.path.join(root, pattern.lstrip('/'))


def _display(path, root):
    return path if root == '/' else '/' + os.path.relpath(path, root)


def snapshot(*, root='/', patterns=LOGS):
    logs, gaps = {}, []
    for pattern in patterns:
        expanded = _expand(pattern, root)
        matches = sorted(glob.glob(expanded)) if any(c in expanded for c in '*?[') else [expanded]
        for path in matches[:MAX_LOGS]:
            found = _identity(path)
            if found is None:
                continue
            if found == 'unreadable':
                gaps.append(_display(path, root))
                continue
            logs[_display(path, root)] = found
    return dict(logs=logs, gaps=gaps)


def _rotated(path, recorded):
    """A sibling such as name.1 or name.1.gz that is the recorded file or starts with its content."""
    for candidate in sorted(glob.glob(path + '.*') + glob.glob(path + '-*'))[:64]:
        try:
            info = os.lstat(candidate)
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        if (info.st_dev, info.st_ino) == (recorded.get('device'), recorded.get('inode')):
            return os.path.basename(candidate)
        head = _head(candidate)
        if head and recorded.get('head_bytes') and head[1] >= recorded['head_bytes']:
            # Compare the same number of leading bytes as the record.
            data_digest = _prefix_digest(candidate, recorded['head_bytes'])
            if data_digest == recorded['head']:
                return os.path.basename(candidate)
    return None


def _prefix_digest(path, length):
    try:
        if path.endswith('.gz'):
            with gzip.open(path, 'rb') as stream:
                data = stream.read(length)
        else:
            with open(path, 'rb') as stream:
                data = stream.read(length)
    except (OSError, EOFError):
        return None
    return hashlib.sha256(data).hexdigest()


def compare(old, new, *, root='/'):
    findings, rotated = [], []
    for name, before in sorted(old['logs'].items()):
        after = new['logs'].get(name)
        path = _expand(name, root)
        if before.get('kind') != 'file':
            continue

        def finding(rule, detail):
            findings.append(dict(rule_id=rule, severity=SEVERITY[rule], log=name, technique=TECHNIQUE,
                                 detail=detail))
        if after is None:
            sibling = _rotated(path, before)
            if sibling:
                rotated.append(dict(log=name, rotated_to=sibling))
            else:
                finding('LOG_DELETED', dict(previous_size=before['size']))
            continue
        if after.get('kind') != 'file':
            finding('LOG_REPLACED', dict(now='not a regular file'))
            continue
        same_file = (after['device'], after['inode']) == (before['device'], before['inode'])
        if not same_file or after['size'] < before['size']:
            sibling = _rotated(path, before)
            if sibling:
                rotated.append(dict(log=name, rotated_to=sibling))
            elif not same_file:
                finding('LOG_REPLACED', dict(previous_size=before['size'], size=after['size']))
            else:
                finding('LOG_TRUNCATED', dict(previous_size=before['size'], size=after['size']))
        elif (os.path.basename(name) not in IN_PLACE and before['head_bytes']
              and _prefix_digest(path, before['head_bytes']) != before['head']):
            finding('LOG_REWRITTEN', dict(previous_size=before['size'], size=after['size']))
        writable = int(after['mode'], 8) & 0o002 and not int(before['mode'], 8) & 0o002
        if writable or after['uid'] != before['uid']:
            finding('LOG_PERMISSIONS', {k: [before[k], after[k]] for k in ('mode', 'uid') if before[k] != after[k]})
    findings.sort(key=lambda item: (-RANK[item['severity']], item['log']))
    return findings, rotated


def _write(path, value):
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.log-integrity-', dir=path.parent)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def _read(path):
    path = Path(path).expanduser()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise LogIntegrityError(f'no log baseline at {path}; run megalodon logwatch baseline') from None
    except OSError as exc:
        raise LogIntegrityError(f'log baseline {path} cannot be opened: {exc.strerror}') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise LogIntegrityError(f'log baseline {path} must be a mode-600 file owned by you')
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    try:
        value = json.loads(raw)
    except ValueError:
        raise LogIntegrityError('log baseline is not valid JSON') from None
    if len(raw) > MAX_MANIFEST_BYTES or type(value) is not dict or value.get('schema') != SCHEMA:
        raise LogIntegrityError('log baseline has an unsupported format')
    return value


def baseline(manifest=DEFAULT_MANIFEST, *, replace=False, **options):
    path = Path(manifest).expanduser()
    if path.exists() and not replace:
        raise LogIntegrityError(f'{path} exists; use accept to record the reviewed state')
    state = snapshot(**options)
    _write(path, dict(schema=SCHEMA, recorded_at=_now(), **state))
    return dict(schema=REPORT_SCHEMA, action='baseline', manifest=str(path), logs=sorted(state['logs']),
                gaps=state['gaps'])


def check(manifest=DEFAULT_MANIFEST, **options):
    old = _read(manifest)
    new = snapshot(**options)
    findings, rotated = compare(old, new, root=options.get('root', '/'))
    return dict(schema=REPORT_SCHEMA, action='check', manifest=str(Path(manifest).expanduser()),
                baseline_recorded_at=old.get('recorded_at'), checked_at=_now(), findings=findings,
                rotated=rotated, new_logs=sorted(set(new['logs']) - set(old['logs'])), gaps=new['gaps'],
                note='Run accept after reviewing, and after rotation, so the next check compares with today.')


def accept(manifest=DEFAULT_MANIFEST, **options):
    _read(manifest)
    return dict(baseline(manifest, replace=True, **options), action='accept')
