"""Notice when system logs are wiped, cut short, swapped out or rewritten.

Logs are the record of what happened, so an intruder's last step is often to
erase them (ATT&CK T1070.002, Clear Linux or Mac System Logs). ``megalodon
logwatch baseline`` records each log file's identity: inode, size, owner,
mode, a digest of its first 4 KiB and digests of its whole recorded content in
up to 128 pieces, all of which stay fixed while a log only grows.
``megalodon logwatch check`` compares the logs with that record:

``LOG_DELETED`` (HIGH)
    A recorded log is gone, and no rotated copy holds its earlier content.
``LOG_TRUNCATED`` (HIGH)
    The same file got smaller, and no rotated copy holds its earlier content.
``LOG_REWRITTEN`` (HIGH)
    The same file kept or grew its size, but content it already had changed,
    such as one line removed from the middle. Logs only append.
``LOG_REPLACED`` (MEDIUM)
    A different file now has the log's name, and no rotated copy explains it.
``LOG_PERMISSIONS`` (MEDIUM)
    The log became writable by others, or changed owner.

Normal rotation stays quiet. When a sibling such as ``auth.log.1`` (or a
compressed ``.1.gz``) holds the whole recorded content unchanged, the change
is reported as ``rotated``, not as a finding. The baseline is refreshed by
``accept``, or by ``check --advance`` for every log without a finding. Only
metadata and digests are stored, never log content.
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
PIECE_BYTES = 1 << 20  # The smallest piece; a log over 128 MiB gets larger ones.
MAX_PIECES = 128
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


def _piece_size(size):
    pieces = -(-size // PIECE_BYTES)
    return PIECE_BYTES * max(1, -(-pieces // MAX_PIECES))


def _open(path):
    """A stream of the content, compressed rotations read transparently."""
    if path.endswith('.gz'):
        return gzip.open(path, 'rb')
    return os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC), 'rb')


def _pieces(stream, size, piece):
    """Digests of the first ``size`` bytes in ``piece``-byte parts; None when there are fewer bytes."""
    digests, left = [], size
    while left:
        want, digest = min(piece, left), hashlib.sha256()
        while want:
            data = stream.read(min(want, 1 << 20))
            if not data:
                return None
            digest.update(data)
            want -= len(data)
            left -= len(data)
        digests.append(digest.hexdigest())
    return digests


def _first_change(path, recorded):
    """Where the recorded content first differs in ``path``: None if it is all there, unchanged.

    The offset is the start of the first piece that changed. A file holding less
    than the recorded size, or that cannot be read, changed at its end at the latest."""
    piece, expected, size = recorded.get('piece_bytes'), recorded.get('pieces'), recorded.get('size')
    if not (type(piece) is int and piece > 0 and type(size) is int and size >= 0 and type(expected) is list
            and len(expected) == -(-size // piece)):
        return 0  # A damaged record matches nothing.
    try:
        with _open(path) as stream:
            found = _pieces(stream, size, piece)
    except (OSError, EOFError, gzip.BadGzipFile):
        found = None
    if found == expected:
        return None
    for index, digest in enumerate(found or ()):
        if digest != expected[index]:
            return index * piece
    return len(found or ()) * piece


def _identity(path, tries=3):
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
    found = dict(kind='file', inode=info.st_ino, device=info.st_dev, size=info.st_size, uid=info.st_uid,
                 mode=oct(stat.S_IMODE(info.st_mode)), head=head[0], head_bytes=head[1])
    if os.path.basename(path) not in IN_PLACE:
        # Only the bytes present when the size was read: the log may grow meanwhile.
        piece = _piece_size(info.st_size)
        try:
            with _open(path) as stream:
                pieces = _pieces(stream, info.st_size, piece)
        except OSError:
            return 'unreadable'
        if pieces is None:  # Cut short while being read: record what it is now.
            return _identity(path, tries - 1) if tries > 1 else 'unreadable'
        found.update(piece_bytes=piece, pieces=pieces)
    return found


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
    """A sibling such as name.1 or name.1.gz that still holds the recorded content.

    Being the recorded file (same inode) is not enough: a rotated copy that
    was emptied afterwards no longer holds anything. The sibling must keep at
    least the recorded size and start with the recorded first bytes."""
    for candidate in sorted(glob.glob(path + '.*') + glob.glob(path + '-*'))[:64]:
        try:
            info = os.lstat(candidate)
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode) and _holds(candidate, info, recorded):
            return os.path.basename(candidate)
    return None


def _shrunk_rotation(path, recorded):
    """The recorded file under a rotated name, no longer holding the recorded content."""
    for candidate in sorted(glob.glob(path + '.*') + glob.glob(path + '-*'))[:64]:
        try:
            info = os.lstat(candidate)
        except OSError:
            continue
        if (info.st_dev, info.st_ino) == (recorded.get('device'), recorded.get('inode')):
            return os.path.basename(candidate), info.st_size, candidate
    return None


def _holds(path, info, recorded):
    length, size = recorded.get('head_bytes', 0), recorded.get('size', 0)
    if not path.endswith('.gz') and info.st_size < size:
        return False
    if 'pieces' in recorded:  # A copy edited before or after rotation no longer explains the change.
        return _first_change(path, recorded) is None
    try:
        if path.endswith('.gz'):
            with gzip.open(path, 'rb') as stream:
                data = stream.read(length)
                total = len(data)
                while total < size:  # Bounded by the recorded size.
                    chunk = stream.read(min(1 << 20, size - total))
                    if not chunk:
                        return False
                    total += len(chunk)
        else:
            with open(path, 'rb') as stream:
                data = stream.read(length)
    except (OSError, EOFError, gzip.BadGzipFile):
        return False
    return len(data) == length and hashlib.sha256(data).hexdigest() == recorded['head']


def _prefix_digest(path, length):
    try:
        with open(path, 'rb') as stream:
            data = stream.read(length)
    except OSError:
        return None
    return hashlib.sha256(data).hexdigest()


def _rewritten(path, recorded):
    """Where content the log already had changed, or None. A baseline from before
    whole-content digests compares the first bytes only."""
    if 'pieces' in recorded:
        return _first_change(path, recorded)
    if recorded['head_bytes'] and _prefix_digest(path, recorded['head_bytes']) != recorded['head']:
        return 0
    return None


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
        def lost(rule, detail):
            """No rotated copy holds the recorded content: say whether the rotated file was cut."""
            shrunk = _shrunk_rotation(path, before)
            if shrunk and shrunk[1] >= before['size']:  # Not cut short: what it held was changed.
                finding('LOG_REWRITTEN', dict(previous_size=before['size'], rotated_to=shrunk[0], size=shrunk[1],
                                              changed_from_byte=_rewritten(shrunk[2], before)))
            elif shrunk:
                finding('LOG_TRUNCATED', dict(previous_size=before['size'], rotated_to=shrunk[0], size=shrunk[1]))
            else:
                finding(rule, detail)
        if after is None:
            sibling = _rotated(path, before)
            if sibling:
                rotated.append(dict(log=name, rotated_to=sibling))
            else:
                lost('LOG_DELETED', dict(previous_size=before['size']))
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
                lost('LOG_REPLACED', dict(previous_size=before['size'], size=after['size']))
            else:
                finding('LOG_TRUNCATED', dict(previous_size=before['size'], size=after['size']))
        elif os.path.basename(name) not in IN_PLACE and (changed := _rewritten(path, before)) is not None:
            # copytruncate keeps the inode; the log may have grown back past
            # its recorded size before this check.
            sibling = _rotated(path, before)
            if sibling:
                rotated.append(dict(log=name, rotated_to=sibling))
            else:
                finding('LOG_REWRITTEN', dict(previous_size=before['size'], size=after['size'],
                                              changed_from_byte=changed))
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


def check(manifest=DEFAULT_MANIFEST, *, advance=False, **options):
    """Compare the logs with the baseline. With ``advance``, every log without a
    finding is then recorded as it is now, so the next check covers what was
    written since, and rotation does not pile up. A log with a finding keeps its
    old record, and is reported again until ``accept``."""
    old = _read(manifest)
    new = snapshot(**options)
    findings, rotated = compare(old, new, root=options.get('root', '/'))
    report = dict(schema=REPORT_SCHEMA, action='check', manifest=str(Path(manifest).expanduser()),
                  baseline_recorded_at=old.get('recorded_at'), checked_at=_now(), findings=findings,
                  rotated=rotated, new_logs=sorted(set(new['logs']) - set(old['logs'])), gaps=new['gaps'],
                  note='Run accept after reviewing, and after rotation, so the next check compares with today.')
    if advance:
        # A log with a finding, or one that cannot be read now (even if a rotated copy explains it), keeps its
        # record, to be compared again until it is accepted or read.
        kept = {item['log'] for item in findings} | {name for name in new['gaps'] if name in old['logs']}
        logs = {name: value for name, value in new['logs'].items() if name not in kept}
        logs.update({name: old['logs'][name] for name in kept})
        _write(manifest, dict(schema=SCHEMA, recorded_at=report['checked_at'], logs=logs, gaps=new['gaps']))
        report.update(advanced=sorted(set(logs) - kept),
                      note='Logs without a finding were recorded as they are now. Run accept after reviewing.')
    return report


def accept(manifest=DEFAULT_MANIFEST, **options):
    _read(manifest)
    return dict(baseline(manifest, replace=True, **options), action='accept')
