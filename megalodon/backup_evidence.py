"""Bounded, read-only admission of externally reviewed host-backup receipts.

Digest pins are an operator-supplied trust boundary, not issuer signatures or
proof of a clean backup. This module never opens a backup or performs a test.
"""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat

from .host_security import date, pairs

SCHEMA = 'megalodon-backup-evidence-v1'
MAX_BYTES = 16384
MAX_AGE = timedelta(days=7)
DETAILS = ('backup_id', 'source_id', 'test_id', 'verifier_id', 'artifact_sha256',
           'source_snapshot_sha256', 'backup_created_at', 'backup_verified_at',
           'test_completed_at', 'approved_at', 'expires_at', 'conflicts')
BACKUP_FIELDS = frozenset(('schema', 'backup_id', 'source_id', 'producer_id',
                          'created_at', 'verified_at', 'expires_at', 'artifact_sha256',
                          'source_snapshot_sha256', 'artifact_bytes', 'availability'))
TEST_FIELDS = frozenset(('schema', 'test_id', 'backup_id', 'source_id', 'verifier_id',
                        'artifact_sha256', 'source_snapshot_sha256', 'restored_snapshot_sha256',
                        'started_at', 'completed_at', 'expires_at', 'result', 'coverage',
                        'environment', 'conflicts'))
TRUST_FIELDS = frozenset(('schema', 'backup_id', 'source_id', 'producer_id', 'verifier_id',
                         'backup_receipt_sha256', 'restore_test_receipt_sha256',
                         'approved_at', 'expires_at'))


class EvidenceError(ValueError):
    """Fixed refusal code, never raw input or a private path."""


def unavailable(reason='missing'):
    return dict(schema=SCHEMA, state='unavailable', reason=reason,
                **dict.fromkeys(DETAILS))


def _require(condition, reason='malformed'):
    if not condition:
        raise EvidenceError(reason)


def _load(raw, fields, schema):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    value = json.loads(raw, object_pairs_hook=pairs)
    _require(type(value) is dict and set(value) == fields and value['schema'] == schema)
    for name, item in value.items():
        if name.endswith('_id'):
            _require(type(item) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', item))
        elif name.endswith('_sha256'):
            _require(type(item) is str and re.fullmatch(r'[0-9a-f]{64}', item))
    return value


def review(backup_raw, test_raw, trust_raw, *, now=None):
    """Verify exact external receipt bytes against separately approved pins.

    Every record is closed-schema and time bounded. A pinned independent test
    must cover the same whole snapshot in isolation. Even success conveys no
    attribution, current-host conflict clearance, or restoration authority.
    """
    try:
        if any(raw is None for raw in (backup_raw, test_raw, trust_raw)):
            return unavailable()
        observed = datetime.now(timezone.utc) if now is None else now
        _require(type(observed) is datetime and observed.tzinfo is not None
                 and observed.utcoffset() is not None)
        backup = _load(backup_raw, BACKUP_FIELDS, 'megalodon-host-backup-receipt-v1')
        test = _load(test_raw, TEST_FIELDS, 'megalodon-isolated-restore-test-v1')
        trust = _load(trust_raw, TRUST_FIELDS, 'megalodon-backup-trust-v1')
        _require(sha256(backup_raw).hexdigest() == trust['backup_receipt_sha256']
                 and sha256(test_raw).hexdigest() == trust['restore_test_receipt_sha256'], 'untrusted')
        _require(backup['backup_id'] == test['backup_id'] == trust['backup_id']
                 and backup['source_id'] == test['source_id'] == trust['source_id']
                 and backup['producer_id'] == trust['producer_id']
                 and test['verifier_id'] == trust['verifier_id']
                 and backup['artifact_sha256'] == test['artifact_sha256']
                 and backup['source_snapshot_sha256'] == test['source_snapshot_sha256']
                 == test['restored_snapshot_sha256'], 'conflicting')
        _require(trust['verifier_id'] != trust['producer_id'], 'untrusted')
        _require(type(backup['artifact_bytes']) is int and 0 < backup['artifact_bytes'] <= 2**53-1)
        _require(backup['availability'] == 'observed_available'
                 and test['result'] == 'passed' and test['coverage'] == 'full_snapshot'
                 and test['environment'] == 'isolated'
                 and test['conflicts'] in ('not_assessed', 'reported_legitimate_changes'), 'incomplete')
        created, verified = date(backup['created_at']), date(backup['verified_at'])
        started, completed = date(test['started_at']), date(test['completed_at'])
        approved = date(trust['approved_at'])
        _require(created <= verified <= started <= completed <= approved <= observed, 'conflicting')
        expiries = [date(row['expires_at']) for row in (backup, test, trust)]
        for checked, expires in zip((verified, completed, approved), expiries):
            _require(checked < expires <= checked + MAX_AGE)
            _require(checked <= observed < expires, 'expired')
        return dict(schema=SCHEMA, state='verified_external_evidence', reason='verified',
                    backup_id=backup['backup_id'], source_id=backup['source_id'],
                    test_id=test['test_id'], verifier_id=test['verifier_id'],
                    artifact_sha256=backup['artifact_sha256'],
                    source_snapshot_sha256=backup['source_snapshot_sha256'],
                    backup_created_at=backup['created_at'], backup_verified_at=backup['verified_at'],
                    test_completed_at=test['completed_at'], approved_at=trust['approved_at'],
                    expires_at=min(expiries).strftime('%Y-%m-%dT%H:%M:%SZ'),
                    conflicts=test['conflicts'])
    except EvidenceError as exc:
        return unavailable(str(exc))
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        return unavailable('malformed')


def _read(path):
    """Pin real directory ancestry and bound a private regular-file read."""
    _require(path.is_absolute(), 'unreadable')
    descriptors, bindings = [], []
    try:
        directory = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(directory)
        for name in path.parts[1:-1]:
            parent = directory
            directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append(directory)
            info = os.fstat(directory)
            _require(info.st_uid in (0, os.geteuid())
                     and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX), 'unreadable')
            bindings.append((parent, name, info))
        parent_info = os.fstat(directory)
        _require(parent_info.st_uid == os.geteuid() and not parent_info.st_mode & 0o077, 'unreadable')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        descriptors.append(fd)
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                 and not before.st_mode & 0o077 and before.st_nlink == 1
                 and 0 < before.st_size <= MAX_BYTES, 'unreadable')
        chunks, size = [], 0
        while size <= MAX_BYTES:
            chunk = os.read(fd, MAX_BYTES + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size,
                                 info.st_mtime_ns, info.st_ctime_ns, info.st_mode, info.st_uid, info.st_nlink)
        _require(size == before.st_size and identity(before) == identity(os.fstat(fd))
                 == identity(os.stat(path.name, dir_fd=directory, follow_symlinks=False)), 'unreadable')
        for parent, name, info in bindings:
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            _require((info.st_dev, info.st_ino, info.st_mode, info.st_uid)
                     == (current.st_dev, current.st_ino, current.st_mode, current.st_uid), 'unreadable')
        return b''.join(chunks)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def snapshot(home, *, now=None):
    """Read only three fixed private files; never create directories or trust.

    Re-read the trust record to refuse a concurrent approval/revocation change.
    No positive cache survives expiry, a failed read, or removed evidence.
    """
    if os.name != 'posix' or not all(hasattr(os, flag) for flag in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_NONBLOCK')):
        return unavailable('unreadable')
    root = Path(home)
    trust_path = root / '.config/megalodon/recovery-trust.json'
    evidence = root / '.local/share/megalodon/support/recovery-evidence'
    try:
        trust = _read(trust_path)
        backup = _read(evidence / 'backup.json')
        test = _read(evidence / 'restore-test.json')
        if _read(trust_path) != trust:
            return unavailable('untrusted')
        return review(backup, test, trust, now=now)
    except FileNotFoundError:
        return unavailable()
    except (OSError, ValueError, TypeError, RecursionError):
        return unavailable('unreadable')
