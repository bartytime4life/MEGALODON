"""Notice when systemd journal files are deleted, cut back or edited.

The journal keeps its records in binary files under ``/var/log/journal`` (and
``/run/log/journal`` when it is kept in memory). Each file's header carries a
random file ID, the ID of the sequence its entries are numbered in, the first
and last entry numbers and the number of entries
(https://systemd.io/JOURNAL_FILE_FORMAT/). Within one file those only grow,
and once a file is rotated (archived) it is never written again.

The record keeps each file's header fields, keyed by file ID, so a rename at
rotation is followed, plus a SHA-256 digest of every archived file. A check
then reports:

``JOURNAL_FILE_DELETED`` (HIGH)
    A recorded journal file is gone, and its loss is not what vacuuming does:
    journald deletes only archived files, oldest first.
``JOURNAL_ENTRIES_REMOVED`` (HIGH)
    The same file now holds fewer entries, its first entry number changed or
    its last one went back, or the file is shorter than its header says.
``JOURNAL_ARCHIVE_CHANGED`` (HIGH)
    An archived file's content changed.

Only header fields and digests are stored, never journal content.
"""
from __future__ import annotations

import glob
import hashlib
import os
import stat
import struct

PLACES = ('/var/log/journal', '/run/log/journal')
SIGNATURE = b'LPKSHHRH'
HEADER_READ = 272
MIN_HEADER = 208  # Through tail_entry_monotonic, in every file since the format began.
STATE_ONLINE, STATE_OFFLINE, STATE_ARCHIVED = 1, 0, 2
COMPATIBLE_SEALED = 1
MAX_FILES = 4096
TECHNIQUE = 'T1070.002'
SEVERITY = {'JOURNAL_FILE_DELETED': 'HIGH', 'JOURNAL_ENTRIES_REMOVED': 'HIGH', 'JOURNAL_ARCHIVE_CHANGED': 'HIGH'}


def _display(path, root):
    return path if root == '/' else '/' + os.path.relpath(path, root)


def header(data):
    """The header fields this check uses, or None if ``data`` is not a journal header."""
    if len(data) < MIN_HEADER or data[:8] != SIGNATURE:
        return None
    compatible, = struct.unpack_from('<I', data, 8)
    state = data[16]
    file_id, seqnum_id = data[24:40].hex(), data[72:88].hex()
    header_size, arena_size = struct.unpack_from('<QQ', data, 88)
    n_entries, tail, head = struct.unpack_from('<QQQ', data, 152)
    head_realtime, tail_realtime = struct.unpack_from('<QQ', data, 184)
    if header_size < MIN_HEADER:
        return None
    return dict(file_id=file_id, seqnum_id=seqnum_id, state=state, n_entries=n_entries, head=head, tail=tail,
                head_realtime=head_realtime, tail_realtime=tail_realtime, used=header_size + arena_size,
                sealed=bool(compatible & COMPATIBLE_SEALED))


def _digest(path):
    digest = hashlib.sha256()
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC), 'rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def _boot_id(root):
    try:
        with open(os.path.join(root, 'proc/sys/kernel/random/boot_id'), encoding='ascii') as stream:
            return stream.read(64).strip() or None
    except OSError:
        return None


def snapshot(*, root='/', previous=None):
    """Every journal file's header, keyed by file ID, and a digest of each archived one.

    An archived file whose inode, size and change times match ``previous`` keeps
    its recorded digest instead of being read again: writing to a file changes
    its change time, which cannot be set back."""
    known = (previous or {}).get('files', {})
    files, gaps, corrupt = {}, [], []
    paths = []
    for place in PLACES:
        base = place if root == '/' else os.path.join(root, place.lstrip('/'))
        paths += sorted(glob.glob(os.path.join(base, '*', '*.journal')) + glob.glob(os.path.join(base, '*', '*.journal~')))
    for path in paths[:MAX_FILES]:
        name = _display(path, root)
        try:
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode):
                continue
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC), 'rb') as stream:
                found = header(stream.read(HEADER_READ))
        except OSError:
            gaps.append(name)
            continue
        if found is None or found['file_id'] in files:
            continue
        dirty = path.endswith('~')
        if dirty:
            corrupt.append(name)
        found.update(path=name, volatile=name.startswith('/run/'), dirty=dirty, inode=info.st_ino,
                     device=info.st_dev, size=info.st_size, mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns)
        if found['state'] == STATE_ARCHIVED or dirty:  # Never written again.
            before = known.get(found['file_id'], {})
            same = all(before.get(key) == found[key] for key in ('inode', 'device', 'size', 'mtime_ns', 'ctime_ns'))
            try:
                found['sha256'] = before['sha256'] if same and before.get('sha256') else _digest(path)
            except OSError:
                gaps.append(name)
                continue
        files[found['file_id']] = found
    return dict(files=files, gaps=gaps, corrupt=corrupt, boot_id=_boot_id(root))


def _active(record):
    return record['state'] != STATE_ARCHIVED and not record['dirty']


def compare(old, new):
    """Findings, and the recorded files whose absence is explained (vacuumed, flushed or cleared at boot)."""
    findings, explained = [], []
    old_files, new_files = old.get('files', {}), new['files']

    def finding(rule, record, detail):
        findings.append(dict(rule_id=rule, severity=SEVERITY[rule], log=record['path'], technique=TECHNIQUE,
                             journal_file_id=record['file_id'], detail=detail))

    for file_id, before in sorted(old_files.items(), key=lambda item: item[1]['path']):
        after = new_files.get(file_id)
        if after is None:
            if before['path'] in new['gaps']:
                continue  # Unreadable now: its record is kept and compared again later.
            reason = _why_gone(before, old, new)
            if reason:
                explained.append(dict(log=before['path'], journal_file_id=file_id, reason=reason))
            else:
                finding('JOURNAL_FILE_DELETED', before, dict(entries=before['n_entries'], first=before['head'],
                                                             last=before['tail'], archived=not _active(before)))
            continue
        removed = []
        if before['n_entries'] and after['head'] != before['head']:
            removed.append('first entry number changed')
        if after['tail'] < before['tail']:
            removed.append('last entry number went back')
        if after['n_entries'] < before['n_entries']:
            removed.append('fewer entries')
        if after['size'] < after['used']:
            removed.append('file shorter than its header says')
        if removed:
            finding('JOURNAL_ENTRIES_REMOVED', after, dict(
                why=removed, entries=[before['n_entries'], after['n_entries']], first=[before['head'], after['head']],
                last=[before['tail'], after['tail']]))
        elif before.get('sha256') and after.get('sha256') and before['sha256'] != after['sha256']:
            finding('JOURNAL_ARCHIVE_CHANGED', after, dict(previous_sha256=before['sha256'], sha256=after['sha256'],
                                                           entries=after['n_entries']))
    return findings, explained


def _older(before, record):
    """Whether journald's vacuuming would delete ``before`` ahead of ``record``: by entry number within one
    sequence, and by the time of the first entry across sequences."""
    if record['seqnum_id'] == before['seqnum_id']:
        return before['head'] < record['head']
    return before['head_realtime'] < record['head_realtime']


def _why_gone(before, old, new):
    """Why a recorded file may be gone without anything being wrong, or None."""
    if not before['n_entries']:
        return 'empty'  # journald deletes an empty file instead of archiving it; nothing was lost.
    rebooted = old.get('boot_id') and new.get('boot_id') and old['boot_id'] != new['boot_id']
    if before['volatile']:
        if rebooted:
            return 'kept in memory, cleared at boot'
        if any(not record['volatile'] and record['seqnum_id'] == before['seqnum_id'] and record['tail'] >= before['tail']
               for record in new['files'].values()):
            return 'flushed to the persistent journal'
    if _active(before):
        return None  # journald never deletes the file it writes to.
    # Vacuuming deletes the archived files of one folder, oldest first. Empty files have no first entry.
    folder = os.path.dirname(before['path'])
    present = [record for record in new['files'].values()
               if os.path.dirname(record['path']) == folder and record['n_entries']]
    if present and all(_older(before, record) for record in present):
        return 'vacuumed (oldest first)'
    return None
