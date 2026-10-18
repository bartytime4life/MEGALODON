"""Read-only review of common Linux persistence locations. No execution or removal.

Each run inventories a fixed set of autostart, scheduler, shell-startup, SSH and
loader paths for this user and world-readable system locations, then compares
the inventory with an operator-recorded baseline. A baseline is what was
observed when it was recorded, not a known-clean state. A change is a reason
to look, never proof of compromise; package updates and the operator's own
edits change these files too. Nothing here starts, stops, edits or deletes a
file, unit, job or key.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import heapq
import json
import os
from pathlib import Path
import re
import stat

SCHEMA = 'megalodon-persistence-review-v1'
SUMMARY_SCHEMA = 'megalodon-persistence-summary-v1'
BASELINE_SCHEMA = 'megalodon-persistence-baseline-v1'
MAX_READ = 256 * 1024
MAX_DIR_ENTRIES = 128
MAX_ITEMS = 512
MAX_FINDINGS = 64
MAX_GAPS = 32
MAX_KEYS = 64
MAX_TEXT = 240
TRUST = 'observed_not_known_clean'
# The HUD summary keeps the first findings and gaps so the setup snapshot stays small.
SUMMARY_FINDINGS = 16
SUMMARY_GAPS = 8
# (category, ATT&CK technique, location, kind). Paths starting with ~ are
# relative to the reviewed home. Locations are code, never operator input.
LOCATIONS = (
    ('autostart', 'T1547.013', '~/.config/autostart', 'dir'),
    ('autostart', 'T1547.013', '/etc/xdg/autostart', 'dir'),
    ('systemd', 'T1543.002', '~/.config/systemd/user', 'dir'),
    ('systemd', 'T1543.002', '~/.local/share/systemd/user', 'dir'),
    ('systemd', 'T1543.002', '/etc/systemd/system', 'dir'),
    ('systemd', 'T1543.002', '/etc/systemd/user', 'dir'),
    ('cron', 'T1053.003', '/etc/crontab', 'file'),
    ('cron', 'T1053.003', '/etc/cron.d', 'dir'),
    ('cron', 'T1053.003', '/etc/cron.hourly', 'dir'),
    ('cron', 'T1053.003', '/etc/cron.daily', 'dir'),
    ('cron', 'T1053.003', '/etc/cron.weekly', 'dir'),
    ('cron', 'T1053.003', '/etc/cron.monthly', 'dir'),
    ('shell', 'T1546.004', '~/.bashrc', 'file'),
    ('shell', 'T1546.004', '~/.bash_profile', 'file'),
    ('shell', 'T1546.004', '~/.bash_login', 'file'),
    ('shell', 'T1546.004', '~/.bash_logout', 'file'),
    ('shell', 'T1546.004', '~/.profile', 'file'),
    ('shell', 'T1546.004', '~/.zshrc', 'file'),
    ('shell', 'T1546.004', '~/.zprofile', 'file'),
    ('shell', 'T1546.004', '/etc/profile', 'file'),
    ('shell', 'T1546.004', '/etc/bash.bashrc', 'file'),
    ('shell', 'T1546.004', '/etc/profile.d', 'dir'),
    ('session', 'T1037.004', '~/.xprofile', 'file'),
    ('session', 'T1037.004', '~/.xsessionrc', 'file'),
    ('session', 'T1037.004', '/etc/rc.local', 'file'),
    ('ssh', 'T1098.004', '~/.ssh/authorized_keys', 'keys'),
    ('ssh', 'T1098.004', '~/.ssh/authorized_keys2', 'keys'),
    ('ssh', 'T1098.004', '~/.ssh/rc', 'file'),
    ('loader', 'T1574.006', '/etc/ld.so.preload', 'file'),
)
_EXEC = re.compile(rb'^\s*(Exec|ExecStart|ExecStartPre|ExecStartPost)\s*=\s*(.+)$', re.M)
_KEY = re.compile(r'(?:^|\s)((?:ssh|ecdsa|sk)-[A-Za-z0-9@._-]{1,64})\s+([A-Za-z0-9+/=]{16,16384})(?:\s|$)')


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _text(value):
    value = value.decode('utf-8', 'replace') if isinstance(value, bytes) else str(value)
    value = ''.join(c if c.isprintable() else '?' for c in value)
    return value if len(value) <= MAX_TEXT else value[:MAX_TEXT]+'...'


def _read(path):
    """Open without following a final symlink; never block on a FIFO or device."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, 'O_CLOEXEC', 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('not a regular file')
        chunks, size = [], 0
        while size <= MAX_READ:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk); size += len(chunk)
        data = b''.join(chunks)
        return info, data[:MAX_READ], size > MAX_READ
    finally:
        os.close(fd)


def _command(line):
    """Keep the executable only; arguments can carry tokens or passwords."""
    words = line.decode('utf-8', 'replace').split()
    # systemd prefixes such as '-' or '@' change failure handling, not the program.
    executable = words[0].lstrip('-@+!:') if words else ''
    return dict(executable=_text(executable), arguments=max(0, len(words)-1))


def _fingerprints(data):
    keys = []
    for line in data.decode('utf-8', 'replace').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = _KEY.search(line)
        if not match:
            keys.append(dict(type='unparsed', fingerprint=None))
        else:
            try:
                blob = base64.b64decode(match.group(2), validate=True)
            except ValueError:
                keys.append(dict(type='unparsed', fingerprint=None)); continue
            # Same form as `ssh-keygen -lf`; the key comment is never kept.
            digest = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
            keys.append(dict(type=match.group(1), fingerprint='SHA256:'+digest))
        if len(keys) >= MAX_KEYS:
            break
    return keys


def _item(path, category, technique, kind):
    row = dict(path=str(path), category=category, attack=technique)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return dict(row, state='unreadable', reason=_text(exc.strerror or 'unreadable'))
    row.update(mode=oct(stat.S_IMODE(info.st_mode)), uid=info.st_uid,
               modified_at=datetime.fromtimestamp(int(info.st_mtime), timezone.utc).isoformat().replace('+00:00', 'Z'))
    if stat.S_ISLNK(info.st_mode):
        try:
            return dict(row, state='symlink', target=_text(os.readlink(path)))
        except OSError:
            return dict(row, state='unreadable', reason='link target unreadable')
    if not stat.S_ISREG(info.st_mode):
        return dict(row, state='other', reason='not a regular file')
    try:
        opened, data, truncated = _read(path)
    except (OSError, ValueError) as exc:
        return dict(row, state='unreadable', reason=_text(getattr(exc, 'strerror', None) or exc))
    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
        return dict(row, state='unreadable', reason='file changed during review')
    row.update(state='file', bytes=opened.st_size, sha256=hashlib.sha256(data).hexdigest(), truncated=truncated)
    if kind == 'keys':
        row['keys'] = _fingerprints(data)
    commands = [_command(m.group(2)) for m in _EXEC.finditer(data)][:4]
    if commands:
        row['commands'] = commands
    return row


def _names(path):
    """Return the MAX_DIR_ENTRIES smallest names and the total, in bounded memory."""
    total = 0
    def walk(entries):
        nonlocal total
        for entry in entries:
            total += 1
            yield entry.name
    with os.scandir(path) as entries:
        return heapq.nsmallest(MAX_DIR_ENTRIES, walk(entries)), total


def inventory(home=None, root='/'):
    """Return the bounded inventory, its gaps, and coverage.

    coverage['incomplete'] lists every path that was not fully enumerated, so
    a baseline entry under it is unconfirmed rather than removed.
    """
    home = Path(home or Path.home())
    base = Path(root)
    items, gaps, incomplete = [], [], []
    def take(path, category, technique, kind):
        # The item bound also bounds file reads, so check it before each one.
        if len(items) >= MAX_ITEMS:
            return False
        row = _item(path, category, technique, kind)
        if row is not None:
            items.append(row)
        return True
    def listed(path, label):
        names, total = _names(path)
        if total > MAX_DIR_ENTRIES:
            gaps.append(f'{label} has {total} entries; only the first {MAX_DIR_ENTRIES} were reviewed.')
            incomplete.append(str(path))
        return names
    def resolve(location):
        return home/location[2:] if location.startswith('~/') else base/location.lstrip('/')
    stopped = False
    for position, (category, technique, location, kind) in enumerate(LOCATIONS):
        path = resolve(location)
        if kind != 'dir':
            stopped = not take(path, category, technique, kind)
        else:
            try:
                names = listed(path, location)
            except FileNotFoundError:
                continue
            except NotADirectoryError:
                stopped = not take(path, category, technique, 'file')
                names = []
            except OSError:
                gaps.append(f'{location} could not be listed.'); incomplete.append(str(path)); continue
            for name in names:
                # Unit drop-in and .wants directories are listed one level deep.
                child = path/name
                if child.is_dir() and not child.is_symlink():
                    try:
                        nested = listed(child, f'{location}/{name}')
                    except OSError:
                        gaps.append(f'{location}/{name} could not be listed.'); incomplete.append(str(child)); continue
                    paths = [child/n for n in nested if not (child/n).is_dir() or (child/n).is_symlink()]
                else:
                    paths = [child]
                if not all(take(candidate, category, technique, 'file') for candidate in paths):
                    stopped = True
                    break
        if stopped:
            # This location and every later one are unconfirmed, not empty.
            incomplete.extend(str(resolve(row[2])) for row in LOCATIONS[position:])
            break
    if stopped:
        gaps.insert(0, f'Review stopped at {MAX_ITEMS} items; later locations were not reviewed.')
    gaps.append('User crontabs in the system spool need root to read and were not reviewed.')
    return items, gaps, dict(stopped=stopped, incomplete=sorted(set(incomplete)))


def _covered(path, incomplete):
    return any(path == prefix or path.startswith(prefix+'/') for prefix in incomplete)


def _bounded(gaps):
    """Deduplicate gaps and disclose, rather than drop, any beyond MAX_GAPS."""
    gaps = list(dict.fromkeys(gaps))
    if len(gaps) <= MAX_GAPS:
        return gaps, len(gaps)
    return gaps[:MAX_GAPS-1]+[f'{len(gaps)-MAX_GAPS+1} more coverage gaps were not listed.'], len(gaps)


IDENTITY = ('state', 'sha256', 'bytes', 'mode', 'uid', 'target', 'keys')


def _identity(row):
    # The hash covers at most MAX_READ bytes; a truncated file also compares
    # its modification time so a change past the prefix is not missed.
    value = {k: row.get(k) for k in IDENTITY}
    if row.get('truncated'):
        value['modified_at'] = row.get('modified_at')
    return value


def compare(items, baseline, *, uid=None, incomplete=()):
    """Return bounded review findings and the uncapped total; never an action or verdict."""
    uid = os.getuid() if uid is None else uid
    findings = []
    total = 0
    def add(rule, row, detail):
        nonlocal total
        total += 1
        if len(findings) < MAX_FINDINGS:
            findings.append(dict(rule=rule, path=row['path'], category=row['category'], attack=row['attack'],
                                 detail=detail, action_status='not_attempted'))
    for row in items:
        mode = int(row['mode'], 8) if row.get('mode') else 0
        if row['path'].endswith('ld.so.preload') and row.get('state') == 'file' and row.get('bytes'):
            add('PRELOAD_PRESENT', row, 'The system loader preload list is not empty; every program loads these libraries.')
        if row.get('state') == 'file' and mode & 0o002:
            add('WORLD_WRITABLE', row, 'Any local account can change this startup file.')
        if row.get('state') in {'file', 'symlink'} and row.get('uid') not in (0, uid):
            add('UNEXPECTED_OWNER', row, f'Owned by uid {row.get("uid")}, neither root nor this account.')
    if baseline is None:
        return findings, total
    before = {row['path']: row for row in baseline['items']}
    now = {row['path']: row for row in items}
    for path in sorted(now.keys() - before.keys()):
        add('ADDED', now[path], 'Present now but not in the recorded baseline.')
    for path in sorted(before.keys() & now.keys()):
        if _identity(before[path]) != _identity(now[path]):
            old, new = _identity(before[path]), _identity(now[path])
            changed = [k for k in dict.fromkeys([*old, *new]) if old.get(k) != new.get(k)]
            add('CHANGED', now[path], 'Changed since the recorded baseline: '+', '.join(changed)+'.')
    for path in sorted(before.keys() - now.keys()):
        if _covered(path, incomplete):
            continue
        add('REMOVED', before[path], 'In the recorded baseline but no longer present.')
    return findings, total


_EXISTS = 'A persistence baseline already exists. Review its changes, then replace it from the command line if they are expected.'


def _create(path, value):
    """Create a private file only if absent, atomically, so a baseline recorded meanwhile is never replaced."""
    from .host_security import MAX_FILE
    from .local_install import _owned_directory
    _owned_directory(path.parent, private=True)
    if len(value) > MAX_FILE:
        raise ValueError('Persistence baseline exceeds its bound.')
    temporary = path.parent/f'.{path.name}.new-{os.getpid()}-{os.urandom(4).hex()}'
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)  # fails, rather than replacing, when the baseline exists
        except FileExistsError:
            raise ValueError(_EXISTS) from None
    finally:
        temporary.unlink(missing_ok=True)


class PersistenceReview:
    def __init__(self, home=None, *, root='/', now=_now):
        self.home = Path(home or Path.home())
        self.state = self.home/'.local/share/megalodon/support/persistence-review'
        self.root, self.now = root, now

    def _baseline(self):
        from .host_security import read
        path = self.state/'baseline.json'
        if not os.path.lexists(path):
            return None
        value = json.loads(read(path, 4 * 1024 * 1024))
        if (type(value) is not dict or set(value) != {'schema', 'created_at', 'trust', 'items'}
                or value['schema'] != BASELINE_SCHEMA or value['trust'] != TRUST
                or type(value['items']) is not list or len(value['items']) > MAX_ITEMS
                or not all(type(r) is dict and all(type(r.get(k)) is str for k in ('path', 'category', 'attack', 'state'))
                           for r in value['items'])):
            raise ValueError('Invalid persistence baseline.')
        return value

    def record_baseline(self, *, initial=False):
        """Record what is present now. An initial recording never replaces a baseline."""
        from .host_security import write
        path = self.state/'baseline.json'
        if initial and os.path.lexists(path):
            raise ValueError(_EXISTS)
        items, gaps, coverage = inventory(self.home, self.root)
        value = json.dumps(dict(schema=BASELINE_SCHEMA, created_at=self.now(), trust=TRUST, items=items),
                           sort_keys=True, separators=(',', ':')).encode()
        if initial:
            _create(path, value)
        else:
            write(path, value)
        gaps, gap_total = _bounded(gaps)
        return dict(schema=SCHEMA, state='baseline_recorded', items=len(items), gaps=gaps, gaps_total=gap_total, trust=TRUST,
                    inventory_truncated=coverage['stopped'],
                    message='Baseline recorded from what is present now. It is not a known-clean state.')

    def review(self):
        baseline = self._baseline()
        items, gaps, coverage = inventory(self.home, self.root)
        findings, total = compare(items, baseline, incomplete=coverage['incomplete'])
        first = []
        if total > len(findings):
            first.append(f'{total} findings were found; only the first {len(findings)} are listed.')
        if baseline is None:
            first.append('No baseline is recorded, so additions, changes and removals cannot be reported.')
        else:
            present = {row['path'] for row in items}
            unconfirmed = sum(1 for row in baseline['items'] if row['path'] not in present and _covered(row['path'], coverage['incomplete']))
            if unconfirmed:
                first.append(f'{unconfirmed} baseline paths are in locations that were not fully reviewed; they are not reported as removed.')
        gaps, gap_total = _bounded(first+gaps)
        return dict(schema=SCHEMA, reviewed_at=self.now(), baseline_at=baseline and baseline['created_at'],
                    trust=TRUST, items=items, findings=findings, findings_total=total,
                    findings_truncated=total > len(findings), inventory_truncated=coverage['stopped'],
                    incomplete_locations=coverage['incomplete'], gaps=gaps, gaps_total=gap_total,
                    gaps_truncated=gap_total > len(gaps), action_authority='none',
                    limitations=['Findings describe observed files, not intent or compromise.',
                                 'Root-only locations, other accounts and in-memory persistence are not reviewed.',
                                 'Package updates and your own edits also add and change these files.'])


def summary(result):
    """Compact HUD form of a review: counts and the first findings and gaps, no inventory rows."""
    findings = [dict(rule=f['rule'], path=_text(f['path']), category=f['category'], attack=f['attack'],
                     detail=_text(f['detail']), action_status='not_attempted') for f in result['findings'][:SUMMARY_FINDINGS]]
    return dict(schema=SUMMARY_SCHEMA, reviewed_at=result['reviewed_at'], baseline_at=result['baseline_at'], trust=TRUST,
                items=len(result['items']), findings=findings, findings_total=result['findings_total'],
                gaps=[_text(gap) for gap in result['gaps'][:SUMMARY_GAPS]], gaps_total=result['gaps_total'],
                inventory_truncated=result['inventory_truncated'],
                incomplete_locations=len(result['incomplete_locations']), action_authority='none')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('action', choices=('review', 'baseline'))
    args = parser.parse_args(argv)
    try:
        manager = PersistenceReview()
        print(json.dumps(manager.record_baseline() if args.action == 'baseline' else manager.review(), indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        print('Persistence review unavailable: '+_text(exc))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
