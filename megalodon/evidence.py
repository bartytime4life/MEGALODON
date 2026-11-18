"""Collect a read-only, hashed evidence snapshot of this machine before anything changes.

``megalodon evidence collect`` saves what an investigator needs in the first
minutes after an alert, before a reboot, a cleanup or a response action
destroys it:

* **processes**: process and parent IDs, user, state, start time, program path,
  a SHA-256 of the running program (even when its file was deleted), working
  folder and socket count. Command lines only with ``--with-command-lines``,
  because they can contain passwords and tokens.
* **deleted or in-memory programs**: a copy of each running program whose file
  was deleted, lives only in memory or runs from a temporary folder, read
  from ``/proc/<pid>/exe``. That is often the only copy of a dropped tool.
  Copies are stored read-only and never executable.
* **network**: every TCP and UDP socket, with addresses, state and the
  processes holding it.
* **sessions**: logged-in users from utmp.
* **recent files**: files changed in the last ``--hours`` in temporary,
  program, configuration, startup and home folders, with metadata and a
  SHA-256 of each file up to 16 MiB.
* **reports**: the persistence, listener and log snapshots, the program
  package verification, the process-and-network review, and each watch's
  ``check`` against its baseline when one exists.

Each bundle is a new folder. Every file is listed in ``manifest.json`` with its
size and SHA-256, and the manifest's own SHA-256 is printed. Keep that digest
off the machine. Files are then made read-only. ``megalodon evidence verify``
re-checks a bundle against its manifest. Nothing on the machine is changed,
stopped or removed.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import stat
import struct

SCHEMA = 'megalodon-evidence-v1'
DEFAULT_ROOT = '~/.local/share/megalodon/evidence'
MAX_PROCESSES = 65536
MAX_HASH_FILE = 512 * 1024 * 1024
MAX_HASH_TOTAL = 4 * 1024 * 1024 * 1024
MAX_COPY_FILE = 64 * 1024 * 1024
MAX_COPY_TOTAL = 512 * 1024 * 1024
MAX_RECENT_FILES = 5000
MAX_RECENT_HASH = 16 * 1024 * 1024
MAX_WALK_ENTRIES = 500_000
MAX_CMDLINE = 4096
TEMPORARY = ('/tmp/', '/var/tmp/', '/dev/shm/')
# (folder, depth): where recently changed files matter most.
RECENT_ROOTS = (('/tmp', 6), ('/var/tmp', 6), ('/dev/shm', 6), ('/etc', 4), ('/usr/bin', 1), ('/usr/sbin', 1),
                ('/usr/local', 4), ('/usr/lib/systemd', 3), ('/var/spool/cron', 3), ('/root', 4), ('/home', 5),
                ('/opt', 4), ('/srv', 4), ('/var/www', 5))
SKIP_PREFIXES = ('/proc/', '/sys/', '/dev/pts/', '/run/user/')
UTMP_FORMAT = '<h2xi32s4s32s256shhiii16s20x'
UTMP_TYPES = {6: 'login', 7: 'user', 8: 'dead'}
TCP_STATES = {'01': 'established', '02': 'syn_sent', '03': 'syn_received', '04': 'fin_wait1', '05': 'fin_wait2',
              '06': 'time_wait', '07': 'close', '08': 'close_wait', '09': 'last_ack', '0A': 'listen',
              '0B': 'closing'}


class EvidenceError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc)


def _iso(moment):
    return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _text(path, limit=65536):
    try:
        with open(path, 'rb') as stream:
            return stream.read(limit).decode('utf-8', 'replace')
    except OSError:
        return None


class _Budget:
    def __init__(self, total):
        self.left = total


def _sha256_fd(fd, size_limit, budget):
    """SHA-256 of an open regular file, within the per-file and total budgets; else a reason."""
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        return None, 'not a regular file'
    if info.st_size > size_limit:
        return None, 'too large'
    if info.st_size > budget.left:
        return None, 'hashing budget reached'
    # The size is checked again while reading: a file that grows after fstat must not exceed either allowance.
    allowance, digest, read = min(size_limit, budget.left), hashlib.sha256(), 0
    while True:
        chunk = os.read(fd, min(1 << 20, allowance - read + 1))
        if not chunk:
            break
        read += len(chunk)
        if read > allowance:
            budget.left -= min(read, budget.left)
            return None, 'too large' if read > size_limit else 'hashing budget reached'
        digest.update(chunk)
    budget.left -= read
    return digest.hexdigest(), None


# ------------------------------------------------------------------ host

def host_info(root='/'):
    boot = _text(Path(root, 'proc/sys/kernel/random/boot_id'))
    uptime = _text(Path(root, 'proc/uptime'))
    return dict(hostname=socket.gethostname() if root == '/' else (_text(Path(root, 'etc/hostname')) or '').strip(),
                kernel=platform.release() if root == '/' else None,
                boot_id=(boot or '').strip() or None,
                uptime_seconds=float(uptime.split()[0]) if uptime else None,
                collector_uid=os.geteuid())


# ------------------------------------------------------------------ processes

def _boot_time(root):
    for line in (_text(Path(root, 'proc/stat')) or '').splitlines():
        if line.startswith('btime '):
            return int(line.split()[1])
    return None


def _flags(path):
    flags = []
    if path and path.endswith(' (deleted)'):
        flags.append('deleted')
    if path and path.startswith('/memfd:'):
        flags.append('in_memory')
    if path and path.replace(' (deleted)', '').startswith(TEMPORARY):
        flags.append('temporary')
    return flags


def processes(root='/', *, command_lines=False, budget=None, copies=None):
    """Every visible process; programs are hashed once per file identity."""
    budget = budget or _Budget(MAX_HASH_TOTAL)
    proc = Path(root, 'proc')
    boot, ticks = _boot_time(root), os.sysconf('SC_CLK_TCK') if hasattr(os, 'sysconf') else 100
    hashed: dict[tuple, dict] = {}
    found, unreadable = [], 0
    try:
        pids = sorted((int(e.name) for e in os.scandir(proc) if e.name.isdigit()))[:MAX_PROCESSES]
    except OSError:
        return [], ['/proc could not be listed']
    for pid in pids:
        base = proc / str(pid)
        raw = _text(base / 'stat')
        if raw is None:
            continue
        # comm is in parentheses and may itself contain them.
        comm, rest = raw[raw.find('(') + 1:raw.rfind(')')], raw[raw.rfind(')') + 2:].split()
        item = dict(pid=pid, ppid=int(rest[1]) if len(rest) > 1 else None, state=rest[0] if rest else None,
                    name=comm[:64])
        if boot and len(rest) > 19:
            item['started_at'] = _iso(datetime.fromtimestamp(boot + int(rest[19]) / ticks, timezone.utc))
        status = _text(base / 'status') or ''
        for line in status.splitlines():
            if line.startswith('Uid:'):
                item['uid'] = int(line.split()[1])
        try:
            exe = os.readlink(base / 'exe')
        except OSError:
            exe = None
            unreadable += 1
        item['program'] = exe
        flags = _flags(exe)
        if flags:
            item['flags'] = flags
        try:
            item['cwd'] = os.readlink(base / 'cwd')
        except OSError:
            pass
        try:
            descriptors = os.listdir(base / 'fd')
        except OSError:
            descriptors = None
        if descriptors is not None:
            held = []
            for fd in descriptors:
                try:  # A descriptor can close between listing and reading; skip only that one.
                    target = os.readlink(base / 'fd' / fd)
                except OSError:
                    continue
                if target.startswith('socket:[') and target[8:-1].isdigit():
                    held.append(int(target[8:-1]))
            item['sockets'] = sorted(held)[:4096]
        if command_lines:
            raw_cmd = _text(base / 'cmdline', MAX_CMDLINE)
            if raw_cmd is not None:
                item['command_line'] = raw_cmd.rstrip('\0').split('\0')
        if exe:
            try:
                fd = os.open(base / 'exe', os.O_RDONLY | os.O_CLOEXEC)
            except OSError:
                fd = None
            if fd is not None:
                try:
                    info = os.fstat(fd)
                    identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                    if identity not in hashed:
                        digest, reason = _sha256_fd(fd, MAX_HASH_FILE, budget)
                        hashed[identity] = dict(sha256=digest) if digest else dict(hash_skipped=reason)
                        if digest and flags and copies is not None:
                            copies.append(dict(pid=pid, program=exe, sha256=digest, size=info.st_size))
                    item.update(hashed[identity])
                finally:
                    os.close(fd)
        found.append(item)
    gaps = []
    if unreadable and os.geteuid() != 0:
        gaps.append(f'{unreadable} processes of other accounts were not readable; run as root to cover them')
    return found, gaps


def copy_programs(copies, folder, root='/'):
    """Copy deleted, in-memory and temporary-folder programs from /proc/<pid>/exe, read-only."""
    saved, left = [], MAX_COPY_TOTAL
    seen = set()
    for item in copies:
        if item['sha256'] in seen:
            continue
        seen.add(item['sha256'])
        if item['size'] > MAX_COPY_FILE or item['size'] > left:
            saved.append(dict(item, copied=False, reason='too large for the copy budget'))
            continue
        target = folder / f"{item['sha256']}.bin"
        try:
            source = os.open(Path(root, 'proc', str(item['pid']), 'exe'), os.O_RDONLY | os.O_CLOEXEC)
        except OSError as exc:
            saved.append(dict(item, copied=False, reason=exc.strerror))
            continue
        try:
            out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
            digest, written, allowance = hashlib.sha256(), 0, min(MAX_COPY_FILE, left)
            try:
                # Never copy more than the allowance, even if the program grew since it was hashed.
                while written <= allowance:
                    chunk = os.read(source, min(1 << 20, allowance - written + 1))
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > allowance:
                        break
                    digest.update(chunk)
                    os.write(out, chunk)
            finally:
                os.close(out)
        finally:
            os.close(source)
        left -= min(written, allowance)
        if written > allowance:
            saved.append(dict(item, copied=False, file=f'programs/{target.name}',
                              reason='the program grew past the copy budget while it was copied'))
            continue
        copied = digest.hexdigest() == item['sha256']
        saved.append(dict(item, copied=copied, file=f'programs/{target.name}',
                          **({} if copied else dict(reason='the program changed while it was copied'))))
    return saved


# ------------------------------------------------------------------ network and sessions

def network(root='/', process_list=()):
    from .process_network import TABLES, _endpoint, _read_table, _shown
    owners: dict[int, list] = {}
    for item in process_list:
        for inode in item.get('sockets', ()):
            owners.setdefault(inode, []).append(item['pid'])
    sockets, gaps = [], []
    for protocol, family, name, length in TABLES:
        try:
            lines, complete = _read_table(Path(root, 'proc/net', name))
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            gaps.append(f'/proc/net/{name} could not be read')
            continue
        if not complete:
            gaps.append(f'/proc/net/{name} was too large to read whole')
        for line in lines:
            fields = line.split()
            if len(fields) < 10:
                continue
            local, remote = _endpoint(fields[1], length), _endpoint(fields[2], length)
            if local is None or remote is None:
                continue
            inode = int(fields[9]) if fields[9].isdigit() else 0
            sockets.append(dict(protocol=protocol, family=family, local=_shown(*local), remote=_shown(*remote),
                                state=TCP_STATES.get(fields[3], fields[3]) if protocol == 'tcp' else None,
                                uid=int(fields[7]) if fields[7].isdigit() else None, inode=inode,
                                pids=owners.get(inode, [])))
    return sockets, gaps


def sessions(root='/'):
    size = struct.calcsize(UTMP_FORMAT)
    for path in ('run/utmp', 'var/run/utmp'):
        try:
            data = Path(root, path).read_bytes()
        except OSError:
            continue
        found = []
        for offset in range(0, len(data) - size + 1, size):
            kind, pid, line, _, user, host, _, _, _, seconds, _, _ = struct.unpack_from(UTMP_FORMAT, data, offset)
            if kind not in (6, 7):
                continue
            found.append(dict(type=UTMP_TYPES[kind], pid=pid, user=user.rstrip(b'\0').decode('utf-8', 'replace'),
                              line=line.rstrip(b'\0').decode('utf-8', 'replace'),
                              host=host.rstrip(b'\0').decode('utf-8', 'replace'),
                              since=_iso(datetime.fromtimestamp(seconds, timezone.utc)) if seconds else None))
        return found, []
    return [], ['no utmp session record found']


# ------------------------------------------------------------------ recent files

def recent_files(root='/', *, hours=24, now=None, budget=None):
    now = now or _now()
    cutoff = (now - timedelta(hours=hours)).timestamp()
    budget = budget or _Budget(512 * 1024 * 1024)
    found, gaps, walked = [], [], 0
    real_root = os.path.realpath(root)

    def shown(path):
        return path if real_root == '/' else '/' + os.path.relpath(path, real_root)
    for folder, depth in RECENT_ROOTS:
        base = os.path.join(real_root, folder.lstrip('/'))
        if not os.path.isdir(base) or os.path.islink(base):
            continue
        stack = [(base, 0)]
        while stack and walked < MAX_WALK_ENTRIES and len(found) < MAX_RECENT_FILES:
            directory, level = stack.pop()
            try:
                entries = os.scandir(directory)
            except OSError:
                continue
            with entries:
                for entry in entries:
                    # Both limits hold inside a single directory too: a flat /tmp can hold millions of entries.
                    if walked >= MAX_WALK_ENTRIES or len(found) >= MAX_RECENT_FILES:
                        break
                    walked += 1
                    path = shown(entry.path)
                    if path.startswith(SKIP_PREFIXES):
                        continue
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        if level < depth:
                            stack.append((entry.path, level + 1))
                        continue
                    if max(info.st_mtime, info.st_ctime) < cutoff:
                        continue
                    item = dict(path=path, size=info.st_size, mode=oct(stat.S_IMODE(info.st_mode)), uid=info.st_uid,
                                modified=_iso(datetime.fromtimestamp(info.st_mtime, timezone.utc)),
                                changed=_iso(datetime.fromtimestamp(info.st_ctime, timezone.utc)))
                    if stat.S_ISLNK(info.st_mode):
                        try:
                            item['link'] = os.readlink(entry.path)
                        except OSError:
                            pass
                    elif stat.S_ISREG(info.st_mode):
                        try:
                            fd = os.open(entry.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                            try:
                                digest, reason = _sha256_fd(fd, MAX_RECENT_HASH, budget)
                            finally:
                                os.close(fd)
                            item.update(dict(sha256=digest) if digest else dict(hash_skipped=reason))
                        except OSError:
                            item['hash_skipped'] = 'unreadable'
                    else:
                        item['kind'] = 'special'
                    found.append(item)
    if len(found) >= MAX_RECENT_FILES or walked >= MAX_WALK_ENTRIES:
        gaps.append('the recent-file scan reached its limit; older or deeper changes were not listed')
    return sorted(found, key=lambda f: f['changed'], reverse=True), gaps


# ------------------------------------------------------------------ watch reports

def reports(root='/', *, verify_programs=True):
    """Snapshots that need no baseline, plus each watch's check where a baseline exists."""
    out, gaps = {}, []

    def attempt(name, function):
        try:
            out[name] = function()
        except Exception as exc:  # Evidence collection reports a broken source instead of stopping.
            gaps.append(f'{name}: {type(exc).__name__}: {exc}'[:300])
    from . import binary_integrity, listener_watch, log_integrity, persistence_watch, process_network
    attempt('process_network_review', lambda: process_network.review(root))
    attempt('persistence_snapshot', lambda: persistence_watch.snapshot(root=root))
    attempt('listener_snapshot', lambda: listener_watch.snapshot(root=root))
    attempt('log_snapshot', lambda: log_integrity.snapshot(root=root))
    if verify_programs:
        attempt('program_verification', lambda: binary_integrity.verify(root=root))
    if root == '/':
        for name, module in (('persistence_check', persistence_watch), ('listener_check', listener_watch),
                             ('program_check', binary_integrity), ('log_check', log_integrity)):
            if Path(module.DEFAULT_MANIFEST).expanduser().exists():
                attempt(name, lambda module=module: module.check(Path(module.DEFAULT_MANIFEST).expanduser()))
    return out, gaps


# ------------------------------------------------------------------ bundle

def _write(folder, name, value):
    path = folder / name
    data = (json.dumps(value, indent=1, sort_keys=True, default=str) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def _file_digest(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def collect(*, output=None, root='/', hours=24, command_lines=False, verify_programs=True,
            copy_suspicious=True, now=None):
    """Write one sealed evidence bundle; returns its summary."""
    now = now or _now()
    base = Path(output).expanduser() if output else Path(DEFAULT_ROOT).expanduser() / now.strftime('%Y%m%dT%H%M%SZ')
    if base.exists():
        raise EvidenceError(f'{base} already exists; evidence bundles are never overwritten')
    base.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    base.mkdir(mode=0o700)
    gaps = []
    budget = _Budget(MAX_HASH_TOTAL)
    copies = [] if copy_suspicious else None
    started = _now()
    process_list, found = processes(root, command_lines=command_lines, budget=budget, copies=copies)
    gaps += found
    saved = []
    if copies:
        (base / 'programs').mkdir(mode=0o700)
        saved = copy_programs(copies, base / 'programs', root)
    sockets, found = network(root, process_list)
    gaps += found
    users, found = sessions(root)
    gaps += found
    files, found = recent_files(root, hours=hours, now=now)
    gaps += found
    watch, found = reports(root, verify_programs=verify_programs)
    gaps += found
    _write(base, 'processes.json', process_list)
    _write(base, 'network.json', sockets)
    _write(base, 'sessions.json', users)
    _write(base, 'recent_files.json', files)
    _write(base, 'programs.json', saved)
    for name, value in watch.items():
        _write(base, f'report_{name}.json', value)
    listed = []
    for path in sorted(p for p in base.rglob('*') if p.is_file()):
        listed.append(dict(file=str(path.relative_to(base)), size=path.stat().st_size, sha256=_file_digest(path)))
    manifest = dict(schema=SCHEMA, collected_at=_iso(now), finished_at=_iso(_now()),
                    seconds=round((_now() - started).total_seconds(), 1), host=host_info(root),
                    options=dict(hours=hours, command_lines=command_lines, verify_programs=verify_programs,
                                 copy_suspicious=copy_suspicious),
                    counts=dict(processes=len(process_list), sockets=len(sockets), sessions=len(users),
                                recent_files=len(files), programs_copied=sum(1 for s in saved if s.get('copied')),
                                reports=len(watch)),
                    gaps=gaps, files=listed,
                    note='Read-only snapshot; nothing on the machine was changed. Keep manifest_sha256 off the machine.')
    _write(base, 'manifest.json', manifest)
    digest = _file_digest(base / 'manifest.json')
    _seal(base)
    return dict(schema=SCHEMA, action='collect', bundle=str(base), manifest_sha256=digest, counts=manifest['counts'],
                gaps=gaps, seconds=manifest['seconds'],
                note='Keep manifest_sha256 somewhere off this machine; megalodon evidence verify checks the bundle.')


def _seal(base):
    """Make every file read-only and the folders unwritable, so the bundle is not changed by accident."""
    for path in sorted(base.rglob('*'), key=lambda p: len(p.parts), reverse=True):
        os.chmod(path, 0o500 if path.is_dir() else 0o400)
    os.chmod(base, 0o500)


def verify(bundle, *, expected=None):
    """Re-check every file of a bundle against its manifest (and the manifest against `expected`)."""
    base = Path(bundle).expanduser()
    manifest_path = base / 'manifest.json'
    try:
        digest = _file_digest(manifest_path)
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise EvidenceError(f'{manifest_path} cannot be read: {exc}') from None
    if not isinstance(manifest, dict) or manifest.get('schema') != SCHEMA:
        raise EvidenceError('not a MEGALODON evidence bundle')
    problems = []
    if expected and expected.lower() != digest:
        problems.append(dict(file='manifest.json', problem='differs from the expected digest'))
    listed = {item['file']: item for item in manifest.get('files', [])}
    present = {str(p.relative_to(base)) for p in base.rglob('*') if p.is_file()} - {'manifest.json'}
    for name in sorted(set(listed) | present):
        if name not in listed:
            problems.append(dict(file=name, problem='not in the manifest'))
        elif name not in present:
            problems.append(dict(file=name, problem='missing'))
        elif _file_digest(base / name) != listed[name]['sha256']:
            problems.append(dict(file=name, problem='changed'))
    return dict(schema=SCHEMA, action='verify', bundle=str(base), manifest_sha256=digest,
                collected_at=manifest.get('collected_at'), files=len(listed), intact=not problems, problems=problems)
