"""Hardening drift: protections that get weaker, and quiet ways back to root.

The hardening review reads the machine's protections once. Attackers who get in
lower them so they can stay: they turn ptrace back on, allow root over SSH, or
leave a back door that no account or service shows (ATT&CK T1562, T1548, T1574).
`megalodon hardening` records the protections and reports what gets weaker:

* every hardening review check (kernel parameters, the SSH daemon, automatic
  updates and exposed listeners) that goes from passing to failing;
* file capabilities, a root back door that the setuid checks miss:
  `cap_setuid` on a copy of Python lets anyone who runs it become root;
* folders on root's command search path, and the programs in them, that an
  ordinary account can write to: whatever it plants there, root later runs.

Read-only: settings, file attributes and permissions are only read.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import stat
import struct
import tempfile
import time

from .container_watch import CAPS
from .process_network import TEMPORARY, _program_kind

SCHEMA = 'megalodon-hardening-drift-v1'
REPORT_SCHEMA = 'megalodon-hardening-drift-report-v1'
DEFAULT_MANIFEST = '~/.config/megalodon/hardening.json'
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_FILES = 2_000_000
MAX_SECONDS = 120
RANK = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
ORDER = {'pass': 0, 'review': 1, 'fail': 2}
# How bad each check getting worse is; the rest are MEDIUM.
HIGH_CHECKS = frozenset({'aslr', 'kptr_restrict', 'ptrace_scope', 'protected_symlinks', 'protected_hardlinks',
                         'suid_dumpable', 'ssh_root_login', 'ssh_password_auth', 'ssh_empty_passwords'})
# The command search path root's sessions, sudo and services use when nothing else is set.
DEFAULT_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
# Any one of these on a file is a way to root.
ROOT_CAPS = frozenset({'CHOWN', 'DAC_OVERRIDE', 'DAC_READ_SEARCH', 'FOWNER', 'SETGID', 'SETUID', 'SYS_MODULE',
                       'SYS_RAWIO', 'SYS_PTRACE', 'SYS_ADMIN', 'SETFCAP', 'BPF'})
# Not walked: kernel views, other machines' files and container image layers.
SKIP = ('/proc', '/sys', '/run', '/var/lib/docker', '/var/lib/containers', '/var/lib/containerd',
        '/snap', '/var/lib/snapd/snaps')
# Overlay is local too: it is how containers and live systems mount their root.
LOCAL = frozenset({'overlay', 'ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'f2fs', 'jfs', 'reiserfs', 'zfs', 'bcachefs',
                   'tmpfs',
                   'vfat', 'exfat', 'ntfs', 'ntfs3'})

RULES = {
    'FILE_CAPABILITY_BACKDOOR': ('CRITICAL', ['T1548'],
                                 'A shell, script interpreter or program in a temporary or home folder holds a file '
                                 'capability that leads to root: anyone who runs it becomes root.'),
    'PROGRAM_WRITABLE': ('HIGH', ['T1574.009'], 'A program on root\'s command search path can be changed by an '
                                                'ordinary account.'),
    'PATH_FOLDER_WRITABLE': ('HIGH', ['T1574.007'], 'A folder on root\'s command search path, or one above it, can be '
                                                    'written by an ordinary account: what it plants there, root runs.'),
    'PATH_HAS_RELATIVE_ENTRY': ('HIGH', ['T1574.007'], 'Root\'s command search path has an empty or relative entry, '
                                                       'so root runs programs from whatever folder it is in.'),
    'FILE_CAPABILITY_ADDED': ('HIGH', ['T1548'], 'A program gained a file capability that leads to root.'),
    'HARDENING_WEAKENED': ('HIGH', ['T1562.001'], 'A protection the hardening review checks got weaker.'),
    'FILE_CAPABILITY_CHANGED': ('MEDIUM', ['T1548'], 'A program gained or changed a file capability.'),
}


class HardeningError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


# ------------------------------------------------------------------ file capabilities

def capabilities(raw):
    """Capability names a security.capability value grants, '+e' when effective; None if it cannot be read."""
    if len(raw) < 12:
        return None
    magic, low = struct.unpack_from('<II', raw, 0)
    version = magic & 0xFF000000
    high = struct.unpack_from('<I', raw, 12)[0] if version in (0x02000000, 0x03000000) and len(raw) >= 20 else 0
    permitted = low | high << 32
    names = [CAPS[i] if i < len(CAPS) else str(i) for i in range(64) if permitted >> i & 1]
    return sorted(names), bool(magic & 1)


def _mounts(root):
    """{mountpoint: fstype} from the host's mount table."""
    found = {}
    try:
        text = Path(root, 'proc/self/mountinfo').read_text('utf-8', 'replace')
    except OSError:
        return found
    for line in text.splitlines():
        fields = line.split(' ')
        if '-' in fields and len(fields) > fields.index('-') + 1:
            found[fields[4].replace('\\040', ' ')] = fields[fields.index('-') + 1]
    return found


def file_capabilities(root='/', *, budget=MAX_SECONDS):
    """{path: {caps, effective}} for every file with a capability on the local filesystems, and gaps."""
    found, gaps, seen = {}, [], 0
    real = os.path.realpath(root)
    # The root file system is always searched, whatever it is; other network and FUSE mounts are not.
    remote = {point for point, kind in _mounts(root).items() if kind not in LOCAL and point != '/'}
    skipped = set()
    started = time.monotonic()
    stack = [real]
    while stack:
        folder = stack.pop()
        shown = '/' + os.path.relpath(folder, real).lstrip('.').lstrip('/')
        if shown == '/dev':
            stack.append(os.path.join(folder, 'shm'))      # of /dev, only shared memory holds files
            continue
        if shown in remote:
            skipped.add(shown)
            continue
        if any(shown == s or shown.startswith(s + '/') for s in SKIP):
            continue
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        for entry in entries:
            seen += 1
            if seen > MAX_FILES or time.monotonic() - started > budget:
                gaps.append(f'only part of the file system was searched for file capabilities '
                            f'({seen - 1} files in {int(time.monotonic() - started)} s)')
                return found, gaps
            try:
                if entry.is_dir(follow_symlinks=False):
                    stack.append(entry.path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                raw = os.getxattr(entry.path, 'security.capability', follow_symlinks=False)
            except OSError:
                continue
            decoded = capabilities(raw)
            if decoded:
                path = '/' + os.path.relpath(entry.path, real)
                found[path] = dict(caps=decoded[0], effective=decoded[1])
    if skipped:
        gaps.append(f'{len(skipped)} network or FUSE mounts were not searched for file capabilities: '
                    + ', '.join(sorted(skipped)[:8]))
    return found, gaps


def _backdoor(path, caps):
    if not ROOT_CAPS & set(caps):
        return False
    return (_program_kind(path, '') is not None or path.startswith(TEMPORARY) or path.startswith('/home/')
            or path.startswith('/root/'))


# ------------------------------------------------------------------ the command search path

def _paths(root):
    """[(where it is set, PATH value)] for root's sessions, sudo and services."""
    found = [('default', DEFAULT_PATH)]

    def read(path):
        try:
            return Path(root, path.lstrip('/')).read_text('utf-8', 'replace')
        except OSError:
            return ''
    for line in read('/etc/environment').splitlines():
        match = re.match(r'\s*PATH\s*=\s*"?([^"\n]*)"?', line)
        if match:
            found.append(('/etc/environment', match.group(1)))
    for line in read('/etc/login.defs').splitlines():
        match = re.match(r'\s*ENV_SUPATH\s+(?:PATH=)?(\S+)', line)
        if match:
            found.append(('/etc/login.defs ENV_SUPATH', match.group(1)))
    sudoers = ['/etc/sudoers']
    try:
        sudoers += sorted('/etc/sudoers.d/' + n for n in os.listdir(Path(root, 'etc/sudoers.d')))[:64]
    except OSError:
        pass
    for name in sudoers:
        for line in read(name).splitlines():
            match = re.match(r'\s*Defaults\s+secure_path\s*=\s*"?([^"\n]*)"?', line)
            if match:
                found.append((f'{name} secure_path', match.group(1)))
    found += _shell_paths(read)
    found += _cron_paths(root, read)
    found += _service_paths(root, read)
    return found


ROOT_SHELL_FILES = ('/root/.profile', '/root/.bash_profile', '/root/.bash_login', '/root/.bashrc', '/root/.zshenv',
                    '/root/.zprofile', '/root/.zshrc')
_SHELL_PATH = re.compile(r'^\s*(?:export\s+)?PATH=(.*)$')
UNIT_FOLDERS = ('/etc/systemd/system', '/run/systemd/system', '/usr/local/lib/systemd/system', '/usr/lib/systemd/system',
                '/lib/systemd/system')
MAX_UNITS = 4096


def _shell_paths(read):
    """PATH as root's own login and shell files set it. `$HOME` and `~` are /root, and `$PATH` is the path it
    extends, already read. A part built from any other variable or a command is unknown and left out."""
    found = []
    for name in ROOT_SHELL_FILES:
        for line in read(name).splitlines():
            match = _SHELL_PATH.match(line.split(' #', 1)[0].strip().rstrip(';'))
            if not match:
                continue
            value = match.group(1).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
                value = value[1:-1]
            parts = []
            for part in value.split(':'):
                part = re.sub(r'^~(?=/|$)', '/root', part.replace('${HOME}', '/root').replace('$HOME', '/root'))
                if '$' in part or '`' in part:
                    continue            # $PATH is the path already read; any other variable is unknown
                parts.append(part)
            if parts:
                found.append((f'{name} PATH', ':'.join(parts)))
    return found


def _cron_paths(root, read):
    """PATH set in the system crontab, /etc/cron.d and root's own crontab, for the jobs there."""
    files = ['/etc/crontab', '/var/spool/cron/crontabs/root', '/var/spool/cron/root']
    try:
        files += sorted('/etc/cron.d/' + n for n in os.listdir(Path(root, 'etc/cron.d'))
                        if not n.startswith('.'))[:256]
    except OSError:
        pass
    found = []
    for name in files:
        for line in read(name).splitlines():
            match = re.match(r'\s*PATH\s*=\s*(.*)$', line)
            if match:
                found.append((f'{name} PATH', match.group(1).strip().strip('"\'')))
    return found


def _assignments(text):
    """The VAR=value pairs on one systemd Environment= line, quoted or not."""
    try:
        words = shlex.split(text, posix=True)
    except ValueError:
        return []
    return [word.split('=', 1) for word in words if '=' in word]


def _service_paths(root, read):
    """PATH for every service: systemd's default environment, and the PATH each service that runs as root sets
    itself, in its unit file, its drop-ins or an environment file they name."""
    found = []
    defaults = ['/etc/systemd/system.conf']
    try:
        defaults += sorted('/etc/systemd/system.conf.d/' + n for n in os.listdir(Path(root, 'etc/systemd/system.conf.d'))
                           if n.endswith('.conf'))
    except OSError:
        pass
    for name in defaults:
        for line in read(name).splitlines():
            match = re.match(r'\s*DefaultEnvironment\s*=\s*(.*)$', line)
            for key, value in _assignments(match.group(1)) if match else ():
                if key == 'PATH':
                    found.append((f'{name} DefaultEnvironment', value))
    units = {}                      # name: its file, from the folder that takes precedence
    drop_ins = {}                   # name: {drop-in file name: path}, the first folder's copy winning
    for folder in UNIT_FOLDERS:
        try:
            names = sorted(os.listdir(Path(root, folder.lstrip('/'))))
        except OSError:
            continue
        for name in names:
            if name.endswith('.service') and name not in units:
                units[name] = f'{folder}/{name}'
            elif name.endswith('.service.d'):
                try:
                    confs = sorted(n for n in os.listdir(Path(root, folder.lstrip('/'), name)) if n.endswith('.conf'))
                except OSError:
                    continue
                for conf in confs:
                    drop_ins.setdefault(name[:-2], {}).setdefault(conf, f'{folder}/{name}/{conf}')
    for name in sorted(units)[:MAX_UNITS]:
        files = [units[name]] + [path for _conf, path in sorted(drop_ins.get(name, {}).items())]
        user, path, where, in_unit = None, None, None, True
        for file in files:
            section = None
            for line in read(file).splitlines():
                line = line.strip()
                if line.startswith('['):
                    section = line
                    continue
                if section != '[Service]' or '=' not in line or line.startswith(('#', ';')):
                    continue
                key, _, value = (part.strip() for part in line.partition('='))
                if key == 'User':
                    user = value or None
                elif key == 'DynamicUser' and value.lower() in ('yes', 'true', '1', 'on'):
                    user = 'dynamic'
                elif key == 'Environment':
                    if not value:
                        path = None                                   # an empty assignment resets the list
                    for env_key, env_value in _assignments(value):
                        if env_key == 'PATH':
                            path, where, in_unit = env_value, f'{file} Environment', True
                elif key == 'EnvironmentFile' and value:
                    env_file = value.lstrip('-')
                    if env_file.startswith('/'):
                        for env_line in read(env_file).splitlines():
                            match = re.match(r'\s*(?:export\s+)?PATH\s*=\s*(.*)$', env_line)
                            if match:
                                path, where, in_unit = match.group(1).strip().strip('"\''), \
                                    f'{env_file} (EnvironmentFile of {name})', False
        if path is None or user not in (None, 'root', '0'):
            continue                # the default path, or a service that does not run as root
        # In a unit file, %h is the home of the account the service runs as: root's. A part with any other
        # specifier, or with one in an environment file, is not known for certain and is left out.
        parts = [part.replace('%h', '/root') if in_unit else part for part in path.split(':')]
        found.append((f'{name}: {where}', ':'.join(part for part in parts if '%' not in part)))
    return found


TRUSTED_UID, TRUSTED_GID = 0, 0


def _resolve(real, path):
    """Where `path` leads, following symlinks inside `real` (absolute targets start from it), or None."""
    parts, done, hops = [p for p in path.split('/') if p], [], 0
    while parts:
        part = parts.pop(0)
        if part == '..':
            done = done[:-1]
            continue
        if part == '.':
            continue
        here = os.path.join(real, *done, part)
        try:
            target = os.readlink(here)
        except OSError:
            done.append(part)
            continue
        hops += 1
        if hops > 40:
            return None
        if target.startswith('/'):
            done = []
        parts = [p for p in target.split('/') if p] + parts
    return '/' + '/'.join(done)


def _writable_by_others(info):
    """Whether an account other than root can change this file or folder."""
    return info.st_uid != TRUSTED_UID or bool(info.st_mode & 0o002) or \
        bool(info.st_mode & 0o020 and info.st_gid != TRUSTED_GID)


def _sticky_protects(info, child):
    """Whether a writable folder's sticky bit keeps others from swapping the folder below it on the way to a path
    entry. With the sticky bit, only an entry's owner, the folder's owner or root can rename or remove the entry, so
    a root-owned folder in a root-owned sticky folder stays put. If the folder below does not exist yet, anyone who
    can write here can create it, if another account owns it, that account can move it, and if it is a link, the
    links it leads through may not be root's."""
    if not info.st_mode & stat.S_ISVTX or info.st_uid != TRUSTED_UID or child is None:
        return False
    try:
        below = os.lstat(child)
    except OSError:
        return False
    # A link below only names somewhere else: the chain it leads through, which may run through links another
    # account owns, is not protected by this folder's sticky bit.
    return below.st_uid == TRUSTED_UID and not stat.S_ISLNK(below.st_mode)


def _who(info):
    if info.st_mode & 0o002:
        return 'everyone'
    if info.st_uid != TRUSTED_UID:
        return f'its owner, UID {info.st_uid}'
    return f'group {info.st_gid}'


def search_path(root='/'):
    """Writable folders on root's command search path, writable programs in them, and relative entries."""
    real = os.path.realpath(root)
    folders, programs, relative = {}, {}, {}
    entries = {}
    for where, value in _paths(root):
        for item in value.split(':'):
            if not item.startswith('/'):
                relative.setdefault(item or '(empty)', where)
            else:
                entries.setdefault(os.path.normpath(item), where)
    for folder, where in sorted(entries.items()):
        # The folder and every one above it: whoever can rename a parent can swap the folder. A folder that is a
        # symlink is walked twice: up from its own path, and up from where it leads.
        for start in dict.fromkeys(p for p in (folder, _resolve(real, folder)) if p):
            current, child = start, None
            while True:
                try:
                    info = os.stat(Path(real, current.lstrip('/')), follow_symlinks=True)
                except OSError:
                    info = None
                # The path entry itself is reported whenever another account can write to it: anyone who can add a
                # file there can add a program. A folder above it only matters if the way down can be swapped.
                if info is not None and stat.S_ISDIR(info.st_mode) and _writable_by_others(info) and \
                        not _sticky_protects(info, child):
                    folders.setdefault(current, dict(on_path=folder, set_in=where, writable_by=_who(info)))
                if current == '/':
                    break
                child = Path(real, current.lstrip('/'))
                current = os.path.dirname(current)
        try:
            names = sorted(os.listdir(Path(real, folder.lstrip('/'))))[:8192]
        except OSError:
            continue
        for name in names:
            path = os.path.join(folder, name)
            try:
                info = os.stat(Path(real, path.lstrip('/')), follow_symlinks=True)
            except OSError:
                continue
            if stat.S_ISREG(info.st_mode) and info.st_mode & 0o111 and _writable_by_others(info):
                programs.setdefault(path, dict(writable_by=_who(info)))
    return folders, programs, relative


# ------------------------------------------------------------------ snapshot, baseline and check

def snapshot(*, root='/', review=None, budget=MAX_SECONDS):
    from . import hardening_review
    rows = (review or hardening_review.review)(root)['checks']
    checks = {r['id']: dict(state=r['state'], observed=r['observed'], title=r['title']) for r in rows}
    caps, gaps = file_capabilities(root, budget=budget)
    folders, programs, relative = search_path(root)
    return dict(checks=checks, capabilities=caps, folders=folders, programs=programs, relative=relative, gaps=gaps)


def _write(path, value):
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.hardening-', dir=path.parent)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, sort_keys=True, separators=(',', ':'))
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
        raise HardeningError(f'no hardening baseline at {path}; run megalodon hardening baseline') from None
    except OSError as exc:
        raise HardeningError(f'hardening baseline {path} cannot be opened: {exc.strerror}') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise HardeningError(f'hardening baseline {path} must be a mode-600 file owned by you')
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    try:
        value = json.loads(raw)
    except ValueError:
        raise HardeningError('hardening baseline is not valid JSON') from None
    if type(value) is not dict or value.get('schema') != SCHEMA or type(value.get('checks')) is not dict:
        raise HardeningError('hardening baseline has an unsupported format')
    return value


def _finding(rule, subject, detail, severity=None, **extra):
    default, techniques, summary = RULES[rule]
    return dict(rule_id=rule, severity=severity or default, techniques=techniques, subject=subject, detail=detail,
                summary=summary, **extra)


def compare(old, new):
    """Findings for what got weaker since `old`; with old None, only what is already a back door."""
    findings = []
    first = old is None
    old = old or dict(checks={}, capabilities={}, folders={}, programs={}, relative={})
    for check, now in sorted(new['checks'].items()):
        was = old['checks'].get(check)
        if was and was['state'] in ORDER and now['state'] in ORDER and ORDER[now['state']] > ORDER[was['state']]:
            findings.append(_finding('HARDENING_WEAKENED', f'hardening:{check}',
                                     f"{now['title']}: {was['observed']} → {now['observed']} "
                                     f"({was['state']} → {now['state']})",
                                     severity='HIGH' if check in HIGH_CHECKS else 'MEDIUM', check=check))
    for path, entry in sorted(new['capabilities'].items()):
        was = old['capabilities'].get(path, {})
        before = set(was.get('caps', []))
        # A capability that was only permitted and is now also effective is switched on: count it as added.
        if was and entry['effective'] and not was.get('effective'):
            before = set()
        added = sorted(set(entry['caps']) - before)
        if not added or (first and not _backdoor(path, entry['caps'])):
            continue
        text = f"{path} holds cap_{', cap_'.join(c.lower() for c in entry['caps'])}" \
               f"{'+ep' if entry['effective'] else '+p'}"
        if _backdoor(path, added):
            findings.append(_finding('FILE_CAPABILITY_BACKDOOR', f'file:{path}', text, path=path, caps=entry['caps']))
        elif ROOT_CAPS & set(added):
            findings.append(_finding('FILE_CAPABILITY_ADDED', f'file:{path}', text, path=path, caps=entry['caps']))
        else:
            findings.append(_finding('FILE_CAPABILITY_CHANGED', f'file:{path}', text, path=path, caps=entry['caps']))
    if not first:
        for folder, entry in sorted(new['folders'].items()):
            if folder not in old['folders']:
                findings.append(_finding('PATH_FOLDER_WRITABLE', f'file:{folder}',
                                         f"{folder} can be written by {entry['writable_by']} "
                                         f"(on the search path through {entry['on_path']}, set in {entry['set_in']})",
                                         severity='CRITICAL' if entry['writable_by'] == 'everyone' else None,
                                         path=folder))
        for program, entry in sorted(new['programs'].items()):
            if program not in old['programs']:
                findings.append(_finding('PROGRAM_WRITABLE', f'file:{program}',
                                         f"{program} can be changed by {entry['writable_by']}",
                                         severity='CRITICAL' if entry['writable_by'] == 'everyone' else None,
                                         path=program))
        for item, where in sorted(new['relative'].items()):
            if item not in old['relative']:
                findings.append(_finding('PATH_HAS_RELATIVE_ENTRY', f'path:{item}',
                                         f'root\'s search path has the entry {item!r}, set in {where}'))
    findings.sort(key=lambda f: (RANK.index(f['severity']), f['subject']))
    return findings


def _counts(state):
    return dict(checks=len(state['checks']), file_capabilities=len(state['capabilities']),
                writable_folders=len(state['folders']), writable_programs=len(state['programs']))


def baseline(manifest=DEFAULT_MANIFEST, *, replace=False, root='/', review=None, budget=MAX_SECONDS):
    path = Path(manifest).expanduser()
    if path.exists() and not replace:
        raise HardeningError(f'{path} exists; use accept to record the reviewed state')
    state = snapshot(root=root, review=review, budget=budget)
    _write(path, dict(schema=SCHEMA, recorded_at=_now(), root=os.path.realpath(root),
                      **{k: v for k, v in state.items() if k != 'gaps'}))
    # A back door already in place is reported now, not recorded as normal; so is what is already exposed.
    return dict(schema=REPORT_SCHEMA, action='baseline', manifest=str(path), findings=compare(None, state),
                exposures=dict(writable_folders=state['folders'], writable_programs=state['programs'],
                               relative_entries=state['relative'],
                               failing=sorted(k for k, v in state['checks'].items() if v['state'] == 'fail')),
                **_counts(state), gaps=state['gaps'])


def check(manifest=DEFAULT_MANIFEST, *, root=None, review=None, budget=MAX_SECONDS):
    old = _read(manifest)
    root = root or old.get('root', '/')
    new = snapshot(root=root, review=review, budget=budget)
    removed = sorted(set(old.get('capabilities', {})) - set(new['capabilities']))
    return dict(schema=REPORT_SCHEMA, action='check', manifest=str(Path(manifest).expanduser()), checked_at=_now(),
                baseline_recorded_at=old.get('recorded_at'), findings=compare(old, new),
                capabilities_removed=removed, **_counts(new), gaps=new['gaps'],
                note='After review, `megalodon hardening accept` records the current state.')


def accept(manifest=DEFAULT_MANIFEST, *, root=None, review=None, budget=MAX_SECONDS):
    old = _read(manifest)
    return dict(baseline(manifest, replace=True, root=root or old.get('root', '/'), review=review, budget=budget),
                action='accept')
