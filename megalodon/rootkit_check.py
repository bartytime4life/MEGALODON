"""Rootkit cross-checks: two independent views of the same thing must agree.

A rootkit hides by hooking one way of looking: the directory listing of
/proc, the kernel's module list, the socket tables, readdir() of a folder.
It rarely hooks every way. Each check here asks the same question twice,
through different kernel paths, and reports where the answers disagree
(ATT&CK T1014, T1574.006):

* processes: PIDs that answer a signal probe or open directly in /proc but
  are missing from the /proc listing;
* kernel modules: loaded modules in /sys/module but not in /proc/modules,
  and the reverse;
* ports: TCP and UDP ports that cannot be bound but appear in no socket
  table;
* folders: a folder whose link count says it has more subfolders than its
  listing shows, on filesystems that keep that count;
* preloaded libraries: libraries named in /etc/ld.so.preload, and any of
  them hidden from their folder's listing.

Read-only, except that the port check briefly binds each port it tests (see
docs/rootkit-check.md). Run as root to see everything.
"""
from __future__ import annotations

from datetime import datetime, timezone
import errno
import os
from pathlib import Path
import socket
import stat

SCHEMA = 'megalodon-rootkit-check-v1'
MAX_PID_DEFAULT = 4_194_304
DIRECTORIES = ('/', '/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/lib', '/usr/local/bin', '/lib',
               '/lib/modules', '/boot', '/root', '/tmp', '/var/tmp', '/dev/shm', '/var/lib', '/var/log', '/home',
               '/opt', '/srv')
# Filesystems where a folder's link count is 2 plus its number of subfolders.
LINK_COUNTING = {'ext2', 'ext3', 'ext4', 'xfs', 'tmpfs', 'jfs', 'reiserfs', 'f2fs'}
TAINT_FORCED = {1: 'F (a module was loaded by force)', 7: 'R (a module was unloaded by force)'}
TAINT_NOTES = {0: 'P (proprietary module)', 12: 'O (out-of-tree module)', 13: 'E (unsigned module)'}

RULES = {
    'HIDDEN_PROCESS': ('CRITICAL', 'T1014', 'A process exists but is missing from the /proc listing, as when a '
                                            'rootkit hooks directory reads to hide it.'),
    'HIDDEN_MODULE': ('CRITICAL', 'T1014', 'A kernel module is loaded but missing from one of the kernel\'s two '
                                           'module lists, as when a rootkit unlinks itself.'),
    'HIDDEN_PORT': ('HIGH', 'T1014', 'A port is in use but appears in no socket table, as when a rootkit hides a '
                                     'backdoor\'s socket.'),
    'HIDDEN_DIRECTORY': ('HIGH', 'T1564.001', 'A folder\'s link count shows more subfolders than its listing, as '
                                              'when a rootkit hides a folder from directory reads.'),
    'HIDDEN_FILE': ('CRITICAL', 'T1574.006', 'A library named in /etc/ld.so.preload exists but is hidden from its '
                                             'folder\'s listing: a userland rootkit hiding itself.'),
    'PRELOAD_LIBRARY': ('HIGH', 'T1574.006', '/etc/ld.so.preload loads a library into every program. Userland '
                                             'rootkits use it to hide processes and files; few systems need it.'),
    'KERNEL_FORCED_MODULE': ('MEDIUM', 'T1014', 'The kernel records that a module was loaded or unloaded by force, '
                                                'skipping its version checks; some rootkits load this way.'),
}


class RootkitError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _finding(rule, subject, detail, **extra):
    severity, technique, summary = RULES[rule]
    return dict(rule_id=rule, severity=severity, techniques=[technique], subject=subject, detail=detail,
                summary=summary, **extra)


# ------------------------------------------------------------------ processes

def _listed_pids(proc):
    with os.scandir(proc) as listing:
        return {int(e.name) for e in listing if e.name.isdigit()}


def _exists(pid):
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return False


def _thread_group(proc, pid):
    """The thread group (process) a PID belongs to; None if /proc will not say."""
    try:
        for line in Path(proc, str(pid), 'status').read_text('utf-8', 'replace').splitlines():
            if line.startswith('Tgid:'):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


def hidden_processes(*, proc='/proc', max_pid=None, exists=_exists, listed=_listed_pids, thread_group=_thread_group):
    """PIDs that exist (by signal probe or direct /proc lookup) but are absent from two /proc listings."""
    if max_pid is None:
        try:
            max_pid = int(Path(proc, 'sys/kernel/pid_max').read_text().strip())
        except (OSError, ValueError):
            max_pid = MAX_PID_DEFAULT
    max_pid = min(max_pid, MAX_PID_DEFAULT)
    first = listed(proc)
    candidates = []
    for pid in range(1, max_pid + 1):
        if pid in first:
            continue
        direct = os.path.isdir(os.path.join(proc, str(pid)))
        if not (direct or exists(pid)):
            continue
        group = thread_group(proc, pid)
        if group is not None and group != pid:
            continue      # a thread: /proc lists only thread-group leaders
        candidates.append((pid, direct, group))
    if not candidates:
        return []
    # A process started after the first listing is in the second one; a hidden one is in neither.
    second = listed(proc)
    found = []
    for pid, direct, group in candidates:
        if pid in second or not (os.path.isdir(os.path.join(proc, str(pid))) or exists(pid)):
            continue
        how = 'opens directly in /proc' if direct else 'answers a signal probe but has no /proc entry'
        found.append(_finding('HIDDEN_PROCESS', str(pid), f'process {pid} {how} but is not listed',
                              pid=pid, program=_program(proc, pid)))
    return found


def _program(proc, pid):
    try:
        return os.readlink(os.path.join(proc, str(pid), 'exe'))
    except OSError:
        return None


# ------------------------------------------------------------------ kernel modules

def module_findings(root='/'):
    gaps, found = [], []
    sys_module, listing = Path(root, 'sys/module'), Path(root, 'proc/modules')
    try:
        text = listing.read_text('ascii', 'replace')
    except FileNotFoundError:
        return found, ['the kernel has no loadable modules (/proc/modules is absent); nothing to compare']
    except OSError as exc:
        return found, [f'/proc/modules cannot be read: {exc.strerror}']
    listed = {line.split()[0] for line in text.splitlines() if line.strip()}
    try:
        # Built-in modules have no initstate; a loaded module's says live, coming or going.
        loaded = {e.name for e in os.scandir(sys_module) if os.path.exists(os.path.join(e.path, 'initstate'))}
    except OSError as exc:
        return found, [f'/sys/module cannot be read: {exc.strerror}']
    for name in sorted(loaded - listed):
        found.append(_finding('HIDDEN_MODULE', name, f'module {name} is in /sys/module but not in /proc/modules'))
    for name in sorted(listed - loaded):
        found.append(_finding('HIDDEN_MODULE', name, f'module {name} is in /proc/modules but not in /sys/module'))
    return found, gaps


def taint(root='/'):
    try:
        value = int(Path(root, 'proc/sys/kernel/tainted').read_text().strip())
    except (OSError, ValueError):
        return None, []
    flags = [text for bit, text in {**TAINT_FORCED, **TAINT_NOTES}.items() if value >> bit & 1]
    found = [_finding('KERNEL_FORCED_MODULE', 'kernel', f'kernel taint flag {text}', taint=value)
             for bit, text in TAINT_FORCED.items() if value >> bit & 1]
    return dict(value=value, flags=flags), found


# ------------------------------------------------------------------ ports

TABLES = (('tcp', 'tcp'), ('tcp', 'tcp6'), ('udp', 'udp'), ('udp', 'udp6'))


def table_ports(root='/'):
    """Local ports of every socket the kernel lists, per protocol, in this network namespace."""
    ports, gaps = {'tcp': set(), 'udp': set()}, []
    for protocol, name in TABLES:
        try:
            lines = Path(root, 'proc/net', name).read_text('ascii', 'replace').splitlines()[1:]
        except FileNotFoundError:
            continue
        except OSError as exc:
            gaps.append(f'/proc/net/{name} cannot be read: {exc.strerror}')
            continue
        for line in lines:
            fields = line.split()
            if len(fields) > 1 and ':' in fields[1]:
                try:
                    ports[protocol].add(int(fields[1].rsplit(':', 1)[1], 16))
                except ValueError:
                    continue
    return ports, gaps


def _in_use(protocol, family, port):
    """True when binding the port fails because something holds it."""
    kind = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
    with socket.socket(family, kind) as probe:
        if family == socket.AF_INET6:
            probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            probe.bind(('::' if family == socket.AF_INET6 else '0.0.0.0', port))
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                return True
            if exc.errno in (errno.EACCES, errno.EPERM):
                return None
            return False
    return False


def hidden_ports(root='/', *, in_use=_in_use, tables=table_ports, first_port=1):
    found, gaps = [], []
    listed, table_gaps = tables(root)
    gaps += table_gaps
    families = [socket.AF_INET] + ([socket.AF_INET6] if socket.has_ipv6 and os.path.exists(
        os.path.join(root, 'proc/net/tcp6')) else [])
    refused = 0
    for protocol in ('tcp', 'udp'):
        for port in range(first_port, 65536):
            if port in listed[protocol]:
                continue
            busy = False
            for family in families:
                result = in_use(protocol, family, port)
                if result is None:
                    refused += 1
                    break
                if result:
                    busy = True
                    break
            if not busy:
                continue
            # A socket opened after the tables were read is in a fresh read; a hidden one is not.
            again, _ = tables(root)
            if port in again[protocol]:
                continue
            if any(in_use(protocol, family, port) for family in families):
                found.append(_finding('HIDDEN_PORT', f'{protocol}:{port}',
                                      f'{protocol.upper()} port {port} is in use but in no socket table',
                                      protocol=protocol, port=port))
    if refused:
        gaps.append(f'{refused} privileged ports could not be tested without root')
    return found, gaps


# ------------------------------------------------------------------ folders and preloaded libraries

def _filesystems(root='/'):
    """Mount point -> filesystem type, from mountinfo."""
    out = {}
    try:
        for line in Path(root, 'proc/self/mountinfo').read_text('utf-8', 'replace').splitlines():
            left, _, right = line.partition(' - ')
            fields = left.split()
            if len(fields) > 4 and right:
                out[fields[4].replace('\\040', ' ')] = right.split()[0]
    except OSError:
        pass
    return out


def _filesystem_of(path, mounts):
    best = ''
    for point in mounts:
        if (path == point or path.startswith(point.rstrip('/') + '/')) and len(point) > len(best):
            best = point
    return mounts.get(best)


def hidden_directories(root='/', directories=DIRECTORIES):
    found, skipped = [], 0
    mounts = _filesystems(root)
    for folder in directories:
        path = os.path.join(root, folder.lstrip('/')) if root != '/' else folder
        try:
            info = os.stat(path, follow_symlinks=False)
        except OSError:
            continue
        if not stat.S_ISDIR(info.st_mode):
            continue
        if _filesystem_of(folder, mounts) not in LINK_COUNTING or info.st_nlink < 2:
            skipped += 1
            continue
        try:
            with os.scandir(path) as listing:
                subfolders = sum(1 for e in listing if e.is_dir(follow_symlinks=False))
        except OSError:
            continue
        expected = info.st_nlink - 2
        if expected > subfolders:
            # Re-read: a folder created between the two reads is not hidden.
            again = os.stat(path, follow_symlinks=False).st_nlink - 2
            with os.scandir(path) as listing:
                recount = sum(1 for e in listing if e.is_dir(follow_symlinks=False))
            if again > recount:
                found.append(_finding('HIDDEN_DIRECTORY', folder,
                                      f'{folder} has {again} subfolders by its link count but lists {recount}',
                                      expected=again, listed=recount))
    return found, ([f'{skipped} folders are on filesystems that do not count subfolders and were not compared']
                   if skipped else [])


def preload_findings(root='/'):
    path = Path(root, 'etc/ld.so.preload')
    try:
        text = path.read_text('utf-8', 'replace')
    except FileNotFoundError:
        return [], []
    except OSError as exc:
        return [], [f'/etc/ld.so.preload cannot be read: {exc.strerror}']
    libraries = [word for line in text.splitlines() for word in line.split('#', 1)[0].replace(':', ' ').split()]
    found = []
    if libraries:
        found.append(_finding('PRELOAD_LIBRARY', '/etc/ld.so.preload',
                              f'/etc/ld.so.preload loads {", ".join(libraries[:8])}', libraries=libraries[:32]))
    for library in libraries[:32]:
        real = os.path.join(root, library.lstrip('/')) if root != '/' else library
        folder, name = os.path.split(real)
        try:
            os.stat(real)
            with os.scandir(folder) as listing:
                visible = any(e.name == name for e in listing)
        except OSError:
            continue
        if not visible:
            found.append(_finding('HIDDEN_FILE', library, f'{library} exists but is not in the listing of {folder}'))
    return found, []


# ------------------------------------------------------------------ all of it

def check(root='/', *, ports=True, max_pid=None, now=None):
    findings, gaps = [], []
    if root == '/':
        findings += hidden_processes(max_pid=max_pid)
    else:
        findings += hidden_processes(proc=os.path.join(root, 'proc'), max_pid=max_pid,
                                     exists=lambda pid: False)
    found, more = module_findings(root)
    findings += found
    gaps += more
    kernel, forced = taint(root)
    findings += forced
    if ports:
        if root != '/':
            gaps.append('ports are only checked on the running system')
        else:
            found, more = hidden_ports(root)
            findings += found
            gaps += more
    found, more = hidden_directories(root)
    findings += found
    gaps += more
    found, more = preload_findings(root)
    findings += found
    gaps += more
    if os.geteuid() != 0:
        gaps.append('not run as root: other accounts\' processes are probed but not inspected, and privileged '
                    'ports and protected folders are skipped')
    order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    findings.sort(key=lambda f: (order[f['severity']], f['rule_id'], f['subject']))
    return dict(schema=SCHEMA, checked_at=now or _now(), findings=findings, kernel=kernel, gaps=gaps,
                ports_checked=bool(ports and root == '/'))
