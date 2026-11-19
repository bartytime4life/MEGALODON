"""Read-only map of this account's network sockets to the programs that own them. Nothing is stopped or changed.

The kernel socket tables give each socket's addresses, state and inode; this
account's own `/proc/<pid>/fd` links name the inodes each process holds. A
program is identified by its executable path and process name, never by its
command line, so arguments that carry tokens or passwords are not read.
Processes of other accounts and of root are not visible without privilege,
and loopback-only sockets are left out. A signal here is a reason to look:
updates replace running executables, and developer tools run from temporary
directories too.
"""
from __future__ import annotations

import argparse
from collections import OrderedDict
from datetime import datetime, timezone
import hashlib
import heapq
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
from threading import Lock, Thread

SCHEMA = 'megalodon-process-network-v1'
MAX_TABLE_READ = 16 * 1024 * 1024
MAX_TABLE_LINES = 65536
MAX_PROCESSES = 2048
# At most this many /proc entries are considered, chosen in bounded memory.
MAX_PROC_ENTRIES = 65536
# Network namespaces beyond the HUD's own whose socket tables are read.
MAX_NAMESPACES = 16
MAX_FD_LINKS = 65536
MAX_PROGRAMS = 16
MAX_REMOTES = 3
MAX_TEXT_BYTES = 256
# Every coverage gap the review can emit fits this bound, which the HUD validator also uses.
MAX_GAPS = 8
# Executable hashing: per file, per review, and remembered file identities.
MAX_HASH_FILE = 256 * 1024 * 1024
MAX_HASH_REVIEW = 512 * 1024 * 1024
MAX_HASH_CACHE = 512
# A stalled network or FUSE file can block a read indefinitely, so hashing has a wall-clock limit per review.
MAX_HASH_SECONDS = 20
# Processes per row kept as hash sources, in case the first exits or calls exec before hashing.
MAX_HASH_SOURCES = 4
HASH_STATUSES = ('hashed', 'too_large', 'unreadable', 'deferred', 'changed')
# (protocol, family, table name, address bytes)
TABLES = (('tcp', 'ipv4', 'tcp', 4), ('tcp', 'ipv6', 'tcp6', 16),
          ('udp', 'ipv4', 'udp', 4), ('udp', 'ipv6', 'udp6', 16))
TCP_ESTABLISHED, TCP_LISTEN = '01', '0A'
TEMPORARY = ('/tmp/', '/var/tmp/', '/dev/shm/')
# rule: (ATT&CK technique, detail)
RULES = {
    'EXECUTABLE_DELETED': ('T1070.004', 'The program file was deleted or replaced after it started. Updates also do this; a '
                                        'program that removes its own file is a common way to hide.'),
    'EXECUTABLE_IN_MEMORY': ('T1620', 'The program runs from an anonymous in-memory file with no path on disk.'),
    'EXECUTABLE_IN_TEMPORARY': ('T1105', 'The program runs from a temporary directory, where downloaded tools are often '
                                         'placed. Installers and developer tools also run there.'),
    # Reverse-shell shapes, read from which descriptors hold which sockets and pipes.
    'STDIO_SHELL_ON_NETWORK': ('T1059', 'A shell or script interpreter reads its input from, or writes its output to, a '
                                        'remote network connection. This is how reverse shells such as bash -i >& '
                                        '/dev/tcp/..., nc -e /bin/sh and Python pty spawns work. Socket-activated '
                                        'services can also look like this.'),
    'PIPED_TO_SHELL': ('T1059.004', 'A program holding a remote network connection shares a pipe with a shell\'s input or '
                                    'output, as in mkfifo relays (cat f | sh -i | nc host port > f) or running a '
                                    'downloaded script (curl ... | sh). Installers piped into a shell also do this.'),
    'SHELL_HOLDS_SOCKET': ('T1059.004', 'A Unix shell itself holds a remote network connection, for example through '
                                        'bash\'s /dev/tcp redirection. Interactive shells rarely do this.'),
    'STDIO_ON_NETWORK': ('T1071', 'The program\'s standard input or output is a remote network connection rather than a '
                                  'terminal, file or pipe. Socket-activated services and some relays work this way.'),
}
# Identified by executable path (or process name when the path is unavailable), never by command line.
SHELLS = frozenset({'sh', 'bash', 'rbash', 'dash', 'zsh', 'ksh', 'mksh', 'pdksh', 'fish', 'ash', 'busybox',
                    'tcsh', 'csh', 'yash'})
_INTERPRETER = re.compile(r'(?:python|perl|ruby|php|lua|tclsh|pwsh)[0-9.]*|node|nodejs|deno|bun|powershell')


def _program_kind(path, comm):
    """'shell', 'interpreter' or None, from the executable's file name or the process name."""
    for name in (path.rsplit('/', 1)[-1], comm):
        if name in SHELLS:
            return 'shell'
        if _INTERPRETER.fullmatch(name):
            return 'interpreter'
    return None
# /proc/net prints each network-order address word as a host-order number.
_HEX = re.compile(r'[0-9A-Fa-f]+')
_BYTE_ORDER = sys.byteorder


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _short(value):
    """Printable text that fits MAX_TEXT_BYTES once JSON-escaped, as the HUD sends it."""
    value = ''.join(c if c.isprintable() else '?' for c in str(value))
    if len(json.dumps(value)) <= MAX_TEXT_BYTES:
        return value
    kept, size = [], len('"..."')
    for char in value:
        size += len(json.dumps(char)) - 2
        if size > MAX_TEXT_BYTES:
            break
        kept.append(char)
    return ''.join(kept)+'...'


def _read_table(path):
    """Return (lines, complete) for a bounded socket table, without following a final symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, 'O_CLOEXEC', 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('not a regular file')
        chunks, size = [], 0
        while size <= MAX_TABLE_READ:
            chunk = os.read(fd, MAX_TABLE_READ + 1 - size)
            if not chunk:
                break
            chunks.append(chunk); size += len(chunk)
    finally:
        os.close(fd)
    lines = b''.join(chunks)[:MAX_TABLE_READ].decode('ascii', 'replace').splitlines()
    complete = size <= MAX_TABLE_READ
    if not complete:
        lines = lines[:-1]
    if len(lines) > MAX_TABLE_LINES + 1:
        lines, complete = lines[:MAX_TABLE_LINES + 1], False
    return lines[1:], complete


def _endpoint(value, length):
    address, _, port = value.partition(':')
    # Only plain hex digits: int() also accepts signs and underscores, which would not round-trip.
    if len(address) != length * 2 or len(port) != 4 or not _HEX.fullmatch(address) or not _HEX.fullmatch(port):
        return None
    try:
        raw = b''.join(int(address[i:i + 8], 16).to_bytes(4, _BYTE_ORDER) for i in range(0, len(address), 8))
        return ipaddress.ip_address(raw), int(port, 16)
    except ValueError:
        return None


def _loopback(address):
    mapped = getattr(address, 'ipv4_mapped', None)
    return address.is_loopback or bool(mapped and mapped.is_loopback)


def _shown(address, port):
    mapped = getattr(address, 'ipv4_mapped', None)
    address = mapped or address
    return f'[{address}]:{port}' if address.version == 6 else f'{address}:{port}'


def sockets(root='/', net='proc/net'):
    """Return {inode: socket} for non-loopback TCP and UDP sockets, and whether every table was fully read.

    `net` is the network directory to read: `proc/net` for the HUD's own
    namespace, or `proc/<pid>/net` for the namespace that process is in.
    """
    found, complete = {}, True
    for protocol, family, name, length in TABLES:
        try:
            lines, whole = _read_table(Path(root, net, name))
        except FileNotFoundError:
            # Without an IPv6 stack the IPv6 tables do not exist; that is complete.
            if family != 'ipv6' or os.path.lexists(Path(root, net, 'if_inet6')):
                complete = False
            continue
        except (OSError, ValueError):
            complete = False
            continue
        complete = complete and whole
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or not fields[9].isdigit() or fields[9] == '0':
                continue
            local, remote = _endpoint(fields[1], length), _endpoint(fields[2], length)
            if local is None or remote is None:
                continue
            listening = remote[1] == 0 and remote[0].is_unspecified
            if _loopback(local[0]) and (listening or _loopback(remote[0])):
                continue
            if protocol == 'tcp':
                kind = 'listening' if fields[3] == TCP_LISTEN else 'established' if fields[3] == TCP_ESTABLISHED else 'other'
            else:
                kind = 'listening' if listening else 'established'
            found[int(fields[9])] = dict(protocol=protocol, kind=kind,
                                         remote=None if listening else _shown(*remote))
    return found, complete


def _comm(path):
    try:
        return _short(path.read_text('utf-8', 'replace').strip()) or '?'
    except OSError:
        return '?'


# (device, inode, size, mtime_ns, ctime_ns) -> SHA-256, so an unchanged executable is read once. The change
# time is part of the identity because an owner can rewrite a file and set its modification time back.
_hashes = OrderedDict()
_hashes_lock = Lock()


def _executable_hash(proc, budget, identity):
    """Return (sha256 or None, status, bytes read) for the file behind /proc/<pid>/exe.

    The link is opened rather than its path, so a deleted or memfd executable
    is hashed as it runs. `identity` is the file seen when the process was
    scanned; a different file now (the process called exec, or its PID was
    reused) or one that changes while it is read is not hashed.
    """
    if identity is None:
        return None, 'unreadable', 0
    read = 0
    try:
        fd = os.open(proc/'exe', os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_CLOEXEC', 0))
    except OSError:
        return None, 'unreadable', 0
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None, 'unreadable', 0
        key = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if key != identity:
            return None, 'changed', 0
        with _hashes_lock:
            if key in _hashes:
                _hashes.move_to_end(key)
                return _hashes[key], 'hashed', 0
        if info.st_size > MAX_HASH_FILE:
            return None, 'too_large', 0
        if info.st_size > budget:
            return None, 'deferred', 0
        digest = hashlib.sha256()
        while read <= info.st_size:
            chunk = os.read(fd, min(1024 * 1024, info.st_size + 1 - read))
            if not chunk:
                break
            digest.update(chunk); read += len(chunk)
        after = os.fstat(fd)
        if read != info.st_size or (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != key[2:]:
            return None, 'changed', read
        value = digest.hexdigest()
        with _hashes_lock:
            _hashes[key] = value
            while len(_hashes) > MAX_HASH_CACHE:
                _hashes.popitem(last=False)
        return value, 'hashed', read
    except OSError:
        # Bytes read before a failure still count against the review's budget.
        return None, 'unreadable', read
    finally:
        os.close(fd)


# The thread hashing the last review's executables, if one is still blocked on a read.
_hasher = None


def _hash_rows(jobs):
    """Hash each job's executable within the read budget and MAX_HASH_SECONDS.

    Returns None, 'time' when the limit stopped hashing, or 'busy' when an
    earlier review's read is still blocked; at most one hashing thread runs.
    Rows not reached are `deferred`.
    """
    global _hasher
    for row, _, _ in jobs:
        row['sha256'], row['hash_status'] = None, 'deferred'
    if not jobs:
        return None
    with _hashes_lock:
        if _hasher is not None and _hasher.is_alive():
            return 'busy'
    results, done = {}, Lock()
    def work():
        budget = MAX_HASH_REVIEW
        for index, (_, procs, identity) in enumerate(jobs):
            # Any member of the group runs the same file; try the next if one has exited or exec'd.
            for proc in procs:
                value = _executable_hash(proc, budget, identity)
                budget -= value[2]
                if value[1] not in ('unreadable', 'changed'):
                    break
            with done:
                results[index] = value
    thread = Thread(target=work, daemon=True, name='megalodon-executable-hash')
    with _hashes_lock:
        _hasher = thread
    thread.start()
    thread.join(MAX_HASH_SECONDS)
    with done:
        finished = dict(results)
    for index, (row, _, _) in enumerate(jobs):
        if index in finished:
            row['sha256'], row['hash_status'] = finished[index][:2]
    if thread.is_alive():
        return 'time'
    return 'budget' if any(row['hash_status'] == 'deferred' for row, _, _ in jobs) else None


def _parent(proc):
    try:
        text = (proc/'stat').read_text('utf-8', 'replace')
        return int(text[text.rindex(')') + 2:].split()[1])
    except (OSError, ValueError, IndexError):
        return None


def start_time(proc):
    """The process's start time in clock ticks since boot (stat field 22): with the PID, it names one process."""
    try:
        text = (proc/'stat').read_text('utf-8', 'replace')
        return int(text[text.rindex(')') + 2:].split()[19])
    except (OSError, ValueError, IndexError):
        return None


# Flags that hold for every process running the flagged file, not only the one that showed them.
FILE_FLAGS = ('EXECUTABLE_IN_MEMORY', 'EXECUTABLE_DELETED', 'EXECUTABLE_IN_TEMPORARY')
MAX_FLAG_PROCESSES = 8


def _namespace(path):
    try:
        return os.readlink(path)
    except OSError:
        return None


def review(root='/', *, uid=None, now=_now, with_pids=False):
    """with_pids adds flag_processes, the 'pid@start' of the processes behind each flag (for the
    response engine; the HUD's row format is fixed)."""
    uid = os.getuid() if uid is None else uid
    base = Path(root, 'proc')
    # Socket tables are per network namespace. The HUD's own comes from /proc/net; a process in
    # another one (a rootless container, PrivateNetwork=) is matched against /proc/<pid>/net.
    own = _namespace(base/'self/ns/net')
    tables = {own: sockets(root)}
    unread_namespaces = set()
    programs, links, seen, stopped, vanished, total = {}, 0, 0, False, 0, 0
    def numbered(listing):
        nonlocal total
        for entry in listing:
            if entry.name.isdigit():
                total += 1
                yield int(entry.name)
    try:
        with os.scandir(base) as listing:
            pids = heapq.nsmallest(MAX_PROC_ENTRIES, numbered(listing))
    except OSError:
        pids = []
    if total > MAX_PROC_ENTRIES:
        stopped = True
    # First pass: each process's socket inodes, loading each namespace's tables once.
    candidates = []
    # Processes whose standard input or output is a pipe, to find shells fed by networked programs.
    stdio_owners = []
    for pid in pids:
        if seen >= MAX_PROCESSES or links >= MAX_FD_LINKS:
            stopped = True
            break
        proc = base/str(pid)
        try:
            if os.stat(proc, follow_symlinks=False).st_uid != uid:
                continue
            fds = os.scandir(proc/'fd')
        except OSError:
            vanished += 1
            continue
        seen += 1
        namespace = _namespace(proc/'ns/net')
        if namespace is not None and namespace not in tables:
            if len(tables) > MAX_NAMESPACES:
                unread_namespaces.add(namespace)
            else:
                tables[namespace] = sockets(root, f'proc/{pid}/net')
        inodes, stdio_sockets, stdio_pipes, pipes = [], set(), set(), set()
        with fds:
            # Iterate rather than list, so a process with very many descriptors stays within the bound.
            for fd in fds:
                if links >= MAX_FD_LINKS:
                    stopped = True
                    break
                links += 1
                try:
                    target = os.readlink(fd.path)
                except OSError:
                    continue
                stdio = fd.name in ('0', '1', '2')
                for prefix, found in (('socket:[', inodes), ('pipe:[', None)):
                    if target.startswith(prefix) and target.endswith(']') and target[len(prefix):-1].isdigit():
                        number = int(target[len(prefix):-1])
                        if found is not None:
                            found.append(number)
                            if stdio:
                                stdio_sockets.add(number)
                        else:
                            pipes.add(number)
                            if stdio:
                                stdio_pipes.add(number)
        if stdio_pipes:
            stdio_owners.append((proc, stdio_pipes))
        if inodes:
            candidates.append((proc, inodes, stdio_sockets, pipes))
    # Socket inodes are unique across namespaces, and a process can hold a socket from a namespace
    # it is not a member of (socket activation into PrivateNetwork=), so match against every table.
    known = {}
    for table, _ in tables.values():
        known.update(table)
    # Pipes on a shell's standard input or output, keyed by pipe inode.
    shell_pipes = {}
    networked_pipes = set().union(*(pipes for _, _, _, pipes in candidates)) if candidates else set()
    for proc, stdio_pipes in stdio_owners:
        if not stdio_pipes & networked_pipes:
            continue
        try:
            path = os.readlink(proc/'exe').removesuffix(' (deleted)')
        except OSError:
            path = ''
        if _program_kind(path, _comm(proc/'comm')) == 'shell':
            for pipe in stdio_pipes:
                shell_pipes.setdefault(pipe, set()).add(proc.name)
    for proc, inodes, stdio_sockets, pipes in candidates:
        held = [(inode, known[inode]) for inode in inodes if inode in known]
        if not held:
            continue
        try:
            executable = os.readlink(proc/'exe')
        except OSError:
            vanished += 1
            continue
        deleted = executable.endswith(' (deleted)')
        path = executable[:-len(' (deleted)')] if deleted else executable
        # Group by the running file, not only its path: during an update an old process can still run the
        # replaced (deleted) file at the same path, and each file gets its own row and hash.
        try:
            info = os.stat(proc/'exe')
            identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        except OSError:
            identity = None
        # Read the path again: an exec between the first readlink and the stat would otherwise pair the
        # old path with the new file. Later execs are caught when the file is opened for hashing.
        try:
            if os.readlink(proc/'exe') != executable:
                vanished += 1
                continue
        except OSError:
            vanished += 1
            continue
        group = (path, deleted, identity)
        row = programs.get(group)
        if row is None:
            parent = _parent(proc)
            flags = []
            if path.startswith('/memfd:'):
                flags.append('EXECUTABLE_IN_MEMORY')
            elif deleted:
                flags.append('EXECUTABLE_DELETED')
            if path.startswith(TEMPORARY):
                flags.append('EXECUTABLE_IN_TEMPORARY')
            row = programs[group] = dict(program=_comm(proc/'comm'), executable=_short(path),
                                        parent=_comm(base/str(parent)/'comm') if parent else '?',
                                        processes=0, established=0, listening=0, other=0, remotes=[], remotes_total=0,
                                        flags=flags, _remotes=set(), _inodes=set(), _procs=[], _identity=identity)
        # Per-process reverse-shell shapes; a row carries a flag when any of its processes shows it.
        remote = {inode for inode, item in held if item['kind'] == 'established' and item['remote']}
        stdio_remote = remote & stdio_sockets
        kind = _program_kind(path, _comm(proc/'comm'))
        found = []
        if stdio_remote:
            found.append('STDIO_SHELL_ON_NETWORK' if kind else 'STDIO_ON_NETWORK')
        elif kind == 'shell' and remote:
            found.append('SHELL_HOLDS_SOCKET')
        if remote and any(shell_pipes.get(pipe, set()) - {proc.name} for pipe in pipes):
            found.append('PIPED_TO_SHELL')
        for flag in found:
            if flag not in row['flags']:
                row['flags'].append(flag)
        if with_pids:
            marks, start = row.setdefault('_flag_pids', {}), start_time(proc)
            if start is not None:
                for flag in [f for f in row['flags'] if f in FILE_FLAGS] + found:
                    bucket = marks.setdefault(flag, [])
                    if f'{proc.name}@{start}' not in bucket and len(bucket) < MAX_FLAG_PROCESSES:
                        bucket.append(f'{proc.name}@{start}')
        row['processes'] += 1
        if len(row['_procs']) < MAX_HASH_SOURCES:
            row['_procs'].append(proc)
        # A socket shared by duplicated descriptors or worker processes is counted once.
        for inode, item in held:
            if inode in row['_inodes']:
                continue
            row['_inodes'].add(inode)
            row[item['kind']] += 1
            if item['remote']:
                row['_remotes'].add(item['remote'])
    rows = []
    for row in programs.values():
        remotes = sorted(row.pop('_remotes'))
        row.pop('_inodes')
        marks = row.pop('_flag_pids', {})
        if with_pids:
            row['flag_processes'] = marks
        row.update(remotes=remotes[:MAX_REMOTES], remotes_total=len(remotes))
        rows.append(row)
    rows.sort(key=lambda r: (not r['flags'], -(r['established'] + r['listening'] + r['other']), r['executable']))
    shown = rows[:MAX_PROGRAMS]
    # Only listed programs are hashed, within one review's read budget; later reviews continue from the cache.
    listed = {id(row) for row in shown}
    jobs = []
    for row in rows:
        procs, identity = row.pop('_procs'), row.pop('_identity')
        if id(row) in listed:
            jobs.append((row, procs, identity))
    hash_limit = _hash_rows(jobs)
    deferred = sum(1 for row in shown if row['hash_status'] == 'deferred')
    tables_complete = all(complete for _, complete in tables.values()) and not unread_namespaces
    gaps = []
    if unread_namespaces:
        gaps.append(f'{len(unread_namespaces)} more network namespaces were not read (limit {MAX_NAMESPACES}); '
                    'their processes\' sockets are not listed.')
    if not tables_complete:
        gaps.append('A socket table was not fully read; other connections may exist.')
    if stopped:
        gaps.append(f'The process scan stopped at {MAX_PROC_ENTRIES} process entries, {MAX_PROCESSES} processes of this account '
                    f'or {MAX_FD_LINKS} open files; later processes were not reviewed.')
    if len(rows) > MAX_PROGRAMS:
        gaps.append(f'{len(rows)} programs hold network sockets; only the first {MAX_PROGRAMS} are listed.')
    if vanished:
        gaps.append(f'{vanished} processes of this account exited or could not be read during the scan.')
    if deferred:
        reason = {'busy': 'an earlier executable read has not finished',
                  'time': f'the {MAX_HASH_SECONDS} s hashing limit was reached'}.get(hash_limit, f'the {MAX_HASH_REVIEW // 1048576} MiB read limit was reached')
        gaps.append(f'{deferred} executables were not hashed in this review ({reason}); a later review continues.')
    gaps.append('Processes of other accounts and of root are not visible without privilege, and loopback-only sockets are left out.')
    # Each flag is a review item: its ATT&CK technique and meaning are fixed in RULES, not repeated per row.
    return dict(schema=SCHEMA, reviewed_at=now(), programs=shown, programs_total=len(rows),
                flagged_total=sum(1 for row in rows if row['flags']),
                processes_reviewed=seen, tables_complete=tables_complete, scan_complete=not stopped,
                gaps=gaps, action_status='not_attempted', action_authority='none')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.parse_args(argv)
    try:
        print(json.dumps(review(), indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        print('Process network review unavailable: ' + _short(exc))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
