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
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import stat
import sys

SCHEMA = 'megalodon-process-network-v1'
MAX_TABLE_READ = 16 * 1024 * 1024
MAX_TABLE_LINES = 65536
MAX_PROCESSES = 2048
MAX_FD_LINKS = 65536
MAX_PROGRAMS = 16
MAX_REMOTES = 3
MAX_TEXT_BYTES = 256
# (protocol, family, path, address bytes)
TABLES = (('tcp', 'ipv4', 'proc/net/tcp', 4), ('tcp', 'ipv6', 'proc/net/tcp6', 16),
          ('udp', 'ipv4', 'proc/net/udp', 4), ('udp', 'ipv6', 'proc/net/udp6', 16))
TCP_ESTABLISHED, TCP_LISTEN = '01', '0A'
TEMPORARY = ('/tmp/', '/var/tmp/', '/dev/shm/')
# rule: (ATT&CK technique, detail)
RULES = {
    'EXECUTABLE_DELETED': ('T1070.004', 'The program file was deleted or replaced after it started. Updates also do this; a '
                                        'program that removes its own file is a common way to hide.'),
    'EXECUTABLE_IN_MEMORY': ('T1620', 'The program runs from an anonymous in-memory file with no path on disk.'),
    'EXECUTABLE_IN_TEMPORARY': ('T1105', 'The program runs from a temporary directory, where downloaded tools are often '
                                         'placed. Installers and developer tools also run there.'),
}
# /proc/net prints each network-order address word as a host-order number.
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
    if len(address) != length * 2 or len(port) != 4:
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


def sockets(root='/'):
    """Return {inode: socket} for non-loopback TCP and UDP sockets, and whether every table was fully read."""
    found, complete = {}, True
    for protocol, family, rel, length in TABLES:
        try:
            lines, whole = _read_table(Path(root, rel))
        except FileNotFoundError:
            # Without an IPv6 stack the IPv6 tables do not exist; that is complete.
            if family != 'ipv6' or os.path.lexists(Path(root, 'proc/net/if_inet6')):
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


def _parent(proc):
    try:
        text = (proc/'stat').read_text('utf-8', 'replace')
        return int(text[text.rindex(')') + 2:].split()[1])
    except (OSError, ValueError, IndexError):
        return None


def review(root='/', *, uid=None, now=_now):
    uid = os.getuid() if uid is None else uid
    table, tables_complete = sockets(root)
    base = Path(root, 'proc')
    programs, links, seen, stopped, vanished = {}, 0, 0, False, 0
    try:
        with os.scandir(base) as listing:
            entries = sorted((e for e in listing if e.name.isdigit()), key=lambda e: int(e.name))
    except OSError:
        entries = []
    for entry in entries:
        if seen >= MAX_PROCESSES or links >= MAX_FD_LINKS:
            stopped = True
            break
        proc = Path(entry.path)
        try:
            if entry.stat(follow_symlinks=False).st_uid != uid:
                continue
            fds = os.scandir(proc/'fd')
        except OSError:
            vanished += 1
            continue
        seen += 1
        held = []
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
                if target.startswith('socket:[') and target.endswith(']') and target[8:-1].isdigit() and int(target[8:-1]) in table:
                    held.append(table[int(target[8:-1])])
        if not held:
            continue
        try:
            executable = os.readlink(proc/'exe')
        except OSError:
            vanished += 1
            continue
        deleted = executable.endswith(' (deleted)')
        path = executable[:-len(' (deleted)')] if deleted else executable
        row = programs.get(path)
        if row is None:
            parent = _parent(proc)
            flags = []
            if path.startswith('/memfd:'):
                flags.append('EXECUTABLE_IN_MEMORY')
            elif deleted:
                flags.append('EXECUTABLE_DELETED')
            if path.startswith(TEMPORARY):
                flags.append('EXECUTABLE_IN_TEMPORARY')
            row = programs[path] = dict(program=_comm(proc/'comm'), executable=_short(path),
                                        parent=_comm(base/str(parent)/'comm') if parent else '?',
                                        processes=0, established=0, listening=0, other=0, remotes=[], remotes_total=0,
                                        flags=flags, _remotes=set())
        row['processes'] += 1
        for item in held:
            row[item['kind']] += 1
            if item['remote']:
                row['_remotes'].add(item['remote'])
    rows = []
    for row in programs.values():
        remotes = sorted(row.pop('_remotes'))
        row.update(remotes=remotes[:MAX_REMOTES], remotes_total=len(remotes))
        rows.append(row)
    rows.sort(key=lambda r: (not r['flags'], -(r['established'] + r['listening'] + r['other']), r['executable']))
    shown = rows[:MAX_PROGRAMS]
    gaps = []
    if not tables_complete:
        gaps.append('A socket table was not fully read; other connections may exist.')
    if stopped:
        gaps.append(f'The process scan stopped at {MAX_PROCESSES} processes or {MAX_FD_LINKS} open files; later processes were not reviewed.')
    if len(rows) > MAX_PROGRAMS:
        gaps.append(f'{len(rows)} programs hold network sockets; only the first {MAX_PROGRAMS} are listed.')
    if vanished:
        gaps.append(f'{vanished} processes of this account exited or could not be read during the scan.')
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
