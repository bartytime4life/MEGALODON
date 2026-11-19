"""Which programs talk out, and the first time a new one does.

An implant phoning home, an info-stealer uploading, a trojaned updater: each
is a program making outgoing connections it never made before (ATT&CK
T1071, T1041, T1105). The listener watch covers incoming connections.
`megalodon egress` learns which programs connect out, and to which ports, and
reports a program connecting out for the first time, a known program using a
new port, and any program running from a temporary folder, a deleted file
or memory that connects out.

It reads the kernel's socket tables and maps each new connection to its
process. As root every process is visible; otherwise only your own.
Read-only.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import stat
import tempfile
import time

from .process_network import TABLES, TEMPORARY, _endpoint, _program_kind, _read_table

SCHEMA = 'megalodon-egress-v1'
REPORT_SCHEMA = 'megalodon-egress-report-v1'
DEFAULT_MANIFEST = '~/.config/megalodon/egress.json'
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_PROGRAMS = 4096
MAX_PORTS = 256
MAX_NETWORKS = 256
MAX_FD_LINKS = 262144
MAX_ARGV = 512
COOLDOWN_SECONDS = 3600
OUTGOING = {'01': 'established', '02': 'syn_sent'}      # TCP states of a connection this side opened or holds
RANK = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')

RULES = {
    'OUTBOUND_FROM_TEMPORARY': ('HIGH', ['T1105', 'T1071'], 'A program running from a temporary folder, a deleted '
                                                            'file or memory is connecting out: how dropped tools '
                                                            'and implants usually run.'),
    'NEW_OUTBOUND_PROGRAM': ('HIGH', ['T1071', 'T1041'], 'A program that has not connected out before is '
                                                         'connecting out. New software does this; so does an '
                                                         'implant phoning home.'),
    'NEW_OUTBOUND_PORT': ('MEDIUM', ['T1571'], 'A program that connects out is using a port it has not used '
                                               'before.'),
    # Named from DNS answers and TLS server names, read while `egress watch` runs.
    'OUTBOUND_TO_WATCHLISTED_NAME': ('CRITICAL', ['T1071', 'T1568'], 'A program connects to a name on your watchlist.'),
    'OUTBOUND_TO_GENERATED_NAME': ('MEDIUM', ['T1568.002'], 'A program connects to a name spelled the way generated '
                                                            '(DGA) and encoded names are. Cloud and tracking names '
                                                            'are sometimes spelled this way too.'),
}


class EgressError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _scope(address):
    """'public', 'private' or None (loopback, link-local, multicast, unspecified: not outgoing traffic)."""
    mapped = getattr(address, 'ipv4_mapped', None)
    address = mapped or address
    if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
        return None
    return 'public' if address.is_global else 'private'


def _network(address):
    mapped = getattr(address, 'ipv4_mapped', None)
    address = mapped or address
    return str(ipaddress.ip_network(f'{address}/{24 if address.version == 4 else 48}', strict=False))


def connections(root='/', *, include_private=False):
    """Outgoing connections in this network namespace: {inode: (protocol, remote address, remote port)}."""
    found, gaps, tables = {}, [], []
    for protocol, _family, name, length in TABLES:
        try:
            lines, complete = _read_table(Path(root, 'proc/net', name))
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            gaps.append(f'/proc/net/{name} could not be read')
            continue
        if not complete:
            gaps.append(f'/proc/net/{name} was too large to read whole')
        tables.append((protocol, length, lines))
    # A connection a server accepted is established too, on the port it listens on: that one came in.
    listening = set()
    for protocol, length, lines in tables:
        for line in lines:
            fields = line.split()
            if protocol == 'tcp' and len(fields) > 3 and fields[3] == '0A':
                local = _endpoint(fields[1], length)
                if local is not None:
                    listening.add(local[1])
    for protocol, length, lines in tables:
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or not fields[9].isdigit() or fields[9] == '0':
                continue
            if protocol == 'tcp' and fields[3] not in OUTGOING:
                continue
            local = _endpoint(fields[1], length)
            if protocol == 'tcp' and local is not None and local[1] in listening:
                continue
            remote = _endpoint(fields[2], length)
            if remote is None or remote[1] == 0:
                continue                        # an unconnected UDP socket, or a listener
            scope = _scope(remote[0])
            if scope is None or (scope == 'private' and not include_private):
                continue
            found[int(fields[9])] = (protocol, remote[0], remote[1], scope, local[1] if local else None)
    return found, gaps


def _proc_info(proc):
    try:
        path = os.readlink(proc / 'exe')
    except OSError:
        return None
    deleted = path.endswith(' (deleted)')
    path = path.removesuffix(' (deleted)')
    try:
        with open(proc / 'cmdline', 'rb') as handle:
            argv = [a.decode('utf-8', 'replace') for a in handle.read(MAX_ARGV).split(b'\0') if a]
    except OSError:
        argv = []
    try:
        text = (proc / 'stat').read_text('utf-8', 'replace')
        start = int(text[text.rindex(')') + 2:].split()[19])
    except (OSError, ValueError, IndexError):
        start = None
    try:
        cwd = os.readlink(proc / 'cwd')
    except OSError:
        cwd = None
    return dict(path=path, deleted=deleted, argv=argv, start=start, cwd=cwd)


def script(info):
    """The script an interpreter or shell runs: an absolute path, `-m module`, or None."""
    if _program_kind(info['path'], '') not in ('interpreter', 'shell'):
        return None
    argv = info['argv'][1:]
    if '-m' in argv and argv.index('-m') + 1 < len(argv):
        return f"-m {argv[argv.index('-m') + 1]}"
    operands = [a for a in argv if not a.startswith('-')]
    if not operands or '\n' in operands[0]:
        return None
    operand = operands[0]
    if not operand.startswith('/'):
        # `python3 backup.py` names a file in the working directory; without it, keep the name as given.
        operand = os.path.normpath(os.path.join(info['cwd'], operand)) if info.get('cwd') else f'./{operand}'
    return operand


def identity(info):
    """A program is its executable; for a script interpreter, the executable and the script it runs."""
    found = script(info)
    return f"{info['path']} {found}" if found else info['path']


def owners(root, inodes):
    """{inode: (pid, info)} for the given socket inodes, reading each process's descriptors once."""
    wanted, found, links = set(inodes), {}, 0
    base = Path(root, 'proc')
    try:
        with os.scandir(base) as listing:
            pids = [e.name for e in listing if e.name.isdigit()]
    except OSError:
        return found, True
    truncated = False
    for pid in pids:
        if not wanted - set(found):
            break
        try:
            descriptors = os.scandir(base / pid / 'fd')
        except OSError:
            continue
        info = None
        with descriptors:
            for fd in descriptors:
                links += 1
                if links > MAX_FD_LINKS:
                    truncated = True
                    break
                try:
                    target = os.readlink(fd.path)
                except OSError:
                    continue
                if target.startswith('socket:[') and target[8:-1].isdigit() and int(target[8:-1]) in wanted:
                    info = info or _proc_info(base / pid)
                    if info is not None:
                        found[int(target[8:-1])] = (int(pid), info)
        if truncated:
            break
    return found, truncated


def observe(root='/', *, include_private=False, known=None):
    """Current outgoing connections with their programs; `known` caches inode owners between calls."""
    known = {} if known is None else known
    table, gaps = connections(root, include_private=include_private)
    for inode in [i for i in known if i not in table]:
        del known[inode]
    missing = [i for i in table if i not in known]
    if missing:
        resolved, truncated = owners(root, missing)
        known.update(resolved)
        if truncated:
            gaps.append('too many open files to map every connection to its program')
    seen, unattributed = [], 0
    for inode, (protocol, address, port, scope, local_port) in table.items():
        owner = known.get(inode)
        if owner is None:
            unattributed += 1
            continue
        pid, info = owner
        seen.append(dict(inode=inode, protocol=protocol, address=str(address), port=port, scope=scope, pid=pid,
                         local_port=local_port,
                         start=info['start'], program=identity(info), executable=info['path'], script=script(info),
                         deleted=info['deleted'], argv=info['argv'][:8]))
    if unattributed:
        gaps.append(f'{unattributed} outgoing connections could not be matched to a program'
                    + ('; run as root to see every process' if os.geteuid() else ''))
    return seen, gaps


# ------------------------------------------------------------------ the baseline

def _empty():
    return dict(schema=SCHEMA, recorded_at=_now(), programs={})


def _write(path, value):
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.egress-', dir=path.parent)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, sort_keys=True, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def read(path):
    path = Path(path).expanduser()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise EgressError(f'no egress baseline at {path}; run megalodon egress learn') from None
    except OSError as exc:
        raise EgressError(f'egress baseline {path} cannot be opened: {exc.strerror}') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise EgressError(f'egress baseline {path} must be a mode-600 file owned by you')
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise EgressError('egress baseline is too large')
    try:
        value = json.loads(raw)
    except ValueError:
        raise EgressError('egress baseline is not valid JSON') from None
    if type(value) is not dict or value.get('schema') != SCHEMA or type(value.get('programs')) is not dict:
        raise EgressError('egress baseline has an unsupported format')
    return value


def record(baseline, connection):
    """Add one observed connection to the baseline."""
    programs = baseline['programs']
    entry = programs.get(connection['program'])
    if entry is None:
        if len(programs) >= MAX_PROGRAMS:
            return False
        entry = programs[connection['program']] = dict(ports=[], networks=[], first_seen=_now())
    port = f"{connection['protocol']}/{connection['port']}"
    if port not in entry['ports'] and len(entry['ports']) < MAX_PORTS:
        entry['ports'] = sorted(entry['ports'] + [port])
    network = _network(ipaddress.ip_address(connection['address']))
    if network not in entry['networks'] and len(entry['networks']) < MAX_NETWORKS:
        entry['networks'] = sorted(entry['networks'] + [network])
    entry['last_seen'] = _now()
    return True


def _temporary(connection):
    path, run = connection['executable'], connection.get('script') or ''
    return (connection['deleted'] or path.startswith(TEMPORARY) or path.startswith('/memfd:')
            or run.startswith(TEMPORARY))      # `python3 /tmp/stage2.py`: the interpreter is installed, the script is not


def judge(baseline, connection, watchlist=None):
    """Findings for one connection against the baseline (empty when it is known)."""
    found, entry = [], baseline['programs'].get(connection['program'])
    names = connection.get('names') or []
    where = (f"{names[0]} ({connection['address']}):{connection['port']}/{connection['protocol']}" if names
             else f"{connection['address']}:{connection['port']}/{connection['protocol']}")
    for name in names:
        hit = watchlist.match_domain(name) if watchlist is not None else None
        if hit:
            found.append(_finding('OUTBOUND_TO_WATCHLISTED_NAME', connection,
                                  f"{connection['program']} (pid {connection['pid']}) connects to {name} "
                                  f"({connection['address']}:{connection['port']}/{connection['protocol']}), "
                                  f"on the watchlist as {hit[0]}{': ' + hit[1] if hit[1] else ''}", name=name))
            break
    for name in names:
        from .domain_signals import assess
        signals = assess(name)
        if signals and signals['level'] == 'review':
            found.append(_finding('OUTBOUND_TO_GENERATED_NAME', connection,
                                  f"{connection['program']} (pid {connection['pid']}) connects to {name} "
                                  f"({connection['address']}): " + ' '.join(s['detail'] for s in signals['signals'][:2]),
                                  name=name))
            break
    if _temporary(connection):
        found.append(_finding('OUTBOUND_FROM_TEMPORARY', connection,
                              f"{connection['program']} (pid {connection['pid']}), run from "
                              f"{'a deleted file' if connection['deleted'] else 'a temporary folder or memory'}, "
                              f"connects to {where}"))
    if entry is None:
        found.append(_finding('NEW_OUTBOUND_PROGRAM', connection,
                              f"{connection['program']} (pid {connection['pid']}) connects out for the first time, "
                              f"to {where}"))
    elif not entry.get('any_port') and f"{connection['protocol']}/{connection['port']}" not in entry['ports']:
        found.append(_finding('NEW_OUTBOUND_PORT', connection,
                              f"{connection['program']} (pid {connection['pid']}) uses a new port: {where}"))
    return found


def _finding(rule, connection, detail, name=None):
    severity, techniques, summary = RULES[rule]
    if rule == 'NEW_OUTBOUND_PROGRAM' and connection['scope'] == 'private':
        severity = 'MEDIUM'
    extra = dict(name=name) if name else {}
    return dict(rule_id=rule, severity=severity, techniques=techniques, program=connection['program'],
                detail=detail, summary=summary, address=connection['address'], port=connection['port'],
                names=list(connection.get('names') or []), **extra,
                # `egress watch | respond ingest` reads the destination from dst_ip, as for network findings.
                dst_ip=connection['address'],
                protocol=connection['protocol'], detected_at=_now(),
                evidence=dict(processes=[dict(program=connection['executable'], pid=connection['pid'],
                                              start=connection['start'])],
                              argv=connection['argv']))


def learn(manifest=DEFAULT_MANIFEST, *, seconds=0, interval=1.0, root='/', include_private=False, clock=time.monotonic,
          sleep=time.sleep):
    """Record every program seen connecting out, now and for `seconds` more, into the baseline."""
    path = Path(manifest).expanduser()
    baseline = read(path) if path.exists() else _empty()
    known, gaps, observed = {}, set(), 0
    deadline = clock() + max(0, seconds)
    while True:
        seen, more = observe(root, include_private=include_private, known=known)
        gaps.update(more)
        for connection in seen:
            if not _temporary(connection):      # a program run from a temporary folder is never learned as normal
                observed += record(baseline, connection)
        if clock() >= deadline:
            break
        sleep(interval)
    baseline['recorded_at'] = _now()
    baseline['include_private'] = include_private
    _write(path, baseline)
    return dict(schema=REPORT_SCHEMA, action='learn', manifest=str(path), programs=len(baseline['programs']),
                connections_recorded=observed, gaps=sorted(gaps))


def allow(manifest, program, port=None):
    """After review: record a program, and optionally one of its ports ('tcp/443'), as normal."""
    path = Path(manifest).expanduser()
    baseline = read(path) if path.exists() else _empty()
    entry = baseline['programs'].setdefault(program, dict(ports=[], networks=[], first_seen=_now()))
    if port:
        if not (port.count('/') == 1 and port.split('/')[0] in ('tcp', 'udp') and port.split('/')[1].isdigit()):
            raise EgressError('a port is written tcp/443 or udp/53')
        entry['ports'] = sorted(set(entry['ports']) | {port})
    else:
        entry['any_port'] = True           # reviewed as normal wherever it connects
    _write(path, baseline)
    return dict(manifest=str(path), program=program, ports=entry['ports'])


def check(manifest=DEFAULT_MANIFEST, *, root='/'):
    baseline = read(manifest)
    seen, gaps = observe(root, include_private=baseline.get('include_private', False))
    findings = [f for connection in seen for f in judge(baseline, connection)]
    findings.sort(key=lambda f: (RANK.index(f['severity']), f['program'], f['port']))
    return dict(schema=REPORT_SCHEMA, action='check', manifest=str(Path(manifest).expanduser()), checked_at=_now(),
                connections=len(seen), findings=findings, gaps=gaps,
                note='Review each program; `megalodon egress allow PROGRAM` records one as normal.')


class Watcher:
    """Poll the socket tables and report each new finding once per hour."""

    def __init__(self, manifest=DEFAULT_MANIFEST, emit=print, *, root='/', interval=1.0, clock=time.monotonic,
                 names=None, watchlist=None):
        self.manifest, self.emit, self.root, self.interval, self.clock = manifest, emit, root, interval, clock
        self.names, self.watchlist = names, watchlist
        self.baseline, self.loaded = read(manifest), self._stamp()
        self.known, self.last, self.stats = {}, {}, dict(polls=0, findings=0)

    def _stamp(self):
        try:
            info = os.stat(Path(self.manifest).expanduser())
            return (info.st_mtime_ns, info.st_size, info.st_ino)
        except OSError:
            return None

    def poll(self):
        self.stats['polls'] += 1
        stamp = self._stamp()
        if stamp != self.loaded:                 # `allow` or `learn` changed the baseline while watching
            self.baseline, self.loaded = read(self.manifest), stamp
        seen, _ = observe(self.root, include_private=self.baseline.get('include_private', False), known=self.known)
        now, out = self.clock(), []
        for connection in seen:
            if self.names is not None:
                connection['names'] = self.names.lookup(connection['address'], connection['port'],
                                                        connection.get('local_port'))
            for found in judge(self.baseline, connection, self.watchlist):
                key = (found['rule_id'], found['program'], found['protocol'], found['port'], found.get('name'))
                if now - self.last.get(key, -1e18) < COOLDOWN_SECONDS:
                    continue
                self.last[key] = now
                self.stats['findings'] += 1
                out.append(found)
                self.emit(found)
        if len(self.last) > 65536:
            self.last.clear()
        return out

    def run(self, stop):
        while not stop.is_set():
            self.poll()
            stop.wait(self.interval)
