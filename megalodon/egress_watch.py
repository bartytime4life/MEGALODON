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

As root, the socket tables of every network namespace are read, not only this
one's: a container with its own network is watched too. A connection from
another namespace names its container (or namespace), and its program is
recorded apart from the host's: `[container] /usr/bin/curl` is not
`/usr/bin/curl`.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import select
import stat
import sys
import tempfile
import time

from . import closed_connections, net_namespaces
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
    # Heard as the connection closed, between two scans: too late to name the program.
    'BRIEF_OUTBOUND_CONNECTION': ('MEDIUM', ['T1071', 'T1041'], 'A connection opened and closed between two scans, '
                                                                'to a port and network no learned program uses. Its '
                                                                'program was gone before it could be named: a short '
                                                                'beacon or upload looks like this, and so does a '
                                                                'quick update check.'),
}
MAX_DESTINATIONS = 4096
UNNAMED = '(closed before it was seen)'


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


def connections(root='/', *, include_private=False, net='proc/net', listeners=None):
    """Outgoing connections in one network namespace: {inode: (protocol, remote address, remote port)}.

    `net` is that namespace's table folder: `proc/net` for this one, `proc/PID/net` for the one PID is in. The TCP
    ports listened on are added to the set `listeners`, when given.
    """
    found, gaps, tables = {}, [], []
    for protocol, _family, name, length in TABLES:
        try:
            lines, complete = _read_table(Path(root, net, name))
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            gaps.append(f'/{net}/{name} could not be read')
            continue
        if not complete:
            gaps.append(f'/{net}/{name} was too large to read whole')
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
    if listeners is not None:
        listeners.update(listening)
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


def every_connection(root='/', *, include_private=False, listeners=None, spaces=None):
    """Outgoing connections in every network namespace that can be read: ({inode: connection}, {inode: namespace},
    gaps). Socket inodes are unique across namespaces, so one table holds them all.

    `listeners`, when given, is filled with {namespace id, or None for this one: TCP ports listened on}, and `spaces`
    (a list) with the namespaces read."""
    found_spaces, gaps = net_namespaces.namespaces(root)
    if spaces is not None:
        spaces.extend(found_spaces)
    table, where = {}, {}
    for space in found_spaces:
        ports = None if listeners is None else listeners.setdefault(None if space['own'] else space['id'], set())
        found, more = connections(root, include_private=include_private, net=space['net'], listeners=ports)
        gaps += more
        for inode, connection in found.items():
            if inode not in table:
                table[inode] = connection
                if not space['own']:
                    where[inode] = space
    return table, where, gaps


def observe(root='/', *, include_private=False, known=None, listeners=None, spaces=None):
    """Current outgoing connections with their programs; `known` caches inode owners between calls."""
    known = {} if known is None else known
    table, where, gaps = every_connection(root, include_private=include_private, listeners=listeners, spaces=spaces)
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
        connection = dict(inode=inode, protocol=protocol, address=str(address), port=port, scope=scope, pid=pid,
                          local_port=local_port,
                          start=info['start'], program=identity(info), executable=info['path'], script=script(info),
                          deleted=info['deleted'], argv=info['argv'][:8])
        space = where.get(inode)
        if space is not None:
            # Inside a container, /usr/bin/curl is the container's, not the host's: its own entry in the baseline.
            # Containers come and go with new IDs, so they share one: what any container may run.
            connection.update(namespace=space['id'], container=space['container'],
                              program=f"[{'container' if space['container'] else 'namespace'}] {connection['program']}")
        seen.append(connection)
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
    if connection.get('namespace') and baseline.get('all_namespaces') is not True:
        # A baseline learned before other namespaces were read knows nothing of them: listed, not reported as new.
        return found
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
    if connection.get('closed'):
        extra.update(closed=True, sent=connection.get('sent'), received=connection.get('received'))
    if connection.get('namespace'):
        extra.update(namespace=connection['namespace'], container=connection.get('container'))
        detail = f"in {net_namespaces.label(dict(id=connection['namespace'], container=connection.get('container')))}: " \
                 + detail
    return dict(rule_id=rule, severity=severity, techniques=techniques, program=connection['program'],
                detail=detail, summary=summary, address=connection['address'], port=connection['port'],
                names=list(connection.get('names') or []), **extra,
                # `egress watch | respond ingest` reads the destination from dst_ip, as for network findings.
                dst_ip=connection['address'],
                protocol=connection['protocol'], detected_at=_now(),
                evidence=dict(processes=[dict(program=connection['executable'], pid=connection['pid'],
                                              start=connection['start'])] if connection.get('executable') else [],
                              argv=connection.get('argv') or []))


# ------------------------------------------------------------------ connections heard as they closed

def _kind(namespace, container):
    """How a program's entry is prefixed for where it runs: '' here, '[container] ' or '[namespace] ' elsewhere."""
    return '' if namespace is None else ('[container] ' if container else '[namespace] ')


def destination(protocol, port, address, namespace=None, container=None):
    """How a learned or allowed destination is written: `tcp/443@203.0.113.0/24`, prefixed as programs are."""
    return f"{_kind(namespace, container)}{protocol}/{port}@{_network(ipaddress.ip_address(address))}"


def _parse_destination(text):
    kind, _, rest = text.rpartition('] ')
    kind = f'{kind}] ' if kind else ''
    where, _, network = rest.partition('@')
    protocol, _, port = where.partition('/')
    if kind not in ('', '[container] ', '[namespace] ') or protocol not in ('tcp', 'udp') or not port.isdigit() \
            or not 0 < int(port) < 65536:
        raise EgressError('a destination is written tcp/443@203.0.113.0/24, or [container] tcp/443@...')
    try:
        network = ipaddress.ip_network(network, strict=False)
    except ValueError:
        raise EgressError(f'{network!r} is not a network, such as 203.0.113.0/24 or 0.0.0.0/0') from None
    return kind, protocol, int(port), network


def known_destination(baseline, connection):
    """Whether a learned program, or a learned or allowed destination, already uses this port and network."""
    kind = _kind(connection.get('namespace'), connection.get('container'))
    address = ipaddress.ip_address(connection['address'])
    address = getattr(address, 'ipv4_mapped', None) or address
    port, network = f"{connection['protocol']}/{connection['port']}", _network(address)
    for name, entry in baseline['programs'].items():
        if (name.startswith(kind) if kind else not name.startswith('[')) and network in entry.get('networks', ()) and (
                entry.get('any_port') or port in entry.get('ports', ())):
            return True
    for text in baseline.get('destinations', ()):
        try:
            listed_kind, protocol, number, listed = _parse_destination(text)
        except EgressError:
            continue
        if listed_kind == kind and protocol == connection['protocol'] and number == connection['port'] \
                and address.version == listed.version and address in listed:
            return True
    return False


def heard(closed, namespace=None, container=None, *, include_private=False, listening=()):
    """A closed socket as an outgoing connection, or None: a listener, an accepted connection, local traffic."""
    if closed['port'] == 0:
        return None
    scope = _scope(closed['address'])
    if scope is None or (scope == 'private' and not include_private):
        return None
    if closed['protocol'] == 'tcp' and closed['local_port'] in listening:
        return None                         # accepted on a port listened on: it came in
    return dict(protocol=closed['protocol'], address=str(closed['address']), port=closed['port'], scope=scope,
                local_port=closed['local_port'], closed=True, sent=closed['sent'], received=closed['received'], namespace=namespace, container=container,
                program=_kind(namespace, container) + UNNAMED, pid=None)


def _seen(connection):
    return (connection.get('namespace'), connection['protocol'], connection.get('local_port'), connection['address'],
            connection['port'])


def judge_closed(baseline, connection, watchlist=None):
    """Findings for one connection heard as it closed, never seen by a scan."""
    found, names = [], connection.get('names') or []
    where = (f"{names[0]} ({connection['address']}):{connection['port']}/{connection['protocol']}" if names
             else f"{connection['address']}:{connection['port']}/{connection['protocol']}")
    amount = ('' if connection.get('sent') is None else
              f", sending about {connection['sent']} bytes and receiving about {connection['received']}")
    who = 'a program, gone before it could be named,'
    for name in names:
        hit = watchlist.match_domain(name) if watchlist is not None else None
        if hit:
            found.append(_finding('OUTBOUND_TO_WATCHLISTED_NAME', connection,
                                  f"{who} connected to {name} ({connection['address']}:{connection['port']}/"
                                  f"{connection['protocol']}){amount}, on the watchlist as {hit[0]}"
                                  f"{': ' + hit[1] if hit[1] else ''}", name=name))
            break
    for name in names:
        from .domain_signals import assess
        signals = assess(name)
        if signals and signals['level'] == 'review':
            found.append(_finding('OUTBOUND_TO_GENERATED_NAME', connection,
                                  f"{who} connected to {name} ({connection['address']}){amount}: "
                                  + ' '.join(s['detail'] for s in signals['signals'][:2]), name=name))
            break
    if connection.get('namespace') and baseline.get('all_namespaces') is not True:
        return found
    if not known_destination(baseline, connection):
        finding = _finding('BRIEF_OUTBOUND_CONNECTION', connection,
                           f"{who} opened a connection to {where}{amount}, and closed it between two scans")
        if connection['scope'] == 'private':
            finding['severity'] = 'LOW'
        found.append(finding)
    return found


def record_destination(baseline, connection):
    """Learn one connection heard as it closed, by its port and network."""
    listed = baseline.setdefault('destinations', [])
    text = destination(connection['protocol'], connection['port'], connection['address'],
                       connection.get('namespace'), connection.get('container'))
    if text in listed or len(listed) >= MAX_DESTINATIONS:
        return False
    listed.append(text)
    listed.sort()
    return True


def _closings(root, closings):
    if closings == 'auto':
        return closed_connections.Closings(root) if root == '/' else None
    return closings


def learn(manifest=DEFAULT_MANIFEST, *, seconds=0, interval=1.0, root='/', include_private=False, clock=time.monotonic,
          sleep=time.sleep, all_namespaces=None, closings='auto'):
    """Record every program seen connecting out, now and for `seconds` more, into the baseline.

    While learning for `seconds`, connections too short for a scan are heard as they close and recorded by their
    port and network: the program is gone by then."""
    path = Path(manifest).expanduser()
    baseline = read(path) if path.exists() else _empty()
    known, gaps, observed, brief = {}, set(), 0, 0
    closings = _closings(root, closings) if seconds > 0 else None
    live, listeners, containers = set(), {}, {}
    deadline = clock() + max(0, seconds)
    try:
        while True:
            if closings is not None:
                for space, closed in closings.drain():
                    connection = heard(closed, space, containers.get(space), include_private=include_private,
                                       listening=listeners.get(space, ()))
                    if connection is not None and _seen(connection) not in live:
                        brief += record_destination(baseline, connection)
            listeners, spaces = {}, []
            seen, more = observe(root, include_private=include_private, known=known, listeners=listeners,
                                 spaces=spaces)
            gaps.update(more)
            live = {_seen(connection) for connection in seen}
            containers = {space['id']: space.get('container') for space in spaces}
            if closings is not None:
                closings.subscribe(spaces)
                gaps.update(closings.gaps)
            for connection in seen:
                if not _temporary(connection):      # a program run from a temporary folder is never learned as normal
                    observed += record(baseline, connection)
            if clock() >= deadline:
                break
            sleep(interval)
    finally:
        if closings is not None:
            closings.close()
    baseline['recorded_at'] = _now()
    baseline['include_private'] = include_private
    # Learned as root, every namespace was read: what other namespaces run from now on is compared, not listed.
    if os.geteuid() == 0 if all_namespaces is None else all_namespaces:
        baseline['all_namespaces'] = True
    _write(path, baseline)
    return dict(schema=REPORT_SCHEMA, action='learn', manifest=str(path), programs=len(baseline['programs']),
                connections_recorded=observed, brief_destinations_recorded=brief, gaps=sorted(gaps))


def allow(manifest, program=None, port=None, destination=None):
    """After review: record a program, and optionally one of its ports ('tcp/443'), as normal; or a destination
    ('tcp/443@203.0.113.0/24'), for connections too short to name their program."""
    path = Path(manifest).expanduser()
    baseline = read(path) if path.exists() else _empty()
    if destination is not None:
        kind, protocol, number, network = _parse_destination(destination)
        text = f'{kind}{protocol}/{number}@{network}'
        listed = baseline.setdefault('destinations', [])
        if text not in listed:
            listed.append(text)
            listed.sort()
        _write(path, baseline)
        return dict(manifest=str(path), destination=text)
    if not program:
        raise EgressError('name a program, or a destination with --destination')
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
    report = dict(schema=REPORT_SCHEMA, action='check', manifest=str(Path(manifest).expanduser()), checked_at=_now(),
                  connections=len(seen), findings=findings, gaps=gaps,
                  note='Review each program; `megalodon egress allow PROGRAM` records one as normal.')
    if baseline.get('all_namespaces') is not True:
        unlearned = sorted({(c['program'], c.get('container') or c['namespace']) for c in seen if c.get('namespace')})
        if unlearned:
            report['newly_watched'] = [dict(program=program, where=where) for program, where in unlearned]
            report['note'] += (' Programs in other network namespaces (containers) are listed under newly_watched: '
                               'the baseline was learned before they were read. Run `megalodon egress learn` as '
                               'root to start comparing them.')
    return report


class Watcher:
    """Poll the socket tables and report each new finding once per hour."""

    def __init__(self, manifest=DEFAULT_MANIFEST, emit=print, *, root='/', interval=1.0, clock=time.monotonic,
                 names=None, watchlist=None, closings='auto', warn=None):
        self.manifest, self.emit, self.root, self.interval, self.clock = manifest, emit, root, interval, clock
        self.names, self.watchlist = names, watchlist
        self.baseline, self.loaded = read(manifest), self._stamp()
        self.known, self.last, self.stats = {}, {}, dict(polls=0, findings=0, closed=0, brief=0)
        # Connections too short for a scan are heard as they close (as root), from this namespace and, once a scan
        # has listed them, every other one.
        self.closings = _closings(root, closings)
        self.warn = warn or (lambda text: print(f'megalodon: {text}', file=sys.stderr, flush=True))
        self.live, self.listeners, self.containers, self.warned, self.missed = set(), {}, {}, set(), 0
        self._tell()

    def _tell(self):
        if self.closings is None:
            return
        for gap in sorted(self.closings.gaps - self.warned):
            self.warned.add(gap)
            self.warn(gap)
        if self.closings.missed > self.missed:
            self.warn(f'{self.closings.missed - self.missed} bursts of closed connections came faster than they '
                      'could be read: some short connections were missed')
            self.missed = self.closings.missed

    def _report(self, found, now, where):
        key = (found['rule_id'], found['program'], found['protocol'], found['port'], found.get('name') or where)
        if now - self.last.get(key, -1e18) < COOLDOWN_SECONDS:
            return False
        self.last[key] = now
        self.stats['findings'] += 1
        self.emit(found)
        return True

    def hear(self):
        """Judge the connections heard closing since the last call that no scan saw."""
        if self.closings is None:
            return []
        out, now = [], self.clock()
        include_private = self.baseline.get('include_private', False)
        for space, closed in self.closings.drain():
            self.stats['closed'] += 1
            connection = heard(closed, space, self.containers.get(space), include_private=include_private,
                               listening=self.listeners.get(space, ()))
            if connection is None or _seen(connection) in self.live:
                continue                    # a scan saw it open, and judged it with its program
            self.stats['brief'] += 1
            if self.names is not None:
                connection['names'] = self.names.lookup(connection['address'], connection['port'],
                                                        connection.get('local_port'))
            for found in judge_closed(self.baseline, connection, self.watchlist):
                if self._report(found, now, _network(ipaddress.ip_address(connection['address']))):
                    out.append(found)
        self._tell()
        return out

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
        out = self.hear()                       # before the scan, while the last one's connections are known
        listeners, spaces = {}, []
        seen, _ = observe(self.root, include_private=self.baseline.get('include_private', False), known=self.known,
                          listeners=listeners, spaces=spaces)
        self.live, self.listeners = {_seen(connection) for connection in seen}, listeners
        self.containers = {space['id']: space.get('container') for space in spaces}
        if self.closings is not None:
            self.closings.subscribe(spaces)
            self._tell()
        now = self.clock()
        for connection in seen:
            if self.names is not None:
                connection['names'] = self.names.lookup(connection['address'], connection['port'],
                                                        connection.get('local_port'))
            for found in judge(self.baseline, connection, self.watchlist):
                if self._report(found, now, None):
                    out.append(found)
        if len(self.last) > 65536:
            self.last.clear()
        return out

    def run(self, stop):
        """Scan every `interval` seconds, and judge each connection heard closing as soon as it is heard."""
        try:
            due = self.clock()
            while not stop.is_set():
                if self.clock() >= due:
                    self.poll()
                    due = self.clock() + self.interval
                wait = max(0.0, min(due - self.clock(), 1.0))
                listening = self.closings.filenos() if self.closings is not None else []
                if not listening:
                    stop.wait(wait)
                    continue
                try:
                    ready, _, _ = select.select(listening, [], [], wait)
                except (OSError, ValueError):
                    stop.wait(wait)
                    continue
                if ready:
                    self.hear()
        finally:
            if self.closings is not None:
                self.closings.close()
