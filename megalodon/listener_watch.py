"""Baseline and check which programs listen for network connections on this machine.

A backdoor or bind shell has to listen somewhere. ``megalodon listeners
baseline`` records every listening TCP socket and every bound UDP service
port, with the addresses it is reachable on and the programs that own it.
``megalodon listeners check`` reports what changed:

* ``NEW_LISTENER``: a port that was not listening before. HIGH when a shell,
  a script interpreter or a network relay tool (nc, socat...) owns it, or its
  program runs from a temporary folder, from memory or from a deleted file;
  MEDIUM when it is reachable from other machines; LOW on loopback only.
* ``LISTENER_PROGRAM_CHANGED``: a known port is now served by a different
  program, as when a service binary is swapped.
* ``LISTENER_EXPOSED``: a known port became reachable more widely, for
  example from loopback only to every interface.
* ``LISTENER_OPENED_AND_CLOSED`` (``watch``, as root): a port reachable from
  other machines that opened and closed between two checks, as a bind shell
  that takes one connection does. The kernel announces the socket as it
  closes, without its program.

Only metadata is kept: protocol, port, local addresses, and each owner's
executable path and process name. Command lines, process IDs and traffic are
never read or stored. Owners of other accounts' sockets need root to see; the
report lists that as a coverage gap. Nothing is stopped or changed: ``accept``
records the reviewed state as the new baseline.

As root, every network namespace's listeners are read, not only this one's. A
listener in a container is keyed by kind, ``container/tcp:8080``, so it never
merges with the host's ``tcp:8080``, and containers recreated with new IDs keep
the same key. The containers that hold it now are listed under ``where``.
"""
from __future__ import annotations

from collections import OrderedDict, deque
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
from .process_network import (TABLES, TCP_LISTEN, TEMPORARY, _endpoint, _loopback, _program_kind,
                              _read_table, _short, _shown)

SCHEMA = 'megalodon-listener-manifest-v1'
REPORT_SCHEMA = 'megalodon-listener-check-v1'
DEFAULT_MANIFEST = '~/.config/megalodon/listeners.json'
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_PROCESSES = 65536
MAX_FD_LINKS = 1_000_000
MAX_PROGRAMS = 8
MAX_ADDRESSES = 64
# Baselines written before addresses_complete existed kept at most this many addresses.
_LEGACY_MAX_ADDRESSES = 16
RANK = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
SCOPES = ('loopback', 'specific', 'all')  # Increasing reach.
# Relays that turn a port into a shell or a tunnel.
NETWORK_TOOLS = frozenset({'nc', 'ncat', 'netcat', 'nc.openbsd', 'nc.traditional', 'socat', 'cryptcat',
                           'pwncat', 'telnetd', 'in.telnetd'})
TECHNIQUES = {
    'NEW_LISTENER': 'T1571',
    'LISTENER_PROGRAM_CHANGED': 'T1543',
    'LISTENER_EXPOSED': 'T1133',
    'LISTENER_OPENED_AND_CLOSED': 'T1571',
}
SHELL_TECHNIQUE = 'T1059'
DEFAULT_EPHEMERAL = (32768, 60999)
WATCH_INTERVAL = 10.0
# One brief listener is reported at most once in this many seconds, and at most this many an hour in all: an FTP server's
# passive data ports open and close all day.
CLOSED_COOLDOWN_SECONDS = 300.0
MAX_CLOSED_PER_HOUR = 30
MAX_SEEN = 65536


class ListenerError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _ephemeral(root):
    """The local port range the kernel hands to outgoing sockets."""
    try:
        low, high = (int(part) for part in
                     Path(root, 'proc/sys/net/ipv4/ip_local_port_range').read_text('ascii').split()[:2])
        if 1 <= low <= high <= 65535:
            return low, high
    except (OSError, ValueError):
        pass
    return DEFAULT_EPHEMERAL


def _listening(root, net='proc/net', clients=None):
    """{inode: (protocol, address, port)} for listening TCP sockets and bound UDP service ports, plus gaps.

    `net` is one namespace's table folder: `proc/net` for this one, `proc/PID/net` for the one PID is in. With
    `clients`, the unconnected UDP sockets left out as clients are put there, so their owners can be looked at.
    """
    low, high = _ephemeral(root)
    found, gaps = {}, []
    for protocol, family, name, length in TABLES:
        path = Path(root, net, name)
        try:
            lines, complete = _read_table(path)
        except FileNotFoundError:
            if family != 'ipv6' or os.path.lexists(Path(root, net, 'if_inet6')):
                gaps.append(f'/{net}/{name} is missing')
            continue
        except (OSError, ValueError):
            gaps.append(f'/{net}/{name} could not be read')
            continue
        if not complete:
            gaps.append(f'/{net}/{name} was too large to read whole')
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or not fields[9].isdigit() or fields[9] == '0':
                continue
            local, remote = _endpoint(fields[1], length), _endpoint(fields[2], length)
            if local is None or remote is None or local[1] == 0:
                continue
            if protocol == 'tcp':
                if fields[3] != TCP_LISTEN:
                    continue
            elif not (remote[1] == 0 and remote[0].is_unspecified):
                continue
            elif low <= local[1] <= high:
                # An unconnected UDP socket on an outgoing-range port is a client, not a service, unless its owner
                # says otherwise (see snapshot).
                if clients is not None:
                    clients[int(fields[9])] = (protocol, local[0], local[1])
                continue
            found[int(fields[9])] = (protocol, local[0], local[1])
    return found, gaps


def _owners(root, inodes):
    """{inode: {program path: program}} from the /proc/<pid>/fd links this account can read."""
    owners: dict[int, dict[str, dict]] = {}
    unreadable = links = 0
    try:
        entries = [e for e in os.scandir(Path(root, 'proc')) if e.name.isdigit()][:MAX_PROCESSES]
    except OSError:
        return owners, ['/proc could not be listed']
    for entry in entries:
        proc = Path(entry.path)
        try:
            descriptors = os.listdir(proc / 'fd')
        except OSError:
            unreadable += 1
            continue
        held = set()
        for fd in descriptors:
            links += 1
            if links > MAX_FD_LINKS:
                break
            try:
                target = os.readlink(proc / 'fd' / fd)
            except OSError:
                continue
            if target.startswith('socket:[') and target.endswith(']') and target[8:-1].isdigit():
                inode = int(target[8:-1])
                if inode in inodes:
                    held.add(inode)
        if not held:
            continue
        program = _program(proc)
        for inode in held:
            owners.setdefault(inode, {})[program['path']] = program
    gaps = []
    if links > MAX_FD_LINKS:
        gaps.append('too many open files to map every socket to its program')
    if unreadable and os.geteuid() != 0:
        gaps.append(f'{unreadable} processes of other accounts are not visible; run as root to see every owner')
    return owners, gaps


def _program(proc):
    try:
        comm = _short(Path(proc, 'comm').read_text('utf-8', 'replace').strip()) or '?'
    except OSError:
        comm = '?'
    try:
        path = os.readlink(Path(proc, 'exe'))
    except OSError:
        path = None
    flags = []
    if path and path.endswith(' (deleted)'):
        path, flags = path[:-len(' (deleted)')], ['deleted']
    if path and path.startswith('/memfd:'):
        flags.append('in_memory')
    if path and path.startswith(TEMPORARY):
        flags.append('temporary')
    shown = _short(path) if path else f'[{comm}]'
    kind = _program_kind(path or '', comm)
    name = (path or '').rsplit('/', 1)[-1]
    if name in NETWORK_TOOLS or comm in NETWORK_TOOLS:
        kind = 'network_tool'
    item = dict(path=shown, name=comm)
    if kind:
        item['kind'] = kind
    if flags:
        item['flags'] = flags
    return item


def _scope(addresses):
    if any(a.is_unspecified or getattr(a, 'ipv4_mapped', None) and a.ipv4_mapped.is_unspecified
           for a in addresses):
        return 'all'
    return 'loopback' if all(_loopback(a) for a in addresses) else 'specific'


def _kind(key):
    """'container' or 'namespace' for a listener in another network namespace, None for this one's."""
    head = key.split(':', 1)[0]
    return head.split('/', 1)[0] if '/' in head else None


def snapshot(*, root='/', all_namespaces=None):
    """Listeners in this network namespace and, with `all_namespaces` (the default for root), in every other one."""
    all_namespaces = os.geteuid() == 0 if all_namespaces is None else all_namespaces
    spaces, gaps = net_namespaces.namespaces(root) if all_namespaces else ([dict(own=True, net='proc/net')], [])
    sockets, where, clients = {}, {}, {}
    for space in spaces:
        maybe = {}
        found, more = _listening(root, space['net'], maybe)
        gaps += more
        for table, into in ((found, sockets), (maybe, clients)):
            for inode, socket in table.items():
                if inode not in sockets and inode not in clients:
                    into[inode] = socket
                    if not space.get('own'):
                        where[inode] = space
    owners, owner_gaps = _owners(root, set(sockets) | set(clients))
    # A UDP socket on an outgoing-range port is a client, unless a shell, a relay tool or a program run from a
    # temporary folder, memory or a deleted file holds it: then it is a backdoor's port like any other.
    for inode, socket in clients.items():
        if inode in owners and _suspicious(list(owners[inode].values()))[0]:
            sockets[inode] = socket
    grouped: dict[str, dict] = {}
    for inode, (protocol, address, port) in sockets.items():
        space = where.get(inode)
        kind = ('container' if space['container'] else 'namespace') if space else None
        key = f'{kind}/{protocol}:{port}' if kind else f'{protocol}:{port}'
        item = grouped.setdefault(key, dict(protocol=protocol, port=port, addresses=set(), programs={}, unknown=0,
                                            where=set()))
        if space:
            item['where'].add(space['container'] or space['id'])
        item['addresses'].add(address)
        if inode in owners:
            item['programs'].update(owners[inode])
        else:
            item['unknown'] += 1
    listeners, ownerless, partly = {}, [], []
    for key, item in grouped.items():
        if item['unknown']:
            (partly if item['programs'] else ownerless).append(key)
        listeners[key] = dict(
            protocol=item['protocol'], port=item['port'], scope=_scope(item['addresses']),
            addresses=sorted(_shown(a, item['port']) for a in item['addresses'])[:MAX_ADDRESSES],
            addresses_complete=len(item['addresses']) <= MAX_ADDRESSES,
            programs=[item['programs'][p] for p in sorted(item['programs'])][:MAX_PROGRAMS],
            owners_known=not item['unknown'])
        if item['where']:
            listeners[key]['where'] = sorted(item['where'])[:MAX_ADDRESSES]
    if not owner_gaps:
        # Readable processes hold none of these sockets: another network namespace's process, or the kernel.
        # A port with any such socket gets no owner-change check, so it is listed even when partly owned.
        if ownerless:
            owner_gaps.append(f"no visible program owns {', '.join(sorted(ownerless)[:8])}")
        if partly:
            owner_gaps.append(f"some sockets have no visible owner on {', '.join(sorted(partly)[:8])}; "
                              "a change of owner is not checked there")
    return dict(listeners=listeners, gaps=gaps + owner_gaps, all_namespaces=bool(all_namespaces))


def _write(path, value):
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.listeners-', dir=path.parent)
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


def _read(path):
    path = Path(path).expanduser()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise ListenerError(f'no listener baseline at {path}; run megalodon listeners baseline') from None
    except OSError as exc:
        raise ListenerError(f'listener baseline {path} cannot be opened: {exc.strerror}') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ListenerError(f'listener baseline {path} must be a mode-600 file owned by you')
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ListenerError('listener baseline is too large')
    try:
        value = json.loads(raw)
    except ValueError:
        raise ListenerError('listener baseline is not valid JSON') from None
    if type(value) is not dict or value.get('schema') != SCHEMA or type(value.get('listeners')) is not dict:
        raise ListenerError('listener baseline has an unsupported format')
    return value


def baseline(manifest=DEFAULT_MANIFEST, *, replace=False, **options):
    path = Path(manifest).expanduser()
    if path.exists() and not replace:
        raise ListenerError(f'{path} exists; use accept to record the reviewed state')
    state = snapshot(**options)
    _write(path, dict(schema=SCHEMA, recorded_at=_now(), user=os.geteuid(), **state))
    return dict(schema=REPORT_SCHEMA, action='baseline', manifest=str(path), listeners=len(state['listeners']),
                gaps=state['gaps'])


_WHERE = dict(deleted='from a deleted file', in_memory='from memory', temporary='from a temporary folder')


def _suspicious(programs):
    """(strong reasons, notes): why these owners look like a bind shell or a dropped tool.

    Shells, relay tools and programs running from temporary folders, memory or
    deleted files are strong signs. A script interpreter is only noted: dev
    servers written in Python or Node listen too."""
    strong, notes = [], []
    for program in programs:
        kind = program.get('kind')
        if kind == 'shell':
            strong.append(f"{program['path']} is a shell")
        elif kind == 'network_tool':
            strong.append(f"{program['path']} is a network relay tool")
        elif kind == 'interpreter':
            notes.append(f"{program['path']} is a script interpreter")
        for flag in program.get('flags', ()):
            strong.append(f"{program['path']} runs {_WHERE[flag]}")
    return strong, notes


def _finding(rule, key, entry, severity, detail):
    techniques = [TECHNIQUES[rule]]
    if any(p.get('kind') in ('shell', 'network_tool') for p in entry['programs']):
        techniques.append(SHELL_TECHNIQUE)
    found = dict(rule_id=rule, severity=severity, listener=key, protocol=entry['protocol'], port=entry['port'],
                 scope=entry['scope'], addresses=entry['addresses'], programs=entry['programs'],
                 techniques=techniques, detail=detail)
    if entry.get('where'):
        found['where'] = entry['where']
    return found


def _address(shown):
    host = shown.rsplit(':', 1)[0]
    return ipaddress.ip_address(host[1:-1] if host.startswith('[') else host)


def _newly_reachable(before, after):
    """Bind addresses in `after` that reach networks `before` did not: neither loopback nor
    already covered by a wildcard of the same address family."""
    old = {_address(a) for a in before}
    wildcard = {a.version for a in old if a.is_unspecified}
    added = []
    for shown in after:
        address = _address(shown)
        if address in old or _loopback(address) or (address.version in wildcard and not address.is_unspecified):
            continue
        added.append(shown)
    return added


def newly_watched(old, new):
    """Listeners in other namespaces that a baseline taken before they were read cannot be compared with."""
    if old.get('all_namespaces') is True or not new.get('all_namespaces'):
        return []
    return [dict(listener=key, where=entry.get('where', []), programs=[p['path'] for p in entry['programs']])
            for key, entry in sorted(new['listeners'].items()) if _kind(key)]


def compare(old, new):
    findings, closed = [], []
    before_all, after_all = old['listeners'], new['listeners']
    if not new.get('all_namespaces') or old.get('all_namespaces') is not True:
        # Other namespaces are compared only when both sides read them: unread now is a gap, not a closed port,
        # and a baseline that never read them has nothing to compare with.
        before_all = {k: v for k, v in before_all.items() if not _kind(k)}
        after_all = {k: v for k, v in after_all.items() if not _kind(k)}
    for key in sorted(set(before_all) | set(after_all), key=lambda k: (k.split(':')[0], int(k.split(':')[1]))):
        before, after = before_all.get(key), after_all.get(key)
        if after is None:
            closed.append(dict(listener=key, programs=[p['path'] for p in before.get('programs', [])]))
            continue
        strong, notes = _suspicious(after['programs'])
        reasons = strong + notes
        if before is None:
            severity = 'HIGH' if strong else 'LOW' if after['scope'] == 'loopback' else 'MEDIUM'
            findings.append(_finding('NEW_LISTENER', key, after, severity, dict(reasons=reasons)))
            continue
        old_paths = {p['path'] for p in before.get('programs', [])}
        new_paths = {p['path'] for p in after['programs']}
        if before.get('owners_known') and after.get('owners_known') and old_paths != new_paths:
            findings.append(_finding('LISTENER_PROGRAM_CHANGED', key, after, 'HIGH' if strong else 'MEDIUM',
                                     dict(previous_programs=sorted(old_paths), reasons=reasons)))
        # A truncated earlier list is not a complete record of earlier reach: an address
        # that only moved into the retained part is not proven new.
        complete = before.get('addresses_complete', len(before['addresses']) < _LEGACY_MAX_ADDRESSES)
        added = _newly_reachable(before['addresses'], after['addresses']) if complete else []
        if SCOPES.index(after['scope']) > SCOPES.index(before['scope']) or added:
            findings.append(_finding('LISTENER_EXPOSED', key, after, 'HIGH' if strong else 'MEDIUM',
                                     dict(previous_scope=before['scope'], previous_addresses=before['addresses'],
                                          added_addresses=added, reasons=reasons)))
    findings.sort(key=lambda item: (-RANK[item['severity']], item['protocol'], item['port'], item['rule_id']))
    return findings, closed


def check(manifest=DEFAULT_MANIFEST, **options):
    old = _read(manifest)
    new = snapshot(**options)
    findings, closed = compare(old, new)
    counts = {level: sum(1 for f in findings if f['severity'] == level) for level in RANK}
    report = dict(schema=REPORT_SCHEMA, action='check', manifest=str(Path(manifest).expanduser()),
                  baseline_recorded_at=old.get('recorded_at'), checked_at=_now(), findings=findings,
                  closed=closed, severity_counts=counts, gaps=new['gaps'],
                  note='Review each listener; accept records the reviewed state. Nothing was stopped or changed.')
    watched = newly_watched(old, new)
    if watched:
        report['newly_watched'] = watched
        report['note'] += (' Listeners in other network namespaces (containers) are listed under newly_watched: the '
                           'baseline was taken before they were read. Review them, then run accept.')
    return report


def accept(manifest=DEFAULT_MANIFEST, **options):
    _read(manifest)  # Only an existing, private baseline can be replaced.
    return dict(baseline(manifest, replace=True, **options), action='accept')


def closed_listener(closed, space=None, container=None):
    """(key, address shown) for a TCP socket the kernel announced closing with no remote end, on an address other
    machines reach: a listener, most likely. None for anything else.

    The kernel gives the closed state for every socket, so a listener is told by having had no peer; a socket that was
    only bound to a port is too, and is rare."""
    if closed.get('protocol') != 'tcp' or not closed.get('local_port'):
        return None
    if not closed['address'].is_unspecified or _loopback(closed['local']):      # a peer, or loopback only
        return None
    kind = None if space is None else ('container' if container else 'namespace')
    port = closed['local_port']
    return (f'{kind}/tcp:{port}' if kind else f'tcp:{port}'), _shown(closed['local'], port)


class Watcher:
    """``listeners watch``: compare with the baseline every `interval` seconds and report each change once while it
    lasts, and, as root, hear listeners that opened and closed between two checks."""

    def __init__(self, manifest=DEFAULT_MANIFEST, emit=print, *, root='/', interval=WATCH_INTERVAL,
                 clock=time.monotonic, closings='auto', warn=None, all_namespaces=None):
        self.manifest, self.emit, self.root, self.interval, self.clock = manifest, emit, root, interval, clock
        self.all_namespaces = all_namespaces
        self.baseline, self.loaded = _read(manifest), self._stamp()
        if closings == 'auto':
            closings = closed_connections.Closings(root) if root == '/' else None
        self.closings = closings
        self.warn = warn or (lambda text: print(f'megalodon: {text}', file=sys.stderr, flush=True))
        self.reported, self.seen, self.spaces = set(), OrderedDict(), {}
        self.last_closed, self.recent, self.warned, self.missed, self.capped_at = {}, deque(), set(), 0, None
        self.stats = dict(polls=0, findings=0, closed=0, brief=0, capped=0)
        self._tell()

    def _stamp(self):
        try:
            info = os.stat(Path(self.manifest).expanduser())
            return (info.st_mtime_ns, info.st_size, info.st_ino)
        except OSError:
            return None

    def _tell(self):
        if self.closings is None:
            return
        for gap in sorted(self.closings.gaps - self.warned):
            self.warned.add(gap)
            self.warn(gap)
        if self.closings.missed > self.missed:
            self.warn(f'{self.closings.missed - self.missed} bursts of closed sockets came faster than they could be '
                      'read: some brief listeners were missed')
            self.missed = self.closings.missed

    def _send(self, found):
        self.stats['findings'] += 1
        found = dict(found, detected_at=_now())
        self.emit(found)
        return found

    def _known(self, key):
        """Whether `key` is a listener the baseline records, or one a check of this watch has already seen."""
        if key in self.seen:
            return True
        if _kind(key) and self.baseline.get('all_namespaces') is not True:
            return True              # the baseline never read other namespaces: nothing to compare with
        return key in self.baseline.get('listeners', {})

    def hear(self):
        """Report the listeners heard closing since the last call that no check saw and the baseline does not know."""
        if self.closings is None:
            return []
        out, now = [], self.clock()
        for space, closed in self.closings.drain():
            self.stats['closed'] += 1
            found = closed_listener(closed, space, self.spaces.get(space))
            if found is None:
                continue
            key, shown = found
            if self._known(key) or now - self.last_closed.get(key, -1e18) < CLOSED_COOLDOWN_SECONDS:
                continue
            while self.recent and now - self.recent[0] >= 3600:
                self.recent.popleft()
            if len(self.recent) >= MAX_CLOSED_PER_HOUR:
                self.stats['capped'] += 1
                if self.capped_at is None or now - self.capped_at >= 3600:
                    self.capped_at = now
                    self.warn(f'more than {MAX_CLOSED_PER_HOUR} brief listeners in an hour: the rest are counted, '
                              'not reported, until the hour has passed')
                continue
            self.recent.append(now)
            self.last_closed[key] = now
            self.stats['brief'] += 1
            where = [self.spaces.get(space) or space] if space is not None else []
            finding = _finding('LISTENER_OPENED_AND_CLOSED', key, dict(
                protocol='tcp', port=closed['local_port'],
                scope='all' if closed['local'].is_unspecified else 'specific', addresses=[shown], programs=[],
                where=where), 'MEDIUM', dict(reasons=[
                    f'a TCP socket on {shown} closed without a peer, between two checks: most likely a listener',
                    'the kernel announces a closing socket without its program']))
            out.append(self._send(finding))
        if len(self.last_closed) > MAX_SEEN:
            self.last_closed.clear()
        self._tell()
        return out

    def poll(self):
        self.stats['polls'] += 1
        stamp = self._stamp()
        if stamp != self.loaded:                  # `accept` changed the baseline while watching
            self.baseline, self.loaded = _read(self.manifest), stamp
        out = self.hear()                        # before the check, while the last one's listeners are known
        new = snapshot(root=self.root, all_namespaces=self.all_namespaces)
        for key in new['listeners']:
            self.seen[key] = True
            self.seen.move_to_end(key)
        while len(self.seen) > MAX_SEEN:
            self.seen.popitem(last=False)
        for gap in new['gaps']:
            if gap not in self.warned:               # a check that cannot see everything says so, once
                if len(self.warned) >= MAX_SEEN:
                    self.warned.clear()
                self.warned.add(gap)
                self.warn(gap)
        findings, _closed = compare(self.baseline, new)
        current = set()
        for found in findings:
            # What makes it this finding: its programs and the addresses it listens on, from which its reach and
            # severity follow. Wider reach of a change already reported is reported again.
            mark = (found['rule_id'], found['listener'], tuple(sorted(p['path'] for p in found['programs'])),
                    tuple(found['addresses']))
            current.add(mark)
            if mark not in self.reported:         # reported once while it lasts, and again if it comes back
                out.append(self._send(found))
        self.reported = current
        if self.closings is not None and new.get('all_namespaces'):
            spaces, _gaps = net_namespaces.namespaces(self.root)
            self.spaces = {space['id']: space.get('container') for space in spaces if not space.get('own')}
            self.closings.subscribe(spaces)
            self._tell()
        return out

    def run(self, stop):
        """Check every `interval` seconds, and report each brief listener as soon as it is heard closing."""
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
