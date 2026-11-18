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

Only metadata is kept: protocol, port, local addresses, and each owner's
executable path and process name. Command lines, process IDs and traffic are
never read or stored. Owners of other accounts' sockets need root to see; the
report lists that as a coverage gap. Nothing is stopped or changed: ``accept``
records the reviewed state as the new baseline.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import stat
import tempfile

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
}
SHELL_TECHNIQUE = 'T1059'
DEFAULT_EPHEMERAL = (32768, 60999)


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


def _listening(root):
    """{inode: (protocol, address, port)} for listening TCP sockets and bound UDP service ports, plus gaps."""
    low, high = _ephemeral(root)
    found, gaps = {}, []
    for protocol, family, name, length in TABLES:
        path = Path(root, 'proc/net', name)
        try:
            lines, complete = _read_table(path)
        except FileNotFoundError:
            if family != 'ipv6' or os.path.lexists(Path(root, 'proc/net/if_inet6')):
                gaps.append(f'/proc/net/{name} is missing')
            continue
        except (OSError, ValueError):
            gaps.append(f'/proc/net/{name} could not be read')
            continue
        if not complete:
            gaps.append(f'/proc/net/{name} was too large to read whole')
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
            elif not (remote[1] == 0 and remote[0].is_unspecified) or low <= local[1] <= high:
                # An unconnected UDP socket on an outgoing-range port is a client, not a service.
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


def snapshot(*, root='/'):
    sockets, gaps = _listening(root)
    owners, owner_gaps = _owners(root, set(sockets))
    grouped: dict[str, dict] = {}
    for inode, (protocol, address, port) in sockets.items():
        item = grouped.setdefault(f'{protocol}:{port}', dict(protocol=protocol, port=port, addresses=set(),
                                                             programs={}, unknown=0))
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
    if not owner_gaps:
        # Readable processes hold none of these sockets: another network namespace's process, or the kernel.
        # A port with any such socket gets no owner-change check, so it is listed even when partly owned.
        if ownerless:
            owner_gaps.append(f"no visible program owns {', '.join(sorted(ownerless)[:8])}")
        if partly:
            owner_gaps.append(f"some sockets have no visible owner on {', '.join(sorted(partly)[:8])}; "
                              "a change of owner is not checked there")
    return dict(listeners=listeners, gaps=gaps + owner_gaps)


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
    return dict(rule_id=rule, severity=severity, listener=key, protocol=entry['protocol'], port=entry['port'],
                scope=entry['scope'], addresses=entry['addresses'], programs=entry['programs'],
                techniques=techniques, detail=detail)


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


def compare(old, new):
    findings, closed = [], []
    before_all, after_all = old['listeners'], new['listeners']
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
    return dict(schema=REPORT_SCHEMA, action='check', manifest=str(Path(manifest).expanduser()),
                baseline_recorded_at=old.get('recorded_at'), checked_at=_now(), findings=findings,
                closed=closed, severity_counts=counts, gaps=new['gaps'],
                note='Review each listener; accept records the reviewed state. Nothing was stopped or changed.')


def accept(manifest=DEFAULT_MANIFEST, **options):
    _read(manifest)  # Only an existing, private baseline can be replaced.
    return dict(baseline(manifest, replace=True, **options), action='accept')
