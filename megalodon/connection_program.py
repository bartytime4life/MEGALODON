"""Bounded same-user Linux TCP holder observations for local flow recording."""
from collections import deque
import os
import re
import socket
import struct
import sys
import time

from .evidence_storage import epoch, utc

NAME = re.compile(r'[A-Za-z0-9_+.-]{1,80}')
HEADER = struct.Struct('=IHHII')
BUDGET = 0.15
DIRECTORY = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)


def _remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError
    return left


def _sockets(deadline):
    """Established IPv4 TCP sockets in this network namespace, with kernel lifetime cookies."""
    body = struct.pack('=BBBBI', socket.AF_INET, socket.IPPROTO_TCP, 0, 0, 1 << 1) + bytes(48)
    found = {}
    with socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, 4) as diag:
        diag.settimeout(_remaining(deadline))
        diag.sendto(HEADER.pack(HEADER.size + len(body), 20, 0x301, 1, 0) + body, (0, 0))
        for _ in range(32):
            diag.settimeout(_remaining(deadline))
            data, _, flags, sender = diag.recvmsg(32768)
            if sender != (0, 0) or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                raise ValueError('Incomplete socket table')
            offset = 0
            while offset < len(data):
                size, kind, hdr_flags, seq, _ = HEADER.unpack_from(data, offset)
                if size < 16 or offset + size > len(data) or seq != 1 or hdr_flags & 0x10:
                    raise ValueError('Interrupted socket table')
                msg = data[offset+16:offset+size]
                offset += (size + 3) & ~3
                if kind == 3:  # NLMSG_DONE, possibly followed by a signed error code
                    if msg and (len(msg) < 4 or struct.unpack_from('=i', msg)[0]):
                        raise ValueError('Incomplete socket dump')
                    return found
                if kind != 20 or len(msg) < 72 or msg[:2] != bytes((socket.AF_INET, 1)):
                    raise ValueError('Unexpected socket reply')
                uid, inode = struct.unpack_from('=II', msg, 64)
                cookie = msg[44:52]
                if uid != os.getuid() or not inode or cookie in (bytes(8), b'\xff'*8):
                    continue
                src, dst = struct.unpack_from('!HH', msg, 4)
                key = (socket.inet_ntoa(msg[8:12]), src, socket.inet_ntoa(msg[24:28]), dst)
                found[key] = (inode, cookie) if key not in found else None
                if len(found) > 512:
                    raise ValueError('Socket table limit')
    raise ValueError('Socket dump limit')


def _programs(wanted, deadline):
    """Read executable basenames around FD inspection, pinned to the same proc directory."""
    found = {}
    links = 0
    with os.scandir('/proc') as processes:
        for index, process in enumerate(processes):
            _remaining(deadline)
            if index >= 8192 or links >= 16384:
                break
            if not process.name.isdecimal():
                continue
            try:
                proc = os.open(process.path, DIRECTORY)
            except OSError:
                continue
            try:
                if os.fstat(proc).st_uid != os.getuid():
                    continue
                exe = os.stat('exe', dir_fd=proc)
                name = os.path.basename(os.readlink('exe', dir_fd=proc))
                if not NAME.fullmatch(name) or name in ('.', '..'):
                    continue
                held = set()
                fds = os.open('fd', DIRECTORY, dir_fd=proc)
                try:
                    with os.scandir(fds) as entries:
                        for fd in entries:
                            if links >= 16384:
                                break
                            links += 1
                            if links % 64 == 0:
                                _remaining(deadline)
                            try:
                                target = os.readlink(fd.name, dir_fd=fds)
                            except OSError:
                                continue
                            if target in wanted:
                                held.add(wanted[target])
                finally:
                    os.close(fds)
                if not os.path.samestat(exe, os.stat('exe', dir_fd=proc)):
                    continue
                for inode in held:
                    names = found.setdefault(inode, set())
                    if len(names) < 2:
                        names.add(name)
            except OSError:
                continue
            finally:
                os.close(proc)
    return found


def observe():
    if sys.platform != 'linux' or os.getuid() == 0:
        return {}
    deadline = time.monotonic() + BUDGET
    before = _sockets(deadline)
    wanted = {f'socket:[{value[0]}]': value[0] for value in before.values() if value}
    if not wanted:
        return {}
    programs = _programs(wanted, deadline)
    after = _sockets(deadline)
    # A descriptor was seen between two kernel observations of the same living socket.
    return {key: (value[1], tuple(sorted(programs.get(value[0], ()))))
            for key, value in before.items() if value and after.get(key) == value}


class ConnectionPrograms:
    """Short in-memory window. No lookup at alert viewing time or on old imports."""
    def __init__(self):
        self.samples = deque(maxlen=60)
        self.next_sample = 0
        self.clock_offset = None

    def clear(self):
        self.samples.clear()
        self.next_sample = 0
        self.clock_offset = None

    def sample(self):
        now = time.monotonic()
        if now < self.next_sample:
            return
        self.next_sample = now + 2
        start = time.time()
        offset = start - now
        if self.clock_offset is not None and abs(offset - self.clock_offset) > 0.025:
            self.samples.clear()
        self.clock_offset = offset
        try:
            observed = observe()
        except (OSError, ValueError, struct.error):
            return
        end = time.time()
        if end < start or abs(end - time.monotonic() - offset) > 0.025:
            self.clear()
        elif observed:
            self.samples.append((start, end, observed))

    def match(self, flow):
        if flow.get('protocol') != 'TCP':
            return None
        key = (flow['src_ip'], flow['src_port'], flow['dst_ip'], flow['dst_port'])
        first, last = epoch(flow['first_seen']), epoch(flow['last_seen'])
        now = time.time()
        if last > now or (self.clock_offset is not None and abs(now-time.monotonic()-self.clock_offset)>0.025):
            return None
        identities, names, witness = set(), set(), None
        for begin, end, sockets in self.samples:
            if not (now-120 <= begin <= end <= now and first <= begin and end <= last) or key not in sockets:
                continue
            cookie, holders = sockets[key]
            identities.add(cookie)
            names.update(holders)
            if holders:
                witness = (begin, end)
        if len(identities) == len(names) == 1 and witness:
            return dict(name=names.pop(), begin=utc(witness[0]), end=utc(witness[1]))
        return None


def cadence_detail(evidence, record):
    """Read only the linked flow rows on this Findings page. Never query a live process."""
    import ipaddress
    import json
    import sqlite3

    facts = record['facts']['recorded_evidence']
    refs = record['evidence_refs']
    sensor = record['finding']['source']
    result = dict(destination=None, programs={}, checked=len(refs))
    if not isinstance(facts, dict) or sensor not in ('suricata-eve', 'zeek-conn', 'zeek-sample'):
        return result
    targets = set()
    counts = {}
    try:
        with evidence.lock:
            entries = {e['id']: e for e in evidence._catalog['entries'] if e['category']=='flows'
                       and e['kind']=='generic' and e['state'] in ('open', 'closed')}
            for ref in dict.fromkeys(refs):
                if not re.fullmatch(r'[a-f0-9]{32}:[1-9][0-9]{0,17}', ref):
                    return result
                segment, seq = ref.split(':')
                if segment not in record['source_segments'] or segment not in entries:
                    return result
                with evidence._db(entries[segment]) as db:
                    row = db.execute('SELECT data FROM records WHERE id=? AND source=? AND length(CAST(data AS BLOB))<=8192',
                                     (int(seq), sensor)).fetchone()
                if not row:
                    return result
                flow = json.loads(row[0])
                if (flow['src_ip'] != record['finding']['subject'] or flow['protocol'] != facts.get('protocol')
                        or type(flow['dst_port']) is not int or flow['dst_port'] != facts.get('port')):
                    return result
                targets.add(str(ipaddress.ip_address(flow['dst_ip'])))
                w = flow.get('local_tcp_holder')
                if (flow['protocol']=='TCP' and isinstance(w, dict) and isinstance(w.get('name'), str)
                        and NAME.fullmatch(w['name']) and w['name'] not in ('.', '..')
                        and epoch(flow['first_seen']) <= epoch(w['begin']) <= epoch(w['end']) <= epoch(flow['last_seen'])):
                    counts[w['name']] = counts.get(w['name'], 0) + 1
        if len(targets)==1:
            result.update(destination=targets.pop(), programs=counts)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError, sqlite3.Error):
        pass
    return result
