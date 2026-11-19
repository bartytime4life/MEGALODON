"""Names for outgoing connections: which name each address was looked up as, and which name a program asked for.

The egress watch sees addresses. An address alone says little: one cloud
address serves thousands of names, and an implant's server looks like any
other. This listener reads, passively, the two places a machine says the name
it means:

* DNS answers (UDP port 53), which map each address to the name that was
  looked up, for as long as the answer's time to live;
* the server name in each TLS ClientHello a program sends, which names the
  service it asked that address for.

A classic BPF filter makes the kernel pass only those packets. Nothing is
sent, blocked or changed, and packet contents other than these names are
neither kept nor shown. Raw packet capture needs root (CAP_NET_RAW).
"""
from __future__ import annotations

from collections import OrderedDict
import ipaddress
import socket
import struct
import threading
import time

MAX_ENTRIES = 65536
MAX_NAMES = 4
MIN_TTL, MAX_TTL = 60, 86400
SNI_SECONDS = 3600
MAX_NAME = 253
ETH_P_ALL = 0x0003
SO_ATTACH_FILTER = 26

# Classic BPF over the network-layer packet (AF_PACKET, SOCK_DGRAM): accept UDP from port 53, and TCP whose payload
# starts with a TLS handshake record (0x16). Everything else stays in the kernel. IPv6 extension headers are not
# followed. Jumps are relative to the next instruction.


def _program():
    """The classic BPF program, one (code, jt, jf, k) per instruction."""
    accept, reject = 0x40000, 0
    code = [
        (0x30, 0, 0, 0),            # 0  ldb [0]
        (0x74, 0, 0, 4),            # 1  rsh 4
        (0x15, 0, 14, 4),           # 2  jeq 4 ? 3 : 17
        (0x30, 0, 0, 9),            # 3  ldb [9]
        (0x15, 0, 3, 17),           # 4  jeq 17 ? 5 : 8
        (0xb1, 0, 0, 0),            # 5  ldxb 4*([0]&0xf)
        (0x48, 0, 0, 0),            # 6  ldh [x+0]
        (0x15, 23, 24, 53),         # 7  jeq 53 ? accept(31) : reject(32)
        (0x15, 0, 23, 6),           # 8  jeq 6 ? 9 : reject(32)
        (0xb1, 0, 0, 0),            # 9  ldxb 4*([0]&0xf)
        (0x50, 0, 0, 12),           # 10 ldb [x+12]
        (0x74, 0, 0, 2),            # 11 rsh 2
        (0x54, 0, 0, 0x3c),         # 12 and 0x3c
        (0x0c, 0, 0, 0),            # 13 add x
        (0x07, 0, 0, 0),            # 14 tax
        (0x50, 0, 0, 0),            # 15 ldb [x+0]
        (0x15, 14, 15, 0x16),       # 16 jeq 0x16 ? accept(31) : reject(32)
        (0x15, 0, 14, 6),           # 17 (A = version) jeq 6 ? 18 : reject(32)
        (0x30, 0, 0, 6),            # 18 ldb [6]
        (0x15, 0, 2, 17),           # 19 jeq 17 ? 20 : 22
        (0x28, 0, 0, 40),           # 20 ldh [40]
        (0x15, 9, 10, 53),          # 21 jeq 53 ? accept(31) : reject(32)
        (0x15, 0, 9, 6),            # 22 jeq 6 ? 23 : reject(32)
        (0x30, 0, 0, 52),           # 23 ldb [52]
        (0x74, 0, 0, 2),            # 24 rsh 2
        (0x54, 0, 0, 0x3c),         # 25 and 0x3c
        (0x07, 0, 0, 0),            # 26 tax
        (0x50, 0, 0, 40),           # 27 ldb [x+40]
        (0x15, 2, 3, 0x16),         # 28 jeq 0x16 ? accept(31) : reject(32)
        (0x06, 0, 0, reject),       # 29 (unreached)
        (0x06, 0, 0, reject),       # 30 (unreached)
        (0x06, 0, 0, accept),       # 31 accept
        (0x06, 0, 0, reject),       # 32 reject
    ]
    return code


# ------------------------------------------------------------------ parsing

def _name(data, offset, depth=0):
    """(name, offset after it) for a DNS name at offset, following compression pointers."""
    labels, jumped, end = [], False, offset
    for _ in range(128):
        if offset >= len(data):
            return None, end
        length = data[offset]
        if length == 0:
            if not jumped:
                end = offset + 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data) or depth > 16:
                return None, end
            pointer = (length & 0x3F) << 8 | data[offset + 1]
            if not jumped:
                end = offset + 2
            jumped, depth, offset = True, depth + 1, pointer
            continue
        if length > 63 or offset + 1 + length > len(data):
            return None, end
        labels.append(data[offset + 1:offset + 1 + length])
        offset += 1 + length
    else:
        return None, end
    try:
        name = b'.'.join(labels).decode('ascii').lower()
    except UnicodeDecodeError:
        return None, end
    return (name if 0 < len(name) <= MAX_NAME else None), end


def parse_dns(data):
    """[(address, name, ttl)] from a DNS response: each A and AAAA answer, under the name that was asked for."""
    if len(data) < 12:
        return []
    flags, questions, answers = struct.unpack_from('!HHH', data, 2)
    if not flags & 0x8000 or flags & 0x000F or questions != 1:
        return []
    asked, offset = _name(data, 12)
    offset += 4
    if asked is None or offset > len(data):
        return []
    out = []
    for _ in range(min(answers, 64)):
        owner, offset = _name(data, offset)
        if offset + 10 > len(data):
            break
        kind, _class, ttl, length = struct.unpack_from('!HHIH', data, offset)
        offset += 10
        if offset + length > len(data):
            break                                         # the record's data was cut short
        value = data[offset:offset + length]
        offset += length
        if kind == 1 and length == 4:
            address = str(ipaddress.IPv4Address(value))
        elif kind == 28 and length == 16:
            address = str(ipaddress.IPv6Address(value))
        else:
            continue
        names = [asked] + ([owner] if owner and owner != asked else [])
        out += [(address, name, max(MIN_TTL, min(MAX_TTL, ttl))) for name in names]
    return out


def parse_client_hello(data):
    """The server name a TLS ClientHello asks for, or None."""
    if len(data) < 43 or data[0] != 0x16 or data[5] != 0x01:
        return None
    offset = 9 + 2 + 32                                   # record and handshake headers, version, random
    try:
        offset += 1 + data[offset]                        # session id
        offset += 2 + struct.unpack_from('!H', data, offset)[0]   # cipher suites
        offset += 1 + data[offset]                        # compression methods
        end = offset + 2 + struct.unpack_from('!H', data, offset)[0]
        offset += 2
        while offset + 4 <= min(end, len(data)):
            kind, length = struct.unpack_from('!HH', data, offset)
            offset += 4
            if kind == 0:                                 # server_name: list length, type, name length, name
                if data[offset + 2] != 0:
                    return None
                size = struct.unpack_from('!H', data, offset + 3)[0]
                name = data[offset + 5:offset + 5 + size].decode('ascii').lower()
                return name if 0 < len(name) <= MAX_NAME and len(name) == size else None
            offset += length
    except (IndexError, struct.error, UnicodeDecodeError):
        return None
    return None


def parse_packet(packet):
    """('dns', [(address, name, ttl)]) or ('sni', address, port, source port, name) from a network-layer packet,
    or None."""
    if not packet:
        return None
    version = packet[0] >> 4
    if version == 4 and len(packet) >= 20:
        header = (packet[0] & 0x0F) * 4
        protocol, destination = packet[9], packet[16:20]
    elif version == 6 and len(packet) >= 40:
        header, protocol, destination = 40, packet[6], packet[24:40]
    else:
        return None
    if protocol == 17 and len(packet) >= header + 8 and struct.unpack_from('!H', packet, header)[0] == 53:
        found = parse_dns(packet[header + 8:])
        return ('dns', found) if found else None
    if protocol == 6 and len(packet) >= header + 20:
        source_port, port = struct.unpack_from('!HH', packet, header)
        offset = header + (packet[header + 12] >> 4) * 4
        name = parse_client_hello(packet[offset:])
        if name:
            return 'sni', str(ipaddress.ip_address(bytes(destination))), port, source_port, name
    return None


# ------------------------------------------------------------------ the cache and the listener

class Names:
    """Which names each address had, while the answers hold; thread-safe and bounded."""

    def __init__(self, clock=time.monotonic):
        self.clock, self.lock = clock, threading.Lock()
        self.dns, self.sni = OrderedDict(), OrderedDict()

    def _put(self, table, key, value, until):
        entry = table.pop(key, {})
        entry[value] = until
        if len(entry) > MAX_NAMES:
            entry.pop(min(entry, key=entry.get))
        table[key] = entry
        while len(table) > MAX_ENTRIES:
            table.popitem(last=False)

    def learn(self, event):
        now = self.clock()
        with self.lock:
            if event[0] == 'dns':
                for address, name, ttl in event[1]:
                    self._put(self.dns, address, name, now + ttl)
            elif event[0] == 'sni':
                # One connection's server name, kept for that connection only: another program reaching the same
                # address and port may have asked for a different service.
                self._put(self.sni, (event[1], event[2], event[3]), event[4], now + SNI_SECONDS)

    def lookup(self, address, port=None, local_port=None):
        """Names for a connection: the server name it asked for first, then what the address was looked up as."""
        now, out = self.clock(), []
        with self.lock:
            for table, key in ((self.sni, (address, port, local_port)), (self.dns, address)):
                for name, until in sorted(table.get(key, {}).items(), key=lambda item: -item[1]):
                    if until >= now and name not in out:
                        out.append(name)
        return out[:MAX_NAMES]


class Listener:
    """Read DNS answers and TLS server names from every interface into `names` until stopped."""

    def __init__(self, names, *, open_socket=None):
        self.names, self.open_socket = names, open_socket or self._open
        self.stats = dict(packets=0, dns=0, sni=0, malformed=0)
        self.error = None

    @staticmethod
    def _open():
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL))
        program = b''.join(struct.pack('HBBI', *op) for op in _program())
        import ctypes
        buffer = ctypes.create_string_buffer(program)
        fprog = struct.pack('HP', len(program) // 8, ctypes.addressof(buffer))
        sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
        sock.settimeout(0.5)
        return sock

    def start(self):
        """Open the capture; False (with `error` set) when it cannot be opened."""
        try:
            self.sock = self.open_socket()
        except OSError as exc:
            self.error = ('names need root: raw packet capture (CAP_NET_RAW) was refused'
                          if isinstance(exc, PermissionError) else f'names are unavailable: {exc}')
            return False
        return True

    def handle(self, packet):
        self.stats['packets'] += 1
        try:
            event = parse_packet(packet)
        except Exception:                                 # noqa: BLE001 - one odd packet must not stop the listener
            self.stats['malformed'] += 1
            return
        if event:
            self.stats[event[0]] += 1
            self.names.learn(event)

    def run(self, stop):
        while not stop.is_set():
            try:
                packet = self.sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                if stop.is_set():
                    break
                continue
            self.handle(packet)
        self.sock.close()


def start(names=None):
    """A Names cache filled by a background listener; (names, listener, error)."""
    names = names or Names()
    listener = Listener(names)
    if not listener.start():
        return names, None, listener.error
    stop = threading.Event()
    thread = threading.Thread(target=listener.run, args=(stop,), daemon=True, name='megalodon-names')
    thread.start()
    listener.stop = stop
    return names, listener, None
