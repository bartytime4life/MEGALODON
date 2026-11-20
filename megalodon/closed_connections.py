"""Connections as they close, announced by the kernel, so one too short to be polled is still seen.

The egress watch reads the socket tables once a second. A connection opened,
used and closed between two reads is never in them: a beacon that checks in
for a few milliseconds, a quick upload, a single fetch of a second stage
(ATT&CK T1071, T1041, T1105). The kernel announces every TCP and UDP socket
it frees to whoever listens on the sock_diag "destroy" groups. Each
announcement gives the socket's addresses and ports and, for TCP, how many
bytes went each way. It does not say which program or account opened the
socket: the kernel leaves both fields empty in these announcements, and the
program may have exited already. So a connection seen only this way is
reported by its destination alone.

Listening takes root (CAP_NET_ADMIN). Announcements are per network
namespace. A container's are read through a socket opened inside its
namespace: a short-lived helper enters the namespace, opens the socket and
hands it back. This process never changes namespace. Nothing on the machine
is changed: these sockets only listen.
"""
from __future__ import annotations

import array
import errno
import ipaddress
import os
import socket
import struct
import subprocess
import sys

NETLINK_SOCK_DIAG = 4
SOL_NETLINK = 270
NETLINK_ADD_MEMBERSHIP = 1
# SKNLGRP_INET_TCP_DESTROY, SKNLGRP_INET_UDP_DESTROY, SKNLGRP_INET6_TCP_DESTROY, SKNLGRP_INET6_UDP_DESTROY
GROUPS = (1, 2, 3, 4)
SOCK_DIAG_BY_FAMILY = 20
INET_DIAG_INFO = 2
INET_DIAG_PROTOCOL = 10
PROTOCOLS = {6: 'tcp', 17: 'udp'}
MESSAGE = 72                        # struct inet_diag_msg
RECEIVE_BUFFER = 4 * 1024 * 1024
MAX_SOCKETS = 512
MAX_PER_DRAIN = 65536
CLONE_NEWNET = 0x40000000

# Runs in a short-lived helper: enter the namespace whose descriptor is argv[1], open a sock_diag socket there, and
# send it back over the socket whose descriptor is argv[2]. Only the helper changes namespace.
HELPER = r'''
import array, ctypes, os, socket, sys
space, back = int(sys.argv[1]), int(sys.argv[2])
if hasattr(os, "setns"):
    os.setns(space, 0x40000000)
else:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.setns(space, 0x40000000) != 0:
        raise OSError(ctypes.get_errno(), "setns")
made = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 4)
channel = socket.socket(fileno=back)
channel.sendmsg([b"s"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [made.fileno()]))])
'''


def _address(family, raw):
    return ipaddress.ip_address(raw[:4] if family == socket.AF_INET else raw[:16])


def parse(data):
    """The closed sockets in one netlink read: [dict(protocol, family, local, local_port, address, port, sent,
    received)]. `sent` and `received` are TCP byte counts, None for UDP: the kernel counts the opening and closing
    of the connection as a byte each, so they can be two more than the data. The owner and inode fields of these
    announcements are always zero, so they are not read."""
    found, offset = [], 0
    while offset + 16 <= len(data):
        length, kind = struct.unpack_from('=IH', data, offset)
        if length < 16 or offset + length > len(data):
            break
        body = data[offset + 16:offset + length]
        offset += (length + 3) & ~3
        if kind != SOCK_DIAG_BY_FAMILY or len(body) < MESSAGE:
            continue
        family = body[0]
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        local_port, port = struct.unpack_from('>HH', body, 4)
        protocol, info, at = None, None, MESSAGE
        while at + 4 <= len(body):
            size, attribute = struct.unpack_from('=HH', body, at)
            if size < 4:
                break
            value = body[at + 4:at + size]
            if attribute == INET_DIAG_PROTOCOL and value:
                protocol = PROTOCOLS.get(value[0])
            elif attribute == INET_DIAG_INFO:
                info = value
            at += (size + 3) & ~3
        if protocol is None:
            continue
        sent = received = None
        if protocol == 'tcp' and info is not None and len(info) >= 136:
            sent, received = struct.unpack_from('=QQ', info, 120)     # tcpi_bytes_acked, tcpi_bytes_received
        found.append(dict(protocol=protocol, family=family, local=_address(family, body[8:24]), local_port=local_port,
                          address=_address(family, body[24:40]), port=port, sent=sent, received=received))
    return found


def _listen(made):
    made.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RECEIVE_BUFFER)
    try:
        made.setsockopt(socket.SOL_SOCKET, 33, RECEIVE_BUFFER)       # SO_RCVBUFFORCE: past the limit, as root
    except OSError:
        pass
    made.bind((0, 0))
    for group in GROUPS:
        made.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, group)
    made.setblocking(False)
    return made


def _opened_inside(root, space):
    """A sock_diag socket opened inside the namespace `space` (from net_namespaces), or raise OSError."""
    pid = space['pid']
    target = os.open(os.path.join(root, 'proc', str(pid), 'ns/net'), os.O_RDONLY | os.O_CLOEXEC)
    try:
        # The process may have exited and its number been reused: the namespace is checked through the descriptor.
        if os.readlink(f'/proc/self/fd/{target}') != space['id']:
            raise OSError(errno.ESRCH, f"process {pid} has left namespace {space['id']}")
        mine, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        with mine:
            try:
                done = subprocess.run([sys.executable, '-I', '-S', '-c', HELPER, str(target), str(theirs.fileno())],
                                      pass_fds=(target, theirs.fileno()), stdin=subprocess.DEVNULL,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10, check=False)
            finally:
                theirs.close()
            if done.returncode != 0:
                lines = done.stderr.decode('utf-8', 'replace').strip().splitlines()
                raise OSError(errno.EPERM, (lines or ['the helper failed'])[-1][:200])
            mine.setblocking(False)
            try:
                _, ancillary, _, _ = mine.recvmsg(1, socket.CMSG_SPACE(4))
            except BlockingIOError:
                raise OSError(errno.EIO, 'the helper sent no socket') from None
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS and len(data) >= 4:
                    return socket.socket(fileno=array.array('i', data[:4])[0])
            raise OSError(errno.EIO, 'the helper sent no socket')
    finally:
        os.close(target)


class Closings:
    """Listen for closed sockets in this network namespace and, with `subscribe`, in others."""

    def __init__(self, root='/'):
        self.root, self.sockets, self.gaps, self.missed = root, {}, set(), 0
        try:
            self.sockets[None] = _listen(socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_SOCK_DIAG))
        except OSError as exc:
            self.gaps.add('closed connections cannot be heard here' + (
                ': run as root to see connections too short for a scan' if exc.errno == errno.EPERM
                else f': {exc.strerror or exc}'))
        self.failed = set()

    def subscribe(self, spaces):
        """Listen in each namespace in `spaces` (from net_namespaces.namespaces); stop for those that are gone."""
        wanted = {space['id']: space for space in spaces if not space.get('own') and space.get('id')}
        for name in [n for n in self.sockets if n is not None and n not in wanted]:
            self.sockets.pop(name).close()
        self.failed &= set(wanted)
        for name, space in wanted.items():
            if name in self.sockets or name in self.failed or None not in self.sockets:
                continue
            if len(self.sockets) >= MAX_SOCKETS:
                self.gaps.add(f'more than {MAX_SOCKETS} network namespaces: closed connections in the rest are '
                              'not heard')
                break
            try:
                self.sockets[name] = _listen(_opened_inside(self.root, space))
            except (OSError, subprocess.SubprocessError) as exc:
                self.failed.add(name)
                self.gaps.add(f"closed connections in {name} cannot be heard: {getattr(exc, 'strerror', None) or exc}")

    def filenos(self):
        return [made.fileno() for made in self.sockets.values()]

    def drain(self):
        """Every closed socket announced since the last drain: [(namespace id or None, closed)]."""
        found = []
        for name, made in list(self.sockets.items()):
            while len(found) < MAX_PER_DRAIN:
                try:
                    data = made.recv(1 << 20)
                except BlockingIOError:
                    break
                except OSError as exc:
                    if exc.errno == errno.ENOBUFS:      # more closed at once than the buffer held: some were lost
                        self.missed += 1
                        continue
                    raise
                found.extend((name, closed) for closed in parse(data))
        return found

    def close(self):
        for made in self.sockets.values():
            made.close()
        self.sockets.clear()
