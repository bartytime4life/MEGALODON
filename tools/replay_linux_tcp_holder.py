"""Bounded native lab: link one established loopback TCP socket to a live child's FD."""

from contextlib import ExitStack
import errno
import json
import multiprocessing
import os
import re
import socket
import struct
import sys
import time
from typing import NamedTuple

LOOPBACK = '127.0.0.1'
TIME_BUDGET = 8
HEADER = struct.Struct('=IHHII')  # linux/netlink.h: nlmsghdr
NETLINK_SOCK_DIAG = 4
SOCK_DIAG_BY_FAMILY = 20
NO_COOKIE = b'\xff' * 8
ESTABLISHED = 1


class KernelSocket(NamedTuple):
    inode: int
    cookie: bytes


def _remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError
    return seconds


def _socket_id(client_port, server_port):
    if not (0 < client_port <= 65535 and 0 < server_port <= 65535 and client_port != server_port):
        raise ValueError('invalid fixture ports')
    addr = socket.inet_aton(LOOPBACK).ljust(16, b'\0')
    return struct.pack('!HH', client_port, server_port) + addr + addr


def _request(key, cookie, sequence):
    # inet_diag_req_v2 and inet_diag_sockid. Only NLM_F_REQUEST, never a dump.
    body = struct.pack('=BBBBI', socket.AF_INET, socket.IPPROTO_TCP, 0, 0, 1 << ESTABLISHED)
    body += key + struct.pack('=I', 0) + cookie
    return HEADER.pack(HEADER.size + len(body), SOCK_DIAG_BY_FAMILY, 1, sequence, 0) + body


def _decode(packet, key, cookie, sequence, uid):
    data, control, flags, peer = packet
    if (peer != (0, 0) or control or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or len(data) < HEADER.size):
        raise ValueError('incomplete kernel reply')
    size, kind, reply_flags, seq, _ = HEADER.unpack_from(data)
    if size != len(data) or seq != sequence or reply_flags & 2:  # NLM_F_MULTI
        raise ValueError('unexpected netlink framing')
    body = data[HEADER.size:]
    if kind == 2:  # NLMSG_ERROR includes the original request header even for a capped ACK.
        if len(body) < 4 + HEADER.size or body[4:4 + HEADER.size] != _request(key, cookie, sequence)[:HEADER.size]:
            raise ValueError('unmatched netlink error')
        error, = struct.unpack_from('=i', body)
        if error in (-errno.ENOENT, -errno.ESTALE):
            return None
        if error >= 0:
            raise ValueError('unexpected netlink acknowledgement')
        raise OSError(-error, 'diagnostic query refused')
    # inet_diag_msg: 4 state bytes, 48-byte sockid, five native u32s.
    if (kind != SOCK_DIAG_BY_FAMILY or len(body) < 72 or body[0] != socket.AF_INET
            or body[4:40] != key):
        raise ValueError('unexpected TCP diagnostic reply')
    if body[1] != ESTABLISHED:
        return None
    observed_cookie = body[44:52]
    owner_uid, inode = struct.unpack_from('=II', body, 64)
    if (owner_uid != uid or not inode or observed_cookie in (NO_COOKIE, bytes(8))
            or (cookie != NO_COOKIE and observed_cookie != cookie)):
        raise ValueError('inconsistent established socket identity')
    return KernelSocket(inode, observed_cookie)


def _links(directory, slots):
    inodes = []
    for slot in slots:
        try:
            target = os.readlink(str(slot), dir_fd=directory)
        except FileNotFoundError:
            target = ''
        match = re.fullmatch(r'socket:\[([1-9][0-9]{0,19})\]', target)
        inodes.append(int(match[1]) if match else None)
    return tuple(inodes)


class Observation(NamedTuple):
    before: tuple
    current: KernelSocket | None
    after: tuple

    def holders(self):
        return tuple('observed_holder' if self.current is not None and old == new == self.current.inode
                     else 'unknown' for old, new in zip(self.before, self.after, strict=True))


def _observe(directory, slots, diag, key, cookie, sequence, deadline):
    before = _links(directory, slots)
    diag.settimeout(_remaining(deadline))
    diag.sendto(_request(key, cookie, sequence), (0, 0))
    current = _decode(diag.recvmsg(4096), key, cookie, sequence, os.getuid())
    after = _links(directory, slots)
    return Observation(before, current, after)


def _expect(control, marker, deadline):
    if not control.poll(_remaining(deadline)) or control.recv_bytes(1) != marker:
        raise OSError('fixture synchronization failed')


def _client(listener, endpoint, client, spare, parent_end, control, deadline):
    try:
        listener.close()
        parent_end.close()
        original = client.fileno()
        client.settimeout(_remaining(deadline))
        client.connect(endpoint)
        control.send_bytes(b'O')
        _expect(control, b'M', deadline)
        os.dup2(original, spare)
        client.close()
        os.dup2(control.fileno(), original)  # Same number now refers to a different local socket.
        control.send_bytes(b'M')
        _expect(control, b'C', deadline)
        os.close(spare)  # Last fixture client TCP reference, while this child is still alive.
        control.send_bytes(b'C')
        _expect(control, b'Q', deadline)
    except (EOFError, OSError, ValueError):
        raise SystemExit(2)


def _probe():
    deadline = time.monotonic() + TIME_BUDGET
    ctx = multiprocessing.get_context('fork')
    with ExitStack() as resources:
        listener = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        listener.bind((LOOPBACK, 0))
        listener.listen(1)
        endpoint = listener.getsockname()
        client = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        client.bind((LOOPBACK, 0))
        local = client.getsockname()
        expected_inode = os.fstat(client.fileno()).st_ino  # Ground truth only, never a lookup input.
        key = _socket_id(local[1], endpoint[1])
        parent, control = ctx.Pipe()
        resources.enter_context(parent)
        resources.enter_context(control)
        reservation = resources.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        slots = (client.fileno(), reservation.fileno())
        child = ctx.Process(target=_client, args=(listener, endpoint, client, slots[1],
                                                  parent, control, deadline))
        child.start()
        try:
            control.close()
            reservation.close()
            client.close()  # Observer retains the accepted side only, never the client's socket.
            _expect(parent, b'O', deadline)
            listener.settimeout(_remaining(deadline))
            accepted, peer = listener.accept()
            resources.enter_context(accepted)
            listener.close()
            if peer != local or accepted.getsockname() != endpoint:
                raise OSError('fixture peer mismatch')
            directory = os.open(f'/proc/{child.pid}/fd', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            resources.callback(os.close, directory)
            diag = resources.enter_context(socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_SOCK_DIAG))
            cookie = NO_COOKIE
            phases = {}
            for sequence, (phase, marker) in enumerate((('open', b'O'), ('moved', b'M'), ('closed', b'C')), 1):
                if phase != 'open':
                    parent.send_bytes(marker)
                    _expect(parent, marker, deadline)
                phases[phase] = _observe(directory, slots, diag, key, cookie, sequence, deadline)
                if phase == 'open':
                    first = phases['open'].current
                    if first is None or first.inode != expected_inode:
                        raise OSError('initial fixture socket not established')
                    cookie = first.cookie
            parent.send_bytes(b'Q')
            child.join(_remaining(deadline))
            if child.exitcode != 0:
                raise OSError('fixture child incomplete')
        finally:
            if child.is_alive():
                child.kill()
            child.join()
            child.close()
    return _result(phases)


def _result(phases):
    opened, moved, closed = (phases[name] for name in ('open', 'moved', 'closed'))
    holders = {name: observation.holders() for name, observation in phases.items()}
    expected = {'open': ('observed_holder', 'unknown'), 'moved': ('unknown', 'observed_holder'),
                'closed': ('unknown', 'unknown')}
    same_socket = opened.current is not None and opened.current == moved.current
    reused = (moved.current is not None and moved.before[0] == moved.after[0]
              and moved.after[0] not in (None, moved.current.inode))
    cleared = reused and closed.before == closed.after == (moved.after[0], None)
    passed = holders == expected and same_socket and reused and cleared
    return dict(all_match=passed, status='passed' if passed else 'failed', holder_by_slot=holders,
                original_slot_reused=reused, same_established_socket_after_move=same_socket,
                client_links_cleared=cleared)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    result = dict(schema='megalodon-linux-tcp-holder-replay-v1', all_match=False,
                  status='inconclusive', evidence_scope='fixture_descriptor_at_observation',
                  historical_ownership='not_evaluated', job_authorization='not_evaluated')
    if args:
        result['reason'] = 'no_arguments_accepted'
    elif sys.platform != 'linux' or not hasattr(socket, 'AF_NETLINK'):
        result['reason'] = 'linux_diagnostics_required'
    elif os.getuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        result['reason'] = 'ordinary_account_required'
    else:
        try:
            result.update(_probe())
        except PermissionError:
            result['reason'] = 'kernel_operation_denied'
        except (EOFError, OSError, RuntimeError, ValueError):
            result['reason'] = 'fixture_did_not_complete'
    print(json.dumps(result, sort_keys=True))
    return {'passed': 0, 'failed': 1, 'inconclusive': 2}[result['status']]


if __name__ == '__main__':
    raise SystemExit(main())
