"""Name the program behind every outgoing TCP connection as it is made, with a small eBPF program.

The egress watch reads the socket tables once a second, and hears connections
close through sock_diag. A connection opened and closed between two reads is
heard only by its addresses: the kernel does not say which program made it,
and that program may have exited already. A short beacon, a quick upload or a
single fetch of a second stage looks like this (ATT&CK T1071, T1041, T1105).

This module attaches a program to the kernel's ``inet_sock_set_state``
tracepoint, which fires on every TCP state change. A connect moves a socket
into SYN_SENT in the connecting process: the program sends back the process
and thread group IDs, the parent's, the user and group IDs and the command
name, with the socket's kernel address. When the socket leaves SYN_SENT
(connected, or failed), its local port has been chosen: the program sends its
addresses, ports and network namespace. The two are joined here by the
socket's address, and the egress watch matches a closed connection to the
program that opened it by its four addresses and ports and its namespace.
Other state changes (servers accepting, connections closing) are ignored in
the kernel.

It uses no compiler or library: the program is written as eBPF instructions
here, loaded with the ``bpf()`` system call, and reads its results from a BPF
ring buffer. Field offsets come from the running kernel's own type
information (BTF, ``/sys/kernel/btf/vmlinux``), so one build works across
kernel versions.

It needs root (CAP_BPF and CAP_PERFMON, or CAP_SYS_ADMIN), a kernel built with
BTF (``/sys/kernel/btf/vmlinux``) and BPF ring buffers (Linux 5.8 or later),
and x86-64 or arm64. While it runs, the kernel calls the program on every TCP
connect on the machine; it is removed when this process closes it or exits.
Nothing else on the machine is changed, and nothing is stored.
"""
from __future__ import annotations

import ctypes
import errno
import ipaddress
import mmap
import os
import platform
import select
import socket
import struct

BTF_PATH = '/sys/kernel/btf/vmlinux'
SYSCALL_BPF = {'x86_64': 321, 'aarch64': 280}
TRACEPOINT = b'inet_sock_set_state'
TCP_SYN_SENT = 2
PENDING_SECONDS = 600       # A connect still unanswered after this is forgotten.
MAX_PENDING = 65536
RING_BYTES = 1 << 20
MAX_EVENTS_PER_DRAIN = 65536
LICENSE = b'Dual BSD/GPL'

# bpf() commands, program and map types (include/uapi/linux/bpf.h)
BPF_MAP_CREATE, BPF_PROG_LOAD, BPF_RAW_TRACEPOINT_OPEN = 0, 5, 17
BPF_MAP_TYPE_RINGBUF = 27
BPF_PROG_TYPE_RAW_TRACEPOINT = 17
BPF_PSEUDO_MAP_FD = 1
# Helpers
GET_CURRENT_PID_TGID, GET_CURRENT_UID_GID, GET_CURRENT_COMM, GET_CURRENT_TASK = 14, 15, 16, 35
PROBE_READ_USER, PROBE_READ_KERNEL, PROBE_READ_KERNEL_STR, RINGBUF_RESERVE, RINGBUF_SUBMIT = 112, 113, 115, 131, 132
# The executable's last path components, read in the kernel: kept for a process gone before it can be read.
EXE_LEVELS, EXE_NAME = 6, 64
# Ring buffer record header bits
RINGBUF_BUSY, RINGBUF_DISCARD, RINGBUF_HEADER = 1 << 31, 1 << 30, 8

# BTF kinds, and how many bytes follow each type's 12-byte header (per member where it has members)
BTF_KIND_STRUCT, BTF_KIND_UNION, BTF_KIND_FUNC = 4, 5, 12
_TRAILER = {1: (4, 0), 2: (0, 0), 3: (12, 0), 4: (0, 12), 5: (0, 12), 6: (0, 8), 7: (0, 0), 8: (0, 0), 9: (0, 0),
            10: (0, 0), 11: (0, 0), 12: (0, 0), 13: (0, 8), 14: (4, 0), 15: (0, 12), 16: (0, 0), 17: (4, 0),
            18: (0, 0), 19: (0, 12)}

# The event the program writes: pid_tgid, uid_gid, comm, the parent's tgid, the old and new states, the socket's
# kernel address, its network namespace number, then the start of struct sock.
EVENT_PID, EVENT_UID, EVENT_COMM, EVENT_PARENT, EVENT_OLD, EVENT_NEW, EVENT_SK, EVENT_NETNS, EVENT_MOUNT, \
    EVENT_SOCK = 0, 8, 16, 32, 36, 40, 48, 56, 60, 64
SOCK_FIELDS = ('skc_daddr', 'skc_rcv_saddr', 'skc_dport', 'skc_num', 'skc_family', 'skc_v6_daddr',
               'skc_v6_rcv_saddr')


class TraceError(OSError):
    pass


# ------------------------------------------------------------------ kernel type information

class BTF:
    """The kernel's BTF: function IDs, and member offsets of structures, anonymous members included."""

    def __init__(self, data):
        magic, version, _flags, header = struct.unpack_from('<HBBI', data, 0)
        if magic != 0xEB9F or version != 1:
            raise TraceError(errno.EINVAL, 'not kernel BTF')
        type_off, type_len, str_off, str_len = struct.unpack_from('<IIII', data, 8)
        self.strings = data[header + str_off:header + str_off + str_len]
        self.types = [None]  # Type IDs start at 1.
        position, end = header + type_off, header + type_off + type_len
        while position < end:
            name_off, info, size = struct.unpack_from('<III', data, position)
            kind, count = (info >> 24) & 0x1F, info & 0xFFFF
            fixed, each = _TRAILER.get(kind, (None, None))
            if fixed is None:
                raise TraceError(errno.EINVAL, f'unknown BTF kind {kind}')
            members = []
            if kind in (BTF_KIND_STRUCT, BTF_KIND_UNION):
                for index in range(count):
                    m_name, m_type, m_offset = struct.unpack_from('<III', data, position + 12 + index * 12)
                    bits = m_offset & 0xFFFFFF if info >> 31 else m_offset  # kind_flag: bitfield size in high bits
                    members.append((self._name(m_name), m_type, bits))
            self.types.append((kind, self._name(name_off), size, members))
            position += 12 + fixed + count * each

    def _name(self, offset):
        return self.strings[offset:self.strings.index(b'\0', offset)].decode('ascii', 'replace')

    def function(self, name):
        for index, entry in enumerate(self.types):
            if entry and entry[0] == BTF_KIND_FUNC and entry[1] == name:
                return index
        raise TraceError(errno.ENOENT, f'{name} is not in the kernel BTF')

    def struct(self, name):
        for index, entry in enumerate(self.types):
            if entry and entry[0] == BTF_KIND_STRUCT and entry[1] == name:
                return index
        raise TraceError(errno.ENOENT, f'struct {name} is not in the kernel BTF')

    def offsets(self, type_id, wanted):
        """Byte offsets of members named in ``wanted``, looking into anonymous structures and unions."""
        found = {}

        def walk(type_id, base):
            kind, _name, _size, members = self.types[type_id]
            for name, member_type, bits in members:
                if name in wanted and name not in found:
                    found[name] = (base + bits) // 8
                elif not name:
                    target = self._resolve(member_type)
                    if self.types[target][0] in (BTF_KIND_STRUCT, BTF_KIND_UNION):
                        walk(target, base + bits)
        walk(type_id, 0)
        missing = set(wanted) - set(found)
        if missing:
            raise TraceError(errno.ENOENT, f'kernel BTF has no {", ".join(sorted(missing))}')
        return found

    def _resolve(self, type_id):
        while self.types[type_id][0] in (8, 9, 10, 11, 18):  # typedef, volatile, const, restrict, type tag
            type_id = self.types[type_id][2]
        return type_id


# ------------------------------------------------------------------ instructions

def _insn(code, dst=0, src=0, off=0, imm=0):
    return struct.pack('<BBhi', code, (src << 4) | dst, off, imm)


def mov_reg(dst, src):
    return _insn(0xBF, dst, src)


def mov_imm(dst, imm):
    return _insn(0xB7, dst, imm=imm)


def add_imm(dst, imm):
    return _insn(0x07, dst, imm=imm)


def load_dw(dst, src, off):
    return _insn(0x79, dst, src, off)


def store_dw(dst, off, src):
    return _insn(0x7B, dst, src, off)


def call(helper):
    return _insn(0x85, imm=helper)


def jump_if_zero(reg, off):
    return _insn(0x15, reg, off=off)


def exit_():
    return _insn(0x95)


def load_map(dst, fd):
    return _insn(0x18, dst, BPF_PSEUDO_MAP_FD, imm=fd) + _insn(0)


def store_w(dst, off, src):
    return _insn(0x63, dst, src, off)


def jump_if(reg, imm, off):
    """Jump ``off`` instructions ahead when ``reg`` equals ``imm``."""
    return _insn(0x15, reg, off=off, imm=imm)


def jump_if_not(reg, imm, off):
    return _insn(0x55, reg, off=off, imm=imm)


def jump_if_at_most(reg, imm, off):
    """Jump ``off`` instructions ahead when ``reg`` <= ``imm``, unsigned."""
    return _insn(0xB5, reg, off=off, imm=imm)


def sub_reg(dst, src):
    return _insn(0x1F, dst, src)


def deref(reg, offset):
    """reg = *(u64 *)(reg + offset), read through the stack. Clobbers r0 to r5."""
    return [mov_reg(3, reg), add_imm(3, offset), mov_reg(1, 10), add_imm(1, -8), mov_imm(2, 8),
            call(PROBE_READ_KERNEL), load_dw(reg, 10, -8)]


def read_into(event, dst_off, size, src_reg):
    """probe_read_kernel(event + dst_off, size, src_reg), ``event`` being the register holding the record."""
    return [mov_reg(1, event), add_imm(1, dst_off), mov_imm(2, size), mov_reg(3, src_reg), call(PROBE_READ_KERNEL)]


def read_mount(event, dst_off, reg, to_mount, mount_id):
    """The ID of the mount at ``reg + to_mount`` (a struct path's mnt: a struct vfsmount inside a struct mount),
    written as 4 bytes at ``event + dst_off``. Clobbers r0 to r5."""
    return [mov_reg(3, reg), add_imm(3, to_mount), mov_reg(1, 10), add_imm(1, -8), mov_imm(2, 8),
            call(PROBE_READ_KERNEL), load_dw(3, 10, -8), add_imm(3, mount_id),
            mov_reg(1, event), add_imm(1, dst_off), mov_imm(2, 4), call(PROBE_READ_KERNEL)]


def walk_names(event, dst_off, reg, name, parent, levels=EXE_LEVELS):
    """Starting from the dentry in ``reg``, write it and ``levels`` - 1 of its parents' names, EXE_NAME bytes
    each, from ``event + dst_off``. A read that fails leaves zeros, and the names after it empty."""
    out = []
    for level in range(levels):
        out += [mov_reg(3, reg), add_imm(3, name), mov_reg(1, 10), add_imm(1, -8), mov_imm(2, 8),
                call(PROBE_READ_KERNEL), load_dw(3, 10, -8),
                mov_reg(1, event), add_imm(1, dst_off + level * EXE_NAME), mov_imm(2, EXE_NAME),
                call(PROBE_READ_KERNEL_STR)]
        if level < levels - 1:
            out += deref(reg, parent)
    return out


def names_at(data, offset, levels=EXE_LEVELS):
    """The names :func:`walk_names` wrote from ``offset``."""
    return [bytes(data[offset + i * EXE_NAME:offset + (i + 1) * EXE_NAME]).split(b'\0', 1)[0]
            .decode('utf-8', 'replace') for i in range(levels)]


def _count(items):
    return sum(len(item) // 8 for item in items)


def program(ring_fd, sock_bytes, real_parent, tgid, net=None, exe=None):
    """Raw tracepoint inet_sock_set_state(sk, oldstate, newstate): an event for each move into or out of
    SYN_SENT. ``net`` is (offset of skc_net in sock_common, offset of the namespace number in struct net); ``exe``
    is the chain of offsets from the task to its executable's dentry, then a dentry's name and parent."""
    event = EVENT_SOCK + sock_bytes + (EXE_LEVELS * EXE_NAME if exe else 0)

    def read(dst_off, size, src_reg):
        return read_into(8, dst_off, size, src_reg)

    fill = [
        mov_reg(8, 0),                      # r8 = event
        call(GET_CURRENT_PID_TGID), store_dw(8, EVENT_PID, 0),
        call(GET_CURRENT_UID_GID), store_dw(8, EVENT_UID, 0),
        mov_reg(1, 8), add_imm(1, EVENT_COMM), mov_imm(2, 16), call(GET_CURRENT_COMM),
        store_w(8, EVENT_OLD, 9), load_dw(0, 6, 16), store_w(8, EVENT_NEW, 0), store_dw(8, EVENT_SK, 7),
        *read(EVENT_SOCK, sock_bytes, 7),
        # The parent: current->real_parent->tgid, read through the stack.
        call(GET_CURRENT_TASK), mov_reg(3, 0), add_imm(3, real_parent),
        mov_reg(1, 10), add_imm(1, -8), mov_imm(2, 8), call(PROBE_READ_KERNEL),
        load_dw(3, 10, -8), add_imm(3, tgid), *read(EVENT_PARENT, 4, 3),
    ]
    if net:
        # The namespace: sk->skc_net (a struct net pointer), then its number.
        fill += [mov_reg(3, 7), add_imm(3, net[0]), mov_reg(1, 10), add_imm(1, -8), mov_imm(2, 8),
                 call(PROBE_READ_KERNEL), load_dw(3, 10, -8), add_imm(3, net[1]),
                 mov_reg(1, 8), add_imm(1, EVENT_NETNS), mov_imm(2, 4), call(PROBE_READ_KERNEL)]
    if exe:
        # current->mm->exe_file->f_path.dentry, then each dentry's name and its parent. A read that fails (a
        # kernel thread has no mm) leaves zeros, and the names after it empty.
        to_mm, to_file, to_dentry, name, parent, to_mount, mount_id = exe
        fill += [call(GET_CURRENT_TASK), mov_reg(9, 0), *deref(9, to_mm), *deref(9, to_file),
                 # The mount the file is on, whose ID maps it to its mount point (/proc/self/mountinfo).
                 *read_mount(8, EVENT_MOUNT, 9, to_mount, mount_id),
                 *deref(9, to_dentry), *walk_names(8, EVENT_SOCK + sock_bytes, 9, name, parent)]
    fill += [mov_reg(1, 8), mov_imm(2, 0), call(RINGBUF_SUBMIT)]
    reserve = [load_map(1, ring_fd), mov_imm(2, event), mov_imm(3, 0), call(RINGBUF_RESERVE)]
    done = [mov_imm(0, 0), exit_()]
    tail = reserve + [jump_if_zero(0, _count(fill))] + fill
    head = [
        mov_reg(6, 1),                      # r6 = ctx: the tracepoint's arguments
        load_dw(7, 6, 0),                   # r7 = sk
        load_dw(9, 6, 8),                   # r9 = oldstate
        jump_if(9, TCP_SYN_SENT, 2),        # leaving SYN_SENT: report
        load_dw(0, 6, 16),                  # r0 = newstate
        jump_if_not(0, TCP_SYN_SENT, _count(tail)),   # neither: skip to the exit
    ]
    return b''.join(head + tail + done)


# ------------------------------------------------------------------ the bpf() system call

_libc = ctypes.CDLL(None, use_errno=True)


def _bpf(command, attr):
    number = SYSCALL_BPF.get(platform.machine())
    if number is None:
        raise TraceError(errno.ENOSYS, f'connect tracing supports x86-64 and arm64, not {platform.machine()}')
    buffer = ctypes.create_string_buffer(bytes(attr), 128)
    result = _libc.syscall(ctypes.c_long(number), ctypes.c_int(command), buffer, ctypes.c_uint(128))
    if result < 0:
        code = ctypes.get_errno()
        raise TraceError(code, f'bpf({command}): {os.strerror(code)}')
    return result


def _address(data):
    return ctypes.addressof(data) if not isinstance(data, int) else data


def attach(code, name, tracepoint):
    """Load ``code`` as a raw tracepoint program called ``name`` (up to 15 bytes) and attach it to
    ``tracepoint``: [program fd, link fd]. Closing both removes it."""
    insns = ctypes.create_string_buffer(code, len(code))
    # The kernel lets only GPL-compatible programs call the helpers used here; the in-kernel programs are
    # dual-licensed, as the kernel's own BPF tools are.
    license_ = ctypes.create_string_buffer(LICENSE)
    log = ctypes.create_string_buffer(65536)
    attr = bytearray(128)
    struct.pack_into('<IIQQIIQ', attr, 0, BPF_PROG_TYPE_RAW_TRACEPOINT, len(code) // 8, _address(insns),
                     _address(license_), 1, len(log), _address(log))
    attr[48:64] = name.encode('ascii')[:15].ljust(16, b'\0')
    try:
        prog = _bpf(BPF_PROG_LOAD, attr)
    except TraceError as exc:
        detail = log.value.decode('ascii', 'replace').strip().splitlines()[-3:]
        raise TraceError(exc.errno, f'the kernel refused the program: {exc.strerror}; '
                                    f'{" / ".join(detail)}') from None
    try:
        point = ctypes.create_string_buffer(tracepoint)
        return [prog, _bpf(BPF_RAW_TRACEPOINT_OPEN, struct.pack('<QI', _address(point), prog))]
    except BaseException:
        os.close(prog)
        raise


class Ring:
    """A BPF ring buffer map, read with ``mmap``: the records the programs submit, oldest first."""

    def __init__(self, size=RING_BYTES):
        self.size = size
        self.fd = _bpf(BPF_MAP_CREATE, struct.pack('<IIIII', BPF_MAP_TYPE_RINGBUF, 0, 0, size, 0))
        self.consumer = self.producer = self.poller = None
        try:
            self.page = mmap.PAGESIZE
            self.consumer = mmap.mmap(self.fd, self.page, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE,
                                      offset=0)
            self.producer = mmap.mmap(self.fd, self.page + 2 * size, mmap.MAP_SHARED, mmap.PROT_READ,
                                      offset=self.page)
            self.poller = select.epoll()
            self.poller.register(self.fd, select.EPOLLIN)
        except BaseException:
            self.close()
            raise

    def wait(self, seconds):
        return bool(self.poller.poll(seconds))

    def records(self, limit=MAX_EVENTS_PER_DRAIN):
        records = []
        consumer, = struct.unpack_from('<Q', self.consumer, 0)
        producer, = struct.unpack_from('<Q', self.producer, 0)
        while consumer < producer and len(records) < limit:
            start = self.page + consumer % self.size
            header, = struct.unpack_from('<I', self.producer, start)
            if header & RINGBUF_BUSY:
                break
            length = header & ~(RINGBUF_BUSY | RINGBUF_DISCARD)
            if not header & RINGBUF_DISCARD:
                records.append(self.producer[start + RINGBUF_HEADER:start + RINGBUF_HEADER + length])
            consumer += (length + RINGBUF_HEADER + 7) // 8 * 8
        struct.pack_into('<Q', self.consumer, 0, consumer)
        return records

    def close(self):
        for name in ('consumer', 'producer', 'poller'):
            item = getattr(self, name, None)
            if item is not None:
                item.close()
                setattr(self, name, None)
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def _net_offsets(btf):
    """Where a socket's network namespace number is: skc_net in sock_common, then ns.inum in struct net. None
    when this kernel lays them out otherwise; connections are then matched without their namespace."""
    try:
        skc_net = btf.offsets(btf.struct('sock_common'), ('skc_net',))['skc_net']
        net = btf.struct('net')
        ns = btf.offsets(net, ('ns',))['ns']
        member_type = next(t for name, t, _ in btf.types[net][3] if name == 'ns')
        inum = btf.offsets(btf._resolve(member_type), ('inum',))['inum']
    except (TraceError, StopIteration):
        return None
    return skc_net, ns + inum


def _exe_offsets(btf):
    """(task->mm, mm->exe_file, file->f_path.dentry, dentry->d_name.name, dentry->d_parent, file->f_path.mnt,
    from a struct vfsmount to its struct mount's mnt_id), or None."""
    try:
        mm = btf.offsets(btf.struct('task_struct'), ('mm',))['mm']
        exe_file = btf.offsets(btf.struct('mm_struct'), ('exe_file',))['exe_file']
        f_path = btf.offsets(btf.struct('file'), ('f_path',))['f_path']
        path = btf.offsets(btf.struct('path'), ('dentry', 'mnt'))
        dentry_fields = btf.offsets(btf.struct('dentry'), ('d_name', 'd_parent'))
        name = btf.offsets(btf.struct('qstr'), ('name',))['name']
        mount = btf.offsets(btf.struct('mount'), ('mnt', 'mnt_id'))
    except TraceError:
        return None
    return (mm, exe_file, f_path + path['dentry'], dentry_fields['d_name'] + name, dentry_fields['d_parent'],
            f_path + path['mnt'], mount['mnt_id'] - mount['mnt'])


def _tail(names, mount=None):
    """The executable's path from the names of its dentry and its parents. The names stop at the root of the
    file system it is on: with ``mount`` (that file system's (root within it, mount point), from mountinfo) the
    path is put under its mount point. Without it, when the names ran out first, or when a name may have been
    cut short (it fills the 64-byte buffer it is read into), it is shown after '…/' as partial."""
    parts = []
    for name in names:
        if not name or name == '/':
            break
        parts.append(name)
    if not parts:
        return None
    path = '/' + '/'.join(reversed(parts))
    reached_root = len(parts) < len(names) and names[len(parts)] == '/'
    # A name that fills the kernel's buffer may have been cut short: the path is then not the program's.
    cut = any(len(part.encode('utf-8', 'surrogateescape')) >= EXE_NAME - 1 for part in parts)
    if not reached_root or mount is None or cut:
        return '…' + path
    root, point = mount
    if root != '/':                          # A bind mount of a folder: the path is below that folder.
        if not path.startswith(root.rstrip('/') + '/'):
            return '…' + path
        path = path[len(root.rstrip('/')):]
    return (point.rstrip('/') + path) if point != '/' else path


def mounts(path='/proc/self/mountinfo'):
    """{mount ID: (root within its file system, mount point)} for this process's mounts."""
    found = {}
    try:
        with open(path, encoding='utf-8', errors='replace') as stream:
            for line in stream:
                fields = line.split(' ')
                if len(fields) > 4 and fields[0].isdigit():
                    unescape = lambda text: text.replace('\\040', ' ').replace('\\011', '\t').replace(
                        '\\012', '\n').replace('\\134', '\\')
                    found[int(fields[0])] = (unescape(fields[3]), unescape(fields[4]))
    except OSError:
        pass
    return found


class ConnectTrace:
    """Attach the program, and read the connections it reports, each named by the program that made it."""

    def __init__(self, btf_path=BTF_PATH, *, clock=None, process=None):
        import time
        self.fds, self.pending, self.clock = [], {}, clock or time.monotonic
        # Called with a pid as its connect is seen, while the process is (normally) still running.
        self.process = process or (lambda pid: dict(executable=_exe(pid)))
        self.lost = 0
        try:
            with open(btf_path, 'rb') as stream:
                btf = BTF(stream.read())
            self.layout = btf.offsets(btf.struct('sock_common'), SOCK_FIELDS)
            task = btf.offsets(btf.struct('task_struct'), ('real_parent', 'tgid'))
            self.net = _net_offsets(btf)
            self.exe_chain = _exe_offsets(btf)
        except OSError as exc:
            raise TraceError(exc.errno or errno.ENOENT, f'kernel type information: {exc}') from None
        self.sock_bytes = (max(self.layout.values()) + 16 + 7) // 8 * 8
        self.ring = Ring()
        try:
            code = program(self.ring.fd, self.sock_bytes, task['real_parent'], task['tgid'], self.net,
                           self.exe_chain)
            self.fds += attach(code, 'megalodon_conn', TRACEPOINT)
        except BaseException:
            self.close()
            raise

    def fileno(self):
        return self.ring.fd

    def wait(self, seconds):
        """Wait up to ``seconds`` for the program to report something; True if it has."""
        return self.ring.wait(seconds)

    def drain(self):
        """Every connection whose local port was chosen since the last call, oldest first, each with the
        program that made it when its connect was seen."""
        return self.join(self.ring.records())

    def join(self, records):
        """Pair each socket's connect (process side) with its leaving SYN_SENT (addresses side)."""
        now, out = self.clock(), []
        for data in records:
            event = self.parse(data)
            if event is None:
                continue
            if event['new'] == TCP_SYN_SENT:
                if len(self.pending) >= MAX_PENDING:
                    self.pending.pop(next(iter(self.pending)))
                    self.lost += 1
                event['process'] = self.process(event['pid'])
                self.pending[event['sk']] = (now, event)
            elif event['old'] == TCP_SYN_SENT:
                started = self.pending.pop(event['sk'], None)
                if started is None:
                    continue          # Its connect came before the trace started.
                who = started[1]
                out.append(dict(protocol='tcp', pid=who['pid'], parent=who['parent'], uid=who['uid'],
                                gid=who['gid'], comm=who['comm'], process=who['process'], exe_tail=who['exe_tail'],
                                netns=event['netns'],
                                local_address=event['local_address'], local_port=event['local_port'],
                                address=event['address'], port=event['port'],
                                connected=event['new'] == 1))   # TCP_ESTABLISHED; otherwise it failed
        for sk in [sk for sk, (seen, _) in self.pending.items() if now - seen > PENDING_SECONDS]:
            del self.pending[sk]
        return out

    def parse(self, data):
        if len(data) < EVENT_SOCK + self.sock_bytes + (EXE_LEVELS * EXE_NAME if self.exe_chain else 0):
            return None
        pid_tgid, uid_gid = struct.unpack_from('<QQ', data, EVENT_PID)
        comm = data[EVENT_COMM:EVENT_COMM + 16].split(b'\0', 1)[0].decode('utf-8', 'replace')
        parent, old, new = struct.unpack_from('<III', data, EVENT_PARENT)
        sk, = struct.unpack_from('<Q', data, EVENT_SK)
        netns, = struct.unpack_from('<I', data, EVENT_NETNS)
        sock, layout = data[EVENT_SOCK:], self.layout
        family, = struct.unpack_from('<H', sock, layout['skc_family'])
        remote_port, = struct.unpack_from('>H', sock, layout['skc_dport'])
        local_port, = struct.unpack_from('<H', sock, layout['skc_num'])
        if family == socket.AF_INET:
            remote = ipaddress.IPv4Address(bytes(sock[layout['skc_daddr']:layout['skc_daddr'] + 4]))
            local = ipaddress.IPv4Address(bytes(sock[layout['skc_rcv_saddr']:layout['skc_rcv_saddr'] + 4]))
        elif family == socket.AF_INET6:
            remote = ipaddress.IPv6Address(bytes(sock[layout['skc_v6_daddr']:layout['skc_v6_daddr'] + 16]))
            local = ipaddress.IPv6Address(bytes(sock[layout['skc_v6_rcv_saddr']:layout['skc_v6_rcv_saddr'] + 16]))
        else:
            return None
        names, mount = [], None
        if self.exe_chain:
            names = names_at(data, EVENT_SOCK + self.sock_bytes)
            mount_id, = struct.unpack_from('<I', data, EVENT_MOUNT)
            mount = self.mount(mount_id)
        return dict(exe_tail=_tail(names, mount), pid=pid_tgid >> 32, uid=uid_gid & 0xFFFFFFFF, gid=uid_gid >> 32, comm=comm, parent=parent,
                    old=old, new=new, sk=sk, netns=netns or None, local_address=str(local), local_port=local_port,
                    address=str(remote), port=remote_port)

    def mount(self, mount_id):
        """(root, mount point) of a mount ID, reading mountinfo again when one is new: None if it is not
        among this process's mounts (another mount namespace, such as a container's)."""
        if not mount_id:
            return None
        known = getattr(self, 'known_mounts', None)
        if known is None or mount_id not in known:
            known = self.known_mounts = mounts()
        return known.get(mount_id)

    def close(self):
        while self.fds:                       # The program and its link first, then the ring they write to.
            os.close(self.fds.pop())
        ring = getattr(self, 'ring', None)
        if ring is not None:
            ring.close()
            self.ring = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _exe(pid):
    """The program file a process runs, read at its connect; None once it is gone or unreadable."""
    try:
        return os.readlink(f'/proc/{pid}/exe')
    except OSError:
        return None
