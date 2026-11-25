"""Remember every program as it starts, with a small eBPF program, so one that has already exited can be named.

Watches that learn a process ID from the kernel, such as the credential
watch's file-access notifications, read the program from ``/proc`` when they
handle the event. A program that starts, does its work and exits within
microseconds is gone by then: a burst of quick readers, or one run while the
watch is busy, goes unnamed.

This module attaches two programs to the kernel's scheduler tracepoints:

* ``sched_process_exec`` runs in the new program as its exec completes. It
  sends back the process and parent IDs, user and group IDs, command name,
  start time, the start of the command line (from the new program's own
  memory), and the executable's and the working folder's names, each read
  from its dentry and its parents, with the ID of the mount they are on. For
  the container watch it adds the mount namespace, the executable's device
  and inode, and the path names of the control groups the program is in.
* ``sched_process_fork`` sends the new process's ID and start time and its
  parent's ID, so a worker that forks without exec carries its parent's
  program. New threads are skipped in the kernel.

The records are read here from a BPF ring buffer. The program is written as
eBPF instructions and loaded with the ``bpf()`` system call, with field offsets
from the running kernel's BTF, as :mod:`megalodon.connect_trace` does.

It needs root (CAP_BPF and CAP_PERFMON, or CAP_SYS_ADMIN), a kernel with BTF
and BPF ring buffers (Linux 5.8 or later), and x86-64 or arm64. While it runs,
the kernel calls the programs on every exec and fork on the machine; they are
removed when this process closes them or exits. Nothing else is changed, and
nothing is stored.
"""
from __future__ import annotations

import errno
import os
import struct

from .connect_trace import (BTF, BTF_PATH, EXE_NAME, GET_CURRENT_COMM, GET_CURRENT_PID_TGID,
                            GET_CURRENT_TASK, GET_CURRENT_UID_GID, PROBE_READ_KERNEL, PROBE_READ_USER,
                            RINGBUF_RESERVE, RINGBUF_SUBMIT, Counter, Ring, TraceError, _count, _exe_offsets,
                            _insn, count_drop,
                            _tail, add_imm, attach, call, deref, exit_, jump_if_at_most, jump_if_zero, load_dw,
                            load_map, mount_table, mov_imm, mov_reg, names_at, read_into, read_mount, store_dw,
                            store_w, sub_reg, walk_names)

EXEC_POINT, FORK_POINT = b'sched_process_exec', b'sched_process_fork'
RING_BYTES = 8 << 20            # About 2,400 execs between two reads.
ARGV_BYTES = 512                 # As much of the command line as /proc is read for (egress_watch.MAX_ARGV).
KIND_EXEC, KIND_FORK = 1, 2

LEVELS = 10                      # Folder names read for the executable and the working folder.
# The exec record
EXEC_KIND, EXEC_PARENT, EXEC_PID, EXEC_UID, EXEC_COMM, EXEC_START, EXEC_ARGS, EXEC_EXE_MOUNT, EXEC_CWD_MOUNT, \
    EXEC_EXE, EXEC_CWD = 0, 4, 8, 16, 24, 40, 48, 52, 56, 64, 64 + LEVELS * EXE_NAME
EXEC_ARGV = EXEC_CWD + LEVELS * EXE_NAME
# Then the executable's inode number and device, the mount namespace, and two control groups' path names (the
# unified hierarchy's, and the memory controller's, which holds containers on cgroup v1), leaf first.
CG_LEVELS, CG_NAME = 6, 128
EXEC_INO = EXEC_ARGV + ARGV_BYTES
EXEC_DEV, EXEC_MNTNS, EXEC_CGROUP_DFL = EXEC_INO + 8, EXEC_INO + 12, EXEC_INO + 16
EXEC_CGROUP_V1 = EXEC_CGROUP_DFL + CG_LEVELS * CG_NAME
# Then the account that logged in (the audit login ID, kept through sudo and su) and the login session.
EXEC_LOGIN = EXEC_CGROUP_V1 + CG_LEVELS * CG_NAME
EXEC_SESSION = EXEC_LOGIN + 4
EXEC_BYTES = EXEC_LOGIN + 8
UNSET = 0xFFFFFFFF               # No login ID, or no session: the kernel's (u32)-1.
# The fork record: kind, parent tgid, child pid, child tgid, child start time
FORK_KIND, FORK_PARENT, FORK_PID, FORK_TGID, FORK_START, FORK_BYTES = 0, 4, 8, 12, 16, 24


def store_w_imm(dst, off, imm):
    return _insn(0x62, dst, off=off, imm=imm)


def load_w(dst, src, off):
    return _insn(0x61, dst, src, off)


def jump_if_regs_differ(dst, src, off):
    return _insn(0x5D, dst, src, off)


def _finish(ring_fd, size, fill, counter_fd):
    """Reserve ``size`` bytes, run ``fill`` (which submits), and return 0; with ``counter_fd``, a reserve that
    fails (the ring buffer is full) adds one to that counter instead."""
    reserve = [load_map(1, ring_fd), mov_imm(2, size), mov_imm(3, 0), call(RINGBUF_RESERVE)]
    done = [mov_imm(0, 0), exit_()]
    if counter_fd is None:
        return reserve + [jump_if_zero(0, _count(fill))] + fill + done
    return reserve + [jump_if_zero(0, _count(fill) + 2)] + fill + done + count_drop(counter_fd) + done


def exec_program(ring_fd, task, mm, exe, cwd, ns=None, inode=None, cgroup=None, login=None, counter_fd=None):
    """Raw tracepoint sched_process_exec: one record per exec, in the new program.

    ``task`` is the offsets of real_parent, tgid and start_boottime (or None) in task_struct; ``mm`` those of
    arg_start and arg_end in mm_struct; ``exe`` the chain from :func:`connect_trace._exe_offsets`; ``cwd``
    (task->fs, fs->pwd.dentry, fs->pwd.mnt) or None. Each of these may be None: ``ns`` (task->nsproxy,
    nsproxy->mnt_ns, the namespace number in it); ``inode`` (file->f_inode, inode->i_ino, inode->i_sb,
    super_block->s_dev); ``cgroup`` (task->cgroups, css_set->dfl_cgrp, the memory controller's state in
    css_set->subsys or None, its ->cgroup, cgroup->kn, kernfs_node->name, kernfs_node->parent); ``login``
    (task->loginuid, task->sessionid). ``counter_fd`` is the map that counts records the ring buffer had no
    room for."""
    real_parent, tgid, start = task
    arg_start, arg_end = mm
    to_mm, to_file, to_dentry, name, parent, to_mount, mount_id = exe
    fill = [
        mov_reg(8, 0), store_w_imm(8, EXEC_KIND, KIND_EXEC),
        call(GET_CURRENT_PID_TGID), store_dw(8, EXEC_PID, 0),
        call(GET_CURRENT_UID_GID), store_dw(8, EXEC_UID, 0),
        mov_reg(1, 8), add_imm(1, EXEC_COMM), mov_imm(2, 16), call(GET_CURRENT_COMM),
        call(GET_CURRENT_TASK), store_dw(10, -16, 0), mov_reg(9, 0),
        # The parent: current->real_parent->tgid.
        mov_reg(6, 9), *deref(6, real_parent), add_imm(6, tgid), *read_into(8, EXEC_PARENT, 4, 6),
    ]
    if start is not None:
        fill += [mov_reg(3, 9), add_imm(3, start), *read_into(8, EXEC_START, 8, 3)]
    fill += [
        # The command line, from the new program's memory: [arg_start, arg_end), at most ARGV_BYTES of it.
        *deref(9, to_mm), mov_reg(7, 9), *deref(7, arg_start), mov_reg(6, 9), *deref(6, arg_end),
        sub_reg(6, 7), store_w(8, EXEC_ARGS, 6),
        mov_reg(2, 6), jump_if_at_most(2, ARGV_BYTES, 1), mov_imm(2, ARGV_BYTES),
        mov_reg(1, 8), add_imm(1, EXEC_ARGV), mov_reg(3, 7), call(PROBE_READ_USER),
        # The executable: mm->exe_file, its mount, then its dentry's names.
        *deref(9, to_file), *read_mount(8, EXEC_EXE_MOUNT, 9, to_mount, mount_id),
        *deref(9, to_dentry), *walk_names(8, EXEC_EXE, 9, name, parent, LEVELS),
    ]
    if cwd is not None:
        to_fs, pwd_dentry, pwd_mnt = cwd
        fill += [load_dw(9, 10, -16), *deref(9, to_fs), *read_mount(8, EXEC_CWD_MOUNT, 9, pwd_mnt, mount_id),
                 *deref(9, pwd_dentry), *walk_names(8, EXEC_CWD, 9, name, parent, LEVELS)]
    if ns is not None:
        # The mount namespace: task->nsproxy->mnt_ns, then its number.
        to_nsproxy, to_mnt_ns, inum = ns
        fill += [load_dw(9, 10, -16), *deref(9, to_nsproxy), *deref(9, to_mnt_ns),
                 mov_reg(3, 9), add_imm(3, inum), *read_into(8, EXEC_MNTNS, 4, 3)]
    if inode is not None:
        # The executable's inode: mm->exe_file->f_inode, its number, and its file system's device.
        to_inode, i_ino, i_sb, s_dev = inode
        fill += [load_dw(9, 10, -16), *deref(9, to_mm), *deref(9, to_file), *deref(9, to_inode),
                 mov_reg(3, 9), add_imm(3, i_ino), *read_into(8, EXEC_INO, 8, 3),
                 *deref(9, i_sb), mov_reg(3, 9), add_imm(3, s_dev), *read_into(8, EXEC_DEV, 4, 3)]
    if cgroup is not None:
        # The control groups: task->cgroups (a css_set); its unified hierarchy's group, and the memory
        # controller's; each group's kernfs node, whose names and parents' names are its path.
        to_cgroups, dfl, memory, css_cgroup, to_kn, kn_name, kn_parent = cgroup
        fill += [load_dw(9, 10, -16), *deref(9, to_cgroups), store_dw(10, -24, 9),
                 *deref(9, dfl), *deref(9, to_kn),
                 *walk_names(8, EXEC_CGROUP_DFL, 9, kn_name, kn_parent, CG_LEVELS, CG_NAME)]
        if memory is not None:
            fill += [load_dw(9, 10, -24), *deref(9, memory), *deref(9, css_cgroup), *deref(9, to_kn),
                     *walk_names(8, EXEC_CGROUP_V1, 9, kn_name, kn_parent, CG_LEVELS, CG_NAME)]
    if login is not None:
        loginuid, sessionid = login
        fill += [load_dw(9, 10, -16), mov_reg(3, 9), add_imm(3, loginuid), *read_into(8, EXEC_LOGIN, 4, 3),
                 mov_reg(3, 9), add_imm(3, sessionid), *read_into(8, EXEC_SESSION, 4, 3)]
    fill += [mov_reg(1, 8), mov_imm(2, 0), call(RINGBUF_SUBMIT)]
    return b''.join(_finish(ring_fd, EXEC_BYTES, fill, counter_fd))


def fork_program(ring_fd, pid, tgid, start, counter_fd=None):
    """Raw tracepoint sched_process_fork(parent, child): one record per new process, none for a new thread.
    It runs in the parent. ``pid``, ``tgid`` and ``start`` are their offsets in task_struct (``start`` may be
    None)."""
    fill = [
        mov_reg(8, 0), store_w_imm(8, FORK_KIND, KIND_FORK),
        call(GET_CURRENT_PID_TGID), mov_imm(1, 32), _insn(0x7F, 0, 1), store_w(8, FORK_PARENT, 0),  # r0 >>= 32
        mov_reg(3, 7), add_imm(3, pid), *read_into(8, FORK_PID, 4, 3),
        mov_reg(3, 7), add_imm(3, tgid), *read_into(8, FORK_TGID, 4, 3),
    ]
    if start is not None:
        fill += [mov_reg(3, 7), add_imm(3, start), *read_into(8, FORK_START, 8, 3)]
    fill += [mov_reg(1, 8), mov_imm(2, 0), call(RINGBUF_SUBMIT)]
    body = _finish(ring_fd, FORK_BYTES, fill, counter_fd)[:-2]         # its return is the program's last
    # A new thread has pid != tgid: read both through the stack and skip the record.
    head = [
        load_dw(7, 6, 8),                   # r7 = the child task
        mov_reg(3, 7), add_imm(3, pid), mov_reg(1, 10), add_imm(1, -8), mov_imm(2, 4),
        call(PROBE_READ_KERNEL),
        mov_reg(3, 7), add_imm(3, tgid), mov_reg(1, 10), add_imm(1, -16), mov_imm(2, 4),
        call(PROBE_READ_KERNEL),
        load_w(1, 10, -8), load_w(2, 10, -16),
        jump_if_regs_differ(1, 2, _count(body)),
    ]
    # The stack slots are read whether or not the reads succeeded: zero them first.
    zero = [mov_reg(6, 1), mov_imm(1, 0), store_dw(10, -8, 1), store_dw(10, -16, 1)]   # r6 = ctx
    return b''.join(zero + head + body + [mov_imm(0, 0), exit_()])


def _offsets(btf):
    task = btf.offsets(btf.struct('task_struct'), ('real_parent', 'tgid', 'pid'))
    try:
        start = btf.offsets(btf.struct('task_struct'), ('start_boottime',))['start_boottime']
    except TraceError:
        start = None                    # Before Linux 5.5 it was real_start_time; the start is then unknown.
    mm = btf.offsets(btf.struct('mm_struct'), ('arg_start', 'arg_end'))
    exe = _exe_offsets(btf)
    if exe is None:
        raise TraceError(errno.ENOENT, 'kernel BTF lacks the executable file fields')
    try:
        fs = btf.offsets(btf.struct('task_struct'), ('fs',))['fs']
        pwd = btf.offsets(btf.struct('fs_struct'), ('pwd',))['pwd']
        path = btf.offsets(btf.struct('path'), ('dentry', 'mnt'))
        cwd = (fs, pwd + path['dentry'], pwd + path['mnt'])
    except TraceError:
        cwd = None
    return task, start, (mm['arg_start'], mm['arg_end']), exe, cwd


def _container_offsets(btf):
    """The offsets :func:`exec_program` takes as ``ns``, ``inode`` and ``cgroup``: each None where this kernel
    lays them out otherwise."""
    try:
        mnt_ns = btf.offsets(btf.struct('nsproxy'), ('mnt_ns',))['mnt_ns']
        ns = (btf.member('task_struct', 'nsproxy'), mnt_ns,
              btf.member('mnt_namespace', 'ns') + btf.member('ns_common', 'inum'))
    except TraceError:
        ns = None
    try:
        inode = (btf.member('file', 'f_inode'), btf.member('inode', 'i_ino'), btf.member('inode', 'i_sb'),
                 btf.member('super_block', 's_dev'))
    except TraceError:
        inode = None
    try:
        try:
            memory = btf.member('css_set', 'subsys') + 8 * btf.enumerator('memory_cgrp_id')
        except TraceError:
            memory = None                        # A kernel without the memory controller.
        cgroup = (btf.member('task_struct', 'cgroups'), btf.member('css_set', 'dfl_cgrp'), memory,
                  btf.member('cgroup_subsys_state', 'cgroup'), btf.member('cgroup', 'kn'),
                  btf.member('kernfs_node', 'name'), btf.member('kernfs_node', 'parent', '__parent'))
    except TraceError:
        cgroup = None
    return ns, inode, cgroup


def written(start, ns, inode, cgroup, login=None):
    """The parts of an exec record the program writes, from the offsets it was built with. A ring buffer's space
    is not cleared when it is reserved: a part the program does not write holds bytes of earlier records, so it
    is not read."""
    return dict(start=start is not None, ns=ns is not None, inode=inode is not None, cgroup=cgroup is not None,
                memory=cgroup is not None and cgroup[2] is not None, login=login is not None)


def group_path(names):
    """A control group's path from its kernfs node's name and its parents', leaf first: '…/' before it when the
    names ran out before the hierarchy's root (whose name is empty). None when nothing was read."""
    parts = []
    for name in names:
        if not name:
            break
        parts.append(name)
    if not parts:
        return None
    path = '/' + '/'.join(reversed(parts))
    return path if len(parts) < len(names) else '…' + path


def ticks(boottime_ns):
    """A start time in nanoseconds since boot, in the clock ticks /proc/PID/stat gives."""
    return boottime_ns // (1_000_000_000 // os.sysconf('SC_CLK_TCK'))


class ExecTrace:
    """Attach both programs, and read the execs and forks they report."""

    def __init__(self, btf_path=BTF_PATH):
        self.fds, self.ring, self.known_mounts = [], None, None
        try:
            with open(btf_path, 'rb') as stream:
                btf = BTF(stream.read())
        except OSError as exc:
            raise TraceError(exc.errno or errno.ENOENT, f'kernel type information: {exc}') from None
        task, start, mm, exe, self.cwd_chain = _offsets(btf)
        ns, inode, cgroup = _container_offsets(btf)
        try:
            login = (btf.member('task_struct', 'loginuid'), btf.member('task_struct', 'sessionid'))
        except TraceError:
            login = None                         # A kernel built without audit.
        self.written = written(start, ns, inode, cgroup, login)
        self.ring = Ring(RING_BYTES)
        self.counter = None
        try:
            self.counter = Counter()
            self.fds += attach(exec_program(self.ring.fd, (task['real_parent'], task['tgid'], start), mm, exe,
                                            self.cwd_chain, ns, inode, cgroup, login, self.counter.fd),
                               'megalodon_exec', EXEC_POINT)
            self.fds += attach(fork_program(self.ring.fd, task['pid'], task['tgid'], start, self.counter.fd),
                               'megalodon_fork', FORK_POINT)
        except BaseException:
            self.close()
            raise

    def fileno(self):
        return self.ring.fd

    def wait(self, seconds):
        return self.ring.wait(seconds)

    def dropped(self):
        """How many execs and forks the ring buffer had no room for since the trace started."""
        return self.counter.value()

    def drain(self):
        """[record] since the last call, oldest first: dict(kind='exec', pid, parent, uid, gid, comm, start,
        path, argv, cwd) or dict(kind='fork', pid, parent, start)."""
        out = []
        for data in self.ring.records():
            record = self.parse(data)
            if record is not None:
                out.append(record)
        return out

    def parse(self, data):
        if len(data) < 4:
            return None
        kind, = struct.unpack_from('<I', data, 0)
        if kind == KIND_FORK and len(data) >= FORK_BYTES:
            parent, pid, _tgid, start = struct.unpack_from('<IIIQ', data, FORK_PARENT)
            return dict(kind='fork', pid=pid, parent=parent, start=ticks(start) if start else None)
        if kind != KIND_EXEC or len(data) < EXEC_BYTES:
            return None
        parent, = struct.unpack_from('<I', data, EXEC_PARENT)
        pid_tgid, uid_gid = struct.unpack_from('<QQ', data, EXEC_PID)
        comm = bytes(data[EXEC_COMM:EXEC_COMM + 16]).split(b'\0', 1)[0].decode('utf-8', 'replace')
        start, = struct.unpack_from('<Q', data, EXEC_START)
        length, exe_mount, cwd_mount = struct.unpack_from('<III', data, EXEC_ARGS)
        raw = bytes(data[EXEC_ARGV:EXEC_ARGV + min(length, ARGV_BYTES)])
        argv = [a.decode('utf-8', 'replace') for a in raw.split(b'\0') if a]
        names = names_at(data, EXEC_EXE, LEVELS)
        mount = self.mount(exe_mount)
        path, deleted = _tail(names, mount), False
        if mount is None and names[0].startswith('memfd:'):
            # A program run from memory: /proc shows it as /memfd:NAME (deleted).
            path, deleted = '/' + names[0], True
        cwd = None
        if self.cwd_chain is not None:
            found = _tail(names_at(data, EXEC_CWD, LEVELS), self.mount(cwd_mount))
            cwd = found if found and not found.startswith('…') else None
        written = self.written
        ino, dev, mnt_ns = struct.unpack_from('<QII', data, EXEC_INO)
        ino = ino if written['inode'] else 0
        mnt_ns = mnt_ns if written['ns'] else 0
        start = start if written['start'] else 0
        login_uid, session = struct.unpack_from('<II', data, EXEC_LOGIN) if written['login'] else (UNSET, UNSET)
        groups = [(label, group_path(names_at(data, offset, CG_LEVELS, CG_NAME)))
                  for label, offset, part in (('0:', EXEC_CGROUP_DFL, 'cgroup'), ('memory', EXEC_CGROUP_V1, 'memory'))
                  if written[part]]
        return dict(kind='exec', pid=pid_tgid >> 32, parent=parent, uid=uid_gid & 0xFFFFFFFF, gid=uid_gid >> 32,
                    comm=comm, start=ticks(start) if start else None, path=path, deleted=deleted, argv=argv,
                    argv_cut=length > ARGV_BYTES, argv_bytes=raw, cwd=cwd, mnt_ns=mnt_ns or None,
                    login_uid=None if login_uid == UNSET else login_uid,
                    session=None if session == UNSET else session,
                    exe_file=(os.makedev(dev >> 20, dev & 0xFFFFF), ino) if ino else None,
                    # As /proc/PID/cgroup gives them: what the container watch names containers from.
                    cgroup=''.join(f'{label}:{found}\n' for label, found in groups if found))

    def mount(self, mount_id):
        """(root, mount point) of a mount ID, reading the mount tables again when one is new; None when it is
        neither this process's nor the host's. See :func:`connect_trace.mount_table`: in a service with a mount
        namespace of its own, the host's programs' mounts are not among this process's."""
        if not mount_id:
            return None
        if self.known_mounts is None or mount_id not in self.known_mounts:
            self.known_mounts = mount_table(mount_id)
        return self.known_mounts.get(mount_id)

    def close(self):
        while self.fds:
            os.close(self.fds.pop())
        if self.ring is not None:
            self.ring.close()
            self.ring = None
        if getattr(self, 'counter', None) is not None:
            self.counter.close()
            self.counter = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def info(record):
    """A traced exec as the process description :func:`egress_watch._proc_info` gives, or None when the
    executable's path is unknown."""
    if record.get('kind') != 'exec' or not record.get('path'):
        return None
    return dict(path=record['path'], deleted=record['deleted'], argv=record['argv'], start=record['start'],
                cwd=record['cwd'], traced=dict(parent=record['parent'], uid=record['uid'], comm=record['comm']))
