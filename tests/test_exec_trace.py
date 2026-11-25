"""Exec tracing: the eBPF programs, reading their records, and the credential watch naming readers that exited
within microseconds. The live tests run only where eBPF raw tracepoints can be loaded (root, BTF, Linux 5.8+)."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import threading
import time

import pytest

from megalodon import connect_trace as ct
from megalodon import credential_watch as cw
from megalodon import exec_trace as et
from megalodon.egress_watch import _proc_info

EXE = (1136, 1320, 72, 40, 24, 64, 276)       # task->mm, mm->exe_file, ... as _exe_offsets gives them


def decode(code):
    return [struct.unpack('<BBhi', code[i:i + 8]) for i in range(0, len(code), 8)]


def jumps_land_inside(insns):
    exit_at = len(insns) - 2
    assert insns[-1][0] == 0x95 and insns[-2][0] == 0xB7 and insns[-2][3] == 0, 'ends by returning 0'
    jumps = [(i, op, off) for i, (op, _, off, _imm) in enumerate(insns) if op in (0x15, 0x55, 0x5D, 0xB5)]
    for i, op, off in jumps:
        assert 0 < i + 1 + off <= exit_at, f'jump at {i} lands outside the program'
    return jumps, exit_at


# ------------------------------------------------------------- the programs

@pytest.mark.parametrize('cwd', [None, (1816, 48, 40)])
@pytest.mark.parametrize('start', [None, 1560])
def test_the_exec_program(cwd, start):
    insns = decode(et.exec_program(9, (1280, 1268, start), (488, 496), EXE, cwd))
    jumps, exit_at = jumps_land_inside(insns)
    reserve, = [i for i, (op, *_) in enumerate(insns) if op == 0x18]
    assert insns[reserve][3] == 9, 'the ring buffer map is the one created'
    assert reserve == 0
    failed = jumps[0]
    assert failed[1] == 0x15 and failed[0] + 1 + failed[2] == exit_at, 'a failed reserve goes to the return'
    helpers = [imm for op, _, _, imm in insns if op == 0x85]
    assert helpers[0] == ct.RINGBUF_RESERVE and helpers[-1] == ct.RINGBUF_SUBMIT
    assert helpers.count(ct.PROBE_READ_KERNEL_STR) == et.LEVELS * (2 if cwd else 1)
    assert helpers.count(ct.PROBE_READ_USER) == 1
    # The command line's length is bounded before it is read: if r2 <= ARGV_BYTES skip, else r2 = ARGV_BYTES.
    bound = next(i for i, (op, *_) in enumerate(insns) if op == 0xB5)
    assert insns[bound][1] & 0xF == 2 and insns[bound][3] == et.ARGV_BYTES and insns[bound][2] == 1
    assert insns[bound + 1] == (0xB7, 2, 0, et.ARGV_BYTES)
    user_read = next(i for i in range(bound, len(insns)) if insns[i][0] == 0x85)
    assert insns[user_read][3] == ct.PROBE_READ_USER
    assert insns[reserve + 2] == (0xB7, 2, 0, et.EXEC_BYTES)
    # The start time is read only where the kernel has it.
    reads_start = any(op == 0x07 and imm == 1560 for op, _, _, imm in insns)
    assert reads_start == (start is not None)


@pytest.mark.parametrize('memory', [None, 4 * 8])
def test_the_exec_program_reads_the_namespace_inode_and_control_groups(memory):
    plain = decode(et.exec_program(9, (1280, 1268, 1560), (488, 496), EXE, (1816, 48, 40)))
    full = decode(et.exec_program(9, (1280, 1268, 1560), (488, 496), EXE, (1816, 48, 40), ns=(1840, 24, 24),
                                  inode=(32, 64, 40, 16), cgroup=(2376, 112, memory, 0, 256, 16, 8)))
    jumps_land_inside(full)
    strings = [imm for op, _, _, imm in full if op == 0x85].count(ct.PROBE_READ_KERNEL_STR)
    assert strings == 2 * et.LEVELS + et.CG_LEVELS * (2 if memory is not None else 1)
    # Each part is written where the record has it, at its size.
    sizes = {(insn[3], full[i + 1][3]) for i, insn in enumerate(full[:-1]) if insn[0] == 0x07 and insn[1] == 1}
    assert (et.EXEC_MNTNS, 4) in sizes and (et.EXEC_INO, 8) in sizes and (et.EXEC_DEV, 4) in sizes
    assert (et.EXEC_CGROUP_DFL, et.CG_NAME) in sizes
    assert ((et.EXEC_CGROUP_V1, et.CG_NAME) in sizes) == (memory is not None)
    assert len(full) > len(plain)


@pytest.mark.parametrize('program', ['exec', 'fork'])
def test_a_full_ring_buffer_is_counted(program):
    def build(counter):
        if program == 'exec':
            return et.exec_program(9, (1280, 1268, 1560), (488, 496), EXE, None, login=(1952, 1956),
                                   counter_fd=counter)
        return et.fork_program(9, 1264, 1268, 1560, counter_fd=counter)
    plain, counted = decode(build(None)), decode(build(13))
    assert not any(op == 0xDB for op, *_ in plain)
    jumps, exit_at = jumps_land_inside(counted)
    maps = [i for i, (op, _, _, imm) in enumerate(counted) if op == 0x18]
    assert [counted[i][3] for i in maps] == [9, 13], 'the ring buffer, then the counter'
    reserve_failed = next(j for j in jumps if j[1] == 0x15 and j[0] > maps[0])
    # A failed reserve goes to the counting, which adds one to the counter's value and then returns.
    count_at = reserve_failed[0] + 1 + reserve_failed[2]
    assert counted[count_at] == (0x62, 10, -4, 0), 'the key, 0, on the stack'
    assert count_at < maps[1] < len(counted) - 2
    assert [imm for op, _, _, imm in counted[maps[1]:] if op == 0x85] == [ct.MAP_LOOKUP_ELEM]
    xadd = next(i for i, (op, *_) in enumerate(counted) if op == 0xDB)
    assert counted[xadd] == (0xDB, 0 | (1 << 4), 0, 0) and counted[xadd - 1] == (0xB7, 1, 0, 1)
    found_null = next(j for j in jumps if j[0] > maps[1])
    assert found_null[0] + 1 + found_null[2] == exit_at, 'no value: nothing to add'
    # A record that is reserved is submitted and returns before the counting.
    submit = max(i for i, (op, _, _, imm) in enumerate(counted) if op == 0x85 and imm == ct.RINGBUF_SUBMIT)
    assert counted[submit + 1:submit + 3] == [(0xB7, 0, 0, 0), (0x95, 0, 0, 0)] and submit < count_at


def test_the_fork_program_skips_new_threads():
    insns = decode(et.fork_program(9, 1264, 1268, 1560))
    jumps, exit_at = jumps_land_inside(insns)
    assert insns[0] == (0xBF, 6 | (1 << 4), 0, 0), 'the context is kept in r6'
    assert (0x79, 7 | (6 << 4), 8, 0) in insns, 'the child is the second argument'
    differ, = [j for j in jumps if j[1] == 0x5D]
    assert differ[0] + 1 + differ[2] == exit_at, 'a thread (pid != tgid) is skipped'
    # The two stack slots compared are zeroed first, so a failed read cannot compare garbage.
    first_read = next(i for i, (op, *_) in enumerate(insns) if op == 0x85)
    assert {(0x7B, 10 | (1 << 4), -8, 0), (0x7B, 10 | (1 << 4), -16, 0)} <= set(insns[:first_read])
    reserve, = [i for i, (op, *_) in enumerate(insns) if op == 0x18]
    assert reserve > differ[0] and insns[reserve + 2] == (0xB7, 2, 0, et.FORK_BYTES)
    helpers = [imm for op, _, _, imm in insns if op == 0x85]
    assert helpers[-1] == ct.RINGBUF_SUBMIT


# ------------------------------------------------------------- reading the records

def tracer(mounts=None, cwd=True):
    trace = object.__new__(et.ExecTrace)
    trace.cwd_chain = (1, 2, 3) if cwd else None
    trace.known_mounts = mounts if mounts is not None else {5: ('/', '/'), 6: ('/', '/dev/shm')}
    trace.fds, trace.ring = [], None
    trace.written = dict(start=True, ns=True, inode=True, cgroup=True, memory=True, login=True)
    return trace


def names(*parts):
    out = b''
    for part in list(parts) + [''] * (et.LEVELS - len(parts)):
        out += part.encode().ljust(ct.EXE_NAME, b'\0')
    return out


def group_names(*parts):
    out = b''
    for part in list(parts) + [''] * (et.CG_LEVELS - len(parts)):
        out += part.encode().ljust(et.CG_NAME, b'\0')
    return out


def exec_record(exe=('agent', '.x', 'tmp', '/'), cwd=('.x', 'tmp', '/'), argv=b'/tmp/.x/agent\0-q\0',
                length=None, exe_mount=5, cwd_mount=5, start=1_230_000_000, pid=4321, parent=77, comm=b'agent',
                ino=0, dev=0, mnt_ns=0, unified=(), memory=(), login=(et.UNSET, et.UNSET)):
    head = struct.pack('<II', et.KIND_EXEC, parent) + struct.pack('<QQ', pid << 32 | pid, 1000 << 32 | 1000)
    head += comm.ljust(16, b'\0') + struct.pack('<Q', start)
    head += struct.pack('<IIII', len(argv) if length is None else length, exe_mount, cwd_mount, 0)
    assert len(head) == et.EXEC_EXE
    data = head + names(*exe) + names(*cwd) + argv.ljust(et.ARGV_BYTES, b'\0')[:et.ARGV_BYTES]
    data += struct.pack('<QII', ino, dev, mnt_ns) + group_names(*unified) + group_names(*memory)
    data += struct.pack('<II', *login)
    assert len(data) == et.EXEC_BYTES
    return data


def test_an_exec_record():
    hz = os.sysconf('SC_CLK_TCK')
    record = tracer().parse(exec_record())
    assert record == dict(kind='exec', pid=4321, parent=77, uid=1000, gid=1000, comm='agent',
                          start=1_230_000_000 // (10 ** 9 // hz), path='/tmp/.x/agent', deleted=False,
                          argv=['/tmp/.x/agent', '-q'], argv_cut=False, cwd='/tmp/.x', mnt_ns=None,
                          login_uid=None, session=None, exe_file=None, cgroup='')
    assert tracer().parse(exec_record(exe=('helper', '.x', '/'), exe_mount=6))['path'] == '/dev/shm/.x/helper'


def test_the_namespace_inode_and_control_groups_of_an_exec():
    # The kernel's device number is major << 20 | minor; stat() gives it encoded for user space.
    kernel_dev = 259 << 20 | 3
    record = tracer().parse(exec_record(ino=4242, dev=kernel_dev, mnt_ns=4026531840,
                                        unified=('docker-' + 'a' * 64 + '.scope', 'system.slice', ''),
                                        memory=('c1', 'lxc.payload.web', '')))
    assert record['mnt_ns'] == 4026531840
    assert record['exe_file'] == (os.makedev(259, 3), 4242)
    assert record['cgroup'] == f"0::/system.slice/docker-{'a' * 64}.scope\nmemory:/lxc.payload.web/c1\n"
    # Names that ran out before the hierarchy's root: the path is partial; none read: left out.
    deep = tracer().parse(exec_record(unified=tuple(f'g{i}' for i in range(et.CG_LEVELS))))
    assert deep['cgroup'] == '0::…/' + '/'.join(f'g{i}' for i in reversed(range(et.CG_LEVELS))) + '\n'


def test_which_parts_the_program_writes():
    group = (2376, 112, 32, 0, 256, 16, 8)
    assert et.written(1560, (1, 2, 3), (1, 2, 3, 4), group) == dict(start=True, ns=True, inode=True, cgroup=True,
                                                                     memory=True, login=False)
    # A kernel without the memory controller: its group is not written.
    assert et.written(1560, (1, 2, 3), (1, 2, 3, 4), group[:2] + (None,) + group[3:])['memory'] is False
    assert et.written(None, None, None, None) == dict(start=False, ns=False, inode=False, cgroup=False,
                                                      memory=False, login=False)
    assert et.written(None, None, None, None, (1952, 1956))['login'] is True


def test_the_login_and_a_cut_command_line():
    record = tracer().parse(exec_record(login=(1000, 42)))
    assert (record['login_uid'], record['session']) == (1000, 42)
    long = b'x' * (et.ARGV_BYTES + 1)
    assert tracer().parse(exec_record(argv=long, length=len(long)))['argv_cut'] is True
    assert tracer().parse(exec_record())['argv_cut'] is False


@pytest.mark.parametrize('missing', ['start', 'ns', 'inode', 'cgroup', 'memory', 'login'])
def test_parts_the_program_does_not_write_are_not_read(missing):
    # Reserved ring buffer space is not cleared: a part the loaded program does not write holds bytes of earlier
    # records, here a container's group name, and must not be read as this exec's.
    trace = tracer()
    trace.written = dict(trace.written, **{missing: False})
    record = trace.parse(exec_record(ino=4242, dev=1, mnt_ns=4026531840, login=(1000, 3),
                                     unified=('docker-' + 'a' * 64 + '.scope', ''),
                                     memory=('docker-' + 'b' * 64 + '.scope', '')))
    unwritten = dict(start=record['start'], ns=record['mnt_ns'], inode=record['exe_file'],
                     cgroup='a' * 64 in record['cgroup'] or None, memory='b' * 64 in record['cgroup'] or None,
                     login=record['login_uid'])
    assert unwritten[missing] is None
    assert all(value is not None for part, value in unwritten.items() if part != missing)


@pytest.mark.parametrize('parts, path', [(('b', 'a', ''), '/a/b'), (('b', 'a'), '…/a/b'), (('',), None),
                                         ((), None)])
def test_a_control_group_path(parts, path):
    assert et.group_path(list(parts)) == path


def test_the_command_line_stops_at_its_length():
    # What follows the command line in the program's memory (its environment) is not taken as arguments.
    data = exec_record(argv=b'/bin/sh\0-c\0SECRET=1\0', length=len(b'/bin/sh\0-c\0'))
    assert tracer().parse(data)['argv'] == ['/bin/sh', '-c']
    long = b'x' * (et.ARGV_BYTES + 10)
    assert tracer().parse(exec_record(argv=long, length=len(long)))['argv'] == ['x' * et.ARGV_BYTES]


def test_paths_that_are_not_complete():
    # A working folder not fully named, or on a mount not ours, is unknown rather than partial.
    assert tracer().parse(exec_record(cwd=('a',) * et.LEVELS))['cwd'] is None
    assert tracer().parse(exec_record(cwd_mount=999_999))['cwd'] is None
    assert tracer(cwd=False).parse(exec_record())['cwd'] is None
    # An executable on an unknown mount is kept as a partial path.
    assert tracer().parse(exec_record(exe_mount=999_999))['path'] == '…/tmp/.x/agent'
    # A name that fills the kernel's buffer may have been cut short.
    assert tracer().parse(exec_record(exe=('a' * 63, '.x', 'tmp', '/')))['path'].startswith('…/')


def test_a_program_run_from_memory():
    record = tracer().parse(exec_record(exe=('memfd:payload',) * et.LEVELS, exe_mount=999_999))
    assert record['path'] == '/memfd:payload' and record['deleted'] is True
    # A file of that name on a mount we know is a file.
    record = tracer().parse(exec_record(exe=('memfd:payload', 'tmp', '/')))
    assert record['path'] == '/tmp/memfd:payload' and record['deleted'] is False


def test_fork_and_unknown_records():
    hz = os.sysconf('SC_CLK_TCK')
    data = struct.pack('<IIIIQ', et.KIND_FORK, 50, 51, 51, 2_000_000_000)
    assert tracer().parse(data) == dict(kind='fork', pid=51, parent=50, start=2_000_000_000 // (10 ** 9 // hz))
    assert tracer().parse(data[:12]) is None
    assert tracer().parse(exec_record()[:-1]) is None
    assert tracer().parse(struct.pack('<I', 9) + bytes(et.EXEC_BYTES)) is None
    assert tracer().parse(b'') is None


def test_a_traced_exec_as_a_process():
    record = tracer().parse(exec_record())
    assert et.info(record) == dict(path='/tmp/.x/agent', deleted=False, argv=['/tmp/.x/agent', '-q'],
                                   start=record['start'], cwd='/tmp/.x',
                                   traced=dict(parent=77, uid=1000, comm='agent'))
    assert et.info(dict(kind='fork', pid=1, parent=2, start=3)) is None
    assert et.info(dict(record, path=None)) is None


# ------------------------------------------------------------- the credential watch

class FakeSource:
    mode = 'file-access notifications'

    def __init__(self, opens=()):
        self.opens, self.read_called = list(opens), False
        self.r, self.w = os.pipe()
        if self.opens:
            os.write(self.w, b'x')

    def fileno(self):
        return self.r

    def read(self):
        self.read_called = True
        out, self.opens = self.opens, []
        return out

    def close(self):
        os.close(self.r)
        os.close(self.w)


class FakeTrace:
    def __init__(self, records=(), source=None):
        self.records, self.source, self.closed = list(records), source, False
        self.r, self.w = os.pipe()

    def fileno(self):
        return self.r

    def drain(self):
        # As in the kernel: an exec is in the ring before the program's opens can be read.
        if self.source is not None and not self.source.read_called:
            return []
        out, self.records = self.records, []
        return out

    def close(self):
        self.closed = True
        os.close(self.r)
        os.close(self.w)


@pytest.fixture
def home(tmp_path):
    base = tmp_path / 'home'
    (base / '.ssh').mkdir(parents=True)
    (base / '.ssh/id_ed25519').write_text('placeholder key\n')
    (base / '.aws').mkdir()
    (base / '.aws/credentials').write_text('[default]\n')
    return base


GONE = 4_000_000      # A pid with no process


def gone_exec(path='/tmp/.x/agent', pid=GONE, start=555, argv=None, cwd='/tmp/.x', parent=77):
    return dict(kind='exec', pid=pid, parent=parent, uid=1000, gid=1000, comm=os.path.basename(path),
                start=start, path=path, deleted=False, argv=argv or [path], cwd=cwd)


def watcher(home, records=(), opens=()):
    source = FakeSource(opens)
    found = []
    trace = FakeTrace(records, source if opens else None)
    w = cw.Watcher(found.append, home_dirs=[str(home)], allow_path=None, source=source, trace=trace)
    return w, found, source, trace


def test_a_reader_gone_at_once_is_named_from_the_trace(home):
    key = str(home / '.ssh/id_ed25519')
    w, found, source, trace = watcher(home, [gone_exec()], [(GONE, key)])
    assert w.processes is None, 'the trace replaces the process events'
    stop = threading.Event()
    worker = threading.Thread(target=w.run, args=(stop,), kwargs=dict(timeout=0.05))
    worker.start()
    time.sleep(0.3)
    stop.set()
    worker.join(5)
    w.close()
    assert trace.closed
    assert [(f['rule_id'], f['program']) for f in found] == [('CREDENTIAL_READ_BY_DROPPED_TOOL', '/tmp/.x/agent')]
    assert found[0]['evidence']['traced'] == dict(parent=77, uid=1000, comm='agent')
    assert found[0]['evidence']['processes'] == [dict(program='/tmp/.x/agent', pid=GONE, start=555)]
    assert w.stats['named_after_exit'] == 1 and w.stats['unattributed'] == 0


def test_a_script_is_named_with_the_traced_working_folder(home):
    # `python3 steal.py` run from a temporary folder: the script is found through the traced working folder.
    w, found, _, _ = watcher(home, [gone_exec('/usr/bin/python3', argv=['python3', 'steal.py'], cwd='/tmp/.x')])
    w._traced()
    w.handle(GONE, str(home / '.ssh/id_ed25519'))
    w.close()
    assert [(f['rule_id'], f['program']) for f in found] == [
        ('CREDENTIAL_READ_BY_DROPPED_TOOL', '/usr/bin/python3 /tmp/.x/steal.py')]


def test_the_kernel_record_is_the_identity(home, monkeypatch):
    me = os.getpid()
    live = _proc_info(Path('/proc', str(me)))
    same = dict(kind='exec', pid=me, parent=77, uid=0, gid=0, comm='python', start=live['start'],
                path=live['path'], deleted=False, argv=live['argv'], cwd='/at/exec')
    proc = dict(live, deleted=True, cwd='/usr/bin')
    monkeypatch.setattr(cw, '_proc_info', lambda path: proc if path.name == str(me) else None)
    w, _, _, _ = watcher(home, [same])
    w._traced()
    # As the kernel saw it at exec; /proc adds only that the same file was deleted since.
    assert (w.cache[me]['path'], w.cache[me]['argv'], w.cache[me]['cwd']) == (live['path'], live['argv'], '/at/exec')
    assert w.cache[me]['deleted'] is True
    # /proc does not complete what the kernel saw in part: it may show a program run since.
    w.trace.records = [dict(same, path='…/' + os.path.basename(live['path']), cwd=None)]
    w._traced()
    assert w.cache[me]['path'] == '…/' + os.path.basename(live['path']) and w.cache[me]['cwd'] is None
    # Another file, or another process with this ID (another start time): nothing is taken from /proc.
    for other in (dict(same, path='/tmp/.x/agent'), dict(same, start=live['start'] + 1)):
        w.trace.records = [other]
        w._traced()
        assert (w.cache[me]['path'], w.cache[me]['deleted']) == (other['path'], False)
    # No path from the kernel: /proc, unless the process runs another program later in this batch.
    w.trace.records = [dict(same, path=None)]
    w._traced()
    assert w.cache.pop(me) == proc
    w.trace.records = [dict(same, path=None), dict(same, path='/tmp/.x/agent')]
    seen = []
    keep = w._keep
    monkeypatch.setattr(w, '_keep', lambda pid, info: (seen.append(info['path']), keep(pid, info)))
    w._traced()
    assert seen == ['/tmp/.x/agent']
    w.close()


def test_a_reader_forked_before_its_parent_runs_an_expected_reader_is_still_named(home, monkeypatch):
    # /tmp/.x/reader forks a reader, then runs curl (an expected reader of cloud tokens) before the trace is
    # read: /proc shows curl for the parent, with the same start time. The child is the reader's.
    parent, child = GONE, GONE + 1
    curl = dict(path='/usr/bin/curl', deleted=False, argv=['curl', 'http://127.0.0.1/'], start=555, cwd='/')
    monkeypatch.setattr(cw, '_proc_info', lambda proc: curl if proc.name == str(parent) else None)
    w, found, _, _ = watcher(home, [gone_exec('/tmp/.x/reader', pid=parent, start=555),
                                    dict(kind='fork', pid=child, parent=parent, start=556),
                                    gone_exec('/usr/bin/curl', pid=parent, start=555,
                                              argv=['curl', 'http://127.0.0.1/'], cwd='/')])
    w._traced()
    w.handle(child, str(home / '.aws/credentials'))
    w.close()
    assert [(f['rule_id'], f['program']) for f in found] == [('CREDENTIAL_READ_BY_DROPPED_TOOL', '/tmp/.x/reader')]


def test_a_parent_from_before_the_trace_that_runs_another_program_is_not_read(home, monkeypatch):
    # Its program at the fork is unknown: /proc shows the one it ran later in the batch.
    old = 3_999_000
    monkeypatch.setattr(cw, '_proc_info', lambda proc: dict(path='/usr/bin/curl', deleted=False, argv=['curl'],
                                                            start=1, cwd='/') if proc.name == str(old) else None)
    w, _, _, _ = watcher(home, [dict(kind='fork', pid=GONE, parent=old, start=2),
                                gone_exec('/usr/bin/curl', pid=old, start=1, argv=['curl'], cwd='/')])
    w._traced()
    assert GONE not in w.cache
    w.close()


def test_a_forked_reader_is_named_as_its_parent(home):
    w, found, _, _ = watcher(home, [gone_exec(pid=GONE, start=555),
                                    dict(kind='fork', pid=GONE + 1, parent=GONE, start=556),
                                    dict(kind='fork', pid=GONE + 2, parent=GONE + 3, start=557)])
    w._traced()
    child = w.cache[GONE + 1]
    assert child['path'] == '/tmp/.x/agent' and child['start'] == 556
    assert child['traced'] == dict(parent=GONE, forked=True)
    assert GONE + 2 not in w.cache, 'a fork of an unknown process that is gone is not named'
    w.handle(GONE + 1, str(home / '.ssh/id_ed25519'))
    assert [f['program'] for f in found] == ['/tmp/.x/agent']
    # A parent that started before the watch is read from /proc, and remembered.
    me = os.getpid()
    w.trace.records = [dict(kind='fork', pid=GONE + 4, parent=me, start=600)]
    w._traced()
    assert w.cache[GONE + 4]['path'] == _proc_info(Path('/proc', str(me)))['path'] and me in w.cache
    w.close()


def test_the_trace_is_read_after_the_opens(home):
    # The trace is read once the opens are, so an exec whose open is in this batch is already known.
    key = str(home / '.ssh/id_ed25519')
    w, found, source, trace = watcher(home, [gone_exec()], [(GONE, key)])
    stop = threading.Event()
    worker = threading.Thread(target=w.run, args=(stop,), kwargs=dict(timeout=0.05))
    worker.start()
    time.sleep(0.3)
    stop.set()
    worker.join(5)
    w.close()
    assert len(found) == 1 and w.stats['unattributed'] == 0


def test_the_watch_wakes_for_the_trace_alone(home):
    # With no opens, the trace is still read as records arrive, so a burst of starts does not fill it.
    w, _, _, trace = watcher(home, [gone_exec()])
    os.write(trace.w, b'x')
    stop = threading.Event()
    worker = threading.Thread(target=w.run, args=(stop,), kwargs=dict(timeout=30), daemon=True)
    worker.start()
    try:
        deadline = time.monotonic() + 3
        while GONE not in w.cache and time.monotonic() < deadline:
            time.sleep(0.02)
        assert GONE in w.cache
    finally:
        stop.set()
        os.write(w.source.w, b'x')        # wake it to stop
        worker.join(5)
        w.close()


def test_without_fanotify_the_trace_is_not_used(home):
    class Inotify(FakeSource):
        mode = 'inotify (no process names)'
    source = Inotify()
    trace = FakeTrace()
    w = cw.Watcher(lambda f: None, home_dirs=[str(home)], allow_path=None, source=source, trace=trace)
    assert w.trace is None and trace.closed
    w.close()


def test_the_command_line_falls_back_when_tracing_is_unavailable(tmp_path, monkeypatch, capsys):
    def refuse(*a, **k):
        raise ct.TraceError(1, 'the kernel refused the program')
    monkeypatch.setattr(et, 'ExecTrace', refuse)
    ran = {}

    class Stopper(cw.Watcher):
        def __init__(self, emit, **kw):
            ran['trace'] = kw.get('trace')
            super().__init__(emit, source=FakeSource(), **kw)

        def run(self, stop):
            pass
    monkeypatch.setattr(cw, 'Watcher', Stopper)
    from megalodon.cli import main
    with pytest.raises(SystemExit) as exit_:
        main(['credentials', 'watch', '--allow-file', str(tmp_path / 'allow.json'), '--trace-execs'])
    assert exit_.value.code == 0 and ran['trace'] is None
    assert 'exec tracing unavailable: the kernel refused the program' in capsys.readouterr().err


# ------------------------------------------------------------- live, where eBPF can be loaded

def loaded():
    try:
        return et.ExecTrace()
    except (ct.TraceError, OSError) as exc:
        pytest.skip(f'exec tracing cannot be loaded here: {exc}')


def test_live_execs_and_forks_are_described_as_proc_does(tmp_path):
    trace = loaded()
    try:
        folder = tmp_path / '.x'
        folder.mkdir()
        tool = folder / 'sleeper'
        shutil.copy(shutil.which('sleep'), tool)
        child = subprocess.Popen([str(tool), '2'], cwd=folder)
        try:
            time.sleep(0.3)
            live = _proc_info(Path('/proc', str(child.pid)))
            login = [int(Path('/proc', str(child.pid), name).read_text()) for name in ('loginuid', 'sessionid')]
            forked = os.fork()
            if forked == 0:
                os._exit(0)
            os.waitpid(forked, 0)
            spawned = threading.Thread(target=lambda: None)
            spawned.start()
            spawned.join()
            time.sleep(0.1)
            records = trace.drain()
        finally:
            child.kill()
            child.wait()
    finally:
        trace.close()
    execs = [r for r in records if r['kind'] == 'exec' and r['pid'] == child.pid]
    assert len(execs) == 1
    traced = et.info(execs[0])
    assert (traced['path'], traced['argv'], traced['start'], traced['cwd']) == (
        live['path'], live['argv'], live['start'], live['cwd'])
    assert execs[0]['parent'] == os.getpid() and execs[0]['comm'] == 'sleeper'
    assert [execs[0]['login_uid'], execs[0]['session']] == [None if n == et.UNSET else n for n in login]
    forks = [r for r in records if r['kind'] == 'fork' and r['parent'] == os.getpid()]
    assert forked in {r['pid'] for r in forks}
    assert all(r['pid'] != threading.get_native_id() for r in forks)
    assert len(forks) == 2, 'the subprocess and the fork, not the thread'


def test_live_readers_that_exit_at_once_are_named(home, tmp_path):
    trace = loaded()
    found = []
    w = cw.Watcher(found.append, home_dirs=[str(home)], allow_path=None, trace=trace)
    if w.trace is None:
        w.close()
        pytest.skip('no file-access notifications here')
    folder = tmp_path / '.x'
    folder.mkdir()
    tool = folder / 'helper'
    shutil.copy(shutil.which('head'), tool)
    stop = threading.Event()
    worker = threading.Thread(target=w.run, args=(stop,), kwargs=dict(timeout=0.05), daemon=True)
    worker.start()
    try:
        time.sleep(0.3)
        key = str(home / '.ssh/id_ed25519')
        children = [subprocess.Popen([str(tool), '-c', '1', key], stdout=subprocess.DEVNULL) for _ in range(50)]
        for child in children:
            child.wait()
        time.sleep(0.5)
    finally:
        stop.set()
        worker.join(5)
        w.close()
    assert w.stats['opens'] == 50 and w.stats['unattributed'] == 0, w.stats
    assert ('CREDENTIAL_READ_BY_DROPPED_TOOL', str(tool)) in {(f['rule_id'], f['program']) for f in found}


def test_live_a_program_run_from_memory_is_named_as_proc_names_it():
    trace = loaded()
    try:
        fd = os.memfd_create('payload', 0)
        with open(shutil.which('sleep'), 'rb') as stream:
            os.write(fd, stream.read())
        child = subprocess.Popen([f'/proc/self/fd/{fd}', '1'], pass_fds=(fd,))
        try:
            time.sleep(0.3)
            shown = os.readlink(f'/proc/{child.pid}/exe')
            records = trace.drain()
        finally:
            child.kill()
            child.wait()
            os.close(fd)
    finally:
        trace.close()
    traced = et.info(next(r for r in records if r['kind'] == 'exec' and r['pid'] == child.pid))
    assert shown == '/memfd:payload (deleted)'
    assert (traced['path'], traced['deleted']) == ('/memfd:payload', True)
