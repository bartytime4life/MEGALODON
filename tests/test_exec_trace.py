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
    return trace


def names(*parts):
    out = b''
    for part in list(parts) + [''] * (et.LEVELS - len(parts)):
        out += part.encode().ljust(ct.EXE_NAME, b'\0')
    return out


def exec_record(exe=('agent', '.x', 'tmp', '/'), cwd=('.x', 'tmp', '/'), argv=b'/tmp/.x/agent\0-q\0',
                length=None, exe_mount=5, cwd_mount=5, start=1_230_000_000, pid=4321, parent=77, comm=b'agent'):
    head = struct.pack('<II', et.KIND_EXEC, parent) + struct.pack('<QQ', pid << 32 | pid, 1000 << 32 | 1000)
    head += comm.ljust(16, b'\0') + struct.pack('<Q', start)
    head += struct.pack('<IIII', len(argv) if length is None else length, exe_mount, cwd_mount, 0)
    assert len(head) == et.EXEC_EXE
    data = head + names(*exe) + names(*cwd) + argv.ljust(et.ARGV_BYTES, b'\0')[:et.ARGV_BYTES]
    assert len(data) == et.EXEC_BYTES
    return data


def test_an_exec_record():
    hz = os.sysconf('SC_CLK_TCK')
    record = tracer().parse(exec_record())
    assert record == dict(kind='exec', pid=4321, parent=77, uid=1000, gid=1000, comm='agent',
                          start=1_230_000_000 // (10 ** 9 // hz), path='/tmp/.x/agent', deleted=False,
                          argv=['/tmp/.x/agent', '-q'], cwd='/tmp/.x')
    assert tracer().parse(exec_record(exe=('helper', '.x', '/'), exe_mount=6))['path'] == '/dev/shm/.x/helper'


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


def test_a_running_process_is_read_from_proc(home):
    me = os.getpid()
    live = _proc_info(Path('/proc', str(me)))
    w, _, _, _ = watcher(home, [gone_exec('/elsewhere/x', pid=me, start=live['start'])])
    w._traced()
    assert w.cache[me] == live, 'the same process, still running: /proc is read'
    # The same pid with another start time is another process that has gone: the trace's description is kept.
    w.trace.records = [gone_exec('/elsewhere/x', pid=me, start=live['start'] + 1)]
    w._traced()
    assert w.cache[me]['path'] == '/elsewhere/x' and w.cache[me]['traced']['parent'] == 77
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
