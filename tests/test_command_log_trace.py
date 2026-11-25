"""The command log from the exec trace: each program as the kernel recorded it starting, so one gone at once keeps
its arguments and folder, and records the ring buffer had no room for are logged as lost. The live tests run only
where eBPF raw tracepoints can be loaded (root, BTF, Linux 5.8+)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time

import pytest

from megalodon import command_log as cl
from megalodon.egress_watch import _proc_info

GONE = 4_000_000


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        self.now += timedelta(seconds=1)
        return self.now


def traced(pid=GONE, path='/usr/bin/curl', argv=None, start=555, cut=False, cwd='/srv', login_uid=1000, session=7):
    return dict(kind='exec', pid=pid, parent=77, uid=0, gid=0, comm=os.path.basename(path), start=start, path=path,
                deleted=False, argv=argv or [path, '-s', 'http://example.invalid/'], argv_cut=cut, cwd=cwd,
                login_uid=login_uid, session=session)


BASE = Path('/proc')


def test_a_program_gone_at_once_is_recorded_from_the_kernels_record():
    entry = cl.describe_traced(BASE, traced())
    assert entry == dict(pid=GONE, ppid=77, uid=0, program='/usr/bin/curl',
                         argv=['/usr/bin/curl', '-s', 'http://example.invalid/'], cwd='/srv', login_uid=1000,
                         session=7, tty=None, start=555, exited=True)


def test_a_running_process_adds_its_terminal_and_only_that():
    me = os.getpid()
    live = _proc_info(BASE / str(me))
    record = traced(pid=me, path=live['path'], argv=live['argv'][:2], start=live['start'], cwd='/at/exec')
    entry = cl.describe_traced(BASE, record)
    assert 'exited' not in entry
    assert entry['argv'] == live['argv'][:2] and entry['cwd'] == '/at/exec', 'the kernel record, not /proc'
    # Another start time, or another program: not this process.
    for other in (dict(record, start=live['start'] + 1), dict(record, path='/usr/bin/other')):
        assert cl.describe_traced(BASE, other)['exited'] is True


def test_a_long_command_line_is_completed_only_from_the_same_one():
    me = os.getpid()
    live = _proc_info(BASE / str(me))
    full = live['argv']
    joined = '\0'.join(full)
    # The trace read the first part, cut inside an argument.
    head = joined[:max(1, len(joined) // 2)].split('\0')
    record = traced(pid=me, path=live['path'], argv=head, start=live['start'], cut=True)
    assert cl.describe_traced(BASE, record)['argv'] == cl._kept(full)
    # A different start of the command line: the kernel's part is kept, marked cut.
    other = dict(record, argv=['something', 'else'])
    assert cl.describe_traced(BASE, other)['argv'] == ['something', 'else', '[cut]']
    # Gone: kept as read, marked cut.
    assert cl.describe_traced(BASE, dict(record, pid=GONE))['argv'] == head + ['[cut]']


def test_secrets_are_blanked_in_the_kernels_record_too():
    secret = 'Hunter' + '2pass'
    entry = cl.describe_traced(BASE, traced(path='/usr/bin/mysql', argv=['mysql', '-uroot', '-p' + secret, 'db']))
    assert secret not in str(entry) and entry['hidden'] == 1
    kept = cl.describe_traced(BASE, traced(path='/usr/bin/mysql', argv=['mysql', '-p' + secret]), redact=False)
    assert kept['argv'] == ['mysql', '-p' + secret]


class Trace:
    def __init__(self, stop, batches, dropped):
        self.stop, self.batches, self.drops, self.closed = stop, list(batches), list(dropped), False

    def wait(self, seconds):
        return True

    def drain(self):
        if not self.batches:
            self.stop.set()
            return []
        return self.batches.pop(0)

    def dropped(self):
        return self.drops.pop(0) if len(self.drops) > 1 else self.drops[0]

    def close(self):
        self.closed = True


def test_recording_from_the_trace_and_its_lost_records(tmp_path):
    paths = dict(state=tmp_path / 'state.json', log=tmp_path / 'commands.jsonl')
    key = cl.init(**paths)['key']
    stop = threading.Event()
    trace = Trace(stop, [[traced(pid=GONE), dict(kind='fork', pid=5, parent=6, start=7)],
                         [traced(pid=GONE + 1, path='/usr/bin/id', argv=['id'])], []], [0, 3, 3, 5])
    assert cl.record(stop, trace=trace, clock=Clock(), **paths) == 2
    assert trace.closed
    lines = list(cl.entries(paths['log']))
    assert [(e['kind'], e.get('program'), e.get('dropped')) for e in lines] == [
        ('start', None, None), ('exec', '/usr/bin/curl', None), ('exec', '/usr/bin/id', None),
        ('lost', None, 3), ('lost', None, 2), ('stop', None, None)]
    assert lines[0]['mode'] == 'exec trace' and lines[1]['argv'] == ['/usr/bin/curl', '-s', 'http://example.invalid/']
    report = cl.verify(key, log=paths['log'])
    assert [(f['rule_id'], f['subject']) for f in report['findings']] == [
        ('COMMAND_LOG_EVENTS_LOST', 'line:4'), ('COMMAND_LOG_EVENTS_LOST', 'line:5')]
    assert '(3 execs and forks)' in report['findings'][0]['detail']
    shown = cl.show(log=paths['log'])
    assert [row['command'] for row in shown] == ['/usr/bin/curl -s http://example.invalid/', 'id']


def test_the_command_line_falls_back_when_tracing_is_unavailable(tmp_path, monkeypatch, capsys):
    from megalodon import exec_trace
    from megalodon.cli import main
    from megalodon.connect_trace import TraceError

    def refuse():
        raise TraceError(1, 'the kernel refused the program')
    monkeypatch.setattr(exec_trace, 'ExecTrace', refuse)
    seen = {}

    def record(stop, **kw):
        seen.update(kw)
        return 0
    monkeypatch.setattr(cl, 'record', record)
    with pytest.raises(SystemExit) as exit_:
        main(['commands', 'record', '--log', str(tmp_path / 'c.jsonl'), '--state', str(tmp_path / 's.json'),
              '--trace-execs'])
    assert exit_.value.code == 0 and seen['trace'] is None
    assert 'exec tracing unavailable: the kernel refused the program' in capsys.readouterr().err


# ------------------------------------------------------------- live, where eBPF can be loaded

def loaded():
    from megalodon.connect_trace import TraceError
    from megalodon.exec_trace import ExecTrace
    try:
        return ExecTrace()
    except (TraceError, OSError) as exc:
        pytest.skip(f'exec tracing cannot be loaded here: {exc}')


def test_live_programs_gone_at_once_keep_their_arguments(tmp_path):
    trace = loaded()
    paths = dict(state=tmp_path / 'state.json', log=tmp_path / 'commands.jsonl')
    key = cl.init(**paths)['key']
    stop = threading.Event()
    worker = threading.Thread(target=cl.record, args=(stop,), kwargs=dict(trace=trace, **paths), daemon=True)
    worker.start()
    tool = tmp_path / 'tool'
    shutil.copy(shutil.which('true'), tool)
    marker = f'marker-{os.getpid()}'
    try:
        time.sleep(0.5)
        for number in range(100):
            os.posix_spawn(str(tool), [str(tool), marker, str(number)], {})
        for _ in range(100):
            os.wait()
        time.sleep(1.5)
    finally:
        stop.set()
        worker.join(10)
    recorded = [e for e in cl.entries(paths['log']) if e.get('kind') == 'exec' and marker in (e.get('argv') or [])]
    assert sorted(int(e['argv'][2]) for e in recorded) == list(range(100))
    assert all(e['program'] == str(tool) and e['cwd'] == os.getcwd() for e in recorded)
    assert cl.verify(key, log=paths['log'])['findings'] == []


def test_live_records_the_ring_buffer_had_no_room_for_are_counted():
    trace = loaded()
    try:
        assert trace.dropped() == 0
        children = [subprocess.Popen(['true']) for _ in range(3500)]     # not read meanwhile: the buffer fills
        for child in children:
            child.wait()
        dropped = trace.dropped()
        pids = {child.pid for child in children}
        read = [r for r in trace.drain() if r['pid'] in pids]
    finally:
        trace.close()
    # Each child's fork and exec was either read or counted as dropped.
    execs = sum(1 for r in read if r['kind'] == 'exec')
    forks = sum(1 for r in read if r['kind'] == 'fork')
    assert dropped > 0 and dropped >= (3500 - execs) + (3500 - forks)


def test_a_running_process_adds_its_terminal():
    import pty
    leader, follower = pty.openpty()
    name = os.ttyname(follower)

    def take_terminal():                         # a new session's leader opening a terminal makes it its own
        os.close(os.open(name, os.O_RDWR))
    child = subprocess.Popen(['sleep', '2'], start_new_session=True, preexec_fn=take_terminal)
    try:
        time.sleep(0.3)
        live = _proc_info(BASE / str(child.pid))
        stat = (BASE / str(child.pid) / 'stat').read_text()
        tty = int(stat[stat.rindex(')') + 2:].split()[4])
        entry = cl.describe_traced(BASE, traced(pid=child.pid, path=live['path'], argv=live['argv'],
                                                start=live['start']))
    finally:
        child.kill()
        child.wait()
        os.close(leader)
        os.close(follower)
    assert tty and entry['tty'] == tty
