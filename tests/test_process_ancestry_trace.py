"""Process ancestry from the exec trace: each started program as the kernel recorded it, so one gone before the
watch reads it is still judged. The live test runs only where eBPF raw tracepoints can be loaded."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import threading
import time

import pytest

from megalodon import process_ancestry as anc
from test_process_ancestry import proc, root  # noqa: F401


def started(pid, parent, path, argv=None, start=None, cwd='/var/www'):
    return dict(kind='exec', pid=pid, parent=parent, uid=33, gid=33, comm=os.path.basename(path)[:15],
                start=start if start is not None else 5000 + pid, path=path, deleted=False,
                argv=argv or [path], argv_cut=False, cwd=cwd, login_uid=None, session=None)


def forked(pid, parent):
    return dict(kind='fork', pid=pid, parent=parent, start=None)


class Trace:
    def __init__(self, stop, records, dropped=0):
        self.stop, self.records, self.lost, self.closed = stop, list(records), dropped, False

    def wait(self, seconds):
        return True

    def drain(self):
        if not self.records:
            self.stop.set()
            return []
        out, self.records = self.records, []
        return out

    def dropped(self):
        return self.lost

    def close(self):
        self.closed = True


def watcher(root, trace=None):
    found = []
    w = anc.Watcher(found.append, root=str(root), allow_path=str(root / 'allow.json'),
                    trace=trace or Trace(threading.Event(), []))
    return w, found


def test_a_command_gone_before_it_is_read_is_judged_from_the_kernels_record(root):
    # nginx (pid 11) ran id, which exited at once: /proc has no entry for it.
    w, found = watcher(root)
    assert w.mode == 'exec trace'
    w.handle_traced(started(200, 11, '/usr/bin/id', ['id', '-a']))
    assert [(f['rule_id'], f['severity']) for f in found] == [('SERVICE_SPAWNED_TOOL', 'HIGH')]
    evidence = found[0]['evidence']
    assert (evidence['program'], evidence['pid'], evidence['start'], evidence['argv']) == (
        '/usr/bin/id', 200, 5200, ['id', '-a'])
    assert evidence['service']['program'] == '/usr/sbin/nginx' and evidence['service']['pid'] == 11
    assert w.stats['vanished'] == 0 and w.stats['started'] == 1


def test_a_shell_and_its_command_both_gone_lead_back_to_the_service(root):
    # nginx -> sh -c 'id' -> id, all within a millisecond: the shell is known from its exec record.
    w, found = watcher(root)
    for record in (forked(300, 11), started(300, 11, '/usr/bin/dash', ['sh', '-c', 'id']),
                   forked(301, 300), started(301, 300, '/usr/bin/id', ['id'])):
        w.handle_traced(record)
    assert [(f['rule_id'], f['evidence']['pid']) for f in found] == [
        ('SERVICE_SPAWNED_SHELL', 300), ('SERVICE_SPAWNED_TOOL', 301)]
    assert found[1]['evidence']['chain'][:2] == ['/usr/bin/dash', '/usr/sbin/nginx']


def test_the_kernels_record_is_the_program_not_what_proc_shows_later(root):
    # The ID was reused, or the process ran another program: /proc shows that one, the trace the one that started.
    proc(root, 400, 11, '/usr/bin/true', ['true'])
    w, found = watcher(root)
    w.handle_traced(started(400, 11, '/usr/bin/curl', ['curl', '-s', 'http://198.51.100.9/x']))
    assert [f['evidence']['program'] for f in found] == ['/usr/bin/curl']


@pytest.mark.parametrize('recorded, now, reported', [
    # A startup script ran id, then exec nginx: /proc shows nginx with the same start time. Not a finding.
    ('/usr/bin/dash', '/usr/sbin/nginx', []),
    # nginx ran id, then the worker ran something else: /proc no longer shows nginx. Still a finding.
    ('/usr/sbin/nginx', '/usr/bin/true', ['/usr/sbin/nginx']),
])
def test_a_recorded_parent_is_as_its_records_left_it(root, recorded, now, reported):
    proc(root, 800, 1, now, start=5800)
    w, found = watcher(root)
    for record in (started(800, 1, recorded, [recorded], start=5800), forked(801, 800),
                   started(801, 800, '/usr/bin/id', ['id'])):
        w.handle_traced(record)
    assert [f['evidence']['service']['program'] for f in found if f['evidence']['pid'] == 801] == reported


def test_a_subshell_and_a_reparented_command_lead_back_to_the_service(root):
    # nginx -> sh -c '(id &)': the subshell forks without exec, id is reparented to init before it execs, and
    # nginx's PID now belongs to another process. The fork records, not /proc, say where id came from.
    proc(root, 800, 1, '/usr/bin/true', start=9999)
    w, found = watcher(root)
    for record in (started(800, 1, '/usr/sbin/nginx', ['nginx'], start=5800), forked(801, 800),
                   forked(802, 801), started(802, 1, '/usr/bin/id', ['id'])):
        w.handle_traced(record)
    assert [(f['evidence']['pid'], f['evidence']['service']['program']) for f in found] == [(802, '/usr/sbin/nginx')]


def test_distinct_commands_are_each_reported(root):
    w, found = watcher(root)
    for number in range(5):
        w.handle_traced(started(500 + number, 11, '/usr/bin/id', ['id', str(number)]))
    w.handle_traced(started(510, 11, '/usr/bin/id', ['id', '0']))              # the same command again
    assert [f['evidence']['argv'] for f in found] == [['id', str(n)] for n in range(5)]


def test_what_is_not_a_finding_stays_quiet(root):
    w, found = watcher(root)
    w.handle_traced(started(600, 61, '/usr/bin/id', ['id']))                   # an admin's own shell
    w.handle_traced(started(601, 11, '/usr/sbin/nginx', ['nginx', '-s', 'reload']))   # not a shell or tool
    w.handle_traced(dict(kind='other', pid=602))
    assert found == [] and w.stats['started'] == 2


def test_the_watch_runs_on_the_trace_and_counts_what_it_lost(root):
    stop = threading.Event()
    trace = Trace(stop, [started(700, 11, '/usr/bin/id', ['id'])], dropped=4)
    w, found = watcher(root, trace)
    w.run(stop, timeout=0.01)
    w.close()
    assert len(found) == 1 and w.stats['trace_dropped'] == 4 and trace.closed


def test_the_command_line_falls_back_when_tracing_is_unavailable(tmp_path, monkeypatch, capsys):
    from megalodon import exec_trace
    from megalodon.cli import main
    from megalodon.connect_trace import TraceError

    def refuse():
        raise TraceError(1, 'the kernel refused the program')
    monkeypatch.setattr(exec_trace, 'ExecTrace', refuse)
    seen = {}

    class Stopper(anc.Watcher):
        def __init__(self, emit, **kw):
            seen['trace'] = kw.get('trace')
            super().__init__(emit, source=Events(), **kw)

        def run(self, stop, timeout=0.5):
            pass
    monkeypatch.setattr(anc, 'Watcher', Stopper)
    with pytest.raises(SystemExit) as exit_:
        main(['ancestry', 'watch', '--allow-file', str(tmp_path / 'allow.json'), '--trace-execs'])
    assert exit_.value.code == 0 and seen['trace'] is None
    assert 'exec tracing unavailable: the kernel refused the program' in capsys.readouterr().err
    # Loaded, the trace is what the watch reads.
    loaded = Trace(threading.Event(), [])
    monkeypatch.setattr(exec_trace, 'ExecTrace', lambda: loaded)
    with pytest.raises(SystemExit) as exit_:
        main(['ancestry', 'watch', '--allow-file', str(tmp_path / 'allow.json'), '--trace-execs'])
    assert exit_.value.code == 0 and seen['trace'] is loaded
    assert '(exec trace)' in capsys.readouterr().err


class Events:
    def events(self, timeout):
        return []

    def close(self):
        pass


# ------------------------------------------------------------- live, where eBPF can be loaded

def test_live_quick_commands_from_a_service_are_each_judged(tmp_path):
    from megalodon.connect_trace import TraceError
    from megalodon.exec_trace import ExecTrace
    try:
        trace = ExecTrace()
    except (TraceError, OSError) as exc:
        pytest.skip(f'exec tracing cannot be loaded here: {exc}')
    service, tool = tmp_path / 'nginx', tmp_path / 'id'          # named as a web server and a recon command
    shutil.copy(shutil.which('sh'), service)
    shutil.copy(shutil.which('true'), tool)
    found = []
    w = anc.Watcher(found.append, allow_path=str(tmp_path / 'allow.json'), trace=trace)
    stop = threading.Event()
    worker = threading.Thread(target=w.run, args=(stop,), kwargs=dict(timeout=0.1), daemon=True)
    worker.start()
    try:
        time.sleep(0.3)
        script = ' '.join(f'{tool} {number} &' for number in range(20)) + ' wait; sleep 1'
        subprocess.run([str(service), '-c', script], check=True)
        time.sleep(1)
    finally:
        stop.set()
        worker.join(5)
        w.close()
    mine = [f for f in found if f['evidence']['service']['program'] == str(service)]
    assert sorted(int(f['evidence']['argv'][1]) for f in mine) == list(range(20)), w.stats
