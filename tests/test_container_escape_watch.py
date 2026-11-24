"""Container escapes as they start: an exec in the host's mount namespace from a container's control group, from
the exec trace. The live test runs only as root, with eBPF, runc and a C compiler, in a throwaway container."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time

import pytest

from megalodon import container_watch as cw
from megalodon import respond_now

HOST, OTHER = 4026531840, 4026532999
CID = 'c' * 64
DOCKER = f'0::/system.slice/docker-{CID}.scope\n'


def record(path='/usr/bin/cat', pid=900, parent=800, mnt=HOST, cgroup=DOCKER, exe_file=(64, 5000),
           deleted=False, argv=None, comm=None):
    return dict(kind='exec', pid=pid, parent=parent, uid=0, gid=0, comm=comm or os.path.basename(path), start=4242,
                path=path, deleted=deleted, argv=argv or [path], cwd='/', mnt_ns=mnt, exe_file=exe_file,
                cgroup=cgroup)


class Trace:
    def __init__(self, records=()):
        self.records, self.closed = list(records), False

    def wait(self, seconds):
        time.sleep(min(seconds, 0.01))
        return bool(self.records)

    def drain(self):
        out, self.records = self.records, []
        return out

    def close(self):
        self.closed = True


@pytest.fixture
def host(tmp_path):
    """A root with process 1 in the host's mount namespace, and an installed runc."""
    (tmp_path / 'proc/1/ns').mkdir(parents=True)
    os.symlink(f'mnt:[{HOST}]', tmp_path / 'proc/1/ns/mnt')
    (tmp_path / 'usr/bin').mkdir(parents=True)
    (tmp_path / 'usr/bin/runc').write_bytes(b'runc')
    return tmp_path


def watch(root, clock=None):
    found = []
    w = cw.EscapeWatch(found.append, Trace(), root=str(root), api=None, clock=clock or time.monotonic)
    return w, found


def runc_file(root):
    info = os.stat(root / 'usr/bin/runc')
    return (info.st_dev, info.st_ino)


def test_a_program_started_in_the_host_namespace_from_a_container_is_an_escape(host):
    w, found = watch(host)
    assert (w.host_mnt, w.host_from) == (HOST, 'process 1')
    out = w.handle(record('/usr/bin/cat', argv=['cat', '/etc/shadow']))
    assert out == found and len(found) == 1
    finding = found[0]
    assert finding['rule_id'] == 'CONTAINER_ESCAPE' and finding['severity'] == 'CRITICAL'
    assert finding['subject'] == 'process:900' and finding['container'] == f'docker:{CID}'
    assert finding['evidence'] == dict(processes=[dict(pid=900, start=4242, program='/usr/bin/cat')],
                                       argv=['cat', '/etc/shadow'], traced=dict(parent=800, uid=0, comm='cat'))
    assert 'in the host\'s mount namespace' in finding['detail']


@pytest.mark.parametrize('change', [dict(mnt=OTHER), dict(cgroup='0::/user.slice/session-2.scope\n'),
                                    dict(cgroup=''), dict(mnt=None)])
def test_what_is_not_an_escape(host, change):
    # In the container's own namespace, or a host process, or nothing known: not reported.
    w, found = watch(host)
    w.handle(record(**change))
    w.handle(dict(kind='fork', pid=1, parent=2, start=3))
    assert found == [] and w.stats['execs'] == 1, 'a fork is not an exec'


def test_the_installed_runtime_helpers_are_not_escapes(host):
    w, found = watch(host)
    w.handle(record('/usr/bin/runc', exe_file=runc_file(host)))
    assert found == [] and w.stats['runtime_steps'] == 1


def test_runc_running_itself_again_from_a_sealed_copy_is_not_an_escape(host):
    # runc (installed, by inode) starts `runc init` from a sealed copy: the same inode number on a private mount,
    # or before runc 1.2 a deleted in-memory copy. With CLONE_INTO_CGROUP it is in the container's group already.
    dev, ino = runc_file(host)
    w, found = watch(host)
    w.handle(record('/usr/bin/runc', pid=800, parent=1, exe_file=(dev, ino), cgroup=''))
    w.handle(record('…/runc', pid=801, parent=800, exe_file=(41, ino), argv=['runc', 'init']))
    w.handle(record('/memfd:runc_cloned:/proc/self/exe', pid=802, parent=800, deleted=True, exe_file=(9, 77)))
    assert found == [] and w.stats['runtime_steps'] == 2       # runc itself is a host process, not a step
    # The same copies with a parent that is not the runtime: escapes.
    w.handle(record('…/runc', pid=803, parent=799, exe_file=(41, ino)))
    w.handle(record('/memfd:runc_cloned:/proc/self/exe', pid=804, parent=799, deleted=True, exe_file=(9, 78)))
    # A runtime child running anything else: an escape (as nsenter run by `docker exec` would be).
    w.handle(record('/usr/bin/sh', pid=805, parent=800, exe_file=(64, 6000)))
    # An in-memory copy not named as runc's, from runc: an escape.
    w.handle(record('/memfd:payload', pid=806, parent=800, deleted=True, exe_file=(9, 79)))
    assert [f['subject'] for f in found] == ['process:803', 'process:804', 'process:805', 'process:806']


def test_a_parent_from_before_the_trace_is_read_from_proc(host):
    # runc started before the watch: its executable is read from /proc.
    dev, ino = runc_file(host)
    (host / 'proc/800').mkdir()
    os.symlink(host / 'usr/bin/runc', host / 'proc/800/exe')
    w, found = watch(host)
    w.handle(record('…/runc', pid=801, parent=800, exe_file=(41, ino)))
    assert found == []


def test_a_runtime_installed_or_upgraded_since_the_watch_started(host):
    (host / 'usr/bin/runc').unlink()
    w, found = watch(host)
    (host / 'usr/bin/runc').write_bytes(b'runc 2')        # a new runc, a new inode
    w.handle(record('/usr/bin/runc', exe_file=runc_file(host)))
    assert found == []


def test_the_same_program_from_the_same_container_is_reported_once_an_hour(host):
    now = [0.0]
    w, found = watch(host, clock=lambda: now[0])
    w.handle(record('/usr/bin/cat', pid=900))
    w.handle(record('/usr/bin/cat', pid=901))
    w.handle(record('/usr/bin/id', pid=902))
    other = f'0::/system.slice/docker-{"d" * 64}.scope\n'
    w.handle(record('/usr/bin/cat', pid=903, cgroup=other))
    now[0] = cw.COOLDOWN_SECONDS
    w.handle(record('/usr/bin/cat', pid=904))
    assert [f['subject'] for f in found] == ['process:900', 'process:902', 'process:903', 'process:904']
    assert w.stats == dict(execs=5, escapes=4, repeats=1, runtime_steps=0)


def test_where_the_host_namespace_is_read(tmp_path):
    (tmp_path / 'proc/self/ns').mkdir(parents=True)
    os.symlink(f'mnt:[{HOST}]', tmp_path / 'proc/self/ns/mnt')
    assert cw.host_mount_namespace(str(tmp_path)) == (HOST, 'this process')
    (tmp_path / 'proc/1/ns').mkdir(parents=True)
    os.symlink(f'mnt:[{OTHER}]', tmp_path / 'proc/1/ns/mnt')
    assert cw.host_mount_namespace(str(tmp_path)) == (OTHER, 'process 1')
    with pytest.raises(cw.ContainerError):
        cw.EscapeWatch(lambda f: None, Trace(), root=str(tmp_path / 'nothing'))


def test_the_watch_runs_until_stopped_and_closes_the_trace(host):
    found = []
    trace = Trace([record()])
    w = cw.EscapeWatch(found.append, trace, root=str(host))
    stop = threading.Event()
    worker = threading.Thread(target=w.run, args=(stop,), kwargs=dict(timeout=0.01))
    worker.start()
    deadline = time.monotonic() + 3
    while not found and time.monotonic() < deadline:
        time.sleep(0.01)
    stop.set()
    worker.join(5)
    w.close()
    assert len(found) == 1 and trace.closed


def test_a_live_escape_is_decided_as_the_timer_would_decide_it(host):
    w, found = watch(host)
    w.handle(record())
    signals = respond_now.signals_of('containers', found[0])
    assert [(s.rule_id, s.key) for s in signals] == [('CONTAINER_ESCAPE', 'containers:CONTAINER_ESCAPE:process:900')]
    assert 'containers' in respond_now.LIVE_SOURCES


def test_the_command_line(monkeypatch, capsys, host):
    from megalodon import exec_trace
    from megalodon.connect_trace import TraceError
    from megalodon.cli import main

    def refuse():
        raise TraceError(1, 'the kernel refused the program')
    monkeypatch.setattr(exec_trace, 'ExecTrace', refuse)
    with pytest.raises(SystemExit) as exit_:
        main(['containers', 'watch'])
    assert exit_.value.code == 2
    assert 'exec tracing unavailable: the kernel refused the program' in capsys.readouterr().err

    monkeypatch.setattr(exec_trace, 'ExecTrace', lambda: Trace([record()]))
    real = cw.EscapeWatch

    class Once(real):
        def __init__(self, emit, trace, **kw):
            super().__init__(emit, trace, root=str(host))

        def run(self, stop, timeout=0.5):
            for item in self.trace.drain():
                self.handle(item)
    monkeypatch.setattr(cw, 'EscapeWatch', Once)
    with pytest.raises(SystemExit) as exit_:
        main(['containers', 'watch'])
    out = capsys.readouterr()
    assert exit_.value.code == 0
    assert json.loads(out.out.splitlines()[0])['rule_id'] == 'CONTAINER_ESCAPE'
    assert '"escapes": 1' in out.err and "process 1's" in out.err


# ------------------------------------------------------------- live: a throwaway runc container

ESCAPE_C = r'''
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
int main(int c, char **v) {
  int fd = open(v[1], O_RDONLY);
  if (fd < 0 || setns(fd, CLONE_NEWNS)) return 1;
  execv(v[2], v + 2);
  return 1;
}
'''
HOLD_C = 'int main(void) { for (;;) pause(); }\n#include <unistd.h>\n'


def _cleanup(name):
    subprocess.run(['runc', 'kill', name, 'KILL'], stderr=subprocess.DEVNULL)
    for _ in range(50):
        if subprocess.run(['runc', 'delete', '-f', name], stderr=subprocess.DEVNULL).returncode == 0:
            break
        time.sleep(0.1)


def test_live_an_escape_that_finishes_at_once_is_reported(tmp_path):
    if os.geteuid() != 0 or not shutil.which('runc') or not shutil.which('gcc'):
        pytest.skip('needs root, runc and gcc')
    from megalodon.connect_trace import TraceError
    from megalodon.exec_trace import ExecTrace
    try:
        trace = ExecTrace()
    except (TraceError, OSError) as exc:
        pytest.skip(f'exec tracing cannot be loaded here: {exc}')
    bundle = tmp_path / 'bundle'
    (bundle / 'rootfs/bin').mkdir(parents=True)
    for name, source in (('escape', ESCAPE_C), ('hold', HOLD_C)):
        (tmp_path / f'{name}.c').write_text(source)
        subprocess.run(['gcc', '-O2', '-static', '-o', str(bundle / 'rootfs/bin' / name), str(tmp_path / f'{name}.c')],
                       check=True)
    subprocess.run(['runc', 'spec'], cwd=bundle, check=True)
    config = json.loads((bundle / 'config.json').read_text())
    ident = os.urandom(32).hex()
    config['process'].update(args=['/bin/hold'], terminal=False)
    for kind in ('bounding', 'effective', 'permitted'):
        config['process']['capabilities'][kind] = sorted(set(config['process']['capabilities'][kind])
                                                         | {'CAP_SYS_ADMIN', 'CAP_SYS_CHROOT', 'CAP_SYS_PTRACE'})
    # Docker's layout of control groups, and the host's process table: the setting this escape relies on.
    config['linux'].update(cgroupsPath=f'/docker/{ident}',
                           namespaces=[n for n in config['linux']['namespaces'] if n['type'] != 'pid'])
    config['linux'].pop('maskedPaths', None)
    config['linux'].pop('readonlyPaths', None)
    (bundle / 'config.json').write_text(json.dumps(config))
    name = f'megalodon-test-{ident[:8]}'
    found = []
    w = cw.EscapeWatch(found.append, trace)
    stop = threading.Event()
    worker = threading.Thread(target=w.run, args=(stop,), kwargs=dict(timeout=0.1), daemon=True)
    worker.start()
    try:
        if subprocess.run(['runc', 'run', '-d', name], cwd=bundle, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode != 0:
            pytest.skip('runc cannot run a container here')
        time.sleep(0.3)
        ordinary = subprocess.Popen(['runc', 'exec', name, '/bin/hold'])
        time.sleep(0.3)
        ordinary.kill()
        ordinary.wait()
        # Inside the container: join the host's mount namespace and run one program there, gone at once.
        escaped = subprocess.run(['runc', 'exec', name, '/bin/escape', f'/proc/{os.getpid()}/ns/mnt', '/usr/bin/true'])
        assert escaped.returncode == 0
        time.sleep(0.5)
    finally:
        _cleanup(name)
        stop.set()
        worker.join(5)
        w.close()
        for folder in sorted(Path('/sys/fs/cgroup').glob('**/docker'), reverse=True):
            try:
                folder.rmdir()              # Empty groups runc left behind; one in use is not removed.
            except OSError:
                pass
    assert [(f['rule_id'], f['evidence']['processes'][0]['program'], f['container']) for f in found] == [
        ('CONTAINER_ESCAPE', '/usr/bin/true', f'docker:{ident}')]
