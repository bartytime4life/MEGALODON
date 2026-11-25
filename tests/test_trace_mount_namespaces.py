"""The exec and connect traces name programs by their mount's place in the file tree. A service with a mount
namespace of its own (systemd's ProtectSystem=, as `megalodon schedule` writes them) has its own copies of the
host's mounts, with other IDs: the host's programs are found in init's mount table. No other table is read: a
mount namespace a program made itself can put any folder at /usr/bin."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import textwrap
import time

import pytest

from megalodon import connect_trace as ct
from megalodon import exec_trace as et
from test_connect_trace import record as connect_record, trace  # noqa: F401
from test_exec_trace import exec_record, tracer


def table(path, *entries):
    path.mkdir(parents=True, exist_ok=True)
    (path / 'mountinfo').write_text(''.join(f'{number} 1 0:{number} {root} {point} rw - ext4 /dev/x rw\n'
                                            for number, root, point in entries))


@pytest.fixture
def proc(tmp_path, monkeypatch):
    # This service's namespace: copies of the host's mounts, with IDs of their own.
    table(tmp_path / 'self', (900, '/', '/'), (901, '/', '/srv'))
    monkeypatch.setattr(ct, 'PROC', str(tmp_path))
    return tmp_path


def test_a_mount_not_among_this_processs_is_found_in_inits(proc):
    table(proc / '1', (20, '/', '/'), (21, '/', '/srv'))
    assert ct.mount_table(21) == {900: ('/', '/'), 901: ('/', '/srv'), 20: ('/', '/'), 21: ('/', '/srv')}
    assert ct.mount_table(901) == {900: ('/', '/'), 901: ('/', '/srv')}, "init's read only when needed"


def test_an_exec_on_the_host_is_named_in_full(proc):
    table(proc / '1', (20, '/', '/'), (32, '/', '/tmp'))
    record = tracer(mounts={}).parse(exec_record(exe_mount=20, cwd=('.x', '/'), cwd_mount=32))
    assert (record['path'], record['cwd']) == ('/tmp/.x/agent', '/tmp/.x')


@pytest.mark.parametrize('who', ['4321', '77'])      # the record's process, and its parent
def test_a_namespace_a_program_made_is_not_taken_as_the_hosts(proc, who):
    # Its own folder bind-mounted at /tmp: read from its table, its program would look like the host's.
    table(proc / '1', (20, '/', '/'))
    table(proc / who, (31, '/home/u/evil', '/tmp'))
    record = tracer(mounts={}).parse(exec_record(exe=('agent', '.x', 'evil', 'u', 'home', '/'), exe_mount=31,
                                                 cwd_mount=31))
    assert record['path'] == '…/home/u/evil/.x/agent' and record['cwd'] is None


def test_a_connect_on_the_host_is_named_in_full_and_a_foreign_one_is_not(proc, trace):  # noqa: F811
    table(proc / '1', (20, '/', '/'))
    table(proc / '40', (31, '/', '/'))              # the connecting process's own namespace
    trace.known_mounts = {}
    named = trace.parse(connect_record(trace, old=7, new=2, sk=0xA, names=['curl', 'bin', 'usr', '/'], mount=20))
    assert named['exe_tail'] == '/usr/bin/curl'
    foreign = trace.parse(connect_record(trace, old=7, new=2, sk=0xB, names=['curl', 'bin', 'usr', '/'], mount=31))
    assert foreign['exe_tail'] == '…/usr/bin/curl'


# ------------------------------------------------------------- live, in mount namespaces

INNER = textwrap.dedent('''
    import json, sys, time
    sys.path.insert(0, sys.argv[1])
    from megalodon import connect_trace
    from megalodon.exec_trace import ExecTrace
    if len(sys.argv) > 4:
        connect_trace.HOST = int(sys.argv[4])
    trace = ExecTrace()
    open(sys.argv[2], 'w').write('ready')
    end, seen = time.time() + 8, []
    while time.time() < end and not seen:
        trace.wait(0.2)
        seen = [r for r in trace.drain() if r.get('kind') == 'exec' and sys.argv[3] in r['argv']]
    trace.close()
    print(json.dumps([[r['path'], r['cwd']] for r in seen]))
''')


def _loadable():
    from megalodon.connect_trace import TraceError
    try:
        et.ExecTrace().close()
    except (TraceError, OSError) as exc:
        pytest.skip(f'exec tracing cannot be loaded here: {exc}')
    if not shutil.which('unshare'):
        pytest.skip('no unshare here')


def _watch(tmp_path, marker, run, *, own_namespace, host=None):
    """Start the trace (in a mount namespace of its own, as systemd sets up ProtectSystem=), run `run`, and
    return the [path, cwd] of each exec the marker was given to."""
    script, ready = tmp_path / 'inner.py', tmp_path / 'ready'
    script.write_text(INNER)
    root = str(Path(et.__file__).resolve().parents[1])
    command = [sys.executable, '-B', str(script), root, str(ready), marker, *([str(host)] if host else [])]
    if own_namespace:
        command = ['unshare', '-m', '--propagation', 'slave', *command]
    inner = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(100):
            if ready.exists() or inner.poll() is not None:
                break
            time.sleep(0.1)
        if not ready.exists():
            pytest.skip(f'no mount namespace here: {inner.communicate(timeout=10)[1].strip()[-200:]}')
        run()
        out, err = inner.communicate(timeout=20)
    finally:
        if inner.poll() is None:
            inner.kill()
    return json.loads(out), err


def test_live_a_trace_in_its_own_mount_namespace_names_host_programs_in_full(tmp_path):
    _loadable()
    marker = f'nsmarker-{os.getpid()}'
    # Init's mount table is the host's; this test process, also in the host's namespace, stands in for it where
    # init cannot be read (as in some containers).
    seen, err = _watch(tmp_path, marker, lambda: subprocess.run(
        ['/bin/sh', '-c', f'cd {tmp_path} && exec /usr/bin/env true {marker}'], check=True),
        own_namespace=True, host=os.getpid())
    # Each program run for the marker (env, then the true it runs), in full; before, `…/usr/bin/env` and no folder.
    assert seen and all(path in ('/usr/bin/env', '/usr/bin/true') and cwd == str(tmp_path) for path, cwd in seen), \
        (seen, err)


def test_live_a_folder_put_at_usr_bin_in_a_namespace_of_its_own_is_not_taken_for_it(tmp_path):
    _loadable()
    marker = f'atkmarker-{os.getpid()}'
    evil = tmp_path / 'evil'
    evil.mkdir()
    shutil.copy('/usr/bin/true', evil / 'env')
    fifo = tmp_path / 'fifo'
    os.mkfifo(fifo)
    # The shell stays in that namespace while the trace reads the record: its table names the copy /usr/bin/env.
    attack = ['unshare', '-m', '--propagation', 'private', 'bash', '-c',
              f'mount --bind {evil} /usr/bin && /usr/bin/env {marker}; read -t 2 x <> {fifo}; exit 0']

    def run():
        result = subprocess.run(attack, capture_output=True, text=True)
        if result.returncode:
            pytest.skip(f'cannot make a mount namespace with a bind mount here: {result.stderr.strip()[-200:]}')
    seen, err = _watch(tmp_path, marker, run, own_namespace=False)
    assert seen and all(path == f'…{evil}/env' for path, _ in seen), (seen, err)
