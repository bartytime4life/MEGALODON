"""The exec and connect traces name programs by their mount's place in the file tree. A service with a mount
namespace of its own (systemd's ProtectSystem=, as `megalodon schedule` writes them) has its own copies of the
host's mounts, with other IDs: the host's programs are found in init's mount table, or their own."""
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


def test_then_in_the_traced_processes_own(proc):
    # Init unreadable, or the program in a namespace init is not in: its own table, or its parent's.
    table(proc / '4321', (30, '/', '/'))
    table(proc / '77', (31, '/', '/var/tmp'))
    assert ct.mount_table(31, (4321, 77))[31] == ('/', '/var/tmp')
    assert 31 not in ct.mount_table(30, (4321, 77)), 'read only as far as needed'
    assert ct.mount_table(40, (0, 4321)).keys() == {900, 901, 30}, 'no process, or one gone: nothing more'


def test_an_exec_on_the_host_is_named_in_full(proc):
    table(proc / '1', (20, '/', '/'))
    record = tracer(mounts={}).parse(exec_record(exe_mount=20, cwd_mount=20))
    assert (record['path'], record['cwd']) == ('/tmp/.x/agent', '/tmp/.x')


@pytest.mark.parametrize('who', ['4321', '77'])      # the record's process, and its parent
def test_an_exec_is_found_through_its_process_or_its_parent(proc, who):
    table(proc / who, (31, '/', '/'))
    record = tracer(mounts={}).parse(exec_record(exe_mount=31, cwd_mount=31))
    assert (record['path'], record['cwd']) == ('/tmp/.x/agent', '/tmp/.x')


def test_a_working_folder_on_another_mount_is_found_too(proc):
    # The program on a host mount init has, the folder on one only the process's own table holds.
    table(proc / '1', (20, '/', '/'))
    table(proc / '4321', (20, '/', '/'), (32, '/', '/tmp'))
    record = tracer(mounts={}).parse(exec_record(exe_mount=20, cwd=('.x', '/'), cwd_mount=32))
    assert (record['path'], record['cwd']) == ('/tmp/.x/agent', '/tmp/.x')


def test_a_connect_on_the_host_is_named_in_full(proc, trace):  # noqa: F811
    table(proc / '40', (20, '/', '/'))           # the connecting process is 40
    trace.known_mounts = {}
    data = connect_record(trace, old=7, new=2, sk=0xA, names=['curl', 'bin', 'usr', '/'], mount=20)
    assert trace.parse(data)['exe_tail'] == '/usr/bin/curl'


# ------------------------------------------------------------- live, in a mount namespace of its own

INNER = textwrap.dedent('''
    import json, sys, time
    sys.path.insert(0, sys.argv[1])
    from megalodon.exec_trace import ExecTrace
    trace = ExecTrace()
    open(sys.argv[2], 'w').write('ready')
    end, seen = time.time() + 8, []
    while time.time() < end and not seen:
        trace.wait(0.2)
        seen = [r for r in trace.drain() if r.get('kind') == 'exec' and sys.argv[3] in r['argv']]
    trace.close()
    print(json.dumps([[r['path'], r['cwd']] for r in seen]))
''')


def test_live_a_trace_in_its_own_mount_namespace_names_host_programs_in_full(tmp_path):
    from megalodon.connect_trace import TraceError
    try:
        et.ExecTrace().close()
    except (TraceError, OSError) as exc:
        pytest.skip(f'exec tracing cannot be loaded here: {exc}')
    if not shutil.which('unshare'):
        pytest.skip('no unshare here')
    script, ready, marker = tmp_path / 'inner.py', tmp_path / 'ready', f'nsmarker-{os.getpid()}'
    script.write_text(INNER)
    root = str(Path(et.__file__).resolve().parents[1])
    # As systemd sets up ProtectSystem=: a mount namespace of its own, receiving the host's mounts.
    inner = subprocess.Popen(['unshare', '-m', '--propagation', 'slave', sys.executable, '-B', str(script), root,
                              str(ready), marker], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(100):
            if ready.exists() or inner.poll() is not None:
                break
            time.sleep(0.1)
        if not ready.exists():
            pytest.skip(f'no mount namespace of its own here: {inner.communicate(timeout=10)[1].strip()[-200:]}')
        subprocess.run(['/bin/sh', '-c', f'cd {tmp_path} && exec /usr/bin/env true {marker}'], check=True)
        out, err = inner.communicate(timeout=20)
    finally:
        if inner.poll() is None:
            inner.kill()
    seen = json.loads(out)
    # Each program run for the marker (env, then the true it runs), in full; before, `…/usr/bin/env` and no folder.
    assert seen and all(path in ('/usr/bin/env', '/usr/bin/true') and cwd == str(tmp_path) for path, cwd in seen), \
        (seen, err)
