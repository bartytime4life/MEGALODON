"""Opt-in real parsers and kernel confinement, using only synthetic headers.

Set MEGALODON_INSPECTOR_TEST_HOME to a private isolated runtime rehearsal home.
These tests never acquire packages or read personal downloads.
"""
import json
import os
from pathlib import Path
from threading import Event, Thread
import time
import subprocess
import sys

import pytest

from megalodon.file_inspection import FileInspection
from megalodon import file_inspection_sandbox as sandbox
from megalodon.file_inspection_runtime import validate
from file_inspection_fixtures import elf, pe, macho, universal


@pytest.fixture
def native_home():
    value = os.environ.get('MEGALODON_INSPECTOR_TEST_HOME')
    if value is None:
        pytest.skip('Explicit private inspector runtime rehearsal is not selected.')
    home = Path(value)
    validate(home)  # An opted-in missing/modified runtime is a failure, not skip.
    return home


def inspect(home, raw):
    inspector = FileInspection(home)
    try:
        job, fd, root = inspector.reserve(len(raw))
        os.write(fd, raw)
        assert inspector.submit(job, fd, len(raw), root)
        deadline = time.monotonic() + 35
        while inspector.snapshot()['state'] in ('receiving', 'running'):
            assert time.monotonic() < deadline
            time.sleep(.02)
        return inspector.snapshot()['report']
    finally:
        inspector.close()


@pytest.mark.parametrize('raw,kind,count', [(elf(), 'ELF', 1), (pe(), 'PE', 1),
    (macho(), 'Mach-O', 1), (macho(arm=True), 'Mach-O', 1), (universal(), 'Mach-O', 2)])
def test_native_formats_and_all_universal_slices(native_home, raw, kind, count):
    result = inspect(native_home, raw)
    assert result['state'] == 'completed'
    assert [t['state'] for t in result['tools']] == ['completed', 'completed']
    assert result['structure']['format'] == kind
    assert len(result['structure']['slices']) == result['structure']['slices_detected'] == count


@pytest.mark.parametrize('raw', [elf(writable=True), pe(writable=True), macho(writable=True)])
def test_native_writable_executable_clue(native_home, raw):
    result = inspect(native_home, raw)
    assert result['structure']['slices'][0]['writable_executable'] == 1
    assert result['clues'][0]['code'] == 'writable_executable'


@pytest.mark.parametrize('raw', [b'not a program', b'PK\x03\x04' + b'\0' * 64])
def test_native_unsupported_not_unpacked(native_home, raw):
    result = inspect(native_home, raw)
    assert result['state'] == 'unsupported'
    assert result['structure'] is None


@pytest.mark.parametrize('raw', [b'\x7fELF', b'MZ' + b'\0' * 20,
    b'\xca\xfe\xba\xbe' + (17).to_bytes(4, 'big') + b'\0' * 64])
def test_native_malformed_never_claims_complete_structure(native_home, raw):
    result = inspect(native_home, raw)
    assert result['structure'] is None
    assert result['state'] != 'completed'


def test_native_confinement_and_input_not_executable(native_home, tmp_path, monkeypatch):
    secret = tmp_path / 'private-secret'
    secret.write_text('synthetic secret outside allowed mounts')
    probe = sandbox.PROBE.replace("'/etc/passwd'", repr(str(secret)))
    monkeypatch.setattr(sandbox, 'PROBE', probe)
    fd = sandbox.sealed_input()
    os.write(fd, elf())
    sandbox.seal(fd)
    try:
        state, raw = sandbox.run(validate(native_home), fd, 'lief',
            deadline=time.monotonic() + 5, cancelled=Event(), probe='confinement')
        assert state == 'completed'
        assert json.loads(raw) == dict(network=True, fork=True, host_read=True, host_write=True, execute_input=True)
        assert not (validate(native_home) / 'inspection-write-test').exists()
    finally:
        os.close(fd)


def test_native_deadline_cancel_and_namespace_teardown(native_home, monkeypatch):
    # The isolated namespace cannot fork. Killing its reaper also tears down
    # the payload; neither a detached process nor a tool can outlive its job.
    monkeypatch.setattr(sandbox, 'PROBE', 'import time; time.sleep(60)')
    real_popen = sandbox.subprocess.Popen
    observed, stop = set(), Event()
    processes = []
    def record(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        processes.append(process)
        return process
    monkeypatch.setattr(sandbox.subprocess, 'Popen', record)
    def watch():
        while not stop.is_set():
            pending = [p.pid for p in processes]
            while pending:
                pid = pending.pop()
                if pid in observed:
                    continue
                try:
                    children = Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
                except OSError:
                    continue
                if children:
                    observed.add(pid)
                    pending += [int(child) for child in children]
                else:
                    # Revisit a launcher until it has created the namespace.
                    if pid not in [p.pid for p in processes]:
                        observed.add(pid)
            time.sleep(.005)
    monitor = Thread(target=watch, daemon=True)
    monitor.start()
    fd = sandbox.sealed_input()
    os.write(fd, elf())
    sandbox.seal(fd)
    try:
        started = time.monotonic()
        state, _ = sandbox.run(validate(native_home), fd, 'lief',
            deadline=started + .5, cancelled=Event(), probe='confinement')
        assert state == 'timed_out' and time.monotonic() - started < 3
        cancel = Event()
        cancel.set()
        state, _ = sandbox.run(validate(native_home), fd, 'lief',
            deadline=time.monotonic() + 5, cancelled=cancel, probe='confinement')
        assert state == 'cancelled'
    finally:
        stop.set()
        monitor.join(2)
        os.close(fd)
    assert len(observed) >= 2, 'The actual namespace/reaper payload must be observed.'
    for pid in observed:
        try:
            state = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0]
        except FileNotFoundError:
            continue
        assert state == 'Z', 'No observed namespace descendant may continue executing.'


def test_native_output_flood_is_discarded(native_home, monkeypatch):
    monkeypatch.setattr(sandbox, 'PROBE', 'import os; os.write(1,b"x"*100000)')
    fd = sandbox.sealed_input()
    os.write(fd, elf())
    sandbox.seal(fd)
    try:
        state, raw = sandbox.run(validate(native_home), fd, 'lief',
            deadline=time.monotonic() + 5, cancelled=Event(), probe='confinement')
        assert state == 'failed' and raw == b''
    finally:
        os.close(fd)


def test_native_parent_death_removes_namespace(native_home):
    # Crash a disposable controller without calling close(). Its worker must
    # disappear through the kernel parent-death/namespace boundary alone.
    script = '''
import os,sys,time
from pathlib import Path
from threading import Event
from megalodon import file_inspection_sandbox as s
from megalodon.file_inspection_runtime import validate
s.PROBE='import time; time.sleep(60)'
original=s.subprocess.Popen
def record(*a,**k):
 p=original(*a,**k);print(p.pid,flush=True);return p
s.subprocess.Popen=record
fd=s.sealed_input();os.write(fd,b'synthetic');s.seal(fd)
s.run(validate(Path(sys.argv[1])),fd,'lief',deadline=time.monotonic()+30,cancelled=Event(),probe='confinement')
'''
    process = subprocess.Popen([sys.executable, '-c', script, str(native_home)],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        import select
        assert select.select([process.stdout], [], [], 5)[0]
        child = int(process.stdout.readline())
        # Allow initialization of the isolated namespace before killing the HUD.
        deadline = time.monotonic() + 3
        descendants = []
        while time.monotonic() < deadline:
            try:
                descendants = Path(f'/proc/{child}/task/{child}/children').read_text().split()
            except OSError:
                pass
            if descendants:
                break
            time.sleep(.01)
        assert descendants
        process.kill()
        process.wait(timeout=3)
        for pid in [child] + [int(value) for value in descendants]:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                try:
                    state = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0]
                except FileNotFoundError:
                    break
                if state == 'Z':
                    break
                time.sleep(.01)
            else:
                pytest.fail(f'A worker survived controller death: {pid}, state={state}.')
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)
        process.stdout.close()
