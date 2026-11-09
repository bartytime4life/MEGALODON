"""Submission, normalization and cancellation boundaries without native parsers."""
from copy import deepcopy
import json
import os
from pathlib import Path
from threading import Event
import time

import pytest

from megalodon.file_inspection import FileInspection, InspectionBusy, normalize_die, normalize_lief
from megalodon.file_inspection_contract import (MAX_INPUT, MAX_OUTPUT, report, validate_report, decode)
from megalodon import file_inspection_sandbox as sandbox


STRUCTURE = dict(format='ELF', slices_detected=1, slices=[dict(
    architecture='X86_64', bits=64, sections=3, imports=2, writable_executable=1)])
PROBE = dict(network=True, fork=True, host_read=True, host_write=True, execute_input=True)


def runner(root, fd, tool, *, deadline, cancelled, probe=None):
    if probe:
        return 'completed', json.dumps(PROBE).encode()
    if tool == 'lief':
        return 'completed', json.dumps(dict(state='completed', structure=STRUCTURE)).encode()
    return 'completed', b'{"detects":[{"filetype":"ELF64","info":"","offset":"0","parentfilepart":"Header","size":"4","values":[]}]}'


def finish(service, raw=b'\x7fELF'):
    job, fd, root = service.reserve(len(raw))
    os.write(fd, raw)
    assert service.submit(job, fd, len(raw), root)
    wait(service)
    return service.snapshot()


def wait(service):
    deadline = time.monotonic() + 5
    while service.snapshot()['state'] in ('receiving', 'running'):
        assert time.monotonic() < deadline
        time.sleep(.005)


def service(**kwargs):
    return FileInspection(runner=kwargs.pop('runner', runner), validator=lambda _: Path('/unused'), **kwargs)


def test_explicit_job_does_not_keep_sample_or_filename():
    inspector = service()
    assert inspector.snapshot()['report'] is None
    result = finish(inspector)
    assert result['state'] == 'completed'
    assert result['report']['clues'][0]['code'] == 'writable_executable'
    assert validate_report(result['report'])
    serialized = json.dumps(result)
    for field in ('payload', 'filename', 'sha256', 'path', 'raw_output'):
        assert field not in serialized
    inspector.close()


@pytest.mark.parametrize('size', [0, -1, True, 1.0, MAX_INPUT + 1])
def test_invalid_size_precedes_reservation(size):
    inspector = service()
    with pytest.raises(ValueError):
        inspector.reserve(size)
    assert inspector.snapshot()['state'] == 'idle'


def test_cancel_keeps_receiving_slot_until_request_cleanup():
    inspector = service()
    job, fd, _ = inspector.reserve(4)
    try:
        inspector.cancel()
        assert inspector.receiving_cancelled(job)
        with pytest.raises(InspectionBusy):
            inspector.reserve(4)
        inspector.abort(job)
        assert inspector.snapshot()['state'] == 'cancelled'
    finally:
        os.close(fd)
        inspector.close()


def test_cancel_running_job_discards_late_success_and_closes_fd():
    started, release = Event(), Event()
    def held(*args, **kwargs):
        if not kwargs.get('probe'):
            started.set()
            release.wait(2)
        return runner(*args, **kwargs)
    inspector = service(runner=held)
    job, fd, root = inspector.reserve(4)
    os.write(fd, b'data')
    assert inspector.submit(job, fd, 4, root)
    assert started.wait(2)
    inspector.cancel()
    with pytest.raises(InspectionBusy):
        inspector.reserve(4)
    release.set()
    wait(inspector)
    assert inspector.snapshot()['report']['state'] == 'cancelled'
    with pytest.raises(OSError):
        os.fstat(fd)
    inspector.close()


@pytest.mark.parametrize('failed_state', ['unavailable', 'failed', 'timed_out'])
def test_one_adapter_failure_is_partial(failed_state):
    def failing(root, fd, tool, **kwargs):
        return (failed_state, b'') if tool == 'die' else runner(root, fd, tool, **kwargs)
    result = finish(service(runner=failing))['report']
    assert result['state'] == 'partial'
    assert result['tools'][1]['state'] == failed_state


def test_identification_filter_refusal_preserves_completed_structure(monkeypatch):
    def fail_filter(**_):
        raise sandbox.SandboxUnavailable('synthetic identification filter refusal')
    monkeypatch.setattr(sandbox, '_filter', fail_filter)
    def refusing(root, fd, tool, **kwargs):
        if tool == 'die':
            return sandbox.run(root, fd, tool, **kwargs)
        return runner(root, fd, tool, **kwargs)
    inspector = service(runner=refusing)
    try:
        result = finish(inspector)['report']
        assert result['state'] == 'partial'
        assert result['structure'] == STRUCTURE
        assert result['clues'][0]['code'] == 'writable_executable'
        assert result['tools'] == [dict(id='lief', state='completed'),
                                   dict(id='die', state='unavailable')]
    finally:
        inspector.close()


def test_failed_confinement_never_invokes_analyzers():
    calls = []
    def fail(root, fd, tool, **kwargs):
        calls.append(kwargs.get('probe'))
        return 'completed', json.dumps({**PROBE, 'network': False}).encode()
    result = finish(service(runner=fail))
    assert calls == ['confinement']
    assert result['report']['tools'] == [dict(id='lief', state='unavailable'), dict(id='die', state='unavailable')]


def test_unknown_format_skips_identification_parser():
    calls = []
    def unsupported(root, fd, tool, **kwargs):
        calls.append((tool, kwargs.get('probe')))
        return runner(root, fd, tool, **kwargs) if kwargs.get('probe') else ('completed', b'{"state":"unsupported"}')
    result = finish(service(runner=unsupported))['report']
    assert result['state'] == 'unsupported'
    assert calls == [('lief', 'confinement'), ('lief', None)]


@pytest.mark.parametrize('raw', [b'{"detects":[],"detects":[]}', b'{"detects":NaN}',
    b'[' * 2000, b'x' * (MAX_OUTPUT + 1), b'{"detects":[]}'])
def test_invalid_tool_output_is_refused(raw):
    with pytest.raises((ValueError, RecursionError)):
        normalize_die(raw)


def test_only_bounded_labels_cross_identification_boundary():
    row = dict(info='/secret/path', name='UPX', string='arbitrary tool prose', type='packer', version='x')
    envelope = dict(detects=[dict(filetype='PE64', info='raw info', offset='0', parentfilepart='Header', size='4', values=[row])])
    result = normalize_die(json.dumps(envelope).encode())
    assert result == dict(state='completed', identification=[dict(kind='packer', name='UPX')])
    row['name'] = '<script>alert(1)</script>'
    with pytest.raises(ValueError):
        normalize_die(json.dumps(envelope).encode())


def test_report_cannot_invent_findings_or_tool_success():
    original = report(4, [dict(state='completed', structure=STRUCTURE), dict(state='failed')])
    for key, value in [('state', 'completed'), ('next_step', 'Run this command'), ('filename', 'secret')]:
        candidate = deepcopy(original)
        candidate[key] = value
        with pytest.raises(ValueError):
            validate_report(candidate)


def test_close_stops_new_jobs():
    inspector = service()
    inspector.close()
    with pytest.raises(ValueError):
        inspector.reserve(4)
