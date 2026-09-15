"""Operator command wiring, failure isolation and real privilege acceptance."""

from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile

import pytest

from megalodon.offline import triage
from megalodon.offline.anomaly import build_anomaly_dossier
from megalodon.offline.common import OfflineError
import megalodon.qwen_advisory as qwen
from test_anomaly_advisory import REQUEST, REGISTRY, pin
from test_qwen_advisory import FakeConnection, FakeResponse


def write_inputs(root):
    data = deepcopy(REQUEST['input'])
    files = {'reference.json': data['reference']['baseline'],
             'current.json': data['current']['baseline'],
             'windows.json': {'schema': 'offline-anomaly-windows-v1',
                              'reference': data['reference']['window'],
                              'current': data['current']['window'], 'as_of': data['as_of']},
             'registry.json': REGISTRY}
    for name, value in files.items():
        (root / name).write_text(json.dumps(value))
    return ['--input-root', str(root), '--reference', 'reference.json',
            '--current', 'current.json', '--windows', 'windows.json']


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    # Only content/wiring tests stub privilege checks; separate tests below
    # exercise both the real refusal and real non-root acceptance.
    monkeypatch.setattr(triage, 'require_unprivileged_linux', lambda: None)
    return write_inputs(tmp_path)


def enable(args):
    return args + ['--qwen', '--registry', 'registry.json', '--registry-sha256', pin()]


def forbid(*args, **kwargs):
    pytest.fail('unexpected side effect')


def test_default_command_returns_evidence_without_provider_or_other_io(inputs, monkeypatch, capsys):
    for obj, name in [(triage, 'invoke_qwen_anomaly_advisory'), (socket, 'socket'),
                      (sqlite3, 'connect'), (subprocess, 'Popen')]:
        monkeypatch.setattr(obj, name, forbid)
    assert triage.main(inputs) == 0
    value = json.loads(capsys.readouterr().out)
    assert value['dossier'] == build_anomaly_dossier(REQUEST['input'])
    assert value['ai']['outcome'] == 'not_requested'
    assert value['provider_request_performed'] is False
    assert value['persistence_status'] == value['action_status'] == 'not_attempted'


@pytest.fixture
def provider(monkeypatch):
    FakeConnection.instances = []
    FakeConnection.next_response = FakeResponse()
    FakeConnection.request_error = None
    monkeypatch.setattr(qwen, '_LiteralLoopbackHTTPConnection', FakeConnection)
    return FakeConnection


def test_explicit_command_calls_shared_provider_once_and_keeps_evidence(inputs, provider, capsys):
    assert triage.main(enable(inputs)) == 0
    value = json.loads(capsys.readouterr().out)
    assert value['dossier'] == build_anomaly_dossier(REQUEST['input'])
    assert value['ai']['outcome'] == 'ANSWER'
    assert value['provider_request_performed'] is True
    assert 'prompt' not in value['ai']
    assert len(provider.instances) == 1 and len(provider.instances[0].requests) == 1


def test_bad_pin_preserves_evidence_and_prevents_socket(inputs, monkeypatch, capsys):
    monkeypatch.setattr(qwen, '_LiteralLoopbackHTTPConnection', forbid)
    args = enable(inputs)
    args[-1] = '0'*64
    assert triage.main(args) == 3
    value = json.loads(capsys.readouterr().out)
    assert value['dossier'] == build_anomaly_dossier(REQUEST['input'])
    assert value['ai']['reason_code'] == 'REGISTRY_FINGERPRINT_MISMATCH'
    assert value['provider_request_performed'] is False


def test_provider_timeout_keeps_evidence_and_never_retries(inputs, provider, capsys):
    provider.request_error = TimeoutError('SECRET')
    assert triage.main(enable(inputs)) == 3
    output = capsys.readouterr().out
    value = json.loads(output)
    assert 'SECRET' not in output
    assert value['dossier'] == build_anomaly_dossier(REQUEST['input'])
    assert value['ai']['outcome'] == 'ERROR'
    assert len(provider.instances) == 1


def test_unexpected_provider_escape_records_unknown_without_losing_evidence(inputs, monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise RuntimeError('SECRET')
    monkeypatch.setattr(triage, 'invoke_qwen_anomaly_advisory', fail)
    assert triage.main(enable(inputs)) == 3
    output = capsys.readouterr().out
    value = json.loads(output)
    assert value['provider_request_performed'] is None
    assert value['ai']['reason_code'] == 'PROVIDER_COMPLETION_UNKNOWN'
    assert value['dossier']['candidate_count'] == 2 and 'SECRET' not in output


def test_no_candidates_never_reads_registry_or_starts_provider(inputs, tmp_path, monkeypatch, capsys):
    (tmp_path / 'current.json').write_text((tmp_path / 'reference.json').read_text())
    (tmp_path / 'registry.json').unlink()
    monkeypatch.setattr(triage, 'invoke_qwen_anomaly_advisory', forbid)
    assert triage.main(enable(inputs)) == 0
    value = json.loads(capsys.readouterr().out)
    assert value['dossier']['status'] == 'no_candidates'
    assert value['ai']['reason_code'] == 'EVIDENCE_NOT_ELIGIBLE'
    assert value['provider_request_performed'] is False


def test_missing_registry_is_isolated_from_evidence(inputs, tmp_path, capsys):
    (tmp_path / 'registry.json').unlink()
    assert triage.main(enable(inputs)) == 3
    value = json.loads(capsys.readouterr().out)
    assert value['dossier']['candidate_count'] == 2
    assert value['ai']['reason_code'] == 'LOCAL_REGISTRY_UNAVAILABLE'


@pytest.mark.parametrize('raw', [b'{"schema":1,"schema":2}', b'\xffSECRET', b' '*8193,
                                  b'{"schema":"offline-anomaly-windows-v1","prompt":"SECRET"}'])
def test_malformed_windows_fail_before_any_provider(inputs, tmp_path, monkeypatch, capsys, raw):
    (tmp_path / 'windows.json').write_bytes(raw)
    monkeypatch.setattr(triage, 'invoke_qwen_anomaly_advisory', forbid)
    assert triage.main(enable(inputs)) == 1
    output = capsys.readouterr().out
    value = json.loads(output)
    assert value['status'] == 'failed' and 'dossier' not in value
    assert 'SECRET' not in output and value['provider_request_performed'] is False


def test_symlink_and_traversal_are_denied(inputs, tmp_path, capsys):
    (tmp_path / 'windows.json').unlink()
    (tmp_path / 'windows.json').symlink_to('current.json')
    assert triage.main(inputs) == 1
    assert json.loads(capsys.readouterr().out)['reason_code'] == 'INPUT_IO_ERROR'
    args = list(inputs)
    args[-1] = '../SECRET'
    assert triage.main(args) == 1
    assert 'SECRET' not in capsys.readouterr().out


@pytest.mark.parametrize('extra', [
    ['--qwen'], ['--registry', 'SECRET'], ['--prompt', 'SECRET'],
    ['--reference', 'SECRET'], ['--qwen', '--qwen'], ['--question-type', 'run_commands'],
])
def test_argument_refusals_do_not_echo_values_or_open_files(inputs, monkeypatch, capsys, extra):
    monkeypatch.setattr(triage, '_read_small_json', forbid)
    with pytest.raises(SystemExit) as exc:
        triage.main(inputs + extra)
    assert exc.value.code == 2
    output = capsys.readouterr()
    assert 'SECRET' not in output.err
    assert json.loads(output.err)['reason_code'] == 'INVALID_ARGUMENTS'


def test_privilege_gate_precedes_selected_file_reads(monkeypatch, capsys):
    def denied():
        raise OfflineError('NON_ROOT_REQUIRED')
    monkeypatch.setattr(triage, 'require_unprivileged_linux', denied)
    monkeypatch.setattr(triage, '_read_small_json', forbid)
    assert triage.main(['--input-root', '/SECRET', '--reference', 'r', '--current', 'c', '--windows', 'w']) == 1
    assert json.loads(capsys.readouterr().out)['reason_code'] == 'NON_ROOT_REQUIRED'


@pytest.mark.skipif(sys.platform != 'linux' or os.getuid() == 0 or os.geteuid() == 0,
                    reason='requires a real non-root Linux process')
def test_real_nonroot_capability_free_command_acceptance():
    with tempfile.TemporaryDirectory(prefix='megalodon-triage-', dir='/tmp') as directory:
        root = Path(directory)
        root.chmod(0o755)
        args = write_inputs(root)
        for path in root.iterdir():
            path.chmod(0o644)  # Public synthetic fixtures only.
        result = subprocess.run([sys.executable, '-m', 'megalodon.offline.triage', *args],
                                cwd=Path(__file__).parents[1], capture_output=True,
                                text=True, timeout=15)
        assert result.returncode == 0, result.stderr + result.stdout
        value = json.loads(result.stdout)
        assert value['dossier']['candidate_count'] == 2
        assert value['provider_request_performed'] is False
