"""Cross-policy completion, display and triage failure-isolation regression."""

import builtins
from dataclasses import replace
import json
from pathlib import Path
import socket
import sqlite3
import subprocess

import pytest

from megalodon import qwen_advisory as qwen
from megalodon.anomaly_advisory import POLICY_VERSION
from megalodon.dashboard import advisory_receipt_snapshot
from megalodon.offline import triage
from megalodon.offline.anomaly import build_anomaly_dossier
from test_anomaly_advisory import REQUEST, admit, invoke as anomaly_invoke
from test_anomaly_triage import inputs, provider, enable
from test_dashboard_advisory_receipt import _result
from test_local_model_advisory_contract import validator
from test_qwen_advisory import FakeResponse, invoke as original_invoke


@pytest.mark.parametrize('invoke', [original_invoke, anomaly_invoke])
@pytest.mark.parametrize('field,value', [
    ('done_reason', 'length'), ('done_reason', 'load'), ('done_reason', 'unload'),
    ('done_reason', 'cancelled'), ('done_reason', 'unknown'), ('done_reason', ''),
    ('done_reason', None), ('done_reason', True), ('done_reason', ['stop']),
    ('thinking', None), ('created_at', None), ('context', None),
])
def test_non_normal_completion_and_null_metadata_never_publish_partial_text(invoke, field, value, provider):
    payload = {'model': 'local:qwen-approved-v1', 'done': True, 'response': 'SECRET partial output'}
    payload[field] = value
    provider.next_response = FakeResponse(payload)
    result = invoke()
    assert result.outcome == 'ERROR' and result.reason_code == 'PROVIDER_RESPONSE_INVALID'
    assert result.provider_request_performed is True and result.output_bytes == 0
    assert 'SECRET' not in json.dumps(result.to_dict())
    assert len(provider.instances) == 1 and len(provider.instances[0].requests) == 1
    assert provider.instances[0].closed
    assert qwen._INVOCATION_LOCK.acquire(blocking=False)
    qwen._INVOCATION_LOCK.release()


@pytest.mark.parametrize('invoke', [original_invoke, anomaly_invoke])
@pytest.mark.parametrize('metadata', [{}, {'done_reason': 'stop'},
    {'done_reason': 'stop', 'thinking': '', 'context': [], 'created_at': '2026-09-15T00:00:00Z'}])
def test_normal_stop_and_legacy_omission_keep_existing_valid_outputs(invoke, metadata, provider):
    provider.next_response = FakeResponse(dict(
        model='local:qwen-approved-v1', done=True, response='Café 中文 🙂\n\tNo verdict.', **metadata))
    result = invoke()
    assert result.outcome == 'ANSWER' and result.summary == 'Café 中文 🙂 No verdict.'
    owned = qwen.validated_qwen_result(result, policy_version=result.policy_version)
    assert owned == result and owned is not result


CONTROLS = [chr(code) for code in (*range(32), *range(127, 160), 0x61c, 0x200e, 0x200f,
                                  *range(0x2028, 0x202f), *range(0x2066, 0x206a),
                                  0xd800, 0xdfff, 0xfeff)]


def test_python_and_contract_reject_control_spoofing_but_keep_language_and_emoji():
    text_validator = validator('boundedText')
    for char in CONTROLS:
        text = 'claim' + char + 'counterclaim'
        assert not qwen.bounded_advisory_text(text), repr(char)
        assert not text_validator.is_valid(text), repr(char)
        with pytest.raises(ValueError, match='^dashboard advisory receipt is invalid$'):
            advisory_receipt_snapshot(_result(summary=text))
        with pytest.raises(ValueError):
            advisory_receipt_snapshot(_result(limitations=(text,)))
    for text in ['Café 中文 العربية', '👩\u200d💻', '<b>inert text</b>', '🙂' * 1200]:
        assert qwen.bounded_advisory_text(text)
        assert text_validator.is_valid(text)
    for text in ['', ' ', '\u00a0', '🙂' * 1201]:
        assert not qwen.bounded_advisory_text(text)
        assert not text_validator.is_valid(text)


@pytest.mark.parametrize('invoke', [original_invoke, anomaly_invoke])
@pytest.mark.parametrize('text', ['safe\u202eunsafe', 'safe\x85unsafe', 'safe\x1cunsafe', 'safe\ufeffunsafe'])
def test_provider_controls_are_rejected_before_whitespace_normalization(invoke, text, provider):
    provider.next_response = FakeResponse({'model': 'local:qwen-approved-v1', 'done': True, 'response': text})
    result = invoke()
    assert result.outcome == 'ERROR' and result.reason_code == 'PROVIDER_RESPONSE_INVALID'
    assert result.provider_request_performed is True and result.output_bytes == 0


def test_result_validation_owns_accounting_without_invoking_input_methods(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('result validation performed I/O or invoked untrusted methods')
    class Hostile:
        to_dict = forbidden
        __getattr__ = forbidden
    class HostileText(str):
        __eq__ = forbidden
        __hash__ = forbidden
        strip = forbidden
    for obj, name in [(builtins, 'open'), (Path, 'open'), (socket, 'socket'),
                      (socket, 'getaddrinfo'), (sqlite3, 'connect'), (subprocess, 'Popen')]:
        monkeypatch.setattr(obj, name, forbidden)
    original = _result()
    owned = qwen.validated_qwen_result(original)
    object.__setattr__(original, 'summary', 'changed later')
    assert owned.summary != original.summary
    for bad in [Hostile(), {}, None, _result(summary=HostileText('SECRET')),
                _result(policy_version=HostileText('local-model-advisory-v1')),
                _result(code=HostileText('ADVISORY_ANSWER')),
                _result(outcome='ERROR', code='LOCAL_PROVIDER_ERROR', output_bytes=1),
                _result(provider_request_performed=False),
                _result(output_bytes=1), _result(summary='🙂', output_bytes=3),
                _result(prompt_bytes=True), _result(output_bytes=True)]:
        with pytest.raises(ValueError, match='^Qwen advisory result is invalid$'):
            qwen.validated_qwen_result(bad)


@pytest.mark.parametrize('case', ['none', 'dict', 'hostile', 'wrong-policy', 'wrong-model',
    'wrong-digest', 'bad-summary', 'bad-accounting', 'admitted-preflight', 'denial-requested',
    'denial-reason'])
def test_malformed_provider_returns_keep_identical_evidence_and_unknown_accounting(case, inputs, monkeypatch, capsys):
    class Hostile:
        def to_dict(self):
            pytest.fail('untrusted result method executed')
    valid = _result(policy_version=POLICY_VERSION,
                    model_artifact_sha256=REQUEST['model_receipt']['model_artifact_sha256'])
    denied = admit(fingerprint='0' * 64)
    bad = {'none': None, 'dict': {}, 'hostile': Hostile(),
           'wrong-policy': replace(valid, policy_version='local-model-advisory-v1'),
           'wrong-model': replace(valid, model_id='local:qwen-substituted'),
           'wrong-digest': replace(valid, model_artifact_sha256='f' * 64),
           'bad-summary': replace(valid, summary=['SECRET']),
           'bad-accounting': replace(valid, provider_request_performed='SECRET'),
           'admitted-preflight': admit(),
           'denial-requested': replace(denied, provider_request_performed=True),
           'denial-reason': replace(denied, reason_code=['SECRET'])}[case]
    calls = []
    def returned(*args, **kwargs):
        calls.append(1)
        return bad
    monkeypatch.setattr(triage, 'invoke_qwen_anomaly_advisory', returned)
    assert triage.main(enable(inputs)) == 3
    output = capsys.readouterr().out
    value = json.loads(output)
    assert value['dossier'] == build_anomaly_dossier(REQUEST['input'])
    assert value['ai']['outcome'] == 'ERROR'
    assert value['ai']['reason_code'] == 'PROVIDER_COMPLETION_UNKNOWN'
    assert value['provider_request_performed'] is None
    assert value['action_status'] == value['persistence_status'] == 'not_attempted'
    assert len(output.encode('ascii')) <= triage.MAX_RECEIPT_BYTES
    assert 'SECRET' not in output and calls == [1]


def test_truncated_provider_reply_keeps_dossier_and_known_request_state(inputs, provider, capsys):
    provider.next_response = FakeResponse({'model': 'local:qwen-approved-v1', 'done': True,
                                           'done_reason': 'length', 'response': 'SECRET partial'})
    assert triage.main(enable(inputs)) == 3
    output = capsys.readouterr().out
    value = json.loads(output)
    assert value['dossier'] == build_anomaly_dossier(REQUEST['input'])
    assert value['provider_request_performed'] is True
    assert value['ai']['reason_code'] == 'PROVIDER_RESPONSE_INVALID'
    assert 'SECRET' not in output and len(provider.instances) == 1


def test_serialization_failure_stays_inside_evidence_boundary(inputs, provider, monkeypatch, capsys):
    original = triage._json
    def serialize(value):
        if 'model_receipt' in value:
            raise ValueError('SECRET serialization failure')
        return original(value)
    monkeypatch.setattr(triage, '_json', serialize)
    assert triage.main(enable(inputs)) == 3
    output = capsys.readouterr().out
    value = json.loads(output)
    assert value['dossier'] == build_anomaly_dossier(REQUEST['input'])
    assert value['provider_request_performed'] is None
    assert value['ai']['reason_code'] == 'PROVIDER_COMPLETION_UNKNOWN'
    assert 'SECRET' not in output and len(provider.instances) == 1


@pytest.mark.parametrize('field', ['model_id', 'model_artifact_sha256'])
@pytest.mark.parametrize('suffix', ['\n', '\r', '\u2028', '\u2029'])
def test_schema_and_runtime_require_full_model_tokens(field, suffix):
    result = _result()
    value = result.to_dict()
    value['model_receipt'][field] += suffix
    assert not validator('advisoryResult').is_valid(value)
    with pytest.raises(ValueError):
        qwen.validated_qwen_result(replace(result, **{field: getattr(result, field) + suffix}))
