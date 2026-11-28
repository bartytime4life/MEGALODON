"""Request-scoped cancellation uses synthetic HTTP/provider/DOMs only."""
from contextlib import contextmanager
import json
from pathlib import Path
import shutil
import subprocess
import threading

import pytest

from megalodon import ai_provider as provider
from megalodon.config import AISettings
from megalodon.dashboard import DashboardHandler
from megalodon.dashboard_ai_assets import AI_JS


@pytest.fixture(autouse=True)
def isolated_request_ids(monkeypatch):
    # Provider bookkeeping is process-local; each synthetic case owns its IDs.
    monkeypatch.setattr(provider, '_operator_ids', provider.OrderedDict())


def test_browser_cancellation_is_scoped_bounded_and_truthful():
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node required for the inert cancellation harness')
    result = subprocess.run([node, str(Path(__file__).with_name('ai_cancellation_browser.cjs'))],
                            input=AI_JS, text=True, capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr


def test_cancelled_old_id_cannot_interrupt_the_new_provider_call(monkeypatch, synthetic_runtime_binding):
    entered, release = threading.Event(), threading.Event()
    outcomes = []

    def fake_generate(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        assert not provider._request_context.cancel.is_set()
        return 'Synthetic completion'

    monkeypatch.setattr(provider, '_generate', fake_generate)
    first, second = '1'*32, '2'*32
    with provider.operator_request(request_id=first):
        pass

    def worker():
        with provider.operator_request(request_id=second):
            outcomes.append(provider.generate(AISettings(enabled=True), 'Synthetic data'))

    thread = threading.Thread(target=worker)
    thread.start()
    try:
        assert entered.wait(2)
        assert provider.cancel_operator(request_id=first) is False
        assert not provider._active_cancel.is_set()
    finally:
        release.set()
        thread.join(3)
    assert not thread.is_alive() and outcomes == ['Synthetic completion']


def test_scoped_cancel_matches_one_event_and_survives_between_calls(synthetic_runtime_binding, monkeypatch):
    seen = []
    monkeypatch.setattr(provider, '_generate', lambda *a, **kw: seen.append('inference') or 'READY')
    with provider.operator_request(request_id='3'*32) as first:
        with provider.operator_request(request_id='4'*32) as second:
            assert provider.cancel_operator(request_id='3'*32)
            assert first.is_set() and not second.is_set()
            assert provider.generate(AISettings(enabled=True), 'Synthetic data') == 'READY'
        for _ in range(2):
            with pytest.raises(provider.AIProviderError, match='REQUEST_CANCELLED'):
                provider.generate(AISettings(enabled=True), 'Synthetic data')
    assert seen == ['inference']


def test_duplicate_active_identity_is_refused_without_replacing_original():
    with provider.operator_request(request_id='5'*32) as first:
        with pytest.raises(provider.AIProviderError, match='POLICY_REJECTION'):
            with provider.operator_request(request_id='5'*32):
                pytest.fail('Duplicate identity was admitted')
        assert provider.cancel_operator(request_id='5'*32)
        assert first.is_set()


@pytest.mark.parametrize('value', ['', 'x'*32, 'a'*31, 'A'*32, 12, True, ['a'*32]])
def test_invalid_id_is_refused_before_registration(value):
    before = dict(provider._operator_events)
    with pytest.raises(provider.AIProviderError, match='POLICY_REJECTION'):
        with provider.operator_request(request_id=value):
            pytest.fail('Invalid identity admitted')
    with pytest.raises(provider.AIProviderError, match='POLICY_REJECTION'):
        provider.cancel_operator(request_id=value)
    assert provider._operator_events == before


def test_pre_cancel_is_bounded_and_expires(monkeypatch, synthetic_runtime_binding):
    monkeypatch.setattr(provider, '_operator_ids', provider.OrderedDict())
    clock = [100.0]
    monkeypatch.setattr(provider.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(provider, '_generate', lambda *a, **kw: pytest.fail('Pre-cancelled request reached inference'))
    identifier = '6'*32
    assert provider.cancel_operator(request_id=identifier) is False
    with provider.operator_request(request_id=identifier) as event:
        assert event.is_set()
        with pytest.raises(provider.AIProviderError, match='REQUEST_CANCELLED'):
            provider.generate(AISettings(enabled=True), 'Synthetic data')
    for i in range(provider._OPERATOR_ID_BUDGET + 20):
        provider.cancel_operator(request_id=f'{i+100:032x}')
    assert len(provider._operator_ids) == provider._OPERATOR_ID_BUDGET
    assert identifier in provider._operator_ids, 'Unexpired reservations are not evicted for newer IDs'
    clock[0] += provider._OPERATOR_CANCEL_GRACE_SECONDS
    with provider.operator_request(request_id=identifier) as event:
        assert not event.is_set()
    assert set(provider._operator_ids) == {identifier}
    assert provider._operator_ids[identifier][0] == 'finished'


@contextmanager
def http_server(**extra):
    from http.server import ThreadingHTTPServer
    handler = type('ScopedAIHandler', (DashboardHandler,), dict(store=object(),
        ai_settings=AISettings(enabled=True), ai_operator_token='synthetic-token', **extra))
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown(); server.server_close(); thread.join(2)


def request(server, path, *, method='GET', body=None, headers=None):
    from http.client import HTTPConnection
    connection = HTTPConnection('127.0.0.1', server.server_port, timeout=3)
    try:
        defaults = {'X-Megalodon-AI-Token':'synthetic-token',
                    'Origin':f'http://127.0.0.1:{server.server_port}',
                    'Content-Type':'application/json', 'X-Megalodon-AI-Check':'1'}
        connection.request(method, path, headers=defaults | (headers or {}), body=body)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def test_http_id_binds_verify_and_question_before_inference(monkeypatch, tmp_path, synthetic_runtime_binding):
    seen = []
    def record():
        event = provider._request_context.operator
        seen.append(provider._operator_events[event])
    def status(*args, **kwargs):
        record()
        return dict(schema='megalodon-ai-status-v1',state='model_ready')
    def ask(*args, **kwargs):
        record()
        return dict(schema='megalodon-ai-answer-v1', observed={})
    monkeypatch.setattr(provider, 'status', status)
    monkeypatch.setattr('megalodon.ai_interface.ask', ask)
    with http_server(ai_receipt_path=tmp_path/'synthetic.db') as server:
        headers = {'X-Megalodon-AI-Request':'7'*32}
        assert request(server, '/api/ai/status', headers=headers)[0] == 200
        assert request(server, '/api/ai/ask', method='POST', body='{"question":"seeing"}', headers={'X-Megalodon-AI-Request':'a'*32})[0] == 200
        for invalid in ('bad', 'A'*32, '7'*31, '7'*33):
            assert request(server, '/api/ai/status', headers={'X-Megalodon-AI-Request':invalid})[0] == 400
            assert request(server, '/api/ai/ask', method='POST', body='{"question":"seeing"}', headers={'X-Megalodon-AI-Request':invalid})[0] == 503
        assert seen == ['7'*32, 'a'*32]


def test_http_scoped_cancel_keeps_legacy_auth_and_body_bounds(monkeypatch):
    seen = []
    monkeypatch.setattr(provider, 'cancel_operator', lambda **kw: seen.append(kw) or True)
    with http_server() as server:
        exact = json.dumps({'request_id':'8'*32})
        code, value = request(server, '/api/ai/cancel', method='POST', body=exact)
        assert code == 200 and value == dict(schema='megalodon-ai-cancel-v1',request_id='8'*32,cancelled=True)
        assert request(server, '/api/ai/cancel', method='POST', body='{}')[1] == dict(schema='megalodon-ai-cancel-v1',cancelled=True)
        for body in ('[]', '{"request_id":true}', '{"request_id":"bad"}', '{"request_id":"'+'8'*32+'","request_id":"'+'9'*32+'"}', '{"request_id":"'+'8'*32+'","extra":1}', ' '*97):
            assert request(server, '/api/ai/cancel', method='POST', body=body)[0] == 400
        assert request(server, '/api/ai/cancel', method='POST', body=exact, headers={'X-Megalodon-AI-Token':'wrong'})[0] == 403
        assert request(server, '/api/ai/cancel', method='POST', body=exact, headers={'Origin':'https://invalid.example'})[0] == 403
    assert seen == [{'request_id':'8'*32}, {}]


def test_request_id_never_lifts_unbound_provider_admission(monkeypatch):
    monkeypatch.setattr('megalodon.local_model_runtime.binding_failure', lambda: 'SYNTHETIC_UNBOUND')
    monkeypatch.setattr(provider, '_generate', lambda *a, **kw: pytest.fail('Unbound provider called'))
    with provider.operator_request(request_id='9'*32):
        value = provider.status(AISettings(enabled=True))
    assert value['state'] == 'unbound' and value['inference_verified'] is False


def test_completed_id_is_not_reused_during_grace(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(provider.time, 'monotonic', lambda: clock[0])
    identifier = 'c'*32
    with provider.operator_request(request_id=identifier):
        pass
    with pytest.raises(provider.AIProviderError, match='POLICY_REJECTION'):
        with provider.operator_request(request_id=identifier):
            pytest.fail('Completed identity was replayed')
    with provider.operator_request(request_id='d'*32) as current:
        assert provider.cancel_operator(request_id=identifier) is False
        assert not current.is_set()
    clock[0] += provider._OPERATOR_CANCEL_GRACE_SECONDS
    with provider.operator_request(request_id=identifier) as event:
        assert not event.is_set(), 'Replay guarantee is deliberately bounded by the grace interval'


def test_full_id_budget_refuses_admission_without_eviction():
    for i in range(provider._OPERATOR_ID_BUDGET):
        provider.cancel_operator(request_id=f'{i:032x}')
    with pytest.raises(provider.AIProviderError, match='POLICY_REJECTION'):
        with provider.operator_request(request_id='e'*32):
            pytest.fail('Full identity budget admitted another operation')
    assert len(provider._operator_ids) == provider._OPERATOR_ID_BUDGET


@pytest.mark.parametrize('body', [b'{}', b'{"request_id":"'+b'a'*32+b'"}'])
def test_cancel_short_body_never_dispatches_even_with_valid_json(monkeypatch, body):
    from email.message import Message
    from io import BytesIO
    calls, sent = [], []
    monkeypatch.setattr(provider, 'cancel_operator', lambda **kw: calls.append(kw) or True)
    handler = DashboardHandler.__new__(DashboardHandler)
    handler.headers = Message()
    handler.headers['Content-Length'] = str(len(body)+1)
    handler.rfile = BytesIO(body)
    handler.connection = type('Connection', (), {'settimeout': lambda *a: None})()
    handler._ai_operator_envelope = lambda: True
    handler._send_json = lambda value, status=200: sent.append((status,value))
    handler._ai_cancel()
    assert not calls and sent[0][0] == 400


def test_status_duplicate_header_and_active_identity_are_structured_refusals(monkeypatch, synthetic_runtime_binding):
    entered, release = threading.Event(), threading.Event()
    calls, results = [], []
    def slow_status(*args, **kwargs):
        calls.append('status'); entered.set()
        assert release.wait(3)
        return dict(schema='megalodon-ai-status-v1', state='model_ready')
    monkeypatch.setattr(provider, 'status', slow_status)
    with http_server() as server:
        identifier = 'f'*32
        worker = threading.Thread(target=lambda: results.append(request(server, '/api/ai/status', headers={'X-Megalodon-AI-Request':identifier})))
        worker.start()
        try:
            assert entered.wait(2)
            code, value = request(server, '/api/ai/status', headers={'X-Megalodon-AI-Request':identifier})
            assert code == 503 and value['error_code'] == 'POLICY_REJECTION'
            from http.client import HTTPConnection
            client = HTTPConnection('127.0.0.1', server.server_port, timeout=3)
            try:
                client.putrequest('GET', '/api/ai/status')
                client.putheader('X-Megalodon-AI-Check','1'); client.putheader('X-Megalodon-AI-Token','synthetic-token')
                client.putheader('X-Megalodon-AI-Request','a'*32); client.putheader('X-Megalodon-AI-Request','b'*32)
                client.endheaders(); response = client.getresponse()
                assert response.status == 400
                response.read()
            finally:
                client.close()
            assert calls == ['status']
        finally:
            release.set(); worker.join(3)
        assert results[0][0] == 200


def test_scoped_cancel_interrupts_only_matching_active_provider(monkeypatch, synthetic_runtime_binding):
    entered = threading.Event()
    outcomes = []
    identifier = 'b'*32
    def slow(*args, **kwargs):
        entered.set()
        if provider._request_context.cancel.wait(3):
            raise provider.AIProviderError('REQUEST_CANCELLED')
        pytest.fail('Matching scoped cancellation never reached the active call')
    monkeypatch.setattr(provider, '_generate', slow)
    def worker():
        with provider.operator_request(request_id=identifier):
            try:
                provider.generate(AISettings(enabled=True), 'Synthetic data')
            except provider.AIProviderError as error:
                outcomes.append(error.code)
    thread = threading.Thread(target=worker)
    thread.start()
    try:
        assert entered.wait(2)
        assert provider.cancel_operator(request_id='a'*32) is False
        assert not provider._active_cancel.is_set()
        assert provider.cancel_operator(request_id=identifier) is True
    finally:
        thread.join(3)
    assert not thread.is_alive() and outcomes == ['REQUEST_CANCELLED']
