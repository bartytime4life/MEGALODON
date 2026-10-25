"""Real loopback routing with inert findings providers; no model or host actions."""
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from threading import Lock, Thread
from types import SimpleNamespace

import pytest

from megalodon.dashboard import DashboardHandler
from megalodon.findings_review import FindingsBusy


@pytest.fixture
def api(monkeypatch):
    calls = []
    def snapshot(**query):
        calls.append(('read', query))
        if set(query)-{'start', 'end', 'source', 'severity', 'limit', 'cursor', 'selected'}:
            raise ValueError('Unknown query')
        return dict(schema='megalodon-findings-v1', items=[])
    def action(body):
        calls.append(('action', body))
        return dict(schema='megalodon-findings-action-v1', job=dict(state='running'))
    provider = SimpleNamespace(token='a'*32, snapshot=snapshot, action=action)
    handler = type('FindingsHandler', (DashboardHandler,), dict(findings_review=provider,
        findings_read_lock=Lock(), maintenance_lock=Lock(), http_read_password=None, http_password_verifier=None))
    monkeypatch.setattr('megalodon.dashboard._tool_management_user', lambda: True)
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    worker = Thread(target=server.serve_forever, daemon=True); worker.start()
    def request(method, path='/api/findings', body=None, omit=(), extra=()):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode() if body is not None else None
        host = f'127.0.0.1:{server.server_port}'
        headers = [('Host', host), ('X-Megalodon-Check', '1')] if method == 'GET' else [
            ('Host', host), ('Origin', 'http://'+host), ('Content-Type', 'application/json'),
            ('X-Megalodon-Findings-Token', provider.token), ('Content-Length', str(len(raw or b'')))]
        connection = HTTPConnection('127.0.0.1', server.server_port, timeout=2)
        connection.putrequest(method, path, skip_host=True)
        for name, value in headers:
            if name not in omit:
                connection.putheader(name, value)
        for name, value in extra:
            connection.putheader(name, value)
        connection.endheaders(raw)
        response = connection.getresponse(); result = response.status, json.loads(response.read())
        connection.close(); return result
    yield SimpleNamespace(request=request, provider=provider, calls=calls, handler=handler)
    server.shutdown(); server.server_close(); worker.join(2)


def test_get_is_only_a_read_and_post_queues_closed_action(api):
    assert api.request('GET', '/api/findings?source=detector&limit=25')[0] == 200
    assert api.calls == [('read', dict(source='detector', limit='25'))]
    assert api.request('POST', body=dict(action='cancel'))[0] == 202
    assert api.calls[-1] == ('action', dict(action='cancel'))


@pytest.mark.parametrize('omit,extra', [
    (['X-Megalodon-Findings-Token'], []),
    (['X-Megalodon-Findings-Token'], [('X-Megalodon-Defense-Token', 'a'*32)]),
    (['Origin'], [('Origin', 'http://foreign.invalid')]),
    ([], [('Origin', 'http://duplicate.invalid')]),
    ([], [('X-Megalodon-Findings-Token', 'b'*32)]),
    ([], [('Content-Encoding', 'gzip')]),
    (['Content-Type'], [('Content-Type', 'text/plain')]),
])
def test_mutation_requires_exact_service_token_and_origin(api, omit, extra):
    assert api.request('POST', body=dict(action='cancel'), omit=omit, extra=extra)[0] == 403
    assert api.calls == []


@pytest.mark.parametrize('body', [
    b'{"action":"cancel","action":"analyze"}',
    {'action': 'cancel', 'ip': '1.1.1.1'},
    {'action': 'apply_containment', 'plan_id': 'e'*32},
    {'action': 'apply_containment', 'plan_id': 'e'*32, 'acknowledge_disruption': 1},
    {'action': 'execute', 'command': 'anything'},
])
def test_ambiguous_or_unacknowledged_action_cannot_reach_service(api, body):
    assert api.request('POST', body=body)[0] == 400
    assert api.calls == []


def test_literal_acknowledgment_is_preserved_for_service_revalidation(api):
    body = dict(action='apply_containment', plan_id='e'*32, acknowledge_disruption=True)
    assert api.request('POST', body=body)[0] == 202
    assert api.calls == [('action', body)]


def test_get_requires_explicit_header_and_rejects_ambiguous_query(api):
    assert api.request('GET', omit=['X-Megalodon-Check'])[0] == 403
    assert api.request('GET', '/api/findings?source=sensor&source=pattern')[0] == 422
    assert api.calls == []
    assert api.request('GET', '/api/findings?path=arbitrary')[0] == 422


def test_concurrent_read_and_busy_review_have_explicit_states(api):
    api.handler.findings_read_lock.acquire()
    try:
        assert api.request('GET')[0] == 409
    finally:
        api.handler.findings_read_lock.release()
    api.provider.action = lambda body: (_ for _ in ()).throw(FindingsBusy('Busy'))
    assert api.request('POST', body=dict(action='cancel'))[0] == 409


def test_response_bound_and_service_context_refusal_are_finite(api):
    api.provider.snapshot = lambda **query: {'data': 'x'*262144}
    assert api.request('GET')[0] == 422
    api.provider.action = lambda body: (_ for _ in ()).throw(ValueError('Expired preview'))
    assert api.request('POST', body=dict(action='apply_containment', plan_id='e'*32, acknowledge_disruption=True))[0] == 422
