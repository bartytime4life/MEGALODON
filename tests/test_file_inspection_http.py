"""Real HTTP envelope, with an inert inspection provider."""
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import base64
import os
import secrets
from threading import Thread, Lock
from types import SimpleNamespace

import pytest

from megalodon.dashboard import DashboardHandler
from megalodon.file_inspection import InspectionBusy


@pytest.fixture
def http(monkeypatch):
    calls = []
    class Inspector:
        snapshots = 0
        def snapshot(self):
            self.snapshots += 1
            return {'state': 'idle'}
        def reserve(self, size):
            calls.append(('reserve', size))
            return 'a' * 32, os.memfd_create('test-inspection'), '/unused'
        def receiving_cancelled(self, job):
            return False
        def submit(self, job, fd, size, root):
            os.lseek(fd, 0, 0)
            calls.append(('submit', os.read(fd, size)))
            return False
        def abort(self, job):
            calls.append(('abort',))
        def cancel(self):
            calls.append(('cancel',))
    inspector = Inspector()
    configuration = SimpleNamespace(token=secrets.token_urlsafe(24))
    password = 'synthetic-inspector-password'
    authorization = 'Basic ' + base64.b64encode(('megalodon:' + password).encode()).decode()
    handler = type('InspectionHandler', (DashboardHandler,), dict(
        file_inspection=inspector, support_config=configuration, maintenance_lock=Lock(),
        http_read_password=password, http_password_verifier=None))
    monkeypatch.setattr('megalodon.dashboard._tool_management_user', lambda: True)
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    def request(method='POST', path='/api/file-inspection/run', body=b'data', omit=(), extra=()):
        host = f'127.0.0.1:{server.server_port}'
        headers = [('Host', host), ('X-Megalodon-Check', '1'), ('Authorization', authorization)]
        if method == 'POST':
            headers += [('Origin', 'http://' + host), ('X-Megalodon-Config-Token', configuration.token),
                        ('Content-Type', 'application/json' if path.endswith('/cancel') else 'application/octet-stream'),
                        ('Content-Length', str(len(body)))]
        connection = HTTPConnection('127.0.0.1', server.server_port, timeout=3)
        connection.putrequest(method, path, skip_host=True)
        for key, value in headers:
            if key not in omit:
                connection.putheader(key, value)
        for key, value in extra:
            connection.putheader(key, value)
        connection.endheaders(body if method == 'POST' else None)
        response = connection.getresponse()
        result = response.status, response.read()
        connection.close()
        return result
    yield SimpleNamespace(request=request, calls=calls, inspector=inspector, handler=handler, server=server,
                          password=password)
    server.shutdown()
    server.server_close()
    worker.join(3)


def test_local_read_never_starts_job(http):
    assert http.request('GET', '/api/file-inspection')[0] == 200
    assert http.calls == []


@pytest.mark.parametrize('method,path,body', [
    ('GET', '/api/file-inspection', b''),
    ('POST', '/api/file-inspection/run', b'data'),
    ('POST', '/api/file-inspection/cancel', b'{}'),
])
def test_inspection_refuses_a_hud_without_sign_in(http, monkeypatch, method, path, body):
    monkeypatch.setattr(http.handler, 'http_read_password', None)
    monkeypatch.setattr(http.handler, 'http_password_verifier', None)
    status, response = http.request(method, path, body)
    assert status == 403
    assert b'file_inspection_sign_in_required' in response
    assert b'token' not in response
    assert http.calls == []
    assert http.inspector.snapshots == 0


@pytest.mark.parametrize('missing', ['service', 'configuration', 'operator'])
@pytest.mark.parametrize('method,path', [('GET', '/api/file-inspection'), ('POST', '/api/file-inspection/run')])
def test_inspection_context_refuses_before_access(http, monkeypatch, missing, method, path):
    if missing == 'operator':
        monkeypatch.setattr('megalodon.dashboard._tool_management_user', lambda: False)
    else:
        monkeypatch.setattr(http.handler, 'file_inspection' if missing == 'service' else 'support_config', None)
    status, response = http.request(method, path)
    assert status == 403
    assert b'token' not in response
    assert http.calls == []
    assert http.inspector.snapshots == 0


def test_submission_is_explicit_and_only_bytes_are_passed(http):
    assert http.request()[0] == 202
    assert http.calls == [('reserve', 4), ('submit', b'data')]


@pytest.mark.parametrize('name', ['Host', 'Origin', 'X-Megalodon-Check', 'X-Megalodon-Config-Token', 'Content-Type', 'Content-Length'])
def test_missing_headers_precede_reservation(http, name):
    assert http.request(omit=(name,))[0] in (400, 403, 413)
    assert http.calls == []


@pytest.mark.parametrize('extra', [[('Origin', 'http://evil.test')], [('Host', 'evil.test')],
    [('X-Megalodon-Config-Token', 'c' * 32)], [('X-Megalodon-Check', '1')],
    [('Content-Type', 'application/octet-stream')], [('Content-Length', '4')],
    [('Transfer-Encoding', 'chunked')], [('Content-Encoding', 'gzip')]])
def test_ambiguous_envelopes_precede_reservation(http, extra):
    assert http.request(extra=extra)[0] in (400, 403, 413)
    assert http.calls == []


@pytest.mark.parametrize('length', ['0', '-1', '67108865', '999999999', 'NaN', '４'])
def test_invalid_declared_lengths_precede_reservation(http, length):
    if not length.isascii():
        return  # HTTP headers are Latin-1; server also requires ASCII.
    assert http.request(omit=('Content-Length',), extra=[('Content-Length', length)])[0] == 413
    assert http.calls == []


def test_cancel_bypasses_maintenance_lock_and_requires_exact_body(http):
    http.handler.maintenance_lock.acquire()
    try:
        assert http.request(path='/api/file-inspection/cancel', body=b'{}')[0] == 202
    finally:
        http.handler.maintenance_lock.release()
    assert http.calls == [('cancel',)]
    assert http.request(path='/api/file-inspection/cancel', body=b'{ }')[0] == 400


def test_core_authentication_still_precedes_file_submission(http, monkeypatch):
    monkeypatch.setattr(http.handler, 'http_read_password', 'synthetic-test-password')
    assert http.request(omit=('Authorization',))[0] == 401
    assert http.request('GET', '/api/file-inspection', omit=('Authorization',))[0] == 401
    assert http.request(path='/api/file-inspection/cancel', body=b'{}', omit=('Authorization',))[0] == 401
    assert http.calls == []
    assert http.inspector.snapshots == 0
    authorization = 'Basic ' + base64.b64encode(b'megalodon:synthetic-test-password').decode()
    assert http.request(omit=('Authorization',), extra=[('Authorization', authorization)])[0] == 202
    assert http.calls == [('reserve', 4), ('submit', b'data')]


@pytest.mark.parametrize('mode', ['saved_password', 'session_cookie'])
def test_existing_saved_password_and_session_authentication(http, monkeypatch, mode):
    from megalodon.hud_password import PasswordVerifier
    monkeypatch.setattr(http.handler, 'http_read_password', None)
    monkeypatch.setattr(http.handler, 'http_password_verifier', PasswordVerifier.from_password(http.password))
    options = {}
    if mode == 'session_cookie':
        token = secrets.token_urlsafe(32)
        monkeypatch.setattr(http.handler, 'http_session_token', token)
        options = dict(omit=('Authorization',), extra=[('Cookie', f'megalodon_session_{http.server.server_port}={token}')])
    assert http.request('GET', '/api/file-inspection', **options)[0] == 200
    assert http.request(**options)[0] == 202
    assert http.request(path='/api/file-inspection/cancel', body=b'{}', **options)[0] == 202
    assert http.calls == [('reserve', 4), ('submit', b'data'), ('cancel',)]


def test_busy_rejects_without_consuming_body(http, monkeypatch):
    def busy(_):
        raise InspectionBusy
    monkeypatch.setattr(http.inspector, 'reserve', busy)
    assert http.request()[0] == 409
    assert http.calls == []


def test_short_upload_aborts_reservation(http):
    assert http.request(omit=('Content-Length',), extra=[('Content-Length', '5')])[0] == 422
    assert http.calls == [('reserve', 5), ('abort',)]
