"""The visible startup action has a fixed plan and no arbitrary execution input."""
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from threading import Event, Thread
from types import SimpleNamespace
import stat
import time

import pytest

from megalodon import dashboard, support_startup
from megalodon.companion_automation import CompanionAutomation, CompanionConfig
from megalodon.config import AISettings, DashboardSettings, Settings


@pytest.fixture
def endpoint(monkeypatch):
    monkeypatch.setattr(dashboard, '_tool_management_user', lambda: True)
    manager = support_startup.SupportApps()
    calls = []
    monkeypatch.setattr(manager, 'start', lambda: calls.append('start') or manager.snapshot())
    handler = type('SupportHandler', (dashboard.DashboardHandler,), {'support_startup': manager})
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
    thread.start()
    try:
        yield server, handler, manager, calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def request(endpoint, *, method='POST', path='/api/support-start', body=b'{"action":"start"}', extra=(), omit=()):
    server, _, manager, _ = endpoint
    origin = f'http://127.0.0.1:{server.server_port}'
    headers = [('Host', origin[7:]), ('Origin', origin), ('Content-Type', 'application/json'),
               ('Content-Length', str(len(body))), ('X-Megalodon-Check', '1'),
               ('X-Megalodon-Support-Token', manager.token)]
    client = HTTPConnection('127.0.0.1', server.server_port, timeout=3)
    try:
        client.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for key, value in headers:
            if key not in omit:
                client.putheader(key, value)
        for key, value in extra:
            client.putheader(key, value)
        client.endheaders(body)
        response = client.getresponse()
        return response.status, json.loads(response.read())
    finally:
        client.close()


def test_status_is_read_only_and_start_works_without_general_installer_token(endpoint):
    code, value = request(endpoint, method='GET', body=b'')
    assert code == 200 and value['token'] == endpoint[2].token
    assert value['command'] == support_startup.COMMAND
    assert endpoint[3] == []
    code, value = request(endpoint)
    assert code == 202 and 'token' not in value
    assert endpoint[3] == ['start']
    assert endpoint[1].tool_management_enabled is False
    assert endpoint[1].install_operator_token is None


def test_existing_desktop_app_route_keeps_its_catalog_and_operator_token(endpoint):
    handler = endpoint[1]
    launched = []
    handler.heartbeat = object()
    handler.support_app_launcher = SimpleNamespace(
        catalog=lambda: {'schema': 'megalodon-support-apps-v1', 'apps': []},
        launch=lambda app: launched.append(app) or
        {'app': app, 'state': 'launch_requested', 'window_verified': False},
    )
    handler.tool_management_enabled = True
    handler.install_operator_token = 'z' * 32

    code, value = request(endpoint, method='GET', path='/api/support-apps', body=b'')
    assert code == 200 and value == {'schema': 'megalodon-support-apps-v1', 'apps': []}
    assert endpoint[3] == []

    code, value = request(
        endpoint, path='/api/support-apps', body=b'{"app":"wireshark"}',
        extra=(('X-Megalodon-Install-Token', handler.install_operator_token),
               ('X-Megalodon-Support-App', '1')),
    )
    assert code == 202 and value['state'] == 'launch_requested'
    assert launched == ['wireshark']
    assert endpoint[3] == []


@pytest.mark.parametrize('extra,omit,expected', [
    ((), ('X-Megalodon-Support-Token',), 403),
    ((('X-Megalodon-Support-Token', 'x'*32),), ('X-Megalodon-Support-Token',), 403),
    ((('X-Megalodon-Support-Token', 'x'*32),), (), 403),
    ((('Origin', 'http://other.invalid'),), ('Origin',), 403),
    ((('Origin', 'http://other.invalid'),), (), 403),
    ((), ('Origin',), 403),
    ((('Content-Type', 'text/plain'),), ('Content-Type',), 403),
    ((('Content-Type', 'application/json'),), (), 403),
    ((('Transfer-Encoding', 'chunked'),), (), 403),
    ((('Content-Encoding', 'identity'),), (), 403),
    ((('Content-Length', '18'),), (), 400),
    ((('Content-Length', '65'),), ('Content-Length',), 400),
    ((('Content-Length', '-1'),), ('Content-Length',), 400),
    ((), ('Content-Length',), 400),
    ((('Host', 'other.invalid'),), ('Host',), 400),
])
def test_ambiguous_or_cross_site_start_rejected(endpoint, extra, omit, expected):
    assert request(endpoint, extra=extra, omit=omit)[0] == expected
    assert endpoint[3] == []


@pytest.mark.parametrize('body', [b'[]', b'null', b'bad', b'\xff', b'{"action":true}',
    b'{"action":"start","action":"start"}', b'{"action":"stop"}',
    b'{"action":"start","command":"id"}', b'{"action":"start","target":"10.0.0.1"}'])
def test_untrusted_execution_parameters_never_reach_launcher(endpoint, body):
    assert request(endpoint, body=body)[0] == 400
    assert endpoint[3] == []


@pytest.mark.parametrize('path', ['/api/support-start?x=1', '/api/support-start/', '/api/%73upport-apps', 'http://127.0.0.1/api/support-start'])
def test_post_aliases_rejected(endpoint, path):
    assert request(endpoint, path=path)[0] == 405
    assert endpoint[3] == []


def test_status_gates_and_busy(endpoint, monkeypatch):
    assert request(endpoint, method='GET', body=b'', omit=('X-Megalodon-Check',))[0] == 403
    assert request(endpoint, method='GET', body=b'', path='/api/support-start?x=1')[0] == 400
    def busy():
        raise support_startup.SupportBusy
    monkeypatch.setattr(endpoint[2], 'start', busy)
    assert request(endpoint)[0] == 409
    monkeypatch.setattr(dashboard, '_tool_management_user', lambda: False)
    assert request(endpoint)[0] == 403
    assert request(endpoint, method='GET', body=b'')[0] == 403
    monkeypatch.setattr(dashboard, '_tool_management_user', lambda: True)
    endpoint[1].support_startup = None
    assert request(endpoint)[0] == 403


def test_optional_http_signin_still_applies(endpoint):
    endpoint[1].http_read_password = 'test-only'
    assert request(endpoint)[0] == 401
    assert request(endpoint, method='GET', body=b'')[0] == 401
    assert endpoint[3] == []


def test_fixed_start_plan_skips_running_and_missing_tools(monkeypatch):
    calls, completed = [], []
    active = {'ollama.service', 'megalodon-support-wireshark.service'}
    def run(argv, **kwargs):
        assert kwargs['stdin'] == support_startup.subprocess.DEVNULL
        assert kwargs.get('shell') is None
        calls.append(argv)
        if 'is-active' in argv:
            return SimpleNamespace(returncode=0 if argv[-1] in active else 3)
        if argv[0] == '/bin/pkexec':
            active.add('suricata.service')
        return SimpleNamespace(returncode=0)
    def which(name):
        return None if name == 'clamtk' else '/bin/' + name
    monkeypatch.setattr(support_startup, 'service_unit', lambda tool: {'qwen':'ollama','suricata':'suricata'}[tool])
    monkeypatch.setattr(support_startup, '_trusted_system_executable', lambda name: '/bin/'+name)
    collectors = SimpleNamespace(request_collection=lambda: {'nmap':'queued','clamav':'missing','osquery':'running'})
    manager = support_startup.SupportApps(collectors, run=run, which=which, on_finish=lambda: completed.append(True))
    manager.start()
    manager._thread.join(2)
    value = manager.snapshot()
    assert value['state'] == 'finished' and completed == [True]
    items = {item['id']: item for item in value['items']}
    assert items['nmap']['state'] == 'queued'
    assert {'wireshark','clamtk','zenmap'}.isdisjoint(items)
    assert items['qwen']['state']=='running'
    assert not any('systemd-run' in argv[0] for argv in calls)
    assert all(item['state'] in {'queued','running','missing','launched','needs_setup','not_needed'} for item in value['items'])
    assert len(json.dumps(manager.snapshot(include_token=True))) < 32768
    assert len(value['items']) <= 16
    with pytest.raises(support_startup.SupportBusy):
        manager.start()


def test_privileged_start_rejects_untrusted_system_binary(monkeypatch):
    calls = []
    monkeypatch.setattr(support_startup, 'service_unit', lambda tool: tool)
    monkeypatch.setattr(support_startup, '_trusted_system_executable',
                        lambda name: None if name == 'systemctl' else '/usr/bin/pkexec')
    manager = support_startup.SupportApps(
        run=lambda argv, **kwargs: calls.append(argv) or SimpleNamespace(returncode=3),
        which=lambda name: '/tmp/user-bin/' + name)
    manager._services()
    assert not any('start' in argv for argv in calls)
    assert {item['state'] for item in manager.snapshot()['items']} <= {'missing','needs_setup'}


@pytest.mark.parametrize('mode,owner,expected', [
    (stat.S_IFREG | 0o755, 0, '/usr/bin/systemctl'),
    (stat.S_IFREG | 0o777, 0, None),
    (stat.S_IFREG | 0o755, 1000, None),
    (stat.S_IFLNK | 0o777, 0, None),
    (stat.S_IFREG | 0o644, 0, None),
])
def test_privileged_binary_requires_trusted_file(monkeypatch,mode,owner,expected):
    monkeypatch.setattr(support_startup.Path, 'lstat',
                        lambda path: SimpleNamespace(st_mode=mode, st_uid=owner))
    assert support_startup._trusted_system_executable('systemctl') == expected
    assert support_startup._trusted_system_executable('../other') is None


def test_denied_service_authorization_preserves_other_results(monkeypatch):
    monkeypatch.setattr(support_startup.Path,'is_file',lambda path:True)
    monkeypatch.setattr(support_startup, 'service_unit', lambda tool: tool)
    monkeypatch.setattr(support_startup, '_trusted_system_executable', lambda name: '/bin/'+name)
    manager = support_startup.SupportApps(which=lambda name: '/bin/'+name if name in {'systemctl','pkexec'} else None,
                                     run=lambda *args, **kw: SimpleNamespace(returncode=1))
    manager.start()
    manager._thread.join(2)
    items = {item['id']: item['state'] for item in manager.snapshot()['items']}
    assert items['core'] == 'running'
    assert items['suricata'] == items['qwen'] == 'failed'
    assert 'wireshark' not in items


def test_overlapping_jobs_rejected(monkeypatch):
    entered, release = Event(), Event()
    manager = support_startup.SupportApps()
    def work():
        entered.set()
        release.wait(2)
    monkeypatch.setattr(manager, '_work', work)
    try:
        manager.start()
        assert entered.wait(1)
        with pytest.raises(support_startup.SupportBusy):
            manager.start()
    finally:
        release.set()
        manager._thread.join(2)
    maintenance = support_startup.SupportApps(installer=SimpleNamespace(status=lambda: {'state':'running'}))
    with pytest.raises(support_startup.SupportBusy):
        maintenance.start()


def test_collector_requests_wake_existing_worker_and_do_not_duplicate(monkeypatch):
    monkeypatch.setattr('megalodon.companion_automation.shutil.which', lambda name: '/bin/'+name)
    config = CompanionConfig(interval_seconds=3600, nmap_target='127.0.0.1/32', clamav_paths=(),
                             osquery_enabled=True, watch_nmap_xml=None, watch_clamscan_text=None,
                             watch_clamscan_exit=None, watch_osquery_json=None, qwen_advisory=False)
    worker = CompanionAutomation(config, AISettings())
    worker._next_collection = {kind: time.monotonic()+3600 for kind in ('nmap','clamav','osquery')}
    entered, release, finished = Event(), Event(), Event()
    calls = []
    def collect(due):
        if due:
            calls.append(due)
            entered.set()
            release.wait(2)
            finished.set()
    monkeypatch.setattr(worker, '_collect', collect)
    worker.start()
    try:
        assert worker.request_collection() == {'nmap':'queued','clamav':'needs_setup','osquery':'queued'}
        assert entered.wait(1)
        assert worker.request_collection() == {'nmap':'running','clamav':'needs_setup','osquery':'running'}
        worker._collect_due()  # Even a second caller cannot duplicate active work.
        release.set()
        assert finished.wait(1)
    finally:
        release.set()
        worker.stop()
    assert calls == [{'nmap','osquery'}]
    monkeypatch.setattr('megalodon.companion_automation.shutil.which', lambda name: None)
    assert worker.request_collection()['nmap'] == 'missing'


def test_cli_check_never_launches_or_posts(monkeypatch, capsys):
    requests = []
    payload = {'schema':support_startup.SCHEMA,'state':'idle','items':[],'token':'x'*32}
    class Connection:
        def __init__(self, host, port, timeout):
            assert host == '127.0.0.1'
        def request(self, method, path, **kw):
            requests.append(method)
        def getresponse(self):
            return SimpleNamespace(status=200, read=lambda limit: json.dumps(payload).encode())
        def close(self):
            pass
    monkeypatch.setattr(support_startup, 'HTTPConnection', Connection)
    monkeypatch.setattr(support_startup.os, 'getuid', lambda: 1000)
    monkeypatch.setattr(support_startup.os, 'geteuid', lambda: 1000)
    monkeypatch.setattr(support_startup.subprocess, 'run', lambda *a, **kw: pytest.fail('check must not start'))
    assert support_startup.main(['--check']) == 0
    assert requests == ['GET'] and 'x'*32 not in capsys.readouterr().out


def test_cli_start_wakes_fixed_hud_service_then_posts_fixed_action(monkeypatch, capsys):
    commands, requests = [], []
    refused = [False]
    payload = {'schema':support_startup.SCHEMA,'state':'finished','items':[], 'token':'x'*32}
    class Connection:
        def __init__(self, host, port, timeout):
            assert host == '127.0.0.1'
        def request(self, method, path, **kw):
            if not refused[0]:
                refused[0] = True
                raise ConnectionRefusedError
            assert path == '/api/support-start'
            requests.append((method, kw))
        def getresponse(self):
            return SimpleNamespace(status=200, read=lambda limit: json.dumps(payload).encode())
        def close(self):
            pass
    monkeypatch.setattr(support_startup, 'HTTPConnection', Connection)
    monkeypatch.setattr(support_startup.os, 'getuid', lambda: 1000)
    monkeypatch.setattr(support_startup.os, 'geteuid', lambda: 1000)
    monkeypatch.setattr(support_startup.shutil, 'which', lambda binary: '/bin/'+binary)
    monkeypatch.setattr(support_startup.subprocess, 'run', lambda argv, **kw: commands.append(argv))
    assert support_startup.main([]) == 0
    assert commands == [['/bin/systemctl', '--user', 'start', 'megalodon-hud.service']]
    assert [method for method, _ in requests] == ['GET', 'POST', 'GET']
    post = requests[1][1]
    assert json.loads(post['body']) == {'action':'start'}
    assert post['headers']['X-Megalodon-Support-Token'] == 'x'*32
    assert post['headers']['Origin'].startswith('http://127.0.0.1:')
    assert 'x'*32 not in capsys.readouterr().out


@pytest.mark.parametrize('configured,expected', [('localhost','127.0.0.1'), ('127.0.0.2','127.0.0.2')])
def test_cli_uses_configured_loopback_host(monkeypatch,configured,expected):
    requests = []
    payload = {'schema':support_startup.SCHEMA,'state':'idle','items':[],'token':'x'*32}
    class Connection:
        def __init__(self,host,port,timeout):
            assert host == expected
        def request(self,method,path,**kwargs):
            requests.append((method,kwargs.get('headers',{}).get('Origin')))
        def getresponse(self):
            return SimpleNamespace(status=200,read=lambda limit:json.dumps(payload).encode())
        def close(self):
            pass
    monkeypatch.setattr('megalodon.config.load_settings',
                        lambda path:Settings(dashboard=DashboardSettings(host=configured)))
    monkeypatch.setattr(support_startup,'HTTPConnection',Connection)
    monkeypatch.setattr(support_startup.os,'getuid',lambda:1000)
    monkeypatch.setattr(support_startup.os,'geteuid',lambda:1000)
    assert support_startup.main(['--check']) == 0
    assert requests == [('GET',None)]
