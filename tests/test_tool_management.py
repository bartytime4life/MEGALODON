"""Only an opted-in ordinary Linux operator can invoke fixed HUD actions."""
from contextlib import contextmanager
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import subprocess
from threading import Thread

import pytest

from megalodon import cli, dashboard
from megalodon.config import Settings
from megalodon.tool_installer import InstallBusy, InstallUnavailable


TOKEN = "t" * 32


class FakeInstaller:
    def __init__(self):
        self.calls = []
        self.failure = None

    def status(self):
        return {"state": "idle", "output": []}

    def start(self, tool, action):
        self.calls.append((tool, action))
        if self.failure:
            raise self.failure
        return {"state": "running", "tool": tool, "action": action, "output": []}


class FakeHeartbeat:
    def snapshot(self):
        return b'{"schema":"megalodon-tool-heartbeat-v1","tools":[]}'


@pytest.fixture
def endpoint(monkeypatch):
    monkeypatch.setattr(dashboard, "_tool_management_user", lambda: True)
    monkeypatch.setattr(dashboard, "install_catalog", lambda: {"tools": [], "schema": "megalodon-tool-install-catalog-v1"})
    installer = FakeInstaller()
    handler = type("ManagementHandler", (dashboard.DashboardHandler,), {
        "heartbeat": FakeHeartbeat(), "installer": installer,
        "tool_management_enabled": True, "install_operator_token": TOKEN,
    })
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
    thread.start()
    try:
        yield server, handler, installer
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request(endpoint, *, body=None, path="/api/install", method="POST",
            token=TOKEN, extra=(), omit=()):
    server, _, _ = endpoint
    # GET handlers do not consume a POST payload; unread bytes can reset the
    # connection while a large asset response is still being transferred.
    if body is None:
        body = b'{"tool":"scapy"}' if method == "POST" else b""
    origin = f"http://127.0.0.1:{server.server_port}"
    headers = [("Host", origin[7:]), ("Origin", origin), ("Content-Type", "application/json"),
               ("X-Megalodon-Install", "1"), ("X-Megalodon-Check", "1"),
               ("Content-Length", str(len(body)))]
    if token is not None:
        headers.append(("X-Megalodon-Install-Token", token))
    client = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    try:
        client.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for name, value in headers:
            if name not in omit:
                client.putheader(name, value)
        for name, value in extra:
            client.putheader(name, value)
        client.endheaders(body)
        response = client.getresponse()
        return response.status, response.read()
    finally:
        client.close()


@pytest.mark.parametrize("token", [None, "", "x" * 32, "t" * 31, "t" * 33, "é" * 32])
def test_public_headers_and_invalid_tokens_cannot_start_jobs(endpoint, token):
    code, body = request(endpoint, token=token)
    assert code == 403 and b"operator authorization required" in body
    assert endpoint[2].calls == []
    assert TOKEN.encode() not in body


@pytest.mark.parametrize("extra,omit,status", [
    ((("X-Megalodon-Install-Token", TOKEN),), (), 403),
    ((("X-Megalodon-Install", "1"),), (), 403),
    ((("Origin", "http://evil.invalid"),), (), 403),
    ((("Content-Type", "application/json"),), (), 403),
    ((("Transfer-Encoding", "chunked"),), (), 403),
    ((("Content-Encoding", "identity"),), (), 403),
    ((), ("Origin",), 403),
    ((), ("X-Megalodon-Install",), 403),
    ((("Host", "127.0.0.1"),), (), 400),
    ((("Content-Length", "16"),), (), 400),
    ((), ("Content-Length",), 400),
    ((("Content-Length", "000000000000000016"),), ("Content-Length",), 400),
    ((("Content-Length", "97"),), ("Content-Length",), 400),
    ((("Content-Length", "-1"),), ("Content-Length",), 400),
])
def test_ambiguous_headers_and_encodings_never_reach_installer(endpoint, extra, omit, status):
    assert request(endpoint, extra=extra, omit=omit)[0] == status
    assert endpoint[2].calls == []


@pytest.mark.parametrize("body", [
    b'{"tool":"scapy","tool":"nmap"}',
    b'{"tool":"scapy","t\\u006fol":"nmap"}',
    b'{"tool":"qwen","action":"install","action":"start"}',
    b'{"tool":[]}', b'{"tool":{}}', b'{"tool":null}',
    b'{"tool":"scapy","action":[]}', b'{"tool":"scapy","action":{}}',
    b'{"tool":"scapy","action":"stop"}', b'{"tool":"bash"}',
    b'{"tool":"scapy","extra":1}', b'[]', b'null', b'not json', b'\xff',
])
def test_malformed_closed_bodies_fail_without_coercion(endpoint, body):
    assert request(endpoint, body=body)[0] == 400
    assert endpoint[2].calls == []


@pytest.mark.parametrize("path", ["/api/install?token=" + TOKEN, "/api/install/", "/api/%69nstall", "http://127.0.0.1/api/install"])
def test_route_aliases_cannot_bypass_authorization(endpoint, path):
    assert request(endpoint, path=path)[0] == 405
    assert endpoint[2].calls == []


@pytest.mark.parametrize("tool,action", [("scapy", None), ("nmap", "install"), ("qwen", "install"), ("zabbix", "start")])
def test_authenticated_fixed_recipe_families_remain_available(endpoint, tool, action):
    body = {"tool": tool}
    if action is not None:
        body["action"] = action
    code, value = request(endpoint, body=json.dumps(body).encode())
    assert code == 202 and json.loads(value)["state"] == "running"
    assert endpoint[2].calls == [(tool, action or "install")]


@pytest.mark.parametrize("failure,status", [(InstallBusy(), 409), (InstallUnavailable(), 422)])
def test_existing_job_error_semantics_are_preserved(endpoint, failure, status):
    endpoint[2].failure = failure
    assert request(endpoint)[0] == status


def test_default_observation_retains_heartbeat_and_catalog_without_mutation(endpoint):
    _, handler, installer = endpoint
    handler.tool_management_enabled = False
    handler.install_operator_token = None
    assert request(endpoint)[0] == 403
    assert request(endpoint, method="GET", path="/api/heartbeat")[0] == 200
    code, body = request(endpoint, method="GET")
    assert code == 200 and json.loads(body)["management"] == {"enabled": False, "authorization": "disabled"}
    assert installer.calls == []


def test_privileged_or_disabled_runtime_refuses_even_a_valid_token(endpoint, monkeypatch):
    monkeypatch.setattr(dashboard, "_tool_management_user", lambda: False)
    assert request(endpoint)[0] == 403
    assert json.loads(request(endpoint, method="GET")[1])["management"]["enabled"] is False
    assert endpoint[2].calls == []


def test_token_is_not_disclosed_in_catalog_or_assets_and_old_launch_token_fails(endpoint):
    for path in ("/", "/assets/dashboard.js", "/assets/dashboard.css", "/api/install", "/api/heartbeat"):
        code, value = request(endpoint, path=path, method="GET", token=None)
        assert code == 200 and TOKEN.encode() not in value
    assert json.loads(request(endpoint, method="GET")[1])["management"]["enabled"] is True
    endpoint[1].install_operator_token = "n" * 32
    assert request(endpoint)[0] == 403
    assert request(endpoint, token="n" * 32)[0] == 202
    assert len(endpoint[2].calls) == 1


@pytest.mark.parametrize("platform,uid,euid,allowed", [
    ("linux", 1000, 1000, True), ("linux", 0, 1000, False),
    ("linux", 1000, 0, False), ("win32", 1000, 1000, False),
])
def test_tool_management_requires_linux_and_both_nonroot_ids(monkeypatch, platform, uid, euid, allowed):
    monkeypatch.setattr(dashboard.sys, "platform", platform)
    monkeypatch.setattr(dashboard.os, "getuid", lambda: uid, raising=False)
    monkeypatch.setattr(dashboard.os, "geteuid", lambda: euid, raising=False)
    assert dashboard._tool_management_user() is allowed


def test_unknown_user_identity_fails_closed(monkeypatch):
    monkeypatch.setattr(dashboard.sys, "platform", "linux")
    monkeypatch.delattr(dashboard.os, "getuid", raising=False)
    assert dashboard._tool_management_user() is False


def test_launch_tokens_are_separate_ephemeral_and_only_printed_on_opt_in(monkeypatch, capsys):
    handlers = []

    class Server:
        def __init__(self, _address, handler):
            handlers.append(handler)

        def serve_forever(self):
            pass

        def server_close(self):
            pass

    monkeypatch.setattr(dashboard, "ThreadingHTTPServer", Server)
    monkeypatch.setattr(dashboard, "_tool_management_user", lambda: True)
    monkeypatch.setattr(dashboard, "setup_snapshot", lambda **_: b"{}")
    monkeypatch.setattr(dashboard, "local_python_lifecycle", lambda: {})
    monkeypatch.setattr(dashboard, "local_hud_launch", lambda: {})
    dashboard.serve(object(), "127.0.0.1", 8787, inspect_tools=True)
    assert "operator token" not in capsys.readouterr().out
    assert handlers[-1].install_operator_token is None
    assert handlers[-1].installer is not None and handlers[-1].heartbeat is not None
    for _ in range(2):
        dashboard.serve(object(), "127.0.0.1", 8787, inspect_tools=True, enable_tool_management=True,
                        ai_settings=dashboard.AISettings(enabled=True))
        handler = handlers[-1]
        token = handler.install_operator_token
        assert len(token) == 32 and token != handler.ai_operator_token
        assert token in capsys.readouterr().out
        assert token.encode() not in handler.javascript
    assert handlers[-1].install_operator_token != handlers[-2].install_operator_token


@pytest.mark.parametrize("hud,allowed", [(False, True), (True, False)])
def test_invalid_opt_in_is_refused_before_server_or_source_access(monkeypatch, hud, allowed):
    monkeypatch.setattr(dashboard, "_tool_management_user", lambda: allowed)
    monkeypatch.setattr(dashboard, "setup_snapshot", lambda **_: pytest.fail("source inspected"))
    with pytest.raises(ValueError):
        dashboard.serve(object(), "127.0.0.1", 8787, inspect_tools=hud, enable_tool_management=True)
    monkeypatch.setattr(cli, "_load", lambda _: Settings())
    monkeypatch.setattr(cli, "_dashboard_reader", lambda *_a, **_k: pytest.fail("store opened"))
    args = cli.build_parser().parse_args(["hud" if hud else "dashboard", "--enable-tool-management"])
    assert cli._dashboard(args) == 2


def test_cli_passes_explicit_opt_in_without_changing_default(monkeypatch):
    calls = []
    monkeypatch.setattr(dashboard, "_tool_management_user", lambda: True)
    monkeypatch.setattr(cli, "_load", lambda _: Settings())

    @contextmanager
    def reader(*_args, **_kwargs):
        yield dashboard.UnconfiguredDashboardReader()

    monkeypatch.setattr(cli, "_dashboard_reader", reader)
    monkeypatch.setattr(dashboard, "serve", lambda *_args, **kwargs: calls.append(kwargs))
    for tail in ([], ["--enable-tool-management"]):
        assert cli._dashboard(cli.build_parser().parse_args(["hud", *tail])) == 0
    assert [call["enable_tool_management"] for call in calls] == [False, True]


def test_browser_requires_opt_in_token_and_confirmation():
    from megalodon.dashboard_heartbeat import HEARTBEAT_JS
    from megalodon.dashboard_connections import INTEGRATIONS_JS
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node required for tool-management browser behavior")
    result = subprocess.run(
        [node, str(Path(__file__).with_name("tool_management_browser.cjs"))],
        input=json.dumps({"code": HEARTBEAT_JS + INTEGRATIONS_JS}), text=True, capture_output=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
