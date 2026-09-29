"""Loopback-only startup tests; unsafe addresses never reach a socket."""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import errno
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from threading import Event, Thread
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from megalodon import cli, dashboard, local_install
from megalodon import offline_projection
from megalodon.hud_password import PasswordVerifier
from megalodon.storage import DashboardStore, StorageSchemaError, Store


INVALID_HOSTS = (
    "0.0.0.0", "192.168.1.1", "8.8.8.8", "::", "::1", "0:0:0:0:0:0:0:1",
    "::ffff:127.0.0.1", "::1%lo", "fe80::1%eth0", "localhost.", "LOCALHOST",
    "example.invalid", "127.1", "2130706433", "0x7f000001", "127.00.0.1",
    " 127.0.0.1", "127.0.0.1\n", "127.0.0.1\x00", "", "x" * 1000,
    None, True, 2130706433, b"127.0.0.1", [], {},
)


def _forbidden(*args, **kwargs):
    raise AssertionError("startup crossed a forbidden boundary")


@pytest.mark.parametrize("failure, expected_code, message", (
    (KeyboardInterrupt(), 0, "dashboard stopped"),
    (OSError(errno.EADDRINUSE, "Address already in use"), 2, "--port 8788"),
))
def test_manual_dashboard_exit_closes_reader(monkeypatch, capsys, failure, expected_code, message):
    closed = []

    @contextmanager
    def reader(*args, **kwargs):
        try:
            yield dashboard.UnconfiguredDashboardReader()
        finally:
            closed.append(True)

    def serve(*args, **kwargs):
        raise failure

    monkeypatch.setattr(cli, "_dashboard_reader", reader)
    monkeypatch.setattr(dashboard, "serve", serve)
    assert cli._dashboard(cli.build_parser().parse_args(["hud"])) == expected_code
    result = capsys.readouterr()
    assert message in result.out + result.err
    assert "Traceback" not in result.err
    assert closed == [True]


@pytest.mark.parametrize("host", INVALID_HOSTS)
@pytest.mark.parametrize("allow_remote", (False, True))
def test_unsafe_bind_never_constructs_server(monkeypatch, host, allow_remote):
    monkeypatch.setattr(dashboard, "ThreadingHTTPServer", _forbidden)
    with pytest.raises(ValueError, match="loopback") as error:
        dashboard.serve(None, host, 8787, allow_remote=allow_remote)
    assert len(str(error.value)) < 100


@pytest.mark.parametrize("override", (True, 1, 0, None, "false", [], {}))
def test_legacy_or_type_confused_override_is_a_refusal(monkeypatch, override):
    monkeypatch.setattr(dashboard, "ThreadingHTTPServer", _forbidden)
    with pytest.raises(ValueError, match="no longer supported"):
        dashboard.serve(None, "127.0.0.1", 8787, allow_remote=override)


@pytest.mark.parametrize("host, expected", (
    ("localhost", "127.0.0.1"), ("127.0.0.1", "127.0.0.1"),
    ("127.0.0.2", "127.0.0.2"), ("127.255.255.254", "127.255.255.254"),
))
def test_loopback_server_gets_numeric_host_and_closes(monkeypatch, host, expected):
    server = Mock()
    server.serve_forever.side_effect = KeyboardInterrupt
    factory = Mock(return_value=server)
    monkeypatch.setattr(dashboard, "ThreadingHTTPServer", factory)
    monkeypatch.setattr(dashboard, "_show_http_read_password", lambda _: None)
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", _forbidden)
    monkeypatch.setattr(socket, "gethostbyname", _forbidden)
    store = object()
    with pytest.raises(KeyboardInterrupt):
        dashboard.serve(store, host, 8787, offline_summary={}, refresh_seconds=12, event_limit=25)
    address, handler = factory.call_args.args
    assert address == (expected, 8787)
    assert handler.store is store
    assert handler.offline_summary == {}
    assert handler.refresh_seconds == 12
    assert handler.event_limit == 25
    assert handler.http_read_password is None
    assert handler.http_session_token is None
    server.server_close.assert_called_once_with()


def test_chosen_password_reaches_bound_handler_without_a_random_secret(monkeypatch):
    verifier = PasswordVerifier.from_password("synthetic private phrase 123")
    server = Mock()
    server.serve_forever.side_effect = KeyboardInterrupt
    factory = Mock(return_value=server)
    notice = Mock()
    monkeypatch.setattr(dashboard, "ThreadingHTTPServer", factory)
    monkeypatch.setattr(dashboard, "_show_http_read_password", notice)
    with pytest.raises(KeyboardInterrupt):
        dashboard.serve(object(), "127.0.0.1", 8787, http_password_verifier=verifier)
    handler = factory.call_args.args[1]
    assert handler.http_read_password is None
    assert handler.http_password_verifier is verifier
    notice.assert_called_once_with(None)
    server.server_close.assert_called_once_with()


def test_opt_in_sign_in_generates_a_private_launch_password(monkeypatch):
    server = Mock()
    server.serve_forever.side_effect = KeyboardInterrupt
    factory = Mock(return_value=server)
    notice = Mock()
    monkeypatch.setattr(dashboard, "ThreadingHTTPServer", factory)
    monkeypatch.setattr(dashboard, "_show_http_read_password", notice)
    with pytest.raises(KeyboardInterrupt):
        dashboard.serve(object(), "127.0.0.1", 8787, require_sign_in=True)
    handler = factory.call_args.args[1]
    assert isinstance(handler.http_read_password, str)
    assert len(handler.http_read_password) == 12
    assert len(handler.http_session_token) >= 32
    notice.assert_called_once_with(handler.http_read_password)
    server.server_close.assert_called_once_with()


def test_browser_opens_only_after_loopback_server_binds(monkeypatch):
    server = Mock()
    opener_started = Event()
    server_started = Event()
    opener_finished = Event()

    def open_tab(url):
        assert url == "http://127.0.0.1:8787/"
        opener_started.set()
        assert server_started.wait(2), "browser opener blocked the HTTP server"
        opener_finished.set()
        return True

    def serve_forever():
        assert opener_started.wait(2)
        server_started.set()
        raise KeyboardInterrupt

    server.serve_forever.side_effect = serve_forever
    factory = Mock(return_value=server)
    monkeypatch.setattr(dashboard, "ThreadingHTTPServer", factory)
    monkeypatch.setattr(dashboard, "_show_http_read_password", lambda _: None)
    monkeypatch.setattr(dashboard.webbrowser, "open_new_tab", open_tab)
    with pytest.raises(KeyboardInterrupt):
        dashboard.serve(object(), "127.0.0.1", 8787, open_browser=True)
    assert factory.call_count == 1
    assert opener_finished.wait(2)
    server.server_close.assert_called_once_with()


def test_launch_password_is_restricted_to_a_terminal(monkeypatch):
    writes = []
    with monkeypatch.context() as patch:
        patch.setattr(dashboard.sys, "stdout", SimpleNamespace(fileno=lambda: 7))
        patch.setattr(dashboard.os, "isatty", lambda fd: False)
        patch.setattr(dashboard.os, "write", lambda *_: pytest.fail("secret reached redirected output"))
        with pytest.raises(ValueError, match="interactive terminal"):
            dashboard._show_http_read_password("private-launch-password")
        patch.setattr(dashboard.os, "isatty", lambda fd: fd == 7)
        patch.setattr(dashboard.os, "write", lambda fd, data: writes.append((fd, data)) or len(data))
        dashboard._show_http_read_password("private-launch-password")
    assert writes == [(7, b"MEGALODON local dashboard sign-in password: private-launch-password\n")]


def test_chosen_password_notice_never_prints_a_secret(monkeypatch):
    writes = []
    monkeypatch.setattr(dashboard.sys, "stdout", SimpleNamespace(fileno=lambda: 7))
    monkeypatch.setattr(dashboard.os, "isatty", lambda fd: fd == 7)
    monkeypatch.setattr(dashboard.os, "write", lambda fd, data: writes.append(data) or len(data))
    dashboard._show_http_read_password(None)
    assert writes == [b"MEGALODON local dashboard sign-in password: your configured HUD password\n"]


@pytest.mark.parametrize("host, override", (
    ("0.0.0.0", False), ("0.0.0.0", True), ("127.0.0.1", True),
    ("localhost", True), ("::1", False), ("", False), (None, False),
))
def test_cli_refuses_before_store_report_or_server(monkeypatch, capsys, host, override):
    settings = SimpleNamespace(
        dashboard=SimpleNamespace(host="0.0.0.0", port=8787), db_path="not-opened",
    )
    monkeypatch.setattr(cli, "_load", lambda _: settings)
    monkeypatch.setattr(cli, "DashboardStore", _forbidden)
    monkeypatch.setattr(offline_projection, "load_offline_projection", _forbidden)
    monkeypatch.setattr(dashboard, "serve", _forbidden)
    args = argparse.Namespace(
        config="unused", host=host, port=None, allow_remote=override,
        offline_run="not-read", refresh_seconds=None, event_limit=None,
    )
    assert cli._dashboard(args) == 2
    result = capsys.readouterr()
    assert result.out == ""
    assert result.err.startswith("megalodon: dashboard requires")
    assert "not-read" not in result.err
    assert "not-opened" not in result.err


def test_disabled_cli_dashboard_refuses_before_projection_or_store(monkeypatch, capsys):
    settings = SimpleNamespace(
        dashboard=SimpleNamespace(
            host="127.0.0.1", port=8787, enabled=False
        ),
        db_path="not-opened",
    )
    monkeypatch.setattr(cli, "_load", lambda _: settings)
    monkeypatch.setattr(cli, "DashboardStore", _forbidden)
    monkeypatch.setattr(offline_projection, "load_offline_projection", _forbidden)
    monkeypatch.setattr(dashboard, "serve", _forbidden)
    args = argparse.Namespace(
        config="unused",
        host=None,
        port=None,
        allow_remote=False,
        offline_run="not-read",
        refresh_seconds=None,
        event_limit=None,
    )

    assert cli._dashboard(args) == 2
    result = capsys.readouterr()
    assert result.out == ""
    assert result.err == "megalodon: dashboard is disabled by configuration\n"


def test_cli_dashboard_uses_the_dedicated_reader(tmp_path, monkeypatch):
    path = tmp_path / "private" / "audit.db"
    with Store(path):
        pass
    settings = SimpleNamespace(
        dashboard=SimpleNamespace(
            host="127.0.0.1",
            port=8787,
            enabled=True,
            refresh_seconds=5,
            event_limit=50,
        ),
        db_path=path,
    )
    observed = {}

    def inspect(reader, *_args, **_kwargs):
        observed["reader"] = reader
        assert isinstance(reader, DashboardStore)
        assert reader.summary()["events"] == 0

    monkeypatch.setattr(cli, "_load", lambda _: settings)
    monkeypatch.setattr(dashboard, "serve", inspect)
    args = argparse.Namespace(
        config="unused",
        host=None,
        port=None,
        allow_remote=False,
        offline_run=None,
        refresh_seconds=None,
        event_limit=None,
    )

    assert cli._dashboard(args) == 0
    assert "reader" in observed


@pytest.mark.parametrize("require_sign_in", (False, True))
def test_installed_hud_loads_chosen_password_verifier_only_on_opt_in(tmp_path, monkeypatch, require_sign_in):
    settings_path = tmp_path / "settings.toml"
    settings = SimpleNamespace(
        dashboard=SimpleNamespace(host="127.0.0.1", port=8787, enabled=True, refresh_seconds=5, event_limit=50),
        db_path=tmp_path / "audit.db",
    )
    verifier = PasswordVerifier.from_password("synthetic private phrase 123")
    observed = {}

    @contextmanager
    def reader(*_args, **_kwargs):
        yield dashboard.UnconfiguredDashboardReader()

    monkeypatch.setattr(cli, "_load", lambda _: settings)
    monkeypatch.setattr(cli, "_dashboard_reader", reader)
    monkeypatch.setattr(local_install, "install_paths", lambda: SimpleNamespace(settings=settings_path))
    monkeypatch.setattr(local_install, "load_hud_password_verifier", lambda: verifier)
    monkeypatch.setattr(dashboard, "serve", lambda *_args, **kwargs: observed.update(kwargs))
    args = argparse.Namespace(
        config=settings_path, host=None, port=None, allow_remote=False,
        offline_run=None, refresh_seconds=None, event_limit=None,
        require_sign_in=require_sign_in,
    )
    assert cli._dashboard(args) == 0
    assert observed["http_password_verifier"] is (verifier if require_sign_in else None)
    assert observed["require_sign_in"] is require_sign_in


def test_cli_dashboard_missing_store_creates_nothing(tmp_path, monkeypatch, capsys):
    path = tmp_path / "missing" / "audit.db"
    settings = SimpleNamespace(
        dashboard=SimpleNamespace(
            host="127.0.0.1",
            port=8787,
            enabled=True,
            refresh_seconds=5,
            event_limit=50,
        ),
        db_path=path,
    )
    monkeypatch.setattr(cli, "_load", lambda _: settings)
    monkeypatch.setattr(dashboard, "serve", _forbidden)
    args = argparse.Namespace(
        config="unused",
        host=None,
        port=None,
        allow_remote=False,
        offline_run=None,
        refresh_seconds=None,
        event_limit=None,
    )

    assert cli._dashboard(args) == 2
    assert not path.parent.exists()
    assert str(path) not in capsys.readouterr().err


def test_parser_preserves_legacy_flag_for_explicit_refusal():
    args = cli.build_parser().parse_args(["dashboard", "--allow-remote"])
    assert args.allow_remote is True


def _host_request(server, values, path="/api/summary", authorizations=()):
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    connection.putrequest(
        "GET", path, skip_host=True, skip_accept_encoding=True
    )
    for value in values:
        connection.putheader("Host", value)
    for value in authorizations:
        connection.putheader("Authorization", value)
    connection.endheaders()
    response = connection.getresponse()
    body = json.loads(response.read())
    headers = dict(response.getheaders())
    connection.close()
    return response.status, body, headers


def test_launch_password_guards_private_reads_before_store_access():
    store = Mock()
    store.summary.return_value = {"events": 1}
    handler = type("AuthorizedDashboardHandler", (dashboard.DashboardHandler,), {
        "store": store, "http_read_password": "private-launch-password",
    })
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host = f"127.0.0.1:{server.server_port}"
        for credentials in ((), ("Basic invalid!",), ("Basic " + base64.b64encode(b"megalodon:wrong").decode("ascii"),)):
            status, body, headers = _host_request(server, (host,), authorizations=credentials)
            assert status == 401
            assert body == {"error": "local dashboard sign-in required"}
            assert "WWW-Authenticate" not in headers
        assert not store.summary.called
        valid = "Basic " + base64.b64encode(b"megalodon:private-launch-password").decode("ascii")
        status, _, _ = _host_request(server, (host,), authorizations=(valid, valid))
        assert status == 401
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        try:
            connection.request("POST", "/api/automation-preview", body=b"{}", headers={"Host": host})
            response = connection.getresponse()
            assert response.status == 401
            response.read()
        finally:
            connection.close()
        status, body, _ = _host_request(server, (host,), authorizations=(valid,))
        assert status == 200
        assert body == store.summary.return_value
        store.summary.assert_called_once_with()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_chosen_password_guards_private_reads_before_store_access():
    store = Mock()
    store.summary.return_value = {"events": 1}
    verifier = PasswordVerifier.from_password("synthetic private phrase 123")
    handler = type("ChosenPasswordHandler", (dashboard.DashboardHandler,), {
        "store": store, "http_read_password": None, "http_password_verifier": verifier,
    })
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host = f"127.0.0.1:{server.server_port}"
        for supplied in (b"megalodon:wrong private phrase 123", b"other:synthetic private phrase 123"):
            auth = "Basic " + base64.b64encode(supplied).decode("ascii")
            status, _, _ = _host_request(server, (host,), authorizations=(auth,))
            assert status == 401
        assert not store.summary.called
        auth = "Basic " + base64.b64encode(b"megalodon:synthetic private phrase 123").decode("ascii")
        status, body, _ = _host_request(server, (host,), authorizations=(auth,))
        assert status == 200 and body == {"events": 1}
        store.summary.assert_called_once_with()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_password_only_landing_page_and_session_guard_private_data():
    store = Mock()
    store.summary.return_value = {"events": 1}
    handler = type("SignInHandler", (dashboard.DashboardHandler,), {
        "store": store, "http_read_password": "twelve-chars",
        "http_session_token": "private-session-token",
        "login_lock": dashboard.Lock(), "login_failures": 0, "login_blocked_until": 0.0,
    })
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host = f"127.0.0.1:{server.server_port}"

    def request(method, path, body=None, headers=None):
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        try:
            connection.request(method, path, body=body, headers={"Host": host, **(headers or {})})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    try:
        status, headers, _ = request("GET", "/")
        assert status == 303 and headers["Location"] == "/sign-in"
        assert "WWW-Authenticate" not in headers
        status, _, body = request("GET", "/sign-in")
        assert status == 200 and b'HUD password' in body
        assert b'twelve-chars' not in body
        assert request("GET", "/api/summary")[0] == 401
        assert request("GET", "/assets/dashboard.js")[0] == 401
        assert not store.summary.called
        login_headers = {"Origin": f"http://{host}", "Content-Type": "application/json",
                         "X-Megalodon-Sign-In": "1"}
        assert request("POST", "/sign-in", b'{"password":"twelve-chars"}',
                       {**login_headers, "Origin": "http://attacker.invalid"})[0] == 403
        assert request("POST", "/sign-in", b'{"password":"wrong","password":"twelve-chars"}',
                       login_headers)[0] == 400
        assert request("POST", "/sign-in", b'{"password":"wrong"}', login_headers)[0] == 401
        assert request("GET", "/api/summary")[0] == 401
        status, headers, _ = request("POST", "/sign-in", b'{"password":"twelve-chars"}', login_headers)
        assert status == 200
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        assert "HttpOnly" in headers["Set-Cookie"] and "SameSite=Strict" in headers["Set-Cookie"]
        assert request("GET", "/api/summary", headers={"Cookie": cookie})[0] == 200
        assert request("GET", "/api/summary", headers={"Cookie": cookie + "; " + cookie})[0] == 401
        for _ in range(5):
            assert request("POST", "/sign-in", b'{"password":"wrong"}', login_headers)[0] == 401
        assert request("POST", "/sign-in", b'{"password":"twelve-chars"}', login_headers)[0] == 429
        assert request("GET", "/api/summary", headers={"Cookie": cookie})[0] == 200
        assert store.summary.call_count == 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_default_hud_opens_without_sign_in_and_keeps_host_guard():
    store = Mock()
    store.summary.return_value = {"events": 1}
    handler = type("OpenLocalHandler", (dashboard.DashboardHandler,), {"store": store})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host = f"127.0.0.1:{server.server_port}"
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        connection.request("GET", "/", headers={"Host": host})
        response = connection.getresponse()
        assert response.status == 200
        assert b"MEGALODON" in response.read()
        connection.close()
        status, body, _ = _host_request(server, (host,))
        assert status == 200 and body == {"events": 1}
        status, _, _ = _host_request(server, ("attacker.invalid",))
        assert status == 400
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        connection.request("GET", "/sign-in", headers={"Host": host})
        response = connection.getresponse()
        assert response.status == 303 and response.getheader("Location") == "/"
        response.read()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_dashboard_rejects_untrusted_host_before_store_access():
    store = Mock()
    handler = type(
        "HostBoundDashboardHandler", (dashboard.DashboardHandler,), {"store": store}
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_port
    try:
        invalid = (
            (),
            ("attacker.example",),
            (f"attacker.example:{port}",),
            ("localhost.",),
            ("127.00.0.1",),
            ("127.0.0.2",),
            (f"127.0.0.1:{port + 1}",),
            ("127.0.0.1", "attacker.example"),
        )
        for values in invalid:
            status, body, headers = _host_request(server, values)
            assert status == 400
            assert body == {"error": "invalid request host"}
            assert headers["Cache-Control"] == "no-store"
        store.summary.assert_not_called()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_dashboard_accepts_only_bound_loopback_host_forms():
    store = Mock()
    store.summary.return_value = {
        "events": 0,
        "detections": 0,
        "actions": 0,
        "high_or_critical": 0,
    }
    handler = type(
        "ExpectedHostDashboardHandler", (dashboard.DashboardHandler,), {"store": store}
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_port
    try:
        expected = (
            "127.0.0.1",
            f"127.0.0.1:{port}",
            "localhost",
            f"localhost:{port}",
        )
        for value in expected:
            status, body, _ = _host_request(server, (value,))
            assert status == 200
            assert body == store.summary.return_value
        assert store.summary.call_count == len(expected)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_dashboard_returns_a_fixed_503_when_a_served_read_fails():
    store = Mock()
    store.summary.side_effect = StorageSchemaError(
        "DASHBOARD_STORE:DIRECTORY_CHANGED:/private/operator/path"
    )
    store.recent.side_effect = StorageSchemaError(
        "DASHBOARD_STORE:READ_FAILED:/private/operator/path"
    )
    handler = type(
        "FailClosedDashboardHandler", (dashboard.DashboardHandler,), {"store": store}
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for path in ("/api/summary", "/api/events?limit=1"):
            status, body, headers = _host_request(
                server, (f"127.0.0.1:{server.server_port}",), path
            )
            assert status == 503
            assert body == {"error": "telemetry unavailable"}
            assert headers["Cache-Control"] == "no-store"
            assert "private" not in json.dumps(body)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
