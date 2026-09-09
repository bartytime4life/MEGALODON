"""Loopback-only startup tests; unsafe addresses never reach a socket."""
from __future__ import annotations

import argparse
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from threading import Thread
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from megalodon import cli, dashboard
from megalodon import offline_projection


INVALID_HOSTS = (
    "0.0.0.0", "192.168.1.1", "8.8.8.8", "::", "::1", "0:0:0:0:0:0:0:1",
    "::ffff:127.0.0.1", "::1%lo", "fe80::1%eth0", "localhost.", "LOCALHOST",
    "example.invalid", "127.1", "2130706433", "0x7f000001", "127.00.0.1",
    " 127.0.0.1", "127.0.0.1\n", "127.0.0.1\x00", "", "x" * 1000,
    None, True, 2130706433, b"127.0.0.1", [], {},
)


def _forbidden(*args, **kwargs):
    raise AssertionError("startup crossed a forbidden boundary")


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
    server.server_close.assert_called_once_with()


@pytest.mark.parametrize("host, override", (
    ("0.0.0.0", False), ("0.0.0.0", True), ("127.0.0.1", True),
    ("localhost", True), ("::1", False), ("", False), (None, False),
))
def test_cli_refuses_before_store_report_or_server(monkeypatch, capsys, host, override):
    settings = SimpleNamespace(
        dashboard=SimpleNamespace(host="0.0.0.0", port=8787), db_path="not-opened",
    )
    monkeypatch.setattr(cli, "_load", lambda _: settings)
    monkeypatch.setattr(cli, "Store", _forbidden)
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


def test_parser_preserves_legacy_flag_for_explicit_refusal():
    args = cli.build_parser().parse_args(["dashboard", "--allow-remote"])
    assert args.allow_remote is True


def _host_request(server, values):
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    connection.putrequest(
        "GET", "/api/summary", skip_host=True, skip_accept_encoding=True
    )
    for value in values:
        connection.putheader("Host", value)
    connection.endheaders()
    response = connection.getresponse()
    body = json.loads(response.read())
    headers = dict(response.getheaders())
    connection.close()
    return response.status, body, headers


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
