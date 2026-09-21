"""Explicit HUD diagnostics perform only fixed, read-only observations."""
from contextlib import contextmanager
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from threading import Event, Thread
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from megalodon import dashboard, dashboard_checks as checks
from megalodon.storage import StorageSchemaError


@pytest.fixture
def probes(monkeypatch):
    presence = Mock(return_value={"presence": "fixed"})
    runtime = Mock(return_value={"runtime": "fixed"})
    monkeypatch.setattr(checks, "readiness_report", presence)
    monkeypatch.setattr(checks, "runtime_report", runtime)
    return presence, runtime


@contextmanager
def serve_checks(collector):
    handler = type("CheckHandler", (dashboard.DashboardHandler,), {"local_checks": collector})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
    thread.start()
    try:
        def request(path="/api/local-checks", *, method="GET", headers=None):
            conn = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            conn.request(method, path, headers=headers or {})
            response = conn.getresponse()
            body = response.read()
            result = response.status, dict(response.getheaders()), body
            conn.close()
            return result
        yield request
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_check_is_explicit_closed_and_cached(probes, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(checks, "monotonic", lambda: clock[0])
    store = SimpleNamespace(summary=Mock(return_value={"private": "not serialized"}))
    collector = checks.LocalChecks(store, source_available=True)
    assert not probes[0].called
    with serve_checks(collector) as request:
        for path, method, headers, expected in (
            ("/api/local-checks", "GET", {}, 403),
            ("/api/local-checks", "GET", {"X-Megalodon-Check": "0"}, 403),
            ("/api/local-checks?tool=tshark", "GET", {"X-Megalodon-Check": "1"}, 400),
            ("/api/local-checks", "POST", {"X-Megalodon-Check": "1"}, 405),
            ("/api/local-checks", "GET", {"X-Megalodon-Check": "1", "Host": "evil.invalid"}, 400),
        ):
            assert request(path, method=method, headers=headers)[0] == expected
        assert not probes[0].called
        status, headers, raw = request(headers={"X-Megalodon-Check": "1"})
        assert status == 200
        assert headers["Cache-Control"] == "no-store"
        assert "Access-Control-Allow-Origin" not in headers
        receipt = json.loads(raw)
        assert set(receipt) == {"schema", "checked_at", "environment", "source", "readiness", "runtime"}
        assert receipt["schema"] == "dashboard-local-checks-v1"
        assert receipt["source"] == {"status": "available"}
        assert set(receipt["environment"]) == {"python_version", "sqlite_version", "platform"}
        assert b"private" not in raw
        assert request(headers={"X-Megalodon-Check": "1"})[2] == raw
        assert store.summary.call_count == probes[0].call_count == probes[1].call_count == 1
        clock[0] += checks.CHECK_CACHE_SECONDS + 1
        assert request(headers={"X-Megalodon-Check": "1"})[0] == 200
        assert store.summary.call_count == probes[0].call_count == probes[1].call_count == 2


def test_missing_and_unreadable_sources_are_distinct(probes):
    store = SimpleNamespace(summary=Mock(side_effect=StorageSchemaError("PRIVATE_PATH")))
    missing = json.loads(checks.LocalChecks(store, source_available=False).snapshot())
    assert missing["source"]["status"] == "not_configured"
    store.summary.assert_not_called()
    failed = checks.LocalChecks(store, source_available=True).snapshot()
    assert json.loads(failed)["source"]["status"] == "unavailable"
    assert b"PRIVATE_PATH" not in failed


def test_only_one_probe_runs_and_busy_http_has_retry_after(probes):
    collector = checks.LocalChecks(object(), source_available=False)
    started, finish = Event(), Event()
    def slow_probe():
        started.set()
        assert finish.wait(timeout=3)
        return {"ok": True}
    probes[0].side_effect = slow_probe
    worker = Thread(target=collector.snapshot)
    worker.start()
    assert started.wait(timeout=2)
    try:
        with serve_checks(collector) as request:
            status, headers, _ = request(headers={"X-Megalodon-Check": "1"})
            assert status == 429
            assert headers["Retry-After"] == "5"
            assert probes[0].call_count == 1
    finally:
        finish.set(); worker.join(timeout=2)


def test_disabled_mode_errors_and_oversized_report_do_not_leak(probes):
    with serve_checks(None) as request:
        assert request(headers={"X-Megalodon-Check": "1"})[0] == 403
    collector = checks.LocalChecks(object(), source_available=False)
    probes[0].side_effect = OSError("PRIVATE_PATH")
    with serve_checks(collector) as request:
        status, _, raw = request(headers={"X-Megalodon-Check": "1"})
        assert status == 503
        assert b"PRIVATE_PATH" not in raw
        probes[0].side_effect = None
        probes[0].return_value = {"huge": "x" * checks.MAX_CHECK_BYTES}
        assert request(headers={"X-Megalodon-Check": "1"})[0] == 503
        probes[0].return_value = {"ok": True}
        assert request(headers={"X-Megalodon-Check": "1"})[0] == 200


def test_real_probes_do_not_execute_programs_or_return_private_data(monkeypatch, tmp_path):
    from megalodon import readiness, runtime_status
    import subprocess
    def forbidden(*args, **kwargs):
        pytest.fail("A metadata check attempted to execute a program")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(readiness, "runtime_platform", lambda: "linux")
    monkeypatch.setenv("PATH", str(tmp_path))
    candidate = tmp_path / "tshark"
    candidate.write_text("not executable program content")
    candidate.chmod(0o700)
    monkeypatch.setattr(checks, "runtime_report", lambda: runtime_status.runtime_report(tmp_path))
    raw = checks.LocalChecks(object(), source_available=False).snapshot()
    receipt = json.loads(raw)
    assert receipt["readiness"]["tools"][1]["status"] == "executable_found"
    assert str(tmp_path).encode() not in raw
    assert b"not executable program content" not in raw
    assert len(raw) < checks.MAX_CHECK_BYTES


def test_browser_checks_validate_failures_and_recover():
    import shutil
    import subprocess
    from pathlib import Path
    from megalodon.dashboard_setup import SETUP_JS
    from megalodon.dashboard_tool_assets import READINESS_JS
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node required for browser logic')
    report = json.loads(checks.LocalChecks(object(), source_available=False).snapshot())
    result = subprocess.run(
        [node, str(Path(__file__).with_name('dashboard_checks_behavior.cjs'))],
        input=json.dumps({'code': READINESS_JS + '\n' + SETUP_JS, 'report': report}),
        text=True, capture_output=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
