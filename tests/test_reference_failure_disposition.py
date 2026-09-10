"""Reference load failures use closed diagnostics, never partial context.

These tests inject fixed loader failures. They are not real-bundle tamper,
installed-package, or rendered-browser acceptance; existing suites own those.
"""
from __future__ import annotations

from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from threading import Thread

import pytest

import megalodon.dashboard as dashboard
from megalodon.reference import ReferenceDataError


CASES = [
    ("RESOURCE_IO", "unavailable"),
    ("RESOURCE_LIMIT", "integrity_failure"),
    ("RESOURCE_NAME", "integrity_failure"),
    ("RESOURCE_SET", "integrity_failure"),
    ("MANIFEST", "integrity_failure"),
    ("INTEGRITY", "integrity_failure"),
    ("ARTIFACT", "integrity_failure"),
    ("IANA_RECORD", "integrity_failure"),
    ("JSON", "integrity_failure"),
    ("JSON_NUMBER", "integrity_failure"),
    ("FRAMING", "integrity_failure"),
    ("ENCODING", "integrity_failure"),
    ("DUPLICATE_KEY", "integrity_failure"),
    ("SCHEMA", "integrity_failure"),
    ("ROW_COUNT", "integrity_failure"),
    ("ORDER_OR_DUPLICATE", "integrity_failure"),
    ("FUTURE_VALIDATION_CODE", "integrity_failure"),
    ("RESOURCE_IO_EXTRA", "integrity_failure"),
]


def _failure(monkeypatch, code):
    calls = []

    def reject_bundle():
        calls.append("load")
        raise ReferenceDataError("REFERENCE_DATA:" + code)

    monkeypatch.setattr(dashboard, "load_iana", reject_bundle)
    return calls


def _expected(category):
    return {
        "schema": "reference-library-status-v1",
        "available": False,
        "status": category,
        "error": "reference bundle unavailable" if category == "unavailable"
        else "reference bundle integrity failure",
        "network_access_performed": False,
        "persistence_status": "not_attempted",
        "action_status": "not_attempted",
    }


@pytest.mark.parametrize("code,category", CASES)
def test_load_failure_has_closed_category_no_partial_rows_or_cache(monkeypatch, code, category):
    calls = _failure(monkeypatch, code)
    library = dashboard.ReferenceLibrary.load()
    expected = _expected(category)
    assert library.status() == expected
    assert library.lookup_port("tcp", 443) == expected
    assert library.lookup_protocol(6) == expected
    assert library.available is False
    assert library.cache_size == 0
    assert calls == ["load"]
    assert "REFERENCE_DATA:" not in json.dumps(expected)


@pytest.mark.parametrize("code,category", [
    ("RESOURCE_IO", "unavailable"), ("RESOURCE_LIMIT", "integrity_failure"),
])
@pytest.mark.parametrize("route", [
    "/api/reference/status",
    "/api/reference/port?transport=tcp&port=443",
    "/api/reference/protocol?number=6",
])
def test_http_failure_is_fixed_503_with_security_headers_and_no_store(monkeypatch, code, category, route):
    calls = _failure(monkeypatch, code)

    class NoStore:
        def summary(self):
            raise AssertionError("reference route read telemetry")

        def recent(self, limit=50):
            raise AssertionError("reference route read telemetry")

    handler = type("FailureDashboardHandler", (dashboard.DashboardHandler,), {
        "store": NoStore(), "reference_library": dashboard.ReferenceLibrary.load(),
    })
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    try:
        connection.request("GET", route)
        response = connection.getresponse()
        body = response.read(4097)
        assert response.status == 503
        assert len(body) <= 4096
        assert json.loads(body) == _expected(category)
        assert response.getheader("Cache-Control") == "no-store"
        assert response.getheader("X-Content-Type-Options") == "nosniff"
        assert "frame-ancestors 'none'" in response.getheader("Content-Security-Policy")
        assert "unsafe-inline" not in response.getheader("Content-Security-Policy")
        assert calls == ["load"]
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_default_failure_remains_cached_without_automatic_retry(monkeypatch):
    calls = _failure(monkeypatch, "FRAMING")
    monkeypatch.setattr(dashboard, "_default_reference_library", None)
    first = dashboard.default_reference_library()
    second = dashboard.default_reference_library()
    assert first is second
    assert first.status() == _expected("integrity_failure")
    assert calls == ["load"]


def test_load_does_not_swallow_unrelated_programming_errors(monkeypatch):
    def programming_error():
        raise RuntimeError("synthetic programmer failure")

    monkeypatch.setattr(dashboard, "load_iana", programming_error)
    with pytest.raises(RuntimeError, match="synthetic programmer failure"):
        dashboard.ReferenceLibrary.load()
