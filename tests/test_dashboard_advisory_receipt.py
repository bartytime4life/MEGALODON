"""Read-only Qwen receipt projection; no model or action path is exercised."""

from __future__ import annotations

import builtins
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
import shutil
import socket
import sqlite3
import subprocess
from threading import Thread

import pytest

from megalodon import dashboard, firewall, qwen_advisory
from megalodon.dashboard import DashboardHandler, advisory_receipt_snapshot
from megalodon.dashboard_assets import DASHBOARD_JS
from megalodon.qwen_advisory import QwenAdvisoryResult


def _result(**changes: object) -> QwenAdvisoryResult:
    values: dict[str, object] = {
        "outcome": "ANSWER",
        "code": "ADVISORY_ANSWER",
        "reason_code": "BOUNDED_MODEL_OUTPUT_ACCEPTED",
        "summary": "The aggregate counts require human interpretation.",
        "limitations": (
            "This is an AI advisory, not evidence or an action.",
            "Qwen received only the approved aggregate projection and cannot execute tools or responses.",
        ),
        "model_id": "local:qwen-approved-v1",
        "model_artifact_sha256": "a" * 64,
        "prompt_bytes": 512,
        "output_bytes": 52,
        "provider_request_performed": True,
    }
    values.update(changes)
    return QwenAdvisoryResult(**values)  # type: ignore[arg-type]


class _ForbiddenReader:
    def summary(self):
        raise AssertionError("advisory route read telemetry")

    def recent(self, limit=50):
        raise AssertionError("advisory route read telemetry")


def _request(server: ThreadingHTTPServer, path: str, method: str = "GET"):
    client = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    try:
        client.request(method, path)
        response = client.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        client.close()


@pytest.fixture
def advisory_dashboard():
    snapshot = advisory_receipt_snapshot(_result())
    handler = type(
        "AdvisoryDashboardHandler",
        (DashboardHandler,),
        {"store": _ForbiddenReader(), "advisory_receipt": snapshot},
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
        assert not worker.is_alive()


def test_advisory_route_is_bounded_get_only_and_store_independent(advisory_dashboard):
    status, headers, body = _request(advisory_dashboard, "/api/advisory-receipt")
    payload = json.loads(body)
    assert status == 200
    assert len(body) <= dashboard.MAX_ADVISORY_RESPONSE_BYTES
    assert headers["Cache-Control"] == "no-store"
    assert "connect-src 'self'" in headers["Content-Security-Policy"]
    assert payload["schema"] == "dashboard-advisory-receipt-v1"
    assert payload["available"] is True
    assert payload["receipt"] == _result().to_dict()

    assert _request(advisory_dashboard, "/api/advisory-receipt?refresh=1")[0] == 400
    status, headers, body = _request(advisory_dashboard, "/api/advisory-receipt", "POST")
    assert status == 405 and headers["Allow"] == "GET"
    assert json.loads(body) == {"error": "method not allowed"}


def test_missing_receipt_has_an_explicit_closed_state():
    handler = type(
        "EmptyAdvisoryDashboardHandler",
        (DashboardHandler,),
        {"store": _ForbiddenReader(), "advisory_receipt": None},
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        status, _, body = _request(server, "/api/advisory-receipt")
        assert status == 200
        assert json.loads(body) == {
            "schema": "dashboard-advisory-receipt-v1",
            "available": False,
        }
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_startup_snapshot_is_owned_and_rejects_invalid_results():
    source = _result()
    snapshot = advisory_receipt_snapshot(source)
    object.__setattr__(source, "summary", "changed after startup")
    assert snapshot is not None
    assert snapshot["summary"] == "The aggregate counts require human interpretation."

    invalid = (
        _result(outcome="ANSWER", code="POLICY_DENIED"),
        _result(summary=""),
        _result(summary="line\nbreak"),
        _result(limitations=()),
        _result(limitations=("duplicate", "duplicate")),
        _result(model_id="cloud:qwen"),
        _result(model_artifact_sha256="A" * 64),
        _result(reason_code="private detail"),
        _result(prompt_bytes=True),
        _result(output_bytes=4097),
        _result(provider_request_performed="yes"),
        _result(outcome="DENY", code="POLICY_DENIED", provider_request_performed=True),
    )
    for value in invalid:
        with pytest.raises(ValueError, match="^dashboard advisory receipt is invalid$"):
            advisory_receipt_snapshot(value)
    with pytest.raises(ValueError, match="^dashboard advisory receipt is invalid$"):
        advisory_receipt_snapshot(_result().to_dict())  # type: ignore[arg-type]


def test_snapshot_validation_has_no_model_process_file_database_firewall_or_tool_path(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("advisory projection crossed a forbidden boundary")

    monkeypatch.setattr(qwen_advisory, "invoke_qwen_advisory", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(firewall.NftablesFirewall, "block", forbidden)
    monkeypatch.setattr(firewall.NftablesFirewall, "install", forbidden)

    snapshot = advisory_receipt_snapshot(_result(summary="<img src=x onerror=alert(1)>"))
    assert snapshot is not None
    assert snapshot["summary"] == "<img src=x onerror=alert(1)>"


def test_browser_validates_freezes_and_text_renders_one_receipt():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for dashboard JavaScript behavior")
    harness = r"""
const vm = require('vm'); const assert = require('node:assert/strict');
let input = ''; process.stdin.setEncoding('utf8'); process.stdin.on('data', c => input += c);
process.stdin.on('end', async () => {
  try {
    const nodes = new Map(); const calls = [];
    function fakeNode(id = '') {
      let text = '';
      return {id, value: '', children: [], hidden: false, disabled: false, className: '', tabIndex: 0,
        attrs: {}, listeners: {}, get textContent() { return text; }, set textContent(v) { text = String(v); },
        set innerHTML(_) { throw new Error('unsafe HTML sink'); }, append(...v) { this.children.push(...v); },
        replaceChildren(...v) { this.children = v; }, setAttribute(k,v) { this.attrs[k] = String(v); },
        removeAttribute(k) { delete this.attrs[k]; }, addEventListener(k,v) { this.listeners[k] = v; },
        scrollIntoView() {}, focus() {}};
    }
    const document = {hidden: false, createElement: fakeNode, addEventListener() {},
      getElementById(id) { if (!nodes.has(id)) nodes.set(id, fakeNode(id)); return nodes.get(id); }};
    const value = {schema: 'dashboard-advisory-receipt-v1', available: true, receipt: {
      outcome: 'ANSWER', code: 'ADVISORY_ANSWER', summary: '<img src=x onerror=alert(1)>',
      limitations: ['AI text only.'], model_receipt: {provider_class: 'local_loopback',
        model_id: 'local:qwen-approved-v1', model_artifact_sha256: 'a'.repeat(64),
        policy_version: 'local-model-advisory-v1'}}};
    function responseFor(bytes, declared = String(bytes.byteLength)) {
      let sent = false;
      return {ok: true, headers: {get: name => name === 'Content-Length' ? declared : null},
        body: {getReader() { return {async read() {
          if (sent) return {done: true, value: undefined}; sent = true; return {done: false, value: bytes};
        }, async cancel() {}}; }}};
    }
    const context = {document, AbortController, Intl, Date, Number, String, Math, Set, Promise, Error, Array,
      TextDecoder, Uint8Array,
      window: {location: {hash: ''}, addEventListener() {}, setTimeout: setTimeout, clearTimeout: clearTimeout},
      fetch: async path => { calls.push(path); return responseFor(new Uint8Array(Buffer.from(JSON.stringify(value)))); }};
    vm.createContext(context);
    vm.runInContext(input.replace(/\nbootstrap\(\);\s*$/, '\n'), context, {timeout: 1000});
    const run = code => vm.runInContext(code, context, {timeout: 1000});
    context.value = value;
    const receipt = run('validatedAdvisoryEnvelope(value)');
    assert.equal(Object.isFrozen(receipt), true); assert.equal(Object.isFrozen(receipt.model_receipt), true);
    assert.equal(run("boundedAdvisoryText('😀'.repeat(601))"), true);
    assert.equal(run("boundedAdvisoryText('😀'.repeat(1201))"), false);
    run('renderAdvisoryReceipt(validatedAdvisoryEnvelope(value))');
    assert.equal(nodes.get('analysis-summary').textContent, '<img src=x onerror=alert(1)>');
    assert.equal(nodes.get('analysis-limitations').children.length, 1);
    for (const mutate of [
      v => v.receipt.extra = 'x', v => v.receipt.code = 'POLICY_DENIED',
      v => v.receipt.summary = 'line\nbreak', v => v.receipt.limitations = [],
      v => v.receipt.model_receipt.model_id = 'cloud:qwen',
      v => v.receipt.model_receipt.model_artifact_sha256 = 'A'.repeat(64),
      v => { v.available = false; },
    ]) {
      const bad = JSON.parse(JSON.stringify(value)); mutate(bad); context.bad = bad;
      assert.throws(() => run('validatedAdvisoryEnvelope(bad)'));
    }
    await run('loadAdvisoryReceipt()');
    assert.deepEqual(calls, ['/api/advisory-receipt']);
    assert.equal(nodes.get('analysis-window-title').textContent, 'Qwen advisory receipt · display only');
    context.fetch = async path => { calls.push(path); return responseFor(new Uint8Array(8193)); };
    await run('loadAdvisoryReceipt()');
    assert.equal(nodes.get('analysis-window-title').textContent, 'Qwen advisory receipt · unavailable');
    assert.match(nodes.get('analysis-summary').textContent, /No partial model output/);
    context.fetch = async path => { calls.push(path); return responseFor(new Uint8Array([123, 125]), '0002'); };
    await run('loadAdvisoryReceipt()');
    assert.equal(nodes.get('analysis-window-title').textContent, 'Qwen advisory receipt · unavailable');
    console.log('advisory receipt: closed validation, Unicode parity, byte cap, immutable copy, and text sink passed');
  } catch (error) { console.error(error); process.exitCode = 1; }
});
"""
    result = subprocess.run(
        [node, "-e", harness], input=DASHBOARD_JS, text=True,
        capture_output=True, timeout=10, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Unicode parity, byte cap" in result.stdout
