"""Read-only HTTP and Integration Map regressions; synthetic inputs only."""
from __future__ import annotations

from copy import deepcopy
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
import shutil
import socket
import sqlite3
import subprocess
from threading import Thread

import pytest

from megalodon import dashboard
from megalodon.dashboard import DashboardHandler, ReferenceLibrary, ReferenceLookupError
from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_CSS, DASHBOARD_JS
from megalodon.hub import integration_plan


class SyntheticReader:
    def __init__(self):
        self.calls = []

    def summary(self):
        self.calls.append("summary")
        return {"events": 1, "detections": 1, "high_or_critical": 1, "actions": 0}

    def recent(self, limit=50):
        self.calls.append(("recent", limit))
        return [{"detected_at": "2026-09-10T00:00:00Z", "rule_id": "SYNTHETIC",
                 "severity": "HIGH", "src_ip": "192.0.2.1", "message": "Synthetic only",
                 "evidence": "must not appear", "dst_ip": "198.51.100.1"}]


@pytest.fixture
def http_dashboard():
    reader = SyntheticReader()
    handler = type("BoundedDashboardTestHandler", (DashboardHandler,), {
        "store": reader, "reference_library": ReferenceLibrary(failure="unavailable"),
    })
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    worker.start()
    try:
        yield server, reader
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
        assert not worker.is_alive()


def request(server, target, method="GET", headers=None):
    client = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    try:
        client.request(method, target, headers=headers or {})
        response = client.getresponse()
        body = response.read()
        return response.status, dict(response.getheaders()), body
    finally:
        client.close()


@pytest.mark.parametrize("query", [
    "limit=" + "9" * 5000, "limit=" + "0" * 5000 + "1", "limit=0001", "limit=201",
    "limit=0", "limit=-1", "limit=1.0", "limit=true", "limit=", "limit",
    "limit=1&limit=2", "limit=1&x=2", "x=1", "limit=%FF", "limit=%D9%A1",
    "limit=1&", "limit=1&&", "limit=%20%31", "limit=1;ignored=2",
])
def test_event_query_refusal_is_bounded_and_precedes_store(http_dashboard, query):
    server, reader = http_dashboard
    status, headers, body = request(server, "/api/events?" + query)
    assert status == 400
    assert set(json.loads(body)) == {"error"}
    assert len(body) < 160
    assert headers["Cache-Control"] == "no-store"
    assert not reader.calls
    # Malformed input must not kill the HTTP service or poison the next request.
    assert request(server, "/api/config")[0] == 200


@pytest.mark.parametrize("target,expected", [
    ("/api/events", 50), ("/api/events?limit=1", 1), ("/api/events?limit=200", 200),
    ("/api/events?limit=%32", 2),
])
def test_event_projection_and_valid_limits_remain_compatible(http_dashboard, target, expected):
    server, reader = http_dashboard
    status, _, body = request(server, target)
    assert status == 200
    assert reader.calls == [("recent", expected)]
    assert set(json.loads(body)[0]) == set(dashboard.DASHBOARD_EVENT_FIELDS)
    assert b"must not appear" not in body and b"198.51.100.1" not in body


@pytest.mark.parametrize("path", ["/api/config", "/api/summary", "/api/offline-summary", "/api/reference/status"])
def test_no_query_routes_do_not_ignore_unknown_arguments(http_dashboard, path):
    server, reader = http_dashboard
    assert request(server, path + "?unknown=1")[0] == 400
    assert not reader.calls


@pytest.mark.parametrize("target", ["/api/events;alias?limit=1", "/api/events#alias", "http://localhost/api/events?limit=1"])
def test_non_origin_or_aliased_targets_are_refused(http_dashboard, target):
    server, reader = http_dashboard
    assert request(server, target)[0] == 400
    assert not reader.calls


@pytest.mark.parametrize("platform", ["linux", "windows", "other"])
def test_integrations_reuses_hub_contract_without_store_access(http_dashboard, platform):
    server, reader = http_dashboard
    status, headers, body = request(server, "/api/integrations?platform=" + platform)
    assert status == 200
    assert json.loads(body) == integration_plan(platform)
    assert len(json.loads(body)["workflows"]) == dashboard.MAX_INTEGRATION_WORKFLOWS
    assert len(body) <= dashboard.MAX_INTEGRATION_RESPONSE_BYTES
    assert not reader.calls
    assert headers["Cache-Control"] == "no-store"
    assert "unsafe-inline" not in headers["Content-Security-Policy"]
    assert "connect-src 'self'" in headers["Content-Security-Policy"]
    assert headers["Cross-Origin-Resource-Policy"] == "same-origin"


@pytest.mark.parametrize("query", [
    "platform=", "platform=Linux", "platform=win32", "platform=%FF", "platform=../../run",
    "platform=linux&platform=windows", "platform=linux&run=1", "platform=linux&", "x=1",
    "platform=" + "x" * 5000,
])
def test_integration_query_is_closed(http_dashboard, query):
    server, reader = http_dashboard
    status, _, body = request(server, "/api/integrations?" + query)
    assert status == 400
    assert len(body) < 160 and set(json.loads(body)) == {"error"}
    assert not reader.calls


def test_integration_default_and_host_method_boundaries(http_dashboard):
    server, reader = http_dashboard
    assert json.loads(request(server, "/api/integrations")[2]) == integration_plan()
    assert request(server, "/api/integrations", headers={"Host": "untrusted.example"})[0] == 400
    status, headers, body = request(server, "/api/integrations", method="POST")
    assert status == 405 and headers["Allow"] == "GET"
    assert json.loads(body) == {"error": "method not allowed"}
    assert not reader.calls


@pytest.mark.parametrize("mutation", ["row_count", "field_length", "wrong_type", "response_bytes"])
def test_integration_budget_failure_never_serves_a_partial_map(http_dashboard, monkeypatch, mutation):
    server, reader = http_dashboard
    payload = deepcopy(integration_plan("linux"))
    if mutation == "row_count":
        payload["workflows"].append(deepcopy(payload["workflows"][0]))
    elif mutation == "field_length":
        payload["workflows"][0]["software"] = "x" * 513
    elif mutation == "wrong_type":
        payload["workflows"][0]["software"] = True
    else:
        payload["extra"] = "x" * (dashboard.MAX_INTEGRATION_RESPONSE_BYTES + 1)
    monkeypatch.setattr(dashboard, "integration_plan", lambda _: payload)
    status, _, body = request(server, "/api/integrations?platform=linux")
    assert status == 503
    assert json.loads(body) == {"error": "integration map unavailable"}
    assert not reader.calls


@pytest.mark.parametrize("transport", [[], {}, set(), True, None, 1, "TCP", "unknown"])
def test_direct_reference_transport_types_fail_with_fixed_error(transport):
    with pytest.raises(ReferenceLookupError, match="^invalid reference lookup$"):
        ReferenceLibrary(failure="unavailable").lookup_port(transport, 443)


def test_static_plan_has_no_process_network_or_database_side_effects(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("static integration plan attempted a side effect")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    for platform in ("linux", "windows", "other"):
        plan = integration_plan(platform)
        assert plan["action_status"] == "not_attempted"
        assert not any(plan[key] for key in ("execution_performed", "network_access_performed", "host_change_performed"))


def test_asset_composition_preserves_bootstrap_and_navigation():
    assert DASHBOARD_JS.rstrip().endswith("bootstrap();")
    assert DASHBOARD_JS.count("\nbootstrap();") == 1
    assert INDEX_HTML.index('id="triage-panel"') < INDEX_HTML.index('id="reference-title"')
    for target in ("page-title", "detections-title", "reference-title", "offline-title", "integrations-title"):
        assert f'href="#{target}"' in INDEX_HTML
        assert f'id="{target}" tabindex="-1"' in INDEX_HTML
    assert 'role="status" aria-live="polite" aria-atomic="true"' in INDEX_HTML
    assert "prefers-reduced-motion" in DASHBOARD_CSS
    assert "grid-template-columns: repeat(2, minmax(0, 1fr))" in DASHBOARD_CSS
    assert "innerHTML" not in DASHBOARD_JS and "localStorage" not in DASHBOARD_JS


def test_integration_map_javascript_contract_and_recovery():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for dashboard JavaScript behavior")
    harness = r"""
const vm = require('vm'); const assert = require('node:assert/strict');
let input = ''; process.stdin.setEncoding('utf8'); process.stdin.on('data', c => input += c);
process.stdin.on('end', async () => {
  try {
    const {code, plans} = JSON.parse(input);
    const nodes = new Map(), timers = new Map(); let sequence = 0; const calls = [];
    function fakeNode(id = '') {
      let text = '';
      return {id, value: id === 'integrations-platform' ? 'linux' : id === 'integrations-status-filter' ? 'ALL' : '',
        children: [], className: '', disabled: false, hidden: false, attrs: {}, listeners: {},
        get textContent() { return text; }, set textContent(v) { text = String(v); },
        set innerHTML(_) { throw new Error('unsafe HTML sink'); },
        append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = items; },
        setAttribute(k,v) { this.attrs[k] = String(v); }, removeAttribute(k) { delete this.attrs[k]; },
        addEventListener(k,v) { this.listeners[k] = v; }
      };
    }
    const document = {hidden: false, createElement: fakeNode, addEventListener() {},
      getElementById(id) { if (!nodes.has(id)) nodes.set(id, fakeNode(id)); return nodes.get(id); }};
    const context = {document, AbortController, Intl, Date, Number, String, Math, Set, Promise, Error, Array,
      window: {setTimeout(fn, ms) { assert.equal(ms, 5000); timers.set(++sequence, fn); return sequence; }, clearTimeout(id) { timers.delete(id); }},
      fetch: async path => { calls.push(path); return {ok: true, json: async () => plans[new URL(path, 'http://localhost').searchParams.get('platform')]}; }
    };
    vm.createContext(context);
    const stripped = code.replace(/\nbootstrap\(\);\s*$/, '\n'); assert.notEqual(stripped, code);
    vm.runInContext(stripped, context, {timeout: 1000}); assert.equal(calls.length, 0);
    const run = text => vm.runInContext(text, context, {timeout: 1000});
    const nodeFor = id => document.getElementById(id);
    const textOf = n => n.textContent + n.children.map(textOf).join(' ');
    context.plans = plans;
    for (const platform of ['linux', 'windows', 'other']) {
      assert.equal(run(`validatedIntegrationMap(plans.${platform}, '${platform}').selected_platform`), platform);
    }
    for (const value of [null, [], true, {schema: 'wrong'}]) {
      context.bad = value; assert.throws(() => run("validatedIntegrationMap(bad, 'linux')"));
    }
    const mutations = [p => p.execution_performed = true, p => p.network_access_performed = true,
      p => p.host_change_performed = true, p => p.selected_platform = 'windows', p => p.extra = 'unrecognized',
      p => p.workflows.pop(), p => p.workflows.push(p.workflows[0]), p => p.workflows[1].id = p.workflows[0].id,
      p => p.workflows[0].software = 'x'.repeat(513), p => p.workflows[0].software = true,
      p => p.workflows[0].selected_status = '__proto__', p => p.workflows[0].extra = 'unrecognized'];
    for (const mutate of mutations) {
      const bad = structuredClone(plans.linux); mutate(bad); context.bad = bad;
      assert.throws(() => run("validatedIntegrationMap(bad, 'linux')"));
    }
    run("applyConfig({schema:'dashboard-config-v1',read_only:true,event_limit:50,refresh_seconds:5})");
    for (const value of ['50', true, null, [], 0, 201, 1.5]) {
      context.bad = value;
      assert.throws(() => run("applyConfig({schema:'dashboard-config-v1',read_only:true,event_limit:bad,refresh_seconds:5})"));
      assert.equal(run('state.config.event_limit'), 50);
    }
    for (const value of ['5', true, null, [], 1, 301, 2.5]) {
      context.bad = value;
      assert.throws(() => run("applyConfig({schema:'dashboard-config-v1',read_only:true,event_limit:50,refresh_seconds:bad})"));
    }
    await run('loadIntegrationMap()'); assert.equal(calls.length, 1); assert.equal(nodeFor('integrations-cards').children.length, 8);
    assert.match(nodeFor('integrations-profile').textContent, /linux/);
    nodeFor('integrations-query').value = 'does-not-exist'; run('renderIntegrationMap()');
    assert.match(nodeFor('integrations-status').textContent, /0 of 8/);
    nodeFor('integrations-query').value = ''; nodeFor('integrations-status-filter').value = 'contract_only'; run('renderIntegrationMap()');
    assert.equal(nodeFor('integrations-cards').children.length, 1); assert.match(textOf(nodeFor('integrations-cards')), /Suricata/);
    nodeFor('integrations-status-filter').value = 'ALL'; nodeFor('integrations-platform').value = 'windows'; run('renderIntegrationMap()');
    assert.match(nodeFor('integrations-profile').textContent, /linux/); assert.match(nodeFor('integrations-status').textContent, /windows is not loaded/);
    await run('loadIntegrationMap()'); assert.match(textOf(nodeFor('integrations-cards')), /Evaluation only/);
    const before = run('integrationState.snapshot');
    context.fetch = async () => ({ok: true, json: async () => plans.linux});
    await run('loadIntegrationMap()'); assert.equal(run('integrationState.snapshot'), before);
    assert.match(nodeFor('integrations-status').textContent, /stale/); assert.equal(nodeFor('integrations-load').disabled, false);
    assert.equal(nodeFor('integrations-cards').attrs['aria-busy'], 'false');
    context.fetch = async () => { throw new Error('/private/path/SECRET'); };
    await run('loadIntegrationMap()'); assert.ok(!nodeFor('integrations-status').textContent.includes('SECRET'));
    run('integrationState.snapshot = null'); await run('loadIntegrationMap()');
    assert.match(nodeFor('integrations-status').textContent, /No partial map/);
    let resolve; let concurrentCalls = 0;
    context.fetch = () => { concurrentCalls++; return new Promise(r => resolve = r); };
    nodeFor('integrations-platform').value = 'linux'; const pending = run('loadIntegrationMap()');
    await run('loadIntegrationMap()'); assert.equal(concurrentCalls, 1);
    nodeFor('integrations-platform').value = 'windows'; resolve({ok: true, json: async () => plans.linux}); await pending;
    assert.match(nodeFor('integrations-profile').textContent, /linux/); assert.match(nodeFor('integrations-status').textContent, /windows is not loaded/);
    nodeFor('integrations-platform').value = 'linux';
    context.fetch = (_, options) => new Promise((_, reject) => options.signal.addEventListener('abort', () => reject(new Error('timeout'))));
    const timeoutPending = run('loadIntegrationMap()'); [...timers.values()].at(-1)(); await timeoutPending;
    assert.match(nodeFor('integrations-status').textContent, /stale/);
    assert.equal(nodeFor('integrations-load').disabled, false); assert.equal(timers.size, 0);
    const injection = structuredClone(plans.linux); injection.workflows[0].software = '<img src=x onerror=alert(1)>';
    context.injection = injection; run("integrationState.snapshot = validatedIntegrationMap(injection, 'linux'); renderIntegrationMap()");
    assert.match(textOf(nodeFor('integrations-cards')), /<img src=x/);
    context.fetch = () => { throw new Error('must not fetch invalid profile'); };
    nodeFor('integrations-platform').value = '../../run'; await run('loadIntegrationMap()');
    assert.match(nodeFor('integrations-status').textContent, /No request was made/);
    console.log('integration map: validation, text sinks, filters, platform identity, timeout, stale recovery, and no overlap passed');
  } catch (error) { console.error(error); process.exitCode = 1; }
});
"""
    result = subprocess.run([node, "-e", harness], input=json.dumps({
        "code": DASHBOARD_JS, "plans": {p: integration_plan(p) for p in ("linux", "windows", "other")}
    }), text=True, capture_output=True, timeout=10, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("path", ["/api/reference/port?transport=tcp&port=443", "/api/reference/protocol?number=6"])
def test_reference_output_budget_failure_is_a_fixed_http_error(http_dashboard, monkeypatch, path):
    server, reader = http_dashboard
    def oversized(*args):
        raise ReferenceLookupError("private detail must not be reflected")
    monkeypatch.setattr(ReferenceLibrary, "lookup_port", oversized)
    monkeypatch.setattr(ReferenceLibrary, "lookup_protocol", oversized)
    status, _, body = request(server, path)
    assert status == 503
    assert json.loads(body) == {"error": "reference response unavailable"}
    assert not reader.calls
