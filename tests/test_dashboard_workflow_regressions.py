"""Synthetic dashboard request, reference integrity, and recovery regressions."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
import pytest
import megalodon.dashboard as dashboard
from megalodon.reference import ReferenceDataError
from megalodon.dashboard import (
    DASHBOARD_JS, DashboardHandler, ReferenceLibrary, ReferenceLookupError,
)


@pytest.mark.parametrize("transport", [[], {}, set(), None, True, b"tcp"])
def test_direct_reference_invalid_transport_has_fixed_error(transport):
    # Invalid inputs must fail before touching a bundle, cache or lock.
    with pytest.raises(ReferenceLookupError, match="^invalid reference lookup$"):
        ReferenceLibrary.lookup_port(object(), transport, 443)


@pytest.mark.parametrize("target", [
    "/api/events?limit=" + "9" * 5000,
    "/api/events?" + "limit=1&" * 100,
    "//[",
    "/api/events?limit=1&limit=2",
    "/api/events?unexpected=1",
])
def test_dashboard_bad_target_refused_before_storage(target):
    responses = []
    handler = SimpleNamespace(
        path=target,
        _has_expected_host=lambda: True,
        _send_json=lambda payload, **kw: responses.append((payload, kw)),
    )
    # No store attribute exists: any attempt to access storage fails this test.
    DashboardHandler.do_GET(handler)
    assert len(responses) == 1
    payload, options = responses[0]
    assert options["status"] == 400
    assert set(payload) == {"error"}
    assert len(payload["error"]) < 100


@pytest.mark.parametrize("code, expected", [
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
])
def test_reference_loader_failures_are_closed_and_path_free(monkeypatch, code, expected):
    calls = []

    def reject_bundle():
        calls.append("load")
        raise ReferenceDataError("REFERENCE_DATA:" + code)

    monkeypatch.setattr(dashboard, "load_iana", reject_bundle)
    library = ReferenceLibrary.load()
    status = library.status()
    assert status == {
        "schema": "reference-library-status-v1",
        "available": False,
        "status": expected,
        "error": "reference bundle unavailable" if expected == "unavailable"
        else "reference bundle integrity failure",
        "network_access_performed": False,
        "persistence_status": "not_attempted",
        "action_status": "not_attempted",
    }
    assert library.lookup_port("tcp", 443) == status
    assert library.lookup_protocol(6) == status
    assert library.cache_size == 0
    assert calls == ["load"]
    assert "REFERENCE_DATA:" not in json.dumps(status)


def test_dashboard_reference_semantics_and_recovery_in_node(tmp_path: Path):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for dashboard JavaScript contract checks")
    script = tmp_path / "dashboard.js"
    harness = tmp_path / "reference-contract-checks.cjs"
    script.write_text(DASHBOARD_JS, encoding="utf-8")
    harness.write_text(NODE_CONTRACT_CHECKS, encoding="utf-8")
    completed = subprocess.run(
        [node, str(harness), str(script)], capture_output=True, text=True,
        check=False, timeout=15,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["passed"] == 49
    assert "mismatched_response_preserves_only_old_stale_query" in result["cases"]


NODE_CONTRACT_CHECKS = r"""
'use strict';
// Execute either the full dashboard JS supplied by a repository test or the
// exact retrieved function fixture assembled by verify_package.py. No browser,
// network, package installation, or producer process is used by this harness.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const script = fs.readFileSync(process.argv[2], 'utf8').replace(/\nbootstrap\(\);\s*$/, '\n');
let assertions = 0;
const results = [];
function check(name, body) { body(); assertions++; results.push(name); }
class Element {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.attributes = {}; this.value = ''; this.disabled = false; this.hidden = false; this.className = ''; this._text = ''; this.listeners = {}; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(item => item.textContent || '').join(' '); }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this._text = ''; this.children = [...items]; }
  setAttribute(key, value) { this.attributes[key] = String(value); }
  removeAttribute(key) { delete this.attributes[key]; }
  addEventListener(name, handler) { this.listeners[name] = handler; }
  focus() { document.activeElement = this; }
}
const elements = new Map();
const document = {
  hidden: false, activeElement: null,
  getElementById(id) { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); },
  createElement(tag) { return new Element(tag); }, addEventListener() {}
};
const context = vm.createContext({
  document, console, Intl, AbortController,
  window: {setTimeout: () => 1, clearTimeout() {}},
  fetch: () => { throw new Error('unexpected fetch'); },
});
vm.runInContext(script, context, {timeout: 5000});
const run = code => vm.runInContext(code, context, {timeout: 5000});
const clone = value => JSON.parse(JSON.stringify(value));
const posture = {network_access_performed: false, persistence_status: 'not_attempted', action_status: 'not_attempted'};
const identity = {bundle_id: 'iana-network-reference-20260910', bundle_version: 'v1', manifest_sha256: 'a'.repeat(64)};
const sources = [{id: 'iana-service-names-port-numbers', registry_url: 'https://www.iana.org/assignments/service-names-port-numbers/', registry_last_updated: '2026-09-07', retrieved_at: '2026-09-10T19:10:11.051Z', retrieved_at_basis: 'connector receipt'}];
const portRecord = {service_name: 'https', transport: 'tcp', port_start: 443, port_end: 443, record_kind: 'named', description: 'Synthetic HTTPS registry fixture', registration_date: null, modification_date: null, source_row: 12};
const result = {schema: 'reference-library-lookup-v1', status: 'one_match', available: true, kind: 'port', ...identity, query: {transport: 'tcp', port: 443}, match_count: 1, matches: [portRecord], truncated: false, sources, warning: 'Registration is context, not observation.', ...posture};
const status = {schema: 'reference-library-status-v1', available: true, status: 'ready', ...identity, service_records: 12577, protocol_records: 152, cache_entries: 0, cache_limit: 16, sources, warning: result.warning, ...posture};
const unavailable = {schema: 'reference-library-status-v1', available: false, status: 'unavailable', error: 'reference bundle unavailable', ...posture};
function validate(value, query = result.query, kind = 'port', expectedIdentity = identity) {
  context.input = value; context.expectedQuery = query; context.expectedKind = kind; context.expectedIdentity = expectedIdentity;
  return run('validatedReferenceResult(input, expectedKind, expectedQuery, expectedIdentity)');
}
function rejectMutation(name, mutation) {
  check(name, () => { const value = clone(result); mutation(value); assert.throws(() => validate(value)); });
}
check('accept_exact_port_result', () => assert.equal(validate(clone(result)).match_count, 1));
check('accept_no_match', () => { const value = {...clone(result), status: 'no_match', matches: [], match_count: 0}; assert.equal(validate(value).status, 'no_match'); });
check('accept_multiple_records', () => { const value = clone(result); value.matches.push({...portRecord, source_row: 13}); value.match_count = 2; value.status = 'multiple_matches'; assert.equal(validate(value).matches.length, 2); });
check('accept_capped_result', () => { const value = clone(result); value.match_count = 9; value.truncated = true; value.status = 'multiple_matches'; value.matches = Array.from({length: 8}, (_, i) => ({...portRecord, source_row: i + 1})); assert.equal(validate(value).matches.length, 8); });
check('accept_protocol_result', () => {
  const value = {...clone(result), kind: 'protocol', query: {number: 6}, sources: [], matches: [{decimal_start: 6, decimal_end: 6, keyword: 'TCP', protocol_name: 'Transmission Control', ipv6_extension_header: '', record_kind: 'named', source_row: 7}]};
  assert.equal(validate(value, {number: 6}, 'protocol').kind, 'protocol');
});
rejectMutation('deny_status_count_conflict', value => { value.status = 'no_match'; });
rejectMutation('deny_truncation_conflict', value => { value.truncated = true; });
rejectMutation('deny_missing_returned_record', value => { value.matches = []; });
rejectMutation('deny_wrong_query_port', value => { value.query.port = 80; value.matches[0].port_start = 80; value.matches[0].port_end = 80; });
rejectMutation('deny_wrong_transport', value => { value.query.transport = 'udp'; value.matches[0].transport = 'udp'; });
rejectMutation('deny_unsupported_transport', value => { value.query.transport = 'TCP'; });
rejectMutation('deny_out_of_range_query', value => { value.query.port = 65536; });
rejectMutation('deny_string_port', value => { value.query.port = '443'; });
rejectMutation('deny_boolean_port', value => { value.query.port = true; });
rejectMutation('deny_query_extra_field', value => { value.query.command = 'unused'; });
rejectMutation('deny_snapshot_digest_drift', value => { value.manifest_sha256 = 'b'.repeat(64); });
rejectMutation('deny_invalid_digest', value => { value.manifest_sha256 = 'not a hash'; });
rejectMutation('deny_snapshot_id_drift', value => { value.bundle_id = 'other'; });
rejectMutation('deny_other_bundle_version', value => { value.bundle_version = 'v2'; });
rejectMutation('deny_record_not_covering_query', value => { value.matches[0].port_end = 442; });
rejectMutation('deny_record_transport_mismatch', value => { value.matches[0].transport = 'udp'; });
rejectMutation('deny_numeric_service_name', value => { value.matches[0].service_name = 3; });
rejectMutation('deny_negative_source_row', value => { value.matches[0].source_row = -1; });
rejectMutation('deny_duplicate_source_row', value => { value.match_count = 2; value.status = 'multiple_matches'; value.matches.push(clone(value.matches[0])); });
rejectMutation('deny_oversized_record', value => { value.matches[0].description = 'x'.repeat(513); });
rejectMutation('deny_extra_top_level_field', value => { value.payload = 'hidden'; });
rejectMutation('deny_action_claim', value => { value.action_status = 'applied'; });
rejectMutation('deny_network_claim', value => { value.network_access_performed = true; });
rejectMutation('deny_persistence_claim', value => { value.persistence_status = 'written'; });
rejectMutation('deny_duplicate_source_ids', value => { value.sources.push(clone(value.sources[0])); });
check('deny_wrong_lookup_kind', () => assert.throws(() => validate(clone(result), {number: 6}, 'protocol')));
check('accept_ready_status', () => { context.input = clone(status); assert.equal(run('validatedReferenceStatus(input)').available, true); });
check('accept_unavailable_status', () => { context.input = clone(unavailable); assert.equal(run('validatedReferenceStatus(input)').available, false); });
for (const [key, invalid] of [['network_access_performed', true], ['persistence_status', 'written'], ['action_status', 'applied']]) {
  check(`deny_unavailable_${key}`, () => { context.input = {...unavailable, [key]: invalid}; assert.throws(() => run('validatedReferenceStatus(input)')); });
}
check('deny_unavailable_raw_exception', () => { context.input = {...unavailable, error: '/private/path/traceback'}; assert.throws(() => run('validatedReferenceStatus(input)')); });
check('deny_ready_oversized_cache', () => { context.input = {...status, cache_limit: 1000}; assert.throws(() => run('validatedReferenceStatus(input)')); });
check('error_payload_is_validated', () => { context.input = {payload: {...unavailable, action_status: 'applied'}}; assert.equal(run('referenceFailurePayload(input)'), null); });

// Exercise the actual asynchronous status and lookup functions with a closed
// synthetic transport and a minimal DOM; this is not rendered-browser evidence.
let fetchCount = 0;
let responseProvider;
context.fetch = async path => { fetchCount++; return responseProvider(path); };
function response(value, code = 200) { return {ok: code === 200, status: code, json: async () => clone(value)}; }
async function asyncCheck(name, body) { await body(); assertions++; results.push(name); }
(async () => {
  responseProvider = () => { throw new Error('synthetic transient failure'); };
  await asyncCheck('transient_status_failure_keeps_retry_enabled', async () => {
    await run('loadReferenceStatus()');
    assert.equal(run('referenceState.available'), false);
    assert.equal(document.getElementById('reference-retry').disabled, false);
    assert.equal(document.getElementById('reference-port').disabled, true);
    assert.equal(document.getElementById('reference-panel').attributes['aria-busy'], 'false');
  });
  responseProvider = () => response(status);
  await asyncCheck('manual_recheck_recovers_after_transport_failure', async () => {
    await run('loadReferenceStatus()');
    assert.equal(run('referenceState.available'), true);
    assert.equal(document.getElementById('reference-port').disabled, false);
    assert.equal(run('referenceState.identity.manifest_sha256'), identity.manifest_sha256);
  });
  document.getElementById('reference-transport').value = 'tcp'; document.getElementById('reference-port').value = '443';
  responseProvider = path => { assert.equal(path, '/api/reference/port?transport=tcp&port=443'); return response(result); };
  await asyncCheck('lookup_uses_only_exact_local_route', async () => {
    await run("lookupReference('port')"); assert.equal(run('referenceState.lastResult.query.port'), 443);
    assert.equal(run('referenceState.loading'), false);
  });
  check('provenance_visible_as_text', () => {
    const text = document.getElementById('reference-meta').textContent;
    assert.ok(text.includes(identity.manifest_sha256)); assert.ok(text.includes(sources[0].retrieved_at)); assert.ok(text.includes(sources[0].retrieved_at_basis));
    assert.ok(!document.getElementById('reference-meta').children.some(child => child.tagName === 'a'));
  });
  document.getElementById('reference-port').value = '80'; responseProvider = () => response(result);
  await asyncCheck('mismatched_response_preserves_only_old_stale_query', async () => {
    await run("lookupReference('port')"); assert.equal(run('referenceState.lastResult.query.port'), 443);
    assert.ok(document.getElementById('reference-status').className.includes('stale'));
  });
  document.getElementById('reference-port').value = '00443';
  await asyncCheck('invalid_input_makes_no_request', async () => {
    const prior = fetchCount; await run("lookupReference('port')"); assert.equal(fetchCount, prior);
  });
  document.getElementById('reference-port').value = '443';
  const integrity = {...unavailable, status: 'integrity_failure', error: 'reference bundle integrity failure'};
  responseProvider = () => response(integrity, 503);
  await asyncCheck('authoritative_integrity_failure_clears_old_context', async () => {
    await run("lookupReference('port')"); assert.equal(run('referenceState.lastResult'), null);
    assert.equal(run('referenceState.identity'), null); assert.equal(document.getElementById('reference-port').disabled, true);
    assert.equal(document.getElementById('reference-retry').disabled, false);
  });
  let resolvePending;
  responseProvider = () => new Promise(resolve => { resolvePending = () => resolve(response(status)); });
  await asyncCheck('status_recheck_is_single_flight', async () => {
    const prior = fetchCount;
    const pending = run('loadReferenceStatus()');
    await run('loadReferenceStatus()'); await run("lookupReference('port')");
    assert.equal(fetchCount, prior + 1); assert.equal(document.getElementById('reference-retry').disabled, true);
    resolvePending(); await pending; assert.equal(run('referenceState.statusLoading'), false);
  });
  responseProvider = () => new Promise(resolve => { resolvePending = () => resolve(response(result)); });
  await asyncCheck('lookup_blocks_overlapping_status_and_lookup', async () => {
    const prior = fetchCount; const pending = run("lookupReference('port')");
    await run('loadReferenceStatus()'); await run("lookupReference('port')");
    assert.equal(fetchCount, prior + 1); assert.equal(document.getElementById('reference-port').disabled, true);
    resolvePending(); await pending; assert.equal(document.getElementById('reference-port').disabled, false);
  });
  responseProvider = () => response(status);
  await asyncCheck('status_recheck_clears_prior_query_without_new_lookup', async () => {
    const prior = fetchCount; await run('loadReferenceStatus()');
    assert.equal(fetchCount, prior + 1); assert.equal(run('referenceState.lastResult'), null);
  });
  console.log(JSON.stringify({passed: assertions, cases: results, evidence_scope: 'synthetic Node VM; not rendered-browser acceptance'}));
})().catch(error => { console.error(error.stack); process.exitCode = 1; });
"""
