"""The local companion poller keeps tool status and saved counts distinct."""

import shutil
import subprocess

import pytest

from megalodon.dashboard_companion import COMPANION_JS


def test_companion_poller_isolates_a_bad_aggregate_and_preserves_status():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node unavailable")
    harness = r'''
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(0, 'utf8');
const nodes = new Map();
const element = id => {
  if (!nodes.has(id)) nodes.set(id, {
    textContent: '', hidden: false, attributes: {},
    setAttribute(key, value) { this.attributes[key] = value; }
  });
  return nodes.get(id);
};
let visible;
const document = {
  hidden: false, getElementById: element,
  addEventListener(name, callback) { if (name === 'visibilitychange') visible = callback; }
};
let payload = {
  schema: 'megalodon-companion-automation-v1',
  status: {nmap: 'Local collector (127.0.0.1/32) · completed; saved aggregate', clamav: 'Local collector (Downloads) · completed; saved aggregate', osquery: 'waiting'},
  advisory: {clamav: 'Counts are not proof of safety.'},
  results: {nmap: {bad: true}, clamav: {scanned_files: 2}}
};
const calls = [];
const context = {
  localHudLaunch: {}, document, TextEncoder, setTimeout() {},
  fetch: async () => ({ok: true, text: async () => JSON.stringify(payload)}),
  globalThis: {megalodonCompanionRender: {
    nmap() { throw new Error('invalid aggregate'); },
    clamav() { calls.push('clamav'); },
    osquery() { calls.push('osquery'); }
  }}
};
vm.runInNewContext(source, context);
async function settled() { await new Promise(resolve => setImmediate(resolve)); }
(async () => {
  await settled();
  assert.match(element('inventory-automation').textContent, /aggregate rejected/);
  assert.equal(element('inventory-status').attributes['data-state'], 'warning');
  assert.equal(element('clamav-status').attributes['data-state'], 'ready');
  assert.equal(element('clamav-advisory-wrap').hidden, false);
  assert.equal(element('clamav-advisory').textContent, 'Counts are not proof of safety.');
  payload = {...payload, status: {...payload.status, clamav: 'Scanning configured files; previous aggregate retained until complete'}};
  visible();
  await settled();
  assert.equal(element('clamav-status').attributes['data-state'], 'checking');
  payload = {...payload, status: {...payload.status, clamav: 'Local collector unavailable or rejected; prior aggregate preserved'}};
  visible();
  await settled();
  assert.equal(element('clamav-status').attributes['data-state'], 'warning');
  assert.equal(element('osquery-status').textContent, 'Collection queued.');
  assert.deepEqual(calls, ['clamav']);
  payload = {...payload, results: {}, status: {...payload.status, osquery: 'osquery is not installed'}};
  visible();
  await settled();
  assert.match(element('osquery-status').textContent, /not installed/);
  assert.equal(element('osquery-status').attributes['data-state'], 'warning');
  assert.equal(element('clamav-advisory-wrap').hidden, false);
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
    result = subprocess.run([node, "-e", harness], input=COMPANION_JS, text=True,
                            capture_output=True, timeout=5, check=False)
    assert result.returncode == 0, result.stderr
