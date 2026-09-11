"""Static-map status transitions under local filters; no backend or real I/O."""
from __future__ import annotations

import json
import shutil
import subprocess
import unittest

from megalodon.dashboard_connections import INTEGRATIONS_JS


HARNESS = r"""
const assert = require('node:assert/strict');
const vm = require('node:vm');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', async () => {
  try {
    const {asset, scenario} = JSON.parse(input);
    class Element {
      constructor() { this.value = ''; this.textContent = ''; this.children = []; this.disabled = false; this.attrs = {}; this.listeners = {}; }
      append(...nodes) { this.children.push(...nodes); }
      replaceChildren(...nodes) { this.children = nodes; }
      setAttribute(name, value) { this.attrs[name] = value; }
      addEventListener(name, handler) { this.listeners[name] = handler; }
      set innerHTML(_) { throw new Error('HTML interpolation is not permitted'); }
    }
    const nodes = new Map();
    const get = id => { if (!nodes.has(id)) nodes.set(id, new Element()); return nodes.get(id); };
    get('integrations-platform').value = 'linux';
    get('integrations-status-filter').value = 'ALL';
    const requests = [];
    const context = vm.createContext({
      document: {getElementById: get, createElement: () => new Element()},
      requestJSON(path) { return new Promise((resolve, reject) => { requests.push({path, resolve, reject}); }); },
      fetch() { throw new Error('unexpected network access'); }
    });
    // These two DOM helpers are the same presentation primitives used by the dashboard.
    vm.runInContext(`
      function byId(value) { return document.getElementById(value); }
      function textNode(tag, value, className) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        node.textContent = String(value);
        return node;
      }
    `, context);
    vm.runInContext(asset, context, {timeout: 1000}); // Complete emitted component, including event wiring.
    const state = () => vm.runInContext('integrationState', context);
    const status = () => get('integrations-status').textContent;
    const event = (id, name) => get(id).listeners[name]();
    const ids = ['core-metadata', 'offline-packet-metadata', 'offline-flow-metadata', 'alert-metadata',
      'live-metadata-capture', 'time-limited-response', 'manual-file-scan', 'endpoint-inventory'];
    const fixture = platform => ({
      schema: 'megalodon-integration-hub-v1', capability_schema: 'megalodon-capability-catalog-v1',
      selected_platform: platform, hub_mode: 'static_plan_only', default_posture: 'observe_only',
      execution_performed: false, network_access_performed: false, host_change_performed: false,
      action_status: 'not_attempted', workflows: ids.map((id, index) => ({
        id, component: id, software: 'Synthetic software ' + index, selected_status: index ? 'contract_only' : 'implemented',
        source_kind: 'synthetic', integration_owner: 'synthetic-fixture', input_contract: 'Synthetic input',
        output_contract: 'Synthetic output', entry_point: null, launch_policy: 'not_attempted',
        data_boundary: 'Synthetic metadata only', action_boundary: 'No action', next_gate: 'Independent review'
      }))
    });
    async function ready(platform = 'linux') {
      get('integrations-platform').value = platform;
      const pending = event('integrations-load', 'click');
      requests.at(-1).resolve(fixture(platform));
      await pending;
    }
    function edit(which) {
      if (which === 'query') { get('integrations-query').value = 'no matching card'; event('integrations-query', 'input'); }
      else if (which === 'status') { get('integrations-status-filter').value = 'optional'; event('integrations-status-filter', 'change'); }
      else if (which === 'clear') event('integrations-clear', 'click');
      else { get('integrations-platform').value = 'windows'; event('integrations-platform', 'change'); }
    }
    function idle() {
      assert.equal(state().loading, false);
      assert.equal(get('integrations-load').disabled, false);
      assert.equal(get('integrations-platform').disabled, false);
      assert.equal(get('integrations-cards').attrs['aria-busy'], 'false');
      assert.doesNotMatch(status(), /Loading the static/);
    }
    assert.equal(requests.length, 0, 'import/event wiring must not fetch automatically');
    if (scenario.startsWith('pending:')) {
      const pending = event('integrations-load', 'click');
      edit(scenario.split(':')[1]);
      assert.match(status(), /Loading the static linux documentation profile/, 'filtering must not erase pending status');
      assert.equal(get('integrations-cards').attrs['aria-busy'], 'true');
      assert.equal(state().snapshot, null);
      assert.equal(requests.length, 1);
      requests[0].resolve(fixture('linux')); await pending; idle();
    } else if (scenario.startsWith('failed:')) {
      const pending = event('integrations-load', 'click');
      requests[0].reject(new Error('PRIVATE_DIAGNOSTIC_CANARY')); await pending;
      edit(scenario.split(':')[1]);
      assert.match(status(), /Integration map unavailable/, 'filtering must not erase first-load failure');
      assert.doesNotMatch(status(), /Preserved map|PRIVATE_DIAGNOSTIC_CANARY/);
      assert.equal(state().snapshot, null); assert.equal(requests.length, 1); idle();
    } else if (scenario === 'previous-map') {
      await ready();
      const original = JSON.stringify(state().snapshot);
      get('integrations-platform').value = 'windows';
      const pending = event('integrations-load', 'click'); edit('query');
      assert.match(status(), /Loading the static windows documentation profile/);
      assert.match(status(), /loaded linux documentation profile/);
      assert.match(status(), /0 of 8 workflows/);
      assert.match(get('integrations-profile').textContent, /Loaded profile: linux/);
      assert.equal(JSON.stringify(state().snapshot), original);
      requests[1].reject(new Error('unavailable')); await pending; idle();
      assert.match(status(), /stale/); assert.match(status(), /Selected profile windows is not loaded/);
    } else if (scenario === 'retry') {
      let pending = event('integrations-load', 'click'); requests[0].reject(new Error('unavailable')); await pending;
      pending = event('integrations-load', 'click'); edit('clear');
      assert.match(status(), /Loading the static linux documentation profile/);
      requests[1].resolve(fixture('linux')); await pending; idle();
      assert.equal(state().failed, false); assert.doesNotMatch(status(), /unavailable|stale|Load failed/);
    } else if (scenario === 'single-flight') {
      const pending = event('integrations-load', 'click');
      await event('integrations-load', 'click');
      assert.equal(get('integrations-load').disabled, true); assert.equal(get('integrations-platform').disabled, true);
      // A programmatic edit must not relabel the already dispatched request.
      edit('platform');
      assert.match(status(), /Loading the static linux documentation profile/);
      assert.equal(requests.length, 1); assert.equal(requests[0].path, '/api/integrations?platform=linux');
      requests[0].resolve(fixture('linux')); await pending; idle();
      assert.match(status(), /Selected profile windows is not loaded/);
    } else if (scenario.startsWith('accepted:')) {
      const platform = scenario.split(':')[1]; await ready(platform); idle();
      assert.equal(state().snapshot.selected_platform, platform);
      assert.equal(get('integrations-cards').children.length, 8);
      edit('query'); assert.equal(get('integrations-cards').children.length, 1); // Empty-state paragraph.
      assert.match(status(), /0 of 8 workflows/); edit('clear');
      assert.equal(get('integrations-cards').children.length, 8); assert.equal(requests.length, 1);
    } else if (scenario.startsWith('rejected:')) {
      await ready(); const original = JSON.stringify(state().snapshot);
      get('integrations-platform').value = 'windows'; const pending = event('integrations-load', 'click');
      const bad = fixture('windows');
      if (scenario === 'rejected:profile') bad.selected_platform = 'linux';
      else bad.execution_performed = true;
      requests[1].resolve(bad); await pending; idle();
      assert.equal(JSON.stringify(state().snapshot), original); assert.equal(state().failed, true);
      edit('clear'); assert.match(status(), /Preserved map is stale/);
      assert.match(status(), /loaded linux documentation profile/); assert.equal(requests.length, 2);
    } else if (scenario === 'invalid-selection') {
      get('integrations-platform').value = 'not-supported'; await event('integrations-load', 'click');
      assert.equal(requests.length, 0); assert.equal(state().snapshot, null);
      assert.match(status(), /No request was made/);
    } else throw new Error('unknown test scenario');
    process.stdout.write('integration-state-ok\n');
  } catch (error) { console.error(error); process.exitCode = 1; }
});
"""


@unittest.skipUnless(shutil.which("node"), "Node is required for integration-map behavior")
class IntegrationMapStateTests(unittest.TestCase):
    def run_case(self, scenario: str) -> None:
        result = subprocess.run(
            [shutil.which("node"), "-e", HARNESS],
            input=json.dumps({"asset": INTEGRATIONS_JS, "scenario": scenario}),
            text=True, capture_output=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "integration-state-ok\n")

    def test_filters_preserve_pending_request_status(self) -> None:
        for control in ("query", "status", "clear"):
            with self.subTest(control=control):
                self.run_case(f"pending:{control}")

    def test_filters_and_profile_choice_preserve_initial_failure(self) -> None:
        for control in ("query", "status", "clear", "platform"):
            with self.subTest(control=control):
                self.run_case(f"failed:{control}")

    def test_pending_profile_is_distinct_from_preserved_map(self) -> None:
        self.run_case("previous-map")

    def test_retry_clears_failure_only_after_success(self) -> None:
        self.run_case("retry")

    def test_single_flight_pins_the_dispatched_profile(self) -> None:
        self.run_case("single-flight")

    def test_all_profiles_and_local_filtering(self) -> None:
        for platform in ("linux", "windows", "other"):
            with self.subTest(platform=platform):
                self.run_case(f"accepted:{platform}")

    def test_wrong_profile_and_action_claim_preserve_stale_snapshot(self) -> None:
        for kind in ("profile", "action"):
            with self.subTest(kind=kind):
                self.run_case(f"rejected:{kind}")

    def test_invalid_selection_does_not_request(self) -> None:
        self.run_case("invalid-selection")


if __name__ == "__main__":
    unittest.main()
