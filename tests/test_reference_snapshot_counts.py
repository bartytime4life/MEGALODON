"""Count binding against the complete emitted asset, with no real API or I/O."""
from __future__ import annotations

import json
import shutil
import subprocess
import unittest

from megalodon.dashboard_assets import DASHBOARD_JS


HARNESS = r"""
const vm = require('node:vm');
const assert = require('node:assert/strict');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', () => {
  const {asset, rejection} = JSON.parse(input);
  const code = asset.replace(/\nbootstrap\(\);\s*$/, '\n');
  assert.notEqual(code, asset, 'exact final bootstrap must be removed');
  const context = vm.createContext({
    document: {
      getElementById() { return {addEventListener() {}}; },
      addEventListener() {},
      createElement() { throw new Error('unexpected rendering'); }
    },
    window: {
      setTimeout() { throw new Error('unexpected timer'); },
      clearTimeout() { throw new Error('unexpected timer'); }
    },
    fetch() { throw new Error('unexpected network request'); },
    assert, rejection
  });
  vm.runInContext(code, context, {timeout: 1000});
  vm.runInContext(`
    const sources = Object.values(referenceExpectedSources).map(id => ({
      id, registry_url: 'https://example.invalid/registry',
      registry_last_updated: '2026-09-01', retrieved_at: '2026-09-01T00:00:00Z',
      retrieved_at_basis: 'Synthetic fixture, not production provenance'
    }));
    let assertions = 0;
    for (const kind of ['port', 'protocol']) {
      const cases = rejection ? [[0, 1], [1, 2], [8, 9]] : [[0, 0], [1, 1], [8, 8], [9, 9], [10, 1]];
      for (const [total, count] of cases) {
        const relevant = kind === 'port' ? 'service_records' : 'protocol_records';
        const snapshot = validatedReferenceStatus({
          schema: 'reference-library-status-v1', available: true, status: 'ready',
          bundle_id: 'synthetic-count-test', bundle_version: 'v1', manifest_sha256: 'a'.repeat(64),
          service_records: kind === 'port' ? total : 0,
          protocol_records: kind === 'protocol' ? total : 0,
          cache_entries: 0, cache_limit: 16, sources, warning: 'Synthetic registration context only.',
          network_access_performed: false, persistence_status: 'not_attempted', action_status: 'not_attempted'
        });
        const query = kind === 'port' ? {transport: 'tcp', port: 443} : {number: 6};
        const result = {
          schema: 'reference-library-lookup-v1', available: true, kind, query,
          status: count === 0 ? 'no_match' : count === 1 ? 'one_match' : 'multiple_matches',
          bundle_id: snapshot.bundle_id, bundle_version: snapshot.bundle_version,
          manifest_sha256: snapshot.manifest_sha256, warning: snapshot.warning,
          network_access_performed: false, persistence_status: 'not_attempted', action_status: 'not_attempted',
          match_count: count, truncated: count > 8,
          sources: sources.filter(source => source.id === referenceExpectedSources[kind]),
          matches: Array.from({length: Math.min(count, 8)}, (_, index) => kind === 'port' ? {
            service_name: 'fixture', transport: 'tcp', port_start: 443, port_end: 443,
            record_kind: 'named', description: null, registration_date: null, modification_date: null,
            source_row: index + 1
          } : {
            keyword: 'fixture', protocol_name: 'Synthetic protocol', decimal_start: 6, decimal_end: 6,
            record_kind: 'named', ipv6_extension_header: 'no', source_row: index + 1
          })
        };
        const check = () => validatedReferenceResult(result, kind, query, snapshot);
        if (rejection) assert.throws(check, 'lookup cannot exceed ' + relevant);
        else assert.equal(check().match_count, count, 'use the correct source total');
        assertions += 1;
      }
    }
    assert.equal(assertions, rejection ? 6 : 10);
  `, context, {timeout: 1000});
});
"""


@unittest.skipUnless(shutil.which("node"), "Node is required for count-binding behavior")
class ReferenceSnapshotCountsTests(unittest.TestCase):
    def run_cases(self, *, rejection: bool) -> None:
        result = subprocess.run(
            [shutil.which("node"), "-e", HARNESS],
            input=json.dumps({"asset": DASHBOARD_JS, "rejection": rejection}),
            text=True, capture_output=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_counts_at_or_below_the_correct_snapshot_total(self) -> None:
        self.run_cases(rejection=False)

    def test_counts_above_the_correct_snapshot_total_fail_closed(self) -> None:
        self.run_cases(rejection=True)


if __name__ == "__main__":
    unittest.main()
