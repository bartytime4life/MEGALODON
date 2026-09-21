"""Browser-local ingestion export must follow receipt availability, not traffic."""

import json
import shutil
import subprocess

import pytest

from megalodon.dashboard_assets import DASHBOARD_JS


def test_ingestion_report_uses_only_all_source_receipts_when_traffic_is_unavailable():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for dashboard JavaScript behavior")

    start = DASHBOARD_JS.index("function reportSnapshot()")
    end = DASHBOARD_JS.index("function reportPlainText(", start)
    script = r"""
const vm = require('node:vm');
let code = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { code += chunk; });
process.stdin.on('end', () => {
  const nodes = {'report-scope': {value: 'ingestion'}, 'report-title-input': {value: ''}};
  const state = {
    summary: null, traffic: null, lastSuccessfulRefresh: null,
    ingestionRunsFetchedAt: '2026-09-21T12:00:00.000Z',
    ingestionRuns: [{run_id: 7, source: 'jsonl', status: 'incomplete',
      processed_count: 2, detection_count: 1, action_count: 1}],
    config: {event_limit: 50}
  };
  const context = vm.createContext({state, Date, byId: id => nodes[id],
    formatRefreshTime: date => date.toISOString()});
  vm.runInContext(code, context, {timeout: 1000});
  const receiptReport = vm.runInContext('reportSnapshot()', context, {timeout: 1000});
  if (!receiptReport || receiptReport.scope !== 'ingestion'
      || receiptReport.last_dashboard_refresh !== state.ingestionRunsFetchedAt
      || receiptReport.ingestion_runs.length !== 1
      || 'traffic' in receiptReport || 'summary' in receiptReport
      || !receiptReport.limitation.includes('accepted/rejected counts are not recorded')
      || !receiptReport.limitation.includes('plan-only action records')) {
    throw Error('ingestion export did not preserve its receipt-only evidence boundary');
  }
  receiptReport.ingestion_runs[0].processed_count = 99;
  if (state.ingestionRuns[0].processed_count !== 2) throw Error('report mutated stored UI state');
  nodes['report-scope'].value = 'overview';
  if (vm.runInContext('reportSnapshot()', context) !== null)
    throw Error('unavailable traffic became an overview report');
  nodes['report-scope'].value = 'ingestion';
  state.ingestionRunsFetchedAt = null;
  if (vm.runInContext('reportSnapshot()', context) !== null)
    throw Error('missing receipts became an ingestion report');
  state.ingestionRunsFetchedAt = '2026-09-21T12:01:00.000Z';
  state.ingestionRuns = [];
  const empty = vm.runInContext('reportSnapshot()', context);
  if (!empty || empty.ingestion_runs.length !== 0
      || !empty.limitation.includes('No sensor liveness'))
    throw Error('empty receipt export lost its explicit limit');
  process.stdout.write(JSON.stringify(receiptReport));
});
"""
    result = subprocess.run(
        [node, "-e", script],
        input=DASHBOARD_JS[start:end],
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["source_scope"].startswith("1 all-source run receipts")
    assert report["bounds"] == (
        "Newest 8 stored core ingestion receipts maximum, across all recorded sources."
    )
