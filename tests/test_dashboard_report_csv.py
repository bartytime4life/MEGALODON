"""Exercise the shipped audit CSV serializer without a browser or spreadsheet."""
import csv
import io
import json
import shutil
import subprocess

import pytest

from megalodon.dashboard_assets import DASHBOARD_JS


def _serialize(reports):
    node = shutil.which('node')
    if not node:
        pytest.skip('Node required for audit CSV serializer tests')
    start = DASHBOARD_JS.index('function reportCsv(')
    end = DASHBOARD_JS.index('function downloadReport(', start)
    script = r'''
const fs = require('node:fs'), vm = require('node:vm');
const {code, reports} = JSON.parse(fs.readFileSync(0, 'utf8'));
const context = vm.createContext({reports});
vm.runInContext(code, context, {timeout: 1000});
const before = JSON.stringify(reports);
const result = vm.runInContext('reports.map(reportCsv)', context, {timeout: 1000});
if (before !== JSON.stringify(reports)) throw Error('Export mutated evidence');
process.stdout.write(JSON.stringify(result));
'''
    result = subprocess.run(
        [node, '-e', script], input=json.dumps({'code': DASHBOARD_JS[start:end], 'reports': reports}),
        text=True, capture_output=True, timeout=10, check=True,
    )
    return [list(csv.reader(io.StringIO(value))) for value in json.loads(result.stdout)]


def _report(**rows):
    return dict(scope='detections', source_scope='Synthetic stored rows only',
                last_dashboard_refresh='2026-09-20T00:00:00.000Z',
                bounds='Newest 50 detections maximum', limitation='Not capture completeness.', **rows)


def test_formula_like_cells_are_text_and_original_evidence_is_unchanged():
    dangerous = ['=1+1', '+1+1', '-1+1', '@SUM(1,1)', '\t=1+1', '\r=1+1',
                 '\n=1+1', '  =1+1', '\ufeff=1+1', '\x00=1+1']
    ordinary = ['ordinary text', 'comma, and "quote"', 'two\nlines', '', '192.0.2.10', 'LOW']
    reports = [_report(detections=[dict(detected_at=value, severity=value, rule_id=value,
                                       src_ip=value, message=value)]) for value in dangerous + ordinary]
    rows = _serialize(reports)
    for value, result in zip(dangerous + ordinary, rows):
        expected = "'" + value if value in dangerous else value
        assert result[-1] == [expected] * 5


def test_every_scope_carries_limits_and_protects_ingestion_text():
    reports = [
        _report(detections=[]),
        _report(ingestion_runs=[dict(run_id='=1+1', processed_count=0, finished_at=None)]),
        _report(summary=dict(events=0, detections=0, high_or_critical=0, actions=0),
                traffic=dict(sampled_events=0, total_bytes=0)),
    ]
    reports[1]['scope'] = 'ingestion'
    reports[2]['scope'] = 'overview'
    for report, result in zip(reports, _serialize(reports)):
        metadata = dict(row for row in result[:result.index([])])
        assert metadata['bounds'] == report['bounds']
        assert metadata['limitation'] == report['limitation']
        assert metadata['last_dashboard_refresh'] == report['last_dashboard_refresh']
        assert 'apostrophe' in metadata['csv_text_policy']
        if report['scope'] == 'ingestion':
            assert result[-1][0] == "'=1+1"
            assert result[-1][4:6] == ['', '0']


def test_csv_metadata_uses_the_same_text_protection():
    report = _report(detections=[])
    for field in ('scope', 'source_scope', 'last_dashboard_refresh', 'bounds', 'limitation'):
        report[field] = ' \t=1+1'
    rows = _serialize([report])[0]
    metadata = dict(rows[:rows.index([])])
    for key in ('report_scope', 'source_scope', 'last_dashboard_refresh', 'bounds', 'limitation'):
        assert metadata[key] == "' \t=1+1"
