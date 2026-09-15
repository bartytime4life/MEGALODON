"""A complete report cannot amplify candidates beyond its admitted baseline."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json

import pytest

from megalodon.models import PacketEvent
from megalodon.offline.analysis import baseline
from megalodon.offline.common import Batch, Limits, OfflineError
from megalodon.offline import reports
from megalodon.offline_projection import load_offline_projection


STAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)


def batch(records):
    return Batch('tshark-fields-v1', 'packet', tuple(records), len(records), 0, 128,
                 '4.6.0', 'subprocess_version')


def packet(index, port=53, src='192.0.2.1'):
    return PacketEvent(STAMP + timedelta(seconds=index), src, '198.51.100.2',
                       'TCP', src_port=40000, dst_port=port, byte_count=64)


def report(tmp_path, records=None):
    records = records if records is not None else [packet(i) for i in range(20)]
    output = tmp_path / 'run'
    reference = baseline(batch([packet(i, 443) for i in range(20)]))
    with reports.output_directory(str(output)) as directory:
        reports.finish(directory, reports.manifest('case1', 'tshark', Limits()),
                       Limits(), batch=batch(records), reference=reference)
    return output


def findings(output):
    return [json.loads(line) for line in (output / 'candidates.jsonl').read_text().splitlines()]


def replace_findings(output, rows):
    (output / 'candidates.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='ascii')
    path = output / 'manifest.json'
    value = json.loads(path.read_text())
    value['candidate_count'] = len(rows)
    path.write_text(json.dumps(value), encoding='ascii')


@pytest.mark.parametrize('rule,field,value', [
    ('NEW_DESTINATION_PORT', 'port', 8443),
    ('NEW_DESTINATION_PORT', 'records', 19),
    ('NEW_DESTINATION_PORT', 'protocol', 'UDP'),
    ('REGULAR_INTERVAL', 'port', 8443),
    ('REGULAR_INTERVAL', 'protocol', 'UDP'),
    ('REGULAR_INTERVAL', 'src', 'host-00000'),
    ('REGULAR_INTERVAL', 'dst', 'host-00041'),
    ('PORT_53_BURST', 'relative_minute', 1),
    ('PORT_53_BURST', 'src', 'host-00000'),
    ('PORT_53_BURST', 'src', 'host-00041'),
])
def test_individually_plausible_candidate_cannot_contradict_baseline(tmp_path, rule, field, value):
    output = report(tmp_path)
    rows = findings(output)
    row = next(row for row in rows if row['rule'] == rule)
    row['evidence'][field] = value
    replace_findings(output, rows)
    with pytest.raises(OfflineError, match='^INVALID_OFFLINE_CANDIDATE$'):
        load_offline_projection(output)


@pytest.mark.parametrize('rule', ['NEW_DESTINATION_PORT', 'REGULAR_INTERVAL', 'PORT_53_BURST'])
def test_duplicate_candidate_identity_cannot_inflate_counts(tmp_path, rule):
    output = report(tmp_path)
    rows = findings(output)
    duplicate = deepcopy(next(row for row in rows if row['rule'] == rule))
    # Even alternate numeric representation cannot bypass identity accounting.
    key = 'relative_minute' if rule == 'PORT_53_BURST' else 'port'
    duplicate['evidence'][key] = str(duplicate['evidence'][key])
    replace_findings(output, rows + [duplicate])
    with pytest.raises(OfflineError, match='^INVALID_OFFLINE_CANDIDATE$'):
        load_offline_projection(output)


@pytest.mark.parametrize('rule', ['REGULAR_INTERVAL', 'PORT_53_BURST'])
def test_distinct_groups_cannot_overclaim_the_same_aggregate_support(tmp_path, rule):
    output = report(tmp_path)
    rows = findings(output)
    duplicate = deepcopy(next(row for row in rows if row['rule'] == rule))
    duplicate['evidence']['src'] = 'host-00003'
    replace_findings(output, rows + [duplicate])
    with pytest.raises(OfflineError, match='^INVALID_OFFLINE_CANDIDATE$'):
        load_offline_projection(output)


def test_burst_requires_port_53_support_even_with_sufficient_minute_total(tmp_path):
    output = report(tmp_path, [packet(i, 443) for i in range(20)])
    rows = findings(output)
    rows.append({'rule': 'PORT_53_BURST', 'status': 'candidate', 'record_kind': 'packet',
                 'action_status': 'not_attempted',
                 'evidence': {'src': 'host-00001', 'relative_minute': 0, 'records': 20}})
    replace_findings(output, rows)
    with pytest.raises(OfflineError, match='^INVALID_OFFLINE_CANDIDATE$'):
        load_offline_projection(output)


def test_burst_minute_budget_is_separate_from_whole_run_port_support(tmp_path):
    output = report(tmp_path, [packet(i, 53) for i in range(10)] +
                    [packet(60+i, 53) for i in range(10)])
    rows = findings(output)
    rows.append({'rule': 'PORT_53_BURST', 'status': 'candidate', 'record_kind': 'packet',
                 'action_status': 'not_attempted',
                 'evidence': {'src': 'host-00001', 'relative_minute': 0, 'records': 20}})
    replace_findings(output, rows)
    with pytest.raises(OfflineError, match='^INVALID_OFFLINE_CANDIDATE$'):
        load_offline_projection(output)


def test_generated_overlap_across_rules_is_valid_and_source_details_stay_private(tmp_path):
    output = report(tmp_path)
    before = {p.name: p.read_bytes() for p in output.iterdir()}
    result = load_offline_projection(output)
    assert result['candidates'] == [
        {'rule': rule, 'status': 'candidate', 'count': 1}
        for rule in ('NEW_DESTINATION_PORT', 'REGULAR_INTERVAL', 'PORT_53_BURST')]
    encoded = json.dumps(result)
    for private in ('host-00001', '192.0.2.1', 'median_interval_us', str(output)):
        assert private not in encoded
    assert {p.name: p.read_bytes() for p in output.iterdir()} == before


def test_distinct_generated_groups_can_share_protocol_port_and_minute(tmp_path):
    records = [packet(i, src=src) for src in ('192.0.2.1', '192.0.2.3') for i in range(20)]
    result = load_offline_projection(report(tmp_path, records))
    assert {row['rule']: row['count'] for row in result['candidates']} == {
        'NEW_DESTINATION_PORT': 1, 'REGULAR_INTERVAL': 2, 'PORT_53_BURST': 2}


def test_candidate_support_uses_ports_beyond_the_ui_truncation(tmp_path):
    records = [packet(i, 1000+i) for i in range(15)]
    result = load_offline_projection(report(tmp_path, records))
    assert result['summary']['destination_ports_truncated'] is True
    assert len(result['summary']['destination_ports']) == 12
    assert result['candidates'] == [{'rule': 'NEW_DESTINATION_PORT', 'status': 'candidate', 'count': 15}]


def test_impossible_regular_group_is_rejected_even_below_whole_run_count(tmp_path):
    output = report(tmp_path, [packet(i, 53) for i in range(5)] + [packet(i, 443) for i in range(15)])
    rows = findings(output)
    next(row for row in rows if row['rule'] == 'REGULAR_INTERVAL' and row['evidence']['port'] == 53)['evidence']['unique_observations'] = 6
    replace_findings(output, rows)
    with pytest.raises(OfflineError, match='^INVALID_OFFLINE_CANDIDATE$'):
        load_offline_projection(output)
