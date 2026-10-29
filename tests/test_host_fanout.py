"""Synthetic connection metadata only; no sensor, traffic or host action."""
from dataclasses import replace
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from unittest.mock import patch

import pytest

from megalodon.evidence_storage import utc
from megalodon.models import PacketEvent
from megalodon.offline.analysis import candidates, MAX_FANOUT_RECORDS
from megalodon.offline.common import Batch, FlowRecord, Limits, OfflineError
from megalodon.offline import reports
from megalodon.offline_projection import load_offline_projection
from megalodon.security_patterns import analyze_hour

START = datetime(2026, 10, 1, tzinfo=timezone.utc)
SEGMENT = 'a' * 32


def connection(index, *, seconds=None, destination=None, source='192.0.2.1',
               protocol='TCP', port=445):
    return FlowRecord(START + timedelta(seconds=index if seconds is None else seconds),
                      source, destination or f'198.51.100.{index + 1}', protocol,
                      40000, port, 0, 1, 0, 60, 'S0')


def batch(records, kind='flow'):
    return Batch('synthetic-connection', kind, tuple(records), len(records), 0, 0,
                 '8.0.10', 'synthetic-only')


def fanout(records, kind='flow'):
    return [item for item in candidates(batch(records, kind)) if item['rule'] == 'HOST_FANOUT']


def retained(records, *, sensor='synthetic-sensor', category='flows', prefix='r'):
    return [dict(id=f'{SEGMENT}:{prefix}{index}', observed_at=utc(record.observed_at.timestamp()),
                 source=sensor, category=category, data=dict(
                     src_ip=record.src_ip, dst_ip=record.dst_ip, src_port=record.src_port,
                     dst_port=record.dst_port, protocol=record.protocol, interface='fixture0',
                     source_id=f'{prefix}{index}', first_seen=utc(record.observed_at.timestamp())))
            for index, record in enumerate(records)]


def reviews(rows, **kwargs):
    _, results, _ = analyze_hour(rows, START.timestamp(), START.timestamp() + 3600, [], **kwargs)
    return [item for item in results if item['rule'] == 'HOST_FANOUT']


@pytest.mark.parametrize('count,expected', [(0, 0), (15, 0), (16, 1), (30, 1)])
def test_threshold_and_first_window_only(count, expected):
    result = fanout([connection(i) for i in range(count)])
    assert len(result) == expected
    if result:
        item = result[0]
        assert item['status'] == 'candidate'
        assert item['action_status'] == 'not_attempted'
        assert item['evidence'] == dict(src='host-00001', protocol='TCP', port=445,
            distinct_destinations=16, window_seconds=60, first_offset_us=0,
            last_offset_us=15_000_000, record_numbers=list(range(1, 17)))


@pytest.mark.parametrize('last,expected', [(60, 1), (60.000001, 0)])
def test_exact_sliding_window_boundary(last, expected):
    values = [connection(i) for i in range(15)] + [connection(15, seconds=last)]
    assert len(fanout(values)) == expected


def test_sliding_window_not_fixed_minute_bins_and_input_order():
    values = [connection(i, seconds=55 + i) for i in range(16)]
    for ordered in (values, list(reversed(values))):
        item = fanout(ordered)[0]['evidence']
        assert item['last_offset_us'] - item['first_offset_us'] == 15_000_000
        representatives = [ordered[n - 1] for n in item['record_numbers']]
        assert len({record.dst_ip for record in representatives}) == 16
        assert len(item['record_numbers']) == 16


def test_repeated_destination_and_expired_peers_do_not_inflate_count():
    assert not fanout([connection(i, destination='198.51.100.1') for i in range(100)])
    assert not fanout([connection(i, seconds=i * 5) for i in range(16)])
    # Old duplicate observations expire without removing a still-present peer.
    records = [connection(0, seconds=0), connection(0, seconds=50)]
    records += [connection(i, seconds=61 + i) for i in range(1, 16)]
    item = fanout(records)[0]['evidence']
    assert item['record_numbers'] == list(range(2, 18))
    assert item['first_offset_us'] == 50_000_000


@pytest.mark.parametrize('change', [dict(source='192.0.2.2'), dict(protocol='UDP'), dict(port=443)])
def test_sources_transports_and_ports_never_combine(change):
    values = [connection(i) for i in range(8)]
    values += [connection(i, **change) for i in range(8, 16)]
    assert not fanout(values)


def test_ipv6_and_udp_supported_without_contacting_addresses():
    values = [connection(i, source='2001:db8::1', destination=f'2001:db8:1::{i+1:x}',
                         protocol='UDP') for i in range(16)]
    result = fanout(values)
    assert len(result) == 1
    assert '2001:db8' not in json.dumps(result)


@pytest.mark.parametrize('family', ['multicast', 'loopback', 'unspecified'])
def test_non_unicast_destinations_do_not_complete_a_window(family):
    values = [connection(i) for i in range(15)]
    destination = {'multicast': '239.0.0.1', 'loopback': '127.0.0.2', 'unspecified': '0.0.0.0'}[family]
    assert not fanout(values + [connection(15, destination=destination)])


def test_ipv4_mapped_alias_is_one_destination():
    # Retained summaries use validated PacketEvent projections for flow starts.
    values = [PacketEvent(START + timedelta(seconds=i), '192.0.2.1', f'198.51.100.{i+1}',
                          'TCP', dst_port=445) for i in range(15)]
    values.append(replace(values[0], observed_at=START + timedelta(seconds=15),
                          dst_ip='::ffff:198.51.100.1'))
    assert not fanout(values)


def test_packets_cannot_be_promoted_to_connection_sweep_evidence():
    values = [connection(i) for i in range(16)]
    assert not fanout(values, kind='packet')
    assert not reviews(retained(values, category='packets'))


def test_retained_review_links_late_qualifying_records_and_keeps_gaps():
    ordinary = [connection(i, destination='198.51.100.250') for i in range(30)]
    sweeping = [connection(i, seconds=1800 + i) for i in range(16)]
    rows = retained(ordinary + sweeping)
    item = reviews(rows, gaps=['Synthetic partial visibility'])[0]
    assert item['evidence_refs'] == [row['id'] for row in rows[30:]]
    assert 'record_numbers' not in item['facts']
    assert 'Synthetic partial visibility' in item['missing_information']
    assert item['workflow'] == 'device_changes'
    assert item['state'] == 'unreviewed'
    assert item['action_status'] == 'not_attempted'
    assert 'Inventory scans' in item['why_it_matters']


@pytest.mark.parametrize('field,value', [('source', 'other-sensor'), ('interface', 'other0')])
def test_retained_sensor_and_interface_separation(field, value):
    values = retained([connection(i) for i in range(16)])
    for row in values[8:]:
        (row if field == 'source' else row['data'])[field] = value
    assert not reviews(values)


def test_flow_poll_times_cannot_substitute_for_connection_starts():
    values = retained([connection(i, seconds=i * 120) for i in range(16)])
    for i, row in enumerate(values):
        row['observed_at'] = utc(START.timestamp() + 2000 + i)
    assert not reviews(values)


def test_old_sweep_is_not_replayed_and_cannot_hide_a_current_window():
    old = [replace(connection(i), observed_at=START - timedelta(days=1, seconds=-i))
           for i in range(16)]
    rows = retained(old, prefix='old')
    for row in rows:
        row['observed_at'] = utc(START.timestamp() + 100)
    assert not reviews(rows)
    current = retained([connection(i, seconds=1800+i) for i in range(16)], prefix='new')
    item = reviews(rows + current)[0]
    assert item['evidence_refs'] == [row['id'] for row in current]
    assert item['facts']['first_seen'] == (START + timedelta(seconds=1800)).isoformat()
    assert item['facts']['last_seen'] == (START + timedelta(seconds=1815)).isoformat()
    assert 'first_offset_us' not in item['facts']


def test_periodic_updates_preserve_one_identity_and_missing_identity_abstains():
    values = retained([connection(i) for i in range(15)])
    updates = [dict(row, observed_at=utc(START.timestamp() + 30)) for row in values]
    assert not reviews(values + updates)
    values = retained([connection(i) for i in range(16)])
    values[0]['data'].pop('source_id')
    assert not reviews(values)


def test_new_analysis_is_finite_and_performs_no_external_work():
    values = [connection(i) for i in range(16)]
    rows = retained(values)
    def forbidden(*args, **kwargs):
        raise AssertionError('external work attempted')
    with patch('socket.socket', forbidden), patch('socket.getaddrinfo', forbidden), \
         patch('subprocess.Popen', forbidden), patch('sqlite3.connect', forbidden), \
         patch('builtins.open', forbidden), patch('os.open', forbidden):
        assert fanout(values)
        assert reviews(rows)
    assert rows == retained(values)
    with pytest.raises(OfflineError, match='FANOUT_RECORD_LIMIT'):
        fanout([values[0]] * (MAX_FANOUT_RECORDS + 1))


def flow_report(tmp_path, records=None):
    values = records if records is not None else [connection(i) for i in range(16)]
    source = Batch('zeek-conn-json-v1', 'flow', tuple(values), len(values), 0, 128,
                   '8.0.10', 'operator_declared_unverified')
    output = tmp_path / 'run'
    with reports.output_directory(str(output)) as directory:
        reports.finish(directory, reports.manifest('fanout-case', 'zeek-json', Limits()),
                       Limits(), batch=source)
    return output


def rewrite_candidates(output, rows):
    (output / 'candidates.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
    manifest = output / 'manifest.json'
    value = json.loads(manifest.read_text())
    value['candidate_count'] = len(rows)
    manifest.write_text(json.dumps(value))


def test_completed_report_projection_accepts_counts_and_excludes_private_details(tmp_path):
    output = flow_report(tmp_path)
    before = {path.name: path.read_bytes() for path in output.iterdir()}
    result = load_offline_projection(output)
    assert result['candidates'] == [dict(rule='HOST_FANOUT', status='candidate', count=1)]
    for private in ['192.0.2.1', '198.51.100.1', 'record_numbers', 'host-00001', str(output)]:
        assert private not in json.dumps(result)
    assert {path.name: path.read_bytes() for path in output.iterdir()} == before


@pytest.mark.parametrize('field,value', [
    ('protocol', 'ICMP'), ('protocol', []), ('port', 8443), ('port', True),
    ('src', 'host-00000'), ('src', 'host-00033'), ('distinct_destinations', 15),
    ('distinct_destinations', 17), ('window_seconds', 61), ('window_seconds', True),
    ('first_offset_us', -1), ('first_offset_us', 16_000_000),
    ('last_offset_us', 60_000_001), ('last_offset_us', float('inf')),
    ('record_numbers', list(range(16))), ('record_numbers', list(range(2, 18))),
    ('record_numbers', [1] * 16), ('record_numbers', [True] + list(range(2, 17))),
    ('record_numbers', None), ('record_numbers', [[1]] * 16), ('payload', 'refused'),
])
def test_projection_refuses_contradictions_without_editing_report(tmp_path, field, value):
    output = flow_report(tmp_path)
    rows = [json.loads(line) for line in (output / 'candidates.jsonl').read_text().splitlines()]
    rows[0]['evidence'][field] = value
    rewrite_candidates(output, rows)
    before = {path.name: path.read_bytes() for path in output.iterdir()}
    # Numeric/JSON framing can refuse before the per-candidate shape gate.
    with pytest.raises(OfflineError, match='^INVALID_OFFLINE_CANDIDATES?$'):
        load_offline_projection(output)
    assert {path.name: path.read_bytes() for path in output.iterdir()} == before


def test_projection_accepts_separate_groups_but_refuses_reused_record_numbers(tmp_path):
    values = [connection(i, source=src) for src in ['192.0.2.1', '192.0.2.2'] for i in range(16)]
    output = flow_report(tmp_path, values)
    assert load_offline_projection(output)['candidates'] == [dict(rule='HOST_FANOUT', status='candidate', count=2)]
    rows = [json.loads(line) for line in (output / 'candidates.jsonl').read_text().splitlines()]
    rows[1]['evidence']['record_numbers'] = rows[0]['evidence']['record_numbers']
    rewrite_candidates(output, rows)
    with pytest.raises(OfflineError, match='^INVALID_OFFLINE_CANDIDATE$'):
        load_offline_projection(output)


def test_projection_refuses_duplicate_group_and_unsupported_minute(tmp_path):
    output = flow_report(tmp_path)
    rows = [json.loads(line) for line in (output / 'candidates.jsonl').read_text().splitlines()]
    duplicate = deepcopy(rows[0])
    duplicate['evidence']['port'] = '445'
    rewrite_candidates(output, rows + [duplicate])
    with pytest.raises(OfflineError, match='^INVALID_OFFLINE_CANDIDATE$'):
        load_offline_projection(output)
    rows[0]['evidence'].update(first_offset_us=60_000_000, last_offset_us=75_000_000)
    rewrite_candidates(output, rows)
    with pytest.raises(OfflineError, match='^INVALID_OFFLINE_CANDIDATE$'):
        load_offline_projection(output)
