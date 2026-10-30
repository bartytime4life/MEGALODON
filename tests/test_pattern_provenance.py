"""Synthetic timing evidence stays in its hour and cites its own observations."""
from copy import deepcopy
from datetime import datetime, timezone
import json
from unittest.mock import patch

import pytest

from megalodon.evidence_storage import utc
from megalodon.models import PacketEvent
from megalodon.offline.analysis import candidates, MAX_PROVENANCE_RECORDS
from megalodon.offline.common import Batch, OfflineError
from megalodon.security_patterns import analyze_hour, MAX_GROUP_RECORDS

START = 1790812800
SEGMENT = 'a' * 32


def row(number, seconds, *, port=443, destination='198.51.100.1', category='flows'):
    return dict(id=f'{SEGMENT}:{number}', observed_at=utc(START + seconds),
                category=category, source='synthetic-sensor', data=dict(
                    src_ip='192.0.2.1', dst_ip=destination, src_port=40000,
                    dst_port=port, protocol='TCP', interface='fixture0',
                    source_id=f'connection-{number}', first_seen=utc(START + seconds)))


def activity(rule, *, offset=1800, count=None, first_number=31):
    count = count if count is not None else (5 if rule == 'REGULAR_INTERVAL' else 20)
    return [row(first_number + i, offset + i * (10 if rule == 'REGULAR_INTERVAL' else 1),
                port=443 if rule == 'REGULAR_INTERVAL' else 53) for i in range(count)]


def reviews(values, rule):
    return [item for item in analyze_hour(values, START, START + 3600, [])[1]
            if item['rule'] == rule]


@pytest.mark.parametrize('rule', ['REGULAR_INTERVAL', 'PORT_53_BURST'])
def test_late_signal_cites_its_support_and_excludes_unrelated_early_rows(rule):
    noise = [row(i + 1, i, port=80, destination='198.51.100.250') for i in range(30)]
    support = activity(rule)
    result = reviews(noise + support, rule)[0]
    assert result['evidence_refs'] == [r['id'] for r in support]
    assert result['facts']['first_seen'] == support[0]['data']['first_seen']
    assert result['facts']['last_seen'] == support[-1]['data']['first_seen']
    assert result['facts']['references_omitted'] == 0
    assert 'record_numbers' not in result['facts']
    assert 'offset_us' not in json.dumps(result['facts'])
    assert result['action_status'] == 'not_attempted'


@pytest.mark.parametrize('rule', ['REGULAR_INTERVAL', 'PORT_53_BURST'])
def test_periodic_updates_of_old_connections_cannot_replay_old_activity(rule):
    old = activity(rule, offset=-3600)
    for value in old:
        value['observed_at'] = utc(START + 100)
    assert not reviews(old, rule)
    current = activity(rule, first_number=101)
    result = reviews(old + current, rule)
    assert len(result) == 1
    assert result[0]['evidence_refs'] == [r['id'] for r in current]


@pytest.mark.parametrize('rule', ['REGULAR_INTERVAL', 'PORT_53_BURST'])
@pytest.mark.parametrize('outside', [-1, 3600])
def test_half_open_hour_excludes_a_start_before_or_at_end(rule, outside):
    values = activity(rule, offset=0)
    values[-1]['data']['first_seen'] = utc(START + outside)
    assert not reviews(values, rule)
    values[-1]['data']['first_seen'] = utc(START + (40 if rule == 'REGULAR_INTERVAL' else 19))
    assert reviews(values, rule)


@pytest.mark.parametrize('rule', ['REGULAR_INTERVAL', 'PORT_53_BURST'])
def test_all_support_segments_are_dependencies_even_when_reference_page_is_full(rule):
    values = activity(rule, count=30)
    values[-1]['id'] = 'b' * 32 + ':1'
    result = reviews(values, rule)[0]
    assert result['evidence_refs'] == [r['id'] for r in values[:24]]
    assert result['source_segments'] == ['a' * 32, 'b' * 32]
    assert result['facts']['references_omitted'] == 6
    assert any('6 supporting observations' in gap for gap in result['missing_information'])
    assert result['facts']['last_seen'] == values[-1]['data']['first_seen']
    assert len(json.dumps(result).encode()) < 32768


def test_cadence_selects_one_representative_per_distinct_start_time():
    values = activity('REGULAR_INTERVAL')
    duplicate = deepcopy(values[0])
    duplicate['id'] = SEGMENT + ':100'
    duplicate['data']['source_id'] = 'another-connection-at-the-same-time'
    result = reviews(values + [duplicate], 'REGULAR_INTERVAL')[0]
    assert result['facts']['unique_observations'] == 5
    assert result['evidence_refs'] == [r['id'] for r in values]


def test_burst_exposes_absolute_bin_and_counts_transport_qualified_observations():
    values = activity('PORT_53_BURST', offset=55)
    result = reviews(values, 'PORT_53_BURST')[0]
    assert result['facts']['window_start'] == utc(START + 55)
    assert result['facts']['window_end'] == utc(START + 115)
    assert result['facts']['records'] == 20
    assert 'relative_minute' not in result['facts']
    values[-1]['data']['protocol'] = 'ICMP'
    values[-1]['data']['src_port'] = values[-1]['data']['dst_port'] = None
    assert not reviews(values, 'PORT_53_BURST')


def test_packet_bursts_use_observation_time_and_never_become_connection_cadence():
    values = activity('PORT_53_BURST')
    for value in values:
        value['category'] = 'packets'
        value['data']['first_seen'] = utc(START - 86400)
    result = reviews(values, 'PORT_53_BURST')[0]
    assert result['facts']['first_seen'] == values[0]['observed_at']
    assert result['measurement'] == 'packet'
    assert not reviews(values, 'REGULAR_INTERVAL')


@pytest.mark.parametrize('rule', ['REGULAR_INTERVAL', 'PORT_53_BURST'])
def test_support_dependencies_do_not_include_unrelated_noise_segments(rule):
    noise = row(1, 0, port=80)
    noise['id'] = 'c' * 32 + ':1'
    result = reviews([noise] + activity(rule), rule)[0]
    assert result['source_segments'] == [SEGMENT]


@pytest.mark.parametrize('rule', ['REGULAR_INTERVAL', 'PORT_53_BURST'])
def test_latest_periodic_representatives_are_used_once(rule):
    values = activity(rule)
    updates = deepcopy(values)
    for i, value in enumerate(updates):
        value['id'] = SEGMENT + ':' + str(100 + i)
        value['observed_at'] = utc(START + 2500)
    result = reviews(values + updates, rule)[0]
    assert result['evidence_refs'] == [r['id'] for r in updates]


@pytest.mark.parametrize('rule', ['REGULAR_INTERVAL', 'PORT_53_BURST'])
@pytest.mark.parametrize('field', ['source', 'interface', 'src_ip'])
def test_source_and_interface_scopes_cannot_complete_each_others_signal(rule, field):
    values = activity(rule)
    target = values[-1] if field == 'source' else values[-1]['data']
    target[field] = '192.0.2.2' if field == 'src_ip' else 'other'
    assert not reviews(values, rule)


def test_default_offline_shape_remains_compatible_and_input_is_unchanged():
    values = activity('REGULAR_INTERVAL')
    records = tuple(PacketEvent(datetime.fromtimestamp(START + i * 2, timezone.utc),
                               '192.0.2.1', '198.51.100.1', 'TCP', dst_port=53)
                    for i in range(20))
    batch = Batch('synthetic', 'flow', records, len(records), 0, 0, 'v1', 'synthetic-only')
    result = candidates(batch)
    assert [item['rule'] for item in result] == ['REGULAR_INTERVAL', 'PORT_53_BURST']
    assert set(result[0]['evidence']) == {'src', 'dst', 'protocol', 'port', 'unique_observations',
                                        'median_interval_us', 'interval_spread_us'}
    assert set(result[1]['evidence']) == {'src', 'relative_minute', 'records'}
    original = deepcopy(values)
    def forbidden(*args, **kwargs):
        raise AssertionError('external work attempted')
    with patch('socket.socket', forbidden), patch('socket.getaddrinfo', forbidden), \
         patch('subprocess.Popen', forbidden), patch('sqlite3.connect', forbidden), \
         patch('builtins.open', forbidden), patch('os.open', forbidden):
        assert reviews(values, 'REGULAR_INTERVAL')
    assert values == original


def test_existing_group_work_limit_still_abstains():
    values = activity('PORT_53_BURST', count=MAX_GROUP_RECORDS + 1, offset=0)
    assert not reviews(values, 'PORT_53_BURST')


def test_opt_in_provenance_refuses_over_limit_before_doing_analysis():
    record=PacketEvent(datetime.fromtimestamp(START,timezone.utc),'192.0.2.1','198.51.100.1','TCP',dst_port=53)
    batch=Batch('synthetic','flow',(record,)*(MAX_PROVENANCE_RECORDS+1),MAX_PROVENANCE_RECORDS+1,0,0,'v1','synthetic-only')
    with pytest.raises(OfflineError,match='^TIMING_PROVENANCE_RECORD_LIMIT$'):
        candidates(batch,timing_provenance=True)
