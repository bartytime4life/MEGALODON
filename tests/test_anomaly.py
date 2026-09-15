"""Synthetic anomaly evidence, quality abstention and zero-side-effect checks."""

from copy import deepcopy
import builtins
import json
from pathlib import Path
import socket
import sqlite3
import subprocess

import pytest

from megalodon.offline.anomaly import build_anomaly_dossier
from megalodon.offline.common import OfflineError


def baseline(ports=((443, 20),), *, large=0):
    size = sum(count for _, count in ports)
    return {'schema': 'offline-baseline-v1', 'adapter': 'tshark-fields-v1',
            'record_kind': 'packet', 'record_count': size, 'total_bytes': (size - large) * 64 + large * 4096,
            'protocols': [{'protocol': 'TCP', 'count': size}] if size else [],
            'destination_ports': [{'protocol': 'TCP', 'port': port, 'count': count}
                                  for port, count in ports],
            'byte_bands': {'small': size-large, 'medium': 0, 'large': large},
            'relative_minutes': [{'minute': 0, 'count': size}] if size else []}


def sample():
    def window(start, end):
        return {'source_id': 'source-0001', 'started_at': f'2026-09-15T{start}:00Z',
                'finished_at': f'2026-09-15T{end}:00Z', 'completeness': 'complete'}
    return {'schema': 'offline-anomaly-input-v1', 'as_of': '2026-09-15T02:01:00Z',
            'reference': {'window': window('00:00', '01:00'), 'baseline': baseline()},
            'current': {'window': window('01:00', '02:00'),
                        'baseline': baseline(((443, 15), (8443, 5)))}}


def test_deterministic_candidates_have_exact_support_and_no_authority():
    data = sample()
    saved = deepcopy(data)
    result = build_anomaly_dossier(data)
    assert result == build_anomaly_dossier(data)
    assert data == saved
    assert result['status'] == 'candidates'
    assert [(row['rule'], row['port'], row['reference_count'], row['current_count'])
            for row in result['candidates']] == [
                ('PORT_SHARE_SHIFT', 443, 20, 15), ('NEW_DESTINATION_PORT', 8443, 0, 5)]
    assert result['candidate_count'] == 2
    assert result['quality_label'] == 'uncalibrated'
    assert result['action_status'] == 'not_attempted'
    assert result['truncated'] is False
    assert len(result['dossier_id']) == 64
    data['current']['baseline']['record_count'] = 999
    assert result['current_records'] == 20


def test_no_change_is_not_a_safe_verdict_and_volume_is_not_a_share_shift():
    data = sample()
    data['current']['baseline'] = baseline(((443, 40),))
    result = build_anomaly_dossier(data)
    assert result['status'] == 'no_candidates' and result['candidates'] == []
    assert any('does not establish' in line for line in result['limitations'])


@pytest.mark.parametrize('count,expected', [(3, False), (4, True)])
def test_exact_twenty_percentage_point_boundary(count, expected):
    data = sample()
    data['current']['baseline'] = baseline(((443, 20-count), (8443, count)))
    result = build_anomaly_dossier(data)
    assert any(row['port'] == 443 for row in result['candidates']) is expected


def test_large_records_and_protocol_change_are_explicit():
    data = sample()
    current = baseline(((443, 20),), large=8)
    current['protocols'][0]['protocol'] = 'UDP'
    current['destination_ports'][0]['protocol'] = 'UDP'
    data['current']['baseline'] = current
    result = build_anomaly_dossier(data)
    assert {row['rule'] for row in result['candidates']} == {
        'PORT_SHARE_SHIFT', 'NEW_DESTINATION_PORT', 'PROTOCOL_SHARE_SHIFT',
        'LARGE_RECORD_SHARE_SHIFT'}


@pytest.mark.parametrize('path,value,code', [
    (('current', 'window', 'source_id'), 'source-0002', 'INCOMPARABLE_SOURCE'),
    (('reference', 'window', 'completeness'), 'unknown', 'INCOMPLETE_WINDOW'),
    (('current', 'window', 'completeness'), 'incomplete', 'INCOMPLETE_WINDOW'),
    (('as_of',), '2026-09-15T03:00:01Z', 'CURRENT_WINDOW_NOT_FRESH'),
    (('as_of',), '2026-09-15T01:59:59Z', 'CURRENT_WINDOW_NOT_FRESH'),
    (('current', 'window', 'started_at'), '2026-09-15T00:59:00Z', 'INCOMPARABLE_WINDOWS'),
    (('current', 'baseline'), baseline(((443, 19),)), 'INSUFFICIENT_RECORDS'),
])
def test_quality_gaps_abstain_without_partial_candidates(path, value, code):
    data = sample()
    target = data
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    result = build_anomaly_dossier(data)
    assert (result['status'], result['reason_code']) == ('abstained', code)
    assert result['candidates'] == [] and result['candidate_count'] == 0


def test_old_reference_and_inconsistent_relative_bins_abstain():
    data = sample()
    for key in ('started_at', 'finished_at'):
        data['reference']['window'][key] = data['reference']['window'][key].replace('09-15', '09-01')
    assert build_anomaly_dossier(data)['reason_code'] == 'REFERENCE_TOO_OLD'
    data = sample()
    data['current']['baseline']['relative_minutes'] = [
        {'minute': 0, 'count': 1}, {'minute': 60, 'count': 19}]
    assert build_anomaly_dossier(data)['reason_code'] == 'BASELINE_OUTSIDE_WINDOW'


def test_packet_and_flow_counts_never_mix():
    data = sample()
    data['current']['baseline'].update(adapter='zeek-conn-json-v1', record_kind='flow')
    assert build_anomaly_dossier(data)['reason_code'] == 'INCOMPARABLE_SOURCE'


def test_candidate_overflow_abstains_instead_of_silent_truncation():
    data = sample()
    data['current']['baseline'] = baseline(tuple((port, 5) for port in range(8000, 8009)))
    result = build_anomaly_dossier(data)
    assert result['reason_code'] == 'ANOMALY_CANDIDATE_LIMIT'
    assert result['candidates'] == [] and result['truncated'] is False


def test_low_support_port_changes_are_filtered_before_candidate_limit():
    data = sample()
    data['reference']['baseline'] = baseline(tuple((port, 1) for port in range(1000, 1300)))
    data['current']['baseline'] = baseline(tuple((port, 1) for port in range(2000, 2300)))
    result = build_anomaly_dossier(data)
    assert result['status'] == 'no_candidates'
    assert result['reason_code'] == 'NO_THRESHOLD_CROSSING'
    assert result['candidates'] == []


@pytest.mark.parametrize('value', [None, [], True, 1.5, 'SECRET', {'schema': 'bad'}])
def test_invalid_top_level_is_fixed_error(value):
    with pytest.raises(OfflineError, match='^ANOMALY_INPUT_INVALID$'):
        build_anomaly_dossier(value)


@pytest.mark.parametrize('field,value', [
    ('source_id', 123), ('source_id', 'http://SECRET'),
    ('finished_at', '2026-02-30T02:00:00Z'),
    ('started_at', '2026-09-15T02:00:00Z'),
    ('finished_at', '2026-09-15T02:00:00+00:00'),
])
def test_malformed_windows_raise_non_echoing_errors(field, value):
    data = sample()
    data['current']['window'][field] = value
    with pytest.raises(OfflineError, match='^ANOMALY_WINDOW_INVALID$'):
        build_anomaly_dossier(data)


def test_unknown_fields_and_count_contradictions_are_rejected():
    data = sample()
    data['current']['baseline']['payload'] = 'SECRET'
    with pytest.raises(OfflineError):
        build_anomaly_dossier(data)
    data = sample()
    data['current']['baseline']['protocols'][0]['count'] = 19
    with pytest.raises(OfflineError):
        build_anomaly_dossier(data)


def test_hostile_python_values_and_cycles_do_not_run_methods():
    class Hostile(dict):
        def __iter__(self):
            pytest.fail('caller method executed')
    with pytest.raises(OfflineError):
        build_anomaly_dossier(Hostile())
    cycle = {}
    cycle['cycle'] = cycle
    with pytest.raises(OfflineError):
        build_anomaly_dossier(cycle)


def test_pure_analysis_never_opens_io_or_invokes_model(monkeypatch):
    import megalodon.qwen_advisory as qwen
    import megalodon.firewall as firewall
    def forbidden(*args, **kwargs):
        pytest.fail('unexpected side effect')
    data = sample()
    for obj, name in [(builtins, 'open'), (Path, 'open'), (socket, 'socket'),
                      (socket, 'getaddrinfo'), (sqlite3, 'connect'),
                      (subprocess, 'Popen'), (qwen, 'invoke_qwen_advisory')]:
        monkeypatch.setattr(obj, name, forbidden)
    result = build_anomaly_dossier(data)
    assert result['candidate_count'] == 2
    encoded = json.dumps(result)
    assert 'SECRET' not in encoded and 'payload' not in encoded
