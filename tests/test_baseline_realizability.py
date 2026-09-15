"""Aggregate evidence must be arithmetically possible for its source adapter."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from itertools import product

import pytest

from megalodon.models import PacketEvent
from megalodon.offline.analysis import baseline, validate_reference
from megalodon.offline.anomaly import build_anomaly_dossier
from megalodon.offline.baseline import validate_baseline
from megalodon.offline.common import Batch, OfflineError
from megalodon.offline.compare import compare_baselines
from megalodon.offline_projection import _baseline
from megalodon.offline.tshark import parse_fields
from megalodon.offline.zeek import parse_flow


def value(bands=(1, 1, 3), total=13000, adapter='tshark-fields-v1'):
    count = sum(bands)
    return {'schema': 'offline-baseline-v1', 'adapter': adapter,
            'record_kind': 'packet' if adapter == 'tshark-fields-v1' else 'flow',
            'record_count': count, 'total_bytes': total,
            'protocols': [{'protocol': 'TCP', 'count': count}] if count else [],
            'destination_ports': [{'protocol': 'TCP', 'port': 443, 'count': count}] if count else [],
            'byte_bands': dict(zip(('small', 'medium', 'large'), bands)),
            'relative_minutes': [{'minute': 0, 'count': count}] if count else []}


def dossier(current):
    def side(start, end, data):
        return {'window': {'source_id': 'source-0001', 'started_at': start,
                           'finished_at': end, 'completeness': 'complete'}, 'baseline': data}
    return {'schema': 'offline-anomaly-input-v1', 'as_of': '2026-09-15T02:01:00Z',
            'reference': side('2026-09-15T00:00:00Z', '2026-09-15T01:00:00Z', value((20, 0, 0), 1280)),
            'current': side('2026-09-15T01:00:00Z', '2026-09-15T02:00:00Z', current)}


@pytest.mark.parametrize('adapter,ceiling', [('tshark-fields-v1', 262144),
    ('zeek-conn-json-v1', 2**41 - 2), ('zeek-conn-tsv-v1', 2**41 - 2)])
def test_all_band_combinations_have_exact_inclusive_total_bounds(adapter, ceiling):
    # Exercise both endpoints and immediate outside values for all small band
    # combinations, including empty evidence, using exact integer arithmetic.
    for small, medium, large in product(range(3), repeat=3):
        low = medium * 512 + large * 4096
        high = small * 511 + medium * 4095 + large * ceiling
        for total in {low, high, (low + high) // 2}:
            assert validate_baseline(value((small, medium, large), total, adapter)).total_bytes == total
        for total in (low - 1, high + 1):
            with pytest.raises(OfflineError, match='^INVALID_BASELINE$'):
                validate_baseline(value((small, medium, large), total, adapter))


@pytest.mark.parametrize('bad', [value((20, 0, 0), 20 * 512),
    value((0, 20, 0), 20 * 512 - 1), value((0, 20, 0), 20 * 4096),
    value((0, 0, 20), 20 * 4096 - 1), value((0, 0, 20), 20 * 262144 + 1)])
def test_every_consumer_rejects_impossible_totals_without_mutating_input(bad):
    saved = deepcopy(bad)
    batch = Batch('tshark-fields-v1', 'packet', (), 0, 0, 1, '4.6.0', 'subprocess_version')
    good = value((20, 0, 0), 1280)
    for consume in (validate_baseline, lambda x: validate_reference(x, batch),
                    lambda x: compare_baselines(x, good),
                    lambda x: build_anomaly_dossier(dossier(x))):
        with pytest.raises(OfflineError, match='^INVALID_BASELINE$'):
            consume(bad)
    with pytest.raises(OfflineError, match='^INVALID_OFFLINE_BASELINE$'):
        _baseline(bad, {'adapter': bad['adapter'], 'record_kind': 'packet', 'accepted_records': 20})
    assert bad == saved


def test_nonempty_relative_time_requires_zero_but_allows_gaps_and_unsorted_bins():
    data = value()
    data['relative_minutes'] = [{'minute': 1, 'count': 5}]
    with pytest.raises(OfflineError, match='^INVALID_BASELINE$'):
        validate_baseline(data)
    data['relative_minutes'] = [{'minute': 100, 'count': 4}, {'minute': 0, 'count': 1}]
    assert validate_baseline(data).relative_minutes == ((0, 1), (100, 4))


def test_generated_packet_boundaries_and_out_of_order_records_remain_valid():
    stamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    records = tuple(PacketEvent(stamp + timedelta(seconds=100-index),
        '192.0.2.1', '198.51.100.2', 'TCP', dst_port=443, byte_count=size)
        for index, size in enumerate((0, 511, 512, 4095, 4096, 262144)))
    result = baseline(Batch('tshark-fields-v1', 'packet', records, 6, 0, 1, '4.6.0', 'subprocess_version'))
    parsed = validate_baseline(result)
    assert parsed.byte_bands == (2, 2, 2)
    assert parsed.total_bytes == sum(record.byte_count for record in records)


def test_packet_ceiling_matches_real_tshark_admission():
    fields = ['1700000000', '192.0.2.1', '198.51.100.2', '', '', '6', '', '40000', '443', '', '', '0x0010']
    assert parse_fields('\t'.join(fields + ['262144'])).byte_count == 262144
    with pytest.raises(OfflineError):
        parse_fields('\t'.join(fields + ['262145']))


def test_flow_ceiling_matches_real_zeek_admission():
    data = {'ts': '1700000000', 'id.orig_h': '192.0.2.1', 'id.orig_p': 40000,
            'id.resp_h': '198.51.100.2', 'id.resp_p': 443, 'proto': 'tcp',
            'conn_state': 'SF', 'orig_pkts': 1, 'resp_pkts': 1,
            'orig_ip_bytes': 2**40 - 1, 'resp_ip_bytes': 2**40 - 1}
    assert parse_flow(data).byte_count == 2**41 - 2
    data['resp_ip_bytes'] += 1
    with pytest.raises(OfflineError):
        parse_flow(data)
