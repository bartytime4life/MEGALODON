"""Exact retained-window witnesses; legacy offline exports keep their v1 shape."""
from datetime import datetime, timedelta, timezone
import builtins
import os
import random
import socket
import subprocess

import pytest

from megalodon.models import PacketEvent
from megalodon.offline.analysis import candidates
from megalodon.offline.common import Batch, FlowRecord, OfflineError


BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def record(offset_us, *, source='192.0.2.1', port=53, protocol='UDP', serial=0):
    return PacketEvent(BASE + timedelta(microseconds=offset_us), source, '198.51.100.1',
                       protocol, src_port=30000 + serial % 30000, dst_port=port)


def batch(records, kind='packet'):
    if kind == 'flow':
        records = [FlowRecord(r.observed_at, r.src_ip, r.dst_ip, r.protocol,
                              r.src_port, r.dst_port, None, 1, 0, 64, 'S0') for r in records]
    return Batch('synthetic', kind, tuple(records), len(records), 0, 0, 'test', 'synthetic')


@pytest.fixture
def run(monkeypatch):
    def analyze(value, **kwargs):
        def forbidden(*args, **kwargs):
            raise AssertionError('Pure burst analysis performed an external effect')
        with monkeypatch.context() as guard:
            for owner, name in [(builtins, 'open'), (os, 'open'), (os, 'system'),
                                (socket, 'socket'), (socket, 'create_connection'),
                                (subprocess, 'run'), (subprocess, 'Popen')]:
                guard.setattr(owner, name, forbidden)
            return candidates(value, **kwargs)
    return analyze


def bursts(run, value, **kwargs):
    return [item['evidence'] for item in run(value, rolling_bursts=True, **kwargs)
            if item['rule'] == 'PORT_53_BURST']


def signature(record):
    return (record.observed_at, record.src_ip, record.dst_ip, record.protocol,
            record.src_port, record.dst_port)


def witnesses(value, results):
    origin = min((r.observed_at for r in value.records), default=BASE)
    output = []
    for result in results:
        support = [value.records[number - 1] for number in result['record_numbers']]
        assert result['records'] == len(support)
        assert len(set(result['record_numbers'])) == len(support)
        start = origin + timedelta(microseconds=result['start_offset_us'])
        end = origin + timedelta(microseconds=result['end_offset_us'])
        assert end - start == timedelta(seconds=60)
        assert all(start <= r.observed_at < end for r in support)
        assert all(r.dst_port == 53 and r.protocol in {'TCP', 'UDP'} for r in support)
        assert len({r.src_ip for r in support}) == 1
        output.append((support[0].src_ip, start, end, tuple(sorted(map(signature, support)))))
    return output


def quadratic_oracle(value):
    """Exhaustive datetime windows, independent of offsets and two-pointer state."""
    eligible = [r for r in value.records if r.protocol in {'TCP', 'UDP'} and r.dst_port == 53]
    output = []
    for source in sorted({r.src_ip for r in eligible}):
        remaining = sorted((r for r in eligible if r.src_ip == source), key=signature)
        while remaining:
            for first in remaining:
                end = first.observed_at + timedelta(seconds=60)
                support = [r for r in remaining if first.observed_at <= r.observed_at < end]
                if len(support) >= 20:
                    output.append((source, first.observed_at, end, tuple(sorted(map(signature, support)))))
                    remaining = [r for r in remaining if r.observed_at >= end]
                    break
            else:
                break
    return output


@pytest.mark.parametrize('kind', ['packet', 'flow'])
def test_unrelated_anchor_and_input_order_do_not_change_witness(run, kind):
    records = [record(59_500_000 + i * 50_000, serial=i) for i in range(20)]
    original = batch(records, kind)
    expected = witnesses(original, bursts(run, original, timing_provenance=True))
    assert len(expected) == 1
    anchored = [record(0, port=443, source='192.0.2.2'), *records]
    random.Random(117).shuffle(anchored)
    changed = batch(anchored, kind)
    assert witnesses(changed, bursts(run, changed, timing_provenance=True)) == expected


@pytest.mark.parametrize('last_us, expected', [(0, 1), (59_999_999, 1), (60_000_000, 0), (60_000_001, 0)])
def test_half_open_sixty_second_boundary(run, last_us, expected):
    value = batch([record(0, serial=i) for i in range(19)] + [record(last_us, serial=19)])
    result = bursts(run, value, timing_provenance=True)
    assert len(result) == expected
    assert witnesses(value, result) == quadratic_oracle(value)


def test_full_support_nonoverlap_and_earliest_qualifying_start(run):
    records = [record(0)] + [record(100_000_000 + i * 1_000_000, serial=i) for i in range(27)]
    records += [record(240_000_000 + i * 1_000_000, serial=i + 100) for i in range(20)]
    value = batch(records)
    result = bursts(run, value, timing_provenance=True)
    assert [row['records'] for row in result] == [27, 20]
    assert result[0]['record_numbers'] == list(range(2, 29))
    assert not set(result[0]['record_numbers']) & set(result[1]['record_numbers'])
    assert witnesses(value, result) == quadratic_oracle(value)


def test_protocols_share_the_source_window_but_sources_do_not(run):
    records = [record(i, serial=i, protocol='TCP' if i % 2 else 'UDP') for i in range(20)]
    records += [record(i, source='192.0.2.2', serial=i) for i in range(19)]
    records += [record(i, source='192.0.2.3', port=443) for i in range(30)]
    value = batch(records)
    result = bursts(run, value, timing_provenance=True)
    assert len(result) == 1
    assert witnesses(value, result) == quadratic_oracle(value)


def test_translation_preserves_exact_microsecond_evidence(run):
    records = [record(59_000_000 + i, serial=i) for i in range(23)]
    value = batch(records)
    before = bursts(run, value, timing_provenance=True)
    translated = batch([record(3_600_123_456 + 59_000_000 + i, serial=i) for i in range(23)])
    after = bursts(run, translated, timing_provenance=True)
    assert before == after
    assert witnesses(translated, after) == quadratic_oracle(translated)


def test_seeded_cases_match_exhaustive_datetime_oracle(run):
    rng = random.Random(94217)
    positive = 0
    for case in range(80):
        records = [record(rng.randrange(360_000_001), source=f'192.0.2.{rng.randrange(1, 4)}',
                          port=53 if rng.randrange(5) else 443, serial=i,
                          protocol='TCP' if rng.randrange(2) else 'UDP') for i in range(140)]
        if case % 2 == 0:
            start = rng.randrange(300_000_001)
            records += [record(start + rng.randrange(60_000_000), serial=500 + i)
                        for i in range(rng.randrange(20, 41))]
        rng.shuffle(records)
        value = batch(records)
        expected = quadratic_oracle(value)
        positive += bool(expected)
        assert witnesses(value, bursts(run, value, timing_provenance=True)) == expected
    assert positive >= 40


@pytest.mark.parametrize('provenance', [False, True])
def test_rolling_mode_has_a_twenty_thousand_record_bound(run, provenance):
    item = PacketEvent(BASE, '192.0.2.1', '198.51.100.1', 'ICMP')
    assert bursts(run, batch([item] * 20_000), timing_provenance=provenance) == []
    with pytest.raises(OfflineError, match='^ROLLING_BURST_RECORD_LIMIT$'):
        bursts(run, batch([item] * 20_001), timing_provenance=provenance)
    if not provenance:
        assert run(batch([item] * 20_001), rolling_bursts=False) == []


@pytest.mark.parametrize('invalid', [0, 1, None, 'true', [], {}])
def test_rolling_mode_is_an_explicit_boolean(run, invalid):
    with pytest.raises(OfflineError, match='^INVALID_ROLLING_BURST_MODE$'):
        run(batch([]), rolling_bursts=invalid)


def test_legacy_shape_and_explicit_provenance_stay_separate(run):
    value = batch([record(i * 1_000_000, serial=i) for i in range(20)])
    legacy = run(value)
    assert run(value, rolling_bursts=False) == legacy
    fixed = next(item['evidence'] for item in legacy if item['rule'] == 'PORT_53_BURST')
    assert set(fixed) == {'src', 'relative_minute', 'records'}
    assert fixed['relative_minute'] == 0 and fixed['records'] == 20
    rolling = bursts(run, value)
    assert set(rolling[0]) == {'src', 'start_offset_us', 'end_offset_us', 'records'}
    assert bursts(run, value, timing_provenance=True)[0]['record_numbers'] == list(range(1, 21))


def test_analysis_does_not_mutate_inputs_or_perform_effects(run):
    value = batch([record(i, serial=i) for i in range(30)])
    before = tuple(r.to_dict() for r in value.records)
    result = bursts(run, value, timing_provenance=True)
    assert result[0]['records'] == 30
    assert tuple(r.to_dict() for r in value.records) == before
    assert bursts(run, batch([]), timing_provenance=True) == []
