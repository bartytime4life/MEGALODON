"""Exact share boundaries and source-qualified history selection."""
from copy import deepcopy
from fractions import Fraction
from random import Random

import pytest

from megalodon.evidence_storage import utc
from megalodon.security_patterns import analyze_hour, inventory_hour

START = 1_792_080_000
SEGMENT = 'a' * 32


def compact_rows(tcp=50, total=100, *, device='192.0.2.1', service=False):
    rows = []
    for index, (protocol, count) in enumerate((('TCP', tcp), ('UDP', total - tcp))):
        if not count:
            continue
        rows.append(dict(id=f'{SEGMENT}:{index+1}', observed_at=utc(START),
            category='packet_rollups', source='packet-conversation-summary',
            data=dict(kind='conversation_v1', src_ip=device, dst_ip='198.51.100.1',
                src_port=40000, dst_port=443, protocol='TCP' if service else protocol,
                app_proto=protocol.lower() if service else 'transport', interface='fixture0', packet_count=count,
                first_at=utc(START), last_at=utc(START+3500))))
    return rows


def history(tcp=50, total=100, *, device='192.0.2.1', service=False):
    base, _, gaps = analyze_hour(compact_rows(tcp, total, device=device, service=service), START, START+3600, [])
    assert not gaps and len(base) == 1 and base[0]['eligible']
    return [dict(deepcopy(base[0]), start=START-hour*3600, end=START-(hour-1)*3600)
            for hour in range(1, 25)]


def shifts(current, previous):
    _, checks, gaps = analyze_hour(current, START, START+3600, previous)
    assert not gaps
    return [check for check in checks if check['rule'] in {'PROTOCOL_SHIFT', 'SERVICE_SHIFT'}]


@pytest.mark.parametrize('service', [False, True])
@pytest.mark.parametrize('tcp,total,prior_tcp,prior_total,expected', [
    (4996, 10000, 30, 100, False),  # +19.96 points must not round into admission.
    (5004, 10000, 70, 100, False),  # -19.96 points has the same exact boundary.
    (50, 100, 30, 100, True),
    (50, 100, 70, 100, True),
    (5001, 10000, 30, 100, True),
    (6005, 10000, 40, 100, True),  # Exact display ties round half to even.
    (6015, 10000, 40, 100, True),
    (3995, 10000, 60, 100, True),
    (3*2**50-1, 5*2**50, 40, 100, False),
    (3*2**50, 5*2**50, 40, 100, True),
])
def test_shift_admission_uses_the_unrounded_fraction(service, tcp, total, prior_tcp, prior_total, expected):
    exact = 100 * (Fraction(tcp, total) - Fraction(prior_tcp, prior_total))
    assert (abs(exact) >= 20) is expected
    result = shifts(compact_rows(tcp, total, service=service), history(prior_tcp, prior_total, service=service))
    assert bool(result) is expected
    for finding in result:
        assert finding['facts']['share_change_points'] in (float(round(exact, 1)), float(round(-exact, 1)))
        assert finding['facts']['eligible_hours'] == 24
        assert finding['action_status'] == 'not_attempted'


def test_fraction_oracle_for_seeded_large_count_comparisons():
    random = Random(20261111)
    for _ in range(60):
        total = random.randrange(100, 2**53)
        tcp = random.randrange(5, total-5)
        prior_total = random.randrange(100, 2**53)
        prior_tcp = random.randrange(5, prior_total-5)
        exact = 100 * (Fraction(tcp, total) - Fraction(prior_tcp, prior_total))
        result = shifts(compact_rows(tcp, total), history(prior_tcp, prior_total))
        assert bool(result) == (abs(exact) >= 20)
        assert {check['facts']['share_change_points'] for check in result} == (
            {float(round(exact, 1)), float(round(-exact, 1))} if abs(exact) >= 20 else set())


def test_comparison_history_is_partitioned_once_per_hour():
    class Counted(dict):
        key_reads = 0

        def get(self, key, default=None):
            if key == 'key':
                type(self).key_reads += 1
            return super().get(key, default)

    current, previous = [], []
    for index in range(8):
        device = f'192.0.2.{index+1}'
        current.extend(compact_rows(device=device))
        previous.extend(Counted(row) for row in history(device=device))
    base, checks, gaps = analyze_hour(current, START, START+3600, previous)
    assert len(base) == 8 and not checks and not gaps
    assert Counted.key_reads <= len(previous), 'history selection must not rescan every baseline for every group'


def test_history_keeps_eligibility_window_last_duplicate_and_source_dependencies():
    previous = history()
    # Duplicates replace the value for that same start; they add no sample.
    replacement = deepcopy(previous[0])
    replacement['protocols'] = {'TCP': 50, 'UDP': 50}
    previous[0]['protocols'] = {'TCP': 90, 'UDP': 10}
    previous.extend([replacement, dict(deepcopy(previous[1]), eligible=False),
        dict(deepcopy(previous[0]), start=START),
        dict(deepcopy(previous[0]), start=START-7*86400-1)])
    result = shifts(compact_rows(75), previous)
    assert len(result) == 2
    assert {finding['facts']['eligible_hours'] for finding in result} == {24}
    assert {finding['source_start'] for finding in result} == {utc(START-24*3600)}
    assert all(finding['source_segments'] == [SEGMENT] for finding in result)
    # Another sensor, interface, address or measurement cannot train this group.
    for position, value in enumerate(('192.0.2.2', 'other0', 'other sensor', 'flow')):
        incompatible = deepcopy(previous)
        for baseline in incompatible:
            baseline['key'][position] = value
        assert not shifts(compact_rows(75), incompatible)


def test_inventory_uses_the_latest_prior_within_its_own_two_hour_window():
    row = dict(id=f'{SEGMENT}:1', observed_at=utc(START), category='network', source='fixture-inventory',
        data=dict(node=dict(ip='192.0.2.1', interface='fixture0', services=[dict(name='tls')])))
    base, _ = inventory_hour([row], START, START+3600, [])
    older = dict(deepcopy(base[0]), start=START-7200)
    older['devices']['192.0.2.1']['services'] = []
    latest = dict(deepcopy(base[0]), start=START-3600)
    _, changes = inventory_hour([row], START, START+3600, [older, latest])
    assert not changes
    _, changes = inventory_hour([row], START, START+3600, [older])
    assert changes[0]['facts']['previous_services'] == []
    _, changes = inventory_hour([row], START, START+3600, [dict(older, start=START-7201)])
    assert not changes


def test_traffic_window_includes_seven_days_but_excludes_the_current_hour():
    previous = history()
    previous[0]['start'] = START-7*86400
    result = shifts(compact_rows(75), previous)
    assert len(result) == 2 and all(check['source_start'] == utc(START-7*86400) for check in result)
    previous[0]['start'] = START
    assert not shifts(compact_rows(75), previous), '23 completed hours cannot train a comparison'


def test_tuple_and_malformed_keys_do_not_become_compatible_by_indexing():
    for key in [tuple(history()[0]['key']), ['192.0.2.1'], [{'address': '192.0.2.1'}]*4]:
        previous = history()
        for baseline in previous:
            baseline['key'] = key
        assert not shifts(compact_rows(75), previous)


def test_inventory_preserves_an_explicit_null_interface_key():
    row = dict(id=f'{SEGMENT}:1', observed_at=utc(START), category='network', source='fixture-inventory',
        data=dict(node=dict(ip='192.0.2.1', interface=None, services=[])))
    base, _ = inventory_hour([row], START, START+3600, [])
    previous = dict(deepcopy(base[0]), start=START-3600)
    row['data']['node']['services'] = [dict(name='tls')]
    _, changes = inventory_hour([row], START, START+3600, [previous])
    assert len(changes) == 1
    assert changes[0]['facts']['change'] == 'Observed service labels changed'
