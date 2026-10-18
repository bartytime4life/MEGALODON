"""Passive gateway review over synthetic kernel routing tables and ARP caches."""
import json
import os
import socket
import subprocess

import pytest

from megalodon import gateway_review
from megalodon.gateway_review import (MAX_GROUPS, MAX_SESSION_GATEWAYS, SCHEMA, TRUST, GatewayReview, assess,
                                      default_gateways, neighbors, observe)

NOW = '2026-10-18T07:00:00Z'
ROUTE_HEAD = 'Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n'
ARP_HEAD = 'IP address       HW type     Flags       HW address            Mask     Device\n'


@pytest.fixture(autouse=True)
def passive(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError('the gateway review must never send traffic or run a program')
    for name in ('socket', 'create_connection', 'getaddrinfo'):
        monkeypatch.setattr(socket, name, refuse)
    for name in ('run', 'Popen', 'call', 'check_call', 'check_output'):
        monkeypatch.setattr(subprocess, name, refuse)
    monkeypatch.setattr(os, 'system', refuse)


def hexip(address):
    return bytes(int(part) for part in address.split('.'))[::-1].hex().upper()


def route(interface, gateway, metric=100, flags='0003', destination='00000000', mask='00000000'):
    return f'{interface}\t{destination}\t{hexip(gateway)}\t{flags}\t0\t0\t{metric}\t{mask}\t0\t0\t0\n'


def arp(ip, mac, device='eth0', flags='0x2'):
    return f'{ip:<16} 0x1         {flags:<11} {mac:<21} *        {device}\n'


def tree(tmp_path, routes, entries):
    (tmp_path/'proc/net').mkdir(parents=True, exist_ok=True)
    (tmp_path/'proc/net/route').write_text(ROUTE_HEAD + ''.join(routes))
    (tmp_path/'proc/net/arp').write_text(ARP_HEAD + ''.join(entries))
    return tmp_path


GW, GW_MAC, OTHER_MAC = '192.168.1.1', 'aa:bb:cc:00:00:01', 'aa:bb:cc:00:00:99'


def test_default_routes_need_up_and_gateway_flags_and_sort_by_metric(tmp_path):
    root = tree(tmp_path, [route('wlan0', '10.0.0.1', 600), route('eth0', GW, 100), route('tun0', '0.0.0.0', 50, flags='0001'),
                           route('eth0', '192.168.1.254', 10, destination='0001A8C0', mask='00FFFFFF'),
                           route('bad name', '10.9.9.9', 1), 'garbage line\n'], [])
    routes, complete = default_gateways(root)
    assert [(r['interface'], r['ip']) for r in routes] == [('eth0', GW), ('wlan0', '10.0.0.1')] and complete
    result = GatewayReview(tmp_path/'home', root=root, now=lambda: NOW).review()
    assert result['gateway']['interface'] == 'eth0' and result['other_default_routes'] == 1
    assert '1 other IPv4 default route(s) exist; only the lowest-metric gateway is reviewed.' in result['gaps']


def test_neighbor_states_and_malformed_rows(tmp_path):
    root = tree(tmp_path, [], [arp(GW, GW_MAC.upper()), arp('192.168.1.2', '00:00:00:00:00:00', flags='0x0'),
                               arp('192.168.1.3', OTHER_MAC, flags='0x6'), arp('999.1.1.1', OTHER_MAC),
                               arp('192.168.1.4', 'not-a-mac'), arp('192.168.1.5', OTHER_MAC, device='eth0$bad')])
    rows, complete = neighbors(root)
    assert [(r['ip'], r['mac'], r['state']) for r in rows] == [
        (GW, GW_MAC, 'complete'), ('192.168.1.2', '00:00:00:00:00:00', 'incomplete'), ('192.168.1.3', OTHER_MAC, 'permanent')]


def test_gateway_mac_shared_with_another_address_is_review(tmp_path):
    root = tree(tmp_path, [route('eth0', GW)], [arp(GW, GW_MAC), arp('192.168.1.66', GW_MAC),
                                                arp('192.168.1.7', OTHER_MAC), arp('192.168.1.8', OTHER_MAC),
                                                arp('192.168.1.9', OTHER_MAC, device='wlan0')])
    observation = observe(root)
    assert observation['gateway'] == dict(ip=GW, interface='eth0', mac=GW_MAC, entry='complete')
    findings = assess(observation)
    assert [(f['rule'], f['level']) for f in findings] == [('GATEWAY_MAC_SHARED', 'review'), ('SHARED_MAC', 'note')]
    assert all(f['attack'] == 'T1557.002' and f['action_status'] == 'not_attempted' for f in findings)
    # One MAC on two interfaces is not a shared group: each interface has its own neighbors.
    assert [g['interface'] for g in observation['shared']] == ['eth0', 'eth0']


def test_unresolved_and_missing_gateway_entries_have_no_mac(tmp_path):
    root = tree(tmp_path, [route('eth0', GW)], [arp(GW, '00:00:00:00:00:00', flags='0x0')])
    assert observe(root)['gateway'] == dict(ip=GW, interface='eth0', mac=None, entry='incomplete')
    root = tree(tmp_path, [route('eth0', GW)], [])
    assert observe(root)['gateway']['entry'] == 'absent'
    result = GatewayReview(tmp_path/'home', root=root, now=lambda: NOW).review({})
    assert any('no resolved ARP entry' in gap for gap in result['gaps']) and result['findings'] == []


def test_session_comparison_flags_a_changed_mac_but_not_a_new_network(tmp_path):
    home = tmp_path/'home'
    session = {}
    review = GatewayReview(home, root=tree(tmp_path, [route('eth0', GW)], [arp(GW, GW_MAC)]), now=lambda: NOW)
    first = review.review(session)
    assert first['compared_with'] is None and first['findings'] == [] and session == {f'eth0 {GW}': dict(mac=GW_MAC, seen_at=NOW)}
    tree(tmp_path, [route('eth0', GW)], [arp(GW, OTHER_MAC)])
    changed = review.review(session)
    assert changed['compared_with'] == dict(source='session', interface='eth0', ip=GW, mac=GW_MAC, at=NOW)
    assert [f['rule'] for f in changed['findings']] == ['GATEWAY_MAC_CHANGED'] and OTHER_MAC in changed['findings'][0]['detail']
    tree(tmp_path, [route('wlan0', '10.0.0.1')], [arp('10.0.0.1', OTHER_MAC, device='wlan0')])
    moved = review.review(session)
    assert moved['findings'] == [] and len(session) == 2  # another network starts its own comparison


def test_session_memory_is_bounded(tmp_path):
    session = {f'eth{i} 10.0.{i}.1': dict(mac=GW_MAC, seen_at=NOW) for i in range(MAX_SESSION_GATEWAYS)}
    review = GatewayReview(tmp_path/'home', root=tree(tmp_path, [route('eth0', GW)], [arp(GW, GW_MAC)]), now=lambda: NOW)
    review.review(session)
    assert len(session) == MAX_SESSION_GATEWAYS


def test_baseline_records_the_resolved_gateway_and_takes_precedence(tmp_path):
    home = tmp_path/'home'
    root = tree(tmp_path, [route('eth0', GW)], [arp(GW, GW_MAC)])
    review = GatewayReview(home, root=root, now=lambda: NOW)
    recorded = review.record_baseline()
    assert recorded['state'] == 'baseline_recorded' and recorded['trust'] == TRUST
    path = review.state/'baseline.json'
    assert path.stat().st_mode & 0o777 == 0o600
    session = {f'eth0 {GW}': dict(mac=OTHER_MAC, seen_at=NOW)}  # the baseline wins over a session entry
    tree(tmp_path, [route('eth0', GW)], [arp(GW, OTHER_MAC)])
    result = review.review(session)
    assert result['compared_with']['source'] == 'baseline' and [f['rule'] for f in result['findings']] == ['GATEWAY_MAC_CHANGED']
    tree(tmp_path, [route('wlan0', '10.0.0.1')], [arp('10.0.0.1', OTHER_MAC, device='wlan0')])
    assert [f['rule'] for f in review.review()['findings']] == ['GATEWAY_CHANGED']
    assert not any('No gateway baseline' in gap for gap in result['gaps'])


def test_baseline_needs_a_resolved_gateway_and_rejects_tampering(tmp_path):
    home = tmp_path/'home'
    review = GatewayReview(home, root=tree(tmp_path, [route('eth0', GW)], []), now=lambda: NOW)
    with pytest.raises(ValueError, match='nothing to record'):
        review.record_baseline()
    tree(tmp_path, [route('eth0', GW)], [arp(GW, GW_MAC)])
    review.record_baseline()
    path = review.state/'baseline.json'
    value = json.loads(path.read_text())
    for forged in (dict(value, mac='zz'), dict(value, trust='known_clean'), dict(value, extra=1), dict(value, ip='192.168.001.1'),
                   dict(value, created_at='yesterday')):
        path.write_text(json.dumps(forged))
        with pytest.raises(ValueError):
            review.review()
    path.write_text(json.dumps(value))
    path.chmod(0o644)
    with pytest.raises(ValueError):
        review.review()


def test_cut_off_tables_are_reported_and_groups_are_bounded(tmp_path, monkeypatch):
    entries = [arp(f'192.168.{g}.{i}', f'aa:bb:cc:00:{g:02x}:00') for g in range(MAX_GROUPS + 3) for i in (1, 2)]
    root = tree(tmp_path, [route('eth0', GW)], [arp(GW, GW_MAC)] + entries)
    result = GatewayReview(tmp_path/'home', root=root, now=lambda: NOW).review()
    assert len(result['shared']) == MAX_GROUPS and result['shared_total'] == MAX_GROUPS + 3
    assert any(gap.startswith(f'{MAX_GROUPS + 3} shared-MAC groups') for gap in result['gaps'])
    monkeypatch.setattr(gateway_review, 'MAX_TABLE_READ', 200)
    result = GatewayReview(tmp_path/'home', root=root, now=lambda: NOW).review()
    assert result['tables_complete'] is False and any('not fully read' in gap for gap in result['gaps'])


def test_review_shape_is_closed(tmp_path):
    root = tree(tmp_path, [route('eth0', GW)], [arp(GW, GW_MAC)])
    result = GatewayReview(tmp_path/'home', root=root, now=lambda: NOW).review({})
    assert set(result) == {'schema', 'reviewed_at', 'gateway', 'other_default_routes', 'neighbors', 'shared', 'shared_total',
                           'tables_complete', 'compared_with', 'findings', 'gaps', 'trust', 'action_authority'}
    assert result['schema'] == SCHEMA and result['action_authority'] == 'none'
    json.dumps(result)


def test_the_gateway_group_survives_the_group_bound(tmp_path):
    entries = [arp(f'192.168.{g}.{i}', f'aa:bb:cc:00:{g:02x}:00') for g in range(10, 10 + MAX_GROUPS) for i in (1, 2, 3)]
    root = tree(tmp_path, [route('eth0', GW)], entries + [arp(GW, GW_MAC), arp('192.168.1.66', GW_MAC)])
    observation = observe(root)
    assert observation['shared_total'] == MAX_GROUPS + 1 and len(observation['shared']) == MAX_GROUPS
    assert observation['shared'][0]['mac'] == GW_MAC
    assert [f['rule'] for f in assess(observation)][0] == 'GATEWAY_MAC_SHARED'
