"""Policy authority, receipts and exact helper readback; no host mutation."""
from copy import deepcopy
import json
import stat
from types import SimpleNamespace

import pytest

from megalodon import host_guard
from megalodon.defense import Defense, validate_request
from megalodon.host_protection import validate_policy
from test_defense import manager, perform  # shared inert local-defense fixture
from test_defense_http import endpoint, request

POLICY = {'services': [], 'duration_seconds': 900}
SERVICE = {'protocol': 'tcp', 'port': 22, 'source': '192.168.1.0/24'}


def document(policy=POLICY):
    rows = deepcopy(host_guard.objects(policy))
    for row in rows:
        if 'set' in row:
            for entry in row['set']['elem']:
                entry['elem']['expires'] = policy['duration_seconds'] - 1
    return {'nftables': rows}


def result(policy=POLICY, active=True):
    return dict(present=active, active=active, remaining_seconds=899 if active else 0,
                policy=deepcopy(policy) if active else None, verified=True,
                counters={'invalid': 2, 'unsolicited': 10, 'allowed_service': 4})


def fake_host(manager, response=None):
    defense, calls, _ = manager
    def run(argv, *args):
        calls.append(argv)
        assert argv[:4] == ['/usr/bin/pkexec', '/usr/bin/python3', '-I', '-c']
        assert 'megalodon_host_guard' in argv[4]
        action, policy = argv[-2], json.loads(argv[-1])
        value = response if response is not None else result(policy, active=action == 'apply')
        return json.dumps(value).encode(), 0
    defense.run = run
    return defense, calls


def test_policy_validation_matches_privileged_boundary():
    for services in ([], [SERVICE], [{'protocol': 'udp', 'port': 443, 'source': '::/0'}],
                     [{'protocol': 'tcp', 'port': 443, 'source': '2001:db8::1/128'}]):
        policy = dict(POLICY, services=services)
        assert validate_policy(policy) == host_guard.policy_check(deepcopy(policy))
        assert host_guard.validate(document(policy))['policy'] == policy
    original = deepcopy(POLICY)
    validated = validate_request({'action': 'plan_host_protection', 'policy': original})
    original['services'].append(SERVICE)
    assert validated['policy']['services'] == []


@pytest.mark.parametrize('change', [
    {'duration_seconds': True}, {'duration_seconds': 0}, {'duration_seconds': 86400},
    {'services': [SERVICE] * 9}, {'services': [SERVICE, SERVICE]},
    {'services': [dict(SERVICE, port=True)]}, {'services': [dict(SERVICE, port=0)]},
    {'services': [dict(SERVICE, port=65536)]}, {'services': [dict(SERVICE, protocol='tcp; flush ruleset')]},
    {'services': [dict(SERVICE, source='192.168.1.1/24')]},
    {'services': [dict(SERVICE, source='192.168.1.1')]},
    {'services': [dict(SERVICE, source='::ffff:c000:201/128')]},
    {'services': [dict(SERVICE, source='64:ff9b::/96')]},
    {'services': [dict(SERVICE, source='127.0.0.0/8')]},
    {'services': [dict(SERVICE, command='id')]}, {'command': 'id'},
])
def test_invalid_policy_never_crosses_either_boundary(change):
    policy = dict(POLICY, **change)
    for validator in (validate_policy, host_guard.policy_check):
        with pytest.raises((ValueError, TypeError)):
            validator(policy)


def test_preview_apply_check_remove_and_restart(manager):
    defense, calls = fake_host(manager)
    plan = perform(defense, {'action': 'plan_host_protection', 'policy': POLICY})['result']
    assert calls == [] and defense.snapshot()['host_protection']['state'] == 'unknown'
    applied = perform(defense, {'action': 'apply_host_protection', 'plan_id': plan['id']})
    assert applied['state'] == 'finished' and len(calls) == 1
    assert json.loads(calls[0][-1]) == POLICY
    host = defense.snapshot()['host_protection']
    assert host['state'] == 'last_verified_active' and host['counters']['unsolicited'] == 10
    restored = Defense(defense.operations, defense.configuration, run=defense.run)
    assert restored.snapshot()['host_protection'] == host and len(calls) == 1
    # GET/snapshot never asks for OS authorization or refreshes kernel evidence.
    for _ in range(10):
        restored.snapshot()
    assert len(calls) == 1
    assert perform(restored, {'action': 'remove_host_protection'})['state'] == 'finished'
    assert restored.snapshot()['host_protection']['state'] == 'last_verified_inactive'
    assert calls[-1][-2:] == ['remove', '{}']
    assert perform(restored, {'action': 'check_host_protection'})['state'] == 'finished'
    assert calls[-1][-2:] == ['status', '{}']


def test_preview_is_single_use_expiring_and_bound_to_action(manager):
    defense, calls = fake_host(manager)
    plan = perform(defense, {'action': 'plan_host_protection', 'policy': POLICY})['result']
    assert perform(defense, {'action': 'apply_containment', 'plan_id': plan['id']})['state'] == 'failed'
    assert calls == []
    plan = perform(defense, {'action': 'plan_host_protection', 'policy': POLICY})['result']
    defense._plans[plan['id']]['expires_at'] = '2000-01-01T00:00:00Z'
    assert perform(defense, {'action': 'apply_host_protection', 'plan_id': plan['id']})['state'] == 'failed'
    assert calls == []
    plan = perform(defense, {'action': 'plan_host_protection', 'policy': POLICY})['result']
    assert perform(defense, {'action': 'apply_host_protection', 'plan_id': plan['id']})['state'] == 'finished'
    assert perform(defense, {'action': 'apply_host_protection', 'plan_id': plan['id']})['state'] == 'failed'
    assert len(calls) == 1


def test_intent_is_durable_before_helper_and_ambiguity_survives_restart(manager):
    defense, calls, _ = manager
    def interrupted(*args):
        from megalodon.ai_broker import ReceiptStore
        with ReceiptStore(defense.path) as store:
            opened = store.latest(defense.snapshot()['recent'][-1]['receipt_id'])
        assert opened['state'] == 'not_attempted'
        assert opened['approved_preview']['policy'] == POLICY
        calls.append('attempt')
        raise OSError('connection lost')
    defense.run = interrupted
    plan = perform(defense, {'action': 'plan_host_protection', 'policy': POLICY})['result']
    assert perform(defense, {'action': 'apply_host_protection', 'plan_id': plan['id']})['state'] == 'failed'
    assert calls == ['attempt']
    assert defense.snapshot()['host_protection']['state'] == 'needs_review'
    restored = Defense(defense.operations, defense.configuration)
    assert restored.snapshot()['host_protection']['state'] == 'needs_review'


def test_no_execution_when_opening_receipt_fails(manager, monkeypatch):
    defense, calls = fake_host(manager)
    monkeypatch.setattr(defense, '_append', lambda *a, **k: (_ for _ in ()).throw(OSError('disk full')))
    assert perform(defense, {'action': 'remove_host_protection'})['state'] == 'failed'
    assert calls == []


@pytest.mark.parametrize('change', [
    {'verified': False}, {'active': False}, {'present': False}, {'remaining_seconds': float('nan')},
    {'remaining_seconds': True}, {'remaining_seconds': 901}, {'policy': dict(POLICY, duration_seconds=3600)},
    {'counters': {'unsolicited': -1, 'invalid': 0, 'allowed_service': 0}}, {'extra': 'field'},
])
def test_bad_helper_readback_cannot_claim_protection(manager, change):
    defense, calls = fake_host(manager, dict(result(), **change))
    plan = perform(defense, {'action': 'plan_host_protection', 'policy': POLICY})['result']
    assert perform(defense, {'action': 'apply_host_protection', 'plan_id': plan['id']})['state'] == 'failed'
    assert defense.snapshot()['host_protection']['state'] == 'needs_review'


def test_elapsed_lease_is_not_presented_as_active(manager):
    defense, _ = fake_host(manager)
    defense._host = dict(result(), state='last_verified_active', verified_at='2000-01-01T00:00:00Z', expires_at='2000-01-01T01:00:00Z')
    assert defense.snapshot()['host_protection']['state'] == 'lease_elapsed'


def test_changed_or_extra_firewall_structure_is_refused():
    for index, row in enumerate(document()['nftables']):
        altered = document()
        item = next(iter(altered['nftables'][index].values()))
        item['foreign'] = True
        with pytest.raises(ValueError):
            host_guard.validate(altered)
    altered = document()
    altered['nftables'][-1]['rule']['expr'] = [{'accept': None}]
    with pytest.raises(ValueError):
        host_guard.validate(altered)
    altered = document()
    altered['nftables'].append(deepcopy(altered['nftables'][-1]))
    with pytest.raises(ValueError):
        host_guard.validate(altered)


def test_partial_family_lease_needs_review_and_empty_lease_is_inactive():
    value = document()
    value['nftables'][3]['set']['elem'].pop()
    with pytest.raises(ValueError, match='Partial family'):
        host_guard.validate(value)
    value['nftables'][3]['set']['elem'] = []
    assert host_guard.validate(value)['remaining_seconds'] == 0


@pytest.mark.parametrize('mode,uid', [(stat.S_IFLNK | 0o777, 0), (stat.S_IFREG | 0o775, 0), (stat.S_IFREG | 0o755, 1000)])
def test_helper_refuses_substituted_executable(monkeypatch, mode, uid):
    monkeypatch.setattr(host_guard.os, 'lstat', lambda p: SimpleNamespace(st_mode=mode, st_uid=uid))
    with pytest.raises(ValueError):
        host_guard.check_binary()


def test_foreign_table_prevents_apply_and_remove(monkeypatch):
    calls = []
    def nft(args, body=None):
        calls.append((args, body))
        return (0, {'nftables': [{'table': {'family': 'inet', 'name': host_guard.TABLE}}]}) if args == ['list', 'tables'] else (0, {'nftables': []})
    monkeypatch.setattr(host_guard, 'nft', nft)
    for action, policy in [('apply', POLICY), ('remove', {})]:
        with pytest.raises(ValueError):
            host_guard.act(action, policy)
    assert all(body is None for _, body in calls)


def test_host_policy_http_boundary_and_no_activation_on_get(endpoint):
    assert request(endpoint, method='GET', body=b'')[0] == 200
    assert endpoint[1] == []
    policy = dict(POLICY, services=[dict(SERVICE, port=p) for p in range(10000, 10008)])
    body = json.dumps({'action': 'plan_host_protection', 'policy': policy}).encode()
    assert len(body) > 512
    assert request(endpoint, body=body)[0] == 202
    assert endpoint[1] == [{'action': 'plan_host_protection', 'policy': policy}]
    for body in [b'{"action":"apply_host_protection","policy":{}}',
                 b'{"action":"remove_host_protection","command":"id"}',
                 b'{"action":"plan_host_protection","policy":{"services":[],"services":[],"duration_seconds":900}}']:
        assert request(endpoint, body=body)[0] == 400
    assert len(endpoint[1]) == 1
