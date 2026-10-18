"""Review-only TLS handshake signals over synthetic Suricata EVE metadata."""
from datetime import datetime, timedelta, timezone
import json
import socket
from types import SimpleNamespace

import pytest

from megalodon import tls_signals
from megalodon.config import Settings
from megalodon.live_connections import LiveConnections
from megalodon.models import PacketEvent
from megalodon.operations import Operations, recent_context
from megalodon.tls_signals import MAX_PER_PEER, SCHEMA, add, assess

NOW = datetime(2026, 10, 18, 5, 0, tzinfo=timezone.utc)
VALID = dict(notbefore='2026-01-01T00:00:00', notafter='2027-01-01T00:00:00')
SUBJECT = 'CN=router.private.example, O=Private Owner'


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError('TLS signals must never contact a host')
    monkeypatch.setattr(socket, 'getaddrinfo', refuse)
    monkeypatch.setattr(socket, 'create_connection', refuse)


def ids(record):
    return [s['id'] for s in record['signals']]


@pytest.mark.parametrize('version', ['TLS 1.2', 'TLS 1.3', 'TLSv1.2', 'UNDETERMINED'])
def test_current_protocols_with_valid_certificates_have_no_signal(version):
    assert assess(dict(version=version, subject='CN=a', issuerdn='CN=ca', **VALID), NOW) is None


@pytest.mark.parametrize('version', ['SSLv2', 'SSLv3', 'TLS 1.0', 'TLSv1', 'TLS 1.1', 'TLSv1.1'])
def test_legacy_protocols_are_review(version):
    record = assess(dict(version=version), NOW)
    assert ids(record) == ['legacy_protocol'] and record['level'] == 'review' and record['version'] == version
    assert record['schema'] == SCHEMA and record['action_status'] == 'not_attempted'


def test_certificate_validity_is_judged_at_observation_time():
    expired = assess(dict(version='TLS 1.2', notbefore='2025-01-01T00:00:00', notafter='2026-01-01T00:00:00'), NOW)
    assert ids(expired) == ['expired_certificate'] and expired['level'] == 'review'
    early = assess(dict(version='TLS 1.2', notbefore='2026-12-01T00:00:00', notafter='2027-12-01T00:00:00'), NOW)
    assert ids(early) == ['not_yet_valid_certificate']
    assert assess(dict(version='TLS 1.2', **VALID), NOW - timedelta(days=400)) is not None


def test_self_signed_alone_is_a_note_and_names_are_never_kept():
    record = assess(dict(version='TLS 1.2', subject=SUBJECT, issuerdn=SUBJECT + ' ', **VALID), NOW)
    assert ids(record) == ['self_signed_certificate'] and record['level'] == 'note'
    assert 'router.private.example' not in json.dumps(record) and 'Private Owner' not in json.dumps(record)
    both = assess(dict(version='TLS 1.0', subject=SUBJECT, issuerdn=SUBJECT), NOW)
    assert both['level'] == 'review' and ids(both) == ['legacy_protocol', 'self_signed_certificate']


@pytest.mark.parametrize('tls, observed', [
    (None, NOW), ('TLS 1.0', NOW), (dict(version='TLS 1.0'), NOW.replace(tzinfo=None)),
    (dict(version='<script>', notafter='yesterday', subject='', issuerdn=''), NOW),
    (dict(version='TLS 1.2', subject='x' * 2000, issuerdn='x' * 2000), NOW),
    (dict(version='TLS 1.2', notafter='2026-02-30T00:00:00'), NOW),
])
def test_malformed_metadata_produces_no_signal(tls, observed):
    assert assess(tls, observed) is None


def test_add_deduplicates_and_bounds_per_peer():
    records = []
    for version in ('TLS 1.0', 'TLS 1.0', 'TLS 1.1', 'SSLv3'):
        add(records, assess(dict(version=version), NOW))
    add(records, None)
    assert [r['version'] for r in records] == ['TLS 1.0', 'TLS 1.1'] and len(records) == MAX_PER_PEER


def eve(path, rows):
    path.write_text('\n'.join(json.dumps(r) for r in rows) + '\n')
    return path


def test_recent_context_keeps_signals_for_the_server_only(tmp_path):
    stamp = datetime.now(timezone.utc).isoformat()
    path = eve(tmp_path/'eve.json', [
        dict(timestamp=stamp, event_type='tls', src_ip='10.0.0.2', dest_ip='203.0.113.9',
             tls=dict(sni='old.example', version='TLS 1.0', subject=SUBJECT, issuerdn=SUBJECT)),
        dict(timestamp=stamp, event_type='tls', src_ip='10.0.0.2', dest_ip='203.0.113.10',
             tls=dict(sni='fine.example', version='TLS 1.3')),
    ])
    context = recent_context(path)
    assert ids(context['203.0.113.9']['tls'][0]) == ['legacy_protocol', 'self_signed_certificate']
    assert context['203.0.113.10']['tls'] == []
    assert '10.0.0.2' not in context or context['10.0.0.2']['tls'] == []
    assert 'Private Owner' not in json.dumps(context)


def operations(tmp_path, context, peers):
    geo = SimpleNamespace(snapshot=lambda: {'anchor': None}, lookup=lambda ip: None)
    cache = LiveConnections(geo)
    cache._local = {'10.0.0.2'}
    for index, address in enumerate(peers):
        cache.observe(PacketEvent(datetime.now(timezone.utc), '10.0.0.2', address, 'TCP', 40000 + index, 443, byte_count=100))
    config = SimpleNamespace(settings=Settings(db_path=tmp_path/'absent.db'),
                             live_snapshot=lambda: cache.snapshot({'state': 'running'}, {}))
    return Operations(config, context_reader=lambda: context)


def test_snapshot_rows_carry_bounded_tls_records_outside_sensor_endpoints(tmp_path):
    peers = [f'203.0.113.{i + 1}' for i in range(40)]
    note = assess(dict(version='TLS 1.2', subject='CN=x', issuerdn='CN=x'), NOW)
    review = assess(dict(version='TLS 1.0'), NOW)
    context = {ip: dict(names=[], findings=[], services=[], tls=[note, dict(note, version='TLS 1.3')]) for ip in peers}
    context[peers[-1]]['tls'] = [review]
    ops = operations(tmp_path, context, peers)
    result = ops.snapshot()
    kept = [r for e in result['endpoints'] for r in e['tls']]
    assert len(kept) == tls_signals.MAX_SNAPSHOT_RECORDS
    assert review in ops.endpoint(peers[-1])['tls']  # review outranks earlier notes
    assert all('tls' not in row for row in result['sensor_endpoints'])
    json.dumps(result)


def test_review_record_replaces_a_note_when_the_peer_is_full():
    records = []
    for version in ('TLS 1.2', 'TLS 1.3'):
        add(records, assess(dict(version=version, subject='CN=x', issuerdn='CN=x'), NOW))
    assert [r['level'] for r in records] == ['note', 'note']
    add(records, assess(dict(version='TLS 1.0'), NOW))
    assert [r['level'] for r in records] == ['note', 'review'] and records[1]['version'] == 'TLS 1.0'
    add(records, assess(dict(version='TLS 1.1'), NOW))
    assert [r['level'] for r in records] == ['review', 'review']
    add(records, assess(dict(version='SSLv3'), NOW))  # full of reviews: newest kept
    assert [r['version'] for r in records] == ['TLS 1.1', 'TLS 1.0']
