"""Review-only hostname spelling signals over synthetic names."""
from datetime import datetime, timezone
import json
import socket
from types import SimpleNamespace

import pytest

from megalodon import domain_signals
from megalodon.config import Settings
from megalodon.domain_signals import MAX_NAMES, SCHEMA, assess, entropy, review
from megalodon.live_connections import LiveConnections
from megalodon.models import PacketEvent
from megalodon.operations import Operations

BENIGN = ('www.google.com', 'mail.example.org', 'googleusercontent.com', 'accounts.youtube.com',
          'update.microsoft.com', 'api.github.com', 'fonts.gstatic.com', 'connectivity-check.ubuntu.com',
          'safebrowsing.googleapis.com', 'download.windowsupdate.com', 'strengthsandweaknesses.com',
          'firefox.settings.services.mozilla.com', 'telemetry-incoming.r53-2.services.mozilla.com',
          'r3---sn-ab5l6nzr.googlevideo.com', 'e1234.dscb.akamaiedge.net', '123456.example.com', 'localhost')
GENERATED = ('xkqzjvbwmtrplhgn.com', 'a8f3k2j9x7q1m4z6.net', '4f9a8c7b6d5e4f3a2b1c.biz',
             'aGVsbG8gd29ybGQ.dGhpcyBpcyBkYXRh.ZXhmaWx0cmF0aW9u.YQ.b.c.tunnel.example')


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError('naming signals must never resolve or contact a name')
    monkeypatch.setattr(socket, 'getaddrinfo', refuse)
    monkeypatch.setattr(socket, 'create_connection', refuse)


@pytest.mark.parametrize('name', BENIGN)
def test_common_service_names_are_never_review_level(name):
    result = assess(name)
    assert result is None or result['level'] == 'note'


@pytest.mark.parametrize('name', GENERATED)
def test_generated_and_encoded_names_need_two_signals_for_review(name):
    result = assess(name)
    assert result['level'] == 'review' and len(result['signals']) >= 2
    assert result['schema'] == SCHEMA and result['action_status'] == 'not_attempted'
    assert result['attack'] == ['T1568.002', 'T1071.004']
    assert any('not evidence of malware' in line for line in result['context'])


def test_one_signal_is_a_note_and_hyphenated_words_are_not_random():
    assert assess('mxlqjrtwvb.ru')['level'] == 'note'
    result = assess('international-business-machines.example.com')
    assert [s['id'] for s in result['signals']] == ['long_label'] and result['level'] == 'note'
    assert assess('xn--pple-43d.com')['signals'][0]['id'] == 'punycode'


def test_provider_generated_suffix_caps_level_without_claiming_safety():
    result = assess('d1a2b3c4d5e6f7a8b9.cloudfront.net')
    assert result['level'] == 'note' and len(result['signals']) >= 2
    assert result['context'][0] == ('Providers commonly generate names under cloudfront.net; '
                                    'this spelling is expected there. That does not establish safety.')
    # A look-alike suffix is not the provider's own suffix.
    assert assess('xkqzjvbwmtrplhgn.evilcloudfront.net')['level'] == 'review'


@pytest.mark.parametrize('value', [None, 7, b'abc.com', '', '.', 'a..b.com', '<script>x</script>.com',
                                   'bad name.com', 'x' * 254, '-lead.example', 'ünicode.example'])
def test_malformed_names_are_ignored(value):
    assert assess(value) is None


def test_case_and_trailing_dot_are_normalized():
    assert assess('XKQZJVBWMTRPLHGN.COM.')['name'] == 'xkqzjvbwmtrplhgn.com'


def test_entropy_bounds():
    assert entropy('') == 0.0 and entropy('aaaa') == 0.0
    assert entropy('abcd') == pytest.approx(2.0)


def test_review_is_bounded_deduplicated_and_ordered():
    names = [dict(name=n) for n in ('mxlqjrtwvb.ru', 'XKQZJVBWMTRPLHGN.com', 'xkqzjvbwmtrplhgn.com',
                                    'www.google.com', 'a8f3k2j9x7q1m4z6.net', 'qwrtpsdfgh.info', 'b9x7q1m4z6a8f3k2.org')]
    result = review(names)
    assert [r['name'] for r in result] == ['a8f3k2j9x7q1m4z6.net', 'xkqzjvbwmtrplhgn.com', 'mxlqjrtwvb.ru', 'qwrtpsdfgh.info']
    assert len(names) > MAX_NAMES + 1 and 'b9x7q1m4z6a8f3k2.org' not in {r['name'] for r in result}  # read stops at MAX_NAMES distinct names
    assert review(None) == [] and review([None, 'x', dict(name=3)]) == []


def test_thresholds_are_code_constants():
    assert (domain_signals.HIGH_ENTROPY_BITS, domain_signals.ENTROPY_MIN_CHARS, domain_signals.LONG_LABEL_CHARS) == (3.5, 12, 24)
    assert all(isinstance(s, str) and '.' in s for s in domain_signals.GENERATED_SUFFIXES)


def test_operations_endpoint_carries_separate_review_and_unchanged_names(tmp_path):
    geo = SimpleNamespace(snapshot=lambda: {'anchor': None}, lookup=lambda ip: None)
    cache = LiveConnections(geo)
    cache._local = {'10.0.0.2'}
    cache.observe(PacketEvent(datetime.now(timezone.utc), '10.0.0.2', '203.0.113.8', 'TCP', 54321, 443, byte_count=100))
    names = [dict(name='xkqzjvbwmtrplhgn.com', source='Observed TLS SNI', observed_at='2026-10-18T00:00:00Z'),
             dict(name='www.example.com', source='Observed DNS answer', observed_at='2026-10-18T00:00:00Z')]
    config = SimpleNamespace(settings=Settings(db_path=tmp_path / 'absent.db'),
                             live_snapshot=lambda: cache.snapshot({'state': 'running'}, {}))
    operations = Operations(config, context_reader=lambda: {'203.0.113.8': dict(names=names, findings=[], services=[])})
    result = operations.snapshot()
    remote = operations.endpoint('203.0.113.8')
    assert remote['names'] == names
    assert [r['name'] for r in remote['name_review']] == ['xkqzjvbwmtrplhgn.com']
    assert operations.endpoint('10.0.0.2')['name_review'] == []
    assert any('spelling only' in note for note in result['coverage']['notes'])
    json.dumps(result)


def test_worst_case_snapshot_review_stays_inside_hud_response_budget(tmp_path):
    geo = SimpleNamespace(snapshot=lambda: {'anchor': None}, lookup=lambda ip: None)
    cache = LiveConnections(geo)
    cache._local = {'10.0.0.2'}
    context = {}
    for index in range(70):
        address = f'203.0.113.{index + 1}'
        cache.observe(PacketEvent(datetime.now(timezone.utc), '10.0.0.2', address, 'TCP', 40000 + index, 443, byte_count=100))
        # Hostile observer-controlled names: maximal length, every signal at once.
        context[address] = dict(findings=[], services=[], names=[
            dict(name='.'.join([f'xn--{index}{n}'] + ['q9z8x7w6v5'*5 + f'{n}{j}' for j in range(4)])[:240] + '.example',
                 source='Observed TLS SNI', observed_at='2026-10-18T00:00:00Z') for n in range(5)])
    config = SimpleNamespace(settings=Settings(db_path=tmp_path / 'absent.db'),
                             live_snapshot=lambda: cache.snapshot({'state': 'running'}, {}))
    result = Operations(config, context_reader=lambda: context).snapshot()
    records = [r for e in result['endpoints'] for r in e['name_review']]
    assert len(records) == domain_signals.MAX_SNAPSHOT_RECORDS
    assert all(len(s['detail']) <= 160 for r in records for s in r['signals'])
    assert len(json.dumps(records).encode()) < 96 * 1024


@pytest.mark.parametrize('value', ['x' * 64 + '.com', 'bad-.example', 'a.-bad.example', 'ok.x' + 'y' * 63 + '.net'])
def test_invalid_dns_labels_produce_no_signal(value):
    assert assess(value) is None


def test_longest_valid_label_and_service_labels_are_still_scored():
    assert [s['id'] for s in assess('ab' * 31 + 'a.com')['signals']] == ['long_label']
    assert assess('ab' * 32 + '.com') is None
    assert assess('_dmarc.example.com') is None


def test_equivalent_spellings_count_once():
    names = [dict(name='xkqzjvbwmtrplhgn.com'), dict(name='XKQZJVBWMTRPLHGN.COM.')]
    assert [r['name'] for r in review(names)] == ['xkqzjvbwmtrplhgn.com']


def test_snapshot_cap_keeps_review_records_ahead_of_earlier_notes():
    note = assess('mxlqjrtwvb.ru')
    flagged = assess('xkqzjvbwmtrplhgn.com')
    groups = [[note] * 5 for _ in range(13)] + [[note, flagged]]
    capped = domain_signals.cap(groups)
    assert sum(len(group) for group in capped) == domain_signals.MAX_SNAPSHOT_RECORDS
    assert flagged in capped[-1]
    assert capped[0] == [note] * 5 and domain_signals.cap([[note, flagged]]) == [[note, flagged]]
