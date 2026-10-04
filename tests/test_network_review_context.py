"""Fixed cues preserve detector evidence, prompt bounds and review authority."""
from datetime import datetime, timezone
import json

import pytest

from megalodon import intelligence, network_review_context
from megalodon.config import AISettings, DetectionSettings
from megalodon.detector import Detector
from megalodon.models import PacketEvent
from megalodon.security_patterns import CONTEXT, candidate


START = datetime(2026, 10, 3, tzinfo=timezone.utc).timestamp()
CUES = (
    ('OBSERVED_ACTIVITY', ('If NAT', 'does not establish that NAT')),
    ('PORT_SCAN', ('distinct destination ports per source', 'Repeated packets to one port')),
    ('SYN_FLOOD', ('retransmit SYN', 'resource exhaustion')),
    ('DNS_TUNNELING', ('dns_query_length', 'no destination-port condition', 'length alone')),
    ('PORT_53_BURST', ('Port 53 observations', 'not a count of parsed DNS questions')),
    ('NEW_DESTINATION_PORT', ('not an application identity', 'TLS')),
    ('PROTOCOL_SHIFT', ('transport metadata alone', 'cannot identify the application')),
    ('SERVICE_SHIFT', ('label is an observation', 'not proof')),
)


def _item(rule, facts=None):
    return candidate(rule, ('192.0.2.1', 'eth0', 'synthetic', 'packet'),
                     START, START + 60, facts or {}, ['a:1'], ['a'])


def _response(*args, **kwargs):
    return json.dumps(dict(explanation='Observed evidence.', alternative='Routine activity.',
                           missing='Complete coverage.', citations=['E1'], workflow='contain'))


@pytest.mark.parametrize('rule,terms', CUES)
def test_every_cue_reaches_bounded_prompt_without_granting_authority(rule, terms):
    prompts = []
    def model(settings, prompt, **kwargs):
        prompts.append(prompt)
        return _response()
    item = _item(rule)
    result = intelligence.explain(item, [], AISettings(), model=model)
    assert len(prompts) == 1 and len(prompts[0].encode()) <= 4096
    cue = prompts[0].split(' NETWORK_CONTEXT ', 1)[1].split(' DATA ', 1)[0]
    assert all(term in cue for term in terms)
    assert result['citations'] == [item['id']]
    assert result['references'] == []
    assert result['workflow'] == CONTEXT[rule][3]
    assert result['approval_required'] is True
    assert result['action_status'] == 'not_attempted'


def test_unknown_and_unmapped_rules_have_no_cue():
    assert network_review_context.for_pattern('UNKNOWN_RULE') == ''
    assert network_review_context.for_pattern('AI_FAILURES') == ''
    def model(settings, prompt, **kwargs):
        assert ' NETWORK_CONTEXT ' not in prompt
        return _response()
    assert intelligence.explain(_item('AI_FAILURES'), [], AISettings(), model=model)['workflow'] == 'ai_readiness'


@pytest.mark.parametrize('extra_bytes', [0, 1])
def test_cue_is_omitted_only_when_it_would_exceed_prompt_bound(monkeypatch, extra_bytes):
    item = _item('PORT_SCAN', {'padding': ''})
    prompts = []
    def model(settings, prompt, **kwargs):
        prompts.append(prompt)
        return _response()
    context = network_review_context.for_pattern('PORT_SCAN')
    with monkeypatch.context() as patch:
        patch.setattr(intelligence, 'network_context_for_pattern', lambda rule: '')
        intelligence.explain(item, [], AISettings(), model=model)
    context_bytes = len((' NETWORK_CONTEXT ' + context).encode())
    item['facts']['padding'] = 'x' * (4096 - len(prompts.pop().encode()) - context_bytes + extra_bytes)
    intelligence.explain(item, [], AISettings(), model=model)
    assert (' NETWORK_CONTEXT ' in prompts[0]) is (extra_bytes == 0)
    assert len(prompts[0].encode()) <= 4096
    if extra_bytes == 0:
        assert len(prompts[0].encode()) == 4096
    assert json.loads(prompts[0].split(' DATA ', 1)[1])['E1']['facts'] == item['facts']


def test_oversized_evidence_is_rejected_before_model_call():
    with pytest.raises(ValueError, match='bounded explanation context'):
        intelligence.explain(_item('PORT_SCAN', {'padding': 'x' * 4096}), [], AISettings(),
                             model=lambda *a, **k: pytest.fail('Oversized evidence reached model'))


def _event(**changes):
    value = dict(observed_at=datetime.fromtimestamp(START, timezone.utc), src_ip='192.0.2.1',
                 dst_ip='198.51.100.1', protocol='TCP', dst_port=80, tcp_flags=['ACK'])
    return PacketEvent.from_mapping(value | changes)


def test_port_scan_cue_matches_ack_packets_and_distinct_ports_on_one_host():
    detector = Detector(DetectionSettings(port_scan_distinct_ports=3))
    assert detector.analyze(_event(dst_port=80)) == []
    # Many hosts on one port still supply only one distinct destination port.
    for index in range(2, 6):
        assert detector.analyze(_event(dst_ip=f'198.51.100.{index}')) == []
    assert detector.analyze(_event(dst_port=81)) == []
    finding, = detector.analyze(_event(dst_port=82))
    assert finding.rule_id == 'PORT_SCAN' and finding.evidence['distinct_ports'] == 3
    cue = network_review_context.for_pattern(finding.rule_id)
    assert 'distinct destination ports per source' in cue
    assert 'not distinct destination hosts or SYN attempts' in cue


def test_dns_cue_matches_query_length_without_port_53():
    detector = Detector(DetectionSettings(dns_query_length=50))
    assert detector.analyze(_event(protocol='UDP', dst_port=53, tcp_flags=[])) == []
    finding, = detector.analyze(_event(protocol='UDP', dst_port=5353, tcp_flags=[], dns_query_length=50))
    assert finding.rule_id == 'DNS_TUNNELING' and finding.evidence['dns_query_length'] == 50
    cue = network_review_context.for_pattern(finding.rule_id)
    assert 'dns_query_length' in cue and 'no destination-port condition' in cue
    assert 'Port 53 metadata alone' not in cue
