"""Selected-review prompt and grounding checks; deterministic fake model only."""
from copy import deepcopy
import json

import pytest

from megalodon.config import AISettings
from megalodon.intelligence import SELECTED_EXPLANATION_CONTRACT, explain


@pytest.fixture
def item():
    return dict(id='detector:'+'a'*32+':1', rule='SYN_FLOOD', device='10.0.0.8',
                measurement='Selected finding evidence', sensor='MEGALODON detector',
                endpoint_context=True, selected_finding=True, missing_information=['Complete evaluation window unavailable.'],
                facts=dict(rule='SYN_FLOOD', src_ip='10.0.0.8', dst_ip='198.51.100.10',
                           protocol='TCP', dst_port=443, recorded_evidence=dict(count=100, window_seconds=10),
                           coverage=['Complete evaluation window unavailable.']))


def response(explanation, *, missing='The complete evaluation window and historical threshold are unavailable.'):
    return dict(explanation=explanation, alternative='Retransmissions or an authorized load test could explain the burst.',
                missing=missing, citations=['E1'], workflow='contain')


def test_selected_prompt_uses_exact_record_and_grounded_output(item):
    seen = []
    def model(settings, prompt, **kwargs):
        seen.append((prompt, kwargs))
        return json.dumps(response('SYN flood was recorded with 100 TCP SYN packets in 10 seconds; intent remains unknown.'))
    result = explain(item, [], AISettings(), model=model, owner='finding-test')
    prompt, options = seen[0]
    assert prompt.startswith('Analyze ONE recorded finding in DATA.E1')
    assert 'not a definition' in prompt and 'do not invent missing tools or configuration' in prompt
    assert json.loads(prompt.split(' DATA ', 1)[1])['E1'] == item['facts']
    assert options['priority'] == 'manual' and options['owner'] == 'finding-test'
    assert result['state'] == 'ready' and result['explanation_contract'] == SELECTED_EXPLANATION_CONTRACT
    assert result['citations'] == [item['id']]
    assert result['workflow'] == 'evidence_summary', 'Model does not choose containment authority'


@pytest.mark.parametrize('text', [
    'It involves examining local device configurations, user permissions, and system settings to identify potential vulnerabilities.',
    'A local security review checks network and device settings for possible risks.',
    'The event needs investigation; intent is unknown.',
    'The observation involved 100 settings and 10 tools.',
    'The device 10.0.0.80 has recorded activity.',
])
def test_valid_json_and_e1_do_not_make_generic_or_unrelated_answer_ready(item, monkeypatch, text):
    rejected = []
    monkeypatch.setattr('megalodon.intelligence.ai_provider.reject_response', lambda settings: rejected.append(settings))
    with pytest.raises(ValueError, match='invalid or unsupported explanation'):
        explain(item, [], AISettings(), model=lambda *a, **k: json.dumps(response(text)))
    assert len(rejected) == 1


@pytest.mark.parametrize('text', [
    'The recorded SYN_FLOOD finding needs review; intent is unknown.',
    'Traffic from 10.0.0.8 was recorded; intent is unknown.',
    'The evidence records 100 TCP SYN packets; intent is unknown.',
    'The recorded window is 10 seconds; the complete evaluation is unavailable.',
])
def test_rule_subject_and_recorded_measurement_anchors_are_supported(item, text):
    assert explain(item, [], AISettings(), model=lambda *a, **k: json.dumps(response(text)))['state'] == 'ready'


def test_sensor_signature_can_anchor_a_selected_review(item):
    item['facts'] = dict(rule='42', signature='Synthetic TLS alert', src_ip=None,
                         recorded_evidence={}, coverage=['Sensor alert is not proof of compromise.'])
    item['rule'], item['device'] = 'OBSERVED_ACTIVITY', 'Unknown'
    text = 'The synthetic TLS alert is a recorded sensor observation; it does not establish compromise.'
    assert explain(item, [], AISettings(), model=lambda *a, **k: json.dumps(response(text)))['state'] == 'ready'


def test_preserved_reference_only_needs_subject_and_explicit_unknown_measurements(item, monkeypatch):
    item['facts']['recorded_evidence'] = {'preserved_finding': True}
    item['facts']['coverage'] = ['Only a preserved reference remains; counts, thresholds and window are unavailable.']
    text = 'A SYN flood finding reference was preserved for 10.0.0.8; intent is unknown.'
    result = explain(item, [], AISettings(), model=lambda *a, **k: json.dumps(response(text,
        missing='Original counts, thresholds and evaluation window are unavailable.')))
    assert result['state'] == 'ready'
    monkeypatch.setattr('megalodon.intelligence.ai_provider.reject_response', lambda settings: None)
    with pytest.raises(ValueError):
        explain(item, [], AISettings(), model=lambda *a, **k: json.dumps(response(text, missing='More local configuration tools are needed.')))


def test_legacy_review_contract_and_prompt_remain_unchanged(item):
    legacy = deepcopy(item)
    legacy.pop('selected_finding')
    prompts = []
    def model(settings, prompt, **kwargs):
        prompts.append(prompt)
        return json.dumps(response('Traffic was observed; intent is unknown.'))
    result = explain(legacy, [], AISettings(), model=model)
    assert prompts[0].startswith('Explain a local security review in plain language.')
    assert result['state'] == 'ready' and 'explanation_contract' not in result
