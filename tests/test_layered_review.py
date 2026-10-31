"""Synthetic metadata and fake model only; no sensor, process or firewall."""
from copy import deepcopy
import json

import pytest

from megalodon.config import AISettings
from megalodon.evidence_storage import utc
from megalodon.intelligence import explain
from megalodon.layered_review import layered_reviews, MAX_INPUTS, MAX_REVIEWS, INVALID_GAP, LIMIT_GAP
from megalodon.layered_review import SHARED_SUPPORT, SEPARATED_SUPPORT, UNKNOWN_TIMING, UNKNOWN_AUTHORIZATION
from megalodon.security_patterns import candidate

START = 1790726400
SEGMENT = 'a' * 32


def signal(rule='HOST_FANOUT', *, source='synthetic-zeek', measurement='flow',
           device='192.0.2.1', interface='fixture0', refs=None, segments=None, start=START):
    return candidate(rule, (device, interface, source, measurement), start, start + 3600,
                     {'synthetic': True}, refs or [f'{SEGMENT}:1'], segments or [SEGMENT])


def pair():
    return [signal(), signal('REGULAR_INTERVAL', source='synthetic-suricata', refs=[f'{SEGMENT}:2'])]


def test_distinct_families_retain_separate_units_and_all_references():
    items = pair()
    items[0]['evidence_refs'] = [f'{SEGMENT}:{n}' for n in range(1, 25)]
    items[1]['evidence_refs'] = [f'{SEGMENT}:{n}' for n in range(25, 49)]
    items[1]['measurement'] = 'packet'
    original = deepcopy(items)
    result, gaps = layered_reviews(items, START, START + 3600)
    review, = result
    assert items == original and gaps == []
    assert len(review['evidence_refs']) == 48
    assert review['facts']['signals'] == [
        dict(rule='HOST_FANOUT', sensor='synthetic-zeek', measurement='flow'),
        dict(rule='REGULAR_INTERVAL', sensor='synthetic-suricata', measurement='packet')]
    assert review['facts']['independent_corroboration'] is False
    assert review['facts']['attack_sequence_established'] is False
    assert review['action_status'] == 'not_attempted'
    assert review['workflow'] == 'evidence_summary'
    assert 'not a verified host identity' in review['missing_information'][0]
    assert len(json.dumps(review).encode()) < 32768


@pytest.mark.parametrize('rules', [[], ['HOST_FANOUT'], ['HOST_FANOUT'] * 8,
    ['HOST_FANOUT', 'PORT_SCAN'], ['DNS_TUNNELING', 'PORT_53_BURST'],
    ['NEW_DESTINATION_PORT', 'PROTOCOL_SHIFT', 'SERVICE_SHIFT'],
    ['OBSERVED_ACTIVITY', 'REJECTED_TOOL', 'AI_FAILURES', 'LAYERED_ACTIVITY']])
def test_duplicate_same_family_and_non_network_signals_do_not_create_review(rules):
    assert layered_reviews([signal(rule) for rule in rules], START, START + 3600)[0] == []


@pytest.mark.parametrize('field,value', [
    ('device', '192.0.2.2'), ('interface', 'fixture1'),
    ('start', utc(START - 3600)), ('end', utc(START + 7200)),
    ('interface', 'unreported'), ('device', '::ffff:192.0.2.1'),
])
def test_addresses_interfaces_hours_and_aliases_do_not_merge(field, value):
    items = pair(); items[1][field] = value
    assert layered_reviews(items, START, START + 3600)[0] == []


@pytest.mark.parametrize('field,value', [
    ('device', True), ('device', 'fe80::1%eth0'), ('device', 'not-an-address'),
    ('interface', 'x' * 65), ('interface', 'bad\ninterface'),
    ('sensor', '<script>\n'), ('sensor', 'x' * 129), ('sensor', '\ud800'),
    ('measurement', 'raw_payload'), ('measurement', []),
    ('id', 'forged'), ('source_start', utc(START + 1)),
    ('evidence_refs', []), ('evidence_refs', ['b' * 32 + ':1']),
    ('evidence_refs', [SEGMENT + ':0']), ('evidence_refs', [SEGMENT + ':1'] * 25),
    ('source_segments', []), ('source_segments', [False]),
    ('missing_information', ['bad\ntext']), ('missing_information', ['x'] * 19),
    ('action_status', 'applied'), ('rule', []),
])
def test_invalid_input_excluded_with_fixed_gap(field, value):
    items = pair(); items[1][field] = value
    result, gaps = layered_reviews(items, START, START + 3600)
    assert result == [] and INVALID_GAP in gaps


def test_order_independence_no_input_mutation_and_stable_deduplication():
    items = pair() + [signal('SYN_FLOOD'), signal('PORT_SCAN')]
    forward = layered_reviews(items, START, START + 3600)
    assert layered_reviews(list(reversed(items)), START, START + 3600) == forward
    assert layered_reviews(items * 2, START, START + 3600) == forward
    later = [dict(v, start=utc(START + 3600), end=utc(START + 7200),
                  source_start=utc(START + 3600)) for v in items]
    next_review = layered_reviews(later, START + 3600, START + 7200)[0][0]
    assert next_review['fingerprint'] == forward[0][0]['fingerprint']
    assert next_review['id'] != forward[0][0]['id']


def test_complete_dependency_union_and_old_baseline_expiry_boundary():
    items = pair(); items[1]['source_start'] = utc(START - 86400)
    prior = 'b' * 32; items[1]['source_segments'].append(prior)
    items[1]['missing_information'].insert(0, 'Synthetic coverage gap.')
    review = layered_reviews(items, START, START + 3600)[0][0]
    assert review['source_start'] == utc(START - 86400)
    assert review['source_segments'] == [SEGMENT, prior]
    assert 'Synthetic coverage gap.' in review['missing_information']
    # Exceeding dependency capacity cannot leave a partial dependency list.
    items[0]['source_segments'] = [SEGMENT] + [f'{n:032x}' for n in range(255)]
    result, gaps = layered_reviews(items, START, START + 3600)
    assert not result and LIMIT_GAP in gaps


def test_bounded_input_and_output_are_reported():
    result, gaps = layered_reviews([signal()] * MAX_INPUTS + [pair()[1]], START, START + 3600)
    assert not result and LIMIT_GAP in gaps
    items = []
    for n in range(MAX_REVIEWS + 1):
        items += [signal(device=f'192.0.2.{n+1}'), signal('REGULAR_INTERVAL', device=f'192.0.2.{n+1}')]
    result, gaps = layered_reviews(items, START, START + 3600)
    assert len(result) == MAX_REVIEWS and LIMIT_GAP in gaps


def test_ipv6_and_overlapping_sensor_records_never_claim_independence():
    items = [signal(device='2001:db8::1'), signal('REGULAR_INTERVAL', device='2001:db8::1')]
    review = layered_reviews(items, START, START + 3600)[0][0]
    assert review['device'] == '2001:db8::1'
    assert review['evidence_refs'] == [f'{SEGMENT}:1']
    assert review['facts']['independent_corroboration'] is False


def test_data_and_model_text_cannot_supply_rules_commands_or_response_authority():
    items = pair()
    items[0]['facts']['command'] = 'untrusted command'
    review = layered_reviews(items, START, START + 3600)[0][0]
    prompts = []
    def model(settings, prompt, **kwargs):
        prompts.append(prompt)
        return json.dumps(dict(explanation='Two signals share a recorded address.',
            alternative='Authorized tasks may overlap.', missing='Host identity and intent are unknown.',
            citations=['E1'], workflow='contain'))
    result = explain(review, [], AISettings(), model=model)
    assert 'untrusted command' not in prompts[0]
    assert len(prompts[0].encode()) <= 4096
    assert result['workflow'] == 'evidence_summary'
    assert result['action_status'] == 'not_attempted'


@pytest.mark.parametrize('start,end', [(True, START + 3600), (START, START),
    (float('nan'), float('nan')), (START, START + 3601)])
def test_invalid_hour_refused(start, end):
    with pytest.raises(ValueError):
        layered_reviews(pair(), start, end)


def timed_pair():
    items = pair()
    for item, first, last in zip(items, (0, 3000), (15, 3040)):
        item['facts'] = dict(first_seen=utc(START + first), last_seen=utc(START + last))
    return items


def test_separated_support_is_disclosed_without_inferring_address_reuse_or_hiding_evidence():
    items = timed_pair()
    original = deepcopy(items)
    review, = layered_reviews(items, START, START + 3600)[0]
    assert items == original
    assert review['facts']['evidence_qualification'] == dict(
        reference_scope='selected_reference_pages', shared_reference_count=0,
        support_time_relation='separated', support_time_gap_seconds=2985,
        authorization_context='unavailable')
    assert SEPARATED_SUPPORT in review['missing_information'][:4]
    assert UNKNOWN_AUTHORIZATION in review['missing_information'][0]
    assert review['evidence_refs'] == [f'{SEGMENT}:1', f'{SEGMENT}:2']
    assert layered_reviews(list(reversed(items)), START, START + 3600)[0] == [review]


def test_shared_support_counts_retained_references_without_claiming_complete_equivalence():
    items = pair()
    items[1]['evidence_refs'] = items[0]['evidence_refs'][:]
    items[0]['facts'] = dict(references_omitted=100)
    review, = layered_reviews(items, START, START + 3600)[0]
    qualification = review['facts']['evidence_qualification']
    assert qualification['shared_reference_count'] == 1
    assert qualification['reference_scope'] == 'selected_reference_pages'
    assert qualification['support_time_relation'] == 'unavailable'
    assert qualification['support_time_gap_seconds'] is None
    assert SHARED_SUPPORT in review['missing_information'][:4]
    assert review['facts']['independent_corroboration'] is False


@pytest.mark.parametrize('facts', [None, [], {}, {'first_seen': True, 'last_seen': 123},
    {'first_seen': 'bad', 'last_seen': 'bad'},
    {'first_seen': utc(START - 1), 'last_seen': utc(START + 15)},
    {'first_seen': utc(START), 'last_seen': utc(START + 3600)},
    {'first_seen': utc(START + 15), 'last_seen': utc(START)},
    {'first_seen': 'x' * 41, 'last_seen': utc(START)}])
def test_invalid_optional_support_extent_retains_review_and_reports_unknown(facts):
    items = timed_pair(); items[0]['facts'] = facts
    review, = layered_reviews(items, START, START + 3600)[0]
    assert review['facts']['evidence_qualification']['support_time_relation'] == 'unavailable'
    assert UNKNOWN_TIMING in review['missing_information']
    assert review['action_status'] == 'not_attempted'


def test_unsupported_rule_timestamps_are_not_interpreted_as_support_extents():
    items = timed_pair(); items[0]['rule'] = 'PORT_SCAN'
    review, = layered_reviews(items, START, START + 3600)[0]
    assert review['facts']['evidence_qualification']['support_time_relation'] == 'unavailable'


def test_overlapping_extents_are_not_a_claim_of_simultaneous_activity():
    items = timed_pair()
    items[0]['facts']['last_seen'] = utc(START + 3010)
    review, = layered_reviews(items, START, START + 3600)[0]
    qualification = review['facts']['evidence_qualification']
    assert qualification['support_time_relation'] == 'overlapping_extents'
    assert qualification['support_time_gap_seconds'] == 0
    assert review['facts']['attack_sequence_established'] is False
    assert review['facts']['independent_corroboration'] is False


def test_qualification_notes_survive_bounded_coverage_projection_without_losing_individual_notes():
    items = timed_pair()
    items[0]['missing_information'] = [f'Synthetic coverage note {n}.' for n in range(18)]
    original = deepcopy(items)
    review, = layered_reviews(items, START, START + 3600)[0]
    assert items == original
    assert SEPARATED_SUPPORT in review['missing_information'][:4]
    assert UNKNOWN_AUTHORIZATION in review['missing_information'][0]
    assert any('inspect the individual signals' in gap for gap in review['missing_information'])
    assert len(review['missing_information']) <= 18


def test_component_coverage_is_visible_alongside_shared_support_and_unknown_timing():
    items = pair(); items[1]['evidence_refs'] = items[0]['evidence_refs'][:]
    items[0]['missing_information'].insert(0, 'Synthetic source loss.')
    review, = layered_reviews(items, START, START + 3600)[0]
    assert 'Synthetic source loss.' in review['missing_information'][:4]
    assert SHARED_SUPPORT in review['missing_information'][:4]
    assert UNKNOWN_TIMING in review['missing_information'][:4]
    assert len(review['missing_information'][0]) <= 512
