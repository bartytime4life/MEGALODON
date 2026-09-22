"""Synthetic regressions binding profile snapshot ownership to comparison gates."""
import pytest
from megalodon.model_profile import (
    ModelProfileError, validate_profile, binding_candidate_packet,
    compare_profiles, parse_profile_bytes,
)
from test_model_profile_snapshot import _profile

@pytest.mark.parametrize('section,field,replacement', [
    (None, 'evidence_class', 'operator_observed'),
    (None, 'purpose', 'explanation'),
    (None, 'operational_context', 2048),
    ('runner', 'version', '0.0.1-synthetic'),
    ('runner', 'binary_sha256', '1' * 64),
    ('evaluation', 'corpus_sha256', '1' * 64),
    ('evaluation', 'sample_count', 13),
])
def test_mixed_boundary_refuses_but_returned_view_mutation_does_not_rebind(section, field, replacement):
    first = validate_profile(_profile())
    raw = _profile('qwen-snapshot-b')
    target = raw if section is None else raw[section]
    target[field] = replacement
    second = validate_profile(raw)
    with pytest.raises(ModelProfileError, match='COMPARISON_BOUNDARY_MISMATCH'):
        compare_profiles([first, second])
    exposed = first.value
    target = exposed if section is None else exposed[section]
    target[field] = replacement
    with pytest.raises(ModelProfileError, match='COMPARISON_BOUNDARY_MISMATCH'):
        compare_profiles([first, second])
    current = validate_profile(first.value)
    assert current.comparison_boundary_sha256 == first.comparison_boundary_sha256
    assert current.canonical_sha256 == first.canonical_sha256


def test_valid_candidate_differences_remain_comparable_without_admission():
    a = validate_profile(_profile())
    other = _profile('qwen-snapshot-b')
    other.update(model_alias='qwen2.5:14b-instruct-q4_K_M', quantization='q4_K_M', context_window=131072)
    other['evaluation']['p95_latency_ms'] = 700
    b = validate_profile(other)
    result = compare_profiles([a, b])
    assert result['comparison_boundary_sha256'] == a.comparison_boundary_sha256 == b.comparison_boundary_sha256
    assert result['selection'] is None
    assert result['ranking'][0]['profile_id'] == b.profile_id
    assert binding_candidate_packet(a)['state'] == binding_candidate_packet(b)['state'] == 'SYNTHETIC_ONLY'
    assert not any(binding_candidate_packet(a)['authority'].values())


def test_purpose_narrowing_survives_snapshot_integration():
    raw = _profile()
    raw['purpose'] = 'tool-selection'
    with pytest.raises(ModelProfileError, match='PURPOSE'):
        validate_profile(raw)

@pytest.mark.parametrize('data,code', [
    (b'{"schema":"one","schema":"two"}', 'DUPLICATE_JSON_KEY'),
    (b'{"value":NaN}', 'NON_FINITE_NUMBER'),
    (b'{"value":Infinity}', 'NON_FINITE_NUMBER'),
])
def test_json_refusals_remain_closed(data, code):
    with pytest.raises(ModelProfileError, match=code):
        parse_profile_bytes(data)
