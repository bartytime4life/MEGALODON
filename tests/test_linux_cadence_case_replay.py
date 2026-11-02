"""Offline adversarial controls for the integrated native cadence case."""
from copy import copy, deepcopy
from dataclasses import replace
import json
import sys

import pytest

from tools import replay_linux_cadence_case as lab


def fixture():
    child = object()
    service = lab.Destination(('127.0.0.1', 41001), 'fixture-listener')
    alternate = lab.Destination(('127.0.0.1', 41002), 'reserved-alternate')
    endpoints = {d.address: d for d in (service, alternate)}
    grants = tuple(lab._JobGrant(child, (d,), 0.5, 30) for d in (service, alternate))
    flows = []
    for i in range(5):
        when = 1 + i * 3
        flows.append(lab.Flow(f'{"a" * 32}:{i + 1}', ('127.0.0.1', 50000 + i), service.address,
                              lab.utc(1790812800 + when), when, when + 0.4))
    live = {f.ref: lab.Witness(f, child, f.accepted + 0.1, f.accepted + 0.2) for f in flows}
    last = flows[-1]
    delayed = {**live, last.ref: lab.Witness(last, None, last.released + 0.1, last.released + 0.2)}
    return flows, live, delayed, grants, endpoints


def test_one_unmodified_real_detector_finding_supports_all_three_contexts():
    flows, live, delayed, grants, endpoints = fixture()
    report = lab._case(flows, live, delayed, grants, endpoints, True)
    refs = [f.ref for f in flows]
    _, (native_rule,), _ = lab.analyze_hour([f.row() for f in flows], 1790812801, 1790816401, [])
    assert report['finding'] == {k: native_rule[k] for k in report['finding']}
    assert report['finding']['state'] == 'unreviewed' and report['finding']['action_status'] == 'not_attempted'
    assert report['finding']['evidence_refs'] == refs
    assert report['all_match'] and report['unsupported_matches'] == report['unsupported_reference_matches'] == 0
    match, mismatch, late = report['contexts'].values()
    assert [c['status'] for c in (match, mismatch, late)] == ['scope_match', 'scope_mismatch', 'unknown']
    assert mismatch['permitted_destination'] == 'reserved-alternate' and mismatch['outside_refs'] == refs
    assert late['missing_refs'] == refs[-1:] and late['evidence'][-1]['decision'] == 'outside_held_interval'
    for case in (match, mismatch, late):
        assert [item['ref'] for item in case['evidence']] == refs
        assert {item['observed_destination'] for item in case['evidence']} == {'fixture-listener'}
    public = json.dumps(report)
    assert all(raw not in public for raw in ('127.0.0.1', '41001', '41002', '50000', '2026-10-01'))
    assert lab._case(flows[::-1], live, delayed, grants, endpoints, True) == report


def test_a_later_snapshot_cannot_fill_the_missing_ref_even_with_the_right_identity():
    flows, live, delayed, grants, endpoints = fixture()
    last = flows[-1]
    delayed[last.ref] = replace(delayed[last.ref], subject=grants[0].subject)
    report = lab._case(flows, live, delayed, grants, endpoints, True)
    assert report['contexts']['delayed_fifth_lookup']['missing_refs'] == [last.ref]
    # Even with apparently correct aggregate outcomes, an unverified close is no pass.
    assert not lab._case(flows, live, delayed, grants, endpoints, False)['all_match']


def test_full_evidence_cannot_be_silently_reused_for_the_delayed_lane():
    flows, live, _, grants, endpoints = fixture()
    report = lab._case(flows, live, live, grants, endpoints, True)
    assert not report['all_match']
    assert report['unsupported_matches'] == report['unsupported_reference_matches'] == 1


@pytest.mark.parametrize('substitution', ['different_flow', 'copied_flow', 'different_job', 'early',
                                          'inverted_interval', 'missing_witness', 'no_holder'])
def test_unbound_or_missing_evidence_names_the_exact_unresolved_reference(substitution):
    flows, live, _, grants, endpoints = fixture()
    ref = flows[0].ref
    w = live[ref]
    if substitution == 'missing_witness':
        del live[ref]
    else:
        changes = dict(different_flow={'flow': flows[1]}, copied_flow={'flow': copy(w.flow)},
                       different_job={'subject': object()}, early={'begin': w.flow.accepted - 1},
                       inverted_interval={'end': w.begin - 1}, no_holder={'subject': None})
        live[ref] = replace(w, **changes[substitution])
    outcome = lab._assessment([ref], {ref: flows[0]}, live, grants[0], endpoints)
    assert outcome['status'] == 'unknown' and outcome['missing_refs'] == [ref]


def test_grant_must_cover_start_and_complete_witness_and_facts_remain_read_only():
    flows, live, _, grants, endpoints = fixture()
    flow = flows[0]
    rows = [f.row() for f in flows]
    before = deepcopy(rows)
    for grant in (replace(grants[0], issued=flow.accepted + 0.05),
                  replace(grants[0], expires=live[flow.ref].end),
                  replace(grants[0], revoked=live[flow.ref].begin)):
        out = lab._assessment([flow.ref], {flow.ref: flow}, live, grant, endpoints)
        assert out['status'] == 'unknown' and out['missing_refs'] == [flow.ref]
    assert [f.row() for f in flows] == before


def test_missing_or_irregular_starts_cannot_manufacture_a_cadence_finding():
    flows, live, delayed, grants, endpoints = fixture()
    with pytest.raises(lab.NoCadence):
        lab._case(flows[:-1], live, delayed, grants, endpoints, True)
    flows[-1].first_seen = lab.utc(1790812899)
    with pytest.raises(lab.NoCadence):
        lab._case(flows, live, delayed, grants, endpoints, True)


def test_cli_accepts_no_external_input(monkeypatch, capsys):
    monkeypatch.setattr(lab, '_probe', lambda: pytest.fail('unexpected probe'))
    assert lab.main(['--target', 'somewhere']) == 2
    assert 'somewhere' not in capsys.readouterr().out
    monkeypatch.setattr(sys, 'platform', 'other')
    assert lab.main([]) == 2
    assert json.loads(capsys.readouterr().out)['reason'] == 'linux_diagnostics_required'
