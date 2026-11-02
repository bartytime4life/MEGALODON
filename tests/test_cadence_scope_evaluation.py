"""Regression checks for the isolated five-connection scope experiment."""

from copy import deepcopy
from dataclasses import replace
import json
import socket
import sqlite3
import subprocess

import pytest

from megalodon import cadence_scope_evaluation as replay
from megalodon.evaluation import main
from megalodon.layered_evaluation import load_corpus, observations
from megalodon.security_patterns import analyze_hour


def test_cli_reports_the_original_findings_and_checks_each_counterfactual(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail('offline replay attempted external I/O')

    for module, name in [(socket, 'socket'), (sqlite3, 'connect'), (subprocess, 'Popen')]:
        monkeypatch.setattr(module, name, forbidden)
    assert main(['cadence-scope']) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['synthetic_only'] and report['identical_detector_inputs'] and report['all_match']
    assert report['unsupported_scope_matches'] == report['unexpected_results'] == 0
    assert not report['network_access_performed']
    assert report['action_status'] == report['persistence_status'] == 'not_attempted'
    first, second = report['cases']
    assert first['case'] == 'scheduled_health_checks' and second['case'] == 'suspicious_cadence_only'
    assert first['contexts'] == second['contexts']
    contexts = first['contexts']
    unknowns = {'missing_scope', 'missing_owner', 'partial_owner', 'expired', 'expires_at_last_start',
                'wrong_execution', 'pid_only', 'contradictory_owner', 'contradictory_scope',
                'self_reported_owner', 'self_reported_scope'}
    assert set(contexts) == unknowns | {'valid', 'different_permitted_destination'}
    assert all(contexts[name]['status'] == 'unknown' and contexts[name]['reason'] for name in unknowns)
    assert contexts['valid']['status'] == 'scope_match'
    assert contexts['valid']['outside_scope_starts'] == []
    mismatch = contexts['different_permitted_destination']
    assert mismatch['status'] == 'scope_mismatch'
    assert mismatch['permitted_destination']['address'] == '198.51.100.201'
    assert mismatch['outside_scope_starts'] == [item['time'] for item in first['observed_starts']]
    assert {item['address'] for item in first['observed_starts']} == {'198.51.100.200'}

    corpus, _ = load_corpus()
    for item in report['cases']:
        case = next(case for case in corpus['cases'] if case['id'] == item['case'])
        rows, _ = observations(case, corpus['start'])
        original = analyze_hour(rows, corpus['start'], corpus['start'] + 3600, [])[1]
        assert [item['original_finding']] == original
        assert original[0]['state'] == 'unreviewed' and original[0]['action_status'] == 'not_attempted'
        assert len(original[0]['evidence_refs']) == 5 and item['layered_reviews'] == 0


def test_replay_ignores_labels_and_is_stable_under_reordering(monkeypatch):
    before = replay.cadence_scope_report()
    contexts = replay._contexts()
    make_rows = replay.observations
    corpus, _ = replay.load_corpus()
    monkeypatch.setattr(replay, 'load_corpus', lambda: (corpus, object()))
    monkeypatch.setattr(replay, 'observations',
                        lambda case, start: (make_rows(case, start)[0][::-1], {}))
    monkeypatch.setattr(replay, '_contexts', lambda: [
        (name, owners[::-1], scopes[::-1], expected)
        for name, owners, scopes, expected in contexts[::-1]])
    assert replay.cadence_scope_report() == before


@pytest.mark.parametrize('substitution', [
    {'time': '2026-10-01T00:05:00.000001Z'}, {'vantage': 'another-sensor'},
    {'interface': 'fixture1'}, {'local_address': '192.0.2.2'}, {'local_port': 40001},
    {'remote': replay.Endpoint('198.51.100.201', 443, 'TCP')},
    {'remote': replay.Endpoint('198.51.100.200', 444, 'TCP')},
    {'remote': replay.Endpoint('198.51.100.200', 443, 'UDP')},
])
def test_one_nearby_socket_cannot_cover_a_missing_start(substitution):
    _, owners, scopes, _ = replay._contexts()[0]
    starts = [owner.connection for owner in owners]
    changed = replace(owners[0], connection=replace(starts[0], **substitution))
    assert replay._compare(starts, (changed,) + owners[1:], scopes)['status'] == 'unknown'


@pytest.mark.parametrize('change', [{'port': 444}, {'protocol': 'UDP'}])
def test_scope_compares_the_entire_endpoint(change):
    _, owners, (scope,), _ = replay._contexts()[0]
    changed = replace(scope, remote=replace(scope.remote, **change))
    outcome = replay._compare([owner.connection for owner in owners], owners, (changed,))
    assert outcome['status'] == 'scope_mismatch' and len(outcome['outside_scope_starts']) == 5


def test_multiple_failures_report_the_same_missing_evidence_in_either_order():
    _, owners, scopes, _ = replay._contexts()[0]
    starts = [owner.connection for owner in owners]
    incomplete = (replace(owners[0], producer='fixture-subject'),) + owners[1:-1]
    result = replay._compare(starts, incomplete, scopes)
    assert result == {'status': 'unknown', 'reason': 'independent_socket_owner_required'}
    assert replay._compare(starts[::-1], incomplete[::-1], scopes) == result


def test_collapsed_or_missing_support_does_not_qualify():
    report = replay.cadence_scope_report()
    finding = deepcopy(report['cases'][0]['original_finding'])
    corpus, _ = load_corpus()
    case = next(case for case in corpus['cases'] if case['id'] == report['cases'][0]['case'])
    rows, _ = observations(case, corpus['start'])
    finding['evidence_refs'][-1] = finding['evidence_refs'][0]
    with pytest.raises(replay.ReferenceDataError, match='CADENCE_SCOPE_FIXTURE_SUPPORT'):
        replay._support(rows, finding)


def test_cli_fails_regression_and_rejects_external_input(monkeypatch, capsys):
    contexts = replay._contexts()
    name, owners, scopes, _ = contexts[0]
    monkeypatch.setattr(replay, '_contexts', lambda: ((name, owners, scopes, 'unknown'),))
    assert main(['cadence-scope']) == 1
    assert json.loads(capsys.readouterr().out)['unsupported_scope_matches'] == 2
    with pytest.raises(SystemExit) as denied:
        main(['cadence-scope', '--input', '/untrusted'])
    assert denied.value.code == 2
    assert '/untrusted' not in capsys.readouterr().err
