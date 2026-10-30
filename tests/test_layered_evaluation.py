"""Synthetic evaluation is an honest workload/provenance test, not accuracy proof."""
from copy import deepcopy
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys

import pytest

from megalodon import layered_evaluation as evaluation
from megalodon.evaluation import main
from megalodon.reference import ReferenceDataError
from megalodon.security_patterns import analyze_hour, MAX_GROUP_RECORDS

COMMIT = '1' * 40
TREE = '2' * 40


def report(**kwargs):
    return evaluation.evaluate_layered(source_commit=COMMIT, source_tree=TREE, **kwargs)


def scenario(name):
    corpus, _ = evaluation.load_corpus()
    case = next(case for case in corpus['cases'] if case['id'] == name)
    rows, oracle = evaluation.observations(case, corpus['start'])
    return corpus['start'], case, rows, oracle


def test_declared_intent_is_separate_from_prediction_and_unknowns_are_excluded():
    value = report()
    assert value['denominators'] == dict(total=25, ordinary=10, useful=10, indeterminate_excluded=5)
    assert {key: value['synthetic_workload'][key] for key in ('tp', 'fp', 'fn', 'tn')} == dict(tp=7, fp=4, fn=3, tn=6)
    assert value['totals'] == dict(candidates=38, layered_reviews=12, checked_references=796,
                                  evidence_errors=0, unstable_permutations=0)
    assert value['all_match'] is True  # This does not mean perfect classification.
    assert value['operational_accuracy'] is value['operational_false_positive_rate'] is None
    cases = {row['case']: row for row in value['cases']}
    assert cases['authorized_discovery_and_schedule']['result_sha256'] == cases['suspicious_sweep_and_callback']['result_sha256']
    assert cases['scheduled_dns_connections']['result_sha256'] == cases['suspicious_dns_and_callback']['result_sha256']
    assert cases['dns_bin_boundary_miss']['layered_reviews'] == 0
    assert cases['dns_bin_boundary_control']['layered_reviews'] == 1


def test_swapping_truth_labels_cannot_change_analyzer_output(monkeypatch):
    original = report()
    corpus, labels = evaluation.load_corpus()
    for value in labels['labels'].values():
        value['label'] = {'ordinary': 'useful', 'useful': 'ordinary', 'indeterminate': 'indeterminate'}[value['label']]
    monkeypatch.setattr(evaluation, 'load_corpus', lambda: (corpus, labels))
    changed = report()
    assert [c['result_sha256'] for c in original['cases']] == [c['result_sha256'] for c in changed['cases']]
    assert changed['synthetic_workload']['tp'] == original['synthetic_workload']['fp']


@pytest.mark.parametrize('name', ['authorized_discovery', 'scheduled_dns_connections', 'overlapping_cadence_starts'])
def test_retained_evidence_selection_is_stable_under_permutation(name):
    start, _, rows, _ = scenario(name)
    expected = analyze_hour(rows, start, start + 3600, [])[1]
    for ordered in (list(reversed(rows)), rows[1:] + rows[:1]):
        assert analyze_hour(ordered, start, start + 3600, [])[1] == expected


def test_fanout_depends_only_on_qualifying_support_not_unrelated_segments():
    start, _, rows, _ = scenario('late_fanout_with_noise')
    candidate = next(c for c in analyze_hour(rows, start, start + 3600, [])[1] if c['rule'] == 'HOST_FANOUT')
    assert candidate['source_segments'] == [f'{1:032x}']
    assert len(candidate['evidence_refs']) == 16
    assert all(ref.startswith(f'{1:032x}:') for ref in candidate['evidence_refs'])


@pytest.mark.parametrize('mutation,error', [
    ('missing', 'unresolved_reference'), ('unrelated', 'unsupported_reference'),
    ('dependency', 'incorrect_dependency_set'), ('action', 'action_authority_changed'),
    ('union', 'incorrect_layered_reference_union'),
])
def test_oracle_detects_corrupted_evidence_without_reading_predictions_as_truth(mutation, error):
    start, case, rows, oracle = scenario('late_fanout_with_noise')
    result = evaluation._run(rows, start, [])
    candidate = result['individual'][0]
    if mutation == 'missing':
        candidate['evidence_refs'][0] = 'f' * 32 + ':999'
    elif mutation == 'unrelated':
        candidate['evidence_refs'][0] = rows[0]['id']
    elif mutation == 'dependency':
        candidate['source_segments'].append('f' * 32)
    elif mutation == 'action':
        candidate['action_status'] = 'applied'
    else:
        result['layered'][0]['evidence_refs'].pop()
    assert evaluation.evidence_errors(result, oracle, start)['errors'][error] >= 1


def test_reference_omissions_preserve_full_support_dependencies():
    start, _, rows, oracle = scenario('reference_page_omissions')
    result = evaluation._run(rows, start, [])
    assert evaluation.evidence_errors(result, oracle, start)['errors'] == {}
    for candidate in result['individual']:
        assert candidate['facts']['references_omitted'] == 6
        assert len(candidate['evidence_refs']) == 24


@pytest.mark.parametrize('name,rule', [('authorized_discovery', 'HOST_FANOUT'),
                                    ('scheduled_health_checks', 'REGULAR_INTERVAL'),
                                    ('reference_page_omissions', 'PORT_53_BURST')])
def test_repeated_valid_reference_cannot_replace_distinct_support(name, rule):
    start, _, rows, oracle = scenario(name)
    result = evaluation._run(rows, start, [])
    candidate = next(c for c in result['individual'] if c['rule'] == rule)
    candidate['evidence_refs'] = [candidate['evidence_refs'][0]] * len(candidate['evidence_refs'])
    errors = evaluation.evidence_errors(result, oracle, start)['errors']
    assert errors['duplicate_reference'] == 1
    assert errors['incorrect_distinct_support'] == 1


def test_distinct_same_time_flows_cannot_replace_distinct_cadence_times():
    start, _, rows, oracle = scenario('overlapping_cadence_starts')
    result = evaluation._run(rows, start, [])
    candidate = next(c for c in result['individual'] if c['rule'] == 'REGULAR_INTERVAL')
    # All five references resolve and support cadence, but the first two now
    # represent the same start time, leaving the last distinct time unproved.
    candidate['evidence_refs'][-1] = next(ref for ref, entry in oracle.items()
        if entry['row']['data']['first_seen'] == rows[16]['data']['first_seen']
        and ref not in candidate['evidence_refs'])
    errors = evaluation.evidence_errors(result, oracle, start)['errors']
    assert errors['incorrect_distinct_support'] == 1


def test_layered_reference_union_rejects_duplicate_entries():
    start, _, rows, oracle = scenario('suspicious_sweep_and_callback')
    result = evaluation._run(rows, start, [])
    review = result['layered'][0]
    review['evidence_refs'].append(review['evidence_refs'][0])
    assert evaluation.evidence_errors(result, oracle, start)['errors']['duplicate_layered_reference'] == 1


def test_group_capacity_abstention_and_no_extra_authority_remain():
    start, _, rows, _ = scenario('scheduled_dns_connections')
    values = []
    for index in range(MAX_GROUP_RECORDS + 1):
        row = deepcopy(rows[0]); row['id'] = f'{1:032x}:{index + 1}'
        row['data']['source_id'] = f'synthetic-{index}'
        values.append(row)
    assert analyze_hour(values, start, start + 3600, [])[1] == []


def test_report_determinism_and_cost_separation():
    first = report()
    second = report(benchmark=True)
    assert first['deterministic_sha256'] == second['deterministic_sha256']
    assert first == {key: value for key, value in second.items() if key != 'cost'}
    assert second['cost']['calls'] == 75
    assert 0 < second['cost']['wall_ns']['min'] <= second['cost']['wall_ns']['max']
    assert second['cost']['max_traced_python_bytes'] > 0


def test_evaluation_runs_without_network_subprocess_database_or_host_action(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('external side effect attempted')
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(sqlite3, 'connect', forbidden)
    value = report()
    assert value['all_match'] and value['network_access_performed'] is False
    assert value['persistence_status'] == value['action_status'] == 'not_attempted'


@pytest.mark.parametrize('kwargs', [dict(repeats=1), dict(repeats=11), dict(repeats=True),
                                 dict(benchmark=1), dict(source_commit='bad'), dict(source_tree=None)])
def test_invalid_report_arguments_refused(kwargs):
    args = dict(source_commit=COMMIT, source_tree=TREE)
    args.update(kwargs)
    with pytest.raises(ReferenceDataError):
        evaluation.evaluate_layered(**args)


def test_fixture_and_label_integrity_fail_closed(monkeypatch):
    monkeypatch.setattr(evaluation, 'LABELS_SHA256', '0' * 64)
    with pytest.raises(ReferenceDataError, match='LAYERED_CORPUS_INTEGRITY'):
        report()


def test_cli_json_and_negative_exit_for_evidence_failure(capsys, monkeypatch):
    args = ['layered-report', '--source-commit', COMMIT, '--source-tree', TREE]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)['all_match']
    original = evaluation.evidence_errors
    def broken(*args):
        result = original(*args); result['errors']['synthetic_failure'] = 1
        return result
    monkeypatch.setattr(evaluation, 'evidence_errors', broken)
    assert main(args) == 1
    assert not json.loads(capsys.readouterr().out)['all_match']


@pytest.mark.parametrize('extra', [['--repeats', '0'], ['--repeats', '99999999999'],
                                 ['--repeats', '2', '--repeats', '3'], ['--input', '/etc/passwd']])
def test_cli_refuses_unknown_inputs_and_unbounded_work(extra, capsys):
    with pytest.raises(SystemExit) as failure:
        main(['layered-report', '--source-commit', COMMIT, '--source-tree', TREE, *extra])
    assert failure.value.code == 2
    assert json.loads(capsys.readouterr().err)['error'] == 'INVALID_ARGUMENTS'


def test_same_result_in_fresh_interpreters_and_hash_seeds():
    import os
    command = [sys.executable, '-m', 'megalodon.evaluation', 'layered-report',
               '--source-commit', COMMIT, '--source-tree', TREE]
    outputs = []
    for seed in ('1', '42'):
        result = subprocess.run(command, cwd=Path(__file__).resolve().parents[1],
                                env=dict(os.environ, PYTHONHASHSEED=seed), capture_output=True,
                                text=True, timeout=30, check=True)
        outputs.append(result.stdout)
    assert outputs[0] == outputs[1]
