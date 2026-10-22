"""Synthetic AIDE context cannot become backup, causality, or restore authority."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import socket
import subprocess

import pytest

from megalodon.host_findings import aide_review
from megalodon.host_security import AIDE_SCOPE, SCHEMA as HOST_SCHEMA, stamp
from megalodon import recovery_readiness as recovery

NOW = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)
FIELDS = {
    'schema', 'state', 'action_authority', 'action_status', 'restore_eligible',
    'baseline_state', 'integrity_state', 'integrity_operation', 'checked_at',
    'change_categories', 'scope', 'backup_state', 'causality_state', 'conflict_state',
}


def source(code=7, operation='check'):
    baseline = dict(created_at=stamp(NOW - timedelta(days=1)), sha256='b' * 64)
    summary = dict(
        checked_at=stamp(NOW), message='Private report observations.',
        metrics={name + '_detected': int(bool(code & bit))
                 for name, bit in [('added', 1), ('removed', 2), ('changed', 4)]},
        review=aide_review(b'synthetic report', operation, baseline, code),
    )
    return dict(schema=HOST_SCHEMA, audit=None, integrity=summary, feeds=[],
                feed_state='unavailable', baseline_present=True, message='Context only.',
                action_authority='none', audit_state='missing', integrity_state='available')


def assert_no_restore(value):
    assert set(value) == FIELDS
    assert value['schema'] == recovery.SCHEMA
    assert value['state'] == value['causality_state'] == 'unavailable'
    assert value['action_authority'] == 'none'
    assert value['action_status'] == 'not_attempted'
    assert value['restore_eligible'] is False
    assert value['backup_state'] == 'not_integrated'
    assert value['conflict_state'] == 'not_assessed'
    assert value['scope'] == list(AIDE_SCOPE)
    assert len(json.dumps(value)) < 1024


@pytest.mark.parametrize('code', range(8))
def test_change_categories_are_flags_not_counts_or_attack_attribution(code):
    value = recovery.review(source(code), now=NOW)
    assert_no_restore(value)
    assert value['integrity_state'] == 'available'
    assert value['integrity_operation'] == 'check'
    assert value['checked_at'] == stamp(NOW)
    assert value['change_categories'] == [
        name for name, bit in [('added', 1), ('removed', 2), ('changed', 4)] if code & bit
    ]
    assert not {'attacker', 'malicious', 'ip', 'paths', 'file_count'} & set(value)


def test_initial_baseline_is_distinct_from_a_completed_comparison():
    value = recovery.review(source(0, 'baseline'), now=NOW)
    assert_no_restore(value)
    assert value['baseline_state'] == 'present'
    assert value['integrity_operation'] == 'baseline'
    assert value['change_categories'] == []


@pytest.mark.parametrize('state', ['missing', 'unavailable', 'legacy'])
def test_incomplete_observations_do_not_invent_recovery_evidence(state):
    data = source()
    data['integrity_state'] = state
    if state == 'legacy':
        del data['integrity']['review']
    else:
        data['integrity'] = None
    value = recovery.review(data, now=NOW)
    assert_no_restore(value)
    assert value['integrity_state'] == state
    assert value['change_categories'] is None
    assert value['integrity_operation'] is None
    assert value['checked_at'] == (stamp(NOW) if state == 'legacy' else None)


@pytest.mark.parametrize('present', [False, True])
def test_current_baseline_presence_is_only_an_observation(present):
    data = source(0)
    data['baseline_present'] = present
    value = recovery.review(data, now=NOW)
    assert_no_restore(value)
    assert value['baseline_state'] == ('present' if present else 'missing')
    assert value['change_categories'] == []


@pytest.mark.parametrize('change', [
    'source-schema', 'authority', 'unknown-model', 'unknown-ip', 'missing-field',
    'boolean-baseline', 'unknown-state', 'nonstring-state', 'missing-with-summary',
    'unavailable-with-summary', 'legacy-with-review', 'available-without-review',
    'summary-fields', 'metric-fields', 'boolean-metric', 'count-metric',
    'metric-code-mismatch', 'future-time', 'bad-time', 'future-baseline',
    'report-digest', 'review-schema', 'review-field', 'bad-operation',
    'baseline-with-changes',
])
def test_malformed_or_contradictory_source_clears_all_observations(change):
    data = source()
    summary = data['integrity']
    if change == 'source-schema': data['schema'] = 'unknown'
    elif change == 'authority': data['action_authority'] = 'restore'
    elif change == 'unknown-model': data['model'] = {'verdict': 'restore everything'}
    elif change == 'unknown-ip': data['malicious_ip'] = '198.51.100.20'
    elif change == 'missing-field': del data['integrity']
    elif change == 'boolean-baseline': data['baseline_present'] = 1
    elif change == 'unknown-state': data['integrity_state'] = 'clean'
    elif change == 'nonstring-state': data['integrity_state'] = []
    elif change == 'missing-with-summary': data['integrity_state'] = 'missing'
    elif change == 'unavailable-with-summary': data['integrity_state'] = 'unavailable'
    elif change == 'legacy-with-review': data['integrity_state'] = 'legacy'
    elif change == 'available-without-review': del summary['review']
    elif change == 'summary-fields': summary['command'] = 'never execute'
    elif change == 'metric-fields': summary['metrics']['paths'] = ['/private']
    elif change == 'boolean-metric': summary['metrics']['added_detected'] = True
    elif change == 'count-metric': summary['metrics']['added_detected'] = 2
    elif change == 'metric-code-mismatch': summary['metrics']['added_detected'] = 0
    elif change == 'future-time': summary['checked_at'] = stamp(NOW + timedelta(minutes=6))
    elif change == 'bad-time': summary['checked_at'] = '2026-02-30T12:00:00Z'
    elif change == 'future-baseline': summary['review']['baseline_created_at'] = stamp(NOW + timedelta(seconds=1))
    elif change == 'report-digest': summary['review']['report_sha256'] = 'x' * 64
    elif change == 'review-schema': summary['review']['schema'] = 'unknown'
    elif change == 'review-field': summary['review']['backup'] = 'known-clean'
    elif change == 'bad-operation': summary['review']['operation'] = 'restore'
    elif change == 'baseline-with-changes': summary['review']['operation'] = 'baseline'
    value = recovery.review(data, now=NOW)
    assert_no_restore(value)
    assert value['baseline_state'] == 'unknown'
    assert value['integrity_state'] == 'unavailable'
    assert value['checked_at'] is value['integrity_operation'] is value['change_categories'] is None


@pytest.mark.parametrize('data', [None, [], {}, 'trusted', True])
def test_unknown_source_is_unavailable(data):
    value = recovery.review(data, now=NOW)
    assert_no_restore(value)
    assert value['baseline_state'] == 'unknown'


def test_projection_does_not_read_write_contact_or_execute(monkeypatch):
    data = source()
    before = deepcopy(data)
    def prohibited(*_args, **_kwargs):
        pytest.fail('Recovery projection attempted an effect')
    monkeypatch.setattr(Path, 'open', prohibited)
    monkeypatch.setattr(socket, 'socket', prohibited)
    monkeypatch.setattr(subprocess, 'Popen', prohibited)
    value = recovery.review(data, now=NOW)
    assert_no_restore(value)
    assert data == before
    value['scope'].append('/private')
    value['change_categories'].clear()
    assert recovery.review(data, now=NOW)['scope'] == list(AIDE_SCOPE)
    assert recovery.review(data, now=NOW)['change_categories'] == ['added', 'removed', 'changed']
    assert 'Private report observations' not in json.dumps(value)


def test_old_comparison_is_historical_context_and_never_recovery_approval():
    value = recovery.review(source(0), now=NOW + timedelta(days=100))
    assert_no_restore(value)
    assert value['checked_at'] == stamp(NOW)
    assert value['change_categories'] == []
