"""Synthetic host observations remain bounded, private context, never incidents."""
from contextlib import nullcontext
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from megalodon import host_security as hs
from megalodon.host_findings import MAX_ITEMS, aide_review, lynis_review, validate_summary

NOW = datetime(2026, 10, 17, 12, tzinfo=timezone.utc)
STAMP = hs.stamp(NOW)
HEADER = b'report_version_major=1\nreport_version_minor=0\n'
REPORT = HEADER + (b'hostname=private-host-not-displayed\n'
          b'suggestion[]=AUTH-9262|Review password policy|private-detail|text:never run me|\n'
          b'warning[]=SSH-7408|Review SSH configuration|private-detail|url:https://invalid.test|\n')


def summary(raw=REPORT):
    metrics, review = lynis_review(raw)
    return dict(checked_at=STAMP, message='Unprivileged audit completed.', metrics=metrics, review=review)


@pytest.fixture
def memory(monkeypatch):
    """I/O seam, not a filesystem-admission test. Production guards stay intact."""
    files = {'audit.json': summary(), 'lynis-report.dat': REPORT}
    manager = hs.HostSecurity(now=lambda: NOW, runner=lambda *_: pytest.fail('GET launched a tool'),
                              downloader=lambda *_: pytest.fail('GET contacted a publisher'))
    monkeypatch.setattr(manager, '_json', lambda name, *args: deepcopy(files.get(name)))
    monkeypatch.setattr(hs, 'read', lambda path, *args: files[path.name])
    return manager, files


def test_lynis_preserves_rule_evidence_but_not_details_or_remediation():
    value = summary()
    validate_summary('audit', value, NOW)
    assert value['metrics'] == dict(warnings=1, suggestions=1)
    assert [(row['rule'], row['line']) for row in value['review']['items']] == [('SSH-7408', 5), ('AUTH-9262', 4)]
    assert value['review']['report_sha256'] == hashlib.sha256(REPORT).hexdigest()
    assert not any(word in json.dumps(value) for word in ('private-detail', 'never run me', 'invalid.test', 'private-host'))


@pytest.mark.parametrize('raw', [b'garbage', b'', b'report_version_major=2\nreport_version_minor=0\n',
                               HEADER + b'report_version_major=1\n'])
def test_unknown_empty_and_duplicated_report_version_refuse(raw):
    with pytest.raises(ValueError): lynis_review(raw)


def test_zero_lynis_observations_still_require_a_known_report():
    metrics, review = lynis_review(HEADER)
    assert metrics == dict(warnings=0, suggestions=0) and review['items'] == []


@pytest.mark.parametrize('code', [True, -1, 8])
def test_invalid_aide_exit_status_is_not_a_finding(code):
    value = dict(checked_at=STAMP, message='Comparison', metrics=dict(added_detected=0, removed_detected=0, changed_detected=0),
                 review=aide_review(b'report', 'check', dict(created_at=STAMP, sha256='b'*64), code))
    with pytest.raises(ValueError): validate_summary('integrity', value, NOW)


def test_bounded_warning_first_view_retains_counts_and_omission():
    raw = HEADER + b'suggestion[]=AUTH-1|Suggestion|-|-|\n' * 20 + b'warning[]=SSH-1|Warning|-|-|\n' * 20
    metrics, review = lynis_review(raw)
    assert metrics == dict(warnings=20, suggestions=20)
    assert len(review['items']) == MAX_ITEMS and review['omitted'] == 40 - MAX_ITEMS
    assert {item['kind'] for item in review['items']} == {'configuration_warning'}
    validate_summary('audit', summary(raw), NOW)


@pytest.mark.parametrize('raw', [
    b'warning[]=SSH-1|bad\x00text|-|-|\n', b'warning[]=SSH-1|bad\rtext|-|-|\n',
    b'warning[]=SSH-1|bad\x1btext|-|-|\n', b'warning[]=SSH-1|bad\vtext|-|-|\n',
    b'warning[]=SSH-1|bad\xfftext|-|-|\n', b'warning[]=lowercase|text|-|-|\n',
    b'warning[]=SSH-1||-|-|\n', b'warning[]=SSH-1|unrecognized shape\n',
    b'warning[]=SSH-1|' + b'x' * 241 + b'|-|-|\n',
    b'warning[]=SSH-1|text|' + b'x' * 4096 + b'|-|\n',
    'warning[]=SSH-1|hidden\u202etext|-|-|\n'.encode(),
    b'warning[]=SSH-1|text|-|-|\n' * 10001,
])
def test_rejects_malformed_unbounded_and_control_text(raw):
    with pytest.raises(ValueError):
        lynis_review(raw)


def test_snapshot_is_read_only_and_keeps_observations_out_of_alerts(memory, monkeypatch):
    manager, files = memory
    before = deepcopy(files)
    import socket
    import subprocess
    monkeypatch.setattr(socket, 'socket', lambda *_a, **_k: pytest.fail('socket opened'))
    monkeypatch.setattr(subprocess, 'Popen', lambda *_a, **_k: pytest.fail('program launched'))
    monkeypatch.setattr(manager, '_save', lambda *_: pytest.fail('GET wrote data'))
    value = manager.snapshot()
    assert value['audit_state'] == 'available'
    assert value['integrity_state'] == 'missing'
    assert value['audit'] == summary()
    assert value['action_authority'] == 'none'
    assert not {'detections', 'alerts', 'incidents', 'commands'} & set(value)
    assert files == before


@pytest.mark.parametrize('change', ['report', 'items', 'metrics', 'missing-report'])
def test_report_replacement_or_contradictory_projection_fails_closed(memory, change):
    manager, files = memory
    if change == 'report': files['lynis-report.dat'] += b'changed\n'
    elif change == 'items': files['audit.json']['review']['items'][0]['text'] = 'Invented observation'
    elif change == 'metrics': files['audit.json']['metrics']['warnings'] += 1
    else: del files['lynis-report.dat']
    value = manager.snapshot()
    assert value['audit_state'] == 'unavailable' and value['audit'] is None


@pytest.mark.parametrize('change', ['future', 'boolean', 'unknown-field', 'bad-kind', 'bad-time', 'bad-hash', 'bad-line', 'duplicate-line', 'too-many'])
def test_invalid_saved_summary_is_unavailable(memory, change):
    manager, files = memory
    value = files['audit.json']
    if change == 'future': value['checked_at'] = hs.stamp(NOW + timedelta(minutes=6))
    elif change == 'boolean': value['metrics']['warnings'] = True
    elif change == 'unknown-field': value['command'] = 'never execute'
    elif change == 'bad-kind': value['review']['items'][0]['kind'] = 'verified_incident'
    elif change == 'bad-time': value['checked_at'] = '2026-02-30T12:00:00Z'
    elif change == 'bad-hash': value['review']['report_sha256'] = 'x' * 64
    elif change == 'bad-line': value['review']['items'][0]['line'] = False
    elif change == 'duplicate-line': value['review']['items'][1]['line'] = value['review']['items'][0]['line']
    else: value['metrics']['warnings'] = 10001
    assert manager.snapshot()['audit_state'] == 'unavailable'


def test_legacy_and_missing_are_not_clean_checks(memory):
    manager, files = memory
    del files['audit.json']['review']
    value = manager.snapshot()
    assert value['audit_state'] == 'legacy' and 'review' not in value['audit']
    del files['audit.json']
    assert manager.snapshot()['audit_state'] == 'missing'


@pytest.mark.parametrize('code', range(8))
def test_aide_change_categories_are_flags_with_baseline_identity(memory, code):
    manager, files = memory
    baseline = dict(created_at=hs.stamp(NOW-timedelta(days=2)), sha256='a'*64)
    raw = b'private AIDE aggregate report'
    files['aide-report.txt'] = raw
    files['integrity.json'] = dict(checked_at=STAMP, message='AIDE comparison completed.',
        metrics=dict(added_detected=int(bool(code&1)), removed_detected=int(bool(code&2)), changed_detected=int(bool(code&4))),
        review=aide_review(raw, 'check', baseline, code))
    value = manager.snapshot()
    assert value['integrity_state'] == 'available'
    assert value['integrity']['review']['baseline_sha256'] == 'a'*64
    assert value['integrity']['review']['operation'] == 'check'
    assert 'private AIDE' not in json.dumps(value)


def test_aide_initial_baseline_is_not_a_comparison(memory):
    manager, files = memory
    files['aide-report.txt'] = b'baseline created'
    files['integrity.json'] = dict(checked_at=STAMP, message='Baseline observed, not known clean.',
        metrics=dict(added_detected=0, removed_detected=0, changed_detected=0),
        review=aide_review(files['aide-report.txt'], 'baseline', dict(created_at=STAMP, sha256='b'*64), 0))
    assert manager.snapshot()['integrity_state'] == 'available'
    files['integrity.json']['metrics']['changed_detected'] = 1
    assert manager.snapshot()['integrity_state'] == 'unavailable'


def test_bad_feed_does_not_erase_valid_audit_observations(memory):
    manager, files = memory
    files['feeds.json'] = {'schema': 'wrong'}
    result = manager.snapshot()
    assert result['feed_state'] == 'unavailable' and result['audit_state'] == 'available'


def test_workflow_rows_distinguish_invalid_evidence_from_missing_setup(memory):
    from megalodon.support_workflows import snapshot
    manager, files = memory
    config = SimpleNamespace(host_security=manager, capture=SimpleNamespace(snapshot=lambda:dict(accepted=0, state='idle', message='Idle', started_at=None, skipped=0)),
        sensors=SimpleNamespace(snapshot=lambda:{key:dict(state='stopped', message='Stopped', updated_at=None) for key in ('zeek','suricata')}),
        qwen_status=dict(state='needs_setup', message='Not configured', updated_at=None))
    rows = {r['id']:r for r in snapshot(config, None)['tools']}
    assert rows['lynis']['state'] == 'connected'
    assert rows['lynis']['metrics'][0]['label'] == 'Configuration warnings'
    files['lynis-report.dat'] = b'changed'
    rows = {r['id']:r for r in snapshot(config, None)['tools']}
    assert rows['lynis']['state'] == 'error' and not rows['lynis']['metrics']
    assert rows['aide']['state'] == 'needs_setup'


def test_execute_audit_publishes_evidence_before_summary_and_preserves_prior_on_parser_refusal(tmp_path, monkeypatch):
    """Fake executable/report only; exercise the actual execution adapter."""
    manager = hs.HostSecurity(now=lambda: NOW)
    manager.root = tmp_path
    monkeypatch.setattr(manager, 'locked', nullcontext)
    real_file, real_stat = Path.is_file, Path.stat
    monkeypatch.setattr(Path, 'is_file', lambda p: True if str(p)=='/usr/sbin/lynis' else real_file(p))
    monkeypatch.setattr(Path, 'stat', lambda p, *a, **k: SimpleNamespace(st_uid=0, st_mode=0o100755) if str(p)=='/usr/sbin/lynis' else real_stat(p, *a, **k))
    files, writes = {}, []
    def write(path, body): files[path.name] = body; writes.append(path.name)
    monkeypatch.setattr(hs, 'write', write)
    monkeypatch.setattr(manager, '_save', lambda name, value: write(tmp_path/name, deepcopy(value)))
    def run(argv, workspace):
        assert argv[:3] == ['/usr/sbin/lynis', 'audit', 'system']
        assert '--no-plugins' in argv
        (workspace/'lynis.dat').write_bytes(REPORT)
        return b'', 0
    manager.runner = run
    manager.execute('audit')
    assert writes == ['lynis-report.dat', 'audit.json']
    validate_summary('audit', files['audit.json'], NOW)
    before = deepcopy(files)
    def malformed(argv, workspace):
        (workspace/'lynis.dat').write_bytes(b'warning[]=not supported\n')
        return b'', 0
    manager.runner = malformed
    with pytest.raises(ValueError, match='format'): manager.execute('audit')
    assert files == before


def test_execute_aide_check_keeps_paths_in_private_report_without_updating_baseline(tmp_path, monkeypatch):
    manager = hs.HostSecurity(now=lambda: NOW)
    manager.root = tmp_path
    monkeypatch.setattr(manager, 'locked', nullcontext)
    real_file, real_stat = Path.is_file, Path.stat
    monkeypatch.setattr(Path, 'is_file', lambda p: True if str(p)=='/usr/sbin/aide' else real_file(p))
    monkeypatch.setattr(Path, 'stat', lambda p, *a, **k: SimpleNamespace(st_uid=0, st_mode=0o100755) if str(p)=='/usr/sbin/aide' else real_stat(p, *a, **k))
    body = b'initial observed database'
    baseline = dict(created_at=hs.stamp(NOW-timedelta(days=1)), sha256=hashlib.sha256(body).hexdigest(), scope=list(hs.AIDE_SCOPE))
    monkeypatch.setattr(manager, '_baseline', lambda: deepcopy(baseline))
    files = {'aide.db.gz':body}
    monkeypatch.setattr(hs, 'read', lambda p: files[p.name])
    def write(path, content): files[path.name] = content
    monkeypatch.setattr(hs, 'write', write)
    monkeypatch.setattr(manager, '_save', lambda name, value: write(tmp_path/name, deepcopy(value)))
    def run(argv, workspace):
        assert argv[:2] == ['/usr/sbin/aide', '--check'] and len(argv) == 3
        config = (workspace/'aide.conf').read_text()
        assert config.index('report_level=list_entries') < config.index('report_url=stdout')
        assert all(scope in config for scope in hs.AIDE_SCOPE)
        assert '--update' not in argv
        return b'Added entries:\nf++++++++++++ /usr/bin/synthetic-example\n', 1
    manager.runner = run
    manager.execute('check')
    assert files['aide.db.gz'] == body
    assert 'baseline.json' not in files
    validate_summary('integrity', files['integrity.json'], NOW)
    assert files['integrity.json']['review']['exit_code'] == 1
    assert 'synthetic-example' not in json.dumps(files['integrity.json'])
