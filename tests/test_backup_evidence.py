"""Synthetic external evidence: admission is never permission to restore."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import socket
import subprocess

import pytest

from megalodon import backup_evidence as evidence, recovery_readiness
from megalodon.host_security import stamp

NOW = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)
FIXTURES = Path(__file__).parent / 'fixtures/host-backup-evidence'


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def records():
    return [json.loads((FIXTURES / name).read_bytes())
            for name in ('backup.json', 'restore-test.json', 'trust.json')]


def packet(backup, test, trust, *, pin=True):
    backup_raw, test_raw = encode(backup), encode(test)
    trust = deepcopy(trust)
    if pin:
        trust.update(backup_receipt_sha256=sha256(backup_raw).hexdigest(),
                     restore_test_receipt_sha256=sha256(test_raw).hexdigest())
    return backup_raw, test_raw, encode(trust)


def test_exact_fixture_bytes_match_out_of_band_pins():
    raw = [(FIXTURES / name).read_bytes() for name in ('backup.json', 'restore-test.json', 'trust.json')]
    result = evidence.review(*raw, now=NOW)
    assert result['state'] == 'verified_external_evidence'
    assert result['source_id'] == 'synthetic-host-A-system-files'
    assert result['expires_at'] == '2026-10-23T10:00:00Z'
    assert len(json.dumps(result)) < 2048
    assert result['conflicts'] == 'not_assessed'
    assert 'producer_id' not in result


@pytest.mark.parametrize('case,reason', [
    ('missing-backup-id', 'malformed'), ('unknown-field', 'malformed'),
    ('boolean-size', 'malformed'), ('zero-size', 'malformed'), ('big-size', 'malformed'),
    ('digest-format', 'malformed'), ('id-injection', 'malformed'),
    ('wrong-schema', 'malformed'), ('invalid-time', 'malformed'),
    ('wrong-source', 'conflicting'), ('wrong-backup', 'conflicting'),
    ('wrong-producer', 'conflicting'), ('wrong-verifier', 'conflicting'),
    ('wrong-artifact', 'conflicting'), ('wrong-snapshot', 'conflicting'),
    ('restore-content-mismatch', 'conflicting'), ('test-before-verification', 'conflicting'),
    ('approval-before-test', 'conflicting'), ('future-approval', 'conflicting'),
    ('self-verified', 'untrusted'), ('tampered-backup', 'untrusted'),
    ('tampered-test', 'untrusted'), ('bad-backup-pin', 'untrusted'),
    ('failed-test', 'incomplete'), ('partial-test', 'incomplete'),
    ('live-test', 'incomplete'), ('availability-unknown', 'incomplete'),
    ('conflicts-cleared', 'incomplete'), ('overlong-validity', 'malformed'),
    ('expired-backup', 'expired'), ('expired-test', 'expired'), ('expired-trust', 'expired'),
])
def test_invalid_external_evidence_clears_every_identity(case, reason):
    backup, test, trust = records()
    if case == 'missing-backup-id': del backup['backup_id']
    elif case == 'unknown-field': test['restore_command'] = 'never execute'
    elif case == 'boolean-size': backup['artifact_bytes'] = True
    elif case == 'zero-size': backup['artifact_bytes'] = 0
    elif case == 'big-size': backup['artifact_bytes'] = 2**53
    elif case == 'digest-format': backup['artifact_sha256'] = 'x' * 64
    elif case == 'id-injection': backup['backup_id'] = '<img src=x>'
    elif case == 'wrong-schema': trust['schema'] = 'future-v2'
    elif case == 'invalid-time': test['completed_at'] = '2026-02-30T12:00:00Z'
    elif case == 'wrong-source': test['source_id'] = 'another-host'
    elif case == 'wrong-backup': test['backup_id'] = 'another-backup'
    elif case == 'wrong-producer': trust['producer_id'] = 'another-producer'
    elif case == 'wrong-verifier': trust['verifier_id'] = 'another-verifier'
    elif case == 'wrong-artifact': test['artifact_sha256'] = 'd' * 64
    elif case == 'wrong-snapshot': test['source_snapshot_sha256'] = 'd' * 64
    elif case == 'restore-content-mismatch': test['restored_snapshot_sha256'] = 'd' * 64
    elif case == 'test-before-verification': test['started_at'] = '2026-10-22T09:00:00Z'
    elif case == 'approval-before-test': trust['approved_at'] = '2026-10-22T10:00:00Z'
    elif case == 'future-approval': trust['approved_at'] = stamp(NOW + timedelta(seconds=1))
    elif case == 'self-verified': test['verifier_id'] = trust['verifier_id'] = backup['producer_id']
    elif case == 'tampered-backup': backup['artifact_bytes'] += 1
    elif case == 'tampered-test': test['test_id'] = 'unreviewed-replacement'
    elif case == 'bad-backup-pin': trust['backup_receipt_sha256'] = 'e' * 64
    elif case == 'failed-test': test['result'] = 'failed'
    elif case == 'partial-test': test['coverage'] = 'one_file'
    elif case == 'live-test': test['environment'] = 'live_host'
    elif case == 'availability-unknown': backup['availability'] = 'unknown'
    elif case == 'conflicts-cleared': test['conflicts'] = 'none'
    elif case == 'overlong-validity': test['expires_at'] = stamp(NOW + timedelta(days=8))
    elif case.startswith('expired-'):
        {'expired-backup': backup, 'expired-test': test, 'expired-trust': trust}[case]['expires_at'] = stamp(NOW)
    result = evidence.review(*packet(backup, test, trust, pin=case not in {
        'tampered-backup', 'tampered-test', 'bad-backup-pin'}), now=NOW)
    assert result == evidence.unavailable(reason)


@pytest.mark.parametrize('position', range(3))
@pytest.mark.parametrize('raw,reason', [(None, 'missing'), (b'', 'malformed'),
    (b'{}', 'malformed'), (b'{"schema":1,"schema":2}', 'malformed'),
    (b'\xff', 'malformed'), (b'[' * 1100, 'malformed'), (b'x' * 16385, 'malformed'),
    ('not bytes', 'malformed')])
def test_missing_malformed_duplicate_or_excessive_input(position, raw, reason):
    values = list(packet(*records()))
    values[position] = raw
    assert evidence.review(*values, now=NOW) == evidence.unavailable(reason)


def test_expiry_is_exclusive_and_clock_reversal_is_refused():
    raw = packet(*records())
    assert evidence.review(*raw, now=NOW + timedelta(days=1)) == evidence.unavailable('expired')
    assert evidence.review(*raw, now=NOW - timedelta(hours=2)) == evidence.unavailable('conflicting')
    assert evidence.review(*raw, now=NOW.replace(tzinfo=None)) == evidence.unavailable('malformed')


def test_legitimate_changes_remain_a_conflict_and_no_integrity_or_ip_signal_authorizes_restore(monkeypatch):
    backup, test, trust = records()
    test['conflicts'] = 'reported_legitimate_changes'
    raw = packet(backup, test, trust)
    # The newer source content is legitimate work, not a reason to undo it.
    from test_recovery_readiness import source
    host = source(4)
    host['feeds'] = [{'source': 'synthetic-reputation-match'}]
    host['integrity']['message'] = 'Expected legitimate package update and user edits.'
    before = deepcopy(host)
    def prohibited(*_args, **_kwargs):
        pytest.fail('Pure evidence validation attempted an effect')
    monkeypatch.setattr(Path, 'open', prohibited)
    monkeypatch.setattr(os, 'open', prohibited)
    monkeypatch.setattr(socket, 'socket', prohibited)
    monkeypatch.setattr(subprocess, 'Popen', prohibited)
    result = evidence.review(*raw, now=NOW)
    readiness = recovery_readiness.review(host, now=NOW)
    assert result['state'] == 'verified_external_evidence'
    assert result['conflicts'] == 'reported_legitimate_changes'
    assert readiness['change_categories'] == ['changed']
    assert readiness['restore_eligible'] is False
    assert readiness['causality_state'] == 'unavailable'
    assert readiness['conflict_state'] == 'not_assessed'
    assert readiness['action_authority'] == 'none'
    assert host == before


def install_evidence(home):
    trust_path = home / '.config/megalodon/recovery-trust.json'
    root = home / '.local/share/megalodon/support/recovery-evidence'
    for path, raw in zip((root / 'backup.json', root / 'restore-test.json', trust_path), packet(*records())):
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o600)
    return root, trust_path


def test_fixed_private_reads_do_not_write_execute_or_contact(private_tmp_path, monkeypatch):
    root, trust_path = install_evidence(private_tmp_path)
    paths = [root / 'backup.json', root / 'restore-test.json', trust_path]
    before = [(p.read_bytes(), p.stat().st_mtime_ns) for p in paths]
    def prohibited(*_args, **_kwargs):
        pytest.fail('Saved evidence read attempted a mutation or execution')
    monkeypatch.setattr(Path, 'write_bytes', prohibited)
    monkeypatch.setattr(Path, 'mkdir', prohibited)
    monkeypatch.setattr(socket, 'socket', prohibited)
    monkeypatch.setattr(subprocess, 'Popen', prohibited)
    assert evidence.snapshot(private_tmp_path, now=NOW)['state'] == 'verified_external_evidence'
    assert [(p.read_bytes(), p.stat().st_mtime_ns) for p in paths] == before


@pytest.mark.parametrize('case', ['symlink', 'hardlink', 'fifo', 'directory', 'broad-file',
                                 'broad-parent', 'symlink-parent', 'oversized', 'missing'])
def test_unsafe_files_fail_closed_without_reusing_prior_success(private_tmp_path, case):
    root, trust = install_evidence(private_tmp_path)
    assert evidence.snapshot(private_tmp_path, now=NOW)['state'] == 'verified_external_evidence'
    path = root / 'backup.json'
    if case == 'symlink':
        path.unlink(); path.symlink_to(trust)
    elif case == 'hardlink': os.link(path, root / 'another-link')
    elif case == 'fifo': path.unlink(); os.mkfifo(path)
    elif case == 'directory': path.unlink(); path.mkdir()
    elif case == 'broad-file': path.chmod(0o644)
    elif case == 'broad-parent': root.chmod(0o755)
    elif case == 'symlink-parent':
        other = root.with_name('moved'); root.rename(other); root.symlink_to(other, target_is_directory=True)
    elif case == 'oversized': path.write_bytes(b'x' * (evidence.MAX_BYTES + 1))
    elif case == 'missing': path.unlink()
    result = evidence.snapshot(private_tmp_path, now=NOW)
    assert result == evidence.unavailable('missing' if case == 'missing' else 'unreadable')


def test_missing_files_never_create_directories(private_tmp_path):
    assert evidence.snapshot(private_tmp_path, now=NOW) == evidence.unavailable()
    assert list(private_tmp_path.iterdir()) == []


def test_changed_trust_is_refused(private_tmp_path, monkeypatch):
    install_evidence(private_tmp_path)
    original, calls = evidence._read, []
    def replaced(path):
        raw = original(path)
        calls.append(path.name)
        return raw + b' ' if len(calls) == 4 else raw
    monkeypatch.setattr(evidence, '_read', replaced)
    assert evidence.snapshot(private_tmp_path, now=NOW) == evidence.unavailable('untrusted')


@pytest.mark.parametrize('case', ['file-replacement', 'parent-replacement', 'in-place-write'])
def test_changes_during_read_are_refused(private_tmp_path, monkeypatch, case):
    root, trust = install_evidence(private_tmp_path)
    original, changed = os.read, []
    def raced(fd, size):
        raw = original(fd, size)
        if not changed:
            changed.append(True)
            if case == 'file-replacement':
                prior = trust.read_bytes()
                trust.rename(trust.with_name('old.json'))
                trust.write_bytes(prior); trust.chmod(0o600)
            elif case == 'parent-replacement':
                trust.parent.rename(trust.parent.with_name('old-parent'))
                trust.parent.mkdir(mode=0o700)
                trust.write_bytes(raw); trust.chmod(0o600)
            else:
                trust.write_bytes(raw + b' ')
        return raw
    monkeypatch.setattr(os, 'read', raced)
    assert evidence.snapshot(private_tmp_path, now=NOW) == evidence.unavailable('unreadable')


def test_unsupported_platform_is_honestly_unavailable(monkeypatch):
    monkeypatch.delattr(os, 'O_NOFOLLOW')
    assert evidence.snapshot('/does-not-exist', now=NOW) == evidence.unavailable('unreadable')
