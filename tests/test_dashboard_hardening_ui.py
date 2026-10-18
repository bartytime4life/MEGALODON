"""Shipped hardening panel exercised with a real synthetic review and an inert DOM."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon import hardening_review
from megalodon.dashboard_assets import INDEX_HTML
from megalodon.dashboard_hardening import HARDENING_JS
from megalodon.dashboard_support_config import SUPPORT_CONFIG_HTML, SUPPORT_CONFIG_JS


def synthetic_payload(tmp_path):
    for rel, value in {'kernel/randomize_va_space': '2', 'kernel/kptr_restrict': '0', 'net/ipv4/ip_forward': '1'}.items():
        path = tmp_path/'proc/sys'/rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value + '\n')
    (tmp_path/'proc/net').mkdir(parents=True)
    (tmp_path/'proc/net/tcp').write_text('  sl local rem st\n   0: 00000000:0016 00000000:0000 0A 0:0 0:0 0 0 0 1 1\n')
    return hardening_review.review(tmp_path, now=lambda: '2026-10-18T06:30:00Z')


def test_hardening_panel_renders_real_review_and_rejects_forged_payloads(tmp_path):
    if not shutil.which('node'):
        pytest.skip('Node unavailable')
    payload = synthetic_payload(tmp_path)
    assert {c['state'] for c in payload['checks']} >= {'fail', 'review', 'unknown', 'not_applicable'}
    result = subprocess.run([shutil.which('node'), str(Path(__file__).with_name('hardening_browser.cjs'))],
                            input=json.dumps(dict(code=HARDENING_JS, payload=payload)), text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_panel_is_wired_into_setup_without_an_action():
    assert 'id="hardening-review"' in SUPPORT_CONFIG_HTML
    assert "renderHardening(el('hardening-review'),v.hardening)" in SUPPORT_CONFIG_JS
    assert "renderHardening(el('hardening-review'),null)" in SUPPORT_CONFIG_JS
    assert 'innerHTML' not in HARDENING_JS and 'fetch(' not in HARDENING_JS
    assert 'hardening-review' not in INDEX_HTML or 'id="hardening-review"' in INDEX_HTML


def test_every_review_emits_exactly_the_check_set_the_panel_requires(tmp_path):
    empty = tmp_path/'empty'
    empty.mkdir()
    for payload in (synthetic_payload(tmp_path), hardening_review.review(empty), hardening_review.review()):
        assert tuple(c['id'] for c in payload['checks']) == hardening_review.CHECK_IDS
    assert json.dumps(list(hardening_review.CHECK_IDS)) in HARDENING_JS and '__CHECK_IDS__' not in HARDENING_JS
