"""Shipped gateway panel exercised with real synthetic reviews and an inert DOM."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon.dashboard_gateway import GATEWAY_JS
from megalodon.dashboard_support_config import SUPPORT_CONFIG_HTML, SUPPORT_CONFIG_JS
from megalodon import gateway_review
from megalodon.gateway_review import GatewayReview
from test_gateway_review import GW, GW_MAC, OTHER_MAC, arp, route, tree


@pytest.fixture(autouse=True)
def little_endian_tables(monkeypatch):
    # test_gateway_review.route() writes little-endian route words; pin the decoder to match on any runner.
    monkeypatch.setattr(gateway_review, '_BYTE_ORDER', 'little')


def reviews(tmp_path):
    session, now = {}, lambda: '2026-10-18T07:00:00Z'
    root = tree(tmp_path, [route('eth0', GW)], [arp(GW, GW_MAC)])
    review = GatewayReview(tmp_path/'home', root=root, now=now)
    first = review.review(session)
    tree(tmp_path, [route('eth0', GW)], [arp(GW, OTHER_MAC), arp('192.168.1.66', OTHER_MAC)])
    changed = review.review(session)
    tree(tmp_path, [route('eth0', GW)], [arp(GW, GW_MAC)])
    review.record_baseline()
    baseline = review.review(session)
    tree(tmp_path, [], [])
    offline = review.review(session)
    return first, changed, baseline, offline


def test_gateway_panel_renders_real_reviews_and_rejects_forged_payloads(tmp_path):
    if not shutil.which('node'):
        pytest.skip('Node unavailable')
    first, changed, baseline, offline = reviews(tmp_path)
    assert [f['rule'] for f in changed['findings']] == ['GATEWAY_MAC_CHANGED', 'GATEWAY_MAC_SHARED']
    result = subprocess.run([shutil.which('node'), str(Path(__file__).with_name('gateway_browser.cjs'))],
                            input=json.dumps(dict(code=GATEWAY_JS, first=first, changed=changed, baseline=baseline, offline=offline)),
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_gateway_panel_is_wired_into_setup_without_an_action():
    assert 'id="gateway-review"' in SUPPORT_CONFIG_HTML
    assert "renderGateway(el('gateway-review'),v.gateway)" in SUPPORT_CONFIG_JS
    assert "renderGateway(el('gateway-review'),null)" in SUPPORT_CONFIG_JS
    assert 'innerHTML' not in GATEWAY_JS and 'fetch(' not in GATEWAY_JS and 'gateway_' not in SUPPORT_CONFIG_JS.split('const actions=')[1].split('};')[0]
