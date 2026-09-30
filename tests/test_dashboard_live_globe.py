"""Live globe uses observed packet directions and bounded geographic source data."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest
from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_CSS, DASHBOARD_JS
from megalodon.dashboard_live_globe import LIVE_GLOBE_HTML, LIVE_GLOBE_CSS, LIVE_GLOBE_JS
from megalodon.dashboard_globe import GLOBE_HTML


def live_fixture():
    stamp = '2026-09-30T20:10:00Z'
    anchor = dict(latitude=38.5, longitude=-97.5, label='Kansas', country='United States', accuracy_radius_km=None, source='DB-IP City Lite', approximate=True)
    peer = dict(anchor, latitude=51.5, longitude=-0.1, label='London', country='United Kingdom')
    return dict(schema='megalodon-live-connections-v1', generated_at=stamp,
                capture=dict(state='running', interface='eth0', accepted=5, received=5, skipped=0, started_at=stamp, finished_at=None, message='Capture running.'),
                background=dict(enabled=True, state='running', message='Saved background monitoring is running.', session_count=1),
                geography=dict(status='ready', source='DB-IP City Lite', build_date='2026-09-01', updated_at=stamp, anchor=anchor, anchor_checked_at=stamp, message='Local database ready.', attribution_url='https://db-ip.com'),
                totals=dict(active=1, returned=1, unmapped=0, truncated=False, evicted=0, packets=5, bytes=500),
                connections=[dict(id='abcdef1234', protocol='TCP', a=dict(ip='192.168.1.2', port=49152, local=True, location=anchor), b=dict(ip='1.1.1.1', port=443, local=False, location=peer), a_to_b=dict(packets=5, bytes=500, last_seen=stamp), b_to_a=dict(packets=0, bytes=0, last_seen=None), first_seen=stamp, last_seen=stamp, active=True, state='recent')],
                limits=dict(idle_seconds=15, retention_seconds=60, max_connections=128, tracked_connections=512))


def test_live_globe_behavior_and_geometry():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node unavailable')
    result = subprocess.run([node, str(Path(__file__).with_name('live_globe_browser.cjs'))], input=json.dumps(dict(code=LIVE_GLOBE_JS, fixture=live_fixture())), capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr


def test_local_live_globe_composition_preserves_history():
    assert LIVE_GLOBE_HTML in INDEX_HTML
    assert LIVE_GLOBE_CSS in DASHBOARD_CSS
    assert LIVE_GLOBE_JS in DASHBOARD_JS
    assert GLOBE_HTML in INDEX_HTML
    assert INDEX_HTML.index(LIVE_GLOBE_HTML) < INDEX_HTML.index('id="live-globe-history"') < INDEX_HTML.index(GLOBE_HTML)
    assert '<details class="live-globe-history" id="live-globe-history">' in INDEX_HTML
    assert 'https://db-ip.com' in LIVE_GLOBE_HTML
    assert 'aria-describedby="live-geography-destinations"' in LIVE_GLOBE_HTML
    assert LIVE_GLOBE_HTML.index('id="live-geography-destinations"') < LIVE_GLOBE_HTML.index('<details class="live-location-detail">')
    assert 'download.db-ip.com' in LIVE_GLOBE_HTML
    assert 'api64.ipify.org' in LIVE_GLOBE_HTML
    assert 'Enable background monitoring' in LIVE_GLOBE_HTML
    assert 'Stop monitoring' in LIVE_GLOBE_HTML
    assert 'innerHTML' not in LIVE_GLOBE_JS
    assert 'localStorage' not in LIVE_GLOBE_JS
    assert 'JSON.stringify({action:' not in LIVE_GLOBE_JS
    assert 'live-connections' not in (Path(__file__).resolve().parents[1] / 'site/dist/globe.js').read_text()


def test_offscreen_and_history_requests_stop():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node unavailable')
    result = subprocess.run([node, str(Path(__file__).with_name('live_globe_visibility.cjs'))], input=json.dumps(dict(code=LIVE_GLOBE_JS, fixture=live_fixture())), capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr
