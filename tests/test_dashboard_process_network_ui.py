"""Shipped process network panel exercised with real synthetic reviews and an inert DOM."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon import process_network
from megalodon.dashboard_process_network import PROCESS_NETWORK_JS
from megalodon.dashboard_support_config import SUPPORT_CONFIG_HTML, SUPPORT_CONFIG_JS
from test_process_network import UID, host, proc, row, tables  # noqa: F401  (host is a fixture)


def test_process_network_panel_renders_real_reviews_and_rejects_forged_payloads(host, tmp_path_factory):
    if not shutil.which('node'):
        pytest.skip('Node unavailable')
    now = lambda: '2026-10-18T08:00:00Z'
    result = process_network.review(host, uid=UID, now=now)
    quiet = tmp_path_factory.mktemp('quiet')
    tables(quiet)
    empty = process_network.review(quiet, uid=UID, now=now)
    wide_root = tmp_path_factory.mktemp('wide')
    tables(wide_root, tcp=[row(('192.168.1.5', 1), ('203.0.113.9', 443), '01', 7)])
    proc(wide_root, 500, '/opt/' + '\U0001F600' * 200, [7])
    wide = process_network.review(wide_root, uid=UID, now=now)
    pending = dict(schema=process_network.SCHEMA, state='pending', action_authority='none')
    completed = subprocess.run([shutil.which('node'), str(Path(__file__).with_name('process_network_browser.cjs'))],
                               input=json.dumps(dict(code=PROCESS_NETWORK_JS, result=result, empty=empty, pending=pending, wide=wide)),
                               text=True, capture_output=True, timeout=10)
    assert completed.returncode == 0, completed.stderr


def test_process_network_panel_is_wired_into_setup_without_an_action():
    assert 'id="process-network-review"' in SUPPORT_CONFIG_HTML
    assert "renderProcessNetwork(el('process-network-review'),v.process_network)" in SUPPORT_CONFIG_JS
    assert "renderProcessNetwork(el('process-network-review'),null)" in SUPPORT_CONFIG_JS
    assert "processPending(state.payload?.process_network)" in SUPPORT_CONFIG_JS
    actions = SUPPORT_CONFIG_JS.split('const actions=')[1].split('};')[0]
    assert 'process' not in actions and 'innerHTML' not in PROCESS_NETWORK_JS and 'fetch(' not in PROCESS_NETWORK_JS
