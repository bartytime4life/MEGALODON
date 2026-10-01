"""Explicit setup actions, truthful capture state and protected configuration drafts."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_CSS, DASHBOARD_JS
from megalodon.dashboard_support_config import SUPPORT_CONFIG_HTML, SUPPORT_CONFIG_CSS, SUPPORT_CONFIG_JS


@pytest.mark.parametrize("script", ["support_config_browser.cjs", "support_config_visibility.cjs", "support_setup_visibility.cjs"])
def test_support_config_behavior(script):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node unavailable")
    fixture = dict(schema="megalodon-support-config-v1", token="b" * 32,
                   interfaces=[dict(name="eth0", default=True, up=True), dict(name="wlan0", default=False, up=False)],
                   settings=dict(interface="eth0", nmap_target="127.0.0.1/32", scan_folder="Downloads"),
                   job=dict(state="idle", action=None, message="Ready.", started_at=None, finished_at=None),
                   capture=dict(state="idle", interface="", received=0, accepted=0, skipped=0,
                                started_at=None, finished_at=None, message="Not capturing."), tools=[],
                   background=dict(enabled=False, state="stopped", message="Background off.", session_count=0),
                   geography_enabled=False,
                   command="~/.local/share/megalodon/current/venv/bin/python -I -m megalodon.support_config")
    result = subprocess.run([node, str(Path(__file__).with_name(script))],
                            input=json.dumps(dict(code=SUPPORT_CONFIG_JS, fixture=fixture)),
                            capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr


def test_support_config_composition():
    assert 'id="support-config" aria-labelledby="support-config-title">' in INDEX_HTML
    assert SUPPORT_CONFIG_CSS in DASHBOARD_CSS
    assert SUPPORT_CONFIG_JS in DASHBOARD_JS
    assert INDEX_HTML.index('id="support-apps-configure"') < INDEX_HTML.index('id="pc-live-title"')
    assert 'aria-expanded="false" aria-controls="support-config"' in INDEX_HTML
    assert 'id="workspace-setup"' in INDEX_HTML
    assert 'id="support-config-capture-stop"' in INDEX_HTML
    assert '>Close managed Wireshark</button>' in INDEX_HTML
    assert 'Save any capture you want to keep before closing.' in INDEX_HTML
    assert 'Configure local tools' in INDEX_HTML
    assert 'No capture starts here.' not in INDEX_HTML
    assert 'Other saved-file imports use their adapter commands.' in INDEX_HTML
    assert 'innerHTML' not in SUPPORT_CONFIG_JS
    assert 'localStorage' not in SUPPORT_CONFIG_JS
