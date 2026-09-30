"""Support-app startup is prominent, explicit, bounded and retryable."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_CSS, DASHBOARD_JS
from megalodon.dashboard_support_apps import SUPPORT_APPS_HTML, SUPPORT_APPS_CSS, SUPPORT_APPS_JS


def test_support_apps_behavior():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node unavailable")
    fixture = dict(schema="megalodon-support-startup-v1", state="idle", started_at=None,
                   finished_at=None, token="a" * 32, items=[],
                   command="~/.local/share/megalodon/current/venv/bin/python -I -m megalodon.support_startup")
    result = subprocess.run([node, str(Path(__file__).with_name("support_apps_browser.cjs"))],
                            input=json.dumps(dict(code=SUPPORT_APPS_JS, fixture=fixture)),
                            capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr


def test_support_apps_local_composition():
    from megalodon.dashboard_support_config import SUPPORT_CONFIG_HTML
    assert 'id="support-apps"' in INDEX_HTML
    assert 'id="workspace-setup"' in INDEX_HTML
    assert SUPPORT_APPS_CSS in DASHBOARD_CSS
    assert SUPPORT_APPS_JS in DASHBOARD_JS
    assert INDEX_HTML.index('id="support-apps-title"') < INDEX_HTML.index('id="pc-live-title"')
    assert 'support-apps-title\': \'live' in DASHBOARD_JS
    assert 'type="button" id="support-apps-start"' in INDEX_HTML
    assert 'role="status" aria-live="polite" aria-atomic="true"' in SUPPORT_APPS_HTML
    assert 'innerHTML' not in SUPPORT_APPS_JS


def test_bulk_start_and_individual_launch_routes_remain_separate():
    assert "fetch('/api/support-start',options)" in SUPPORT_APPS_JS
    assert "megalodon-support-startup-v1" in SUPPORT_APPS_JS
    assert "/api/support-apps" not in SUPPORT_APPS_JS
    assert "heartbeatFetch('/api/support-apps', {method:'POST', body:JSON.stringify({app:appId})" in DASHBOARD_JS
    assert "'X-Megalodon-Support-App':'1'" in DASHBOARD_JS
    assert "window_verified !== false" in DASHBOARD_JS
    assert "The HUD has no stop, removal, or configuration action." not in DASHBOARD_JS
    assert "These individual app launchers do not close apps or change their configuration." in DASHBOARD_JS
