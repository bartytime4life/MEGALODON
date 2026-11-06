"""Explicit setup actions, truthful capture state and protected configuration drafts."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_CSS, DASHBOARD_JS
from megalodon.dashboard_support_config import SUPPORT_CONFIG_HTML, SUPPORT_CONFIG_CSS, SUPPORT_CONFIG_JS


@pytest.mark.parametrize("script", ["support_config_browser.cjs", "support_config_visibility.cjs", "support_setup_visibility.cjs", "support_refresh_browser.cjs", "model_library_browser.cjs", "ollama_model_test_browser.cjs", "startup_preferences_browser.cjs"])
def test_support_config_behavior(script):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node unavailable")
    fixture = dict(schema="megalodon-support-config-v1", token="b" * 32,
                   interfaces=[dict(name="eth0", default=True, up=True), dict(name="wlan0", default=False, up=False)],
                   settings=dict(interface="eth0", nmap_target="127.0.0.1/32", scan_folder="Downloads"),
                   tool_directories={}, tool_directories_status="ready",
                   job=dict(state="idle", action=None, message="Ready.", started_at=None, finished_at=None),
                   capture=dict(state="idle", interface="", received=0, accepted=0, skipped=0,
                                started_at=None, finished_at=None, message="Not capturing."), tools=[],
                   background=dict(enabled=False, state="stopped", message="Background off.", session_count=0),
                   geography_enabled=False,
                   command="~/.local/share/megalodon/current/venv/bin/python -I -m megalodon.support_config")
    # Use the real release-fenced producer: no synthetic binding or provider I/O.
    from megalodon.config import AISettings
    from megalodon.model_lifecycle import ModelLifecycle
    from megalodon.model_telemetry import ModelTelemetry
    settings = AISettings(enabled=True)
    unbound_model = ModelTelemetry(lambda: settings).snapshot()
    unbound_model.update(selection_state='restored',keep_ready=True, lifecycle=ModelLifecycle(lambda: settings).snapshot())
    from megalodon.model_library import ModelLibrary
    library = ModelLibrary(Path('/unused-home')).snapshot()
    from megalodon.model_test import ModelTest
    model_test = ModelTest(lambda:settings).snapshot()
    result = subprocess.run([node, str(Path(__file__).with_name(script))],
                            input=json.dumps(dict(code=SUPPORT_CONFIG_JS, fixture=fixture, unbound_model=unbound_model, library=library, model_test=model_test)),
                            capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr


def test_support_config_composition():
    assert 'id="support-config" class="support-config settings-console" aria-labelledby="setup-title">' in INDEX_HTML
    assert SUPPORT_CONFIG_CSS in DASHBOARD_CSS
    assert SUPPORT_CONFIG_JS in DASHBOARD_JS
    assert INDEX_HTML.index('id="support-apps-configure"') < INDEX_HTML.index('id="pc-live-title"')
    assert 'aria-expanded="false" aria-controls="support-config"' in INDEX_HTML
    assert 'id="workspace-setup"' in INDEX_HTML
    assert 'id="support-config-capture-stop"' in INDEX_HTML
    assert 'id="support-config-tool-directory"' in INDEX_HTML
    assert '>Close managed Wireshark</button>' in INDEX_HTML
    assert 'Save any capture you want to keep before closing.' in INDEX_HTML
    assert 'Configure local tools' in INDEX_HTML
    assert 'No capture starts here.' not in INDEX_HTML
    assert 'Other saved-file imports use their adapter commands.' in INDEX_HTML
    assert 'innerHTML' not in SUPPORT_CONFIG_JS
    assert 'localStorage' not in SUPPORT_CONFIG_JS


def test_model_loading_is_secondary_to_explicit_selection_and_test():
    from html.parser import HTMLParser

    class ModelLayout(HTMLParser):
        def __init__(self):
            super().__init__()
            self.details = []
            self.parents = {}

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == "details":
                self.details.append(attrs.get("id", ""))
            if attrs.get("id"):
                self.parents[attrs["id"]] = tuple(self.details)

        def handle_endtag(self, tag):
            if tag == "details":
                self.details.pop()

    layout = ModelLayout()
    layout.feed(INDEX_HTML)
    advanced = "support-model-loading-options"
    assert advanced in layout.parents["support-model-load"]
    for control in ("support-model-select", "support-model-save", "support-model-test", "support-model-next"):
        assert advanced not in layout.parents[control]
    assert 'id="support-model-loading-options" open' not in INDEX_HTML
