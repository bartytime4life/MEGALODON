"""Local workflow rows use validated runtime observations, not capability claims."""
import json
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_CSS, DASHBOARD_JS
from megalodon.dashboard_integrations import INTEGRATIONS_HTML, INTEGRATIONS_JS
from megalodon.dashboard_workflows import WORKFLOWS_CSS, WORKFLOWS_JS, local_workflow_script


def workflow_fixture():
    states = ['connected', 'collecting', 'ready', 'stopped', 'standby', 'needs_setup', 'unavailable', 'error', 'connected', 'ready']
    ids = ['core', 'tshark', 'zeek', 'suricata', 'scapy', 'nftables', 'clamav', 'osquery', 'qwen', 'nmap']
    return dict(schema='megalodon-support-workflows-v1', mode='background', observed_at='2026-09-30T20:10:00Z', tools=[dict(id=name, name=name, state=state, message=f'{name} synthetic observation.', updated_at='2026-09-30T20:09:30Z', metrics=[dict(label='Source records', value=12, unit='records')]) for name, state in zip(ids, states)])


def test_workflow_runtime_validation_and_visibility():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node unavailable')
    result = subprocess.run([node, str(Path(__file__).with_name('workflows_browser.cjs'))], input=json.dumps(dict(code=local_workflow_script(INTEGRATIONS_JS)+WORKFLOWS_JS, fixture=workflow_fixture())), capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr


def test_workflow_local_composition_preserves_hosted_reference():
    assert WORKFLOWS_JS in DASHBOARD_JS
    assert WORKFLOWS_CSS in DASHBOARD_CSS
    assert 'Start background tools' in INDEX_HTML
    assert INDEX_HTML.index('id="integrations-cards"') < INDEX_HTML.index('Advanced actions, desktop apps and capability reference')
    assert 'No Wireshark, Zenmap or ClamTk windows open.' in INDEX_HTML
    assert 'Sensor counts are bounded source summaries.' in INDEX_HTML
    assert 'support-workflows' not in INTEGRATIONS_JS
    assert 'Background tools' not in INTEGRATIONS_HTML
    assert 'innerHTML' not in WORKFLOWS_JS
    assert "method:'POST'" not in WORKFLOWS_JS
    assert 'id="support-config-qwen-setup"' in INDEX_HTML
    assert 'id="support-config-suricata-setup"' in INDEX_HTML
    assert 'Optional desktop inspection' in INDEX_HTML
    class Ids(HTMLParser):
        def __init__(self):
            super().__init__()
            self.ids = []
        def handle_starttag(self, tag, attrs):
            self.ids.extend(value for name, value in attrs if name == 'id')
    parser = Ids()
    parser.feed(INDEX_HTML)
    assert [name for name, count in Counter(parser.ids).items() if count > 1] == []
