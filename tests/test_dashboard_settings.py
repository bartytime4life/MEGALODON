"""Setup reorganization preserves working controls and local authorization."""
from collections import Counter
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_JS, DASHBOARD_CSS
from megalodon.dashboard_heartbeat import HEARTBEAT_JS
from megalodon.dashboard_settings import SETTINGS_CSS


class Elements(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.ids = []
        self.controls = set()
        self.panels = []
        self.feed(html)

    def handle_starttag(self, tag, attributes):
        value = dict(attributes)
        if value.get('id'):
            self.ids.append(value['id'])
            if tag in {'input', 'select', 'button', 'textarea'}:
                self.controls.add(value['id'])
        if 'data-setup-category' in value:
            self.panels.append(value)


def test_composition_retains_every_existing_control_without_runtime_reparenting():
    source = Path('megalodon/dashboard_assets.py').read_text()
    namespace = {'__package__': 'megalodon'}
    exec(compile(source.replace('INDEX_HTML = compose_settings(INDEX_HTML)', ''), '<before-settings>', 'exec'), namespace)
    before, after = Elements(namespace['INDEX_HTML']), Elements(INDEX_HTML)
    assert before.controls == after.controls
    assert not [key for key, count in Counter(after.ids).items() if count > 1]
    assert [panel['data-setup-category'] for panel in after.panels] == ['overview', 'traffic', 'ai', 'apps', 'storage', 'advanced']
    assert ['hidden' in panel for panel in after.panels] == [False, True, True, True, True, True]
    assert SETTINGS_CSS in DASHBOARD_CSS
    assert '#workspace-setup [hidden] { display:none!important; }' in DASHBOARD_CSS


def test_local_install_session_recovers_without_terminal_paste_or_ambiguous_replay():
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node unavailable')
    result = subprocess.run([node, str(Path(__file__).with_name('heartbeat_session.cjs'))],
                            input=json.dumps({'code': HEARTBEAT_JS}), capture_output=True,
                            text=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr


def test_generated_frontend_is_valid_javascript():
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node unavailable')
    result = subprocess.run([node, '--check'], input=DASHBOARD_JS,
                            text=True, capture_output=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr
