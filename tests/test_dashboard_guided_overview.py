"""Task guidance uses current observations without gaining execution authority."""
import json
from html.parser import HTMLParser
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon.dashboard_assets import INDEX_HTML
from megalodon.dashboard_operations import OPERATIONS_JS
from test_dashboard_operations_ui import operations_fixture


class Composition(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parents = []
        self.nodes = {}
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'id' in attrs:
            self.nodes[attrs['id']] = (tag, attrs, list(self.parents))
        if tag == 'a':
            self.links.append((attrs, list(self.parents)))
        if tag not in {'input', 'img', 'meta', 'link', 'br', 'hr', 'wbr', 'area', 'base', 'col', 'embed', 'param', 'source', 'track'}:
            self.parents.append((tag, attrs))

    def handle_endtag(self, tag):
        for index in range(len(self.parents) - 1, -1, -1):
            if self.parents[index][0] == tag:
                del self.parents[index:]
                break


def test_guidance_precedes_tools_and_uses_existing_read_only_routes():
    page = Composition()
    page.feed(INDEX_HTML)
    assert list(page.nodes).index('ops-guide') < list(page.nodes).index('support-apps-title')
    assert list(page.nodes).index('ops-guide') < list(page.nodes).index('ops-download')
    for key in ('ops-guide', 'ops-guide-next', 'ops-guide-refresh'):
        assert [attrs['id'] for _, attrs in page.nodes[key][2] if attrs.get('role') == 'tabpanel'] == ['workspace-live']
    links = [attrs['href'] for attrs, parents in page.links if any(attrs.get('class') == 'ops-guide-routes' for _, attrs in parents)]
    assert links == ['#room-findings-title', '#ops-lens-title', '#room-reports-title']
    assert all(target[1:] in page.nodes for target in links)
    assert page.nodes['ops-lens-title'][1]['tabindex'] == '-1'
    assert 'Sensor observations' in INDEX_HTML
    assert 'AI is optional.' in INDEX_HTML
    assert 'aria-live' not in page.nodes['ops-guide'][1], 'routine guidance polling must not announce repeatedly'


def test_supporting_apps_are_optional_closed_details_with_actions_outside():
    page = Composition()
    page.feed(INDEX_HTML)
    tag, attrs, _ = page.nodes['app-tiles-details']
    assert tag == 'details' and 'open' not in attrs
    assert page.nodes['app-tiles-title'][0] == 'summary'
    assert 'optional tools and status details' in INDEX_HTML
    tile_links = [attrs for attrs, parents in page.links if 'data-app-tile' in attrs and any(attrs.get('id') == 'app-tiles-details' for _, attrs in parents)]
    assert len(tile_links) == 12
    for key in ('support-apps-start', 'support-apps-status'):
        assert not any(attrs.get('id') == 'app-tiles-details' for _, attrs in page.nodes[key][2])


def test_guided_overview_states_retry_and_read_only_behavior():
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node unavailable')
    result = subprocess.run([node, str(Path(__file__).with_name('guided_overview_browser.cjs'))],
                            input=json.dumps(dict(code=OPERATIONS_JS, fixture=operations_fixture())),
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
