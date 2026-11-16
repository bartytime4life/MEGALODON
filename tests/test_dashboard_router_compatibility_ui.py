"""Static guidance never acquires configuration authority or loses user choices."""
from collections import Counter
from dataclasses import replace
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
import subprocess
from urllib.parse import urlsplit

import pytest

from megalodon.dashboard_assets import DASHBOARD_CSS, DASHBOARD_JS, INDEX_HTML
from megalodon.dashboard_router_compatibility import (
    ROUTER_COMPATIBILITY_CSS, ROUTER_COMPATIBILITY_HTML, ROUTER_COMPATIBILITY_JS,
    _mode, _options, _profile,
)
from megalodon.dashboard_settings import SETTINGS_JS
from megalodon.dashboard_support_config import SUPPORT_CONFIG_JS
from megalodon.router_compatibility import (
    CHECKED_ON, COLLECTION_MODES, DEFAULT_MODE_ID, DEFAULT_PROFILE_ID, PROFILES,
    Source,
)


class Layout(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.elements = []
        self.stack = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        self.elements.append((tag, attributes, tuple(self.stack)))
        if tag not in {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
                       'link', 'meta', 'param', 'source', 'track', 'wbr'}:
            self.stack.append((tag, attributes.get('id')))

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break


def test_guide_is_composed_once_in_traffic_before_capture():
    elements = Layout(INDEX_HTML).elements
    ids = Counter(attrs['id'] for _, attrs, _ in elements if 'id' in attrs)
    assert not [identifier for identifier, count in ids.items() if count > 1]
    guide = next(item for item in elements if item[1].get('id') == 'router-compatibility')
    assert ('section', 'setup-category-traffic') in guide[2]
    assert INDEX_HTML.index('id="router-compatibility"') < INDEX_HTML.index('id="support-capture-title"')
    assert ROUTER_COMPATIBILITY_CSS in DASHBOARD_CSS
    assert DASHBOARD_JS.count(ROUTER_COMPATIBILITY_JS) == 1
    assert CHECKED_ON in ROUTER_COMPATIBILITY_HTML
    assert 'does not configure your router or verify monitoring coverage' in ROUTER_COMPATIBILITY_HTML
    assert 'Choices last only while this page is open' in ROUTER_COMPATIBILITY_HTML
    assert 'non-promiscuous capture' in ROUTER_COMPATIBILITY_HTML
    assert '(<code>-p</code>)' in ROUTER_COMPATIBILITY_HTML
    assert 'separately prepared promiscuous sensor and tested local ingestion' in ROUTER_COMPATIBILITY_HTML


def test_every_profile_and_mode_is_rendered_with_only_defaults_visible():
    elements = Layout(ROUTER_COMPATIBILITY_HTML).elements
    for attribute, catalog, default, selector in (
        ('data-router-profile', PROFILES, DEFAULT_PROFILE_ID, 'router-guide-profile'),
        ('data-router-mode', COLLECTION_MODES, DEFAULT_MODE_ID, 'router-guide-mode'),
    ):
        panels = [attrs for _, attrs, _ in elements if attribute in attrs]
        assert [panel[attribute] for panel in panels] == [item.id for item in catalog]
        assert [panel[attribute] for panel in panels if 'hidden' not in panel] == [default]
        options = [attrs for tag, attrs, parents in elements
                   if tag == 'option' and ('select', selector) in parents]
        assert [option['value'] for option in options] == [item.id for item in catalog]
        assert [option['value'] for option in options if 'selected' in option] == [default]
        control = next(attrs for _, attrs, _ in elements if attrs.get('id') == selector)
        assert control['data-default'] == default
        assert 'disabled' not in control
        assert selector not in SUPPORT_CONFIG_JS
    assert not [tag for tag, _, _ in elements if tag in {'form', 'button', 'input', 'iframe', 'script'}]
    links = [attrs for tag, attrs, _ in elements if tag == 'a']
    assert [link['href'] for link in links] == [source.url for profile in PROFILES for source in profile.sources]
    for link in links:
        assert urlsplit(link['href']).scheme == 'https'
        assert link['target'] == '_blank'
        assert set(link['rel'].split()) == {'noopener', 'noreferrer'}


def test_catalog_text_cannot_inject_active_html_or_attributes():
    text = 'Example " <img src=x onerror=alert(1)> & <script>bad()</script>'
    source = Source(text, 'https://example.test/guide?title=" onload="bad()&part=<example>')
    profile = replace(PROFILES[0], id=text, name=text, category=text, collection=text,
                      vendor_features=text, caveats=(text,), sources=(source,))
    mode = replace(COLLECTION_MODES[0], id=text, name=text, visibility=text,
                   limitations=text, preparation=text)
    elements = Layout(_profile(profile) + _mode(mode) + _options((profile,), profile.id)).elements
    assert not [tag for tag, _, _ in elements if tag in {'img', 'script'}]
    assert not [name for _, attrs, _ in elements for name in attrs if name.startswith('on')]
    assert next(attrs['href'] for tag, attrs, _ in elements if tag == 'a') == source.url
    assert next(attrs['data-router-profile'] for _, attrs, _ in elements if 'data-router-profile' in attrs) == text
    assert next(attrs['value'] for tag, attrs, _ in elements if tag == 'option') == text


def test_selector_is_read_only_and_heartbeat_preserves_choices():
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node unavailable')
    result = subprocess.run(
        [node, str(Path(__file__).with_name('router_compatibility_browser.cjs'))],
        input=json.dumps(dict(code=SETTINGS_JS, guide_code=ROUTER_COMPATIBILITY_JS,
                             profiles=[profile.id for profile in PROFILES],
                             modes=[mode.id for mode in COLLECTION_MODES],
                             default_profile=DEFAULT_PROFILE_ID, default_mode=DEFAULT_MODE_ID)),
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == 0, result.stderr
