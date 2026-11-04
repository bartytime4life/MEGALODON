"""Explicit selected-byte submission and bounded report presentation."""
import json
from html.parser import HTMLParser
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon.dashboard_assets import DASHBOARD_CSS, DASHBOARD_JS, INDEX_HTML
from megalodon.dashboard_file_inspection import (
    FILE_INSPECTION_CSS, FILE_INSPECTION_HTML, FILE_INSPECTION_JS,
)


def inspection_report():
    return dict(
        schema='megalodon-file-inspection-report-v1',
        inspected_at='2026-11-04T12:00:00Z', size_bytes=64, state='partial',
        structure=dict(format='Mach-O', slices_detected=2, slices=[dict(
            architecture='arm64', bits=64, sections=4, imports=2,
            writable_executable=1)]),
        identification=[dict(kind='packer', name='<img src=x onerror=alert(1)>')],
        tools=[dict(id='lief', state='completed'), dict(id='die', state='unsupported')],
        clues=[dict(code='WRITABLE_EXECUTABLE', title='A region can be written and executed',
                    meaning='Review this clue with the publisher and intended use.')],
        unknowns=['Only one executable slice was inspected.'],
        next_step='Confirm the publisher and intended use before opening this program.',
    )


def test_file_inspection_is_integrated_with_a_keyboard_route_and_focused_help():
    class Parse(HTMLParser):
        def __init__(self):
            super().__init__(); self.ids = {}; self.duplicates = []
        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if attrs.get('id'):
                if attrs['id'] in self.ids:
                    self.duplicates.append(attrs['id'])
                self.ids[attrs['id']] = (tag, attrs)
    page = Parse(); page.feed(INDEX_HTML)
    assert not page.duplicates
    assert INDEX_HTML.index('id="clamav-title"') < INDEX_HTML.index('id="file-inspection-title"') < INDEX_HTML.index('id="osquery-title"')
    assert FILE_INSPECTION_HTML in INDEX_HTML
    assert FILE_INSPECTION_CSS in DASHBOARD_CSS
    assert FILE_INSPECTION_JS in DASHBOARD_JS
    assert "'file-inspection-title':'live'" in DASHBOARD_JS
    assert 'href="#file-inspection-title">Inspect a file →' in INDEX_HTML
    assert 'How do I inspect a downloaded program?' in INDEX_HTML
    assert page.ids['file-inspection-input'][1]['type'] == 'file'
    assert 'accept' not in page.ids['file-inspection-input'][1], 'extensions do not determine executable support'
    assert 'multiple' not in page.ids['file-inspection-input'][1]
    assert page.ids['file-inspection-title'][1]['tabindex'] == '-1'
    assert page.ids['file-inspection-status'][1]['aria-live'] == 'polite'
    assert 'hidden' in page.ids['file-inspection-sign-in'][1]
    assert 'setup-account-title' in page.ids
    assert '<a href="#setup-account-title">Open Local sign-in in Setup →</a>' in FILE_INSPECTION_HTML
    assert 'Preparing the command does not launch or restart anything.' in INDEX_HTML
    assert '@media(max-width:640px)' in FILE_INSPECTION_CSS
    assert ':focus-visible' in FILE_INSPECTION_CSS
    for forbidden in ['innerHTML', 'localStorage', 'sessionStorage', 'eval(', 'FormData', 'FileReader', 'arrayBuffer(']:
        assert forbidden not in FILE_INSPECTION_JS


def test_file_inspection_explicit_workflow_and_untrusted_results():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node unavailable')
    result = subprocess.run(
        [node, str(Path(__file__).with_name('file_inspection_browser.cjs'))],
        input=json.dumps(dict(code=FILE_INSPECTION_JS, report=inspection_report())),
        text=True, capture_output=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
