"""The composed HUD displays review context without gaining action authority."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_CSS, DASHBOARD_JS
from megalodon.dashboard_host_findings import HOST_FINDINGS_HTML, HOST_FINDINGS_CSS, HOST_FINDINGS_JS
from megalodon.host_findings import aide_review, lynis_review


def host_findings_fixture(observed_at='2026-10-17T12:00:00Z'):
    """Fabricated source observations shared by inert and rendered rehearsals."""
    raw = (b'report_version_major=1\nreport_version_minor=0\nhostname=private-host\nsuggestion[]=AUTH-9262|Review policy|private-detail|text:never run me|\n'
           b'warning[]=SSH-7408|Review SSH settings|private-detail|url:https://invalid.test|\n')
    metrics, review = lynis_review(raw)
    return dict(schema='megalodon-host-security-v1', action_authority='none', audit_state='available', integrity_state='available',
        audit=dict(checked_at=observed_at, message='Unprivileged audit completed.', metrics=metrics, review=review),
        integrity=dict(checked_at=observed_at, message='Review private file changes.',
            metrics=dict(added_detected=1, removed_detected=0, changed_detected=1),
            review=aide_review(b'AIDE synthetic report', 'check', dict(created_at='2026-10-01T12:00:00Z', sha256='a'*64), 5)))


def test_host_findings_browser_behavior():
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node unavailable')
    fixture = host_findings_fixture()
    result = subprocess.run([node, str(Path(__file__).with_name('host_findings_browser.cjs'))],
        input=json.dumps(dict(code=HOST_FINDINGS_JS, fixture=fixture)), text=True, capture_output=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr


def test_host_findings_composed_into_existing_protected_setup_lane():
    assert HOST_FINDINGS_HTML in INDEX_HTML
    assert HOST_FINDINGS_CSS in DASHBOARD_CSS and HOST_FINDINGS_JS in DASHBOARD_JS
    assert "renderHostFindings(el('host-findings'),h)" in DASHBOARD_JS
    assert "renderHostFindings(el('host-findings'),null)" in DASHBOARD_JS
    assert 'None of these observations verifies a security incident' in INDEX_HTML
    assert 'innerHTML' not in HOST_FINDINGS_JS
    assert 'fetch(' not in HOST_FINDINGS_JS
    assert 'addEventListener' not in HOST_FINDINGS_JS
