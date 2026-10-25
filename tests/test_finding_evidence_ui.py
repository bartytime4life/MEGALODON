"""Composed Findings ownership and retained passive compatibility boundaries.

The old finding_evidence_browser.cjs address-case harness is historical. Its
room-case and threshold expectations were absent in baseline26f0d09 and the new
source-bound feed owns active Findings. New interaction/escaping/unknown-gap and
fixed response assertions live in test_dashboard_findings_ui.py.
"""
import re
from megalodon.control_room_assets import ROOM_JS
from megalodon.dashboard_assets import INDEX_HTML
from megalodon.dashboard_findings import FINDINGS_JS


def test_authoritative_findings_does_not_compete_with_legacy_evidence_renderer():
    assert 'id="findings-workbench" data-findings-owned="true"' in INDEX_HTML
    assert "getAttribute?.('data-findings-owned')==='true')return" in ROOM_JS
    assert '<div class="fw-legacy" inert>' in INDEX_HTML
    assert 'id="fw-facts"' in INDEX_HTML and 'id="fw-refs"' in INDEX_HTML
    assert 'id="fw-gaps"' in INDEX_HTML and 'id="fw-context"' in INDEX_HTML
    assert 'Recorded severity basis: ' in FINDINGS_JS
    assert 'Unknown / not recorded' in FINDINGS_JS
    assert 'textContent' in FINDINGS_JS and 'innerHTML' not in FINDINGS_JS


def test_compatibility_evidence_limits_and_fixed_followups_remain_passive():
    start=INDEX_HTML.index('<section class="finding-evidence"')
    panel=INDEX_HTML[start:INDEX_HTML.index('</section>',start)]
    assert 'id="room-evidence-content" hidden' in panel
    assert 'id="room-evidence-status" role="status"' in panel
    assert 'Detector evaluation window' in panel
    assert 'missing values are not reconstructed' in panel
    assert 'Current software settings cannot establish historical detector behavior.' in panel
    assert 'its running or completed state does not prove a process is active' in panel
    assert 'not the complete evidence evaluated by the detector' in panel
    for target in re.findall(r'href="([^"]+)"',panel):
        assert target.startswith('#') and f'id="{target[1:]}"' in INDEX_HTML
    assert 'href="http' not in panel
    assert 'This view does not supply action receipts or authorize a response.' in panel
