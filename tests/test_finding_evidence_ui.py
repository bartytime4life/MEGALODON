"""Evidence inspection is a passive view of the existing bounded projection."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from finding_evidence_fixture import finding_evidence_fixture
from megalodon.control_room_assets import ROOM_JS
from megalodon.dashboard_assets import INDEX_HTML
from megalodon.dashboard_traffic import unavailable


def test_qualified_finding_inspector_behavior():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node required for inspector browser logic")
    result = subprocess.run([node, str(Path(__file__).with_name("finding_evidence_browser.cjs"))],
        input=json.dumps(dict(code=ROOM_JS, payload=finding_evidence_fixture(), empty=unavailable())),
        text=True, capture_output=True, timeout=15, check=False)
    assert result.returncode == 0, result.stderr


def test_inspector_has_explicit_limits_and_fixed_followups():
    start = INDEX_HTML.index('<section class="finding-evidence"')
    end = INDEX_HTML.index('</section>', start)
    panel = INDEX_HTML[start:end]
    assert 'id="room-evidence-content" hidden' in panel
    assert 'id="room-evidence-status" role="status"' in panel
    assert 'Detector evaluation window' in panel
    assert 'Unknown; not supplied by this projection.' in panel
    assert 'Current software settings cannot establish historical detector behavior.' in panel
    assert 'its running or completed state does not prove a process is active' in panel
    assert 'not the complete evidence evaluated by the detector' in panel
    assert 'href="#ingestion-runs-title"' in panel
    assert 'href="#storage-evidence-title"' in panel
    assert 'href="#room-reports-title"' in panel
    assert 'href="http' not in panel
