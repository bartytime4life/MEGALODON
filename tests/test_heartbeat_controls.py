"""Heartbeat repaint retains reviewed control state without performing work."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon.dashboard_heartbeat import HEARTBEAT_JS


@pytest.mark.parametrize("scenario", [
    "removal-summary", "removal-copy", "changed-command", "availability",
    "model-focus", "action-identity", "visibility", "unchanged",
    "interrupted-render", "interrupted-invalidation", "interrupted-branches",
])
def test_heartbeat_repaint_control_state(scenario):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node required for heartbeat control behavior")
    result = subprocess.run(
        [node, str(Path(__file__).with_name("heartbeat_controls_browser.cjs"))],
        input=json.dumps({"code": HEARTBEAT_JS, "scenario": scenario}),
        text=True, capture_output=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
