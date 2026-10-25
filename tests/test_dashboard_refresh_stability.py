"""Background review updates retain browser-owned interaction state."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon import hardening_review
from megalodon.dashboard_support_config import SUPPORT_CONFIG_JS


def test_review_refresh_retains_open_details_and_focus(tmp_path):
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node unavailable')
    payload = hardening_review.review(tmp_path, now=lambda: '2026-10-18T06:30:00Z')
    result = subprocess.run([node, str(Path(__file__).with_name('refresh_stability.cjs'))],
                            input=json.dumps(dict(code=SUPPORT_CONFIG_JS, payload=payload)),
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
