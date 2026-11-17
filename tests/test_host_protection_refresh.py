"""Refresh admission and visibility tests use an inert DOM and HTTP promises."""
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon.dashboard_host_protection import HOST_PROTECTION_JS


def test_controls_match_refresh_admission_and_pause_hidden_reads():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node required for refresh admission')
    result = subprocess.run([node, str(Path(__file__).with_name('host_protection_refresh.cjs'))],
                            input=HOST_PROTECTION_JS, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
