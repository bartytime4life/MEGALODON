"""Exercise the canonical local HUD parser and Python report together."""

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon.readiness import readiness_json, local_readiness_report
from megalodon.dashboard_tool_assets import READINESS_JS


ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js is required for HUD contract tests")


def test_hud_rejects_ambiguous_and_unbounded_readiness_claims():
    # The assertions below inspect TAP, regardless of Node's default reporter.
    result = subprocess.run(
        [NODE, "--test-reporter=tap", str(ROOT / "tests/readiness_browser.cjs")],
        cwd=ROOT, input=READINESS_JS, capture_output=True, text=True, timeout=15, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "# fail 0" in result.stdout
    assert "# skipped 0" in result.stdout


@pytest.mark.parametrize("receipt", [readiness_json(), json.dumps(local_readiness_report())])
def test_actual_python_receipt_matches_hud_schema(receipt):
    # stdin carries only the public, path-free readiness receipt. No tool runs.
    script = READINESS_JS + """\nconst fs = require('node:fs');
const value = validateReadinessReport(fs.readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(value));
"""
    result = subprocess.run(
        [NODE, "-e", script], cwd=ROOT, input=receipt,
        capture_output=True, text=True, timeout=15, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == json.loads(receipt)
