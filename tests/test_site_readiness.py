"""Exercise the actual mirrored Site parser and Python report together."""

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon.readiness import readiness_json


ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
ASSET = ROOT / "site/dist/readiness.js"
pytestmark = [
    pytest.mark.skipif(NODE is None, reason="Node.js is required for Site contract tests"),
    pytest.mark.skipif(not ASSET.is_file(), reason="Site mirror is separate from Python source distributions"),
]


def test_site_rejects_ambiguous_and_unbounded_readiness_claims():
    result = subprocess.run(
        [NODE, "--test", "--test-reporter=tap", str(ROOT / "site/tests/readiness.test.cjs")],
        cwd=ROOT, capture_output=True, text=True, timeout=15, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "# fail 0" in result.stdout
    assert "# skipped 0" in result.stdout


def test_actual_python_receipt_matches_site_schema():
    # stdin carries only the public, path-free readiness receipt. No tool runs.
    script = """const fs = require('node:fs');
const {validateReadinessReport} = require('./site/dist/readiness.js');
const value = validateReadinessReport(fs.readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(value));
"""
    receipt = readiness_json()
    result = subprocess.run(
        [NODE, "-e", script], cwd=ROOT, input=receipt,
        capture_output=True, text=True, timeout=15, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == json.loads(receipt)
