from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "tools" / "validate_exact_head_evidence.py"
FIXTURE = ROOT / "tests" / "fixtures" / "exact_head_evidence" / "valid.json"
HEAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def test_exact_head_evidence_accepts_matching_current_head() -> None:
    result = subprocess.run(
        [sys.executable, str(VALIDATOR), str(FIXTURE), "--current-head", HEAD],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "MEGALODON_EXACT_HEAD_EVIDENCE_VALID" in result.stdout


def test_exact_head_evidence_rejects_stale_head() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(VALIDATOR),
            str(FIXTURE),
            "--current-head",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "STALE_HEAD" in result.stdout
