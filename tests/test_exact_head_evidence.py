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


def _validate(tmp_path: Path, raw: bytes) -> subprocess.CompletedProcess:
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(raw)
    return subprocess.run(
        [sys.executable, str(VALIDATOR), str(manifest), "--current-head", HEAD],
        cwd=ROOT, check=False, capture_output=True, text=True,
    )


def test_impossible_or_reversed_execution_times_are_refused(tmp_path) -> None:
    import json
    for started, finished in (("2026-99-99T99:99:99Z", "2026-09-22T04:01:00Z"),
                              ("2026-09-22T04:01:00Z", "2026-09-22T04:00:00Z"),
                              ("20260922T040000Z", "2026-09-22T04:01:00Z"),
                              ("2026-09-22 04:00:00Z", "2026-09-22T04:01:00Z"),
                              ("2026-09-22T04:00Z", "2026-09-22T04:01:00Z")):
        document = json.loads(FIXTURE.read_text())
        document["execution"].update(started_at=started, finished_at=finished)
        result = _validate(tmp_path, json.dumps(document).encode())
        assert result.returncode == 2, result.stdout + result.stderr
        assert "Traceback" not in result.stderr


def test_undecodable_or_deeply_nested_input_is_a_fixed_refusal(tmp_path) -> None:
    for raw in (b'{"a":"\xff"}', b"[" * 100000):
        result = _validate(tmp_path, raw)
        assert result.returncode == 2
        assert "Traceback" not in result.stderr


def test_fractional_rfc3339_execution_times_are_accepted(tmp_path) -> None:
    import json
    document = json.loads(FIXTURE.read_text())
    document["execution"].update(started_at="2026-09-22T04:00:00.25Z", finished_at="2026-09-22T04:00:00.5Z")
    result = _validate(tmp_path, json.dumps(document).encode())
    assert result.returncode == 0, result.stdout + result.stderr

