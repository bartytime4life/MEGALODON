"""Tests for the repository hygiene guard."""

from pathlib import Path

import pytest

from tools.check_repository_hygiene import (
    MAX_BINARY_FILE_BYTES,
    ROOT,
    scan_paths,
    tracked_paths,
)


def test_current_tracked_tree_is_within_hygiene_bounds():
    assert scan_paths(ROOT, tracked_paths(ROOT)) == []


def test_high_confidence_secret_markers_and_sensitive_names_are_reported(tmp_path):
    private_key_marker = "-----BEGIN " + "PRIVATE KEY-----"
    aws_marker = "AKIA" + "1234567890ABCDEF"
    (tmp_path / "notes.txt").write_text(
        private_key_marker + "\n" + aws_marker + "\n",
        encoding="utf-8",
    )
    (tmp_path / "operator.pem").write_text("not a real key", encoding="utf-8")

    findings = scan_paths(tmp_path, ("notes.txt", "operator.pem"))

    assert "suspected private-key marker: notes.txt" in findings
    assert "suspected aws-access-key marker: notes.txt" in findings
    assert "sensitive tracked filename: operator.pem" in findings


def test_large_binary_is_reported_without_emitting_contents(tmp_path):
    path = tmp_path / "fixture.bin"
    path.write_bytes(b"\0" * (MAX_BINARY_FILE_BYTES + 1))

    findings = scan_paths(
        tmp_path,
        ("fixture.bin",),
        max_file_bytes=MAX_BINARY_FILE_BYTES,
    )

    assert any(finding.startswith("large tracked file: fixture.bin") for finding in findings)
    assert any(finding.startswith("large tracked binary: fixture.bin") for finding in findings)
    assert all("0" * 20 not in finding for finding in findings)


def test_example_environment_files_remain_allowed(tmp_path):
    path = tmp_path / ".env.example"
    path.write_text("MEGALODON_MODE=sample\n", encoding="utf-8")

    assert scan_paths(tmp_path, (".env.example",)) == []

    
def test_symlink_is_not_followed(tmp_path):
    target = tmp_path / "outside.txt"
    target.write_text("-----BEGIN " + "PRIVATE KEY-----", encoding="ascii")
    alias = tmp_path / "alias.txt"
    try:
        alias.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable on this runner")

    assert scan_paths(tmp_path, ("alias.txt",)) == [
        "tracked path is not a regular file: alias.txt"
    ]
