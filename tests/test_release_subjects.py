"""Exact-source binding and offline refusal for temporary release subjects."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_subjects", ROOT / "tools/release_subjects.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
COMMIT = "a" * 40
TREE = "b" * 40
VERSION = "0.1.0"


def subjects(tmp_path: Path, monkeypatch):
    directory = tmp_path / "subjects"
    directory.mkdir()
    wheel, sdist = (directory / name for name in tool._names(VERSION))
    wheel.write_bytes(b"synthetic wheel bytes")
    sdist.write_bytes(b"synthetic source archive bytes")
    expected = {
        ("rev-parse", "--verify", "HEAD"): COMMIT,
        ("rev-parse", "--verify", "HEAD^{tree}"): TREE,
        ("status", "--porcelain", "--untracked-files=normal"): "",
        ("remote", "get-url", "origin"): "https://github.com/bartytime4life/MEGALODON.git",
    }
    monkeypatch.setattr(tool, "_git", lambda _checkout, *args: expected[args])
    manifest = tool.collect(tmp_path, COMMIT, TREE, VERSION, wheel, sdist)
    (directory / "subjects.json").write_bytes(tool._canonical(manifest))
    return directory, wheel, sdist, manifest


def test_exact_subjects_roundtrip_and_source_pins(tmp_path, monkeypatch):
    directory, wheel, sdist, manifest = subjects(tmp_path, monkeypatch)
    assert tool.verify(directory, COMMIT, TREE) == manifest
    assert manifest["status"] == "built_unreviewed"
    assert manifest["published"] is False
    assert [item["sha256"] for item in manifest["artifacts"]] == [
        "sha256:" + sha256(path.read_bytes()).hexdigest() for path in (wheel, sdist)
    ]
    with pytest.raises(tool.SubjectError, match="SOURCE_MISMATCH"):
        tool.verify(directory, "c" * 40, TREE)


@pytest.mark.parametrize("damage", ["wheel", "sdist", "extra", "symlink", "manifest", "duplicate"])
def test_subject_verifier_refuses_damaged_or_expanded_artifacts(tmp_path, monkeypatch, damage):
    directory, wheel, sdist, manifest = subjects(tmp_path, monkeypatch)
    if damage == "wheel":
        wheel.write_bytes(b"changed wheel bytes")
    elif damage == "sdist":
        sdist.write_bytes(b"changed source archive bytes")
    elif damage == "extra":
        (directory / "unreviewed.txt").write_text("extra")
    elif damage == "symlink":
        wheel.unlink()
        wheel.symlink_to(sdist)
    elif damage == "manifest":
        changed = deepcopy(manifest)
        changed["published"] = True
        (directory / "subjects.json").write_bytes(tool._canonical(changed))
    else:
        raw = tool._canonical(manifest).decode()
        (directory / "subjects.json").write_text(raw.replace('"published":false',
            '"published":false,"published":false'))
    with pytest.raises(tool.SubjectError):
        tool.verify(directory, COMMIT, TREE)


def test_collect_refuses_wrong_head_dirty_checkout_and_artifact_name(tmp_path, monkeypatch):
    directory, wheel, sdist, _ = subjects(tmp_path, monkeypatch)
    with pytest.raises(tool.SubjectError, match="SOURCE_MISMATCH"):
        tool.collect(tmp_path, "c" * 40, TREE, VERSION, wheel, sdist)
    monkeypatch.setattr(tool, "_git", lambda _checkout, *args: "dirty" if args[0] == "status" else {
        "HEAD": COMMIT, "HEAD^{tree}": TREE,
    }.get(args[-1], "https://github.com/bartytime4life/MEGALODON.git"))
    with pytest.raises(tool.SubjectError, match="SOURCE_MISMATCH"):
        tool.collect(tmp_path, COMMIT, TREE, VERSION, wheel, sdist)
    with pytest.raises(tool.SubjectError, match="ARTIFACT_MISMATCH"):
        tool._artifact(directory / "subjects.json", "wheel", wheel.name)


def test_offline_verify_does_not_query_git(tmp_path, monkeypatch):
    directory, *_ = subjects(tmp_path, monkeypatch)
    monkeypatch.setattr(tool, "_git", lambda *_: (_ for _ in ()).throw(AssertionError("git used")))
    assert tool.verify(directory, COMMIT, TREE)["source"] == {"commit": COMMIT, "tree": TREE}


def test_workflow_uses_exact_head_and_same_run_artifact_id():
    workflow = (ROOT / ".github/workflows/release-subject-evidence.yml").read_text()
    assert workflow.count("ref: ${{ github.event.pull_request.head.sha }}") == 2
    assert "artifact-ids: ${{ needs.build-subjects.outputs.artifact-id }}" in workflow
    assert "digest-mismatch: error" in workflow
    assert "--require-hashes --only-binary=:all:" in workflow
    assert "PIP_NO_INDEX=1" in workflow
    assert workflow.count("tools/release_subjects.py verify") == 2
