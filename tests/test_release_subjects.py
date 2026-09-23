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
    assert workflow.count("-m build") == 1
    assert 'wheels=("$RUNNER_TEMP"/release-subjects/megalodon_defense-*.whl)' in workflow
    assert '--build-python "$RUNNER_TEMP/release-build/bin/python"' in workflow
    assert "--no-index --no-deps --no-cache-dir" in workflow
    assert 'cd "$RUNNER_TEMP/release-recovery-run"' in workflow
    assert workflow.count('--subjects-directory "$RUNNER_TEMP/release-subjects"') == 2
    assert '--subjects-directory "$RUNNER_TEMP/release-subject-roundtrip"' in workflow
    assert "artifact-ids: ${{ needs.build-subjects.outputs.recovery-artifact-id }}" in workflow
    assert "EXPECTED_PACKET_SHA256: ${{ needs.build-subjects.outputs.recovery-packet-sha256 }}" in workflow
    assert "path: ${{ runner.temp }}/release-recovery-receipts/installed-wheel-recovery.json" in workflow
    assert "if: always()" not in workflow
    assert workflow.count("digest-mismatch: error") == 2
    assert workflow.count("--github-actions-origin") == 3


def ci_context(monkeypatch):
    values = {
        "GITHUB_ACTIONS": "true", "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": tool.REPOSITORY, "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_JOB": "build-subjects",
        "GITHUB_REF": "refs/pull/396/merge",
        "GITHUB_WORKFLOW_REF": tool.REPOSITORY + "/" + tool.WORKFLOW + "@refs/pull/396/merge",
        "GITHUB_WORKFLOW_SHA": "c" * 40,
        "GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "2",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return values


def test_ci_origin_records_workflow_commit_separately_and_roundtrips(tmp_path, monkeypatch, capsys):
    directory, wheel, sdist, old = subjects(tmp_path, monkeypatch)
    ci_context(monkeypatch)
    manifest = tool.collect(tmp_path, COMMIT, TREE, VERSION, wheel, sdist,
                            github_actions_origin=True)
    assert manifest["producer"]["workflow_commit"] != COMMIT
    assert manifest["schema"] == tool.CI_SCHEMA
    assert manifest["producer"]["authentication"] == "not_performed"
    (directory / "subjects.json").write_bytes(tool._canonical(manifest))
    assert tool.verify(directory, COMMIT, TREE) == manifest
    monkeypatch.setenv("GITHUB_JOB", "subject-roundtrip")
    args = ["verify", "--directory", str(directory), "--expected-commit", COMMIT,
            "--expected-tree", TREE, "--github-actions-origin"]
    assert tool.main(args) == 0
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "3")
    assert tool.main(args) == 2
    assert "PRODUCER_MISMATCH" in capsys.readouterr().err
    # Ambient CI environment must never upgrade ordinary local collection.
    local = tool.collect(tmp_path, COMMIT, TREE, VERSION, wheel, sdist)
    assert local == old
    (directory / "subjects.json").write_bytes(tool._canonical(local))
    assert tool.main(args) == 2
    assert "PRODUCER_MISMATCH" in capsys.readouterr().err


@pytest.mark.parametrize("key,value", [
    ("GITHUB_ACTIONS", "false"), ("GITHUB_SERVER_URL", "https://evil.invalid"),
    ("GITHUB_REPOSITORY", "other/MEGALODON"), ("GITHUB_EVENT_NAME", "push"),
    ("GITHUB_JOB", "wheel-smoke"), ("GITHUB_JOB", "subject-roundtrip"),
    ("GITHUB_REF", "refs/pull/397/merge"), ("GITHUB_REF", ""),
    ("GITHUB_WORKFLOW_REF", "bartytime4life/MEGALODON/.github/workflows/ci.yml@refs/pull/396/merge"),
    ("GITHUB_WORKFLOW_REF", tool.REPOSITORY + "/" + tool.WORKFLOW + "@refs/heads/main"),
    ("GITHUB_WORKFLOW_SHA", "not-a-sha"), ("GITHUB_WORKFLOW_SHA", ""),
    ("GITHUB_RUN_ID", "0"), ("GITHUB_RUN_ID", "01"), ("GITHUB_RUN_ID", "9" * 21),
    ("GITHUB_RUN_ATTEMPT", "0"), ("GITHUB_RUN_ATTEMPT", "2\n"),
])
def test_ci_collection_refuses_invalid_or_missing_context(tmp_path, monkeypatch, key, value):
    _, wheel, sdist, _ = subjects(tmp_path, monkeypatch)
    ci_context(monkeypatch)
    monkeypatch.setenv(key, value)
    with pytest.raises(tool.SubjectError, match="PRODUCER_"):
        tool.collect(tmp_path, COMMIT, TREE, VERSION, wheel, sdist,
                     github_actions_origin=True)


@pytest.mark.parametrize("fault", ["url", "job", "authentication", "basis", "extra", "type", "missing"])
def test_retained_origin_is_a_closed_declaration(tmp_path, monkeypatch, fault):
    directory, wheel, sdist, _ = subjects(tmp_path, monkeypatch)
    ci_context(monkeypatch)
    manifest = tool.collect(tmp_path, COMMIT, TREE, VERSION, wheel, sdist,
                            github_actions_origin=True)
    origin = manifest["producer"]
    if fault == "url":
        origin["workflow"] = "https://evil.invalid/builder"
    elif fault == "job":
        origin["job"] = "wheel-smoke"
    elif fault == "authentication":
        origin["authentication"] = "github_actions"
    elif fault == "basis":
        origin["basis"] = "local_checkout"
    elif fault == "extra":
        origin["builder_url"] = "https://evil.invalid"
    elif fault == "type":
        origin["run_attempt"] = True
    else:
        del origin["workflow_commit"]
    (directory / "subjects.json").write_bytes(tool._canonical(manifest))
    with pytest.raises(tool.SubjectError, match="PRODUCER_INVALID"):
        tool.verify(directory, COMMIT, TREE)
