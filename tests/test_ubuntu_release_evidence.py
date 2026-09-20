from __future__ import annotations

from copy import deepcopy
import importlib.util
import inspect
import json
from pathlib import Path
import subprocess
import sys

import pytest
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ubuntu_release_evidence", ROOT / "tools/ubuntu_release_evidence.py",
)
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
CONTRACT = ROOT / "contracts/release-evidence/v1"
SCHEMA = json.loads((CONTRACT / "schema.json").read_text())
ACCEPTED = json.loads((CONTRACT / "fixtures/accepted/synthetic-incomplete.json").read_text())
VIOLATIONS = json.loads((CONTRACT / "fixtures/rejected/violations.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())


def mutate(document, changes):
    result = deepcopy(document)
    for pointer, value in changes.items():
        parts = pointer.lstrip("/").split("/")
        cursor = result
        for part in parts[:-1]:
            cursor = cursor[int(part)] if isinstance(cursor, list) else cursor[part]
        final = parts[-1]
        if isinstance(cursor, list):
            cursor[int(final)] = value
        else:
            cursor[final] = value
    return result


def test_schema_and_synthetic_fixture_are_closed_and_valid():
    Draft202012Validator.check_schema(SCHEMA)
    VALIDATOR.validate(ACCEPTED)
    assert tool.validate(deepcopy(ACCEPTED)) == ACCEPTED
    assert tool.digest(ACCEPTED).startswith("sha256:")
    assert len(tool.digest(ACCEPTED)) == 71


@pytest.mark.parametrize("case", VIOLATIONS, ids=lambda item: item["id"])
def test_rejected_semantic_fixtures_fail_closed(case):
    candidate = mutate(ACCEPTED, case["changes"])
    with pytest.raises(tool.EvidenceError) as caught:
        tool.validate(candidate)
    assert caught.value.code == case["reason"]
    assert not VALIDATOR.is_valid(candidate) or case["reason"] in {
        "SOURCE_MISMATCH", "CHECK_SET", "CANDIDATE_INCOMPLETE"
    }


@pytest.mark.parametrize("raw", [
    b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'\xff', b'{', b'[]',
    b'"forbidden-sentinel"', b'{} trailing',
])
def test_malformed_input_is_bounded_and_never_echoed(raw):
    with pytest.raises(tool.EvidenceError) as caught:
        tool.load(raw)
    assert caught.value.code == "INPUT_INVALID"
    assert "forbidden-sentinel" not in str(caught.value)
    with pytest.raises(tool.EvidenceError) as caught:
        tool.load(b" " * (tool.MAX_INPUT_BYTES + 1))
    assert caught.value.code == "INPUT_LIMIT"


def test_candidate_requires_every_check_and_both_ephemeral_subjects():
    candidate = deepcopy(ACCEPTED)
    candidate["status"] = "candidate_evidence"
    for check in candidate["checks"]:
        check.update(status="passed", result_sha256="sha256:" + "3" * 64)
    for artifact in candidate["artifacts"]:
        artifact.update(
            status="built_ephemeral", sha256="sha256:" + "4" * 64,
            size_bytes=1024,
        )
    VALIDATOR.validate(candidate)
    assert tool.validate(candidate)["status"] == "candidate_evidence"

    for index in range(len(candidate["checks"])):
        incomplete = deepcopy(candidate)
        incomplete["checks"][index].update(status="not_run", result_sha256=None)
        with pytest.raises(tool.EvidenceError, match="CANDIDATE_INCOMPLETE"):
            tool.validate(incomplete)
    for index in range(len(candidate["artifacts"])):
        incomplete = deepcopy(candidate)
        incomplete["artifacts"][index].update(status="not_run", sha256=None, size_bytes=None)
        with pytest.raises(tool.EvidenceError, match="CANDIDATE_INCOMPLETE"):
            tool.validate(incomplete)


def test_collector_reads_identity_only_and_leaves_execution_not_run(monkeypatch, tmp_path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    commit = "5" * 40
    tree = "6" * 40
    calls = []

    def fixed(argv, cwd):
        calls.append((tuple(argv), cwd))
        if argv[-1] == "HEAD":
            return commit
        if argv[-1] == "HEAD^{tree}":
            return tree
        if argv[:2] == ["git", "status"]:
            return ""
        if argv == ["systemd", "--version"]:
            return "systemd 255 (255.4-1ubuntu8.17)\nfeatures omitted"
        raise AssertionError(argv)

    monkeypatch.setattr(tool, "_run_fixed", fixed)
    monkeypatch.setattr(tool, "_os_release", lambda: {
        "ID": "ubuntu", "VERSION_ID": "24.04", "VERSION_CODENAME": "noble",
    })
    monkeypatch.setattr(tool.platform, "release", lambda: "6.8.0-79-generic")
    monkeypatch.setattr(tool.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(tool.platform, "python_implementation", lambda: "CPython")
    monkeypatch.setattr(tool.platform, "python_version", lambda: "3.12.3")
    monkeypatch.setattr(tool.importlib.metadata, "version", lambda _name: "25.0.1")

    manifest = tool.collect(checkout, commit, tree)
    VALIDATOR.validate(manifest)
    assert manifest["status"] == "incomplete"
    assert {item["status"] for item in manifest["checks"]} == {"not_run"}
    assert {item["state"] for item in manifest["optional_components"]} == {"not_checked"}
    assert {item["status"] for item in manifest["artifacts"]} == {"not_run"}
    assert all(value is False for value in manifest["effects"].values())
    assert [argv for argv, _cwd in calls] == [
        ("git", "rev-parse", "--verify", "HEAD"),
        ("git", "rev-parse", "--verify", "HEAD^{tree}"),
        ("git", "status", "--porcelain", "--untracked-files=normal"),
        ("systemd", "--version"),
    ]


def test_host_commands_are_fixed_bounded_and_never_use_shell(monkeypatch, tmp_path):
    observed = {}

    def run(argv, **kwargs):
        observed.update(argv=argv, kwargs=kwargs)
        return subprocess.CompletedProcess(argv, 0, stdout=b"ok\n", stderr=b"")

    monkeypatch.setattr(tool.subprocess, "run", run)
    assert tool._run_fixed(["git", "rev-parse", "--verify", "HEAD"], tmp_path) == "ok"
    assert observed["argv"] == ["git", "rev-parse", "--verify", "HEAD"]
    assert "shell" not in observed["kwargs"]
    assert observed["kwargs"]["timeout"] == 5
    assert observed["kwargs"]["stdin"] is subprocess.DEVNULL

    source = inspect.getsource(tool)
    assert "socket" not in source
    assert "urllib" not in source
    assert "requests" not in source
    assert "shell=True" not in source


def test_cli_validation_emits_canonical_packet_without_writing(tmp_path):
    source = tmp_path / "packet.json"
    source.write_text(json.dumps(ACCEPTED, indent=2))
    completed = subprocess.run(
        [sys.executable, str(ROOT / "tools/ubuntu_release_evidence.py"), "validate", str(source)],
        cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10, check=True,
    )
    result = json.loads(completed.stdout)
    assert completed.stderr == b""
    assert result["status"] == "validated"
    assert result["manifest"] == ACCEPTED
    assert result["manifest_sha256"] == tool.digest(ACCEPTED)
    assert list(tmp_path.iterdir()) == [source]
