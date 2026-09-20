from __future__ import annotations

from copy import deepcopy
import importlib.util
import inspect
import json
import os
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
    candidate["basis"] = "github_actions"
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


@pytest.mark.parametrize("changes,reason,schema_rejects", [
    ({"/effects/release_published": 0}, "AUTHORITY_CLAIM", True),
    ({"/effects/model_invoked": None}, "AUTHORITY_CLAIM", True),
    ({"/generated_at": "2026-02-30T00:00:00Z"}, "INPUT_INVALID", False),
    ({"/platform/pip_version": "1." + "2" * 31}, "INPUT_INVALID", True),
    ({"/platform/systemd_version": "255 (" + "a" * 59 + ")"}, "INPUT_INVALID", True),
])
def test_semantic_validator_rejects_contract_invalid_edge_cases(
    changes, reason, schema_rejects,
):
    candidate = mutate(ACCEPTED, changes)
    if schema_rejects:
        assert not VALIDATOR.is_valid(candidate)
    with pytest.raises(tool.EvidenceError) as caught:
        tool.validate(candidate)
    assert caught.value.code == reason


def test_synthetic_fixture_cannot_be_promoted_to_candidate_evidence():
    candidate = deepcopy(ACCEPTED)
    candidate["status"] = "candidate_evidence"
    for check in candidate["checks"]:
        check.update(status="passed", result_sha256="sha256:" + "3" * 64)
    for artifact in candidate["artifacts"]:
        artifact.update(
            status="built_ephemeral", sha256="sha256:" + "4" * 64, size_bytes=1024,
        )
    assert not VALIDATOR.is_valid(candidate)
    with pytest.raises(tool.EvidenceError, match="CANDIDATE_INCOMPLETE"):
        tool.validate(candidate)


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
        if argv == ["git", "remote", "get-url", "origin"]:
            return "https://github.com/bartytime4life/MEGALODON"
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
    assert manifest["gates"]["license"] == {"status": "not_assessed", "blocker": None}
    assert "255" not in " ".join(manifest["limitations"])
    assert {item["status"] for item in manifest["checks"]} == {"not_run"}
    assert {item["state"] for item in manifest["optional_components"]} == {"not_checked"}
    assert {item["status"] for item in manifest["artifacts"]} == {"not_run"}
    assert all(value is False for value in manifest["effects"].values())
    assert [argv for argv, _cwd in calls] == [
        ("git", "rev-parse", "--verify", "HEAD"),
        ("git", "rev-parse", "--verify", "HEAD^{tree}"),
        ("git", "status", "--porcelain", "--untracked-files=normal"),
        ("git", "remote", "get-url", "origin"),
        ("systemd", "--version"),
    ]


def test_collector_rejects_wrong_repository_origin(monkeypatch, tmp_path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()

    def fixed(argv, _cwd):
        if argv == ["git", "rev-parse", "--verify", "HEAD"]:
            return "5" * 40
        if argv == ["git", "rev-parse", "--verify", "HEAD^{tree}"]:
            return "6" * 40
        if argv[:2] == ["git", "status"]:
            return ""
        if argv == ["git", "remote", "get-url", "origin"]:
            return "https://github.com/example/unrelated.git"
        raise AssertionError(argv)

    monkeypatch.setattr(tool, "_run_fixed", fixed)
    with pytest.raises(tool.EvidenceError, match="SOURCE_REPOSITORY"):
        tool.collect(checkout, "5" * 40, "6" * 40)


def test_empty_systemd_output_returns_bounded_cli_refusal(monkeypatch, tmp_path, capsys):
    def fixed(argv, _cwd):
        if argv == ["git", "remote", "get-url", "origin"]:
            return "https://github.com/bartytime4life/MEGALODON"
        if argv[-1] == "HEAD":
            return "5" * 40
        if argv[-1] == "HEAD^{tree}":
            return "6" * 40
        return ""

    monkeypatch.setattr(tool, "_run_fixed", fixed)
    assert tool.main([
        "collect", "--checkout", str(tmp_path),
        "--declared-commit", "5" * 40, "--declared-tree", "6" * 40,
    ]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "schema_version": "ubuntu-24.04-evidence-validation-v1",
        "status": "blocked", "reason": "HOST_TOOL",
    }


def test_unassessed_license_preserves_historical_packet_and_all_other_gates():
    candidate = deepcopy(ACCEPTED)
    candidate["gates"]["license"] = {"status": "not_assessed", "blocker": None}
    VALIDATOR.validate(candidate)
    assert tool.validate(candidate) == candidate
    assert tool.validate(deepcopy(ACCEPTED)) == ACCEPTED
    for license_gate in (
        {"status": "passed", "blocker": None},
        {"status": "not_assessed", "blocker": "https://github.com/bartytime4life/MEGALODON/issues/255"},
        {"status": "blocked", "blocker": None},
        {"status": "not_assessed", "blocker": None, "approved": True},
    ):
        invalid = deepcopy(candidate)
        invalid["gates"]["license"] = license_gate
        assert not VALIDATOR.is_valid(invalid)
        with pytest.raises(tool.EvidenceError, match="AUTHORITY_CLAIM"):
            tool.validate(invalid)


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


@pytest.mark.parametrize("pointer,reason", [
    ("/basis", "INPUT_INVALID"),
    ("/status", "INPUT_INVALID"),
    ("/platform/os_id", "INPUT_INVALID"),
    ("/platform/version_id", "INPUT_INVALID"),
    ("/platform/version_codename", "INPUT_INVALID"),
    ("/platform/python_implementation", "INPUT_INVALID"),
    ("/platform/architecture", "INPUT_INVALID"),
    ("/optional_components/0/state", "OPTIONAL_STATE"),
    ("/checks/0/status", "INPUT_INVALID"),
    ("/artifacts/0/status", "ARTIFACT_SET"),
])
@pytest.mark.parametrize("value", [[], {"private-sentinel": "do not echo"}])
def test_container_values_in_scalar_fields_return_closed_refusal(
    pointer, reason, value, tmp_path, capsys,
):
    candidate = mutate(ACCEPTED, {pointer: value})
    assert not VALIDATOR.is_valid(candidate)
    with pytest.raises(tool.EvidenceError) as caught:
        tool.validate(candidate)
    assert caught.value.code == reason
    source = tmp_path / "private-sentinel.json"
    source.write_text(json.dumps(candidate))
    assert tool.main(["validate", str(source)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "schema_version": "ubuntu-24.04-evidence-validation-v1",
        "status": "blocked", "reason": reason,
    }
    assert "private-sentinel" not in captured.err


@pytest.mark.parametrize("raw,reason", [
    (b'{"private-sentinel":"\\ud800"}', "INPUT_INVALID"),
    (b'{"\\udfff":"private-sentinel"}', "INPUT_INVALID"),
    (b'{"x":' + b'[' * 2000 + b'0' + b']' * 2000 + b'}', "INPUT_LIMIT"),
])
def test_malformed_unicode_and_nesting_have_bounded_cli_receipts(raw, reason, tmp_path):
    source = tmp_path / "private-sentinel.json"
    source.write_bytes(raw)
    completed = subprocess.run(
        [sys.executable, str(ROOT / "tools/ubuntu_release_evidence.py"), "validate", str(source)],
        cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
    )
    assert completed.returncode == 2
    assert completed.stdout == b""
    assert json.loads(completed.stderr) == {
        "schema_version": "ubuntu-24.04-evidence-validation-v1",
        "status": "blocked", "reason": reason,
    }


def test_regular_file_budget_at_limit_and_first_excess_byte(tmp_path, capsys):
    source = tmp_path / "packet.json"
    raw = tool.canonical(ACCEPTED)
    source.write_bytes(raw + b" " * (tool.MAX_INPUT_BYTES - len(raw)))
    assert tool.main(["validate", str(source)]) == 0
    assert json.loads(capsys.readouterr().out)["manifest"] == ACCEPTED
    with source.open("ab") as stream:
        stream.write(b" ")
    assert tool.main(["validate", str(source)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err)["reason"] == "INPUT_LIMIT"


def test_reader_requests_only_budget_plus_one_byte(monkeypatch, tmp_path):
    source = tmp_path / "packet.json"
    source.write_bytes(b"{}")
    original = tool.os.fdopen
    reads = []

    class TrackedStream:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def read(self, size):
            reads.append(size)
            assert size == tool.MAX_INPUT_BYTES + 1
            return self.stream.read(size)

    monkeypatch.setattr(tool.os, "fdopen", lambda *args, **kwargs: TrackedStream(original(*args, **kwargs)))
    assert tool.read_manifest(source) == b"{}"
    assert reads == [tool.MAX_INPUT_BYTES + 1]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO refusal")
def test_fifo_without_writer_is_refused_without_blocking(tmp_path):
    source = tmp_path / "private-sentinel.fifo"
    os.mkfifo(source)
    completed = subprocess.run(
        [sys.executable, str(ROOT / "tools/ubuntu_release_evidence.py"), "validate", str(source)],
        cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
    )
    assert completed.returncode == 2
    assert completed.stdout == b""
    assert json.loads(completed.stderr) == {
        "schema_version": "ubuntu-24.04-evidence-validation-v1",
        "status": "blocked", "reason": "INPUT_INVALID",
    }


def identity_wrapper():
    return {
        "schema_version": "ubuntu-24.04-evidence-validation-v1",
        "status": "validated",
        "manifest_sha256": tool.digest(ACCEPTED),
        "manifest": deepcopy(ACCEPTED),
    }


def test_verify_packet_cli_round_trip_is_offline_and_read_only(monkeypatch, tmp_path, capsys):
    source = tmp_path / "identity.json"
    source.write_bytes(tool.canonical(identity_wrapper()))
    original = source.read_bytes()

    def forbidden(*args, **kwargs):
        pytest.fail("packet verification must not inspect host identity or run a command")

    monkeypatch.setattr(tool, "collect", forbidden)
    monkeypatch.setattr(tool, "_run_fixed", forbidden)
    monkeypatch.setattr(tool.subprocess, "run", forbidden)
    assert tool.main([
        "verify-packet", str(source),
        "--expected-commit", ACCEPTED["source"]["observed_commit"],
        "--expected-tree", ACCEPTED["source"]["observed_tree"],
    ]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.encode() == original + b"\n"
    assert source.read_bytes() == original
    assert list(tmp_path.iterdir()) == [source]


@pytest.mark.parametrize("changes,reason", [
    ({"/status": "blocked"}, "PACKET_INVALID"),
    ({"/schema_version": "unknown"}, "PACKET_INVALID"),
    ({"/manifest_sha256": "sha256:" + "0" * 64}, "DIGEST_MISMATCH"),
    ({"/manifest_sha256": []}, "PACKET_INVALID"),
    ({"/manifest_sha256": "private-sentinel"}, "PACKET_INVALID"),
    ({"/manifest": None}, "INPUT_INVALID"),
    ({"/manifest/generated_at": "2026-09-21T00:00:00Z"}, "DIGEST_MISMATCH"),
    ({"/manifest/effects/model_invoked": True}, "AUTHORITY_CLAIM"),
])
def test_verify_packet_rejects_tampering_with_fixed_receipt(changes, reason, tmp_path, capsys):
    packet = mutate(identity_wrapper(), changes)
    source = tmp_path / "private-sentinel.json"
    source.write_text(json.dumps(packet))
    assert tool.main([
        "verify-packet", str(source),
        "--expected-commit", ACCEPTED["source"]["observed_commit"],
        "--expected-tree", ACCEPTED["source"]["observed_tree"],
    ]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "schema_version": "ubuntu-24.04-evidence-validation-v1",
        "status": "blocked", "reason": reason,
    }


def test_verify_packet_requires_closed_wrapper_and_external_source_pins():
    packet = identity_wrapper()
    commit = ACCEPTED["source"]["observed_commit"]
    tree = ACCEPTED["source"]["observed_tree"]
    for key in packet:
        missing = deepcopy(packet)
        del missing[key]
        with pytest.raises(tool.EvidenceError, match="PACKET_INVALID"):
            tool.verify_packet(missing, commit, tree)
    with pytest.raises(tool.EvidenceError, match="PACKET_INVALID"):
        tool.verify_packet({**packet, "approved": True}, commit, tree)
    for expected_commit, expected_tree, reason in (
        ("f" * 40, tree, "SOURCE_MISMATCH"),
        (commit, "e" * 40, "SOURCE_MISMATCH"),
        ([], tree, "INPUT_INVALID"),
        (commit, "not-a-sha", "INPUT_INVALID"),
    ):
        with pytest.raises(tool.EvidenceError, match=reason):
            tool.verify_packet(packet, expected_commit, expected_tree)


def test_consistent_packet_does_not_authenticate_self_asserted_host_facts():
    packet = identity_wrapper()
    packet["manifest"]["platform"]["kernel_release"] = "6.8.0-self-asserted"
    packet["manifest_sha256"] = tool.digest(packet["manifest"])
    manifest = tool.verify_packet(
        packet, ACCEPTED["source"]["observed_commit"], ACCEPTED["source"]["observed_tree"],
    )
    assert manifest["basis"] == "synthetic_contract_fixture"
    assert manifest["status"] == "incomplete"
    assert {row["status"] for row in manifest["checks"]} == {"not_run"}
    assert manifest["gates"]["release_authority"] == "not_authorized"
