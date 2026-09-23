from __future__ import annotations

from copy import deepcopy
import importlib.util
import inspect
import json
from pathlib import Path
import stat
import tomllib

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_evidence_packet", ROOT / "tools/release_evidence_packet.py",
)
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
FIXTURE = json.loads(
    (ROOT / "contracts/release-evidence/v1/fixtures/accepted/synthetic-incomplete.json").read_text()
)
VERSION = "0.1.0"
GENERATED_AT = "2026-09-20T23:59:59Z"


def _json_bytes(value):
    return tool.identity.canonical(value) + b"\n"


def producer():
    return {"basis": "github_actions", "authentication": "not_performed",
        "repository": tool.REPOSITORY, "workflow": tool.subjects.WORKFLOW,
        "workflow_ref": tool.REPOSITORY + "/" + tool.subjects.WORKFLOW + "@refs/pull/396/merge",
        "workflow_commit": "c" * 40, "job": "build-subjects", "run_id": "12345", "run_attempt": "2"}


def origin_inputs(wheel):
    return {"subjects_directory": wheel.parent,
        "expected_subjects_sha256": tool._sha256((wheel.parent / "subjects.json").read_bytes())}


def generate_packet(*args, **kwargs):
    return tool.generate_packet(*args, **origin_inputs(args[1]), **kwargs)


def verify_packet_directory(*args, **kwargs):
    return tool.verify_packet_directory(*args,
        expected_subjects_sha256=origin_inputs(args[1])["expected_subjects_sha256"], **kwargs)


def make_inputs(tmp_path: Path):
    subject_dir = tmp_path / "subjects"
    subject_dir.mkdir()
    wheel = subject_dir / f"megalodon_defense-{VERSION}-py3-none-any.whl"
    sdist = subject_dir / f"megalodon_defense-{VERSION}.tar.gz"
    wheel.write_bytes(b"bounded synthetic wheel subject\n")
    sdist.write_bytes(b"bounded synthetic sdist subject\n")

    manifest = deepcopy(FIXTURE)
    manifest["basis"] = "github_actions"
    manifest["status"] = "candidate_evidence"
    manifest["generated_at"] = "2026-09-20T23:58:00Z"
    for index, check in enumerate(manifest["checks"]):
        check.update(
            status="passed",
            output_bytes=index + 1,
            result_sha256="sha256:" + f"{index + 1:064x}",
            notes="Bounded retained result.",
        )
    for row, path in zip(manifest["artifacts"], (wheel, sdist), strict=True):
        raw = path.read_bytes()
        row.update(
            status="built_ephemeral",
            sha256=tool._sha256(raw),
            size_bytes=len(raw),
            published=False,
        )
    wrapper = {
        "schema_version": "ubuntu-24.04-evidence-validation-v1",
        "status": "validated",
        "manifest_sha256": tool.identity.digest(manifest),
        "manifest": manifest,
    }
    subjects = {"schema": tool.subjects.CI_SCHEMA, "status": "built_unreviewed",
        "source": {"commit": manifest["source"]["observed_commit"], "tree": manifest["source"]["observed_tree"]},
        "package_version": VERSION, "artifacts": [tool.subjects._artifact(wheel, "wheel", wheel.name),
            tool.subjects._artifact(sdist, "sdist", sdist.name)], "published": False,
        "limitations": list(tool.subjects.LIMITATIONS), "producer": producer()}
    (subject_dir / "subjects.json").write_bytes(_json_bytes(subjects))
    candidate = tmp_path / "candidate.json"
    candidate.write_bytes(_json_bytes(wrapper))
    return candidate, wheel, sdist, wrapper


def generate(tmp_path: Path):
    candidate, wheel, sdist, wrapper = make_inputs(tmp_path)
    output = tmp_path / "packet"
    receipt = generate_packet(
        candidate, wheel, sdist, output, VERSION, GENERATED_AT,
        wrapper["manifest"]["source"]["observed_commit"],
        wrapper["manifest"]["source"]["observed_tree"],
    )
    return output, candidate, wheel, sdist, wrapper, receipt


def test_generator_emits_canonical_bound_packet_and_privacy_minimized_receipt(tmp_path):
    private_root = tmp_path / "private-user-and-host-sentinel"
    private_root.mkdir()
    output, _candidate, wheel, sdist, wrapper, receipt = generate(private_root)

    assert set(path.name for path in output.iterdir()) == set(tool.ORIGIN_PACKET_FILES)
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir())
    assert receipt["status"] == "binding_verified"
    assert receipt["operation"] == "generated"
    assert receipt["authentication"] == "not_performed"
    assert receipt["effects"] == tool.EFFECTS
    assert str(private_root) not in json.dumps(receipt)

    for path in output.iterdir():
        value = json.loads(path.read_text())
        assert path.read_bytes() == _json_bytes(value)
        assert str(private_root) not in path.read_text()

    sbom = json.loads((output / "megalodon.cdx.json").read_text())
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.7"
    assert sbom["metadata"]["component"]["purl"] == "pkg:pypi/megalodon-defense@0.1.0"
    assert sbom["metadata"]["component"]["licenses"] == [{"license": {"id": "Apache-2.0"}}]
    assert [row["name"] for row in sbom["components"]] == [wheel.name, sdist.name]

    provenance = json.loads((output / "provenance.intoto.json").read_text())
    assert provenance["_type"] == "https://in-toto.io/Statement/v1"
    assert provenance["predicateType"] == "https://slsa.dev/provenance/v1"
    commit = wrapper["manifest"]["source"]["observed_commit"]
    assert provenance["predicate"]["runDetails"] == {
        "builder": {"id": tool.REPOSITORY_URL + "/" + tool.subjects.WORKFLOW + "@" + producer()["workflow_commit"]},
        "metadata": {"invocationId": tool.REPOSITORY_URL + "/actions/runs/12345/attempts/2"},
    }
    assert provenance["predicate"]["buildDefinition"]["externalParameters"]["workflow"] == tool.subjects.WORKFLOW
    assert provenance["predicate"]["buildDefinition"]["externalParameters"]["job"] == "build-subjects"
    assert [subject["name"] for subject in provenance["subject"]] == [wheel.name, sdist.name]

    packet = json.loads((output / "packet.json").read_text())
    assert packet["status"] == "generated_unreviewed"
    assert packet["candidate_evidence"]["manifest_sha256"] == wrapper["manifest_sha256"]
    assert packet["effects"] == tool.EFFECTS
    assert "unselected_environment_variables" in packet["privacy"]["excluded"]
    assert "environment_dumps" in packet["privacy"]["excluded"]
    assert packet["producer_declaration"]["authentication"] == "not_performed"
    assert receipt["origin_binding"] == "declared_origin_bound"
    assert packet["package"]["runtime_dependencies"] == []


def test_generation_is_deterministic_for_the_same_explicit_inputs(tmp_path):
    candidate, wheel, sdist, wrapper = make_inputs(tmp_path)
    commit = wrapper["manifest"]["source"]["observed_commit"]
    tree = wrapper["manifest"]["source"]["observed_tree"]
    outputs = []
    for name in ("first", "second"):
        output = tmp_path / name
        generate_packet(
            candidate, wheel, sdist, output, VERSION, GENERATED_AT, commit, tree,
        )
        outputs.append(output)
    for filename in tool.ORIGIN_PACKET_FILES:
        assert (outputs[0] / filename).read_bytes() == (outputs[1] / filename).read_bytes()


def test_legacy_packet_verification_preserves_historical_bytes_and_origin_limit(tmp_path):
    fixture = json.loads((ROOT / "tests/fixtures/release-packet-v1.json").read_text())
    output = tmp_path / "legacy"
    output.mkdir()
    for name, raw in fixture["files"].items():
        (output / name).write_text(raw)
    wheel = tmp_path / f"megalodon_defense-{VERSION}-py3-none-any.whl"
    sdist = tmp_path / f"megalodon_defense-{VERSION}.tar.gz"
    wheel.write_text(fixture["wheel"])
    sdist.write_text(fixture["sdist"])
    receipt = tool.verify_packet_directory(output, wheel, sdist,
        fixture["source"]["commit"], fixture["source"]["tree"])
    assert receipt["origin_binding"] == "legacy_origin_unbound"
    assert receipt["authentication"] == "not_performed"
    assert {p.name: p.read_text() for p in output.iterdir()} == fixture["files"]
    with pytest.raises(tool.PacketError, match="PRODUCER_REQUIRED"):
        tool.generate_packet(output / "candidate-evidence.json", wheel, sdist,
            tmp_path / "new", VERSION, GENERATED_AT,
            fixture["source"]["commit"], fixture["source"]["tree"])
    assert not (tmp_path / "new").exists()


@pytest.mark.parametrize("fault,reason", [
    ("missing", "PRODUCER_REQUIRED"), ("legacy", "PRODUCER_REQUIRED"),
    ("local", "PRODUCER_INVALID"), ("wrong_source", "PRODUCER_INVALID"),
    ("wrong_version", "PRODUCER_INVALID"), ("wrong_workflow", "PRODUCER_INVALID"),
    ("wrong_job", "PRODUCER_INVALID"), ("extra_url", "PRODUCER_INVALID"),
    ("changed_origin_with_stale_pin", "PRODUCER_DIGEST_MISMATCH"),
    ("wrong_digest", "PRODUCER_DIGEST_MISMATCH"),
    ("extra_file", "PRODUCER_INVALID"),
])
def test_generation_requires_exact_closed_externally_pinned_producer(tmp_path, fault, reason):
    candidate, wheel, sdist, wrapper = make_inputs(tmp_path)
    pins = origin_inputs(wheel)
    path = wheel.parent / "subjects.json"
    manifest = json.loads(path.read_bytes())
    if fault == "missing":
        pins = {}
    elif fault == "legacy":
        manifest["schema"] = tool.subjects.SCHEMA
        del manifest["producer"]
    elif fault == "local":
        manifest["producer"]["basis"] = "local_checkout"
    elif fault == "wrong_source":
        manifest["source"]["commit"] = "e" * 40
    elif fault == "wrong_version":
        manifest["package_version"] = "9.9.9"
    elif fault == "wrong_workflow":
        manifest["producer"]["workflow"] = ".github/workflows/ci.yml"
    elif fault == "wrong_job":
        manifest["producer"]["job"] = "wheel-smoke"
    elif fault == "extra_url":
        manifest["producer"]["builder_url"] = "https://evil.invalid"
    elif fault == "changed_origin_with_stale_pin":
        manifest["producer"]["run_id"] = "54321"
    elif fault == "wrong_digest":
        pins["expected_subjects_sha256"] = "sha256:" + "0" * 64
    else:
        (wheel.parent / "unexpected").write_text("not a subject")
    path.write_bytes(_json_bytes(manifest))
    if fault not in {"missing", "wrong_digest", "changed_origin_with_stale_pin"}:
        pins = origin_inputs(wheel)
    output = tmp_path / "rejected"
    with pytest.raises(tool.PacketError, match=reason):
        tool.generate_packet(candidate, wheel, sdist, output, VERSION, GENERATED_AT,
            wrapper["manifest"]["source"]["observed_commit"],
            wrapper["manifest"]["source"]["observed_tree"], **pins)
    assert not output.exists()
    assert not list(tmp_path.glob(".megalodon-release-evidence-*"))


def test_new_verification_requires_external_subject_digest_and_refuses_origin_tampering(tmp_path):
    output, _candidate, wheel, sdist, wrapper, _receipt = generate(tmp_path)
    commit = wrapper["manifest"]["source"]["observed_commit"]
    tree = wrapper["manifest"]["source"]["observed_tree"]
    with pytest.raises(tool.PacketError, match="PRODUCER_DIGEST_MISMATCH"):
        tool.verify_packet_directory(output, wheel, sdist, commit, tree)
    path = output / "subjects.json"
    value = json.loads(path.read_bytes())
    value["producer"]["workflow_commit"] = "f" * 40
    path.write_bytes(_json_bytes(value))
    with pytest.raises(tool.PacketError, match="PRODUCER_DIGEST_MISMATCH"):
        verify_packet_directory(output, wheel, sdist, commit, tree)


def test_arbitrary_candidate_bytes_cannot_borrow_a_different_subject_declaration(tmp_path):
    candidate, wheel, sdist, wrapper = make_inputs(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    _, other_wheel, other_sdist, _ = make_inputs(other)
    other_wheel.write_bytes(b"different retained wheel")
    subject_file = other_wheel.parent / "subjects.json"
    value = json.loads(subject_file.read_bytes())
    value["artifacts"][0] = tool.subjects._artifact(other_wheel, "wheel", other_wheel.name)
    subject_file.write_bytes(_json_bytes(value))
    with pytest.raises(tool.PacketError, match="PRODUCER_SUBJECT_MISMATCH"):
        tool.generate_packet(candidate, wheel, sdist, tmp_path / "packet", VERSION, GENERATED_AT,
            wrapper["manifest"]["source"]["observed_commit"],
            wrapper["manifest"]["source"]["observed_tree"], **origin_inputs(other_wheel))


def test_verifier_is_offline_read_only_and_recomputes_artifacts(monkeypatch, tmp_path):
    output, _candidate, wheel, sdist, wrapper, _receipt = generate(tmp_path)
    original = {path.name: path.read_bytes() for path in output.iterdir()}

    def forbidden(*_args, **_kwargs):
        pytest.fail("offline verification must not execute host commands")

    monkeypatch.setattr(tool.identity, "_run_fixed", forbidden)
    monkeypatch.setattr(tool.identity, "collect", forbidden)
    receipt = verify_packet_directory(
        output, wheel, sdist,
        wrapper["manifest"]["source"]["observed_commit"],
        wrapper["manifest"]["source"]["observed_tree"],
    )
    assert receipt["operation"] == "verified"
    assert {path.name: path.read_bytes() for path in output.iterdir()} == original
    source = inspect.getsource(tool)
    for forbidden_name in ("subprocess", "socket", "urllib", "requests", "pip install", "python -m build"):
        assert forbidden_name not in source


@pytest.mark.parametrize("filename,reason", [
    ("megalodon.cdx.json", "SBOM_MISMATCH"),
    ("provenance.intoto.json", "PROVENANCE_MISMATCH"),
    ("packet.json", "BINDING_MISMATCH"),
])
def test_verifier_rejects_canonical_document_tampering(tmp_path, filename, reason):
    output, _candidate, wheel, sdist, wrapper, _receipt = generate(tmp_path)
    value = json.loads((output / filename).read_text())
    if filename == "megalodon.cdx.json":
        value["metadata"]["component"]["version"] = "9.9.9"
    elif filename == "provenance.intoto.json":
        value["predicate"]["runDetails"]["builder"]["id"] = "https://example.invalid/builder"
    else:
        value["documents"][0]["sha256"] = "sha256:" + "0" * 64
    (output / filename).write_bytes(_json_bytes(value))
    with pytest.raises(tool.PacketError, match=reason):
        verify_packet_directory(
            output, wheel, sdist,
            wrapper["manifest"]["source"]["observed_commit"],
            wrapper["manifest"]["source"]["observed_tree"],
        )


def test_verifier_rejects_noncanonical_json_and_wrong_file_set(tmp_path):
    output, _candidate, wheel, sdist, wrapper, _receipt = generate(tmp_path)
    commit = wrapper["manifest"]["source"]["observed_commit"]
    tree = wrapper["manifest"]["source"]["observed_tree"]
    with (output / "packet.json").open("ab") as stream:
        stream.write(b" ")
    with pytest.raises(tool.PacketError, match="NONCANONICAL_JSON"):
        verify_packet_directory(output, wheel, sdist, commit, tree)
    (output / "packet.json").write_bytes(_json_bytes(json.loads((output / "packet.json").read_text())))
    (output / "unexpected-private-file").write_text("do not read")
    with pytest.raises(tool.PacketError, match="FILE_SET"):
        verify_packet_directory(output, wheel, sdist, commit, tree)


def test_artifact_bytes_names_and_candidate_digests_are_fail_closed(tmp_path):
    candidate, wheel, sdist, wrapper = make_inputs(tmp_path)
    commit = wrapper["manifest"]["source"]["observed_commit"]
    tree = wrapper["manifest"]["source"]["observed_tree"]

    wheel.write_bytes(wheel.read_bytes() + b"changed")
    with pytest.raises(tool.PacketError, match="ARTIFACT_MISMATCH"):
        generate_packet(
            candidate, wheel, sdist, tmp_path / "changed", VERSION, GENERATED_AT, commit, tree,
        )
    wheel.rename(wheel.parent / "unexpected.whl")
    with pytest.raises(tool.PacketError, match="ARTIFACT_INVALID"):
        generate_packet(
            candidate, wheel.parent / "unexpected.whl", sdist, tmp_path / "wrong-name",
            VERSION, GENERATED_AT, commit, tree,
        )


def test_incomplete_candidate_and_external_source_mismatch_are_refused(tmp_path):
    candidate, wheel, sdist, wrapper = make_inputs(tmp_path)
    wrapper["manifest"]["status"] = "incomplete"
    wrapper["manifest"]["checks"][0].update(status="not_run", result_sha256=None)
    wrapper["manifest_sha256"] = tool.identity.digest(wrapper["manifest"])
    candidate.write_bytes(_json_bytes(wrapper))
    commit = wrapper["manifest"]["source"]["observed_commit"]
    tree = wrapper["manifest"]["source"]["observed_tree"]
    with pytest.raises(tool.PacketError, match="CANDIDATE_INCOMPLETE"):
        generate_packet(
            candidate, wheel, sdist, tmp_path / "incomplete", VERSION, GENERATED_AT, commit, tree,
        )
    with pytest.raises(tool.PacketError, match="SOURCE_MISMATCH"):
        generate_packet(
            candidate, wheel, sdist, tmp_path / "wrong-source", VERSION, GENERATED_AT,
            "f" * 40, tree,
        )


def test_noncanonical_candidate_is_refused_instead_of_normalized(tmp_path):
    candidate, wheel, sdist, wrapper = make_inputs(tmp_path)
    candidate.write_bytes(candidate.read_bytes() + b" ")
    with pytest.raises(tool.PacketError, match="NONCANONICAL_JSON"):
        generate_packet(
            candidate, wheel, sdist, tmp_path / "noncanonical", VERSION, GENERATED_AT,
            wrapper["manifest"]["source"]["observed_commit"],
            wrapper["manifest"]["source"]["observed_tree"],
        )


def test_generator_never_overwrites_an_existing_output(tmp_path):
    candidate, wheel, sdist, wrapper = make_inputs(tmp_path)
    output = tmp_path / "packet"
    output.mkdir()
    marker = output / "private-marker"
    marker.write_text("preserve")
    with pytest.raises(tool.PacketError, match="OUTPUT_EXISTS"):
        generate_packet(
            candidate, wheel, sdist, output, VERSION, GENERATED_AT,
            wrapper["manifest"]["source"]["observed_commit"],
            wrapper["manifest"]["source"]["observed_tree"],
        )
    assert marker.read_text() == "preserve"


def test_atomic_publish_refuses_a_target_created_at_the_rename_boundary(tmp_path):
    staging = tmp_path / "staging"
    target = tmp_path / "target"
    staging.mkdir()
    target.mkdir()
    source_marker = staging / "source-marker"
    target_marker = target / "target-marker"
    source_marker.write_text("source")
    target_marker.write_text("preserve")

    with pytest.raises(tool.PacketError, match="OUTPUT_EXISTS"):
        tool._rename_noreplace(staging, target)

    assert source_marker.read_text() == "source"
    assert target_marker.read_text() == "preserve"


def test_cli_refusal_is_bounded_and_does_not_echo_private_paths(tmp_path, capsys):
    private = tmp_path / "private-user-host-sentinel.json"
    private.write_text("not-json")
    assert tool.main([
        "generate",
        "--candidate", str(private),
        "--wheel", str(private),
        "--sdist", str(private),
        "--output", str(tmp_path / "output"),
        "--package-version", VERSION,
        "--generated-at", GENERATED_AT,
        "--expected-commit", "a" * 40,
        "--expected-tree", "b" * 40,
        "--subjects-directory", str(tmp_path),
        "--expected-subjects-sha256", "sha256:" + "0" * 64,
    ]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "schema_version": "megalodon-release-evidence-verification-v1",
        "status": "blocked",
        "reason": "CANDIDATE_INVALID",
    }
    assert "private-user-host-sentinel" not in captured.err


def test_canonical_sbom_profile_matches_current_package_metadata():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    namespace = {}
    exec((ROOT / "megalodon/__init__.py").read_text(), namespace)
    assert project["name"] == tool.PACKAGE_NAME
    assert project["license"] == "Apache-2.0"
    assert project["dependencies"] == []
    assert namespace["__version__"] == VERSION
