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


def make_inputs(tmp_path: Path):
    wheel = tmp_path / f"megalodon_defense-{VERSION}-py3-none-any.whl"
    sdist = tmp_path / f"megalodon_defense-{VERSION}.tar.gz"
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
    candidate = tmp_path / "candidate.json"
    candidate.write_bytes(_json_bytes(wrapper))
    return candidate, wheel, sdist, wrapper


def generate(tmp_path: Path):
    candidate, wheel, sdist, wrapper = make_inputs(tmp_path)
    output = tmp_path / "packet"
    receipt = tool.generate_packet(
        candidate, wheel, sdist, output, VERSION, GENERATED_AT,
        wrapper["manifest"]["source"]["observed_commit"],
        wrapper["manifest"]["source"]["observed_tree"],
    )
    return output, candidate, wheel, sdist, wrapper, receipt


def test_generator_emits_canonical_bound_packet_and_privacy_minimized_receipt(tmp_path):
    private_root = tmp_path / "private-user-and-host-sentinel"
    private_root.mkdir()
    output, _candidate, wheel, sdist, wrapper, receipt = generate(private_root)

    assert set(path.name for path in output.iterdir()) == set(tool.PACKET_FILES)
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
        "builder": {"id": tool.BUILDER_URI + "@" + commit},
    }
    assert provenance["predicate"]["buildDefinition"]["externalParameters"]["workflow"] == ".github/workflows/ci.yml"
    assert provenance["predicate"]["buildDefinition"]["externalParameters"]["job"] == "wheel-smoke"
    assert [subject["name"] for subject in provenance["subject"]] == [wheel.name, sdist.name]

    packet = json.loads((output / "packet.json").read_text())
    assert packet["status"] == "generated_unreviewed"
    assert packet["candidate_evidence"]["manifest_sha256"] == wrapper["manifest_sha256"]
    assert packet["effects"] == tool.EFFECTS
    assert packet["privacy"] == tool.PRIVACY
    assert packet["package"]["runtime_dependencies"] == []


def test_generation_is_deterministic_for_the_same_explicit_inputs(tmp_path):
    candidate, wheel, sdist, wrapper = make_inputs(tmp_path)
    commit = wrapper["manifest"]["source"]["observed_commit"]
    tree = wrapper["manifest"]["source"]["observed_tree"]
    outputs = []
    for name in ("first", "second"):
        output = tmp_path / name
        tool.generate_packet(
            candidate, wheel, sdist, output, VERSION, GENERATED_AT, commit, tree,
        )
        outputs.append(output)
    for filename in tool.PACKET_FILES:
        assert (outputs[0] / filename).read_bytes() == (outputs[1] / filename).read_bytes()


def test_verifier_is_offline_read_only_and_recomputes_artifacts(monkeypatch, tmp_path):
    output, _candidate, wheel, sdist, wrapper, _receipt = generate(tmp_path)
    original = {path.name: path.read_bytes() for path in output.iterdir()}

    def forbidden(*_args, **_kwargs):
        pytest.fail("offline verification must not execute host commands")

    monkeypatch.setattr(tool.identity, "_run_fixed", forbidden)
    monkeypatch.setattr(tool.identity, "collect", forbidden)
    receipt = tool.verify_packet_directory(
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
        tool.verify_packet_directory(
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
        tool.verify_packet_directory(output, wheel, sdist, commit, tree)
    (output / "packet.json").write_bytes(_json_bytes(json.loads((output / "packet.json").read_text())))
    (output / "unexpected-private-file").write_text("do not read")
    with pytest.raises(tool.PacketError, match="FILE_SET"):
        tool.verify_packet_directory(output, wheel, sdist, commit, tree)


def test_artifact_bytes_names_and_candidate_digests_are_fail_closed(tmp_path):
    candidate, wheel, sdist, wrapper = make_inputs(tmp_path)
    commit = wrapper["manifest"]["source"]["observed_commit"]
    tree = wrapper["manifest"]["source"]["observed_tree"]

    wheel.write_bytes(wheel.read_bytes() + b"changed")
    with pytest.raises(tool.PacketError, match="ARTIFACT_MISMATCH"):
        tool.generate_packet(
            candidate, wheel, sdist, tmp_path / "changed", VERSION, GENERATED_AT, commit, tree,
        )
    wheel.rename(tmp_path / "unexpected.whl")
    with pytest.raises(tool.PacketError, match="ARTIFACT_INVALID"):
        tool.generate_packet(
            candidate, tmp_path / "unexpected.whl", sdist, tmp_path / "wrong-name",
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
        tool.generate_packet(
            candidate, wheel, sdist, tmp_path / "incomplete", VERSION, GENERATED_AT, commit, tree,
        )
    with pytest.raises(tool.PacketError, match="SOURCE_MISMATCH"):
        tool.generate_packet(
            candidate, wheel, sdist, tmp_path / "wrong-source", VERSION, GENERATED_AT,
            "f" * 40, tree,
        )


def test_noncanonical_candidate_is_refused_instead_of_normalized(tmp_path):
    candidate, wheel, sdist, wrapper = make_inputs(tmp_path)
    candidate.write_bytes(candidate.read_bytes() + b" ")
    with pytest.raises(tool.PacketError, match="NONCANONICAL_JSON"):
        tool.generate_packet(
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
        tool.generate_packet(
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
