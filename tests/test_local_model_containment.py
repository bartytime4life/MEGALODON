"""Local-model containment acceptance contract: the future gate #261 asks for.

No operator has approved an exact local model alias/artifact, so this suite
only ever exercises the ``unbound`` state plus in-memory hypothetical shapes
for the ``candidate_evidence`` branch. It never invokes a model, contacts a
network, or asserts anything about a real Ollama/Qwen deployment.
"""

from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "local_model_containment", ROOT / "tools/local_model_containment.py",
)
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
CONTRACT = ROOT / "contracts/local-model-containment/v1"
SCHEMA = json.loads((CONTRACT / "schema.json").read_text())
ACCEPTED = json.loads((CONTRACT / "fixtures/accepted/synthetic-unbound.json").read_text())
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


def _full_binding():
    return {
        "model_alias": "local:qwen-test-1",
        "artifact_sha256": "a" * 64,
        "registry_fingerprint_sha256": "b" * 64,
        "operator_approved": True,
    }


def _passing_candidate_changes():
    return {
        "/status": "candidate_evidence",
        "/model_binding": _full_binding(),
        "/wrapper_reachability/literal_loopback_only": "verified",
        "/wrapper_reachability/outbound_deny_test": "passed",
        "/wrapper_reachability/effective_no_cloud_configuration": "verified",
        "/process_boundary/identity_verified": "verified",
        "/process_boundary/lifecycle_observed": "observed",
        "/process_boundary/concurrency_slot_rejection": "passed",
        "/process_boundary/cancellation_timeout": "passed",
        "/process_boundary/filesystem_mutation_absent": "verified",
        "/process_boundary/host_wide_concurrency_absent": "verified",
        "/adversarial_corpus/corpus_id": "hypothetical-v1",
        "/adversarial_corpus/categories_covered": list(tool.ADVERSARIAL_CATEGORIES),
        "/adversarial_corpus/total_cases": 7,
        "/adversarial_corpus/cases_passed": 7,
        "/adversarial_corpus/cases_failed": 0,
        "/gates/operator_model_selection": "met",
        "/gates/independent_security_review": "recorded",
    }


def test_schema_and_synthetic_fixture_are_closed_and_valid():
    Draft202012Validator.check_schema(SCHEMA)
    VALIDATOR.validate(ACCEPTED)
    assert tool.validate(deepcopy(ACCEPTED)) == ACCEPTED
    assert tool.digest(ACCEPTED).startswith("sha256:")
    assert len(tool.digest(ACCEPTED)) == 71


@pytest.mark.parametrize("case", VIOLATIONS, ids=lambda item: item["id"])
def test_rejected_semantic_fixtures_fail_closed(case):
    candidate = mutate(ACCEPTED, case["changes"])
    with pytest.raises(tool.ContainmentError) as caught:
        tool.validate(candidate)
    assert caught.value.code == case["reason"]


@pytest.mark.parametrize("raw", [
    b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'\xff', b'{', b'[]',
    b'"forbidden-sentinel"', b'{} trailing',
])
def test_malformed_input_is_bounded_and_never_echoed(raw):
    with pytest.raises(tool.ContainmentError) as caught:
        tool.load(raw)
    assert caught.value.code == "INPUT_INVALID"
    assert "forbidden-sentinel" not in str(caught.value)
    with pytest.raises(tool.ContainmentError) as caught:
        tool.load(b" " * (tool.MAX_INPUT_BYTES + 1))
    assert caught.value.code == "INPUT_LIMIT"


def test_hypothetical_fully_passed_packet_is_accepted_only_from_collector_basis():
    candidate = mutate(ACCEPTED, {"/basis": "collector_output", **_passing_candidate_changes()})
    VALIDATOR.validate(candidate)
    assert tool.validate(candidate)["status"] == "candidate_evidence"


def test_synthetic_fixture_cannot_be_promoted_to_candidate_evidence():
    candidate = mutate(ACCEPTED, _passing_candidate_changes())
    assert candidate["basis"] == "synthetic_contract_fixture"
    assert not VALIDATOR.is_valid(candidate)
    with pytest.raises(tool.ContainmentError, match="CANDIDATE_INCOMPLETE"):
        tool.validate(candidate)


@pytest.mark.parametrize("field,value", [
    ("/wrapper_reachability/literal_loopback_only", "failed"),
    ("/process_boundary/identity_verified", "failed"),
    ("/process_boundary/host_wide_concurrency_absent", "not_checked"),
])
def test_candidate_evidence_requires_every_check_to_pass(field, value):
    base_changes = {"/basis": "collector_output", **_passing_candidate_changes()}
    candidate = mutate(ACCEPTED, {**base_changes, field: value})
    with pytest.raises(tool.ContainmentError, match="CANDIDATE_INCOMPLETE"):
        tool.validate(candidate)


def test_candidate_evidence_requires_full_adversarial_category_coverage():
    base_changes = {"/basis": "collector_output", **_passing_candidate_changes()}
    partial = mutate(ACCEPTED, {
        **base_changes,
        "/adversarial_corpus/categories_covered": ["injection"],
        "/adversarial_corpus/total_cases": 1,
        "/adversarial_corpus/cases_passed": 1,
    })
    with pytest.raises(tool.ContainmentError, match="CANDIDATE_INCOMPLETE"):
        tool.validate(partial)


def test_candidate_evidence_requires_zero_failed_cases():
    base_changes = {"/basis": "collector_output", **_passing_candidate_changes()}
    failing = mutate(ACCEPTED, {
        **base_changes,
        "/adversarial_corpus/total_cases": 8,
        "/adversarial_corpus/cases_passed": 7,
        "/adversarial_corpus/cases_failed": 1,
    })
    with pytest.raises(tool.ContainmentError, match="CANDIDATE_INCOMPLETE"):
        tool.validate(failing)


def test_candidate_requires_an_identifiable_corpus_in_both_validators():
    candidate = mutate(ACCEPTED, {
        "/basis": "collector_output", **_passing_candidate_changes(),
        "/adversarial_corpus/corpus_id": None,
    })
    assert not VALIDATOR.is_valid(candidate)
    with pytest.raises(tool.ContainmentError, match="CANDIDATE_INCOMPLETE"):
        tool.validate(candidate)


@pytest.mark.parametrize("corpus_id", ["x", "x" * 128, "é" * 128])
def test_corpus_id_character_boundary_is_accepted(corpus_id):
    candidate = mutate(ACCEPTED, {
        "/basis": "collector_output", **_passing_candidate_changes(),
        "/adversarial_corpus/corpus_id": corpus_id,
    })
    VALIDATOR.validate(candidate)
    assert tool.validate(candidate) == candidate


@pytest.mark.parametrize("corpus_id", ["", "x" * 129, "é" * 129])
def test_corpus_id_length_parity_through_cli(tmp_path, corpus_id):
    candidate = mutate(ACCEPTED, {
        "/basis": "collector_output", **_passing_candidate_changes(),
        "/adversarial_corpus/corpus_id": corpus_id,
    })
    assert not VALIDATOR.is_valid(candidate)
    with pytest.raises(tool.ContainmentError, match="CORPUS_STATE"):
        tool.validate(candidate)
    source = tmp_path / "packet.json"
    source.write_text(json.dumps(candidate))
    completed = subprocess.run(
        [sys.executable, str(ROOT / "tools/local_model_containment.py"), "validate", str(source)],
        cwd=ROOT, capture_output=True, timeout=10, check=False,
    )
    assert completed.returncode == 2
    assert completed.stdout == b""
    assert json.loads(completed.stderr)["reason"] == "CORPUS_STATE"


@pytest.mark.parametrize("field", [
    "/basis", "/status", "/wrapper_reachability/literal_loopback_only",
    "/process_boundary/identity_verified", "/adversarial_corpus/categories_covered",
    "/gates/operator_model_selection", "/gates/independent_security_review",
])
def test_wrong_collection_types_return_closed_denials(field):
    candidate = mutate(ACCEPTED, {field: [{}]})
    with pytest.raises(tool.ContainmentError):
        tool.validate(candidate)


@pytest.mark.parametrize("raw,reason", [
    (b'{"x":"\\ud800"}', "INPUT_INVALID"),
    (b'{"x":' + b'[' * 2000 + b']' * 2000 + b'}', "INPUT_LIMIT"),
])
def test_unencodable_or_deep_json_returns_closed_denial(raw, reason):
    with pytest.raises(tool.ContainmentError) as caught:
        tool.load(raw)
    assert caught.value.code == reason


def test_incomplete_status_requires_a_binding():
    candidate = mutate(ACCEPTED, {"/status": "incomplete"})
    with pytest.raises(tool.ContainmentError, match="BINDING_REQUIRED"):
        tool.validate(candidate)


def test_incomplete_status_accepts_a_valid_binding_without_full_evidence():
    candidate = mutate(ACCEPTED, {"/status": "incomplete", "/model_binding": _full_binding()})
    VALIDATOR.validate(candidate)
    assert tool.validate(candidate)["status"] == "incomplete"


def test_collect_reports_the_fixed_unbound_state():
    manifest = tool.collect()
    VALIDATOR.validate(manifest)
    assert manifest["basis"] == "collector_output"
    assert manifest["status"] == "unbound"
    assert manifest["model_binding"] is None
    assert all(value is False for value in manifest["effects"].values())
    assert manifest["gates"]["operator_model_selection"] == "blocked"


def test_collector_source_performs_no_network_or_process_action():
    import inspect
    source = inspect.getsource(tool)
    for forbidden in ("socket", "urllib", "requests", "subprocess", "shell=True", "os.system"):
        assert forbidden not in source


def test_cli_validation_emits_canonical_packet_without_writing(tmp_path):
    source = tmp_path / "packet.json"
    source.write_text(json.dumps(ACCEPTED, indent=2))
    completed = subprocess.run(
        [sys.executable, str(ROOT / "tools/local_model_containment.py"), "validate", str(source)],
        cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10, check=True,
    )
    result = json.loads(completed.stdout)
    assert completed.stderr == b""
    assert result["status"] == "validated"
    assert result["manifest"] == ACCEPTED
    assert result["manifest_sha256"] == tool.digest(ACCEPTED)
    assert list(tmp_path.iterdir()) == [source]


def test_cli_collect_matches_library_output():
    completed = subprocess.run(
        [sys.executable, str(ROOT / "tools/local_model_containment.py"), "collect"],
        cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10, check=True,
    )
    result = json.loads(completed.stdout)
    assert result["status"] == "validated"
    assert result["manifest"]["status"] == "unbound"


def test_cli_rejects_invalid_manifest_without_leaking_detail(tmp_path):
    source = tmp_path / "packet.json"
    source.write_text(json.dumps(mutate(ACCEPTED, {"/effects/model_installed": True})))
    completed = subprocess.run(
        [sys.executable, str(ROOT / "tools/local_model_containment.py"), "validate", str(source)],
        cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10, check=False,
    )
    assert completed.returncode == 2
    payload = json.loads(completed.stderr)
    assert payload["status"] == "blocked"
    assert payload["reason"] == "AUTHORITY_CLAIM"
