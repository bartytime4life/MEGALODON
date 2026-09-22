"""Offline proof for the model-profile lab. No provider is contacted."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest
from jsonschema import Draft202012Validator

from megalodon.model_profile import (
    ModelProfileError,
    binding_candidate_packet,
    canonical_json,
    compare_profiles,
    parse_profile_bytes,
    validate_profile,
)


def profile() -> dict:
    return {
        "schema": "megalodon-local-model-profile-v1",
        "profile_id": "qwen25-7b-fp16-lab",
        "status": "candidate",
        "evidence_class": "synthetic_fixture",
        "provider": "ollama",
        "endpoint": "http://127.0.0.1:11434",
        "model_alias": "qwen2.5:7b-instruct-fp16",
        "ollama_manifest_digest": "a" * 64,
        "artifact_sha256": "b" * 64,
        "provenance_sha256": "c" * 64,
        "containment_receipt_sha256": "d" * 64,
        "model_family": "qwen2.5",
        "quantization": "fp16",
        "context_window": 32768,
        "operational_context": 4096,
        "purpose": "advisory",
        "structured_output": True,
        "thinking_enabled": False,
        "license": "Apache-2.0",
        "source_reference": "synthetic fixture; not an artifact provenance claim",
        "runner": {
            "name": "ollama",
            "version": "0.0.0-synthetic",
            "binary_sha256": "e" * 64,
        },
        "evaluation": {
            "corpus_sha256": "f" * 64,
            "sample_count": 12,
            "schema_valid_count": 12,
            "citation_valid_count": 12,
            "refusal_valid_count": 12,
            "p95_latency_ms": 900,
            "max_rss_mib": 8192,
        },
    }


def test_valid_synthetic_profile_stays_synthetic_and_never_admitted():
    validated = validate_profile(profile())
    assert validated.hard_gate_passed is True
    assert len(validated.comparison_boundary_sha256) == 64
    packet = binding_candidate_packet(validated)
    assert packet["state"] == "SYNTHETIC_ONLY"
    assert packet["comparison_boundary_sha256"] == (
        validated.comparison_boundary_sha256
    )
    assert packet["remaining_holds"] == [
        "PROVIDER_CONTAINMENT_ACCEPTANCE",
        "ARTIFACT_PROVENANCE_INDEPENDENT_VERIFICATION",
        "OWNER_MODEL_BINDING",
        "INDEPENDENT_SECURITY_ACCEPTANCE",
        "RELEASE_AND_DEPLOYMENT_AUTHORITY",
    ]
    assert packet["authority"] == {
        "starts_provider": False,
        "pulls_model": False,
        "changes_host": False,
        "admits_model": False,
        "authorizes_release": False,
    }


def test_operator_observed_complete_profile_is_only_a_validated_candidate():
    value = profile()
    value["evidence_class"] = "operator_observed"
    packet = binding_candidate_packet(validate_profile(value))
    assert packet["state"] == "CANDIDATE_VALIDATED"
    assert "OWNER_MODEL_BINDING" in packet["remaining_holds"]


def test_incomplete_evaluation_is_a_named_hold():
    value = profile()
    value["evidence_class"] = "operator_observed"
    value["evaluation"]["citation_valid_count"] = 11
    validated = validate_profile(value)
    assert validated.hard_gate_passed is False
    assert validated.gate_failures == ("CITATION_VALIDATION_INCOMPLETE",)
    assert binding_candidate_packet(validated)["state"] == "EVALUATION_HOLD"


@pytest.mark.parametrize(
    ("mutator", "code"),
    [
        (
            lambda value: value.__setitem__(
                "endpoint", "http://localhost:11434"
            ),
            "ENDPOINT",
        ),
        (lambda value: value.__setitem__("model_alias", "llama3:8b"), "MODEL_ALIAS"),
        (
            lambda value: value.__setitem__("thinking_enabled", True),
            "THINKING_MUST_BE_DISABLED",
        ),
        (
            lambda value: value.__setitem__("structured_output", False),
            "STRUCTURED_OUTPUT_REQUIRED",
        ),
        (
            lambda value: value.__setitem__("operational_context", 4097),
            "OPERATIONAL_CONTEXT",
        ),
        (lambda value: value.__setitem__("purpose", "tool-selection"), "PURPOSE"),
        (lambda value: value.__setitem__("extra", "field"), "PROFILE_SHAPE"),
        (
            lambda value: value["runner"].__setitem__("extra", "field"),
            "RUNNER_SHAPE",
        ),
    ],
)
def test_policy_and_closed_shape_refusals(mutator, code):
    value = profile()
    mutator(value)
    with pytest.raises(ModelProfileError, match=code):
        validate_profile(value)


def test_duplicate_json_key_and_nonfinite_number_refuse():
    with pytest.raises(ModelProfileError, match="DUPLICATE_JSON_KEY"):
        parse_profile_bytes(b'{"schema":"a","schema":"b"}')
    with pytest.raises(ModelProfileError, match="NON_FINITE_NUMBER"):
        parse_profile_bytes(b'{"value":NaN}')


def test_profile_digest_is_order_independent_and_mutation_sensitive():
    first = profile()
    second = dict(reversed(list(first.items())))
    assert validate_profile(first).canonical_sha256 == validate_profile(
        second
    ).canonical_sha256
    second["evaluation"] = deepcopy(second["evaluation"])
    second["evaluation"]["p95_latency_ms"] = 901
    assert validate_profile(first).canonical_sha256 != validate_profile(
        second
    ).canonical_sha256


def test_comparison_is_deterministic_like_for_like_and_does_not_select():
    first = profile()
    first["profile_id"] = "qwen25-a"
    second = profile()
    second["profile_id"] = "qwen25-b"
    second["evaluation"]["p95_latency_ms"] = 800
    comparison = compare_profiles(
        [validate_profile(first), validate_profile(second)]
    )
    assert [item["profile_id"] for item in comparison["ranking"]] == [
        "qwen25-b",
        "qwen25-a",
    ]
    assert comparison["state"] == "COMPARISON_ONLY"
    assert comparison["selection"] is None
    assert comparison["comparison_boundary_sha256"] == (
        validate_profile(first).comparison_boundary_sha256
    )


def test_comparison_prioritizes_closed_gates_before_speed():
    first = profile()
    first["profile_id"] = "qwen25-complete"
    first["evaluation"]["p95_latency_ms"] = 1200
    second = profile()
    second["profile_id"] = "qwen25-fast-incomplete"
    second["evaluation"]["p95_latency_ms"] = 100
    second["evaluation"]["refusal_valid_count"] = 11
    comparison = compare_profiles(
        [validate_profile(first), validate_profile(second)]
    )
    assert comparison["ranking"][0]["profile_id"] == "qwen25-complete"


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value["evaluation"].__setitem__("corpus_sha256", "1" * 64),
        lambda value: value["evaluation"].__setitem__("sample_count", 13),
        lambda value: value.__setitem__("purpose", "explanation"),
        lambda value: value.__setitem__("operational_context", 2048),
        lambda value: value["runner"].__setitem__("version", "0.0.1-synthetic"),
        lambda value: value["runner"].__setitem__("binary_sha256", "1" * 64),
        lambda value: value.__setitem__("evidence_class", "operator_observed"),
    ],
)
def test_comparison_refuses_mixed_corpus_or_operating_boundary(change):
    first = profile()
    first["profile_id"] = "qwen25-a"
    second = profile()
    second["profile_id"] = "qwen25-b"
    change(second)
    if second["evaluation"]["sample_count"] == 13:
        second["evaluation"]["schema_valid_count"] = 13
        second["evaluation"]["citation_valid_count"] = 13
        second["evaluation"]["refusal_valid_count"] = 13
    with pytest.raises(ModelProfileError, match="COMPARISON_BOUNDARY_MISMATCH"):
        compare_profiles([validate_profile(first), validate_profile(second)])


def test_candidate_properties_do_not_change_comparison_boundary():
    first = profile()
    first["profile_id"] = "qwen25-a"
    second = profile()
    second["profile_id"] = "qwen25-b"
    second["model_alias"] = "qwen2.5:14b-instruct-q4_K_M"
    second["model_family"] = "qwen2.5"
    second["quantization"] = "q4_K_M"
    second["context_window"] = 131072
    assert validate_profile(first).comparison_boundary_sha256 == (
        validate_profile(second).comparison_boundary_sha256
    )


def test_comparison_refuses_duplicate_identity():
    one = validate_profile(profile())
    with pytest.raises(ModelProfileError, match="DUPLICATE_PROFILE_ID"):
        compare_profiles([one, one])


def test_cli_emits_bounded_refusal_without_paths_or_exception(tmp_path: Path):
    profile_path = tmp_path / "profile.json"
    value = profile()
    value["endpoint"] = "https://example.invalid"
    profile_path.write_text(json.dumps(value), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, "tools/qwen_profile_lab.py", "validate", str(profile_path)],
        cwd=Path(__file__).parents[1],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 2
    result = json.loads(completed.stdout)
    assert result["error_code"] == "ENDPOINT"
    assert str(profile_path) not in completed.stdout


def test_cli_refuses_mixed_boundary_comparison_without_echoing_paths(
    tmp_path: Path,
):
    first = profile()
    first["profile_id"] = "qwen25-a"
    second = profile()
    second["profile_id"] = "qwen25-b"
    second["evaluation"]["corpus_sha256"] = "1" * 64
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    first_path.write_text(json.dumps(first), encoding="utf-8")
    second_path.write_text(json.dumps(second), encoding="utf-8")
    completed = subprocess.run(
        [
            sys.executable,
            "tools/qwen_profile_lab.py",
            "compare",
            str(first_path),
            str(second_path),
        ],
        cwd=Path(__file__).parents[1],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 2
    result = json.loads(completed.stdout)
    assert result["error_code"] == "COMPARISON_BOUNDARY_MISMATCH"
    assert str(first_path) not in completed.stdout
    assert str(second_path) not in completed.stdout


def test_checked_in_contract_schema_accepts_the_synthetic_fixture():
    repository = Path(__file__).parents[1]
    schema = json.loads(
        (repository / "contracts/local-model-profile/v1/schema.json").read_text(
            encoding="utf-8"
        )
    )
    fixture = json.loads(
        (
            repository
            / "contracts/local-model-profile/v1/fixtures/accepted-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    assert list(Draft202012Validator(schema).iter_errors(fixture)) == []
    assert validate_profile(fixture).evidence_class == "synthetic_fixture"


def test_canonical_json_contains_no_incidental_whitespace():
    rendered = canonical_json(
        binding_candidate_packet(validate_profile(profile()))
    )
    assert "\n" not in rendered and ": " not in rendered
