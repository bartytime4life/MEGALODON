"""Offline cross-binding tests for one exact local-model evidence set."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from megalodon.local_model_readiness import (
    LocalModelReadinessError,
    assess_readiness,
    canonical_json,
)


def canonical(value: object, *, ensure_ascii: bool = True) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=ensure_ascii,
        allow_nan=False,
    ).encode("ascii" if ensure_ascii else "utf-8")


def digest(value: object, *, ensure_ascii: bool = True) -> str:
    return sha256(canonical(value, ensure_ascii=ensure_ascii)).hexdigest()


@dataclass
class Profile:
    value: dict
    canonical_sha256: str
    comparison_boundary_sha256: str
    hard_gate_passed: bool = True
    gate_failures: tuple[str, ...] = ()


@dataclass
class Request:
    mode: str
    model_id: str
    request: dict
    request_sha256: str
    format_schema_sha256: str | None


def binding(*, status: str = "BOUND") -> dict:
    if status == "UNBOUND":
        return {
            "schema_version": "megalodon.local-model-binding/v1",
            "repository": "bartytime4life/MEGALODON",
            "status": "UNBOUND",
            "logical_alias": None,
            "provider": {},
            "artifact": {},
            "host_profile": {},
            "registry": {},
            "operator_decision": {},
        }
    return {
        "schema_version": "megalodon.local-model-binding/v1",
        "repository": "bartytime4life/MEGALODON",
        "status": "BOUND",
        "logical_alias": "local:qwen-candidate-v1",
        "provider": {
            "version": "0.24.0",
            "executable_sha256": "sha256:" + "1" * 64,
        },
        "artifact": {
            "installed_tag": "qwen2.5:7b-instruct-fp16",
            "manifest_sha256": "sha256:" + "2" * 64,
            "model_weight_sha256": "sha256:" + "3" * 64,
        },
        "host_profile": {"profile_id": "ubuntu24-rtx5080-cuda-v1"},
        "registry": {"fingerprint_sha256": "sha256:" + "4" * 64},
        "operator_decision": {"status": "APPROVED"},
    }


def identity() -> dict:
    material = {
        "binding_alias": "local:qwen-candidate-v1",
        "model_tag": "qwen2.5:7b-instruct-fp16",
        "manifest_sha256": "2" * 64,
        "artifact_sha256": "3" * 64,
        "provenance_sha256": "5" * 64,
        "runner_version": "0.24.0",
        "runner_binary_sha256": "1" * 64,
        "capabilities": ["completion", "tools"],
    }
    return {
        "value": {"evidence_class": "operator_observed"},
        "identity_material": material,
        "observation_sha256": digest({"observation": 1}),
        "provider_identity_sha256": digest(material),
    }


def containment() -> dict:
    return {
        "schema_version": "local-model-containment-acceptance-v1",
        "basis": "collector_output",
        "status": "candidate_evidence",
        "repository": "bartytime4life/MEGALODON",
        "model_binding": {
            "model_alias": "local:qwen-candidate-v1",
            "artifact_sha256": "3" * 64,
            "registry_fingerprint_sha256": "4" * 64,
            "operator_approved": True,
        },
        "wrapper_reachability": {},
        "process_boundary": {},
        "adversarial_corpus": {
            "corpus_id": "qwen-airlock-v1",
            "categories_covered": [],
            "total_cases": 7,
            "cases_passed": 7,
            "cases_failed": 0,
        },
        "evidence_retention": {},
        "gates": {},
        "effects": {},
        "limitations": [],
        "generated_at": "2026-09-22T00:00:00Z",
    }


def profile(containment_value: dict) -> Profile:
    value = {
        "profile_id": "qwen25-candidate-v1",
        "evidence_class": "operator_observed",
        "model_alias": "qwen2.5:7b-instruct-fp16",
        "ollama_manifest_digest": "2" * 64,
        "artifact_sha256": "3" * 64,
        "provenance_sha256": "5" * 64,
        "containment_receipt_sha256": digest(
            containment_value, ensure_ascii=False
        ),
        "runner": {
            "version": "0.24.0",
            "binary_sha256": "1" * 64,
        },
        "evaluation": {
            "corpus_sha256": "6" * 64,
            "sample_count": 7,
            "p95_latency_ms": 1000,
            "max_rss_mib": 4096,
        },
    }
    return Profile(
        value=value,
        canonical_sha256=digest(value),
        comparison_boundary_sha256=digest({"boundary": 1}),
    )


def evaluation(profile_value: Profile) -> dict:
    value = {
        "evidence_class": "operator_observed",
        "profile_sha256": profile_value.canonical_sha256,
        "comparison_boundary_sha256": profile_value.comparison_boundary_sha256,
        "corpus": {
            "corpus_id": "qwen-airlock-v1",
            "corpus_sha256": "6" * 64,
        },
        "execution": {
            "total_cases": 7,
            "p95_latency_ms": 1000,
            "max_rss_mib": 4096,
        },
    }
    return {
        "value": value,
        "receipt_sha256": digest(value),
        "evaluation_boundary_sha256": digest({"evaluation-boundary": 1}),
        "hard_gate_passed": True,
        "gate_failures": (),
    }


def request() -> Request:
    body = {
        "keep_alive": 0,
        "model": "local:qwen-candidate-v1",
        "options": {
            "num_ctx": 4096,
            "num_predict": 512,
            "seed": 0,
            "temperature": 0,
        },
        "prompt": "bounded",
        "raw": True,
        "stream": False,
        "think": False,
        "format": {"type": "object"},
    }
    return Request(
        mode="anomaly_advisory",
        model_id="local:qwen-candidate-v1",
        request=body,
        request_sha256=digest(body),
        format_schema_sha256=digest(body["format"]),
    )


def full_set() -> dict:
    containment_value = containment()
    profile_value = profile(containment_value)
    return {
        "binding": binding(),
        "identity": identity(),
        "profile": profile_value,
        "containment": containment_value,
        "evaluation": evaluation(profile_value),
        "request": request(),
    }


def assess(values: dict | None = None) -> dict:
    values = full_set() if values is None else values
    return assess_readiness(
        values["binding"],
        identity=values.get("identity"),
        profile=values.get("profile"),
        containment=values.get("containment"),
        evaluation=values.get("evaluation"),
        request=values.get("request"),
    )


def test_complete_packet_is_consistent_not_accepted():
    result = assess()
    assert result["state"] == "CANDIDATE_PACKET_CONSISTENT"
    assert result["gate_failures"] == []
    assert result["model_advertises_tools"] is True
    assert result["tools_used_or_authorized"] is False
    assert all(value is False for value in result["authority"].values())
    assert "OWNER_FINAL_ACCEPTANCE" in result["remaining_holds"]
    assert len(result["packet_sha256"]) == 64


def test_unbound_posture_is_a_named_hold():
    result = assess_readiness(binding(status="UNBOUND"))
    assert result["state"] == "UNBOUND"
    assert result["gate_failures"] == ["OWNER_MODEL_BINDING_NOT_RECORDED"]


def test_unbound_refuses_smuggled_evidence():
    with pytest.raises(
        LocalModelReadinessError, match="EVIDENCE_WITH_UNBOUND_BINDING"
    ):
        assess_readiness(binding(status="UNBOUND"), identity=identity())


@pytest.mark.parametrize(
    ("component", "code"),
    [
        ("identity", "IDENTITY_OBSERVATION_MISSING"),
        ("profile", "MODEL_PROFILE_MISSING"),
        ("containment", "CONTAINMENT_RECEIPT_MISSING"),
        ("evaluation", "EVALUATION_RECEIPT_MISSING"),
        ("request", "REQUEST_CONTRACT_MISSING"),
    ],
)
def test_missing_component_is_a_hold(component: str, code: str):
    values = full_set()
    values[component] = None
    result = assess(values)
    assert result["state"] == "EVIDENCE_HOLD"
    assert code in result["gate_failures"]


@pytest.mark.parametrize(
    ("mutator", "code"),
    [
        (
            lambda v: v["identity"]["identity_material"].__setitem__(
                "binding_alias", "local:qwen-other-v1"
            ),
            "IDENTITY_ALIAS_MISMATCH",
        ),
        (
            lambda v: v["identity"]["identity_material"].__setitem__(
                "manifest_sha256", "9" * 64
            ),
            "IDENTITY_MANIFEST_MISMATCH",
        ),
        (
            lambda v: v["profile"].value.__setitem__(
                "artifact_sha256", "9" * 64
            ),
            "PROFILE_ARTIFACT_MISMATCH",
        ),
        (
            lambda v: v["containment"]["model_binding"].__setitem__(
                "registry_fingerprint_sha256", "9" * 64
            ),
            "CONTAINMENT_REGISTRY_MISMATCH",
        ),
        (
            lambda v: v["evaluation"]["value"].__setitem__(
                "profile_sha256", "9" * 64
            ),
            "EVALUATION_PROFILE_DIGEST_MISMATCH",
        ),
        (
            lambda v: setattr(v["request"], "model_id", "local:qwen-other-v1"),
            "REQUEST_ALIAS_MISMATCH",
        ),
    ],
)
def test_cross_record_substitution_is_a_hold(mutator, code):
    values = full_set()
    mutator(values)
    result = assess(values)
    assert result["state"] == "EVIDENCE_HOLD"
    assert code in result["gate_failures"]


def test_containment_digest_mismatch_is_a_hold():
    values = full_set()
    values["containment"]["generated_at"] = "2026-09-22T00:00:01Z"
    assert "PROFILE_CONTAINMENT_DIGEST_MISMATCH" in assess(values)["gate_failures"]


def test_synthetic_records_never_promote():
    values = full_set()
    values["identity"]["value"]["evidence_class"] = "synthetic_fixture"
    values["profile"].value["evidence_class"] = "synthetic_fixture"
    values["evaluation"]["value"]["evidence_class"] = "synthetic_fixture"
    result = assess(values)
    assert result["state"] == "EVIDENCE_HOLD"
    assert {
        "IDENTITY_NOT_OPERATOR_OBSERVED",
        "PROFILE_NOT_OPERATOR_OBSERVED",
        "EVALUATION_NOT_OPERATOR_OBSERVED",
    } <= set(result["gate_failures"])


def test_request_controls_refuse_tools_or_runtime_drift():
    values = full_set()
    values["request"].request["tools"] = [{"name": "shell"}]
    values["request"].request["options"]["temperature"] = 1
    result = assess(values)
    assert "REQUEST_CONTROLS_MISMATCH" in result["gate_failures"]
    assert result["authority"]["grants_action_authority"] is False


def test_packet_is_deterministic_and_input_owned():
    values = full_set()
    original = deepcopy(values["binding"])
    first = assess(values)
    assert first == assess(values)
    assert values["binding"] == original
    first["identifiers"]["logical_alias"] = "changed"
    assert assess(values)["identifiers"]["logical_alias"] == original["logical_alias"]


def test_contract_schema_accepts_unbound_fixture():
    root = Path(__file__).parents[1]
    schema = json.loads(
        (root / "contracts/local-model-readiness/v1/schema.json").read_text(
            encoding="utf-8"
        )
    )
    fixture = json.loads(
        (root / "contracts/local-model-readiness/v1/fixtures/unbound.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(schema)
    assert list(Draft202012Validator(schema).iter_errors(fixture)) == []


def test_assessor_has_no_network_process_or_host_control_dependencies():
    source = (
        Path(__file__).parents[1]
        / "megalodon"
        / "local_model_readiness.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "import socket",
        "import subprocess",
        "http.client",
        "urllib",
        "requests",
        "os.system",
        "Popen",
        "systemctl",
        "ollama pull",
    ):
        assert forbidden not in source


def test_canonical_output_is_one_line_without_incidental_spacing():
    rendered = canonical_json(assess())
    assert "\n" not in rendered and ": " not in rendered
