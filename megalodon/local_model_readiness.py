"""Cross-bind validated local Ollama/Qwen evidence without operating a model.

The assessor receives values already checked by the repository's binding,
identity, profile, containment, evaluation, and request-contract validators. It
verifies that those independently useful records describe one exact candidate.
It performs no file read, network request, provider discovery, process control,
model pull/start, host mutation, acceptance transition, release, or deployment.
"""

from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Any, Mapping


READINESS_SCHEMA = "megalodon-local-model-readiness-v1"
HEX64 = re.compile(r"[a-f0-9]{64}")
PREFIXED_HEX64 = re.compile(r"sha256:([a-f0-9]{64})")

MISSING_COMPONENTS = (
    ("identity", "IDENTITY_OBSERVATION_MISSING"),
    ("profile", "MODEL_PROFILE_MISSING"),
    ("containment", "CONTAINMENT_RECEIPT_MISSING"),
    ("evaluation", "EVALUATION_RECEIPT_MISSING"),
    ("request", "REQUEST_CONTRACT_MISSING"),
)

REMAINING_HOLDS = (
    "EVIDENCE_ORIGIN_AUTHENTICATION",
    "LOADED_RUNTIME_BYTES_NOT_ATTESTED",
    "INDEPENDENT_SECURITY_ACCEPTANCE_CURRENTNESS",
    "OWNER_FINAL_ACCEPTANCE",
    "RELEASE_AND_DEPLOYMENT_AUTHORITY",
)


class LocalModelReadinessError(ValueError):
    """Fixed-code refusal for malformed or contradictory assessor inputs."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _canonical(value: object, *, ensure_ascii: bool = True) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=ensure_ascii,
            allow_nan=False,
        ).encode("ascii" if ensure_ascii else "utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise LocalModelReadinessError("CANONICALIZATION") from None


def _digest(value: object, *, ensure_ascii: bool = True) -> str:
    return sha256(_canonical(value, ensure_ascii=ensure_ascii)).hexdigest()


def _raw_digest(value: object, code: str) -> str:
    if type(value) is not str:
        raise LocalModelReadinessError(code)
    if HEX64.fullmatch(value) is not None:
        return value
    matched = PREFIXED_HEX64.fullmatch(value)
    if matched is None:
        raise LocalModelReadinessError(code)
    return matched.group(1)


def _mapping(value: object, code: str) -> Mapping[str, Any]:
    if type(value) is not dict:
        raise LocalModelReadinessError(code)
    return value


def _append(failures: list[str], condition: bool, code: str) -> None:
    if condition and code not in failures:
        failures.append(code)


def _packet(
    *,
    state: str,
    binding: Mapping[str, Any],
    failures: list[str],
    identifiers: Mapping[str, object],
    evidence: Mapping[str, object],
    input_states: Mapping[str, object],
    advertised_tools: bool,
) -> dict[str, object]:
    result: dict[str, object] = {
        "schema": READINESS_SCHEMA,
        "state": state,
        "binding_status": binding["status"],
        "identifiers": dict(identifiers),
        "evidence": dict(evidence),
        "input_states": dict(input_states),
        "model_advertises_tools": advertised_tools,
        "tools_used_or_authorized": False,
        "gate_failures": list(failures),
        "remaining_holds": list(REMAINING_HOLDS),
        "authority": {
            "contacts_provider": False,
            "starts_provider": False,
            "pulls_model": False,
            "changes_host": False,
            "attests_loaded_bytes": False,
            "accepts_model": False,
            "grants_detector_authority": False,
            "grants_action_authority": False,
            "authorizes_release": False,
            "authorizes_deployment": False,
        },
        "limitations": [
            "This packet proves cross-record consistency, not evidence origin or execution.",
            "API metadata and supplied digests do not attest bytes loaded during inference.",
            "A consistent packet is not model acceptance, release, deployment, or host authority.",
        ],
    }
    result["packet_sha256"] = _digest(result)
    return result


def assess_readiness(
    binding: object,
    *,
    identity: object | None = None,
    profile: object | None = None,
    containment: object | None = None,
    evaluation: object | None = None,
    request: object | None = None,
) -> dict[str, object]:
    """Cross-bind already-validated evidence for one exact local-model candidate.

    Missing evidence becomes a named HOLD. Contradictory shapes or evidence
    supplied alongside an UNBOUND binding refuse because those states should not
    be silently combined.
    """

    binding_map = _mapping(binding, "BINDING_SHAPE")
    if binding_map.get("schema_version") != "megalodon.local-model-binding/v1":
        raise LocalModelReadinessError("BINDING_SCHEMA")
    if binding_map.get("repository") != "bartytime4life/MEGALODON":
        raise LocalModelReadinessError("BINDING_REPOSITORY")
    status = binding_map.get("status")
    if status not in {"UNBOUND", "BOUND"}:
        raise LocalModelReadinessError("BINDING_STATUS")

    binding_sha256 = _digest(binding_map)
    supplied = {
        "identity": identity,
        "profile": profile,
        "containment": containment,
        "evaluation": evaluation,
        "request": request,
    }

    if status == "UNBOUND":
        if any(value is not None for value in supplied.values()):
            raise LocalModelReadinessError("EVIDENCE_WITH_UNBOUND_BINDING")
        return _packet(
            state="UNBOUND",
            binding=binding_map,
            failures=["OWNER_MODEL_BINDING_NOT_RECORDED"],
            identifiers={
                "logical_alias": None,
                "installed_tag": None,
                "profile_id": None,
                "corpus_id": None,
                "host_profile_id": None,
            },
            evidence={
                "binding_sha256": binding_sha256,
                "identity_observation_sha256": None,
                "provider_identity_sha256": None,
                "profile_sha256": None,
                "comparison_boundary_sha256": None,
                "containment_receipt_sha256": None,
                "evaluation_receipt_sha256": None,
                "evaluation_boundary_sha256": None,
                "request_sha256": None,
                "format_schema_sha256": None,
            },
            input_states={name: None for name, _ in MISSING_COMPONENTS},
            advertised_tools=False,
        )

    logical_alias = binding_map.get("logical_alias")
    provider = _mapping(binding_map.get("provider"), "BINDING_PROVIDER")
    artifact = _mapping(binding_map.get("artifact"), "BINDING_ARTIFACT")
    host_profile = _mapping(binding_map.get("host_profile"), "BINDING_HOST")
    registry = _mapping(binding_map.get("registry"), "BINDING_REGISTRY")
    operator_decision = _mapping(
        binding_map.get("operator_decision"), "BINDING_DECISION"
    )
    if type(logical_alias) is not str:
        raise LocalModelReadinessError("BINDING_ALIAS")

    failures: list[str] = []
    _append(
        failures,
        operator_decision.get("status") != "APPROVED",
        "OWNER_MODEL_BINDING_NOT_APPROVED",
    )
    for name, code in MISSING_COMPONENTS:
        _append(failures, supplied[name] is None, code)

    identifiers: dict[str, object] = {
        "logical_alias": logical_alias,
        "installed_tag": artifact.get("installed_tag"),
        "profile_id": None,
        "corpus_id": None,
        "host_profile_id": host_profile.get("profile_id"),
    }
    evidence: dict[str, object] = {
        "binding_sha256": binding_sha256,
        "identity_observation_sha256": None,
        "provider_identity_sha256": None,
        "profile_sha256": None,
        "comparison_boundary_sha256": None,
        "containment_receipt_sha256": None,
        "evaluation_receipt_sha256": None,
        "evaluation_boundary_sha256": None,
        "request_sha256": None,
        "format_schema_sha256": None,
    }
    input_states: dict[str, object] = {
        "identity": None,
        "profile": None,
        "containment": None,
        "evaluation": None,
        "request": None,
    }
    advertised_tools = False

    binding_manifest = _raw_digest(
        artifact.get("manifest_sha256"), "BINDING_MANIFEST_DIGEST"
    )
    binding_artifact = _raw_digest(
        artifact.get("model_weight_sha256"), "BINDING_ARTIFACT_DIGEST"
    )
    binding_runner = _raw_digest(
        provider.get("executable_sha256"), "BINDING_RUNNER_DIGEST"
    )
    binding_registry = _raw_digest(
        registry.get("fingerprint_sha256"), "BINDING_REGISTRY_DIGEST"
    )

    if identity is not None:
        identity_map = _mapping(identity, "IDENTITY_SHAPE")
        value = _mapping(identity_map.get("value"), "IDENTITY_VALUE")
        material = _mapping(
            identity_map.get("identity_material"), "IDENTITY_MATERIAL"
        )
        evidence["identity_observation_sha256"] = _raw_digest(
            identity_map.get("observation_sha256"), "IDENTITY_OBSERVATION_DIGEST"
        )
        evidence["provider_identity_sha256"] = _raw_digest(
            identity_map.get("provider_identity_sha256"),
            "PROVIDER_IDENTITY_DIGEST",
        )
        input_states["identity"] = (
            "IDENTITY_OBSERVATION_VALIDATED"
            if value.get("evidence_class") == "operator_observed"
            else "SYNTHETIC_ONLY"
        )
        _append(
            failures,
            value.get("evidence_class") != "operator_observed",
            "IDENTITY_NOT_OPERATOR_OBSERVED",
        )
        _append(
            failures,
            material.get("binding_alias") != logical_alias,
            "IDENTITY_ALIAS_MISMATCH",
        )
        _append(
            failures,
            material.get("model_tag") != artifact.get("installed_tag"),
            "IDENTITY_TAG_MISMATCH",
        )
        _append(
            failures,
            material.get("manifest_sha256") != binding_manifest,
            "IDENTITY_MANIFEST_MISMATCH",
        )
        _append(
            failures,
            material.get("artifact_sha256") != binding_artifact,
            "IDENTITY_ARTIFACT_MISMATCH",
        )
        _append(
            failures,
            material.get("runner_version") != provider.get("version"),
            "IDENTITY_RUNNER_VERSION_MISMATCH",
        )
        _append(
            failures,
            material.get("runner_binary_sha256") != binding_runner,
            "IDENTITY_RUNNER_DIGEST_MISMATCH",
        )
        capabilities = material.get("capabilities")
        if type(capabilities) is list:
            advertised_tools = "tools" in capabilities

    profile_value: Mapping[str, Any] | None = None
    if profile is not None:
        try:
            profile_value = _mapping(profile.value, "PROFILE_VALUE")
            profile_sha256 = _raw_digest(
                profile.canonical_sha256, "PROFILE_DIGEST"
            )
            comparison_boundary = _raw_digest(
                profile.comparison_boundary_sha256,
                "COMPARISON_BOUNDARY_DIGEST",
            )
            profile_gate_passed = profile.hard_gate_passed is True
            profile_gate_failures = tuple(profile.gate_failures)
        except (AttributeError, TypeError):
            raise LocalModelReadinessError("PROFILE_SHAPE") from None
        identifiers["profile_id"] = profile_value.get("profile_id")
        evidence["profile_sha256"] = profile_sha256
        evidence["comparison_boundary_sha256"] = comparison_boundary
        input_states["profile"] = (
            "CANDIDATE_VALIDATED"
            if profile_value.get("evidence_class") == "operator_observed"
            and profile_gate_passed
            else "PROFILE_HOLD"
        )
        _append(
            failures,
            profile_value.get("evidence_class") != "operator_observed",
            "PROFILE_NOT_OPERATOR_OBSERVED",
        )
        _append(
            failures,
            not profile_gate_passed or bool(profile_gate_failures),
            "PROFILE_HARD_GATE_INCOMPLETE",
        )
        _append(
            failures,
            profile_value.get("model_alias") != artifact.get("installed_tag"),
            "PROFILE_TAG_MISMATCH",
        )
        _append(
            failures,
            profile_value.get("ollama_manifest_digest") != binding_manifest,
            "PROFILE_MANIFEST_MISMATCH",
        )
        _append(
            failures,
            profile_value.get("artifact_sha256") != binding_artifact,
            "PROFILE_ARTIFACT_MISMATCH",
        )
        profile_runner = _mapping(profile_value.get("runner"), "PROFILE_RUNNER")
        _append(
            failures,
            profile_runner.get("version") != provider.get("version"),
            "PROFILE_RUNNER_VERSION_MISMATCH",
        )
        _append(
            failures,
            profile_runner.get("binary_sha256") != binding_runner,
            "PROFILE_RUNNER_DIGEST_MISMATCH",
        )
        if identity is not None:
            identity_material = _mapping(
                _mapping(identity, "IDENTITY_SHAPE").get("identity_material"),
                "IDENTITY_MATERIAL",
            )
            _append(
                failures,
                profile_value.get("provenance_sha256")
                != identity_material.get("provenance_sha256"),
                "PROFILE_PROVENANCE_MISMATCH",
            )

    if containment is not None:
        containment_map = _mapping(containment, "CONTAINMENT_SHAPE")
        containment_digest = _digest(containment_map, ensure_ascii=False)
        evidence["containment_receipt_sha256"] = containment_digest
        input_states["containment"] = containment_map.get("status")
        _append(
            failures,
            containment_map.get("basis") != "collector_output",
            "CONTAINMENT_NOT_COLLECTOR_OUTPUT",
        )
        _append(
            failures,
            containment_map.get("status") != "candidate_evidence",
            "CONTAINMENT_CANDIDATE_INCOMPLETE",
        )
        containment_binding = containment_map.get("model_binding")
        if type(containment_binding) is not dict:
            _append(failures, True, "CONTAINMENT_BINDING_MISSING")
        else:
            _append(
                failures,
                containment_binding.get("model_alias") != logical_alias,
                "CONTAINMENT_ALIAS_MISMATCH",
            )
            _append(
                failures,
                containment_binding.get("artifact_sha256") != binding_artifact,
                "CONTAINMENT_ARTIFACT_MISMATCH",
            )
            _append(
                failures,
                containment_binding.get("registry_fingerprint_sha256")
                != binding_registry,
                "CONTAINMENT_REGISTRY_MISMATCH",
            )
            _append(
                failures,
                containment_binding.get("operator_approved") is not True,
                "CONTAINMENT_OWNER_APPROVAL_MISSING",
            )
        if profile_value is not None:
            _append(
                failures,
                profile_value.get("containment_receipt_sha256")
                != containment_digest,
                "PROFILE_CONTAINMENT_DIGEST_MISMATCH",
            )

    if evaluation is not None:
        evaluation_map = _mapping(evaluation, "EVALUATION_SHAPE")
        evaluation_value = _mapping(
            evaluation_map.get("value"), "EVALUATION_VALUE"
        )
        evidence["evaluation_receipt_sha256"] = _raw_digest(
            evaluation_map.get("receipt_sha256"), "EVALUATION_RECEIPT_DIGEST"
        )
        evidence["evaluation_boundary_sha256"] = _raw_digest(
            evaluation_map.get("evaluation_boundary_sha256"),
            "EVALUATION_BOUNDARY_DIGEST",
        )
        input_states["evaluation"] = (
            "EVALUATION_RECEIPT_VALIDATED"
            if evaluation_value.get("evidence_class") == "operator_observed"
            and evaluation_map.get("hard_gate_passed") is True
            else "EVALUATION_HOLD"
        )
        corpus = _mapping(evaluation_value.get("corpus"), "EVALUATION_CORPUS")
        execution = _mapping(
            evaluation_value.get("execution"), "EVALUATION_EXECUTION"
        )
        identifiers["corpus_id"] = corpus.get("corpus_id")
        _append(
            failures,
            evaluation_value.get("evidence_class") != "operator_observed",
            "EVALUATION_NOT_OPERATOR_OBSERVED",
        )
        _append(
            failures,
            evaluation_map.get("hard_gate_passed") is not True,
            "EVALUATION_HARD_GATE_INCOMPLETE",
        )
        if profile_value is not None:
            _append(
                failures,
                evaluation_value.get("profile_sha256")
                != evidence["profile_sha256"],
                "EVALUATION_PROFILE_DIGEST_MISMATCH",
            )
            _append(
                failures,
                evaluation_value.get("comparison_boundary_sha256")
                != evidence["comparison_boundary_sha256"],
                "EVALUATION_COMPARISON_BOUNDARY_MISMATCH",
            )
            profile_evaluation = _mapping(
                profile_value.get("evaluation"), "PROFILE_EVALUATION"
            )
            _append(
                failures,
                corpus.get("corpus_sha256")
                != profile_evaluation.get("corpus_sha256"),
                "EVALUATION_CORPUS_MISMATCH",
            )
            _append(
                failures,
                execution.get("total_cases")
                != profile_evaluation.get("sample_count"),
                "EVALUATION_SAMPLE_COUNT_MISMATCH",
            )
            _append(
                failures,
                execution.get("p95_latency_ms")
                != profile_evaluation.get("p95_latency_ms"),
                "EVALUATION_LATENCY_MISMATCH",
            )
            _append(
                failures,
                execution.get("max_rss_mib")
                != profile_evaluation.get("max_rss_mib"),
                "EVALUATION_MEMORY_MISMATCH",
            )
        if containment is not None:
            containment_corpus = _mapping(
                _mapping(containment, "CONTAINMENT_SHAPE").get(
                    "adversarial_corpus"
                ),
                "CONTAINMENT_CORPUS",
            )
            _append(
                failures,
                containment_corpus.get("corpus_id") != corpus.get("corpus_id"),
                "CONTAINMENT_EVALUATION_CORPUS_ID_MISMATCH",
            )
            _append(
                failures,
                containment_corpus.get("total_cases")
                != execution.get("total_cases"),
                "CONTAINMENT_EVALUATION_COUNT_MISMATCH",
            )

    if request is not None:
        try:
            request_map = _mapping(request.request, "REQUEST_VALUE")
            request_sha256 = _raw_digest(
                request.request_sha256, "REQUEST_DIGEST"
            )
            format_digest = request.format_schema_sha256
            mode = request.mode
            request_model_id = request.model_id
        except (AttributeError, TypeError):
            raise LocalModelReadinessError("REQUEST_SHAPE") from None
        evidence["request_sha256"] = request_sha256
        evidence["format_schema_sha256"] = (
            None
            if format_digest is None
            else _raw_digest(format_digest, "FORMAT_SCHEMA_DIGEST")
        )
        input_states["request"] = "REQUEST_CONTRACT_VALIDATED"
        _append(
            failures,
            request_model_id != logical_alias,
            "REQUEST_ALIAS_MISMATCH",
        )
        options = request_map.get("options")
        fixed_options = {
            "num_ctx": 4096,
            "num_predict": 512,
            "seed": 0,
            "temperature": 0,
        }
        _append(
            failures,
            options != fixed_options
            or request_map.get("keep_alive") != 0
            or request_map.get("raw") is not True
            or request_map.get("stream") is not False
            or request_map.get("think") is not False
            or "tools" in request_map,
            "REQUEST_CONTROLS_MISMATCH",
        )
        _append(
            failures,
            mode == "anomaly_advisory" and format_digest is None,
            "ANOMALY_FORMAT_SCHEMA_MISSING",
        )

    state = "CANDIDATE_PACKET_CONSISTENT" if not failures else "EVIDENCE_HOLD"
    return _packet(
        state=state,
        binding=binding_map,
        failures=failures,
        identifiers=identifiers,
        evidence=evidence,
        input_states=input_states,
        advertised_tools=advertised_tools,
    )


def canonical_json(value: object) -> str:
    """Render a deterministic one-line JSON packet."""

    return _canonical(value).decode("ascii")
