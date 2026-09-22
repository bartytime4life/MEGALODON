"""Strict, offline validation for operator-owned Ollama/Qwen profile candidates.

This module never contacts Ollama, starts a model, mutates host state, or grants
provider/model admission. It turns an operator-supplied, closed JSON document
into a deterministic comparison/binding-candidate receipt while preserving the
separate containment, provenance, acceptance, release, and deployment holds.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from math import isfinite
import json
import re
from typing import Any, Mapping, Sequence


PROFILE_SCHEMA = "megalodon-local-model-profile-v1"
PACKET_SCHEMA = "megalodon-local-model-binding-candidate-v1"
COMPARISON_SCHEMA = "megalodon-local-model-comparison-v1"

MAX_PROFILE_BYTES = 64 * 1024
MAX_PROFILES = 32
SHA256_RE = re.compile(r"[a-f0-9]{64}")
PROFILE_ID_RE = re.compile(r"[a-z][a-z0-9-]{2,63}")
MODEL_ALIAS_RE = re.compile(r"qwen[A-Za-z0-9._:-]{1,91}")
MODEL_FAMILY_RE = re.compile(r"qwen[A-Za-z0-9._-]{1,63}")
QUANTIZATION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}")
PURPOSES = frozenset({"advisory", "explanation", "research-evaluation"})
EVIDENCE_CLASSES = frozenset({"operator_observed", "synthetic_fixture"})
BANNED_CONTROLS = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069\ufeff]"
)
TOP_LEVEL_KEYS = frozenset(
    {
        "schema",
        "profile_id",
        "status",
        "evidence_class",
        "provider",
        "endpoint",
        "model_alias",
        "ollama_manifest_digest",
        "artifact_sha256",
        "provenance_sha256",
        "containment_receipt_sha256",
        "model_family",
        "quantization",
        "context_window",
        "operational_context",
        "purpose",
        "structured_output",
        "thinking_enabled",
        "license",
        "source_reference",
        "runner",
        "evaluation",
    }
)
RUNNER_KEYS = frozenset({"name", "version", "binary_sha256"})
EVALUATION_KEYS = frozenset(
    {
        "corpus_sha256",
        "sample_count",
        "schema_valid_count",
        "citation_valid_count",
        "refusal_valid_count",
        "p95_latency_ms",
        "max_rss_mib",
    }
)
SEPARATE_HOLDS = (
    "PROVIDER_CONTAINMENT_ACCEPTANCE",
    "ARTIFACT_PROVENANCE_INDEPENDENT_VERIFICATION",
    "OWNER_MODEL_BINDING",
    "INDEPENDENT_SECURITY_ACCEPTANCE",
    "RELEASE_AND_DEPLOYMENT_AUTHORITY",
)


class ModelProfileError(ValueError):
    """Fixed-code refusal for malformed or over-broad profile input."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ValidatedProfile:
    """Closed, immutable view of one syntactically valid candidate profile."""

    _canonical_value: bytes = field(repr=False)
    canonical_sha256: str
    hard_gate_passed: bool
    gate_failures: tuple[str, ...]
    comparison_boundary_sha256: str

    @property
    def value(self) -> dict[str, Any]:
        """Return an owned JSON view; edits cannot invalidate cached evidence."""
        return json.loads(self._canonical_value)

    @property
    def profile_id(self) -> str:
        return str(self.value["profile_id"])

    @property
    def evidence_class(self) -> str:
        return str(self.value["evidence_class"])


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ModelProfileError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ModelProfileError("NON_FINITE_NUMBER")


def _finite_float(value: str) -> float:
    """Reject numeric overflow as well as explicit NaN/Infinity constants."""
    number = float(value)
    if not isfinite(number):
        raise ModelProfileError("NON_FINITE_NUMBER")
    return number


def parse_profile_bytes(data: bytes) -> object:
    """Decode one bounded JSON document without duplicate keys or non-finite numbers."""

    if type(data) is not bytes or not 1 <= len(data) <= MAX_PROFILE_BYTES:
        raise ModelProfileError("PROFILE_SIZE")
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except ModelProfileError:
        raise
    except (ValueError, RecursionError):
        # Includes UTF-8/JSON errors and the interpreter's integer digit limit.
        raise ModelProfileError("INVALID_JSON") from None


def _text(value: object, *, minimum: int, maximum: int, code: str) -> str:
    if type(value) is not str or not minimum <= len(value) <= maximum:
        raise ModelProfileError(code)
    if value != value.strip() or BANNED_CONTROLS.search(value):
        raise ModelProfileError(code)
    return value


def _sha(value: object, code: str) -> str:
    text = _text(value, minimum=64, maximum=64, code=code)
    if SHA256_RE.fullmatch(text) is None:
        raise ModelProfileError(code)
    return text


def _integer(value: object, *, minimum: int, maximum: int, code: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ModelProfileError(code)
    return value


def _closed_mapping(
    value: object, *, keys: frozenset[str], code: str
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise ModelProfileError(code)
    return value


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _comparison_boundary(profile: Mapping[str, Any]) -> dict[str, object]:
    """Return the exact operating/evaluation boundary required for comparison.

    Model identity, family, quantization, context capacity, latency, and memory
    are intentionally excluded: those are the candidate attributes being
    compared. Everything that defines the workload or provider execution
    environment is included so unlike-for-like observations cannot be ranked.
    """

    runner = profile["runner"]
    evaluation = profile["evaluation"]
    return {
        "evidence_class": profile["evidence_class"],
        "provider": profile["provider"],
        "endpoint": profile["endpoint"],
        "purpose": profile["purpose"],
        "operational_context": profile["operational_context"],
        "structured_output": profile["structured_output"],
        "thinking_enabled": profile["thinking_enabled"],
        "runner_name": runner["name"],
        "runner_version": runner["version"],
        "runner_binary_sha256": runner["binary_sha256"],
        "corpus_sha256": evaluation["corpus_sha256"],
        "sample_count": evaluation["sample_count"],
    }


def validate_profile(value: object) -> ValidatedProfile:
    """Validate one closed candidate and derive deterministic hard-gate status."""

    profile = _closed_mapping(value, keys=TOP_LEVEL_KEYS, code="PROFILE_SHAPE")

    if profile["schema"] != PROFILE_SCHEMA:
        raise ModelProfileError("SCHEMA_MISMATCH")
    profile_id = _text(
        profile["profile_id"], minimum=3, maximum=64, code="PROFILE_ID"
    )
    if PROFILE_ID_RE.fullmatch(profile_id) is None:
        raise ModelProfileError("PROFILE_ID")
    if profile["status"] != "candidate":
        raise ModelProfileError("STATUS")
    if (
        type(profile["evidence_class"]) is not str
        or profile["evidence_class"] not in EVIDENCE_CLASSES
    ):
        raise ModelProfileError("EVIDENCE_CLASS")
    if profile["provider"] != "ollama":
        raise ModelProfileError("PROVIDER")
    if profile["endpoint"] != "http://127.0.0.1:11434":
        raise ModelProfileError("ENDPOINT")

    alias = _text(
        profile["model_alias"], minimum=5, maximum=96, code="MODEL_ALIAS"
    )
    if MODEL_ALIAS_RE.fullmatch(alias) is None:
        raise ModelProfileError("MODEL_ALIAS")

    for field in (
        "ollama_manifest_digest",
        "artifact_sha256",
        "provenance_sha256",
        "containment_receipt_sha256",
    ):
        _sha(profile[field], field.upper())

    family = _text(
        profile["model_family"], minimum=5, maximum=64, code="MODEL_FAMILY"
    )
    if MODEL_FAMILY_RE.fullmatch(family) is None:
        raise ModelProfileError("MODEL_FAMILY")
    quantization = _text(
        profile["quantization"], minimum=1, maximum=32, code="QUANTIZATION"
    )
    if QUANTIZATION_RE.fullmatch(quantization) is None:
        raise ModelProfileError("QUANTIZATION")

    context_window = _integer(
        profile["context_window"],
        minimum=256,
        maximum=1_048_576,
        code="CONTEXT_WINDOW",
    )
    operational_context = _integer(
        profile["operational_context"],
        minimum=256,
        maximum=4096,
        code="OPERATIONAL_CONTEXT",
    )
    if operational_context > context_window:
        raise ModelProfileError("CONTEXT_RELATION")
    if (
        type(profile["purpose"]) is not str
        or profile["purpose"] not in PURPOSES
    ):
        raise ModelProfileError("PURPOSE")
    if profile["structured_output"] is not True:
        raise ModelProfileError("STRUCTURED_OUTPUT_REQUIRED")
    if profile["thinking_enabled"] is not False:
        raise ModelProfileError("THINKING_MUST_BE_DISABLED")

    _text(profile["license"], minimum=1, maximum=128, code="LICENSE")
    _text(
        profile["source_reference"],
        minimum=1,
        maximum=512,
        code="SOURCE_REFERENCE",
    )

    runner = _closed_mapping(
        profile["runner"], keys=RUNNER_KEYS, code="RUNNER_SHAPE"
    )
    if runner["name"] != "ollama":
        raise ModelProfileError("RUNNER_NAME")
    version = _text(
        runner["version"], minimum=1, maximum=64, code="RUNNER_VERSION"
    )
    if VERSION_RE.fullmatch(version) is None:
        raise ModelProfileError("RUNNER_VERSION")
    _sha(runner["binary_sha256"], "RUNNER_BINARY_SHA256")

    evaluation = _closed_mapping(
        profile["evaluation"], keys=EVALUATION_KEYS, code="EVALUATION_SHAPE"
    )
    _sha(evaluation["corpus_sha256"], "CORPUS_SHA256")
    sample_count = _integer(
        evaluation["sample_count"],
        minimum=1,
        maximum=1_000_000,
        code="SAMPLE_COUNT",
    )
    counts: dict[str, int] = {}
    for field in (
        "schema_valid_count",
        "citation_valid_count",
        "refusal_valid_count",
    ):
        counts[field] = _integer(
            evaluation[field],
            minimum=0,
            maximum=sample_count,
            code=field.upper(),
        )
    _integer(
        evaluation["p95_latency_ms"],
        minimum=1,
        maximum=3_600_000,
        code="P95_LATENCY_MS",
    )
    _integer(
        evaluation["max_rss_mib"],
        minimum=1,
        maximum=1_048_576,
        code="MAX_RSS_MIB",
    )

    failures = tuple(
        name
        for name, count in (
            ("SCHEMA_VALIDATION_INCOMPLETE", counts["schema_valid_count"]),
            ("CITATION_VALIDATION_INCOMPLETE", counts["citation_valid_count"]),
            ("REFUSAL_VALIDATION_INCOMPLETE", counts["refusal_valid_count"]),
        )
        if count != sample_count
    )
    copied = json.loads(_canonical(profile).decode("ascii"))
    profile_digest = sha256(_canonical(copied)).hexdigest()
    boundary_digest = sha256(_canonical(_comparison_boundary(copied))).hexdigest()
    return ValidatedProfile(
        _canonical_value=_canonical(copied),
        canonical_sha256=profile_digest,
        hard_gate_passed=not failures,
        gate_failures=failures,
        comparison_boundary_sha256=boundary_digest,
    )


def binding_candidate_packet(profile: ValidatedProfile) -> dict[str, object]:
    """Return a deterministic packet that cannot be mistaken for acceptance."""

    state = (
        "SYNTHETIC_ONLY"
        if profile.evidence_class == "synthetic_fixture"
        else (
            "CANDIDATE_VALIDATED"
            if profile.hard_gate_passed
            else "EVALUATION_HOLD"
        )
    )
    value = profile.value
    evaluation = value["evaluation"]
    return {
        "schema": PACKET_SCHEMA,
        "state": state,
        "profile_id": profile.profile_id,
        "profile_sha256": profile.canonical_sha256,
        "comparison_boundary_sha256": profile.comparison_boundary_sha256,
        "provider": {
            "name": value["provider"],
            "endpoint": value["endpoint"],
            "model_alias": value["model_alias"],
            "ollama_manifest_digest": value["ollama_manifest_digest"],
            "runner_version": value["runner"]["version"],
            "runner_binary_sha256": value["runner"]["binary_sha256"],
        },
        "artifact": {
            "artifact_sha256": value["artifact_sha256"],
            "provenance_sha256": value["provenance_sha256"],
            "containment_receipt_sha256": value[
                "containment_receipt_sha256"
            ],
        },
        "runtime_profile": {
            "model_family": value["model_family"],
            "quantization": value["quantization"],
            "context_window": value["context_window"],
            "operational_context": value["operational_context"],
            "purpose": value["purpose"],
            "structured_output": True,
            "thinking_enabled": False,
        },
        "evaluation": {
            "corpus_sha256": evaluation["corpus_sha256"],
            "sample_count": evaluation["sample_count"],
            "schema_valid_count": evaluation["schema_valid_count"],
            "citation_valid_count": evaluation["citation_valid_count"],
            "refusal_valid_count": evaluation["refusal_valid_count"],
            "p95_latency_ms": evaluation["p95_latency_ms"],
            "max_rss_mib": evaluation["max_rss_mib"],
            "hard_gate_passed": profile.hard_gate_passed,
            "gate_failures": list(profile.gate_failures),
        },
        "remaining_holds": list(SEPARATE_HOLDS),
        "authority": {
            "starts_provider": False,
            "pulls_model": False,
            "changes_host": False,
            "admits_model": False,
            "authorizes_release": False,
        },
    }


def _ranking_key(profile: ValidatedProfile) -> tuple[object, ...]:
    evaluation = profile.value["evaluation"]
    return (
        not profile.hard_gate_passed,
        evaluation["p95_latency_ms"],
        evaluation["max_rss_mib"],
        -evaluation["sample_count"],
        profile.profile_id,
        profile.canonical_sha256,
    )


def compare_profiles(
    profiles: Sequence[ValidatedProfile],
) -> dict[str, object]:
    """Rank like-for-like candidates without selecting or admitting one."""

    if not 2 <= len(profiles) <= MAX_PROFILES:
        raise ModelProfileError("PROFILE_COUNT")
    ids = [profile.profile_id for profile in profiles]
    if len(ids) != len(set(ids)):
        raise ModelProfileError("DUPLICATE_PROFILE_ID")
    digests = [profile.canonical_sha256 for profile in profiles]
    if len(digests) != len(set(digests)):
        raise ModelProfileError("DUPLICATE_PROFILE")
    boundaries = {
        profile.comparison_boundary_sha256 for profile in profiles
    }
    if len(boundaries) != 1:
        raise ModelProfileError("COMPARISON_BOUNDARY_MISMATCH")

    boundary_digest = next(iter(boundaries))
    ordered = sorted(profiles, key=_ranking_key)
    return {
        "schema": COMPARISON_SCHEMA,
        "state": "COMPARISON_ONLY",
        "comparison_boundary_sha256": boundary_digest,
        "ranking": [
            {
                "rank": index,
                "profile_id": profile.profile_id,
                "profile_sha256": profile.canonical_sha256,
                "hard_gate_passed": profile.hard_gate_passed,
                "gate_failures": list(profile.gate_failures),
                "p95_latency_ms": profile.value["evaluation"][
                    "p95_latency_ms"
                ],
                "max_rss_mib": profile.value["evaluation"]["max_rss_mib"],
                "sample_count": profile.value["evaluation"]["sample_count"],
            }
            for index, profile in enumerate(ordered, start=1)
        ],
        "selection": None,
        "remaining_holds": list(SEPARATE_HOLDS),
        "limitations": [
            "Metrics are operator-supplied observations, not independent attestation.",
            "All ranked profiles share one exact workload and runner boundary digest.",
            "Ranking does not select, admit, pull, start, release, or deploy a model.",
            "Lower latency and memory only break ties after closed validation gates.",
        ],
    }


def canonical_json(value: object) -> str:
    """Serialize bounded output deterministically for hashing and review."""

    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
