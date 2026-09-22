"""Offline validation for privacy-minimized Ollama model identity observations.

The module consumes an explicit operator-supplied JSON observation. It performs
no network request, process discovery, model pull, service control, filesystem
search, artifact read, host mutation, approval transition, release, or deploy.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from typing import Any, Mapping


OBSERVATION_SCHEMA = "megalodon-ollama-identity-observation-v1"
RECEIPT_SCHEMA = "megalodon-ollama-identity-receipt-v1"
MAX_INPUT_BYTES = 64 * 1024
SHA256_RE = re.compile(r"[a-f0-9]{64}")
BINDING_ALIAS_RE = re.compile(r"local:qwen-[A-Za-z0-9._-]{1,96}")
MODEL_TAG_RE = re.compile(r"qwen[A-Za-z0-9._:/-]{1,123}")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}")
TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:/-]{0,127}")
BANNED_CONTROLS = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069\ufeff]"
)

TOP_KEYS = frozenset(
    {
        "schema",
        "evidence_class",
        "observed_at",
        "endpoint",
        "binding_alias",
        "model_tag",
        "version",
        "tags",
        "show",
        "artifact",
    }
)
VERSION_KEYS = frozenset({"value", "response_sha256", "binary_sha256"})
TAGS_KEYS = frozenset(
    {
        "response_sha256",
        "matched_name",
        "matched_model",
        "manifest_sha256",
        "size_bytes",
        "details",
    }
)
SHOW_KEYS = frozenset(
    {
        "request_model",
        "response_sha256",
        "modified_at",
        "capabilities",
        "parameters_sha256",
        "template_sha256",
        "license_sha256",
        "model_info_sha256",
        "details",
    }
)
DETAIL_KEYS = frozenset(
    {"format", "family", "parameter_size", "quantization_level"}
)
ARTIFACT_KEYS = frozenset({"artifact_sha256", "provenance_sha256"})
EVIDENCE_CLASSES = frozenset({"synthetic_fixture", "operator_observed"})
REMAINING_HOLDS = (
    "API_SNAPSHOT_ORIGIN_NOT_AUTHENTICATED",
    "LOADED_RUNTIME_BYTES_NOT_ATTESTED",
    "ARTIFACT_PROVENANCE_INDEPENDENT_VERIFICATION",
    "PROVIDER_CONTAINMENT_ACCEPTANCE",
    "OWNER_MODEL_BINDING",
    "INDEPENDENT_SECURITY_ACCEPTANCE",
    "RELEASE_AND_DEPLOYMENT_AUTHORITY",
)


class OllamaIdentityError(ValueError):
    """Fixed-code refusal that carries no untrusted input detail."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise OllamaIdentityError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise OllamaIdentityError("NON_FINITE_NUMBER")


def parse_observation_bytes(data: bytes) -> object:
    if type(data) is not bytes or not 1 <= len(data) <= MAX_INPUT_BYTES:
        raise OllamaIdentityError("OBSERVATION_SIZE")
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except OllamaIdentityError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise OllamaIdentityError("INVALID_JSON") from None


def _closed(value: object, keys: frozenset[str], code: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise OllamaIdentityError(code)
    return value


def _text(
    value: object,
    *,
    minimum: int,
    maximum: int,
    code: str,
    pattern: re.Pattern[str] | None = None,
) -> str:
    if type(value) is not str or not minimum <= len(value) <= maximum:
        raise OllamaIdentityError(code)
    if value != value.strip() or BANNED_CONTROLS.search(value):
        raise OllamaIdentityError(code)
    if pattern is not None and pattern.fullmatch(value) is None:
        raise OllamaIdentityError(code)
    return value


def _sha(value: object, code: str) -> str:
    return _text(
        value,
        minimum=64,
        maximum=64,
        code=code,
        pattern=SHA256_RE,
    )


def _timestamp(value: object, code: str) -> str:
    text = _text(value, minimum=20, maximum=64, code=code)
    if not text.endswith("Z"):
        raise OllamaIdentityError(code)
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError:
        raise OllamaIdentityError(code) from None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise OllamaIdentityError(code)
    return text


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _details(value: object, code: str) -> dict[str, str]:
    details = _closed(value, DETAIL_KEYS, code)
    normalized: dict[str, str] = {}
    for key in sorted(DETAIL_KEYS):
        normalized[key] = _text(
            details[key],
            minimum=1,
            maximum=128,
            code=code,
            pattern=TOKEN_RE,
        )
    if not normalized["family"].lower().startswith("qwen"):
        raise OllamaIdentityError("MODEL_FAMILY")
    return normalized


def validate_observation(value: object) -> dict[str, Any]:
    """Validate a closed identity observation without authenticating its origin."""

    observation = _closed(value, TOP_KEYS, "OBSERVATION_SHAPE")
    if observation["schema"] != OBSERVATION_SCHEMA:
        raise OllamaIdentityError("SCHEMA_MISMATCH")
    if observation["evidence_class"] not in EVIDENCE_CLASSES:
        raise OllamaIdentityError("EVIDENCE_CLASS")
    _timestamp(observation["observed_at"], "OBSERVED_AT")
    if observation["endpoint"] != "http://127.0.0.1:11434":
        raise OllamaIdentityError("ENDPOINT")
    binding_alias = _text(
        observation["binding_alias"],
        minimum=12,
        maximum=108,
        code="BINDING_ALIAS",
        pattern=BINDING_ALIAS_RE,
    )
    model_tag = _text(
        observation["model_tag"],
        minimum=5,
        maximum=128,
        code="MODEL_TAG",
        pattern=MODEL_TAG_RE,
    )

    version = _closed(observation["version"], VERSION_KEYS, "VERSION_SHAPE")
    version_value = _text(
        version["value"],
        minimum=1,
        maximum=64,
        code="VERSION_VALUE",
        pattern=VERSION_RE,
    )
    _sha(version["response_sha256"], "VERSION_RESPONSE_SHA256")
    _sha(version["binary_sha256"], "RUNNER_BINARY_SHA256")

    tags = _closed(observation["tags"], TAGS_KEYS, "TAGS_SHAPE")
    _sha(tags["response_sha256"], "TAGS_RESPONSE_SHA256")
    for field in ("matched_name", "matched_model"):
        matched = _text(
            tags[field],
            minimum=5,
            maximum=128,
            code="TAG_IDENTITY",
            pattern=MODEL_TAG_RE,
        )
        if matched != model_tag:
            raise OllamaIdentityError("TAG_IDENTITY")
    manifest_sha256 = _sha(tags["manifest_sha256"], "MANIFEST_SHA256")
    if type(tags["size_bytes"]) is not int or not 1 <= tags["size_bytes"] <= 2**50:
        raise OllamaIdentityError("MODEL_SIZE")
    tag_details = _details(tags["details"], "TAGS_DETAILS")

    show = _closed(observation["show"], SHOW_KEYS, "SHOW_SHAPE")
    if show["request_model"] != model_tag:
        raise OllamaIdentityError("SHOW_MODEL")
    _sha(show["response_sha256"], "SHOW_RESPONSE_SHA256")
    _timestamp(show["modified_at"], "SHOW_MODIFIED_AT")
    capabilities = show["capabilities"]
    if (
        type(capabilities) is not list
        or not 1 <= len(capabilities) <= 16
        or len(capabilities) != len(set(capabilities))
    ):
        raise OllamaIdentityError("CAPABILITIES")
    normalized_capabilities = [
        _text(
            item,
            minimum=1,
            maximum=64,
            code="CAPABILITIES",
            pattern=TOKEN_RE,
        )
        for item in capabilities
    ]
    if "completion" not in normalized_capabilities:
        raise OllamaIdentityError("COMPLETION_CAPABILITY_REQUIRED")
    for field in (
        "parameters_sha256",
        "template_sha256",
        "license_sha256",
        "model_info_sha256",
    ):
        _sha(show[field], field.upper())
    show_details = _details(show["details"], "SHOW_DETAILS")
    if show_details != tag_details:
        raise OllamaIdentityError("DETAILS_MISMATCH")

    artifact = _closed(
        observation["artifact"], ARTIFACT_KEYS, "ARTIFACT_SHAPE"
    )
    artifact_sha256 = _sha(artifact["artifact_sha256"], "ARTIFACT_SHA256")
    provenance_sha256 = _sha(
        artifact["provenance_sha256"], "PROVENANCE_SHA256"
    )

    copied = json.loads(_canonical(observation).decode("ascii"))
    observation_sha256 = sha256(_canonical(copied)).hexdigest()
    identity_material = {
        "binding_alias": binding_alias,
        "model_tag": model_tag,
        "manifest_sha256": manifest_sha256,
        "artifact_sha256": artifact_sha256,
        "provenance_sha256": provenance_sha256,
        "runner_version": version_value,
        "runner_binary_sha256": version["binary_sha256"],
        "details": tag_details,
        "capabilities": sorted(normalized_capabilities),
        "source_response_sha256": {
            "version": version["response_sha256"],
            "tags": tags["response_sha256"],
            "show": show["response_sha256"],
        },
    }
    return {
        "value": copied,
        "observation_sha256": observation_sha256,
        "provider_identity_sha256": sha256(
            _canonical(identity_material)
        ).hexdigest(),
        "identity_material": identity_material,
    }


def identity_receipt(validated: Mapping[str, Any]) -> dict[str, object]:
    """Project a privacy-minimized non-authoritative identity receipt."""

    value = validated["value"]
    material = deepcopy(validated["identity_material"])
    capabilities = list(material.pop("capabilities"))
    return {
        "schema": RECEIPT_SCHEMA,
        "state": (
            "SYNTHETIC_ONLY"
            if value["evidence_class"] == "synthetic_fixture"
            else "IDENTITY_OBSERVATION_VALIDATED"
        ),
        "evidence_class": value["evidence_class"],
        "observed_at": value["observed_at"],
        "observation_sha256": validated["observation_sha256"],
        "provider_identity_sha256": validated["provider_identity_sha256"],
        "profile_material": material,
        "capability_observation": {
            "listed": capabilities,
            "tools_capability_present": "tools" in capabilities,
            "tools_used_or_authorized": False,
        },
        "remaining_holds": list(REMAINING_HOLDS),
        "authority": {
            "contacts_provider": False,
            "starts_provider": False,
            "pulls_model": False,
            "changes_host": False,
            "attests_loaded_bytes": False,
            "approves_binding": False,
            "authorizes_release": False,
        },
        "limitations": [
            "The validator checks supplied snapshot consistency, not snapshot origin.",
            "API metadata and hashes do not attest the bytes loaded for a generation.",
            "Capability listing does not grant tool, detector, or action authority.",
        ],
    }


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
