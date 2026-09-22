"""Deterministic, offline construction of bounded Ollama generate requests.

The builder performs no network request, provider discovery, model pull, service
control, filesystem search, host mutation, tool invocation, approval transition,
release, or deployment. Runtime wiring remains a separate acceptance step.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Any


INPUT_SCHEMA = "megalodon-ollama-generate-input-v1"
RECEIPT_SCHEMA = "megalodon-ollama-generate-request-receipt-v1"
MAX_INPUT_BYTES = 64 * 1024
MAX_PROMPT_BYTES = 4096
MAX_REQUEST_BYTES = 6144
NUM_CONTEXT_TOKENS = 4096
MAX_PREDICT_TOKENS = 512
MODEL_ID_RE = re.compile(r"local:qwen-[A-Za-z0-9._-]{1,96}")
CANDIDATE_ID_RE = re.compile(r"a[0-9]{2}")
BANNED_PROMPT_CONTROLS = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f"
    r"\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069\ud800-\udfff\ufeff]"
)
TOP_LEVEL_KEYS = frozenset({"schema", "mode", "model_id", "prompt", "candidate_ids"})
MODES = frozenset({"generic_advisory", "anomaly_advisory"})
FIXED_OPTIONS = {
    "num_ctx": NUM_CONTEXT_TOKENS,
    "num_predict": MAX_PREDICT_TOKENS,
    "seed": 0,
    "temperature": 0,
}
SEPARATE_HOLDS = (
    "RUNTIME_PROVIDER_WIRING",
    "EXACT_MODEL_AND_RUNNER_BINDING",
    "PROVIDER_CONTAINMENT_ACCEPTANCE",
    "SIGNED_ADVERSARIAL_EVALUATION",
    "INDEPENDENT_SECURITY_ACCEPTANCE",
    "RELEASE_AND_DEPLOYMENT_AUTHORITY",
)


class GenerateContractError(ValueError):
    """Fixed-code refusal without untrusted detail."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class BuiltGenerateRequest:
    """Owned canonical request body plus non-authoritative identity hashes."""

    mode: str
    model_id: str
    candidate_ids: tuple[str, ...]
    request: dict[str, Any]
    request_bytes: bytes
    request_sha256: str
    format_schema_sha256: str | None


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GenerateContractError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise GenerateContractError("NON_FINITE_NUMBER")


def parse_input_bytes(data: bytes) -> object:
    """Decode one bounded JSON input without duplicate keys or NaN/Infinity."""

    if type(data) is not bytes or not 1 <= len(data) <= MAX_INPUT_BYTES:
        raise GenerateContractError("INPUT_SIZE")
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except GenerateContractError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise GenerateContractError("INVALID_JSON") from None


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise GenerateContractError("CANONICALIZATION") from None


def _prompt(value: object) -> str:
    if type(value) is not str or not value.strip():
        raise GenerateContractError("PROMPT")
    if BANNED_PROMPT_CONTROLS.search(value):
        raise GenerateContractError("PROMPT")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise GenerateContractError("PROMPT") from None
    if not 1 <= size <= MAX_PROMPT_BYTES:
        raise GenerateContractError("PROMPT")
    return value


def _candidate_ids(value: object, mode: str) -> tuple[str, ...]:
    if type(value) is not list or len(value) > 8:
        raise GenerateContractError("CANDIDATE_IDS")
    if any(
        type(item) is not str or CANDIDATE_ID_RE.fullmatch(item) is None
        for item in value
    ):
        raise GenerateContractError("CANDIDATE_IDS")
    if len(value) != len(set(value)):
        raise GenerateContractError("CANDIDATE_IDS")
    ids = tuple(value)
    if mode == "generic_advisory" and ids:
        raise GenerateContractError("CANDIDATE_IDS_FORBIDDEN")
    if mode == "anomaly_advisory" and not ids:
        raise GenerateContractError("CANDIDATE_IDS_REQUIRED")
    return ids


def anomaly_format_schema(candidate_ids: tuple[str, ...]) -> dict[str, object]:
    """Return the exact structured-output schema consumed by anomaly parsing."""

    if not 1 <= len(candidate_ids) <= 8:
        raise GenerateContractError("CANDIDATE_IDS_REQUIRED")
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "candidate_ids",
            "summary",
            "benign_alternatives",
            "missing_evidence",
        ],
        "properties": {
            "candidate_ids": {
                "type": "array",
                "prefixItems": [{"const": item} for item in candidate_ids],
                "items": False,
                "minItems": len(candidate_ids),
                "maxItems": len(candidate_ids),
            },
            "summary": {
                "type": "string",
                "minLength": 1,
                "maxLength": 600,
            },
            "benign_alternatives": {
                "type": "array",
                "minItems": 1,
                "maxItems": 4,
                "uniqueItems": True,
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 300,
                },
            },
            "missing_evidence": {
                "type": "array",
                "minItems": 1,
                "maxItems": 4,
                "uniqueItems": True,
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 300,
                },
            },
        },
    }


def build_generate_request(value: object) -> BuiltGenerateRequest:
    """Build one closed request without contacting or controlling a provider."""

    if type(value) is not dict or set(value) != TOP_LEVEL_KEYS:
        raise GenerateContractError("INPUT_SHAPE")
    if value["schema"] != INPUT_SCHEMA:
        raise GenerateContractError("SCHEMA_MISMATCH")
    mode = value["mode"]
    if type(mode) is not str or mode not in MODES:
        raise GenerateContractError("MODE")
    model_id = value["model_id"]
    if type(model_id) is not str or MODEL_ID_RE.fullmatch(model_id) is None:
        raise GenerateContractError("MODEL_ID")
    prompt = _prompt(value["prompt"])
    candidate_ids = _candidate_ids(value["candidate_ids"], mode)

    request: dict[str, Any] = {
        "keep_alive": 0,
        "model": model_id,
        "options": dict(FIXED_OPTIONS),
        "prompt": prompt,
        "raw": True,
        "stream": False,
        "think": False,
    }
    format_digest: str | None = None
    if mode == "anomaly_advisory":
        format_schema = anomaly_format_schema(candidate_ids)
        request["format"] = format_schema
        format_digest = sha256(_canonical(format_schema)).hexdigest()

    request_bytes = _canonical(request)
    if len(request_bytes) > MAX_REQUEST_BYTES:
        raise GenerateContractError("REQUEST_SIZE")
    owned_request = json.loads(request_bytes.decode("ascii"))
    return BuiltGenerateRequest(
        mode=mode,
        model_id=model_id,
        candidate_ids=candidate_ids,
        request=owned_request,
        request_bytes=request_bytes,
        request_sha256=sha256(request_bytes).hexdigest(),
        format_schema_sha256=format_digest,
    )


def request_receipt(built: BuiltGenerateRequest) -> dict[str, object]:
    """Project a privacy-minimized receipt; the prompt and request stay private."""

    return {
        "schema": RECEIPT_SCHEMA,
        "state": "REQUEST_CONTRACT_VALIDATED",
        "mode": built.mode,
        "model_id": built.model_id,
        "candidate_ids": list(built.candidate_ids),
        "request_sha256": built.request_sha256,
        "request_bytes": len(built.request_bytes),
        "format_schema_sha256": built.format_schema_sha256,
        "fixed_runtime_options": dict(FIXED_OPTIONS),
        "request_controls": {
            "keep_alive": 0,
            "raw": True,
            "stream": False,
            "think": False,
            "tools_present": False,
        },
        "prompt_retained_in_receipt": False,
        "network_performed": False,
        "remaining_holds": list(SEPARATE_HOLDS),
        "authority": {
            "contacts_provider": False,
            "starts_provider": False,
            "pulls_model": False,
            "changes_host": False,
            "authorizes_tools": False,
            "accepts_model": False,
            "authorizes_release": False,
        },
    }


def canonical_json(value: object) -> str:
    return _canonical(value).decode("ascii")
