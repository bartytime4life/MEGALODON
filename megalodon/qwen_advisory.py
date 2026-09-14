"""One explicit, bounded Qwen advisory request to a literal loopback provider."""

from __future__ import annotations

from dataclasses import dataclass
import http.client
import json
import socket
import threading
import time
from typing import Any

from .advisory import (
    AirlockDecision,
    FIXED_LIMITS,
    POLICY_VERSION,
    PROVIDER_CLASS,
    preflight_advisory,
)


LOOPBACK_HOST = "127.0.0.1"
LOOPBACK_PORT = 11434
GENERATE_PATH = "/api/generate"
MAX_OUTPUT_BYTES = FIXED_LIMITS["max_output_bytes"]
TIMEOUT_SECONDS = FIXED_LIMITS["timeout_seconds"]
MAX_PROVIDER_ENVELOPE_BYTES = MAX_OUTPUT_BYTES * 8
MAX_SUMMARY_CHARACTERS = 1200

_READ_CHUNK_BYTES = 4096
_INVOCATION_LOCK = threading.Lock()
_LIMITATIONS = (
    "This is an AI advisory, not evidence or an action.",
    "Qwen received only the approved aggregate projection and cannot execute tools or responses.",
)


class _ProviderResponseInvalid(ValueError):
    """A non-sensitive marker for an invalid local provider response."""


class _LiteralLoopbackHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that never resolves a name or honors a proxy."""

    def connect(self) -> None:
        if self.host != LOOPBACK_HOST or self.port != LOOPBACK_PORT:
            raise OSError("literal loopback policy violation")
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            connection.settimeout(self.timeout)
            connection.connect((LOOPBACK_HOST, LOOPBACK_PORT))
        except BaseException:
            connection.close()
            raise
        self.sock = connection


@dataclass(frozen=True, slots=True)
class QwenAdvisoryResult:
    """Immutable advisory result plus non-display runtime accounting."""

    outcome: str
    code: str
    reason_code: str
    summary: str
    limitations: tuple[str, ...]
    model_id: str
    model_artifact_sha256: str
    prompt_bytes: int
    output_bytes: int
    provider_request_performed: bool
    policy_version: str = POLICY_VERSION
    provider_class: str = PROVIDER_CLASS

    def to_dict(self) -> dict[str, Any]:
        """Return the closed display-only ``advisoryResult`` value."""
        return {
            "outcome": self.outcome,
            "code": self.code,
            "summary": self.summary,
            "limitations": list(self.limitations),
            "model_receipt": {
                "provider_class": self.provider_class,
                "model_id": self.model_id,
                "model_artifact_sha256": self.model_artifact_sha256,
                "policy_version": self.policy_version,
            },
        }


def _remaining_seconds(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("local advisory deadline exceeded")
    return min(float(TIMEOUT_SECONDS), remaining)


def _set_connection_timeout(
    connection: http.client.HTTPConnection, deadline: float
) -> None:
    remaining = _remaining_seconds(deadline)
    connection.timeout = remaining
    active_socket = connection.sock
    if active_socket is not None:
        active_socket.settimeout(remaining)


def _request_bytes(model_id: str, prompt: str) -> bytes:
    return json.dumps(
        {
            "model": model_id,
            "prompt": prompt,
            "stream": False,
            "think": False,
            "raw": True,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _content_length(response: http.client.HTTPResponse) -> int | None:
    value = response.getheader("Content-Length")
    if value is None:
        return None
    if type(value) is not str or not value.isascii() or not value.isdigit():
        raise _ProviderResponseInvalid("invalid content length")
    length = int(value)
    if length > MAX_PROVIDER_ENVELOPE_BYTES:
        raise _ProviderResponseInvalid("provider envelope exceeds limit")
    return length


def _read_provider_body(
    response: http.client.HTTPResponse,
    connection: http.client.HTTPConnection,
    deadline: float,
) -> bytes:
    expected_length = _content_length(response)
    chunks: list[bytes] = []
    received = 0
    while True:
        _set_connection_timeout(connection, deadline)
        chunk = response.read1(
            min(_READ_CHUNK_BYTES, MAX_PROVIDER_ENVELOPE_BYTES + 1 - received)
        )
        if type(chunk) is not bytes:
            raise _ProviderResponseInvalid("provider returned a non-byte body")
        if not chunk:
            break
        chunks.append(chunk)
        received += len(chunk)
        if received > MAX_PROVIDER_ENVELOPE_BYTES:
            raise _ProviderResponseInvalid("provider envelope exceeds limit")
    if expected_length is not None and received != expected_length:
        raise _ProviderResponseInvalid("provider body was partial")
    return b"".join(chunks)


def _parse_provider_output(body: bytes, model_id: str) -> tuple[str, int]:
    def reject_constant(value: str) -> None:
        raise _ProviderResponseInvalid("non-finite JSON value")

    try:
        value = json.loads(body.decode("utf-8"), parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _ProviderResponseInvalid("provider body is not valid UTF-8 JSON") from exc
    if type(value) is not dict:
        raise _ProviderResponseInvalid("provider response is not an object")
    if (
        type(value.get("model")) is not str
        or value["model"] != model_id
        or value.get("done") is not True
        or type(value.get("response")) is not str
    ):
        raise _ProviderResponseInvalid("provider response identity or shape mismatch")
    thinking = value.get("thinking")
    if thinking is not None and (type(thinking) is not str or thinking.strip()):
        raise _ProviderResponseInvalid("provider returned a thinking trace")

    output = value["response"]
    output_bytes = len(output.encode("utf-8"))
    if output_bytes > MAX_OUTPUT_BYTES:
        raise _ProviderResponseInvalid("model output exceeds limit")
    return output, output_bytes


def _plain_summary(output: str) -> str:
    summary = " ".join(output.split())
    if not summary:
        return ""
    if len(summary) > MAX_SUMMARY_CHARACTERS or any(
        ord(character) < 32 or ord(character) == 127 for character in summary
    ):
        raise _ProviderResponseInvalid("model output violates the display contract")
    return summary


def _result(
    admitted: AirlockDecision,
    *,
    outcome: str,
    code: str,
    reason_code: str,
    summary: str,
    output_bytes: int = 0,
    provider_request_performed: bool = False,
) -> QwenAdvisoryResult:
    if (
        admitted.prompt is None
        or admitted.model_id is None
        or admitted.model_artifact_sha256 is None
    ):
        raise RuntimeError("Qwen result construction requires an admitted preflight")
    return QwenAdvisoryResult(
        outcome=outcome,
        code=code,
        reason_code=reason_code,
        summary=summary,
        limitations=_LIMITATIONS,
        model_id=admitted.model_id,
        model_artifact_sha256=admitted.model_artifact_sha256,
        prompt_bytes=admitted.prompt_bytes,
        output_bytes=output_bytes,
        provider_request_performed=provider_request_performed,
    )


def _provider_error(
    admitted: AirlockDecision, reason_code: str, *, request_performed: bool
) -> QwenAdvisoryResult:
    return _result(
        admitted,
        outcome="ERROR",
        code="LOCAL_PROVIDER_ERROR",
        reason_code=reason_code,
        summary="The local Qwen provider did not return a valid bounded advisory.",
        provider_request_performed=request_performed,
    )


def invoke_qwen_advisory(
    request: object,
    *,
    enabled: object,
    local_model_registry: object,
    local_model_registry_sha256: object,
) -> AirlockDecision | QwenAdvisoryResult:
    """Perform at most one explicit Qwen request after a fresh Airlock preflight.

    The only network destination is the numeric IPv4 loopback address
    ``127.0.0.1:11434`` and the only path is ``/api/generate``. The function
    performs no discovery, model pull/start, retry, redirect, fallback, tool
    call, file access, database access, subprocess, or host mutation.
    """
    admitted = preflight_advisory(
        request,
        local_model_registry=local_model_registry,
        local_model_registry_sha256=local_model_registry_sha256,
    )
    if admitted.decision != "ADMIT":
        return admitted
    if enabled is not True:
        return _result(
            admitted,
            outcome="DENY",
            code="POLICY_DENIED",
            reason_code="EXPLICIT_ENABLEMENT_REQUIRED",
            summary="An explicit one-invocation Qwen enablement was not supplied.",
        )
    if not _INVOCATION_LOCK.acquire(blocking=False):
        return _result(
            admitted,
            outcome="DENY",
            code="POLICY_DENIED",
            reason_code="CONCURRENCY_LIMIT_REACHED",
            summary="The concurrency-one local Qwen advisory slot is busy.",
        )

    connection: http.client.HTTPConnection | None = None
    response: http.client.HTTPResponse | None = None
    request_performed = False
    try:
        deadline = time.monotonic() + TIMEOUT_SECONDS
        if admitted.prompt is None or admitted.model_id is None:
            return _provider_error(
                admitted, "ADMITTED_PREFLIGHT_INVALID", request_performed=False
            )
        body = _request_bytes(admitted.model_id, admitted.prompt)
        connection = _LiteralLoopbackHTTPConnection(
            LOOPBACK_HOST,
            LOOPBACK_PORT,
            timeout=_remaining_seconds(deadline),
        )
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Connection": "close",
            "Content-Length": str(len(body)),
            "Content-Type": "application/json",
            "Host": f"{LOOPBACK_HOST}:{LOOPBACK_PORT}",
        }
        _set_connection_timeout(connection, deadline)
        request_performed = True
        connection.request("POST", GENERATE_PATH, body=body, headers=headers)
        _set_connection_timeout(connection, deadline)
        response = connection.getresponse()
        if response.status != 200:
            raise _ProviderResponseInvalid("provider returned a non-success status")
        content_type = response.getheader("Content-Type")
        if (
            type(content_type) is not str
            or content_type.split(";", 1)[0].strip().lower() != "application/json"
        ):
            raise _ProviderResponseInvalid("provider returned a non-JSON content type")
        content_encoding = response.getheader("Content-Encoding")
        if content_encoding not in (None, "identity"):
            raise _ProviderResponseInvalid("provider returned encoded content")

        output, output_bytes = _parse_provider_output(
            _read_provider_body(response, connection, deadline), admitted.model_id
        )
        summary = _plain_summary(output)
        _remaining_seconds(deadline)
        if not summary:
            return _result(
                admitted,
                outcome="ABSTAIN",
                code="INSUFFICIENT_ALLOWED_CONTEXT",
                reason_code="EMPTY_MODEL_OUTPUT",
                summary="The permitted metadata was insufficient for a useful explanation.",
                output_bytes=output_bytes,
                provider_request_performed=True,
            )
        return _result(
            admitted,
            outcome="ANSWER",
            code="ADVISORY_ANSWER",
            reason_code="BOUNDED_MODEL_OUTPUT_ACCEPTED",
            summary=summary,
            output_bytes=output_bytes,
            provider_request_performed=True,
        )
    except TimeoutError:
        return _provider_error(
            admitted, "PROVIDER_TIMEOUT", request_performed=request_performed
        )
    except _ProviderResponseInvalid:
        return _provider_error(
            admitted, "PROVIDER_RESPONSE_INVALID", request_performed=request_performed
        )
    except (OSError, http.client.HTTPException):
        return _provider_error(
            admitted, "LOCAL_PROVIDER_UNAVAILABLE", request_performed=request_performed
        )
    except Exception:
        return _provider_error(
            admitted, "LOCAL_PROVIDER_FAILURE", request_performed=request_performed
        )
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        _INVOCATION_LOCK.release()
