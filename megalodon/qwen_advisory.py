"""One explicit, bounded Qwen advisory request to a literal loopback provider."""

from __future__ import annotations

from dataclasses import dataclass, replace
import http.client
import json
import re
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
MAX_PROVIDER_REQUEST_BYTES = 6144
MAX_PROVIDER_ENVELOPE_BYTES = MAX_OUTPUT_BYTES * 8
MAX_PROVIDER_PROTOCOL_BYTES = 8192
MAX_SUMMARY_CHARACTERS = 1200
MAX_PREDICT_TOKENS = 512

_READ_CHUNK_BYTES = 4096
_WATCHDOG_POLL_SECONDS = 0.05
_WATCHDOG_JOIN_SECONDS = 0.25
_INVOCATION_LOCK = threading.Lock()
_RESPONSE_REQUIRED_KEYS = frozenset({"model", "response", "done"})
_RESPONSE_ALLOWED_KEYS = frozenset(
    {
        "model",
        "created_at",
        "response",
        "thinking",
        "done",
        "done_reason",
        "context",
        "total_duration",
        "load_duration",
        "prompt_eval_count",
        "prompt_eval_cached_count",
        "prompt_eval_duration",
        "eval_count",
        "eval_duration",
    }
)
_RESPONSE_COUNT_KEYS = frozenset(
    {
        "total_duration",
        "load_duration",
        "prompt_eval_count",
        "prompt_eval_cached_count",
        "prompt_eval_duration",
        "eval_count",
        "eval_duration",
    }
)
_LIMITATIONS = (
    "This is an AI advisory, not evidence or an action.",
    "Qwen received only the approved aggregate projection and cannot execute tools or responses.",
)
_DISPLAY_CONTROLS = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069\ud800-\udfff\ufeff]"
)
_RESULT_CODES = {
    "ANSWER": "ADVISORY_ANSWER", "ABSTAIN": "INSUFFICIENT_ALLOWED_CONTEXT",
    "DENY": "POLICY_DENIED", "ERROR": "LOCAL_PROVIDER_ERROR",
}


def bounded_advisory_text(value: object) -> bool:
    """One visible text field, with explicit controls shared by the browser."""
    return (type(value) is str and 1 <= len(value) <= MAX_SUMMARY_CHARACTERS
            and bool(value.strip()) and _DISPLAY_CONTROLS.search(value) is None)


class _ProviderResponseInvalid(ValueError):
    """A non-sensitive marker for an invalid local provider response."""


class _ProviderRequestInvalid(ValueError):
    """A non-sensitive marker for an invalid bounded provider request."""


class _ProtocolBudgetReader:
    """Bound response status, headers, chunk framing, and trailers."""

    def __init__(self, wrapped: Any, limit: int) -> None:
        self._wrapped = wrapped
        self._remaining = limit

    def _consume(self, value: object) -> bytes:
        if type(value) is not bytes or len(value) > self._remaining:
            raise _ProviderResponseInvalid("provider response protocol exceeds limit")
        self._remaining -= len(value)
        return value

    def readline(self, size: int = -1) -> bytes:
        request_size = self._remaining + 1
        if size >= 0:
            request_size = min(request_size, size)
        return self._consume(self._wrapped.readline(request_size))

    def read(self, size: int = -1) -> bytes:
        request_size = self._remaining + 1
        if size >= 0:
            request_size = min(request_size, size)
        return self._consume(self._wrapped.read(request_size))

    def __getattr__(self, name: str) -> Any:
        return getattr(self._wrapped, name)


class _BoundedHTTPResponse(http.client.HTTPResponse):
    """HTTP response whose parsed protocol framing shares one byte budget."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if self.fp is None:
            raise _ProviderResponseInvalid("provider response stream unavailable")
        self._protocol_reader = _ProtocolBudgetReader(
            self.fp, MAX_PROVIDER_PROTOCOL_BYTES
        )
        self.fp = self._protocol_reader


class _LiteralLoopbackHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that never resolves a name or honors a proxy."""

    response_class = _BoundedHTTPResponse

    def __init__(self, host: str, port: int, *, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._abort_requested = threading.Event()
        self._transport_socket: socket.socket | None = None

    def connect(self) -> None:
        if self.host != LOOPBACK_HOST or self.port != LOOPBACK_PORT:
            raise OSError("literal loopback policy violation")
        if self._abort_requested.is_set():
            raise OSError("literal loopback connection aborted")
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._transport_socket = connection
        try:
            connection.settimeout(self.timeout)
            if self._abort_requested.is_set():
                raise OSError("literal loopback connection aborted")
            connection.connect((LOOPBACK_HOST, LOOPBACK_PORT))
            if self._abort_requested.is_set():
                raise OSError("literal loopback connection aborted")
        except BaseException:
            if self.sock is connection:
                self.sock = None
            connection.close()
            if self._transport_socket is connection:
                self._transport_socket = None
            raise
        self.sock = connection

    def abort(self) -> None:
        """Interrupt only this connection's active loopback transport."""
        self._abort_requested.set()
        connection = self._transport_socket
        if connection is None:
            return
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except (OSError, ValueError):
            pass
        try:
            connection.close()
        except (OSError, ValueError):
            pass
        if self.sock is connection:
            self.sock = None


class _InvocationGuard:
    """Enforce the shared deadline and observe explicit in-flight cancellation."""

    def __init__(
        self,
        connection: _LiteralLoopbackHTTPConnection,
        cancel_event: threading.Event | None,
        deadline: float,
    ) -> None:
        self._connection = connection
        self._cancel_event = cancel_event
        self._deadline = deadline
        self._complete = threading.Event()
        self._lock = threading.Lock()
        self._reason: str | None = None
        self._started = False
        self._thread = threading.Thread(
            target=self._watch,
            name="megalodon-qwen-advisory-guard",
            daemon=True,
        )

    def _trigger_reason(self) -> str | None:
        if self._cancel_event is not None and self._cancel_event.is_set():
            return "CANCELLED_DURING_RESPONSE"
        if time.monotonic() >= self._deadline:
            return "PROVIDER_TIMEOUT"
        return None

    def _trip(self, reason: str) -> None:
        with self._lock:
            if self._complete.is_set() or self._reason is not None:
                return
            self._reason = reason
        self._connection.abort()

    def _watch(self) -> None:
        while not self._complete.is_set():
            reason = self._trigger_reason()
            if reason is not None:
                self._trip(reason)
                return
            remaining = max(0.0, self._deadline - time.monotonic())
            wait_seconds = remaining
            if self._cancel_event is not None:
                wait_seconds = min(wait_seconds, _WATCHDOG_POLL_SECONDS)
            if self._complete.wait(wait_seconds):
                return

    def start(self) -> None:
        self._thread.start()
        self._started = True

    def finish(self) -> str | None:
        with self._lock:
            if self._reason is None:
                self._reason = self._trigger_reason()
            self._complete.set()
            reason = self._reason
        if self._started:
            self._thread.join(_WATCHDOG_JOIN_SECONDS)
        return reason


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


def validated_qwen_result(value: object, *, policy_version: str = POLICY_VERSION) -> QwenAdvisoryResult:
    """Own and check runtime accounting before a consumer displays a result.

    This validates consistency, not model authenticity or statement accuracy.
    It invokes no methods on arbitrary result objects or field subclasses.
    """
    if type(value) is not QwenAdvisoryResult:
        raise ValueError("Qwen advisory result is invalid")
    try:
        result = replace(value)
        if (type(policy_version) is not str
                or policy_version not in (POLICY_VERSION, "local-model-anomaly-advisory-v1")
                or type(result.outcome) is not str or type(result.code) is not str
                or _RESULT_CODES.get(result.outcome) != result.code
                or not bounded_advisory_text(result.summary)
                or type(result.limitations) is not tuple or not 1 <= len(result.limitations) <= 8
                or any(not bounded_advisory_text(item) for item in result.limitations)
                or len(set(result.limitations)) != len(result.limitations)
                or type(result.provider_class) is not str or result.provider_class != PROVIDER_CLASS
                or type(result.policy_version) is not str or result.policy_version != policy_version
                or type(result.model_id) is not str
                or re.fullmatch(r"local:qwen-[A-Za-z0-9._-]{1,96}", result.model_id) is None
                or type(result.model_artifact_sha256) is not str
                or re.fullmatch(r"[a-f0-9]{64}", result.model_artifact_sha256) is None
                or type(result.reason_code) is not str
                or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", result.reason_code) is None
                or type(result.prompt_bytes) is not int or not 1 <= result.prompt_bytes <= 4096
                or type(result.output_bytes) is not int or not 0 <= result.output_bytes <= 4096
                or type(result.provider_request_performed) is not bool
                or (result.outcome in {"ANSWER", "ABSTAIN"} and not result.provider_request_performed)
                or (result.outcome == "ANSWER" and result.output_bytes == 0)
                or (result.outcome == "ANSWER" and len(result.summary.encode("utf-8")) > result.output_bytes)
                or (result.outcome == "DENY" and result.provider_request_performed)
                or (result.outcome in {"DENY", "ERROR"} and result.output_bytes != 0)):
            raise ValueError
        return result
    except (AttributeError, KeyError, MemoryError, OverflowError, TypeError, ValueError):
        raise ValueError("Qwen advisory result is invalid") from None


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
            "keep_alive": 0,
            "model": model_id,
            "options": {
                "num_predict": MAX_PREDICT_TOKENS,
                "temperature": 0,
            },
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
    cancel_event: threading.Event | None,
) -> bytes:
    expected_length = _content_length(response)
    chunks: list[bytes] = []
    received = 0
    while True:
        if cancel_event is not None and cancel_event.is_set():
            raise InterruptedError("local advisory invocation cancelled")
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


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if type(key) is not str or key in value:
            raise _ProviderResponseInvalid("provider response has duplicate keys")
        value[key] = item
    return value


def _parse_provider_output(body: bytes, model_id: str) -> tuple[str, int]:
    def reject_constant(value: str) -> None:
        raise _ProviderResponseInvalid("non-finite JSON value")

    try:
        value = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise _ProviderResponseInvalid("provider body is not valid UTF-8 JSON") from exc
    if type(value) is not dict:
        raise _ProviderResponseInvalid("provider response is not an object")
    keys = set(value)
    if not _RESPONSE_REQUIRED_KEYS <= keys or not keys <= _RESPONSE_ALLOWED_KEYS:
        raise _ProviderResponseInvalid("provider response fields are not closed")
    if (
        type(value.get("model")) is not str
        or value["model"] != model_id
        or value.get("done") is not True
        or type(value.get("response")) is not str
    ):
        raise _ProviderResponseInvalid("provider response identity or shape mismatch")
    thinking = value.get("thinking")
    if "thinking" in keys and (type(thinking) is not str or thinking.strip()):
        raise _ProviderResponseInvalid("provider returned a thinking trace")
    created_at = value.get("created_at")
    if "created_at" in keys and (
        type(created_at) is not str
        or not 1 <= len(created_at) <= 64
        or any(not character.isprintable() for character in created_at)
    ):
        raise _ProviderResponseInvalid("provider timestamp is invalid")
    done_reason = value.get("done_reason")
    # A finished request can still contain a token-limited partial answer.
    # Keep legacy omission compatible; an explicit reason must be normal stop.
    if "done_reason" in keys and (type(done_reason) is not str or done_reason != "stop"):
        raise _ProviderResponseInvalid("provider completion reason is invalid")
    for key in _RESPONSE_COUNT_KEYS & keys:
        if type(value[key]) is not int or value[key] < 0:
            raise _ProviderResponseInvalid("provider accounting is invalid")
    context = value.get("context")
    if "context" in keys and (
        type(context) is not list
        or any(type(item) is not int or item < 0 for item in context)
    ):
        raise _ProviderResponseInvalid("provider context is invalid")

    output = value["response"]
    try:
        output_bytes = len(output.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise _ProviderResponseInvalid("model output is not valid UTF-8") from exc
    if output_bytes > MAX_OUTPUT_BYTES:
        raise _ProviderResponseInvalid("model output exceeds limit")
    return output, output_bytes


def _plain_summary(output: str) -> str:
    # Check before normalization so split() cannot erase disallowed controls.
    if _DISPLAY_CONTROLS.search(output.replace("\t", "").replace("\r", "").replace("\n", "")):
        raise _ProviderResponseInvalid("model output violates the display contract")
    summary = " ".join(output.split())
    if not summary:
        return ""
    if not bounded_advisory_text(summary):
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
        policy_version=admitted.policy_version,
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


def _cancelled_before_request(admitted: AirlockDecision) -> QwenAdvisoryResult:
    return _result(
        admitted,
        outcome="DENY",
        code="POLICY_DENIED",
        reason_code="CANCELLED_BEFORE_REQUEST",
        summary="The local Qwen advisory was cancelled before its request.",
    )


def invoke_qwen_advisory(
    request: object,
    *,
    enabled: object,
    local_model_registry: object,
    local_model_registry_sha256: object,
    cancel_event: object = None,
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
    return _invoke_admitted(admitted, enabled=enabled, cancel_event=cancel_event)


def invoke_qwen_anomaly_advisory(
    request: object, *, enabled: object, local_model_registry: object,
    local_model_registry_sha256: object, cancel_event: object = None,
) -> AirlockDecision | QwenAdvisoryResult:
    """Explain recomputed offline candidates under the separate anomaly policy.

    Shares the original literal-loopback transport, lock, deadline and response
    parser. A v1 registry cannot opt into the richer projection implicitly.
    """
    from .anomaly_advisory import preflight_anomaly_advisory

    admitted = preflight_anomaly_advisory(
        request, local_model_registry=local_model_registry,
        local_model_registry_sha256=local_model_registry_sha256,
    )
    return _invoke_admitted(admitted, enabled=enabled, cancel_event=cancel_event)


def _invoke_admitted(
    admitted: AirlockDecision, *, enabled: object, cancel_event: object,
) -> AirlockDecision | QwenAdvisoryResult:
    """Private transport shared only after repository-owned fresh admission."""
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
    if cancel_event is not None and type(cancel_event) is not threading.Event:
        return _result(
            admitted,
            outcome="DENY",
            code="POLICY_DENIED",
            reason_code="INVOCATION_CONTROL_INVALID",
            summary="The local Qwen cancellation control is invalid.",
        )
    cancellation = cancel_event
    if cancellation is not None and cancellation.is_set():
        return _cancelled_before_request(admitted)
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
    guard: _InvocationGuard | None = None
    request_performed = False
    forced_reason: str | None = None
    close_failed = False
    result: QwenAdvisoryResult
    try:
        if cancellation is not None and cancellation.is_set():
            return _cancelled_before_request(admitted)
        deadline = time.monotonic() + TIMEOUT_SECONDS
        if admitted.prompt is None or admitted.model_id is None:
            result = _provider_error(
                admitted, "ADMITTED_PREFLIGHT_INVALID", request_performed=False
            )
        else:
            body = _request_bytes(admitted.model_id, admitted.prompt)
            if len(body) > MAX_PROVIDER_REQUEST_BYTES:
                raise _ProviderRequestInvalid("provider request exceeds limit")
            if cancellation is not None and cancellation.is_set():
                return _cancelled_before_request(admitted)
            connection = _LiteralLoopbackHTTPConnection(
                LOOPBACK_HOST,
                LOOPBACK_PORT,
                timeout=_remaining_seconds(deadline),
            )
            guard = _InvocationGuard(connection, cancellation, deadline)
            guard.start()
            headers = {
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Connection": "close",
                "Content-Length": str(len(body)),
                "Content-Type": "application/json",
                "Host": f"{LOOPBACK_HOST}:{LOOPBACK_PORT}",
            }
            _set_connection_timeout(connection, deadline)
            if cancellation is not None and cancellation.is_set():
                return _cancelled_before_request(admitted)
            request_performed = True
            connection.request("POST", GENERATE_PATH, body=body, headers=headers)
            _set_connection_timeout(connection, deadline)
            response = connection.getresponse()
            if response.status != 200:
                raise _ProviderResponseInvalid("provider returned a non-success status")
            content_type = response.getheader("Content-Type")
            if (
                type(content_type) is not str
                or content_type.split(";", 1)[0].strip().lower()
                != "application/json"
            ):
                raise _ProviderResponseInvalid(
                    "provider returned a non-JSON content type"
                )
            content_encoding = response.getheader("Content-Encoding")
            if content_encoding not in (None, "identity"):
                raise _ProviderResponseInvalid("provider returned encoded content")

            output, output_bytes = _parse_provider_output(
                _read_provider_body(response, connection, deadline, cancellation),
                admitted.model_id,
            )
            summary = _plain_summary(output)
            _remaining_seconds(deadline)
            if not summary:
                result = _result(
                    admitted,
                    outcome="ABSTAIN",
                    code="INSUFFICIENT_ALLOWED_CONTEXT",
                    reason_code="EMPTY_MODEL_OUTPUT",
                    summary="The permitted metadata was insufficient for a useful explanation.",
                    output_bytes=output_bytes,
                    provider_request_performed=True,
                )
            else:
                result = _result(
                    admitted,
                    outcome="ANSWER",
                    code="ADVISORY_ANSWER",
                    reason_code="BOUNDED_MODEL_OUTPUT_ACCEPTED",
                    summary=summary,
                    output_bytes=output_bytes,
                    provider_request_performed=True,
                )
    except TimeoutError:
        result = _provider_error(
            admitted, "PROVIDER_TIMEOUT", request_performed=request_performed
        )
    except InterruptedError:
        result = _provider_error(
            admitted,
            "CANCELLED_DURING_RESPONSE",
            request_performed=request_performed,
        )
    except _ProviderRequestInvalid:
        result = _provider_error(
            admitted, "PROVIDER_REQUEST_INVALID", request_performed=False
        )
    except _ProviderResponseInvalid:
        result = _provider_error(
            admitted, "PROVIDER_RESPONSE_INVALID", request_performed=request_performed
        )
    except (OSError, http.client.HTTPException):
        result = _provider_error(
            admitted, "LOCAL_PROVIDER_UNAVAILABLE", request_performed=request_performed
        )
    except Exception:
        result = _provider_error(
            admitted, "LOCAL_PROVIDER_FAILURE", request_performed=request_performed
        )
    finally:
        try:
            if guard is not None:
                forced_reason = guard.finish()
        finally:
            try:
                if response is not None:
                    try:
                        response.close()
                    except Exception:
                        close_failed = True
            finally:
                try:
                    if connection is not None:
                        try:
                            connection.close()
                        except Exception:
                            close_failed = True
                finally:
                    _INVOCATION_LOCK.release()
    if forced_reason is not None:
        return _provider_error(
            admitted, forced_reason, request_performed=request_performed
        )
    if close_failed:
        return _provider_error(
            admitted, "PROVIDER_CLOSE_FAILED", request_performed=request_performed
        )
    return result
