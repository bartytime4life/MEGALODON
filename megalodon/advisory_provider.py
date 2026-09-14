"""One explicit, bounded Qwen advisory request to a literal loopback Ollama.

The provider boundary is intentionally not configurable.  It accepts the same
closed request and fingerprint-pinned registry as :mod:`megalodon.advisory`,
reruns that preflight internally, and can make only one non-streaming request
to the compiled IPv4 loopback tuple below.  It has no discovery, proxy,
redirect, tool, subprocess, persistence, capture, or host-action path.
"""

from __future__ import annotations

from dataclasses import dataclass
import http.client
import json
import socket
import threading
import time
from types import MappingProxyType
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
OLLAMA_GENERATE_PATH = "/api/generate"
MAX_PROVIDER_REQUEST_BYTES = 6144
MAX_PROVIDER_BODY_BYTES = 12_288
MAX_SUMMARY_CHARACTERS = 1200
MAX_PREDICT_TOKENS = 512
WATCHDOG_POLL_SECONDS = 0.05
WATCHDOG_JOIN_SECONDS = 0.25

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
_INVOCATION_LOCK = threading.Lock()

_LIMITATIONS = (
    "AI advisory; not evidence or an action.",
    "Model output cannot select or execute a tool, command, target, or response.",
    "Only the canonical privacy-bounded metadata prompt was supplied.",
)

_SUMMARIES = MappingProxyType(
    {
        "PROVIDER_DISABLED": "The local advisory provider is disabled for this invocation.",
        "INVOCATION_CONTROL_INVALID": "The local advisory invocation controls are invalid.",
        "CANCELLED_BEFORE_REQUEST": "The local advisory invocation was cancelled before a provider request.",
        "CANCELLED_DURING_RESPONSE": "The local advisory invocation was cancelled while awaiting its bounded response.",
        "PROVIDER_BUSY": "Another local advisory invocation already holds the concurrency-one boundary.",
        "PROVIDER_TIMEOUT": "The local advisory provider did not complete within the fixed timeout.",
        "PROVIDER_UNAVAILABLE": "The literal-loopback local advisory provider is unavailable.",
        "PROVIDER_REDIRECT_DENIED": "The local advisory provider returned a redirect, which is not followed.",
        "PROVIDER_HTTP_ERROR": "The local advisory provider returned a non-success status.",
        "PROVIDER_PROTOCOL_ERROR": "The local advisory provider response did not match the fixed protocol.",
        "PROVIDER_RESPONSE_TOO_LARGE": "The local advisory provider response exceeded its fixed byte bound.",
        "PROVIDER_RESPONSE_INVALID": "The local advisory provider returned an invalid bounded response.",
        "PROVIDER_MODEL_MISMATCH": "The local advisory provider reported a different model identifier.",
        "PROVIDER_CLOSE_FAILED": "The local advisory provider connection did not close cleanly.",
    }
)


@dataclass(frozen=True, slots=True)
class AdvisoryInvocationReceipt:
    """Immutable, display-only receipt for one attempted advisory invocation."""

    outcome: str
    code: str
    reason_code: str
    summary: str
    limitations: tuple[str, ...]
    model_id: str | None
    model_artifact_sha256: str | None
    registry_sha256: str | None
    provider_request_performed: bool
    policy_version: str = POLICY_VERSION

    def to_dict(self) -> dict[str, Any]:
        """Return a fresh JSON-compatible value with no executable fields."""
        model_receipt = None
        if self.model_id is not None and self.model_artifact_sha256 is not None:
            model_receipt = {
                "provider_class": PROVIDER_CLASS,
                "model_id": self.model_id,
                "model_artifact_sha256": self.model_artifact_sha256,
                "policy_version": self.policy_version,
            }
        return {
            "outcome": self.outcome,
            "code": self.code,
            "reason_code": self.reason_code,
            "summary": self.summary,
            "limitations": list(self.limitations),
            "model_receipt": model_receipt,
            "registry_sha256": self.registry_sha256,
            "provider_request_performed": self.provider_request_performed,
        }


class _LiteralLoopbackConnection(http.client.HTTPConnection):
    """HTTP/1.1 connection that cannot resolve or select another host."""

    def __init__(self, host: str, port: int, *, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._abort_requested = threading.Event()
        self._transport_socket: socket.socket | None = None

    def connect(self) -> None:
        if self.host != LOOPBACK_HOST or self.port != LOOPBACK_PORT:
            raise OSError("literal loopback invariant failed")
        if self._abort_requested.is_set():
            raise OSError("literal loopback connection aborted")
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._transport_socket = connection
        self.sock = connection
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

    def abort(self) -> None:
        """Interrupt any active connect, header wait, or body read."""
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
    """Enforce one monotonic deadline and observable in-flight cancellation."""

    def __init__(
        self,
        connection: _LiteralLoopbackConnection,
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
            name="megalodon-local-advisory-guard",
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
                wait_seconds = min(wait_seconds, WATCHDOG_POLL_SECONDS)
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
            self._thread.join(WATCHDOG_JOIN_SECONDS)
        return reason


class _InvalidProviderResponse(ValueError):
    pass


def _model_fields(admission: AirlockDecision | None) -> tuple[str | None, str | None, str | None]:
    if admission is None:
        return None, None, None
    return (
        admission.model_id,
        admission.model_artifact_sha256,
        admission.registry_sha256,
    )


def _receipt(
    outcome: str,
    reason_code: str,
    *,
    admission: AirlockDecision | None = None,
    provider_request_performed: bool = False,
    summary: str | None = None,
) -> AdvisoryInvocationReceipt:
    model_id, artifact_sha256, registry_sha256 = _model_fields(admission)
    code = {
        "ANSWER": "ADVISORY_ANSWER",
        "DENY": "POLICY_DENIED",
        "ERROR": "LOCAL_PROVIDER_ERROR",
    }[outcome]
    return AdvisoryInvocationReceipt(
        outcome=outcome,
        code=code,
        reason_code=reason_code,
        summary=summary if summary is not None else _SUMMARIES[reason_code],
        limitations=_LIMITATIONS,
        model_id=model_id,
        model_artifact_sha256=artifact_sha256,
        registry_sha256=registry_sha256,
        provider_request_performed=provider_request_performed,
    )


def _canonical_provider_request(admission: AirlockDecision) -> bytes:
    body = {
        "keep_alive": 0,
        "model": admission.model_id,
        "options": {
            "num_predict": MAX_PREDICT_TOKENS,
            "temperature": 0,
        },
        "prompt": admission.prompt,
        "stream": False,
        "think": False,
    }
    return json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if type(key) is not str or key in value:
            raise _InvalidProviderResponse
        value[key] = item
    return value


def _reject_constant(value: str) -> object:
    raise _InvalidProviderResponse from None


def _plain_summary(value: object) -> str:
    if type(value) is not str:
        raise _InvalidProviderResponse
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise _InvalidProviderResponse from exc
    if not encoded or len(encoded) > FIXED_LIMITS["max_output_bytes"]:
        raise _InvalidProviderResponse
    if any(character not in "\t\n\r" and not character.isprintable() for character in value):
        raise _InvalidProviderResponse
    summary = " ".join(value.split())
    if not summary or len(summary) > MAX_SUMMARY_CHARACTERS:
        raise _InvalidProviderResponse
    return summary


def _decode_provider_response(raw: bytes, admission: AirlockDecision) -> str:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, _InvalidProviderResponse) as exc:
        raise _InvalidProviderResponse from exc
    if type(value) is not dict:
        raise _InvalidProviderResponse
    keys = set(value)
    if not _RESPONSE_REQUIRED_KEYS <= keys or not keys <= _RESPONSE_ALLOWED_KEYS:
        raise _InvalidProviderResponse
    if type(value["model"]) is not str or value["model"] != admission.model_id:
        raise _InvalidProviderResponse("model mismatch")
    if value["done"] is not True:
        raise _InvalidProviderResponse
    if "thinking" in value and value["thinking"] != "":
        raise _InvalidProviderResponse
    if "created_at" in value and (
        type(value["created_at"]) is not str
        or not 1 <= len(value["created_at"]) <= 64
        or any(not character.isprintable() for character in value["created_at"])
    ):
        raise _InvalidProviderResponse
    if "done_reason" in value and (
        type(value["done_reason"]) is not str
        or value["done_reason"] not in {"stop", "length"}
    ):
        raise _InvalidProviderResponse
    for key in _RESPONSE_COUNT_KEYS & keys:
        if type(value[key]) is not int or value[key] < 0:
            raise _InvalidProviderResponse
    if "context" in value:
        context = value["context"]
        if type(context) is not list or any(type(item) is not int or item < 0 for item in context):
            raise _InvalidProviderResponse
    return _plain_summary(value["response"])


def _content_length(response: http.client.HTTPResponse) -> int | None:
    raw = response.getheader("Content-Length")
    if raw is None:
        return None
    if type(raw) is not str or not raw.isascii() or not raw.isdecimal():
        raise _InvalidProviderResponse
    return int(raw)


def _bounded_response_body(
    response: http.client.HTTPResponse,
    cancel_event: threading.Event | None,
) -> tuple[bytes | None, str | None]:
    length = _content_length(response)
    if length is not None and length > MAX_PROVIDER_BODY_BYTES:
        return None, "PROVIDER_RESPONSE_TOO_LARGE"
    body = bytearray()
    while True:
        if cancel_event is not None and cancel_event.is_set():
            return None, "CANCELLED_DURING_RESPONSE"
        remaining = MAX_PROVIDER_BODY_BYTES + 1 - len(body)
        chunk = response.read(min(1024, remaining))
        if type(chunk) is not bytes:
            return None, "PROVIDER_PROTOCOL_ERROR"
        if not chunk:
            break
        body.extend(chunk)
        if len(body) > MAX_PROVIDER_BODY_BYTES:
            return None, "PROVIDER_RESPONSE_TOO_LARGE"
    return bytes(body), None


def _invoke_admitted(
    admission: AirlockDecision,
    cancel_event: threading.Event | None,
) -> AdvisoryInvocationReceipt:
    deadline = time.monotonic() + FIXED_LIMITS["timeout_seconds"]
    provider_request_performed = False
    connection: _LiteralLoopbackConnection | None = None
    response: http.client.HTTPResponse | None = None
    guard: _InvocationGuard | None = None
    result: AdvisoryInvocationReceipt
    try:
        body = _canonical_provider_request(admission)
        if len(body) > MAX_PROVIDER_REQUEST_BYTES:
            return _receipt("ERROR", "PROVIDER_PROTOCOL_ERROR", admission=admission)
        if cancel_event is not None and cancel_event.is_set():
            return _receipt("DENY", "CANCELLED_BEFORE_REQUEST", admission=admission)

        connection = _LiteralLoopbackConnection(
            LOOPBACK_HOST,
            LOOPBACK_PORT,
            timeout=FIXED_LIMITS["timeout_seconds"],
        )
        guard = _InvocationGuard(connection, cancel_event, deadline)
        guard.start()
        provider_request_performed = True
        connection.request(
            "POST",
            OLLAMA_GENERATE_PATH,
            body=body,
            headers={
                "Accept": "application/json",
                "Connection": "close",
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        if type(response.status) is not int or not 100 <= response.status <= 599:
            result = _receipt(
                "ERROR",
                "PROVIDER_PROTOCOL_ERROR",
                admission=admission,
                provider_request_performed=True,
            )
        elif 300 <= response.status <= 399:
            result = _receipt(
                "ERROR",
                "PROVIDER_REDIRECT_DENIED",
                admission=admission,
                provider_request_performed=True,
            )
        elif response.status != 200:
            result = _receipt(
                "ERROR",
                "PROVIDER_HTTP_ERROR",
                admission=admission,
                provider_request_performed=True,
            )
        else:
            content_type = response.getheader("Content-Type")
            content_encoding = response.getheader("Content-Encoding")
            if (
                type(content_type) is not str
                or content_type.split(";", 1)[0].strip().lower() != "application/json"
                or content_encoding not in (None, "identity")
            ):
                result = _receipt(
                    "ERROR",
                    "PROVIDER_PROTOCOL_ERROR",
                    admission=admission,
                    provider_request_performed=True,
                )
            else:
                raw, reason = _bounded_response_body(response, cancel_event)
                if reason is not None:
                    result = _receipt(
                        "ERROR",
                        reason,
                        admission=admission,
                        provider_request_performed=True,
                    )
                else:
                    try:
                        summary = _decode_provider_response(raw or b"", admission)
                    except _InvalidProviderResponse as exc:
                        reason = (
                            "PROVIDER_MODEL_MISMATCH"
                            if str(exc) == "model mismatch"
                            else "PROVIDER_RESPONSE_INVALID"
                        )
                        result = _receipt(
                            "ERROR",
                            reason,
                            admission=admission,
                            provider_request_performed=True,
                        )
                    else:
                        result = _receipt(
                            "ANSWER",
                            "REQUEST_COMPLETED",
                            admission=admission,
                            provider_request_performed=True,
                            summary=summary,
                        )
    except (TimeoutError, socket.timeout):
        result = _receipt(
            "ERROR",
            "PROVIDER_TIMEOUT",
            admission=admission,
            provider_request_performed=provider_request_performed,
        )
    except OSError:
        result = _receipt(
            "ERROR",
            "PROVIDER_UNAVAILABLE",
            admission=admission,
            provider_request_performed=provider_request_performed,
        )
    except Exception:
        result = _receipt(
            "ERROR",
            "PROVIDER_PROTOCOL_ERROR",
            admission=admission,
            provider_request_performed=provider_request_performed,
        )
    finally:
        forced_reason = guard.finish() if guard is not None else None
        close_failed = False
        if response is not None:
            try:
                response.close()
            except Exception:
                close_failed = True
        if connection is not None:
            try:
                connection.close()
            except Exception:
                close_failed = True
        if forced_reason is not None:
            result = _receipt(
                "ERROR",
                forced_reason,
                admission=admission,
                provider_request_performed=provider_request_performed,
            )
        elif close_failed:
            result = _receipt(
                "ERROR",
                "PROVIDER_CLOSE_FAILED",
                admission=admission,
                provider_request_performed=provider_request_performed,
            )
    return result


def invoke_local_advisory(
    request: object,
    *,
    local_model_registry: object,
    local_model_registry_sha256: object,
    enabled: object = False,
    cancel_event: object = None,
) -> AdvisoryInvocationReceipt:
    """Run one explicit literal-loopback advisory request or fail closed.

    There is deliberately no endpoint, model, prompt, header, credential,
    provider option, transport, tool, or action parameter.
    """
    if type(enabled) is not bool:
        return _receipt("DENY", "INVOCATION_CONTROL_INVALID")
    if enabled is not True:
        return _receipt("DENY", "PROVIDER_DISABLED")
    if cancel_event is not None and type(cancel_event) is not threading.Event:
        return _receipt("DENY", "INVOCATION_CONTROL_INVALID")
    cancellation = cancel_event
    if cancellation is not None and cancellation.is_set():
        return _receipt("DENY", "CANCELLED_BEFORE_REQUEST")

    admission = preflight_advisory(
        request,
        local_model_registry=local_model_registry,
        local_model_registry_sha256=local_model_registry_sha256,
    )
    if admission.decision != "ADMIT":
        return _receipt(
            "DENY",
            admission.reason_code,
            summary=admission.summary,
        )
    if cancellation is not None and cancellation.is_set():
        return _receipt("DENY", "CANCELLED_BEFORE_REQUEST", admission=admission)
    if not _INVOCATION_LOCK.acquire(blocking=False):
        return _receipt("ERROR", "PROVIDER_BUSY", admission=admission)
    try:
        return _invoke_admitted(admission, cancellation)
    finally:
        _INVOCATION_LOCK.release()
