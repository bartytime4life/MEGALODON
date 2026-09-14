"""One explicit, literal-loopback Ollama advisory call with no tool authority."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import socket
import threading
import time
from typing import Any

from .advisory import (
    MAX_INPUT_BYTES,
    POLICY_VERSION,
    AirlockDecision,
    is_admitted_decision,
)


TIMEOUT_SECONDS = 15
MAX_REQUEST_BODY_BYTES = 6144
MAX_RESPONSE_HEADER_BYTES = 8192
MAX_RESPONSE_BODY_BYTES = 8192
MAX_OUTPUT_BYTES = 4096
READ_POLL_SECONDS = 0.25

_MODEL_ID = re.compile(r"local:qwen-[A-Za-z0-9._-]{1,96}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_EVENT_TYPE = type(threading.Event())
_CALL_LOCK = threading.Lock()
_REQUIRED_RESPONSE_KEYS = frozenset({"model", "response", "done"})
_OPTIONAL_RESPONSE_KEYS = frozenset(
    {
        "context",
        "created_at",
        "done_reason",
        "eval_count",
        "eval_duration",
        "load_duration",
        "prompt_eval_count",
        "prompt_eval_duration",
        "total_duration",
    }
)
_INTEGER_RESPONSE_KEYS = frozenset(
    {
        "eval_count",
        "eval_duration",
        "load_duration",
        "prompt_eval_count",
        "prompt_eval_duration",
        "total_duration",
    }
)
_LIMITATIONS = (
    "AI advisory; not evidence or an action.",
    "Model output is untrusted and may be incomplete or incorrect.",
    "No tool, command, target, query, file, firewall, or host action is authorized.",
)
_FIXED_SUMMARIES = {
    "ADVISORY_DISABLED": "The local advisory call was not explicitly enabled.",
    "ENABLEMENT_INVALID": "The local advisory enablement value is invalid.",
    "ADMIT_REQUIRED": "An intact Qwen Airlock ADMIT decision is required.",
    "CANCELLATION_INVALID": "The cancellation control is invalid.",
    "CANCELLED": "The local advisory call was cancelled.",
    "BUSY": "Another local advisory call is already in progress.",
    "REQUEST_LIMIT_EXCEEDED": "The fixed local advisory request exceeds its byte limit.",
    "CONNECT_FAILED": "The literal-loopback provider connection failed.",
    "TIMEOUT": "The literal-loopback provider call reached its time limit.",
    "REQUEST_FAILED": "The literal-loopback provider request failed.",
    "HTTP_STATUS_INVALID": "The provider returned a non-success HTTP status.",
    "RESPONSE_INVALID": "The provider returned an invalid closed response.",
    "RESPONSE_LIMIT_EXCEEDED": "The provider response exceeds its raw byte limit.",
    "MODEL_MISMATCH": "The provider response model does not match the admitted model.",
    "OUTPUT_LIMIT_EXCEEDED": "The provider response text exceeds its byte limit.",
}


@dataclass(frozen=True, slots=True)
class AdvisoryReceipt:
    """Immutable display-only result; it contains no executable field."""

    outcome: str
    code: str
    summary: str
    limitations: tuple[str, ...]
    model_id: str | None
    model_artifact_sha256: str | None
    registry_sha256: str | None
    policy_version: str
    provider_request_performed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "code": self.code,
            "summary": self.summary,
            "limitations": list(self.limitations),
            "model_receipt": {
                "provider_class": "local_loopback",
                "model_id": self.model_id,
                "model_artifact_sha256": self.model_artifact_sha256,
                "registry_sha256": self.registry_sha256,
                "policy_version": self.policy_version,
            },
            "provider_request_performed": self.provider_request_performed,
        }


class _ProviderFailure(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _valid_digest(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _valid_admit(value: object) -> bool:
    if not is_admitted_decision(value):
        return False
    decision = value
    return (
        decision.decision == "ADMIT"
        and decision.code == "PREFLIGHT_ADMITTED"
        and decision.reason_code == "REQUEST_ADMITTED"
        and decision.summary == "Prompt construction passed the local advisory v1 policy."
        and type(decision.prompt) is str
        and type(decision.prompt_bytes) is int
        and 0 < decision.prompt_bytes <= MAX_INPUT_BYTES
        and decision.prompt_bytes == len(decision.prompt.encode("utf-8"))
        and type(decision.model_id) is str
        and _MODEL_ID.fullmatch(decision.model_id) is not None
        and _valid_digest(decision.model_artifact_sha256)
        and _valid_digest(decision.registry_sha256)
        and type(decision.policy_version) is str
        and decision.policy_version == POLICY_VERSION
        and type(decision.provider_request_performed) is bool
        and decision.provider_request_performed is False
    )


def _receipt(
    outcome: str,
    code: str,
    *,
    performed: bool,
    decision: AirlockDecision | None = None,
    answer: str | None = None,
) -> AdvisoryReceipt:
    return AdvisoryReceipt(
        outcome=outcome,
        code=code,
        summary=answer if answer is not None else _FIXED_SUMMARIES[code],
        limitations=_LIMITATIONS,
        model_id=decision.model_id if decision is not None else None,
        model_artifact_sha256=(
            decision.model_artifact_sha256 if decision is not None else None
        ),
        registry_sha256=decision.registry_sha256 if decision is not None else None,
        policy_version=POLICY_VERSION,
        provider_request_performed=performed,
    )


def _cancelled(cancel_event: object) -> bool:
    return cancel_event is not None and cancel_event.is_set()


def _request_bytes(decision: AirlockDecision) -> bytes:
    body = json.dumps(
        {
            "keep_alive": 0,
            "model": decision.model_id,
            "options": {"num_predict": 1024, "seed": 0, "temperature": 0},
            "prompt": decision.prompt,
            "stream": False,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    if len(body) > MAX_REQUEST_BODY_BYTES:
        raise _ProviderFailure("REQUEST_LIMIT_EXCEEDED")
    head = (
        "POST /api/generate HTTP/1.1\r\n"
        "Host: 127.0.0.1:11434\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    return head + body


def _recv(sock: socket.socket, size: int, deadline: float, cancel_event: object) -> bytes:
    while True:
        if _cancelled(cancel_event):
            raise _ProviderFailure("CANCELLED")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _ProviderFailure("TIMEOUT")
        sock.settimeout(min(READ_POLL_SECONDS, remaining))
        try:
            return sock.recv(size)
        except (TimeoutError, socket.timeout):
            continue


def _response_body(sock: socket.socket, cancel_event: object) -> bytes:
    deadline = time.monotonic() + TIMEOUT_SECONDS
    buffered = bytearray()
    marker = b"\r\n\r\n"
    while marker not in buffered:
        remaining_capacity = MAX_RESPONSE_HEADER_BYTES + len(marker) - len(buffered)
        if remaining_capacity <= 0:
            raise _ProviderFailure("RESPONSE_LIMIT_EXCEEDED")
        chunk = _recv(sock, min(2048, remaining_capacity), deadline, cancel_event)
        if not chunk:
            raise _ProviderFailure("RESPONSE_INVALID")
        buffered.extend(chunk)
    header_bytes, body_start = bytes(buffered).split(marker, 1)
    if len(header_bytes) > MAX_RESPONSE_HEADER_BYTES:
        raise _ProviderFailure("RESPONSE_LIMIT_EXCEEDED")
    try:
        lines = header_bytes.decode("ascii").split("\r\n")
    except UnicodeDecodeError as exc:
        raise _ProviderFailure("RESPONSE_INVALID") from exc
    status = lines[0].split(" ", 2)
    if len(status) != 3 or status[0] not in {"HTTP/1.0", "HTTP/1.1"}:
        raise _ProviderFailure("RESPONSE_INVALID")
    if status[1] != "200":
        raise _ProviderFailure("HTTP_STATUS_INVALID")

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or line[:1].isspace() or ":" not in line:
            raise _ProviderFailure("RESPONSE_INVALID")
        name, value = line.split(":", 1)
        name = name.strip().lower()
        value = value.strip()
        if not name or name in headers:
            raise _ProviderFailure("RESPONSE_INVALID")
        headers[name] = value
    if "transfer-encoding" in headers or "content-encoding" in headers:
        raise _ProviderFailure("RESPONSE_INVALID")
    if headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
        raise _ProviderFailure("RESPONSE_INVALID")
    content_length = headers.get("content-length")
    if content_length is None or not content_length.isascii() or not content_length.isdigit():
        raise _ProviderFailure("RESPONSE_INVALID")
    length = int(content_length)
    if length > MAX_RESPONSE_BODY_BYTES:
        raise _ProviderFailure("RESPONSE_LIMIT_EXCEEDED")
    if len(body_start) > length:
        raise _ProviderFailure("RESPONSE_INVALID")
    body = bytearray(body_start)
    while len(body) < length:
        chunk = _recv(sock, min(2048, length - len(body)), deadline, cancel_event)
        if not chunk:
            raise _ProviderFailure("RESPONSE_INVALID")
        body.extend(chunk)
    return bytes(body)


def _plain_text(value: object, *, max_characters: int) -> bool:
    if type(value) is not str or len(value) > max_characters:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return all(
        character in "\t\n\r" or 32 <= ord(character) != 127 for character in value
    )


def _answer(body: bytes, decision: AirlockDecision) -> str:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _ProviderFailure("RESPONSE_INVALID") from exc
    if type(value) is not dict or not all(type(key) is str for key in value):
        raise _ProviderFailure("RESPONSE_INVALID")
    keys = frozenset(value)
    if not _REQUIRED_RESPONSE_KEYS <= keys or keys - (
        _REQUIRED_RESPONSE_KEYS | _OPTIONAL_RESPONSE_KEYS
    ):
        raise _ProviderFailure("RESPONSE_INVALID")
    if type(value["model"]) is not str or value["model"] != decision.model_id:
        raise _ProviderFailure("MODEL_MISMATCH")
    if value["done"] is not True or type(value["response"]) is not str:
        raise _ProviderFailure("RESPONSE_INVALID")
    answer = value["response"]
    if not answer or not _plain_text(answer, max_characters=MAX_OUTPUT_BYTES):
        raise _ProviderFailure("RESPONSE_INVALID")
    if len(answer.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise _ProviderFailure("OUTPUT_LIMIT_EXCEEDED")
    for key in _INTEGER_RESPONSE_KEYS & keys:
        if type(value[key]) is not int or value[key] < 0:
            raise _ProviderFailure("RESPONSE_INVALID")
    for key in {"created_at", "done_reason"} & keys:
        if not _plain_text(value[key], max_characters=128):
            raise _ProviderFailure("RESPONSE_INVALID")
    if "context" in value and (
        type(value["context"]) is not list
        or len(value["context"]) > MAX_OUTPUT_BYTES
        or not all(type(item) is int and item >= 0 for item in value["context"])
    ):
        raise _ProviderFailure("RESPONSE_INVALID")
    return answer


def request_advisory(
    decision: object,
    *,
    enabled: object = False,
    cancel_event: object = None,
) -> AdvisoryReceipt:
    """Perform at most one fixed literal-loopback advisory request."""
    if type(enabled) is not bool:
        return _receipt("DENY", "ENABLEMENT_INVALID", performed=False)
    if not enabled:
        return _receipt("DENY", "ADVISORY_DISABLED", performed=False)
    if not _valid_admit(decision):
        return _receipt("DENY", "ADMIT_REQUIRED", performed=False)
    admitted = decision
    if cancel_event is not None and type(cancel_event) is not _EVENT_TYPE:
        return _receipt(
            "DENY", "CANCELLATION_INVALID", performed=False, decision=admitted
        )
    if _cancelled(cancel_event):
        return _receipt("DENY", "CANCELLED", performed=False, decision=admitted)
    if not _CALL_LOCK.acquire(blocking=False):
        return _receipt("DENY", "BUSY", performed=False, decision=admitted)

    sock: socket.socket | None = None
    performed = False
    try:
        try:
            request_bytes = _request_bytes(admitted)
        except _ProviderFailure as failure:
            return _receipt("DENY", failure.code, performed=False, decision=admitted)
        if _cancelled(cancel_event):
            return _receipt("DENY", "CANCELLED", performed=False, decision=admitted)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT_SECONDS)
            sock.connect(("127.0.0.1", 11434))
        except socket.timeout:
            return _receipt("ERROR", "TIMEOUT", performed=False, decision=admitted)
        except OSError:
            return _receipt("ERROR", "CONNECT_FAILED", performed=False, decision=admitted)
        if _cancelled(cancel_event):
            return _receipt("DENY", "CANCELLED", performed=False, decision=admitted)
        performed = True
        try:
            sock.sendall(request_bytes)
            body = _response_body(sock, cancel_event)
            answer = _answer(body, admitted)
        except _ProviderFailure as failure:
            outcome = "DENY" if failure.code == "CANCELLED" else "ERROR"
            return _receipt(outcome, failure.code, performed=performed, decision=admitted)
        except (OSError, UnicodeError, ValueError):
            return _receipt(
                "ERROR", "REQUEST_FAILED", performed=performed, decision=admitted
            )
        return _receipt(
            "ANSWER",
            "ANSWER_ACCEPTED",
            performed=True,
            decision=admitted,
            answer=answer,
        )
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        _CALL_LOCK.release()
