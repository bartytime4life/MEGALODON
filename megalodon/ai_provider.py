"""Explicit, bounded Ollama checks and text generation for the AI control plane.

No URL, model, prompt, tool, or destination comes from Ollama. The existing
Qwen advisory transport supplies the literal socket, framing budget and lock.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import threading
import time
from typing import Any

from .config import AISettings
from .provider_containment import qwen_provider_posture
from . import qwen_advisory as transport


class AIProviderError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _request(path: str, method: str, body: bytes | None, timeout: float) -> bytes:
    """Exactly one request on the compiled literal-loopback transport."""
    if path not in {"/api/tags", "/api/generate"} or method not in {"GET", "POST"}:
        raise AIProviderError("POLICY_REJECTION")
    if body is not None and len(body) > transport.MAX_PROVIDER_REQUEST_BYTES:
        raise AIProviderError("REQUEST_TOO_LARGE")
    if not transport._INVOCATION_LOCK.acquire(blocking=False):
        raise AIProviderError("CONCURRENCY_LIMIT_REACHED")
    process_lock: int | None = None
    connection: transport._LiteralLoopbackHTTPConnection | None = None
    guard: transport._InvocationGuard | None = None
    try:
        try:
            process_lock = transport._acquire_process_invocation_lock()
        except transport._ProviderConcurrencyBusy:
            raise AIProviderError("CONCURRENCY_LIMIT_REACHED") from None
        except transport._ProviderConcurrencyUnavailable:
            raise AIProviderError("CONCURRENCY_CONTROL_UNAVAILABLE") from None
        deadline = time.monotonic() + timeout
        connection = transport._LiteralLoopbackHTTPConnection(
            transport.LOOPBACK_HOST, transport.LOOPBACK_PORT, timeout=timeout,
        )
        guard = transport._InvocationGuard(connection, None, deadline)
        guard.start()
        headers = {"Accept": "application/json", "Connection": "close"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        if response.status != 200:
            raise AIProviderError("MODEL_MISSING" if response.status == 404 else "PROVIDER_ERROR")
        if response.getheader("Content-Encoding") not in (None, "identity"):
            raise AIProviderError("INVALID_RESPONSE")
        content_type = response.getheader("Content-Type", "")
        if not content_type.lower().startswith("application/json"):
            raise AIProviderError("INVALID_RESPONSE")
        data = transport._read_provider_body(response, connection, deadline, None)
        if guard.finish() is not None:
            raise AIProviderError("REQUEST_TIMEOUT")
        return data
    except AIProviderError:
        raise
    except (TimeoutError, socket.timeout):
        raise AIProviderError("REQUEST_TIMEOUT") from None
    except (OSError, http.client.HTTPException):
        raise AIProviderError("OLLAMA_UNAVAILABLE") from None
    except (ValueError, transport._ProviderResponseInvalid):
        raise AIProviderError("INVALID_RESPONSE") from None
    finally:
        if guard is not None:
            guard.finish()
        if connection is not None:
            connection.close()
        if process_lock is not None:
            os.close(process_lock)
        transport._INVOCATION_LOCK.release()


def _json(data: bytes) -> object:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_strict_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, RecursionError):
        raise AIProviderError("INVALID_RESPONSE") from None


def _admitted(settings: AISettings, deadline: float | None = None) -> dict[str, Any]:
    if not settings.enabled:
        raise AIProviderError("DISABLED")
    if (settings.provider != "ollama" or settings.endpoint != "http://127.0.0.1:11434"
            or type(settings.model) is not str
            or re.fullmatch(r"qwen[A-Za-z0-9._:-]{1,91}", settings.model) is None
            or type(settings.model_digest) is not str
            or re.fullmatch(r"[a-f0-9]{64}", settings.model_digest) is None
            or type(settings.timeout_seconds) is not int or not 1 <= settings.timeout_seconds <= 15
            or type(settings.max_context) is not int or not 256 <= settings.max_context <= 4096):
        raise AIProviderError("POLICY_REJECTION")
    try:
        posture = qwen_provider_posture()
    except (OSError, ValueError):
        raise AIProviderError("POLICY_REJECTION") from None
    if posture["listening"] == "no":
        raise AIProviderError("OLLAMA_UNAVAILABLE")
    if posture["loopback_only"] is not True:
        raise AIProviderError("POLICY_REJECTION")
    remaining = settings.timeout_seconds if deadline is None else min(settings.timeout_seconds, deadline - time.monotonic())
    if remaining <= 0:
        raise AIProviderError("REQUEST_TIMEOUT")
    tags = _json(_request("/api/tags", "GET", None, remaining))
    if type(tags) is not dict or type(tags.get("models")) is not list or len(tags["models"]) > 256:
        raise AIProviderError("INVALID_RESPONSE")
    matches = [item for item in tags["models"] if type(item) is dict and item.get("name") == settings.model]
    if len(matches) != 1:
        raise AIProviderError("MODEL_MISSING")
    digest = matches[0].get("digest")
    if type(digest) is not str or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
        raise AIProviderError("INVALID_RESPONSE")
    if digest != settings.model_digest:
        raise AIProviderError("MODEL_MISMATCH")
    return {"model": settings.model, "digest": digest, "loopback_only": True}


def inventory(settings: AISettings) -> dict[str, object]:
    """Read the fixed local tag list; never starts inference or admits use."""
    try:
        tags = _json(_request("/api/tags", "GET", None, settings.timeout_seconds))
        if type(tags) is not dict or type(tags.get("models")) is not list or len(tags["models"]) > 256:
            raise AIProviderError("INVALID_RESPONSE")
        matches = [item for item in tags["models"] if type(item) is dict and item.get("name") == settings.model]
        if len(matches) > 1:
            raise AIProviderError("INVALID_RESPONSE")
        digest = matches[0].get("digest") if matches else None
        if digest is not None and (type(digest) is not str or re.fullmatch(r"[a-f0-9]{64}", digest) is None):
            raise AIProviderError("INVALID_RESPONSE")
        return {"model_present": bool(matches), "digest_matches": digest == settings.model_digest,
                "observed_digest": digest}
    except AIProviderError as exc:
        return {"model_present": False, "digest_matches": False, "error_code": exc.code}


def generate(settings: AISettings, prompt: str, *, max_tokens: int = 256) -> str:
    """One deterministic request after live listener and manifest admission."""
    if type(settings.timeout_seconds) is not int or not 1 <= settings.timeout_seconds <= 15:
        raise AIProviderError("POLICY_REJECTION")
    deadline = time.monotonic() + settings.timeout_seconds
    _admitted(settings, deadline)
    if type(prompt) is not str or not 1 <= len(prompt.encode("utf-8")) <= 4096:
        raise AIProviderError("REQUEST_TOO_LARGE")
    if type(max_tokens) is not int or not 1 <= max_tokens <= 256:
        raise AIProviderError("POLICY_REJECTION")
    body = json.dumps({
        "model": settings.model, "prompt": prompt, "stream": False,
        "think": False, "raw": True, "keep_alive": 0,
        "options": {"temperature": 0, "num_ctx": settings.max_context,
                    "num_predict": max_tokens},
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AIProviderError("REQUEST_TIMEOUT")
    data = _request("/api/generate", "POST", body, remaining)
    try:
        output, _ = transport._parse_provider_output(data, settings.model)
        summary = transport._plain_summary(output)
        if not summary:
            raise AIProviderError("INVALID_RESPONSE")
        return summary
    except (ValueError, transport._ProviderResponseInvalid):
        raise AIProviderError("INVALID_RESPONSE") from None


def status(settings: AISettings, *, probe: bool = True) -> dict[str, object]:
    """Never report ready from a listener or tag alone."""
    base: dict[str, object] = {"schema": "megalodon-ai-status-v1", "provider": "ollama",
                               "model": settings.model, "state": "disabled",
                               "inference_verified": False, "ollama_available": None,
                               "loopback_only": None}
    try:
        base["loopback_only"] = qwen_provider_posture()["loopback_only"]
    except (OSError, ValueError):
        pass
    try:
        if probe:
            challenge = generate(settings, "Reply with the single word READY.", max_tokens=32)
            if challenge != "READY":
                raise AIProviderError("INVALID_RESPONSE")
            base["state"] = "model_ready"
            base["inference_verified"] = True
            identity = {"digest": settings.model_digest}
        else:
            identity = _admitted(settings)
            base["state"] = "model_available"
        base["loopback_only"] = True
        base["ollama_available"] = True
        base["model_digest"] = identity["digest"]
    except AIProviderError as exc:
        base["state"] = {
            "DISABLED": "disabled", "OLLAMA_UNAVAILABLE": "ollama_unavailable",
            "MODEL_MISSING": "model_missing", "MODEL_MISMATCH": "policy_rejection",
            "POLICY_REJECTION": "policy_rejection", "REQUEST_TIMEOUT": "request_timeout",
            "INVALID_RESPONSE": "invalid_response", "CONCURRENCY_LIMIT_REACHED": "model_loading",
            "CONCURRENCY_CONTROL_UNAVAILABLE": "concurrency_unavailable",
        }.get(exc.code, "invalid_response")
        base["error_code"] = exc.code
        if exc.code == "OLLAMA_UNAVAILABLE":
            base["ollama_available"] = False
        if exc.code in {"MODEL_MISSING", "MODEL_MISMATCH"}:
            base["ollama_available"] = True
    return base
