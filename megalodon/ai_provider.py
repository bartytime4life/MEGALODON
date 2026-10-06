"""Explicit, bounded Ollama checks and text generation for the AI control plane.

No URL, model, prompt, tool, or destination comes from Ollama. The existing
Qwen advisory transport supplies the literal socket, framing budget and lock.
"""

from __future__ import annotations

from collections import OrderedDict
from contextlib import contextmanager
from datetime import datetime, timezone
import http.client
import json
import math
import os
import re
import socket
import threading
import time
from typing import Any

from .config import AISettings, valid_model_name
from .provider_containment import qwen_provider_posture
from . import qwen_advisory as transport


_observations: OrderedDict = OrderedDict()
_observation_lock = threading.Lock()
_generation_lock = threading.Lock()
_active_cancel = threading.Event()
_request_context = threading.local()
_priority_lock = threading.Lock()
_active_priority = None
_active_owner = None
_manual_waiters = 0
OPERATOR_OWNER = 'hud-operator'
_operator_events: set[threading.Event] = set()
_operator_lock = threading.Lock()
_TOOL_CHOICE = re.compile(r'megalodon(?:\.[a-z_]{1,32}){1,4}')


def cancel_current(owner=None) -> None:
    """Interrupt only this process's active model request; no Ollama service kill."""
    with _priority_lock:
        if owner is None or owner == _active_owner:
            _active_cancel.set()


@contextmanager
def operator_request():
    """Mark this thread's model calls as one cancellable HUD operator request."""
    event = threading.Event()
    with _operator_lock:
        _operator_events.add(event)
    previous = getattr(_request_context, 'operator', None)
    _request_context.operator = event
    try:
        yield event
    finally:
        _request_context.operator = previous
        with _operator_lock:
            _operator_events.discard(event)


def cancel_operator() -> bool:
    """Stop HUD operator requests only; background explanations keep their slot rules."""
    with _operator_lock:
        events = list(_operator_events)
    for event in events:
        event.set()
    if events:
        cancel_current(owner=OPERATOR_OWNER)
    return bool(events)


def last_observation(settings: AISettings) -> dict:
    """Process-local response observations, qualified by exact model identity."""
    with _observation_lock:
        return dict(_observations.get((settings.model, settings.model_digest, settings.compute_mode), {}))


def reject_response(settings: AISettings) -> None:
    """A completed transport reply may still fail the caller's response contract."""
    with _observation_lock:
        entry = _observations.get((settings.model, settings.model_digest, settings.compute_mode))
        if entry is not None:
            entry['error_code'] = 'INVALID_RESPONSE'
            entry['last_response_at'] = entry.pop('previous_response_at', None)


class AIProviderError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _ModelMetadataResponse(transport._BoundedHTTPResponse):
    """Model metadata includes tensor names and licenses; generated text does not."""

    body_limit = 256 * 1024


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _request(path: str, method: str, body: bytes | None, timeout: float,
             *, deadline: float | None = None) -> bytes:
    """Exactly one request on the compiled literal-loopback transport."""
    if (path,method) not in {("/api/tags","GET"),("/api/ps","GET"),("/api/show","POST"),("/api/generate","POST")}:
        raise AIProviderError("POLICY_REJECTION")
    if body is not None and len(body) > transport.MAX_PROVIDER_REQUEST_BYTES:
        raise AIProviderError("REQUEST_TOO_LARGE")
    request_deadline = time.monotonic() + timeout
    if deadline is not None:
        request_deadline = min(request_deadline, deadline)
    if request_deadline <= time.monotonic():
        raise AIProviderError("REQUEST_TIMEOUT")
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
        remaining = request_deadline - time.monotonic()
        if remaining <= 0:
            raise AIProviderError("REQUEST_TIMEOUT")
        connection = transport._LiteralLoopbackHTTPConnection(
            transport.LOOPBACK_HOST, transport.LOOPBACK_PORT, timeout=remaining,
        )
        if path != '/api/generate':
            connection.response_class = _ModelMetadataResponse
        guard = transport._InvocationGuard(connection, getattr(_request_context,"cancel",None), request_deadline)
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
        data = transport._read_provider_body(response, connection, request_deadline, getattr(_request_context,"cancel",None))
        reason = guard.finish()
        if reason is not None:
            raise AIProviderError("REQUEST_CANCELLED" if reason == 'CANCELLED_DURING_RESPONSE' else "REQUEST_TIMEOUT")
        return data
    except AIProviderError:
        raise
    except (TimeoutError, socket.timeout):
        raise AIProviderError("REQUEST_TIMEOUT") from None
    except (OSError, http.client.HTTPException):
        if getattr(_request_context,"cancel",None) is not None and _request_context.cancel.is_set():
            raise AIProviderError('REQUEST_CANCELLED') from None
        if guard is not None and guard.finish() == 'PROVIDER_TIMEOUT':
            raise AIProviderError('REQUEST_TIMEOUT') from None
        raise AIProviderError("OLLAMA_UNAVAILABLE") from None
    except (ValueError, transport._ProviderResponseInvalid):
        if getattr(_request_context,"cancel",None) is not None and _request_context.cancel.is_set():
            raise AIProviderError('REQUEST_CANCELLED') from None
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
            or not valid_model_name(settings.model)
            or type(settings.model_digest) is not str
            or re.fullmatch(r"[a-f0-9]{64}", settings.model_digest) is None
            or type(settings.timeout_seconds) is not int or not 1 <= settings.timeout_seconds <= 1800
            or settings.compute_mode not in ("cpu", "auto")
            or type(settings.max_context) is not int or not 256 <= settings.max_context <= 4096):
        raise AIProviderError("POLICY_REJECTION")
    if deadline is not None and time.monotonic() >= deadline:
        raise AIProviderError("REQUEST_TIMEOUT")
    try:
        posture = qwen_provider_posture(deadline=deadline)
    except (OSError, ValueError):
        raise AIProviderError("POLICY_REJECTION") from None
    # A scan cut short by the caller's deadline is a timeout, not a posture finding.
    if deadline is not None and time.monotonic() >= deadline:
        raise AIProviderError("REQUEST_TIMEOUT")
    if posture["listening"] == "no":
        raise AIProviderError("OLLAMA_UNAVAILABLE")
    if posture["loopback_only"] is not True:
        raise AIProviderError("POLICY_REJECTION")
    remaining = 3 if deadline is None else min(3, deadline - time.monotonic())
    if remaining <= 0:
        raise AIProviderError("REQUEST_TIMEOUT")
    tags = _json(_request("/api/tags", "GET", None, remaining, deadline=deadline))
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
    remaining=3 if deadline is None else min(3,deadline-time.monotonic())
    if remaining<=0:raise AIProviderError('REQUEST_TIMEOUT')
    details=_json(_request('/api/show','POST',json.dumps({'model':settings.model}).encode(),remaining,
                           deadline=deadline))
    # A loopback daemon may proxy cloud models. Never send evidence to those.
    if (type(details) is not dict or details.get('remote_host') or details.get('remote_model')
            or type(details.get('details')) is not dict or details['details'].get('format')!='gguf'
            or type(details.get('capabilities')) is not list or 'completion' not in details['capabilities']):
        raise AIProviderError('MODEL_NOT_LOCAL')
    return {"model": settings.model, "digest": digest, "loopback_only": True}


def model_catalog() -> list[dict]:
    """Read installed artifacts only; full local completion checks run on selection."""
    posture=qwen_provider_posture()
    if posture.get('loopback_only') is not True:raise AIProviderError('POLICY_REJECTION')
    value=_json(_request('/api/tags','GET',None,3))
    if type(value) is not dict or type(value.get('models')) is not list or len(value['models'])>256:
        raise AIProviderError('INVALID_RESPONSE')
    rows=[];seen=set()
    for row in value['models']:
        if type(row) is not dict:raise AIProviderError('INVALID_RESPONSE')
        name=row.get('name');digest=row.get('digest');size=row.get('size');details=row.get('details')
        if (not valid_model_name(name) or type(digest) is not str or re.fullmatch(r'[a-f0-9]{64}',digest) is None
                or type(size) is not int or not 0<size<=2**50 or type(details) is not dict):continue
        if name in seen:raise AIProviderError('INVALID_RESPONSE')
        seen.add(name)
        if row.get('remote_host') or row.get('remote_model') or details.get('format')!='gguf':continue
        rows.append(dict(name=name,digest=digest,size_bytes=size))
    return sorted(rows,key=lambda r:r['name'])


def inventory(settings: AISettings) -> dict[str, object]:
    """Read the fixed local tag list only when AI is enabled; never infer."""
    try:
        if not settings.enabled:
            raise AIProviderError("DISABLED")
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


def _generate(settings: AISettings, prompt: str, *, max_tokens: int = 256, response_format: str = 'text',
              choices: tuple[str, ...] = (), deadline: float | None = None) -> str:
    """One deterministic request after live listener and manifest admission."""
    if type(settings.timeout_seconds) is not int or not 1 <= settings.timeout_seconds <= 1800:
        raise AIProviderError("POLICY_REJECTION")
    if deadline is None:
        deadline = time.monotonic() + settings.timeout_seconds
    if deadline <= time.monotonic():
        raise AIProviderError("REQUEST_TIMEOUT")
    _admitted(settings, deadline)
    if type(prompt) is not str or not 1 <= len(prompt.encode("utf-8")) <= 4096:
        raise AIProviderError("REQUEST_TOO_LARGE")
    if type(max_tokens) is not int or not 1 <= max_tokens <= 256:
        raise AIProviderError("POLICY_REJECTION")
    if response_format not in ('text','defense','intelligence','selection'):
        raise AIProviderError('POLICY_REJECTION')
    if (type(choices) is not tuple or (response_format == 'selection') != bool(choices) or len(choices) > 16
            or any(type(c) is not str or _TOOL_CHOICE.fullmatch(c) is None for c in choices)):
        raise AIProviderError('POLICY_REJECTION')
    payload = {
        "model": settings.model, "prompt": prompt, "stream": False,
        "think": False, "raw": False, "keep_alive": 0,
        # Short background advice runs on CPU, leaving GPU memory available to
        # interactive models and avoiding automatic GPU allocation failures.
        "options": {"temperature": 0, "num_ctx": settings.max_context, "num_batch": 64, "num_gpu": 0 if settings.compute_mode=="cpu" else -1,
                    "num_predict": max_tokens},
    }
    if response_format == 'defense':
        payload['format'] = {'type':'object','additionalProperties':False,
            'properties':{'explanation':{'type':'string','minLength':1,'maxLength':240},
                          'proposal':{'type':'string','enum':['observe','refresh_inventory','scan_files','contain']}},
            'required':['explanation','proposal']}
    if response_format == 'intelligence':
        payload['format'] = {'type':'object','additionalProperties':False,
            'properties':{'explanation':{'type':'string','minLength':1,'maxLength':240},
                          'alternative':{'type':'string','minLength':1,'maxLength':160},
                          'missing':{'type':'string','minLength':1,'maxLength':160},
                          'citations':{'type':'array','minItems':1,'maxItems':4,'items':{'type':'string','enum':['E1','K1','K2','K3']}},
                          'workflow':{'type':'string','enum':['evidence_summary','device_changes','ai_readiness','refresh_inventory','scan_files','contain']}},
            'required':['explanation','alternative','missing','citations','workflow']}
    if response_format == 'selection':
        # Constrained decoding keeps small local models to one closed tool
        # request; the broker still validates every field independently.
        payload['format'] = {'type':'object','additionalProperties':False,
            'properties':{'tool':{'type':'string','enum':list(choices)},
                          'arguments':{'type':'object','additionalProperties':False,'properties':{
                              'window_minutes':{'type':'integer','minimum':1,'maximum':1440},
                              'limit':{'type':'integer','minimum':1,'maximum':8},
                              'report_type':{'type':'string','enum':['security_summary']},
                              'query':{'type':'string','minLength':1,'maxLength':160}}},
                          'reason':{'type':'string','minLength':1,'maxLength':200}},
            'required':['tool','arguments','reason']}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AIProviderError("REQUEST_TIMEOUT")
    data = _request("/api/generate", "POST", body, remaining, deadline=deadline)
    try:
        output, _ = transport._parse_provider_output(data, settings.model)
        summary = transport._plain_summary(output)
        if not summary:
            raise AIProviderError("INVALID_RESPONSE")
        if time.monotonic() >= deadline:
            raise AIProviderError("REQUEST_TIMEOUT")
        return summary
    except (ValueError, transport._ProviderResponseInvalid):
        raise AIProviderError("INVALID_RESPONSE") from None



def generate(settings: AISettings, prompt: str, *, max_tokens: int = 256, response_format: str = 'text',
             priority: str = 'manual', owner=None, choices: tuple[str, ...] = (),
             deadline: float | None = None) -> str:
    """Generate once and retain truthful readiness observations without disk writes."""
    key=(settings.model,settings.model_digest,settings.compute_mode);start=time.monotonic()
    def record(**fields):
        with _observation_lock:
            entry=_observations.setdefault(key,{})
            if fields.get('last_response_at'):
                entry['previous_response_at'] = entry.get('last_response_at')
            entry.update(fields);_observations.move_to_end(key)
            while len(_observations)>16:_observations.popitem(last=False)
    stamp=lambda:datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
    global _active_priority, _active_owner, _manual_waiters
    if priority not in {'manual','background'}:raise AIProviderError('POLICY_REJECTION')
    if deadline is not None and (type(deadline) not in (int, float) or not math.isfinite(deadline)):
        raise AIProviderError('POLICY_REJECTION')
    if deadline is not None and time.monotonic() >= deadline:
        raise AIProviderError('REQUEST_TIMEOUT')
    operator = getattr(_request_context, 'operator', None)
    if operator is not None and owner is None:
        owner = OPERATOR_OWNER
    with _priority_lock:
        wait = priority=='manual' and _active_priority=='background'
        if priority=='background' and _manual_waiters:
            raise AIProviderError('CONCURRENCY_LIMIT_REACHED')
        if wait:
            _manual_waiters+=1
            _active_cancel.set()
    wait_seconds = 5 if deadline is None else min(5, max(0, deadline - time.monotonic()))
    acquired = _generation_lock.acquire(timeout=wait_seconds) if wait else _generation_lock.acquire(blocking=False)
    with _priority_lock:
        if wait:_manual_waiters-=1
        if acquired:
            _active_priority=priority;_active_owner=owner
            _active_cancel.clear()
            # Checked under the same lock cancel_operator() uses, so a cancel
            # between two calls of one operator request cannot be lost.
            if operator is not None and operator.is_set():
                _active_cancel.set()
    if not acquired:
        if deadline is not None and time.monotonic() >= deadline:
            raise AIProviderError('REQUEST_TIMEOUT')
        raise AIProviderError('CONCURRENCY_LIMIT_REACHED')
    _request_context.cancel=_active_cancel
    record(running=True,started_at=stamp(),timeout_seconds=settings.timeout_seconds)
    try:
        if _active_cancel.is_set():
            raise AIProviderError('REQUEST_CANCELLED')
        if deadline is not None and time.monotonic() >= deadline:
            raise AIProviderError('REQUEST_TIMEOUT')
        result=_generate(settings,prompt,max_tokens=max_tokens,response_format=response_format,
                         choices=choices,deadline=deadline)
    except AIProviderError as exc:
        # A competing request must not erase the result of an active invocation.
        if exc.code!='CONCURRENCY_LIMIT_REACHED':
            record(last_attempt_at=stamp(),error_code=exc.code,duration_ms=round((time.monotonic()-start)*1000))
        raise
    finally:
        record(running=False)
        _request_context.cancel=None
        with _priority_lock:
            _active_priority=None;_active_owner=None
        _generation_lock.release()
    record(last_attempt_at=stamp(),last_response_at=stamp(),error_code=None,duration_ms=round((time.monotonic()-start)*1000))
    return result


def loaded_model(settings: AISettings) -> dict:
    """Read bounded runtime allocation after the caller verifies model admission."""
    value=_json(_request('/api/ps','GET',None,3))
    if type(value) is not dict or type(value.get('models')) is not list or len(value['models'])>256:
        raise AIProviderError('INVALID_RESPONSE')
    matches=[row for row in value['models'] if type(row) is dict and row.get('name')==settings.model and row.get('digest')==settings.model_digest]
    if len(matches)>1:raise AIProviderError('INVALID_RESPONSE')
    if not matches:return dict(loaded=False,memory_bytes=None,vram_bytes=None)
    row=matches[0]
    if any(type(row.get(k)) is not int or not 0<=row[k]<=2**50 for k in ('size','size_vram')):
        raise AIProviderError('INVALID_RESPONSE')
    return dict(loaded=True,memory_bytes=row['size'],vram_bytes=row['size_vram'])


def status(settings: AISettings, *, probe: bool = True) -> dict[str, object]:
    """Never report ready from a listener or tag alone."""
    base: dict[str, object] = {"schema": "megalodon-ai-status-v1", "provider": "ollama",
                               "model": settings.model, "state": "disabled",
                               "inference_verified": False, "ollama_available": None,
                               "loopback_only": None, "timeout_seconds": settings.timeout_seconds}
    try:
        base["loopback_only"] = qwen_provider_posture()["loopback_only"]
    except (OSError, ValueError):
        pass
    try:
        if probe:
            challenge = generate(settings, "Reply with exactly READY and nothing else. Do not add punctuation.", max_tokens=32)
            if challenge != "READY":
                reject_response(settings)
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
            "POLICY_REJECTION": "policy_rejection", "MODEL_NOT_LOCAL": "model_not_local", "REQUEST_TIMEOUT": "request_timeout",
            "REQUEST_CANCELLED": "cancelled", "INVALID_RESPONSE": "invalid_response", "CONCURRENCY_LIMIT_REACHED": "model_loading",
            "CONCURRENCY_CONTROL_UNAVAILABLE": "concurrency_unavailable", "PROVIDER_ERROR": "provider_error",
        }.get(exc.code, "invalid_response")
        base["error_code"] = exc.code
        if exc.code == "OLLAMA_UNAVAILABLE":
            base["ollama_available"] = False
        if exc.code in {"MODEL_MISSING", "MODEL_MISMATCH"}:
            base["ollama_available"] = True
    return base
