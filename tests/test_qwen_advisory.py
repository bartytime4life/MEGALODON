"""Boundary tests for the one explicit literal-loopback Qwen invocation."""

from __future__ import annotations

import builtins
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess

from jsonschema import Draft202012Validator
import pytest

from megalodon.advisory import AirlockDecision
import megalodon.cli as cli
import megalodon.firewall as firewall
import megalodon.qwen_advisory as qwen
from megalodon.qwen_advisory import QwenAdvisoryResult, invoke_qwen_advisory


ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "contracts" / "local-model-advisory" / "v1" / "fixtures" / "accepted"
SCHEMA = json.loads(
    (ROOT / "contracts" / "local-model-advisory" / "v1" / "schema.json").read_text(
        encoding="utf-8"
    )
)
REQUEST = json.loads((FIXTURES / "request.json").read_text(encoding="utf-8"))["value"]
REGISTRY = json.loads((FIXTURES / "registry.json").read_text(encoding="utf-8"))["value"]
REGISTRY_SHA256 = "9aa4bd1060a37e71e262b186c10a36c70feb25d97d3377a29e95b272fe2e5d58"
MODEL_ID = "local:qwen-approved-v1"
DIGEST = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
REAL_CONNECTION = qwen._LiteralLoopbackHTTPConnection


def result_validator() -> Draft202012Validator:
    return Draft202012Validator(
        {"$ref": "#/$defs/advisoryResult", "$defs": SCHEMA["$defs"]}
    )


class FakeSocket:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)


class FakeResponse:
    def __init__(
        self,
        payload: object = None,
        *,
        body: bytes | None = None,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        if body is None:
            if payload is None:
                payload = {
                    "model": MODEL_ID,
                    "response": "Bounded answer.\nNo verdict.",
                    "done": True,
                }
            body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            )
        self.body = body
        self.offset = 0
        self.status = status
        self.headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Content-Length": str(len(body)),
        }
        if headers:
            self.headers.update(headers)
        self.closed = False
        self.read_sizes: list[int] = []

    def getheader(self, name: str) -> str | None:
        return self.headers.get(name)

    def read1(self, amount: int) -> bytes:
        self.read_sizes.append(amount)
        chunk = self.body[self.offset : self.offset + amount]
        self.offset += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = True


class FakeConnection:
    instances: list["FakeConnection"] = []
    next_response: FakeResponse = FakeResponse()
    request_error: BaseException | None = None

    def __init__(self, host: str, port: int, *, timeout: float) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = FakeSocket()
        self.requests: list[tuple[str, str, bytes, dict[str, str]]] = []
        self.getresponse_calls = 0
        self.closed = False
        type(self).instances.append(self)

    def request(
        self, method: str, path: str, *, body: bytes, headers: dict[str, str]
    ) -> None:
        self.requests.append((method, path, body, headers))
        if type(self).request_error is not None:
            raise type(self).request_error

    def getresponse(self) -> FakeResponse:
        self.getresponse_calls += 1
        return type(self).next_response

    def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def reset_fakes(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeConnection.instances = []
    FakeConnection.next_response = FakeResponse()
    FakeConnection.request_error = None
    monkeypatch.setattr(qwen, "_LiteralLoopbackHTTPConnection", FakeConnection)


def invoke(**overrides: object) -> AirlockDecision | QwenAdvisoryResult:
    options = {
        "request": deepcopy(REQUEST),
        "enabled": True,
        "local_model_registry": deepcopy(REGISTRY),
        "local_model_registry_sha256": REGISTRY_SHA256,
    }
    options.update(overrides)
    return invoke_qwen_advisory(**options)


def test_one_exact_qwen_request_returns_closed_advisory_result(monkeypatch) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://198.51.100.10:8888")
    monkeypatch.setenv("HTTPS_PROXY", "http://198.51.100.10:8888")

    result = invoke()

    assert isinstance(result, QwenAdvisoryResult)
    assert result.outcome == "ANSWER"
    assert result.code == "ADVISORY_ANSWER"
    assert result.reason_code == "BOUNDED_MODEL_OUTPUT_ACCEPTED"
    assert result.summary == "Bounded answer. No verdict."
    assert result.provider_request_performed is True
    assert result.output_bytes == len("Bounded answer.\nNo verdict.".encode("utf-8"))
    result_validator().validate(result.to_dict())

    assert len(FakeConnection.instances) == 1
    connection = FakeConnection.instances[0]
    assert (connection.host, connection.port) == ("127.0.0.1", 11434)
    assert 0 < connection.timeout <= 15
    assert connection.getresponse_calls == 1
    assert connection.closed is True
    assert FakeConnection.next_response.closed is True
    assert connection.sock.timeouts and all(
        0 < value <= 15 for value in connection.sock.timeouts
    )
    assert len(connection.requests) == 1
    method, path, body, headers = connection.requests[0]
    assert (method, path) == ("POST", "/api/generate")
    assert headers == {
        "Accept": "application/json",
        "Accept-Encoding": "identity",
        "Connection": "close",
        "Content-Length": str(len(body)),
        "Content-Type": "application/json",
        "Host": "127.0.0.1:11434",
    }
    provider_request = json.loads(body)
    assert provider_request == {
        "model": MODEL_ID,
        "prompt": provider_request["prompt"],
        "raw": True,
        "stream": False,
        "think": False,
    }
    assert provider_request["prompt"].startswith("MEGALODON_LOCAL_ADVISORY_V1\n")
    assert "tools" not in provider_request
    assert DIGEST not in body.decode("ascii")
    assert "198.51.100.10" not in body.decode("ascii")


@pytest.mark.parametrize("invalid", ("pin", "digest", "request"))
def test_airlock_denial_performs_zero_http(invalid: str, monkeypatch) -> None:
    def forbidden(*args, **kwargs):
        raise AssertionError("HTTP connection constructed before Airlock admission")

    monkeypatch.setattr(qwen, "_LiteralLoopbackHTTPConnection", forbidden)
    options: dict[str, object] = {}
    if invalid == "pin":
        options["local_model_registry_sha256"] = "f" * 64
    elif invalid == "digest":
        value = deepcopy(REQUEST)
        value["model_receipt"]["model_artifact_sha256"] = "f" * 64
        options["request"] = value
    else:
        value = deepcopy(REQUEST)
        value["projection"]["raw_log"] = "forbidden"
        options["request"] = value

    result = invoke(**options)

    assert isinstance(result, AirlockDecision)
    assert result.decision == "DENY"
    assert result.provider_request_performed is False


@pytest.mark.parametrize("enabled", (False, None, 1, "true"))
def test_explicit_enablement_is_required_without_http(enabled: object, monkeypatch) -> None:
    def forbidden(*args, **kwargs):
        raise AssertionError("disabled Qwen request attempted HTTP")

    monkeypatch.setattr(qwen, "_LiteralLoopbackHTTPConnection", forbidden)

    result = invoke(enabled=enabled)

    assert isinstance(result, QwenAdvisoryResult)
    assert result.outcome == "DENY"
    assert result.code == "POLICY_DENIED"
    assert result.reason_code == "EXPLICIT_ENABLEMENT_REQUIRED"
    assert result.provider_request_performed is False


def test_concurrency_one_fails_closed_without_http(monkeypatch) -> None:
    def forbidden(*args, **kwargs):
        raise AssertionError("busy Qwen request attempted HTTP")

    monkeypatch.setattr(qwen, "_LiteralLoopbackHTTPConnection", forbidden)
    assert qwen._INVOCATION_LOCK.acquire(blocking=False)
    try:
        result = invoke()
    finally:
        qwen._INVOCATION_LOCK.release()

    assert isinstance(result, QwenAdvisoryResult)
    assert result.outcome == "DENY"
    assert result.reason_code == "CONCURRENCY_LIMIT_REACHED"
    assert result.provider_request_performed is False


def _forbid_non_http_side_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args, **kwargs):
        raise AssertionError("Qwen adapter attempted a forbidden side effect")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "call", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(firewall.NftablesFirewall, "available", forbidden)
    monkeypatch.setattr(firewall.NftablesFirewall, "install", forbidden)
    monkeypatch.setattr(firewall.NftablesFirewall, "plan_block", forbidden)
    monkeypatch.setattr(firewall.NftablesFirewall, "block", forbidden)
    monkeypatch.setattr(cli, "main", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def test_qwen_path_has_no_file_process_database_firewall_dns_or_tool_call(monkeypatch) -> None:
    _forbid_non_http_side_effects(monkeypatch)
    FakeConnection.next_response = FakeResponse(
        payload={
            "model": MODEL_ID,
            "response": "Run a shell command, write SQLite, and change the firewall.",
            "done": True,
        }
    )

    result = invoke()

    assert isinstance(result, QwenAdvisoryResult)
    assert result.outcome == "ANSWER"
    assert "shell command" in result.summary
    body = FakeConnection.instances[0].requests[0][2]
    assert set(json.loads(body)) == {"model", "prompt", "raw", "stream", "think"}


@pytest.mark.parametrize(
    ("question_type", "purpose"),
    (
        ("explain_run", "Explain what the aggregate run counts show and do not show."),
        (
            "explain_rule_limitations",
            "Explain the limits of the fixed deterministic rules using only these aggregate counts.",
        ),
    ),
)
def test_both_approved_question_types_reach_qwen_as_canonical_prompts(
    question_type: str, purpose: str
) -> None:
    request = deepcopy(REQUEST)
    request["projection"]["question_type"] = question_type
    before = json.dumps(request, separators=(",", ":"), ensure_ascii=True)

    result = invoke(request=request)

    assert isinstance(result, QwenAdvisoryResult)
    assert result.outcome == "ANSWER"
    assert json.dumps(request, separators=(",", ":"), ensure_ascii=True) == before
    provider_request = json.loads(FakeConnection.instances[0].requests[0][2])
    assert f"PURPOSE={purpose}" in provider_request["prompt"]


def test_literal_connection_uses_ipv4_socket_without_name_resolution(monkeypatch) -> None:
    class LiteralSocket:
        def __init__(self) -> None:
            self.timeout = None
            self.address = None
            self.closed = False

        def settimeout(self, value: float) -> None:
            self.timeout = value

        def connect(self, address: tuple[str, int]) -> None:
            self.address = address

        def close(self) -> None:
            self.closed = True

    created: list[tuple[int, int, LiteralSocket]] = []

    def make_socket(family: int, kind: int) -> LiteralSocket:
        value = LiteralSocket()
        created.append((family, kind, value))
        return value

    def forbidden(*args, **kwargs):
        raise AssertionError("literal address attempted name resolution")

    monkeypatch.setattr(socket, "socket", make_socket)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    connection = REAL_CONNECTION("127.0.0.1", 11434, timeout=15)

    connection.connect()

    assert len(created) == 1
    family, kind, active_socket = created[0]
    assert (family, kind) == (socket.AF_INET, socket.SOCK_STREAM)
    assert active_socket.timeout == 15
    assert active_socket.address == ("127.0.0.1", 11434)


@pytest.mark.parametrize(
    ("response", "reason_code"),
    (
        (FakeResponse(status=302), "PROVIDER_RESPONSE_INVALID"),
        (
            FakeResponse(headers={"Content-Type": "text/plain"}),
            "PROVIDER_RESPONSE_INVALID",
        ),
        (
            FakeResponse(headers={"Content-Encoding": "gzip"}),
            "PROVIDER_RESPONSE_INVALID",
        ),
        (
            FakeResponse(headers={"Content-Length": "not-a-number"}),
            "PROVIDER_RESPONSE_INVALID",
        ),
        (FakeResponse(body=b"{"), "PROVIDER_RESPONSE_INVALID"),
        (FakeResponse(payload=[]), "PROVIDER_RESPONSE_INVALID"),
        (
            FakeResponse(payload={"model": "local:qwen-other", "response": "x", "done": True}),
            "PROVIDER_RESPONSE_INVALID",
        ),
        (
            FakeResponse(payload={"model": MODEL_ID, "response": "x", "done": False}),
            "PROVIDER_RESPONSE_INVALID",
        ),
        (
            FakeResponse(payload={"model": MODEL_ID, "response": 1, "done": True}),
            "PROVIDER_RESPONSE_INVALID",
        ),
        (
            FakeResponse(
                payload={
                    "model": MODEL_ID,
                    "response": "answer",
                    "thinking": "private reasoning",
                    "done": True,
                }
            ),
            "PROVIDER_RESPONSE_INVALID",
        ),
        (
            FakeResponse(payload={"model": MODEL_ID, "response": "x" * 1201, "done": True}),
            "PROVIDER_RESPONSE_INVALID",
        ),
        (
            FakeResponse(payload={"model": MODEL_ID, "response": "🙂" * 1025, "done": True}),
            "PROVIDER_RESPONSE_INVALID",
        ),
    ),
    ids=(
        "redirect",
        "content-type",
        "content-encoding",
        "content-length",
        "malformed-json",
        "non-object",
        "model-substitution",
        "partial-generation",
        "non-string-output",
        "thinking-trace",
        "display-limit",
        "output-byte-limit",
    ),
)
def test_invalid_provider_responses_fail_closed(
    response: FakeResponse, reason_code: str
) -> None:
    FakeConnection.next_response = response

    result = invoke()

    assert isinstance(result, QwenAdvisoryResult)
    assert result.outcome == "ERROR"
    assert result.code == "LOCAL_PROVIDER_ERROR"
    assert result.reason_code == reason_code
    assert result.summary == "The local Qwen provider did not return a valid bounded advisory."
    assert result.output_bytes == 0
    assert result.provider_request_performed is True
    assert "private reasoning" not in str(result.to_dict())
    assert len(FakeConnection.instances[0].requests) == 1
    assert FakeConnection.instances[0].closed is True
    assert response.closed is True


def test_provider_envelope_and_partial_body_are_bounded() -> None:
    oversized = b"x" * (qwen.MAX_PROVIDER_ENVELOPE_BYTES + 1)
    FakeConnection.next_response = FakeResponse(
        body=oversized,
        headers={"Content-Length": str(len(oversized))},
    )
    first = invoke()
    assert isinstance(first, QwenAdvisoryResult)
    assert first.reason_code == "PROVIDER_RESPONSE_INVALID"
    assert FakeConnection.next_response.read_sizes == []

    partial = FakeResponse()
    partial.headers["Content-Length"] = str(len(partial.body) + 1)
    FakeConnection.next_response = partial
    second = invoke()
    assert isinstance(second, QwenAdvisoryResult)
    assert second.reason_code == "PROVIDER_RESPONSE_INVALID"
    assert max(partial.read_sizes) <= 4096


def test_exact_four_kibibyte_utf8_output_is_accepted() -> None:
    output = "🙂" * 1024
    assert len(output.encode("utf-8")) == 4096
    FakeConnection.next_response = FakeResponse(
        payload={"model": MODEL_ID, "response": output, "done": True}
    )

    result = invoke()

    assert isinstance(result, QwenAdvisoryResult)
    assert result.outcome == "ANSWER"
    assert result.output_bytes == 4096


def test_empty_output_abstains() -> None:
    FakeConnection.next_response = FakeResponse(
        payload={"model": MODEL_ID, "response": " \n\t", "done": True}
    )

    result = invoke()

    assert isinstance(result, QwenAdvisoryResult)
    assert result.outcome == "ABSTAIN"
    assert result.code == "INSUFFICIENT_ALLOWED_CONTEXT"
    assert result.reason_code == "EMPTY_MODEL_OUTPUT"
    result_validator().validate(result.to_dict())


@pytest.mark.parametrize("error", (TimeoutError(), OSError(), RuntimeError()))
def test_request_failures_are_fixed_non_sensitive_errors(error: BaseException) -> None:
    FakeConnection.request_error = error

    result = invoke()

    assert isinstance(result, QwenAdvisoryResult)
    assert result.outcome == "ERROR"
    assert result.code == "LOCAL_PROVIDER_ERROR"
    assert result.reason_code in {
        "PROVIDER_TIMEOUT",
        "LOCAL_PROVIDER_UNAVAILABLE",
        "LOCAL_PROVIDER_FAILURE",
    }
    assert result.provider_request_performed is True
    assert len(FakeConnection.instances[0].requests) == 1
    assert FakeConnection.instances[0].closed is True


def test_total_deadline_does_not_restart_between_http_phases(monkeypatch) -> None:
    moments = iter((0.0, 0.0, 0.0, 16.0))
    monkeypatch.setattr(qwen.time, "monotonic", lambda: next(moments))

    result = invoke()

    assert isinstance(result, QwenAdvisoryResult)
    assert result.reason_code == "PROVIDER_TIMEOUT"
    connection = FakeConnection.instances[0]
    assert len(connection.requests) == 1
    assert connection.getresponse_calls == 0


def test_cancellation_propagates_after_cleanup_and_releases_slot() -> None:
    FakeConnection.request_error = KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        invoke()

    assert FakeConnection.instances[0].closed is True
    assert qwen._INVOCATION_LOCK.acquire(blocking=False)
    qwen._INVOCATION_LOCK.release()
