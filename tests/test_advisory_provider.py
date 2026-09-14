"""Adversarial tests for the single literal-loopback advisory request."""

from __future__ import annotations

import ast
import builtins
from copy import deepcopy
from dataclasses import FrozenInstanceError
import inspect
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import threading
import urllib.request

import pytest

import megalodon.advisory_provider as provider
import megalodon.cli as cli
import megalodon.firewall as firewall
from megalodon.advisory_provider import invoke_local_advisory


ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "contracts" / "local-model-advisory" / "v1" / "fixtures"
REGISTRY = json.loads((FIXTURES / "accepted" / "registry.json").read_text(encoding="utf-8"))["value"]
REQUEST = json.loads((FIXTURES / "accepted" / "request.json").read_text(encoding="utf-8"))["value"]
REGISTRY_SHA256 = "9aa4bd1060a37e71e262b186c10a36c70feb25d97d3377a29e95b272fe2e5d58"
MODEL_ID = "local:qwen-approved-v1"
MODULE = ROOT / "megalodon" / "advisory_provider.py"


class FakeResponse:
    def __init__(
        self,
        value: object = None,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
        raw: bytes | None = None,
        cancel_after_first_read: threading.Event | None = None,
    ) -> None:
        if value is None:
            value = {
                "model": MODEL_ID,
                "response": "The fixed counts are descriptive only.\nNo infection verdict follows.",
                "done": True,
                "done_reason": "stop",
                "eval_count": 17,
            }
        self.body = raw if raw is not None else json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.status = status
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.offset = 0
        self.read_sizes: list[int] = []
        self.cancel_after_first_read = cancel_after_first_read

    def getheader(self, name: str) -> str | None:
        return self.headers.get(name)

    def read(self, size: int) -> bytes:
        self.read_sizes.append(size)
        chunk = self.body[self.offset : self.offset + size]
        self.offset += len(chunk)
        if self.cancel_after_first_read is not None and len(self.read_sizes) == 1:
            self.cancel_after_first_read.set()
        return chunk


class FakeConnection:
    response = FakeResponse()
    request_error: BaseException | None = None
    response_error: BaseException | None = None
    close_error: BaseException | None = None
    instances: list["FakeConnection"] = []

    def __init__(self, host: str, port: int, *, timeout: int) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.requests: list[tuple[str, str, bytes, dict[str, str]]] = []
        self.closed = False
        type(self).instances.append(self)

    def request(self, method: str, path: str, *, body: bytes, headers: dict[str, str]) -> None:
        self.requests.append((method, path, body, headers))
        if type(self).request_error is not None:
            raise type(self).request_error

    def getresponse(self) -> FakeResponse:
        if type(self).response_error is not None:
            raise type(self).response_error
        return type(self).response

    def close(self) -> None:
        self.closed = True
        if type(self).close_error is not None:
            raise type(self).close_error


@pytest.fixture(autouse=True)
def reset_fake_connection(monkeypatch: pytest.MonkeyPatch):
    FakeConnection.response = FakeResponse()
    FakeConnection.request_error = None
    FakeConnection.response_error = None
    FakeConnection.close_error = None
    FakeConnection.instances = []
    monkeypatch.setattr(provider, "_LiteralLoopbackConnection", FakeConnection)


def invoke(**changes: object):
    options: dict[str, object] = {
        "local_model_registry": deepcopy(REGISTRY),
        "local_model_registry_sha256": REGISTRY_SHA256,
        "enabled": True,
    }
    options.update(changes)
    return invoke_local_advisory(deepcopy(REQUEST), **options)


def test_success_uses_only_the_fixed_loopback_request_and_returns_bounded_receipt() -> None:
    receipt = invoke()

    assert receipt.outcome == "ANSWER"
    assert receipt.code == "ADVISORY_ANSWER"
    assert receipt.reason_code == "REQUEST_COMPLETED"
    assert receipt.summary == "The fixed counts are descriptive only. No infection verdict follows."
    assert receipt.provider_request_performed is True
    assert receipt.model_id == MODEL_ID
    assert receipt.registry_sha256 == REGISTRY_SHA256
    assert len(FakeConnection.instances) == 1
    connection = FakeConnection.instances[0]
    assert (connection.host, connection.port, connection.timeout) == (
        "127.0.0.1",
        11434,
        15,
    )
    assert connection.closed is True
    assert len(connection.requests) == 1
    method, path, body, headers = connection.requests[0]
    assert method == "POST"
    assert path == "/api/generate"
    assert headers == {
        "Accept": "application/json",
        "Connection": "close",
        "Content-Type": "application/json",
    }
    payload = json.loads(body)
    assert set(payload) == {"keep_alive", "model", "options", "prompt", "stream", "think"}
    assert payload["model"] == MODEL_ID
    assert payload["stream"] is False
    assert payload["think"] is False
    assert payload["keep_alive"] == 0
    assert payload["options"] == {"num_predict": 512, "temperature": 0}
    assert payload["prompt"].startswith("MEGALODON_LOCAL_ADVISORY_V1\n")
    assert not set(payload) & {"endpoint", "url", "headers", "credential", "tools", "tool_calls", "action"}
    assert body == json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    assert len(body) <= provider.MAX_PROVIDER_REQUEST_BYTES


def test_receipt_is_immutable_and_serialization_is_fresh() -> None:
    receipt = invoke()
    with pytest.raises(FrozenInstanceError):
        receipt.code = "changed"  # type: ignore[misc]
    value = receipt.to_dict()
    value["limitations"].append("changed")
    value["model_receipt"]["model_id"] = "changed"
    assert receipt.limitations == provider._LIMITATIONS
    assert receipt.model_id == MODEL_ID


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"enabled": False}, "PROVIDER_DISABLED"),
        ({"enabled": 1}, "INVOCATION_CONTROL_INVALID"),
        ({"cancel_event": object()}, "INVOCATION_CONTROL_INVALID"),
        ({"local_model_registry_sha256": "0" * 64}, "REGISTRY_FINGERPRINT_MISMATCH"),
    ],
)
def test_pre_request_denials_never_construct_a_provider_connection(changes: dict[str, object], reason: str) -> None:
    receipt = invoke(**changes)
    assert receipt.outcome == "DENY"
    assert receipt.code == "POLICY_DENIED"
    assert receipt.reason_code == reason
    assert receipt.provider_request_performed is False
    assert FakeConnection.instances == []


def test_pre_request_cancellation_is_deterministic_and_performs_no_request() -> None:
    cancellation = threading.Event()
    cancellation.set()
    receipt = invoke(cancel_event=cancellation)
    assert receipt.reason_code == "CANCELLED_BEFORE_REQUEST"
    assert receipt.provider_request_performed is False
    assert FakeConnection.instances == []


def test_concurrency_one_fails_closed_before_connection() -> None:
    assert provider._INVOCATION_LOCK.acquire(blocking=False)
    try:
        receipt = invoke()
    finally:
        provider._INVOCATION_LOCK.release()
    assert receipt.outcome == "ERROR"
    assert receipt.reason_code == "PROVIDER_BUSY"
    assert receipt.provider_request_performed is False
    assert FakeConnection.instances == []


@pytest.mark.parametrize(
    ("status", "reason"),
    [(301, "PROVIDER_REDIRECT_DENIED"), (302, "PROVIDER_REDIRECT_DENIED"), (400, "PROVIDER_HTTP_ERROR"), (500, "PROVIDER_HTTP_ERROR")],
)
def test_redirects_and_non_success_statuses_are_never_followed(status: int, reason: str) -> None:
    FakeConnection.response = FakeResponse(status=status, headers={"Location": "https://forbidden.invalid/"})
    receipt = invoke()
    assert receipt.reason_code == reason
    assert receipt.provider_request_performed is True
    assert len(FakeConnection.instances) == 1
    assert len(FakeConnection.instances[0].requests) == 1
    assert FakeConnection.response.read_sizes == []


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (socket.timeout("private timeout detail"), "PROVIDER_TIMEOUT"),
        (TimeoutError("private timeout detail"), "PROVIDER_TIMEOUT"),
        (OSError("private socket detail"), "PROVIDER_UNAVAILABLE"),
        (RuntimeError("private unexpected detail"), "PROVIDER_PROTOCOL_ERROR"),
    ],
)
def test_transport_failures_return_fixed_non_echoing_errors(error: BaseException, reason: str) -> None:
    FakeConnection.request_error = error
    receipt = invoke()
    assert receipt.outcome == "ERROR"
    assert receipt.reason_code == reason
    assert receipt.provider_request_performed is True
    assert str(error) not in str(receipt.to_dict())


def test_close_failure_overrides_an_apparent_answer() -> None:
    FakeConnection.close_error = OSError("sensitive close detail")
    receipt = invoke()
    assert receipt.reason_code == "PROVIDER_CLOSE_FAILED"
    assert "sensitive" not in str(receipt.to_dict())


@pytest.mark.parametrize(
    "headers",
    [
        {"Content-Type": "text/plain"},
        {"Content-Type": "application/json", "Content-Encoding": "gzip"},
        {"Content-Type": "application/json", "Content-Length": "not-a-count"},
    ],
)
def test_unexpected_response_headers_fail_closed(headers: dict[str, str]) -> None:
    FakeConnection.response = FakeResponse(headers=headers)
    assert invoke().reason_code in {"PROVIDER_PROTOCOL_ERROR", "PROVIDER_RESPONSE_INVALID"}


def test_declared_and_streamed_response_size_limits_are_discriminating() -> None:
    FakeConnection.response = FakeResponse(headers={"Content-Length": str(provider.MAX_PROVIDER_BODY_BYTES + 1)})
    assert invoke().reason_code == "PROVIDER_RESPONSE_TOO_LARGE"
    assert FakeConnection.response.read_sizes == []

    FakeConnection.response = FakeResponse(raw=b"x" * (provider.MAX_PROVIDER_BODY_BYTES + 1))
    receipt = invoke()
    assert receipt.reason_code == "PROVIDER_RESPONSE_TOO_LARGE"
    assert all(size <= 1024 for size in FakeConnection.response.read_sizes)


def test_cancellation_during_bounded_read_closes_the_connection() -> None:
    cancellation = threading.Event()
    FakeConnection.response = FakeResponse(
        raw=b"x" * 2048,
        cancel_after_first_read=cancellation,
    )
    receipt = invoke(cancel_event=cancellation)
    assert receipt.reason_code == "CANCELLED_DURING_RESPONSE"
    assert receipt.provider_request_performed is True
    assert FakeConnection.instances[0].closed is True
    assert FakeConnection.response.read_sizes == [1024]


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"not json", "PROVIDER_RESPONSE_INVALID"),
        (b'{"model":"local:qwen-approved-v1","response":"one","response":"two","done":true}', "PROVIDER_RESPONSE_INVALID"),
        (b'{"model":"local:qwen-approved-v1","response":"ok","done":true,"tool_calls":[]}', "PROVIDER_RESPONSE_INVALID"),
        (b'{"model":"local:qwen-approved-v1","response":"ok","thinking":"hidden chain","done":true}', "PROVIDER_RESPONSE_INVALID"),
        (b'{"model":"local:qwen-approved-v1","response":"ok","done":false}', "PROVIDER_RESPONSE_INVALID"),
        (b'{"model":"local:qwen-approved-v1","response":"ok","done":true,"eval_count":true}', "PROVIDER_RESPONSE_INVALID"),
        (b'{"model":"local:qwen-approved-v1","response":"ok","done":true,"context":[1,-1]}', "PROVIDER_RESPONSE_INVALID"),
        (b'{"model":"local:qwen-approved-v1","response":NaN,"done":true}', "PROVIDER_RESPONSE_INVALID"),
        (b'{"model":"local:qwen-approved-v1","response":"\\ud800","done":true}', "PROVIDER_RESPONSE_INVALID"),
        (b'{"model":"local:qwen-other","response":"ok","done":true}', "PROVIDER_MODEL_MISMATCH"),
    ],
)
def test_malformed_or_authority_bearing_provider_responses_are_rejected(raw: bytes, reason: str) -> None:
    FakeConnection.response = FakeResponse(raw=raw)
    receipt = invoke()
    assert receipt.reason_code == reason
    assert raw.decode("utf-8", errors="ignore") not in str(receipt.to_dict())


def test_current_benign_ollama_metadata_is_accepted_without_exposing_it() -> None:
    FakeConnection.response = FakeResponse(
        value={
            "model": MODEL_ID,
            "response": "Bounded explanation.",
            "thinking": "",
            "done": True,
            "done_reason": "stop",
            "prompt_eval_cached_count": 4,
        }
    )
    receipt = invoke()
    assert receipt.outcome == "ANSWER"
    assert receipt.summary == "Bounded explanation."
    assert "thinking" not in receipt.to_dict()
    assert "prompt_eval_cached_count" not in receipt.to_dict()


@pytest.mark.parametrize(
    "text",
    [
        "",
        " ",
        "x" * (provider.MAX_SUMMARY_CHARACTERS + 1),
        "é" * (provider.FIXED_LIMITS["max_output_bytes"] // 2 + 1),
        "hidden\x00control",
        "bidirectional\u202ereversal",
    ],
)
def test_model_text_must_fit_plain_text_and_contract_bounds(text: str) -> None:
    FakeConnection.response = FakeResponse(value={"model": MODEL_ID, "response": text, "done": True})
    assert invoke().reason_code == "PROVIDER_RESPONSE_INVALID"


def test_literal_connection_uses_af_inet_numeric_loopback_without_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, ...]] = []

    class Socket:
        def settimeout(self, timeout: object) -> None:
            calls.append(("timeout", timeout))

        def connect(self, address: object) -> None:
            calls.append(("connect", address))

        def close(self) -> None:
            calls.append(("close",))

    def make_socket(family: object, kind: object) -> Socket:
        calls.append(("socket", family, kind))
        return Socket()

    def no_dns(*args: object, **kwargs: object):
        raise AssertionError("literal-loopback connection attempted DNS")

    monkeypatch.setattr(socket, "socket", make_socket)
    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    connection = PRODUCTION_CONNECTION(
        provider.LOOPBACK_HOST,
        provider.LOOPBACK_PORT,
        timeout=15,
    )
    connection.connect()
    assert calls == [
        ("socket", socket.AF_INET, socket.SOCK_STREAM),
        ("timeout", 15),
        ("connect", ("127.0.0.1", 11434)),
    ]
    connection.close()
    assert calls[-1] == ("close",)


PRODUCTION_CONNECTION = provider._LiteralLoopbackConnection


def test_wrong_literal_connection_target_fails_before_socket_creation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(provider, "_LiteralLoopbackConnection", PRODUCTION_CONNECTION)

    def forbidden(*args: object, **kwargs: object):
        raise AssertionError("wrong target reached socket construction")

    monkeypatch.setattr(socket, "socket", forbidden)
    with pytest.raises(OSError, match="literal loopback invariant"):
        PRODUCTION_CONNECTION("127.0.0.2", 11434, timeout=15).connect()
    with pytest.raises(OSError, match="literal loopback invariant"):
        PRODUCTION_CONNECTION("127.0.0.1", 11435, timeout=15).connect()


def test_provider_surface_has_no_endpoint_model_prompt_header_or_transport_argument() -> None:
    parameters = set(inspect.signature(invoke_local_advisory).parameters)
    assert parameters == {
        "request",
        "local_model_registry",
        "local_model_registry_sha256",
        "enabled",
        "cancel_event",
    }
    source = MODULE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert not imports & {"asyncio", "os", "pathlib", "sqlite3", "subprocess", "urllib"}
    assert "getaddrinfo" not in source
    assert "getproxies" not in source
    assert "set_tunnel" not in source


def test_success_path_has_no_process_file_database_firewall_or_command_side_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def denied(*args: object, **kwargs: object):
        raise AssertionError("provider adapter attempted a forbidden side effect")

    monkeypatch.setattr(builtins, "open", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(subprocess, "run", denied)
    monkeypatch.setattr(subprocess, "call", denied)
    monkeypatch.setattr(subprocess, "check_call", denied)
    monkeypatch.setattr(subprocess, "check_output", denied)
    monkeypatch.setattr(sqlite3, "connect", denied)
    monkeypatch.setattr(urllib.request, "urlopen", denied)
    monkeypatch.setattr(Path, "write_text", denied)
    monkeypatch.setattr(Path, "write_bytes", denied)
    monkeypatch.setattr(Path, "touch", denied)
    monkeypatch.setattr(Path, "mkdir", denied)
    monkeypatch.setattr(Path, "unlink", denied)
    monkeypatch.setattr(Path, "rename", denied)
    monkeypatch.setattr(Path, "replace", denied)
    monkeypatch.setattr(firewall.NftablesFirewall, "install", denied)
    monkeypatch.setattr(firewall.NftablesFirewall, "block", denied)
    monkeypatch.setattr(cli, "main", denied)

    assert invoke().outcome == "ANSWER"
