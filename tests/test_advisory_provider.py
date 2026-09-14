"""Adversarial tests for the single literal-loopback advisory provider call."""

from __future__ import annotations

import ast
import builtins
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import threading

import pytest

import megalodon.cli as cli
import megalodon.advisory_provider as provider
import megalodon.firewall as firewall
from megalodon.advisory import AirlockDecision, preflight_advisory
from megalodon.advisory_provider import AdvisoryReceipt, request_advisory


ROOT = Path(__file__).parents[1]
MODULE = ROOT / "megalodon" / "advisory_provider.py"
ACCEPTED = ROOT / "contracts" / "local-model-advisory" / "v1" / "fixtures" / "accepted"
REGISTRY = json.loads((ACCEPTED / "registry.json").read_text(encoding="utf-8"))["value"]
REQUEST = json.loads((ACCEPTED / "request.json").read_text(encoding="utf-8"))["value"]
REGISTRY_SHA256 = "9aa4bd1060a37e71e262b186c10a36c70feb25d97d3377a29e95b272fe2e5d58"


def admitted() -> AirlockDecision:
    decision = preflight_advisory(
        deepcopy(REQUEST),
        local_model_registry=deepcopy(REGISTRY),
        local_model_registry_sha256=REGISTRY_SHA256,
    )
    assert decision.decision == "ADMIT"
    return decision


def response_bytes(
    value: object,
    *,
    status: str = "200 OK",
    extra_headers: tuple[str, ...] = (),
    ensure_ascii: bool = True,
) -> bytes:
    body = json.dumps(
        value, separators=(",", ":"), ensure_ascii=ensure_ascii
    ).encode("utf-8")
    headers = [
        f"HTTP/1.1 {status}",
        "Content-Type: application/json",
        f"Content-Length: {len(body)}",
        *extra_headers,
        "",
        "",
    ]
    return "\r\n".join(headers).encode("ascii") + body


def valid_response(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "model": REQUEST["model_receipt"]["model_id"],
        "response": "The aggregate counts are bounded and do not prove a security verdict.",
        "done": True,
        "done_reason": "stop",
        "eval_count": 12,
    }
    value.update(changes)
    return value


class FakeSocket:
    def __init__(self, response: bytes = b"", *, connect_error: Exception | None = None):
        self._chunks = [response] if response else []
        self.connect_error = connect_error
        self.connected_to: object = None
        self.sent = b""
        self.timeouts: list[float] = []
        self.closed = False

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def connect(self, endpoint: object) -> None:
        self.connected_to = endpoint
        if self.connect_error is not None:
            raise self.connect_error

    def sendall(self, value: bytes) -> None:
        self.sent += value

    def recv(self, size: int) -> bytes:
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        self._chunks.insert(0, chunk[size:]) if len(chunk) > size else None
        return chunk[:size]

    def close(self) -> None:
        self.closed = True


def install_fake(monkeypatch: pytest.MonkeyPatch, fake: FakeSocket) -> list[tuple[int, int]]:
    calls: list[tuple[int, int]] = []

    def factory(family: int, kind: int) -> FakeSocket:
        calls.append((family, kind))
        return fake

    monkeypatch.setattr(provider.socket, "socket", factory)
    return calls


def test_default_disabled_path_performs_no_socket(monkeypatch) -> None:
    monkeypatch.setattr(
        provider.socket,
        "socket",
        lambda *args, **kwargs: pytest.fail("disabled call opened a socket"),
    )

    receipt = request_advisory(admitted())

    assert receipt.outcome == "DENY"
    assert receipt.code == "ADVISORY_DISABLED"
    assert receipt.provider_request_performed is False


@pytest.mark.parametrize("enabled", (None, 0, 1, "yes", [], {}))
def test_enablement_requires_exact_true(monkeypatch, enabled: object) -> None:
    monkeypatch.setattr(
        provider.socket,
        "socket",
        lambda *args, **kwargs: pytest.fail("invalid enablement opened a socket"),
    )

    receipt = request_advisory(admitted(), enabled=enabled)

    assert receipt.code == "ENABLEMENT_INVALID"
    assert receipt.provider_request_performed is False


@pytest.mark.parametrize("value", (None, True, {}, "ADMIT"))
def test_only_an_intact_airlock_admit_can_reach_socket(monkeypatch, value: object) -> None:
    monkeypatch.setattr(
        provider.socket,
        "socket",
        lambda *args, **kwargs: pytest.fail("invalid decision opened a socket"),
    )

    receipt = request_advisory(value, enabled=True)

    assert receipt.code == "ADMIT_REQUIRED"
    assert receipt.provider_request_performed is False


def test_equal_but_forged_airlock_decision_is_denied(monkeypatch) -> None:
    forged = replace(admitted())
    assert forged == admitted()
    monkeypatch.setattr(
        provider.socket,
        "socket",
        lambda *args, **kwargs: pytest.fail("forged decision opened a socket"),
    )

    assert request_advisory(forged, enabled=True).code == "ADMIT_REQUIRED"


def test_tampered_sealed_decision_is_denied(monkeypatch) -> None:
    decision = admitted()
    object.__setattr__(decision, "prompt", "arbitrary prompt")
    monkeypatch.setattr(
        provider.socket,
        "socket",
        lambda *args, **kwargs: pytest.fail("tampered decision opened a socket"),
    )

    assert request_advisory(decision, enabled=True).code == "ADMIT_REQUIRED"


def test_malformed_tampered_decision_fails_closed_without_socket(monkeypatch) -> None:
    decision = admitted()
    object.__setattr__(decision, "prompt", object())
    monkeypatch.setattr(
        provider.socket,
        "socket",
        lambda *args, **kwargs: pytest.fail("malformed decision opened a socket"),
    )

    receipt = request_advisory(decision, enabled=True)

    assert receipt.code == "ADMIT_REQUIRED"
    assert receipt.provider_request_performed is False


def test_invalid_and_pre_cancelled_controls_perform_no_socket(monkeypatch) -> None:
    monkeypatch.setattr(
        provider.socket,
        "socket",
        lambda *args, **kwargs: pytest.fail("cancelled call opened a socket"),
    )
    invalid = request_advisory(admitted(), enabled=True, cancel_event=object())
    cancelled_event = threading.Event()
    cancelled_event.set()
    cancelled = request_advisory(
        admitted(), enabled=True, cancel_event=cancelled_event
    )

    assert invalid.code == "CANCELLATION_INVALID"
    assert cancelled.code == "CANCELLED"
    assert invalid.provider_request_performed is cancelled.provider_request_performed is False


def test_request_uses_only_the_literal_endpoint_path_and_closed_json(monkeypatch) -> None:
    fake = FakeSocket(response_bytes(valid_response()))
    calls = install_fake(monkeypatch, fake)

    receipt = request_advisory(admitted(), enabled=True)

    assert receipt.outcome == "ANSWER"
    assert receipt.code == "ANSWER_ACCEPTED"
    assert receipt.provider_request_performed is True
    assert calls == [(socket.AF_INET, socket.SOCK_STREAM)]
    assert fake.connected_to == ("127.0.0.1", 11434)
    head, body = fake.sent.split(b"\r\n\r\n", 1)
    assert head.startswith(b"POST /api/generate HTTP/1.1\r\n")
    assert b"Host: 127.0.0.1:11434\r\n" in head
    assert json.loads(body) == {
        "keep_alive": 0,
        "model": REQUEST["model_receipt"]["model_id"],
        "options": {"num_predict": 1024, "seed": 0, "temperature": 0},
        "prompt": admitted().prompt,
        "stream": False,
    }
    assert fake.closed is True


def test_endpoint_and_path_are_not_function_arguments_or_configuration() -> None:
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    request_function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "request_advisory"
    )
    arguments = {
        argument.arg
        for argument in (*request_function.args.args, *request_function.args.kwonlyargs)
    }
    assert arguments == {"decision", "enabled", "cancel_event"}
    source = MODULE.read_text(encoding="utf-8")
    assert 'sock.connect(("127.0.0.1", 11434))' in source
    assert '"POST /api/generate HTTP/1.1\\r\\n"' in source


def test_proxy_environment_and_dns_are_not_read_or_used(monkeypatch) -> None:
    fake = FakeSocket(response_bytes(valid_response()))
    install_fake(monkeypatch, fake)
    monkeypatch.setenv("HTTP_PROXY", "http://198.51.100.9:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://203.0.113.8:8080")
    monkeypatch.setattr(
        provider.socket,
        "getaddrinfo",
        lambda *args, **kwargs: pytest.fail("provider attempted DNS"),
    )

    assert request_advisory(admitted(), enabled=True).outcome == "ANSWER"


def test_success_path_has_no_process_file_database_firewall_or_command_call(monkeypatch) -> None:
    decision = admitted()
    fake = FakeSocket(response_bytes(valid_response()))
    install_fake(monkeypatch, fake)

    def denied(*args, **kwargs):
        raise AssertionError("provider attempted a forbidden host or tool operation")

    monkeypatch.setattr(builtins, "open", denied)
    monkeypatch.setattr(os, "open", denied)
    monkeypatch.setattr(Path, "open", denied)
    monkeypatch.setattr(Path, "write_text", denied)
    monkeypatch.setattr(Path, "write_bytes", denied)
    monkeypatch.setattr(sqlite3, "connect", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(subprocess, "run", denied)
    monkeypatch.setattr(firewall.NftablesFirewall, "available", denied)
    monkeypatch.setattr(firewall.NftablesFirewall, "plan_block", denied)
    monkeypatch.setattr(firewall.NftablesFirewall, "block", denied)
    monkeypatch.setattr(cli, "main", denied)

    receipt = request_advisory(decision, enabled=True)

    assert receipt.outcome == "ANSWER"
    assert receipt.provider_request_performed is True


def test_redirect_is_not_followed(monkeypatch) -> None:
    fake = FakeSocket(
        response_bytes(
            {}, status="302 Found", extra_headers=("Location: https://example.com",)
        )
    )
    calls = install_fake(monkeypatch, fake)

    receipt = request_advisory(admitted(), enabled=True)

    assert receipt.code == "HTTP_STATUS_INVALID"
    assert receipt.provider_request_performed is True
    assert calls == [(socket.AF_INET, socket.SOCK_STREAM)]


def test_connection_error_is_fixed_and_non_echoing(monkeypatch) -> None:
    fake = FakeSocket(connect_error=OSError("credential=secret-provider-detail"))
    install_fake(monkeypatch, fake)

    receipt = request_advisory(admitted(), enabled=True)

    assert receipt.code == "CONNECT_FAILED"
    assert receipt.provider_request_performed is False
    assert "secret" not in str(receipt.to_dict())


def test_raw_response_limit_is_enforced_before_body_read(monkeypatch) -> None:
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {provider.MAX_RESPONSE_BODY_BYTES + 1}\r\n\r\n".encode("ascii")
    )
    fake = FakeSocket(response)
    install_fake(monkeypatch, fake)

    receipt = request_advisory(admitted(), enabled=True)

    assert receipt.code == "RESPONSE_LIMIT_EXCEEDED"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({"model": REQUEST["model_receipt"]["model_id"], "response": "x"}, "RESPONSE_INVALID"),
        (valid_response(done=False), "RESPONSE_INVALID"),
        (valid_response(model="local:qwen-substituted-v1"), "MODEL_MISMATCH"),
        (valid_response(tool_calls=[]), "RESPONSE_INVALID"),
        (valid_response(action="block"), "RESPONSE_INVALID"),
        (valid_response(response="text\x1b[31m"), "RESPONSE_INVALID"),
        (valid_response(eval_count=True), "RESPONSE_INVALID"),
    ],
)
def test_closed_response_validation(monkeypatch, value: object, expected: str) -> None:
    fake = FakeSocket(response_bytes(value))
    install_fake(monkeypatch, fake)

    receipt = request_advisory(admitted(), enabled=True)

    assert receipt.outcome == "ERROR"
    assert receipt.code == expected
    assert receipt.provider_request_performed is True


def test_output_utf8_byte_limit_is_independent_of_character_count(monkeypatch) -> None:
    text = "é" * 2049
    fake = FakeSocket(
        response_bytes(valid_response(response=text), ensure_ascii=False)
    )
    install_fake(monkeypatch, fake)

    assert request_advisory(admitted(), enabled=True).code == "OUTPUT_LIMIT_EXCEEDED"


def test_malformed_body_does_not_echo_provider_content(monkeypatch) -> None:
    body = b'{"credential":"secret-provider-detail"'
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        + body
    )
    fake = FakeSocket(response)
    install_fake(monkeypatch, fake)

    receipt = request_advisory(admitted(), enabled=True)

    assert receipt.code == "RESPONSE_INVALID"
    assert "secret" not in str(receipt.to_dict())


def test_cancellation_is_checked_during_bounded_read(monkeypatch) -> None:
    cancel_event = threading.Event()

    class CancellingSocket(FakeSocket):
        def recv(self, size: int) -> bytes:
            cancel_event.set()
            raise socket.timeout()

    fake = CancellingSocket()
    install_fake(monkeypatch, fake)

    receipt = request_advisory(
        admitted(), enabled=True, cancel_event=cancel_event
    )

    assert receipt.outcome == "DENY"
    assert receipt.code == "CANCELLED"
    assert receipt.provider_request_performed is True


def test_read_timeout_uses_the_fixed_total_budget(monkeypatch) -> None:
    class TimingOutSocket(FakeSocket):
        def recv(self, size: int) -> bytes:
            raise socket.timeout()

    fake = TimingOutSocket()
    install_fake(monkeypatch, fake)
    monkeypatch.setattr(provider, "TIMEOUT_SECONDS", 0.001)

    receipt = request_advisory(admitted(), enabled=True)

    assert receipt.code == "TIMEOUT"
    assert receipt.provider_request_performed is True


def test_concurrency_one_returns_busy_without_a_second_socket(monkeypatch) -> None:
    sent = threading.Event()
    release = threading.Event()

    class BlockingSocket(FakeSocket):
        delivered = False

        def sendall(self, value: bytes) -> None:
            super().sendall(value)
            sent.set()

        def recv(self, size: int) -> bytes:
            release.wait(timeout=2)
            if self.delivered:
                return b""
            self.delivered = True
            return response_bytes(valid_response())

    fake = BlockingSocket()
    calls = install_fake(monkeypatch, fake)
    first_result: list[AdvisoryReceipt] = []
    worker = threading.Thread(
        target=lambda: first_result.append(request_advisory(admitted(), enabled=True))
    )
    worker.start()
    assert sent.wait(timeout=2)

    second = request_advisory(admitted(), enabled=True)
    release.set()
    worker.join(timeout=2)

    assert second.code == "BUSY"
    assert second.provider_request_performed is False
    assert [item.outcome for item in first_result] == ["ANSWER"]
    assert len(calls) == 1


def test_literal_loopback_protocol_round_trip_uses_no_dns_or_proxy(monkeypatch) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 11434))
    server.listen(1)
    server.settimeout(3)
    captured: list[bytes] = []
    failure: list[BaseException] = []

    def serve() -> None:
        try:
            connection, address = server.accept()
            assert address[0] == "127.0.0.1"
            with connection:
                data = bytearray()
                while b"\r\n\r\n" not in data:
                    data.extend(connection.recv(2048))
                head, start = bytes(data).split(b"\r\n\r\n", 1)
                length = int(
                    next(
                        line.split(b":", 1)[1]
                        for line in head.split(b"\r\n")
                        if line.lower().startswith(b"content-length:")
                    )
                )
                body = bytearray(start)
                while len(body) < length:
                    body.extend(connection.recv(length - len(body)))
                captured.append(head + b"\r\n\r\n" + bytes(body))
                connection.sendall(response_bytes(valid_response()))
        except BaseException as exc:
            failure.append(exc)

    worker = threading.Thread(target=serve)
    worker.start()
    monkeypatch.setenv("HTTP_PROXY", "http://198.51.100.2:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://203.0.113.3:3128")
    monkeypatch.setattr(
        provider.socket,
        "getaddrinfo",
        lambda *args, **kwargs: pytest.fail("literal-loopback call attempted DNS"),
    )
    try:
        receipt = request_advisory(admitted(), enabled=True)
    finally:
        worker.join(timeout=3)
        server.close()

    assert not failure
    assert receipt.outcome == "ANSWER"
    assert len(captured) == 1
    assert captured[0].startswith(b"POST /api/generate HTTP/1.1\r\n")


def test_receipt_is_immutable_fresh_and_display_only(monkeypatch) -> None:
    fake = FakeSocket(response_bytes(valid_response()))
    install_fake(monkeypatch, fake)

    receipt = request_advisory(admitted(), enabled=True)

    with pytest.raises(FrozenInstanceError):
        receipt.code = "changed"  # type: ignore[misc]
    projection = receipt.to_dict()
    projection["code"] = "changed"
    projection["limitations"].append("changed")
    assert receipt.code == "ANSWER_ACCEPTED"
    assert "changed" not in receipt.limitations
    assert set(projection) == {
        "outcome",
        "code",
        "summary",
        "limitations",
        "model_receipt",
        "provider_request_performed",
    }
    assert not ({"tool", "command", "target", "query", "path", "action"} & set(projection))


def test_provider_module_has_a_closed_runtime_import_surface() -> None:
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert imported_roots == {
        "__future__",
        "advisory",
        "dataclasses",
        "json",
        "re",
        "socket",
        "threading",
        "time",
        "typing",
    }
    source = MODULE.read_text(encoding="utf-8")
    for forbidden in (
        "subprocess",
        "sqlite3",
        "urllib",
        "http.client",
        "pathlib",
        "os.environ",
        "getaddrinfo(",
    ):
        assert forbidden not in source
