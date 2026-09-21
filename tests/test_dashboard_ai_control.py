"""Explicit HUD AI routes never open command or firewall authority."""

from __future__ import annotations

from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from threading import Thread

from megalodon.ai_broker import ReceiptStore
from megalodon.config import AISettings
from megalodon.dashboard import DashboardHandler


def _get(server, path, headers=None, method="GET", body=None):
    client = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    try:
        client.request(method, path, body=body, headers=headers or {})
        response = client.getresponse()
        return response.status, json.loads(response.read())
    finally:
        client.close()


def test_ai_status_requires_explicit_check_and_never_claims_tcp_ready(monkeypatch):
    monkeypatch.setattr("megalodon.ai_provider.status", lambda *_args, **_kwargs: {
        "schema": "megalodon-ai-status-v1", "state": "model_missing", "inference_verified": False})
    handler = type("AIStatusHandler", (DashboardHandler,), {"store": object(),
                                                            "ai_settings": AISettings(enabled=True),
                                                            "ai_operator_token": "exact-test-token"})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert _get(server, "/api/ai/status")[0] == 403
        authorized = {"X-Megalodon-AI-Check": "1", "X-Megalodon-AI-Token": "exact-test-token"}
        code, value = _get(server, "/api/ai/status", authorized)
        assert code == 200 and value["state"] == "model_missing"
        assert value["inference_verified"] is False
        assert _get(server, "/api/ai/status?extra=1", authorized)[0] == 403
        assert _get(server, "/api/ai/status", method="POST")[0] == 405
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_ai_ask_disabled_has_no_model_or_audit_path(monkeypatch):
    monkeypatch.setattr("megalodon.ai_interface.ask", lambda *_: (_ for _ in ()).throw(AssertionError("model called")))
    handler = type("AIDisabledHandler", (DashboardHandler,), {"store": object(), "ai_settings": AISettings()})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert _get(server, "/api/ai/ask", method="POST")[0] == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_enabled_ai_ask_uses_fixed_question_and_audit_path(monkeypatch, tmp_path):
    seen = []

    def fake_ask(question, broker):
        seen.append((question, broker.ai.model))
        return {"schema": "megalodon-ai-answer-v1", "question_id": question,
                "execution_state": "observed", "observed": {"events": 0},
                "inferred": "No stored events in this bounded view.", "receipt_id": "synthetic"}

    monkeypatch.setattr("megalodon.ai_interface.ask", fake_ask)
    handler = type("AIEnabledHandler", (DashboardHandler,), {
        "store": object(), "ai_settings": AISettings(enabled=True),
        "ai_receipt_path": tmp_path / "ai.db",
        "ai_operator_token": "exact-test-token",
    })
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f"http://127.0.0.1:{server.server_port}"
        body = json.dumps({"question": "seeing"})
        headers = {"X-Megalodon-AI-Token": "exact-test-token", "Origin": origin,
                   "Content-Type": "application/json"}
        assert _get(server, "/api/ai/ask", method="POST", body=body)[0] == 403
        assert _get(server, "/api/ai/ask", {**headers, "Origin": "https://evil.invalid"},
                    method="POST", body=body)[0] == 403
        code, value = _get(server, "/api/ai/ask", headers, method="POST", body=body)
        assert code == 200 and value["question_id"] == "seeing"
        assert seen == [("seeing", AISettings.model)]
        assert _get(server, "/api/ai/ask", headers, method="POST",
                    body=json.dumps({"question": "seeing", "path": "../../etc/shadow"}))[0] == 503
        assert len(seen) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_malformed_model_tool_returns_audited_failure_over_http(monkeypatch, tmp_path):
    selections = []

    def fake_generate(*_args, **_kwargs):
        selections.append("selection")
        return json.dumps({"tool": [], "arguments": {}, "reason": "synthetic malformed selection"})

    monkeypatch.setattr("megalodon.ai_interface.generate", fake_generate)
    ledger = tmp_path / "ai.db"
    handler = type("AIMalformedSelectionHandler", (DashboardHandler,), {
        # Any attempt to read evidence would fail: no reader methods exist.
        "store": object(), "ai_settings": AISettings(enabled=True),
        "ai_receipt_path": ledger, "ai_operator_token": "exact-test-token",
    })
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        headers = {"X-Megalodon-AI-Token": "exact-test-token",
                   "Origin": f"http://127.0.0.1:{server.server_port}",
                   "Content-Type": "application/json"}
        code, value = _get(server, "/api/ai/ask", headers, method="POST",
                           body=json.dumps({"question": "seeing"}))
        assert code == 200
        assert value["execution_state"] == "failed" and value["error_code"] == "UNKNOWN_TOOL"
        assert value["observed"] is None and value["inferred"] is None
        assert selections == ["selection"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    with ReceiptStore(ledger) as receipts:
        assert receipts.latest(value["receipt_id"])["state"] == "failed"
        assert receipts.verify_chain()["incomplete_count"] == 0
