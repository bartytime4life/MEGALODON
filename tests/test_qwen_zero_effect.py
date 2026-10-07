"""Issue #446: scoped denial evidence, never native model acceptance.

Inputs and imports are prepared before the sentinels. No server, model,
diagnostic command, service, firewall or background worker is operated here.
"""

from __future__ import annotations

import builtins
from collections import OrderedDict
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import threading
from types import SimpleNamespace

import pytest

from megalodon import ai_broker, ai_interface, ai_provider, firewall
from megalodon import model_telemetry, provider_containment, qwen_advisory
from megalodon.config import AISettings, BlockingSettings
from megalodon.dashboard import DashboardHandler
from megalodon.local_model_readiness import LocalModelReadinessError, assess_readiness


ROOT = Path(__file__).parents[1]
UNBOUND = json.loads((ROOT / "config/model-bindings/qwen.unbound.json").read_text())
FIXTURES = ROOT / "contracts/local-model-advisory/v1/fixtures/accepted"
REQUEST = json.loads((FIXTURES / "request.json").read_text())["value"]
REGISTRY = json.loads((FIXTURES / "registry.json").read_text())["value"]
REGISTRY_PIN = "9aa4bd1060a37e71e262b186c10a36c70feb25d97d3377a29e95b272fe2e5d58"


@pytest.fixture(autouse=True)
def isolated_observations(monkeypatch):
    monkeypatch.setattr(ai_provider, "_observations", OrderedDict())


@contextmanager
def no_effects(monkeypatch):
    """Fail on attempts, including attempts a caller catches and suppresses.

    Scoped to the invocation, excluding imports, fixture reads and pytest's
    own output/cache. File opens are forbidden even in read mode; the status
    test supplies only synthetic procfs reads through its module namespace.
    Process/service/firewall effects cannot escape the process-start guards.
    """
    attempts = []

    def forbidden(name):
        def fail(*_args, **_kwargs):
            attempts.append(name)
            raise AssertionError("forbidden effect: " + name)
        return fail

    with monkeypatch.context() as guard:
        surfaces = [
            (builtins, ("open",)), (io, ("open",)), (Path, ("open",)),
            (os, ("open", "write", "mkdir", "makedirs", "unlink", "remove",
                  "rmdir", "rename", "replace", "chmod", "chown", "fchmod", "fchown",
                  "link", "symlink", "utime", "truncate", "ftruncate", "system",
                  "fork", "posix_spawn", "posix_spawnp", "execv", "execve", "execvp",
                  "execvpe", "spawnv", "spawnve", "spawnvp", "spawnvpe")),
            (socket, ("socket", "create_connection", "getaddrinfo",
                      "gethostbyname", "gethostbyname_ex", "gethostbyaddr")),
            (subprocess, ("Popen", "run", "call", "check_call", "check_output")),
            (sqlite3, ("connect",)), (threading.Thread, ("start",)),
            (firewall.NftablesFirewall, ("available", "install", "plan_block", "block")),
            (ai_broker, ("ReceiptStore",)),
            (ai_provider, ("_request",)),
            (qwen_advisory, ("_LiteralLoopbackHTTPConnection",
                             "_acquire_process_invocation_lock")),
        ]
        for owner, names in surfaces:
            for name in names:
                if hasattr(owner, name):
                    guard.setattr(owner, name, forbidden(name))
        yield
    assert attempts == []


@pytest.mark.parametrize("entry", ["admitted", "inventory", "generate", "background"])
def test_disabled_provider_denies_without_any_io(monkeypatch, entry):
    settings = AISettings()
    # No posture read is needed for these entry points, unlike status().
    def no_posture(**_kwargs):
        raise AssertionError("disabled admission reached posture")
    monkeypatch.setattr(ai_provider, "qwen_provider_posture", no_posture)
    with no_effects(monkeypatch):
        for _ in range(2):
            if entry == "inventory":
                assert ai_provider.inventory(settings) == {
                    "model_present": False, "digest_matches": False, "error_code": "DISABLED",
                }
            else:
                with pytest.raises(ai_provider.AIProviderError, match="^DISABLED$"):
                    if entry == "admitted":
                        ai_provider._admitted(settings)
                    else:
                        ai_provider.generate(settings, "Synthetic request",
                                             priority="background" if entry == "background" else "manual")
    assert ai_provider.last_observation(settings).get("running") is not True


@pytest.mark.parametrize("case", ["disabled", "bad_pin", "bad_digest", "bad_request"])
def test_advisory_denial_precedes_every_effect(monkeypatch, case):
    request, registry = deepcopy(REQUEST), deepcopy(REGISTRY)
    pin = REGISTRY_PIN
    if case == "bad_pin":
        pin = "f" * 64
    elif case == "bad_digest":
        request["model_receipt"]["model_artifact_sha256"] = "f" * 64
    elif case == "bad_request":
        request["projection"]["raw_log"] = "refused synthetic input"
    before = deepcopy((request, registry))
    with no_effects(monkeypatch):
        decisions = [qwen_advisory.invoke_qwen_advisory(
            request, enabled=case != "disabled", local_model_registry=registry,
            local_model_registry_sha256=pin,
        ) for _ in range(2)]
        results = [decision.to_dict() for decision in decisions]
    assert results[0] == results[1]
    assert decisions[0].reason_code == decisions[1].reason_code
    assert results[0].get("outcome", results[0].get("decision")) == "DENY"
    assert all(decision.provider_request_performed is False for decision in decisions)
    assert decisions[0].reason_code == {
        "disabled": "EXPLICIT_ENABLEMENT_REQUIRED",
        "bad_pin": "REGISTRY_FINGERPRINT_MISMATCH",
        "bad_digest": "MODEL_NOT_APPROVED",
        "bad_request": "REQUEST_SHAPE_INVALID",
    }[case]
    assert (request, registry) == before


@pytest.mark.parametrize("evidence", [None, "identity", "profile", "containment", "evaluation", "request"])
def test_canonical_unbound_assessor_is_pure_and_cannot_promote(monkeypatch, evidence):
    binding = deepcopy(UNBOUND)
    with no_effects(monkeypatch):
        for _ in range(2):
            if evidence is not None:
                with pytest.raises(LocalModelReadinessError, match="^EVIDENCE_WITH_UNBOUND_BINDING$"):
                    assess_readiness(binding, **{evidence: {}})
            else:
                first = assess_readiness(binding)
                assert first == assess_readiness(binding)
                assert first["state"] == first["binding_status"] == "UNBOUND"
                assert first["gate_failures"] == ["OWNER_MODEL_BINDING_NOT_RECORDED"]
                assert not any(first["authority"].values())
                assert first["tools_used_or_authorized"] is False
    assert binding == UNBOUND


@pytest.mark.parametrize("probe", [False, True])
def test_disabled_status_reads_synthetic_posture_but_has_no_effects(monkeypatch, probe):
    reads = []

    def proc_read(path, mode="r", **_kwargs):
        assert path in {"/proc/net/tcp", "/proc/net/tcp6"} and mode == "r"
        reads.append(path)
        return io.StringIO("synthetic header\n")

    # Exercise the real posture parser against in-memory tables, not the host.
    monkeypatch.setattr(provider_containment, "require_unprivileged_linux", lambda: None)
    monkeypatch.setattr(provider_containment, "open", proc_read, raising=False)
    with no_effects(monkeypatch):
        first = ai_provider.status(AISettings(), probe=probe)
        assert first == ai_provider.status(AISettings(), probe=probe)
    assert reads == ["/proc/net/tcp", "/proc/net/tcp6"] * 2
    assert first["state"] == "disabled" and first["error_code"] == "DISABLED"
    assert first["inference_verified"] is False and first["ollama_available"] is None


def test_disabled_question_stops_before_model_reader_or_receipts(monkeypatch):
    broker = ai_broker.Broker(object(), object(), AISettings(), BlockingSettings())
    with no_effects(monkeypatch):
        with pytest.raises(ai_provider.AIProviderError, match="^DISABLED$"):
            ai_interface.ask("seeing", broker)


def test_disabled_broker_model_status_has_no_provider_effect_but_still_audits(monkeypatch):
    events = []

    class MemoryReceipts:
        def append(self, receipt_id, event):
            events.append((receipt_id, event))
            return event

    monkeypatch.setattr(ai_provider, "qwen_provider_posture",
                        lambda **_: {"listening": "no", "loopback_only": None})
    broker = ai_broker.Broker(object(), MemoryReceipts(), AISettings(), BlockingSettings())
    with no_effects(monkeypatch):
        result = broker.dispatch({"tool": "megalodon.model.status", "arguments": {},
                                  "reason": "Synthetic disabled diagnostic"})
    assert [event["state"] for _, event in events] == ["not_attempted", "observed"]
    assert events[0][0] == events[1][0]
    assert result["result"]["state"] == "disabled"
    assert result["result"]["inference_verified"] is False
    # The real ReceiptStore persists these events; this is no provider effect,
    # not evidence of zero audit writes for a broker invocation.


@pytest.mark.parametrize("settings_source", ["handler", "support_config"])
def test_disabled_dashboard_question_has_no_body_model_or_audit_io(monkeypatch, settings_source):
    # Invoke the handler in memory: no dashboard server or HTTP socket starts.
    handler = object.__new__(DashboardHandler)
    handler.ai_settings = AISettings(enabled=settings_source == "support_config")
    if settings_source == "support_config":
        handler.support_config = SimpleNamespace(settings=SimpleNamespace(ai=AISettings()))
    sent = []
    handler._send_json = lambda value, **kwargs: sent.append((value, kwargs))
    # rfile, connection and headers are intentionally absent: denial is first.
    with no_effects(monkeypatch):
        handler._ai_ask()
    assert sent == [({"error": "AI operator authorization required"}, {"status": 403})]


def test_disabled_dashboard_status_inherits_read_only_posture_boundary(monkeypatch):
    handler = object.__new__(DashboardHandler)
    handler.path = "/api/ai/status"
    handler._has_expected_host = lambda: True
    handler._has_operator_http_auth = lambda **_: True
    sent, reads = [], []
    handler._send_json = lambda value, **kwargs: sent.append((value, kwargs))

    def proc_read(path, mode="r", **_kwargs):
        assert path in {"/proc/net/tcp", "/proc/net/tcp6"} and mode == "r"
        reads.append(path)
        return io.StringIO("synthetic header\n")

    monkeypatch.setattr(provider_containment, "require_unprivileged_linux", lambda: None)
    monkeypatch.setattr(provider_containment, "open", proc_read, raising=False)
    with no_effects(monkeypatch):
        handler.do_GET()
    assert reads == ["/proc/net/tcp", "/proc/net/tcp6"]
    assert len(sent) == 1 and sent[0][1] == {}
    assert sent[0][0]["state"] == "disabled"
    assert sent[0][0]["inference_verified"] is False


@pytest.mark.parametrize("entry", ["admitted", "inventory"])
def test_canonical_unbound_is_not_a_universal_runtime_gate(monkeypatch, entry):
    """Reach a tripwire, never HTTP, to retain the missing-gate evidence."""
    assert UNBOUND["status"] == "UNBOUND"
    assert UNBOUND["operator_decision"]["status"] == "NOT_RECORDED"
    settings = replace(AISettings(), enabled=True)
    calls = []

    class RequestReached(BaseException):
        pass

    def tripwire(path, method, body, timeout, **_kwargs):
        calls.append((path, method, body))
        raise RequestReached

    monkeypatch.setattr(ai_provider, "qwen_provider_posture",
                        lambda **_: {"listening": "yes", "loopback_only": True})
    with no_effects(monkeypatch):
        # Intentional observation seam; lower socket/process/file guards remain.
        with monkeypatch.context() as seam:
            seam.setattr(ai_provider, "_request", tripwire)
            with pytest.raises(RequestReached):
                if entry == "admitted":
                    ai_provider._admitted(settings)
                else:
                    ai_provider.inventory(settings)
    assert calls == [("/api/tags", "GET", None)]


def test_disabled_telemetry_snapshot_and_direct_refresh_have_no_effects(monkeypatch):
    monitor = model_telemetry.ModelTelemetry(AISettings)
    with no_effects(monkeypatch):
        first = monitor.snapshot()
        assert monitor.snapshot() == first
        monitor._refresh(AISettings(), None)
    assert first["state"] == "needs_setup"
    assert first["model_state"] == "disabled"
    assert first["options"] == []
    assert first["updated_at"] is None
    assert monitor._thread is None


def test_disabling_before_queued_telemetry_refresh_skips_catalog(monkeypatch):
    current = [replace(AISettings(), enabled=True)]
    queued = []

    class DeferredThread:
        def __init__(self, *, target, args, **_kwargs):
            self.target, self.args = target, args

        def start(self):
            queued.append(self)

    monkeypatch.setattr(model_telemetry, "Thread", DeferredThread)
    monitor = model_telemetry.ModelTelemetry(lambda: current[0])
    with no_effects(monkeypatch):
        monitor.snapshot()
        current[0] = AISettings()
        disabled = monitor.snapshot()
        queued[0].target(*queued[0].args)
    assert len(queued) == 1
    assert disabled["model_state"] == "disabled"
    assert monitor.snapshot()["model_state"] == "disabled"
