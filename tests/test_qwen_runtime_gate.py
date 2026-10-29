"""Real release fence: no synthetic binding bypass fixture is used here."""

from argparse import Namespace
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace

import pytest

from megalodon import ai_broker, ai_interface, ai_provider, cli, local_model_runtime
from megalodon import model_telemetry, qwen_advisory
from megalodon.config import AISettings, BlockingSettings
from megalodon.dashboard import DashboardHandler
from megalodon.model_lifecycle import ModelLifecycle
from test_qwen_zero_effect import no_effects, UNBOUND, REQUEST, REGISTRY, REGISTRY_PIN
from test_anomaly_advisory import REQUEST as ANOMALY_REQUEST, REGISTRY as ANOMALY_REGISTRY, pin


FAILURE = "OWNER_MODEL_BINDING_NOT_RECORDED"
ENABLED = replace(AISettings(), enabled=True)


def test_release_fence_matches_canonical_unbound_record(monkeypatch):
    digest = hashlib.sha256(json.dumps(UNBOUND, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
    assert digest == local_model_runtime.BINDING_SHA256
    assert UNBOUND["status"] == local_model_runtime.BINDING_STATUS == "UNBOUND"
    assert UNBOUND["operator_decision"]["status"] == "NOT_RECORDED"
    assert not any(UNBOUND["effects"].values())
    assert model_telemetry.MESSAGES[model_telemetry.ERROR_STATES[FAILURE]] == local_model_runtime.MESSAGE
    monkeypatch.setenv("MEGALODON_MODEL_BINDING", "BOUND")
    with no_effects(monkeypatch):
        assert local_model_runtime.binding_failure() == FAILURE


@pytest.mark.parametrize("settings", [ENABLED, replace(ENABLED, model="other:local", model_digest="a" * 64)])
@pytest.mark.parametrize("entry", ["admitted", "generate", "background", "prepare", "loaded", "catalog"])
def test_unbound_provider_entry_denies_before_every_effect(monkeypatch, settings, entry):
    calls = {
        "admitted": lambda: ai_provider._admitted(settings),
        "generate": lambda: ai_provider.generate(settings, "synthetic"),
        "background": lambda: ai_provider.generate(settings, "synthetic", priority="background"),
        "prepare": lambda: ai_provider.prepare_model(settings),
        "loaded": lambda: ai_provider.loaded_model(settings),
        "catalog": ai_provider.model_catalog,
    }
    class ForbiddenLock:
        def acquire(self, *args, **kwargs):
            pytest.fail("generation scheduling lock acquired")

        def __enter__(self):
            pytest.fail("generation scheduling lock acquired")

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(ai_provider, "_generation_lock", ForbiddenLock())
    monkeypatch.setattr(ai_provider, "_priority_lock", ForbiddenLock())
    before = dict(ai_provider._observations)
    cancel = ai_provider._active_cancel.is_set()
    priority = ai_provider._active_priority, ai_provider._active_owner, ai_provider._manual_waiters
    with no_effects(monkeypatch):
        with pytest.raises(ai_provider.AIProviderError, match="^" + FAILURE + "$"):
            calls[entry]()
    assert dict(ai_provider._observations) == before
    assert ai_provider._active_cancel.is_set() == cancel
    assert (ai_provider._active_priority, ai_provider._active_owner, ai_provider._manual_waiters) == priority


@pytest.mark.parametrize("path,method", [("/api/tags", "GET"), ("/api/ps", "GET"),
                                         ("/api/show", "POST"), ("/api/generate", "POST")])
def test_raw_request_cannot_bypass_release_fence(monkeypatch, path, method):
    request = ai_provider._request  # Retain actual function before the tripwire replaces its name.
    with no_effects(monkeypatch):
        with pytest.raises(ai_provider.AIProviderError, match="^" + FAILURE + "$"):
            request(path, method, None, 3)


@pytest.mark.parametrize("probe", [False, True])
def test_unbound_status_and_inventory_are_pure_unknown_observations(monkeypatch, probe):
    with no_effects(monkeypatch):
        first = ai_provider.status(ENABLED, probe=probe)
        assert ai_provider.status(ENABLED, probe=probe) == first
        inventory = ai_provider.inventory(ENABLED)
    assert first["state"] == "unbound" and first["binding_status"] == "UNBOUND"
    assert first["error_code"] == FAILURE and first["inference_verified"] is False
    assert first["ollama_available"] is first["loopback_only"] is None
    assert inventory == {"model_present": False, "digest_matches": False, "error_code": FAILURE}


@pytest.mark.parametrize("anomaly", [False, True])
def test_valid_caller_preflight_cannot_grant_runtime_acceptance(monkeypatch, anomaly):
    invoke = qwen_advisory.invoke_qwen_anomaly_advisory if anomaly else qwen_advisory.invoke_qwen_advisory
    request = ANOMALY_REQUEST if anomaly else REQUEST
    arguments = dict(enabled=True, local_model_registry=ANOMALY_REGISTRY if anomaly else REGISTRY,
                     local_model_registry_sha256=pin() if anomaly else REGISTRY_PIN)
    if anomaly:
        arguments["selection_sha256"] = request["input"]["selection_sha256"]
    monkeypatch.setattr(qwen_advisory, "_INVOCATION_LOCK", SimpleNamespace(
        acquire=lambda **_: pytest.fail("invocation lock acquired")))
    with no_effects(monkeypatch):
        result = invoke(request, **arguments)
    assert isinstance(result, qwen_advisory.QwenAdvisoryResult)
    assert (result.outcome, result.code, result.reason_code) == ("DENY", "POLICY_DENIED", FAILURE)
    assert result.provider_request_performed is False and result.output_bytes == 0
    assert "No provider request" in result.limitations[0]


@pytest.mark.parametrize("question", list(ai_interface.QUESTIONS))
def test_every_question_refuses_before_fixed_tool_dispatch_or_audit(monkeypatch, question):
    broker = ai_broker.Broker(object(), object(), ENABLED, BlockingSettings())
    with no_effects(monkeypatch):
        with pytest.raises(ai_provider.AIProviderError, match="^" + FAILURE + "$"):
            ai_interface.ask(question, broker)


def test_cli_question_refuses_before_receipt_store_or_reader(monkeypatch, capsys, tmp_path):
    settings = SimpleNamespace(ai=ENABLED, db_path=tmp_path / "uncreated.db")
    monkeypatch.setattr(cli, "_load", lambda _: settings)
    with no_effects(monkeypatch):
        result = cli._ai(Namespace(operation="ask", config=None, question="report"))
    assert result == 2
    assert capsys.readouterr().err == "megalodon ai: " + FAILURE + "\n"
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("settings_source", ["handler", "support_config"])
def test_dashboard_question_refuses_before_body_or_receipt_store(monkeypatch, settings_source):
    handler = object.__new__(DashboardHandler)
    handler.ai_settings = ENABLED if settings_source == "handler" else AISettings()
    if settings_source == "support_config":
        handler.support_config = SimpleNamespace(settings=SimpleNamespace(ai=ENABLED))
    handler._ai_operator_envelope = lambda: True
    sent = []
    handler._send_json = lambda value, **kwargs: sent.append((value, kwargs))
    # No headers, rfile or connection exist: even request body reads are forbidden.
    with no_effects(monkeypatch):
        handler._ai_ask()
    assert sent[0][0]["state"] == "unbound" and sent[0][0]["error_code"] == FAILURE
    assert sent[0][1] == {"status": 503}


def test_unbound_telemetry_never_starts_thread_or_uses_stale_success(monkeypatch):
    monitor = model_telemetry.ModelTelemetry(lambda: ENABLED)
    monitor._value = {"state": "model_available", "options": [{"name": ENABLED.model}]}
    monkeypatch.setattr(ai_provider, "last_observation", lambda _: (_ for _ in ()).throw(AssertionError("stale observation read")))
    with no_effects(monkeypatch):
        first = monitor.snapshot()
        assert monitor.snapshot() == first
        monitor._refresh(ENABLED, None)
    assert first["model_state"] == "unbound" and first["state"] == "needs_setup"
    assert first["error_code"] == FAILURE
    assert first["inference_verified"] is False and first["running"] is False
    assert first["options"] == [] and first["updated_at"] is None
    assert monitor._thread is None and monitor._pending is False


@pytest.mark.parametrize("enabled", [False, True])
def test_even_explicit_inventory_refresh_refuses_unbound(monkeypatch, enabled):
    monitor = model_telemetry.ModelTelemetry(lambda: replace(ENABLED, enabled=enabled))
    with no_effects(monkeypatch):
        with pytest.raises(ai_provider.AIProviderError, match="^" + FAILURE + "$"):
            monitor.refresh_installed_models()
    assert monitor._thread is None and monitor._value is None


def test_keep_ready_worker_cannot_start_cancel_or_relabel_while_unbound(monkeypatch):
    worker = ModelLifecycle(lambda: ENABLED, on_change=lambda: pytest.fail("change callback"))
    monkeypatch.setattr(ai_provider, "cancel_current", lambda **_: pytest.fail("cancelled existing work"))
    with no_effects(monkeypatch):
        worker.start()
        worker.request()
        worker._step(force=True)
        value = worker.snapshot()
    assert worker._thread is None and worker._identity is None
    assert value["state"] == "unbound" and value["error_code"] == FAILURE
    assert value["retry_in_seconds"] == 0 and value["updated_at"] is None
