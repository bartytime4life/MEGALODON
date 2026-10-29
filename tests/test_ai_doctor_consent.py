"""Doctor diagnostics must not enable AI or contact a disabled provider."""

from __future__ import annotations

from argparse import Namespace
from dataclasses import replace
import json
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from megalodon import ai_broker, ai_provider, cli, provider_containment
from megalodon.config import AISettings


@pytest.fixture
def doctor_environment(monkeypatch, tmp_path):
    state = {
        "settings": SimpleNamespace(ai=AISettings(), db_path=tmp_path / "telemetry.db"),
        "posture": {"listening": "yes", "loopback_only": True,
                    "bindings": [{"uid": 1001}]},
        "receipts": [],
        "commands": [],
    }

    class MemoryReceipts:
        def __init__(self, path):
            assert path != state["settings"].db_path

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def append(self, receipt_id, event):
            state["receipts"].append((receipt_id, event))

    def diagnostic(command, **kwargs):
        assert command in (
            ["/usr/bin/nvidia-smi", "--query-gpu=name,driver_version,compute_cap",
             "--format=csv,noheader"],
            ["/usr/bin/systemctl", "show", "ollama", "-p", "IPAddressDeny",
             "-p", "IPAddressAllow", "--no-pager"],
        )
        assert kwargs == {"capture_output": True, "text": True,
                          "timeout": 3, "check": False}
        state["commands"].append(command)
        return SimpleNamespace(returncode=1, stdout="", stderr="")

    monkeypatch.setattr(cli, "_load", lambda _: state["settings"])
    monkeypatch.setattr(ai_broker, "ReceiptStore", MemoryReceipts)
    monkeypatch.setattr(provider_containment, "qwen_provider_posture", lambda **_: state["posture"])
    monkeypatch.setattr(ai_provider, "qwen_provider_posture", lambda **_: state["posture"])
    monkeypatch.setattr(subprocess, "run", diagnostic)
    monkeypatch.setattr(shutil, "which", lambda _: None)
    return state


def _doctor(capsys):
    result = cli._ai(Namespace(operation="doctor", config=None))
    output = capsys.readouterr()
    assert output.err == ""
    return result, json.loads(output.out)


def _forbidden_request(*_, **__):
    raise AssertionError("disabled AI contacted Ollama")


@pytest.mark.parametrize("listening,loopback", [("yes", True), ("no", None), ("unknown", None)])
def test_doctor_preserves_disabled_setting_without_provider_io(
    doctor_environment, monkeypatch, capsys, listening, loopback,
):
    state = doctor_environment
    state["posture"] = {"listening": listening, "loopback_only": loopback, "bindings": []}
    monkeypatch.setattr(ai_provider, "_request", _forbidden_request)
    code, output = _doctor(capsys)
    assert code == 1
    assert state["settings"].ai.enabled is False
    assert output["model_status"]["state"] == "disabled"
    assert output["model_status"]["inference_verified"] is False
    assert output["model_inventory"] == {
        "model_present": False, "digest_matches": False, "error_code": "DISABLED",
    }
    assert output["checks"]["qwen_inference_healthy"] is False
    assert output["checks"]["adapter_connected"] is False
    assert output["checks"]["firewall_authority_disabled"] is True
    assert len(state["commands"]) == 2  # Only the fixed, mocked local diagnostics.
    assert len(state["receipts"]) == 1  # Still a receipt-writing command.
    assert output["operator_action"] == (
        "Review the operator setup gates in docs/ai-control-plane.md; no host change was applied"
    )


@pytest.mark.parametrize(
    "reply,error,state_name",
    [("READY", None, "model_ready"), ("BROKEN", None, "invalid_response"),
     (None, "REQUEST_TIMEOUT", "request_timeout"),
     (None, "POLICY_REJECTION", "policy_rejection")],
)
def test_enabled_doctor_preserves_explicit_probe_and_failure_semantics(
    doctor_environment, monkeypatch, capsys, reply, error, state_name,
):
    state = doctor_environment
    settings = replace(state["settings"].ai, enabled=True)
    state["settings"].ai = settings
    calls = []

    def generate(observed, prompt, *, max_tokens):
        assert observed == settings
        assert prompt == "Reply with exactly READY and nothing else. Do not add punctuation."
        assert max_tokens == 32
        calls.append("probe")
        if error:
            raise ai_provider.AIProviderError(error)
        return reply

    def request(path, method, body, timeout):
        assert (path, method, body, timeout) == ("/api/tags", "GET", None, settings.timeout_seconds)
        calls.append("inventory")
        return json.dumps({"models": [{"name": settings.model,
                                       "digest": settings.model_digest}]}).encode()

    monkeypatch.setattr(ai_provider, "generate", generate)
    monkeypatch.setattr(ai_provider, "_request", request)
    code, output = _doctor(capsys)
    assert code == 1  # Mocked local hardware/service checks are intentionally unavailable.
    assert output["model_status"]["state"] == state_name
    assert output["model_status"]["inference_verified"] is (state_name == "model_ready")
    assert output["checks"]["qwen_inference_healthy"] is (state_name == "model_ready")
    assert output["checks"]["qwen_model_installed"] is True
    assert calls == ["probe", "inventory"]
    assert state["settings"].ai is settings


def test_inventory_refuses_disabled_before_request(monkeypatch):
    monkeypatch.setattr(ai_provider, "qwen_provider_posture", _forbidden_request)
    monkeypatch.setattr(ai_provider, "_request", _forbidden_request)
    assert ai_provider.inventory(AISettings()) == {
        "model_present": False, "digest_matches": False, "error_code": "DISABLED",
    }


@pytest.mark.parametrize("present", [False, True])
def test_enabled_inventory_retains_missing_and_mismatched_diagnostics(monkeypatch, present):
    settings = AISettings(enabled=True)
    models = [{"name": settings.model, "digest": "0" * 64}] if present else []
    monkeypatch.setattr(ai_provider, "qwen_provider_posture",
                        lambda **_: {"listening": "yes", "loopback_only": True})
    monkeypatch.setattr(ai_provider, "_request", lambda *_: json.dumps({"models": models}).encode())
    result = ai_provider.inventory(settings)
    assert result["model_present"] is present
    assert result["digest_matches"] is False
    assert result["observed_digest"] == ("0" * 64 if present else None)


@pytest.mark.parametrize("listening,loopback,error", [
    ("no", None, "OLLAMA_UNAVAILABLE"),
    ("yes", False, "POLICY_REJECTION"),
    ("yes", None, "POLICY_REJECTION"),
    ("unknown", None, "POLICY_REJECTION"),
])
def test_enabled_doctor_and_inventory_refuse_unadmitted_listener(
    doctor_environment, monkeypatch, capsys, listening, loopback, error,
):
    state = doctor_environment
    state["settings"].ai = replace(state["settings"].ai, enabled=True)
    state["posture"] = {"listening": listening, "loopback_only": loopback, "bindings": []}
    calls = []

    def forbidden_request(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("unadmitted listener reached provider I/O")

    monkeypatch.setattr(ai_provider, "_request", forbidden_request)
    expected = {"model_present": False, "digest_matches": False, "error_code": error}
    assert ai_provider.inventory(state["settings"].ai) == expected
    code, output = _doctor(capsys)
    assert code == 1
    assert output["model_inventory"] == expected
    assert output["model_status"]["inference_verified"] is False
    assert output["checks"]["qwen_model_installed"] is False
    assert calls == []
    assert len(state["receipts"]) == 1  # Doctor's diagnostic receipt is intentional.


@pytest.mark.parametrize("error_type", [OSError, ValueError])
def test_inventory_fails_closed_when_listener_observation_fails(monkeypatch, error_type):
    calls = []

    def unavailable(**kwargs):
        raise error_type("synthetic posture failure")

    def forbidden_request(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("unavailable posture reached provider I/O")

    monkeypatch.setattr(ai_provider, "qwen_provider_posture", unavailable)
    monkeypatch.setattr(ai_provider, "_request", forbidden_request)
    assert ai_provider.inventory(AISettings(enabled=True)) == {
        "model_present": False, "digest_matches": False, "error_code": "POLICY_REJECTION",
    }
    assert calls == []


def test_admitted_inventory_reads_only_one_tag_catalog(monkeypatch):
    settings = AISettings(enabled=True)
    calls = []

    def posture(**kwargs):
        calls.append("posture")
        return {"listening": "yes", "loopback_only": True}

    def request(path, method, body, timeout):
        calls.append((path, method, body, timeout))
        return json.dumps({"models": [{"name": settings.model,
                                       "digest": settings.model_digest}]}).encode()

    monkeypatch.setattr(ai_provider, "qwen_provider_posture", posture)
    monkeypatch.setattr(ai_provider, "_request", request)
    assert ai_provider.inventory(settings) == {
        "model_present": True, "digest_matches": True, "observed_digest": settings.model_digest,
    }
    assert calls == ["posture", ("/api/tags", "GET", None, settings.timeout_seconds)]


# These tests exercise dormant behavior below the release UNBOUND fence.
pytestmark = pytest.mark.usefixtures("synthetic_runtime_binding")
