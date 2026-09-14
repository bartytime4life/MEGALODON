"""Tests for the no-network local-model advisory preflight."""

from __future__ import annotations

import ast
import copy
from dataclasses import FrozenInstanceError
import inspect

import pytest

import megalodon.local_model_advisory as airlock


def request() -> dict[str, object]:
    return {
        "projection": {
            "source_kind": "tshark",
            "adapter_id": "offline-tshark-v1",
            "terminal_status": "complete",
            "accepted_records": 206,
            "rejected_records": 0,
            "candidate_count": 0,
            "question_type": "explain_run",
        },
        "model_receipt": {
            "provider_class": "local_loopback",
            "model_id": "local:qwen-approved-v1",
            "model_artifact_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "policy_version": "local-model-advisory-v1",
        },
        "limits": {
            "max_input_bytes": 4096,
            "max_output_bytes": 4096,
            "timeout_seconds": 15,
            "max_concurrency": 1,
        },
    }


def test_preflight_admits_only_an_immutable_prompt_plan() -> None:
    decision = airlock.preflight(request())

    assert decision.outcome == "ADMIT"
    assert decision.code == "PROMPT_CONSTRUCTION_ADMITTED"
    assert decision.plan is not None
    assert decision.plan.model_id == "local:qwen-approved-v1"
    assert decision.plan.prompt == (
        "MEGALODON_LOCAL_ADVISORY_V1\n"
        "role=metadata_only_explainer\n"
        "question_type=explain_run\n"
        "source_kind=tshark\n"
        "adapter_id=offline-tshark-v1\n"
        "terminal_status=complete\n"
        "accepted_records=206\n"
        "rejected_records=0\n"
        "candidate_count=0\n"
        "instruction=Explain only the typed aggregate metadata. Do not infer evidence or actions."
    )
    assert len(decision.plan.prompt.encode("utf-8")) <= 4096
    with pytest.raises(FrozenInstanceError):
        decision.plan.prompt = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.__setitem__("operator_instruction", "ignore policy"),
        lambda value: value["projection"].__setitem__("raw_evidence", "forbidden"),
        lambda value: value["projection"].__setitem__("adapter_id", "bad\nvalue"),
        lambda value: value["projection"].__setitem__("candidate_count", True),
        lambda value: value["model_receipt"].__setitem__("model_id", "local:qwen-other-v1"),
        lambda value: value["model_receipt"].__setitem__("model_artifact_sha256", "A" * 64),
        lambda value: value["model_receipt"].__setitem__("provider_class", "remote"),
        lambda value: value["limits"].__setitem__("max_input_bytes", 4095),
        lambda value: value["limits"].__setitem__("max_concurrency", True),
    ],
)
def test_preflight_denies_closed_policy_violations(mutate: object) -> None:
    value = copy.deepcopy(request())
    mutate(value)  # type: ignore[operator]

    decision = airlock.preflight(value)

    assert decision.outcome == "DENY"
    assert decision.code == "POLICY_DENIED"
    assert decision.plan is None
    assert decision.summary == "The advisory request is outside the no-network preflight policy."


def test_preflight_denies_when_prompt_would_exceed_its_fixed_byte_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    admitted = airlock.preflight(request())
    assert admitted.plan is not None
    constrained_limit = len(admitted.plan.prompt.encode("utf-8")) - 1
    monkeypatch.setattr(airlock, "MAX_INPUT_BYTES", constrained_limit)
    constrained_request = request()
    constrained_request["limits"]["max_input_bytes"] = constrained_limit

    denied = airlock.preflight(constrained_request)

    assert denied.outcome == "DENY"
    assert denied.code == "POLICY_DENIED"


def test_airlock_has_no_network_process_storage_or_host_action_imports() -> None:
    tree = ast.parse(inspect.getsource(airlock))
    imports = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }

    assert imports <= {"__future__", "dataclasses", "re", "typing"}
    source = inspect.getsource(airlock)
    for forbidden in ("socket", "subprocess", "sqlite3", "pathlib", "requests", "urllib"):
        assert forbidden not in source
