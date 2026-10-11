from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools" / "local_model_binding.py"
SPEC = importlib.util.spec_from_file_location("local_model_binding", TOOL_PATH)
assert SPEC and SPEC.loader
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)
UNBOUND = json.loads(
    (ROOT / "config" / "model-bindings" / "qwen.unbound.json").read_text()
)
BOUND = json.loads(
    (ROOT / "tests" / "fixtures" / "local_model_binding" / "bound.example.json").read_text()
)


def test_unbound_template_is_valid_and_empty() -> None:
    assert TOOL.validate(copy.deepcopy(UNBOUND))["status"] == "UNBOUND"


def test_complete_synthetic_bound_fixture_is_structurally_valid() -> None:
    assert TOOL.validate(copy.deepcopy(BOUND))["status"] == "BOUND"


def test_bound_record_rejects_mutable_latest_tag() -> None:
    candidate = copy.deepcopy(BOUND)
    candidate["artifact"]["installed_tag"] = "qwen2.5:latest"
    with pytest.raises(TOOL.BindingError, match="MUTABLE_TAG_FORBIDDEN"):
        TOOL.validate(candidate)


def test_unbound_record_cannot_smuggle_identity() -> None:
    candidate = copy.deepcopy(UNBOUND)
    candidate["logical_alias"] = "local:qwen-forged"
    with pytest.raises(TOOL.BindingError, match="UNBOUND_IDENTITY_MUST_BE_EMPTY"):
        TOOL.validate(candidate)


def test_weight_digest_must_match_component_closure() -> None:
    candidate = copy.deepcopy(BOUND)
    candidate["artifact"]["model_weight_sha256"] = "sha256:" + "1" * 64
    with pytest.raises(TOOL.BindingError, match="MODEL_WEIGHT_DIGEST_MISMATCH"):
        TOOL.validate(candidate)


def test_effects_cannot_claim_host_or_model_mutation() -> None:
    candidate = copy.deepcopy(BOUND)
    candidate["effects"]["model_started"] = True
    with pytest.raises(TOOL.BindingError):
        TOOL.validate(candidate)


@pytest.mark.parametrize(
    ("document", "field", "value"),
    [
        (BOUND, "approved_at", "2026-02-31T25:61:61Z"),
        (BOUND, "generated_at", "2026-99-99T99:99:99Z"),
        (BOUND, "generated_at", "2026-02-29T04:00:00Z"),
        (UNBOUND, "generated_at", "2026-13-01T00:00:00Z"),
    ],
)
def test_impossible_timestamps_refuse(document, field, value) -> None:
    candidate = copy.deepcopy(document)
    if field == "approved_at":
        candidate["operator_decision"]["approved_at"] = value
    else:
        candidate["generated_at"] = value
    # The schema's date-time format only applies when an optional checker is
    # installed; the datetime parse refuses either way.
    with pytest.raises(TOOL.BindingError, match="INVALID_TIMESTAMP|date-time"):
        TOOL.validate(candidate)


def test_binding_generated_before_approval_refuses() -> None:
    candidate = copy.deepcopy(BOUND)
    candidate["generated_at"] = "2026-09-22T03:59:59Z"
    with pytest.raises(TOOL.BindingError, match="BINDING_PRECEDES_APPROVAL"):
        TOOL.validate(candidate)
