"""Data-only local-model advisory contract tests; no provider or runtime surface."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


ROOT = Path(__file__).parents[1] / "contracts" / "local-model-advisory" / "v1"
SCHEMA = json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))


def validator(name: str) -> Draft202012Validator:
    return Draft202012Validator({"$ref": f"#/$defs/{name}", "$defs": SCHEMA["$defs"]})


def fixtures(kind: str) -> list[Path]:
    return sorted((ROOT / "fixtures" / kind).glob("*.json"))


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def property_names(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | set().union(*(property_names(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(property_names(item) for item in value)) if value else set()
    return set()


def test_schema_is_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(SCHEMA)


@pytest.mark.parametrize("path", fixtures("accepted"), ids=lambda path: path.name)
def test_accepted_contract_fixtures(path: Path) -> None:
    case = load(path)
    validator(case["schema"]).validate(case["value"])


@pytest.mark.parametrize("path", fixtures("rejected"), ids=lambda path: path.name)
def test_rejected_contract_fixtures(path: Path) -> None:
    case = load(path)
    with pytest.raises(Exception) as caught:
        validator(case["schema"]).validate(case["value"])
    assert caught.type.__module__.startswith("jsonschema")


def test_contract_keeps_provider_and_action_authority_closed() -> None:
    fields = property_names(SCHEMA["$defs"])
    forbidden = {
        "endpoint", "url", "credential", "secret", "token", "prompt", "command",
        "subprocess", "tool", "action", "firewall", "capture", "path", "query",
    }
    assert not fields & forbidden
    receipt = SCHEMA["$defs"]["modelReceipt"]["properties"]
    limits = SCHEMA["$defs"]["limits"]["properties"]
    assert receipt["provider_class"] == {"const": "local_loopback"}
    assert limits == {
        "max_input_bytes": {"const": 4096},
        "max_output_bytes": {"const": 4096},
        "timeout_seconds": {"const": 15},
        "max_concurrency": {"const": 1},
    }
    registry = SCHEMA["$defs"]["localModelRegistry"]
    assert registry["additionalProperties"] is False
    assert registry["properties"]["schema"] == {"const": "local-model-registry-v1"}
    assert registry["properties"]["models"]["minItems"] == 1
    assert registry["properties"]["models"]["maxItems"] == 1
    assert registry["properties"]["tools"] == {"type": "array", "maxItems": 0}


def test_outcome_vocabulary_and_codes_are_closed() -> None:
    result = SCHEMA["$defs"]["advisoryResult"]
    outcomes = result["properties"]["outcome"]["enum"]
    assert outcomes == ["ANSWER", "ABSTAIN", "DENY", "ERROR"]
    codes = {
        branch["then"]["properties"]["code"]["const"]
        for branch in result["allOf"]
    }
    assert codes == {
        "ADVISORY_ANSWER",
        "INSUFFICIENT_ALLOWED_CONTEXT",
        "POLICY_DENIED",
        "LOCAL_PROVIDER_ERROR",
    }


def test_contract_test_is_data_only_and_imports_no_runtime_modules() -> None:
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert not any(name == "megalodon" or name.startswith("megalodon.") for name in imported)
