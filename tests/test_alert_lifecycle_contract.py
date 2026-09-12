"""Data-only alert-lifecycle contract tests; no notifier or storage surface."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).parents[1] / "contracts" / "alert-lifecycle" / "v1"
SCHEMA = json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))
FORMAT_CHECKER = FormatChecker()
LEGAL_TRANSITIONS = {
    ("open", "acknowledged"),
    ("open", "suppressed"),
    ("acknowledged", "resolved"),
    ("acknowledged", "open"),
    ("suppressed", "open"),
}


def validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(
        {"$ref": f"#/$defs/{name}", "$defs": SCHEMA["$defs"]},
        format_checker=FORMAT_CHECKER,
    )


def fixtures(kind: str) -> list[Path]:
    return sorted((ROOT / "fixtures" / kind).glob("*.json"))


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


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


def test_transition_matrix_is_explicit_and_discriminating() -> None:
    cases = load(ROOT / "fixtures" / "transition-cases.json")
    assert cases
    for case in cases:
        edge = case["from"], case["to"]
        assert (edge in LEGAL_TRANSITIONS) is case["valid"]
    assert ("open", "resolved") not in LEGAL_TRANSITIONS
    assert ("resolved", "open") not in LEGAL_TRANSITIONS


def test_outbox_and_receipt_keep_delivery_authority_closed() -> None:
    outbox = SCHEMA["$defs"]["outboxIntent"]["properties"]
    receipt = SCHEMA["$defs"]["deliveryReceipt"]["properties"]
    assert outbox["destination_class"] == {"enum": ["not_configured"]}
    assert outbox["max_attempts"]["maximum"] == 3
    assert outbox["status"] == {"const": "pending"}
    assert set(receipt["status"]["enum"]) == {
        "not_attempted", "attempted", "delivered", "failed", "expired", "suppressed", "dead_lettered"
    }
    field_names = {
        field
        for definition in SCHEMA["$defs"].values()
        if isinstance(definition, dict)
        for field in definition.get("properties", {})
    }
    for forbidden in ("endpoint", "url", "credential", "secret", "token", "command", "subprocess", "firewall"):
        assert forbidden not in field_names


def test_contract_is_data_only_and_does_not_import_runtime_modules() -> None:
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
