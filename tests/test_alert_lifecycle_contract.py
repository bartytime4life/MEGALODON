"""Data-only alert-lifecycle contract tests; no notifier or storage surface."""

from __future__ import annotations

import ast
from datetime import datetime
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


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def transition_outcome(case: dict[str, object]) -> str:
    """Test-only oracle for an eventual atomic alert-transition operation."""
    projection = case["projection"]
    candidate = case["candidate"]
    prior = case["prior"]
    assert isinstance(projection, dict)
    assert isinstance(candidate, dict)
    assert isinstance(prior, list)
    validator("alertProjection").validate(projection)
    validator("transition").validate(candidate)
    for transition in prior:
        validator("transition").validate(transition)
    if candidate["alert_id"] != projection["id"]:
        return "ALERT_MISMATCH"
    if candidate["expected_revision"] != projection["revision"]:
        return "STALE_REVISION"
    if candidate["sequence"] != candidate["expected_revision"] + 1:
        return "SEQUENCE_MISMATCH"
    if candidate["from_state"] != projection["state"]:
        return "STATE_MISMATCH"
    if candidate["policy_version"] != projection["policy_version"]:
        return "POLICY_VERSION_MISMATCH"
    if _timestamp(candidate["occurred_at"]) < _timestamp(projection["updated_at"]):
        return "CLOCK_ROLLBACK"
    if any(
        transition["alert_id"] == candidate["alert_id"]
        and transition["idempotency_key"] == candidate["idempotency_key"]
        for transition in prior
    ):
        return "REPLAYED_IDEMPOTENCY_KEY"
    if (candidate["from_state"], candidate["to_state"]) not in LEGAL_TRANSITIONS:
        return "ILLEGAL_EDGE"
    return "accepted"


def receipt_outcome(case: dict[str, object]) -> str:
    """Test-only oracle proving the v1 inert outbox cannot produce an attempt."""
    outbox = case["outbox"]
    receipt = case["receipt"]
    assert isinstance(outbox, dict)
    assert isinstance(receipt, dict)
    validator("outboxIntent").validate(outbox)
    validator("deliveryReceipt").validate(receipt)
    if receipt["outbox_id"] != outbox["id"]:
        return "OUTBOX_MISMATCH"
    if outbox["max_attempts"] == 0 and (
        receipt["attempt"] != 0 or receipt["status"] != "not_attempted"
    ):
        return "OUTBOX_HAS_NO_ATTEMPTS"
    return "accepted"


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


def test_transition_semantic_cases_fail_closed() -> None:
    cases = load(ROOT / "fixtures" / "semantic-cases.json")["transitions"]
    outcomes = {case["name"]: transition_outcome(case) for case in cases}
    assert outcomes == {
        "first_acknowledgement": "accepted",
        "stale_revision": "STALE_REVISION",
        "replayed_idempotency_key": "REPLAYED_IDEMPOTENCY_KEY",
        "forged_alert_reference": "ALERT_MISMATCH",
        "policy_version_mismatch": "POLICY_VERSION_MISMATCH",
        "clock_rollback": "CLOCK_ROLLBACK",
        "illegal_edge": "ILLEGAL_EDGE",
        "out_of_order_sequence": "SEQUENCE_MISMATCH",
    }


def test_inert_outbox_semantic_cases_refuse_all_attempts() -> None:
    cases = load(ROOT / "fixtures" / "semantic-cases.json")["receipts"]
    outcomes = {case["name"]: receipt_outcome(case) for case in cases}
    assert outcomes == {
        "not_attempted_is_the_only_v1_receipt": "accepted",
        "ambiguous_timeout_cannot_be_delivered_from_v1_outbox": "OUTBOX_HAS_NO_ATTEMPTS",
    }


def test_outbox_and_receipt_keep_delivery_authority_closed() -> None:
    outbox = SCHEMA["$defs"]["outboxIntent"]["properties"]
    receipt = SCHEMA["$defs"]["deliveryReceipt"]["properties"]
    assert outbox["destination_class"] == {"enum": ["not_configured"]}
    assert outbox["max_attempts"] == {"const": 0}
    assert outbox["status"] == {"const": "pending"}
    assert set(receipt["status"]["enum"]) == {
        "not_attempted", "attempted", "delivered", "failed", "expired", "suppressed", "dead_lettered"
    }
    assert SCHEMA["$defs"]["receiptCode"]["enum"] == [
        "DELIVERY_NOT_CONFIGURED",
        "DELIVERY_ATTEMPTED",
        "DELIVERY_DELIVERED",
        "DELIVERY_FAILED",
        "DELIVERY_TIMEOUT_AMBIGUOUS",
        "DELIVERY_EXPIRED",
        "DELIVERY_SUPPRESSED",
        "DELIVERY_DEAD_LETTERED",
    ]
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
