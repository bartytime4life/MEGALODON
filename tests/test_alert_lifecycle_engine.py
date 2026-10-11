"""Tests for the bounded in-memory alert-lifecycle engine (issue #84)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from megalodon.alert_lifecycle import (
    AlertLifecycleError,
    AlertLifecycleLedger,
    alert_projection,
    apply_transition,
    not_attempted_receipt,
    outbox_intent,
    transition,
)

ROOT = Path(__file__).parents[1] / "contracts" / "alert-lifecycle" / "v1"


def load(name: str):
    return json.loads((ROOT / "fixtures" / name).read_text(encoding="utf-8"))


def test_semantic_fixtures_match_engine_outcomes_exactly() -> None:
    cases = load("semantic-cases.json")["transitions"]
    assert cases
    outcomes = {}
    for case in cases:
        outcome, updated = apply_transition(case["projection"], case["candidate"], case["prior"])
        outcomes[case["name"]] = outcome
        if outcome == "accepted":
            assert updated["state"] == case["candidate"]["to_state"]
            assert updated["revision"] == case["projection"]["revision"] + 1
        else:
            assert updated is None
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


def test_transition_matrix_matches_contract_edges() -> None:
    cases = load("transition-cases.json")
    from megalodon.alert_lifecycle import LEGAL_TRANSITIONS

    for case in cases:
        edge = case["from"], case["to"]
        assert (edge in LEGAL_TRANSITIONS) is case["valid"]


def test_full_open_acknowledge_resolve_flow() -> None:
    ledger = AlertLifecycleLedger()
    ledger.open_alert(
        id="alert-100", detection_id="detection-100",
        policy_version="alert-policy-v1", opened_at="2026-09-19T00:00:00Z",
    )

    ack = transition(
        id="t1", alert_id="alert-100", policy_version="alert-policy-v1",
        sequence=2, expected_revision=1, from_state="open", to_state="acknowledged",
        actor_id="operator-1", reason_code="operator_acknowledged",
        idempotency_key="alert-100.t.2", occurred_at="2026-09-19T00:01:00Z",
    )
    assert ledger.apply(ack) == "accepted"
    assert ledger.projection("alert-100")["state"] == "acknowledged"
    assert ledger.projection("alert-100")["revision"] == 2

    resolve = transition(
        id="t2", alert_id="alert-100", policy_version="alert-policy-v1",
        sequence=3, expected_revision=2, from_state="acknowledged", to_state="resolved",
        actor_id="operator-1", reason_code="operator_resolved",
        idempotency_key="alert-100.t.3", occurred_at="2026-09-19T00:02:00Z",
    )
    assert ledger.apply(resolve) == "accepted"
    assert ledger.projection("alert-100")["state"] == "resolved"
    assert len(ledger.history("alert-100")) == 2

    replay = ledger.apply(ack)
    assert replay in {"STALE_REVISION", "STATE_MISMATCH"}


def _ack_fields(**overrides):
    value = dict(
        id="t1", alert_id="alert-100", policy_version="alert-policy-v1",
        sequence=2, expected_revision=1, from_state="open", to_state="acknowledged",
        actor_id="operator-1", reason_code="operator_acknowledged",
        idempotency_key="alert-100.t.2", occurred_at="2026-09-19T00:01:00Z",
    )
    value.update(overrides)
    return value


def _ledger() -> AlertLifecycleLedger:
    ledger = AlertLifecycleLedger()
    ledger.open_alert(
        id="alert-100", detection_id="detection-100",
        policy_version="alert-policy-v1", opened_at="2026-09-19T00:00:00Z",
    )
    return ledger


@pytest.mark.parametrize("bad", [
    {"id": "t 1\n"}, {"actor_id": "a" * 5001}, {"reason_code": ""},
    {"idempotency_key": ["not", "a", "string"]},
    {"from_state": ["open"]}, {"to_state": {"state": "acknowledged"}},
])
def test_plain_mapping_candidates_get_the_same_value_checks(bad) -> None:
    with pytest.raises(AlertLifecycleError):
        transition(**_ack_fields(**bad))
    ledger = _ledger()
    with pytest.raises(AlertLifecycleError):
        ledger.apply(_ack_fields(**bad))
    assert ledger.projection("alert-100")["state"] == "open"
    assert ledger.history("alert-100") == ()


def test_ledger_history_is_detached_from_the_callers_mapping() -> None:
    ledger = _ledger()
    request = _ack_fields()
    assert ledger.apply(request) == "accepted"
    # A caller that reuses its dict for the next request must not rewrite history.
    request.update(id="t2", sequence=3, expected_revision=2, from_state="acknowledged",
                   to_state="resolved", idempotency_key="alert-100.t.3",
                   occurred_at="2026-09-19T00:02:00Z")
    assert ledger.history("alert-100")[0]["to_state"] == "acknowledged"
    assert ledger.history("alert-100")[0]["idempotency_key"] == "alert-100.t.2"
    assert ledger.apply(request) == "accepted"
    assert ledger.projection("alert-100")["state"] == "resolved"


def test_unhashable_projection_state_is_a_schema_refusal() -> None:
    projection = dict(
        id="alert-100", detection_id="detection-100", policy_version="alert-policy-v1",
        state=["open"], revision=1, created_at="2026-09-19T00:00:00Z",
        updated_at="2026-09-19T00:00:00Z",
    )
    with pytest.raises(AlertLifecycleError):
        apply_transition(projection, _ack_fields())


def test_sub_microsecond_clock_rollback_is_rejected() -> None:
    projection = alert_projection(
        id="alert-100", detection_id="detection-100", policy_version="alert-policy-v1",
        state="open", revision=1, created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00.000000900Z",
    )
    earlier = transition(**_ack_fields(occurred_at="2026-01-01T00:00:00.000000100Z"))
    assert apply_transition(projection, earlier) == ("CLOCK_ROLLBACK", None)
    same = transition(**_ack_fields(occurred_at="2026-01-01T00:00:00.0000009Z"))
    assert apply_transition(projection, same)[0] == "accepted"


def test_ledger_rejects_unknown_alert() -> None:
    ledger = AlertLifecycleLedger()
    candidate = transition(
        id="t1", alert_id="alert-missing", policy_version="alert-policy-v1",
        sequence=2, expected_revision=1, from_state="open", to_state="acknowledged",
        actor_id="operator-1", reason_code="operator_acknowledged",
        idempotency_key="alert-missing.t.2", occurred_at="2026-09-19T00:01:00Z",
    )
    assert ledger.apply(candidate) == "ALERT_MISMATCH"


def test_outbox_and_receipt_match_accepted_fixtures() -> None:
    outbox_fixture = load("accepted/pending-outbox.json")["value"]
    outbox = outbox_intent(
        id=outbox_fixture["id"],
        alert_id=outbox_fixture["alert_id"],
        transition_id=outbox_fixture["transition_id"],
        policy_version=outbox_fixture["policy_version"],
        created_at=outbox_fixture["created_at"],
    )
    assert dict(outbox) == outbox_fixture

    receipt_fixture = load("accepted/not-attempted-receipt.json")["value"]
    receipt = not_attempted_receipt(
        id=receipt_fixture["id"], outbox=outbox, occurred_at=receipt_fixture["occurred_at"],
    )
    assert dict(receipt) == receipt_fixture


def test_not_attempted_receipt_refuses_a_configured_outbox() -> None:
    with pytest.raises(AlertLifecycleError):
        not_attempted_receipt(
            id="receipt-x", outbox={"id": "outbox-1", "max_attempts": 1},
            occurred_at="2026-09-19T00:00:00Z",
        )


def test_engine_exposes_no_delivery_attempt_or_notifier_surface() -> None:
    import megalodon.alert_lifecycle as module

    forbidden_substrings = ("deliver", "notify", "send", "endpoint", "socket", "http")
    public_names = [name for name in dir(module) if not name.startswith("_")]
    for name in public_names:
        lowered = name.lower()
        assert not any(term in lowered for term in forbidden_substrings), name


def test_invalid_fields_fail_closed() -> None:
    with pytest.raises(AlertLifecycleError):
        alert_projection(
            id="not a logical id!", detection_id="d1", policy_version="p1",
            state="open", revision=1, created_at="2026-09-19T00:00:00Z",
            updated_at="2026-09-19T00:00:00Z",
        )
    with pytest.raises(AlertLifecycleError):
        alert_projection(
            id="a1", detection_id="d1", policy_version="p1",
            state="deleted", revision=1, created_at="2026-09-19T00:00:00Z",
            updated_at="2026-09-19T00:00:00Z",
        )
    with pytest.raises(AlertLifecycleError):
        transition(
            id="t1", alert_id="a1", policy_version="p1", sequence=2,
            expected_revision=1, from_state="open", to_state="acknowledged",
            actor_id="operator-1", reason_code="operator_acknowledged",
            idempotency_key="bad key with spaces", occurred_at="2026-09-19T00:00:00Z",
        )
