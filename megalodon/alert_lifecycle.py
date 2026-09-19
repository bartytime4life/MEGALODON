"""Bounded, in-memory alert-lifecycle decision engine for contract v1.

This module turns the checked-in
[alert-lifecycle contract](../contracts/alert-lifecycle/v1) into a reusable,
importable Python API instead of leaving its state-machine logic living only
as a test-only oracle. It validates and applies alert-projection transitions,
and constructs the one outbox intent and one delivery receipt shape the v1
contract allows.

It keeps no database, notifier, scheduler, network call, or credential path.
`AlertLifecycleLedger` is a process-local, non-persistent convenience
wrapper; it is not the SQLite audit store in `storage.py`, does not survive a
process restart, and is not thread-safe. Wiring any of this into detection
ingestion, `storage.py`, the dashboard, or the CLI is a separate,
not-yet-reviewed change requiring its own operator-identity, authorization,
and retention design, per `docs/alert-lifecycle-contract.md`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from types import MappingProxyType
from typing import Any
import re

ALERT_STATES = frozenset({"open", "acknowledged", "resolved", "suppressed", "expired"})

LEGAL_TRANSITIONS = frozenset({
    ("open", "acknowledged"),
    ("open", "suppressed"),
    ("acknowledged", "resolved"),
    ("acknowledged", "open"),
    ("suppressed", "open"),
})

ERROR_CODES = frozenset({
    "SCHEMA", "ALERT_MISMATCH", "STALE_REVISION", "SEQUENCE_MISMATCH",
    "STATE_MISMATCH", "POLICY_VERSION_MISMATCH", "CLOCK_ROLLBACK",
    "REPLAYED_IDEMPOTENCY_KEY", "ILLEGAL_EDGE",
})

_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9._:-]{1,384}\Z")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z\Z"
)

_PROJECTION_KEYS = frozenset({
    "id", "detection_id", "policy_version", "state", "revision", "created_at", "updated_at",
})
_TRANSITION_KEYS = frozenset({
    "id", "alert_id", "policy_version", "sequence", "expected_revision", "from_state",
    "to_state", "actor_id", "reason_code", "idempotency_key", "occurred_at",
})


class AlertLifecycleError(ValueError):
    """A fixed, closed diagnostic for the v1 alert-lifecycle boundary."""

    def __init__(self, code: str):
        if code not in ERROR_CODES:
            code = "SCHEMA"
        super().__init__(f"ALERT_LIFECYCLE_V1:{code}")
        self.code = code


def _fail(code: str) -> None:
    raise AlertLifecycleError(code) from None


def _logical_id(value: object) -> str:
    if type(value) is not str or not _LOGICAL_ID.fullmatch(value):
        _fail("SCHEMA")
    return value


def _idempotency_key(value: object) -> str:
    if type(value) is not str or not _IDEMPOTENCY_KEY.fullmatch(value):
        _fail("SCHEMA")
    return value


def _bounded_text(value: object) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 256
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        _fail("SCHEMA")
    return value


def _timestamp(value: object) -> str:
    if type(value) is not str or not _TIMESTAMP.fullmatch(value):
        _fail("SCHEMA")
    try:
        _parse(value)
    except ValueError:
        _fail("SCHEMA")
    return value


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


def _bounded_int(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 2_147_483_647:
        _fail("SCHEMA")
    return value


def _state(value: object) -> str:
    if value not in ALERT_STATES:
        _fail("SCHEMA")
    return value


def alert_projection(
    *, id: str, detection_id: str, policy_version: str, state: str,
    revision: int, created_at: str, updated_at: str,
) -> Mapping[str, Any]:
    """Validate and freeze one alert projection (contract `alertProjection`)."""
    return MappingProxyType({
        "id": _logical_id(id),
        "detection_id": _logical_id(detection_id),
        "policy_version": _logical_id(policy_version),
        "state": _state(state),
        "revision": _bounded_int(revision),
        "created_at": _timestamp(created_at),
        "updated_at": _timestamp(updated_at),
    })


def open_alert(
    *, id: str, detection_id: str, policy_version: str, opened_at: str,
) -> Mapping[str, Any]:
    """One new alert projection in the initial `open` state at revision 1."""
    return alert_projection(
        id=id, detection_id=detection_id, policy_version=policy_version,
        state="open", revision=1, created_at=opened_at, updated_at=opened_at,
    )


def transition(
    *, id: str, alert_id: str, policy_version: str, sequence: int,
    expected_revision: int, from_state: str, to_state: str, actor_id: str,
    reason_code: str, idempotency_key: str, occurred_at: str,
) -> Mapping[str, Any]:
    """Validate and freeze one candidate transition (contract `transition`)."""
    return MappingProxyType({
        "id": _logical_id(id),
        "alert_id": _logical_id(alert_id),
        "policy_version": _logical_id(policy_version),
        "sequence": _bounded_int(sequence),
        "expected_revision": _bounded_int(expected_revision),
        "from_state": _state(from_state),
        "to_state": _state(to_state),
        "actor_id": _logical_id(actor_id),
        "reason_code": _bounded_text(reason_code),
        "idempotency_key": _idempotency_key(idempotency_key),
        "occurred_at": _timestamp(occurred_at),
    })


def outbox_intent(
    *, id: str, alert_id: str, transition_id: str, policy_version: str, created_at: str,
) -> Mapping[str, Any]:
    """One durable local intent; v1 can only describe an unsent, unconfigured one."""
    return MappingProxyType({
        "id": _logical_id(id),
        "alert_id": _logical_id(alert_id),
        "transition_id": _logical_id(transition_id),
        "policy_version": _logical_id(policy_version),
        "destination_class": "not_configured",
        "max_attempts": 0,
        "status": "pending",
        "created_at": _timestamp(created_at),
    })


def not_attempted_receipt(
    *, id: str, outbox: Mapping[str, Any], occurred_at: str,
) -> Mapping[str, Any]:
    """The only receipt v1 authorizes: this outbox intent was never attempted."""
    if not isinstance(outbox, Mapping) or outbox.get("max_attempts") != 0:
        _fail("SCHEMA")
    return MappingProxyType({
        "id": _logical_id(id),
        "outbox_id": _logical_id(outbox["id"]),
        "attempt": 0,
        "status": "not_attempted",
        "code": "DELIVERY_NOT_CONFIGURED",
        "occurred_at": _timestamp(occurred_at),
    })


def _require_projection(value: Mapping[str, Any]) -> None:
    if not isinstance(value, Mapping) or set(value) != _PROJECTION_KEYS:
        _fail("SCHEMA")


def _require_transition(value: Mapping[str, Any]) -> None:
    if not isinstance(value, Mapping) or set(value) != _TRANSITION_KEYS:
        _fail("SCHEMA")


def apply_transition(
    projection: Mapping[str, Any],
    candidate: Mapping[str, Any],
    prior: Iterable[Mapping[str, Any]] = (),
) -> tuple[str, Mapping[str, Any] | None]:
    """Apply one candidate transition to one projection.

    Returns `("accepted", <new projection>)` or `(<closed rejection code>,
    None)`. This is a pure function: it holds no lock, writes nothing, and
    grants no identity, authorization, notification, or detection-mutation
    authority. It fails closed on any unrecognized edge, stale revision,
    replayed idempotency key, cross-alert reference, policy mismatch, clock
    rollback, or out-of-order sequence value, matching the checked-in
    contract fixtures exactly.
    """
    _require_projection(projection)
    _require_transition(candidate)
    prior = list(prior)
    for item in prior:
        _require_transition(item)

    if candidate["alert_id"] != projection["id"]:
        return "ALERT_MISMATCH", None
    if candidate["expected_revision"] != projection["revision"]:
        return "STALE_REVISION", None
    if candidate["sequence"] != candidate["expected_revision"] + 1:
        return "SEQUENCE_MISMATCH", None
    if candidate["from_state"] != projection["state"]:
        return "STATE_MISMATCH", None
    if candidate["policy_version"] != projection["policy_version"]:
        return "POLICY_VERSION_MISMATCH", None
    if _parse(candidate["occurred_at"]) < _parse(projection["updated_at"]):
        return "CLOCK_ROLLBACK", None
    if any(
        item["alert_id"] == candidate["alert_id"]
        and item["idempotency_key"] == candidate["idempotency_key"]
        for item in prior
    ):
        return "REPLAYED_IDEMPOTENCY_KEY", None
    if (candidate["from_state"], candidate["to_state"]) not in LEGAL_TRANSITIONS:
        return "ILLEGAL_EDGE", None

    updated = alert_projection(
        id=projection["id"],
        detection_id=projection["detection_id"],
        policy_version=projection["policy_version"],
        state=candidate["to_state"],
        revision=projection["revision"] + 1,
        created_at=projection["created_at"],
        updated_at=candidate["occurred_at"],
    )
    return "accepted", updated


class AlertLifecycleLedger:
    """Process-local, non-persistent bookkeeping for the v1 decision engine.

    A convenience for callers who want to hold several alerts' state without
    re-threading each alert's `prior` transition list by hand. It is not a
    database: state lives only in this instance's memory, there is no file,
    no thread-safety, and no relation to the SQLite audit store in
    `storage.py`.
    """

    def __init__(self) -> None:
        self._projections: dict[str, Mapping[str, Any]] = {}
        self._transitions: dict[str, list[Mapping[str, Any]]] = {}

    def open_alert(
        self, *, id: str, detection_id: str, policy_version: str, opened_at: str,
    ) -> Mapping[str, Any]:
        if id in self._projections:
            _fail("SCHEMA")
        projection = open_alert(
            id=id, detection_id=detection_id, policy_version=policy_version, opened_at=opened_at,
        )
        self._projections[projection["id"]] = projection
        self._transitions[projection["id"]] = []
        return projection

    def projection(self, alert_id: str) -> Mapping[str, Any]:
        try:
            return self._projections[alert_id]
        except KeyError:
            _fail("SCHEMA")

    def history(self, alert_id: str) -> tuple[Mapping[str, Any], ...]:
        try:
            return tuple(self._transitions[alert_id])
        except KeyError:
            _fail("SCHEMA")

    def apply(self, candidate: Mapping[str, Any]) -> str:
        """Apply `candidate` to its referenced alert, if this ledger holds one."""
        _require_transition(candidate)
        alert_id = candidate["alert_id"]
        if alert_id not in self._projections:
            return "ALERT_MISMATCH"
        outcome, updated = apply_transition(
            self._projections[alert_id], candidate, self._transitions[alert_id],
        )
        if outcome == "accepted":
            self._projections[alert_id] = updated
            self._transitions[alert_id].append(candidate)
        return outcome
