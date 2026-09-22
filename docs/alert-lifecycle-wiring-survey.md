# Alert lifecycle wiring survey

Status: ◐ **Proposed; blocked on operator and security review.** This is a
design-only map of possible connections. It changes no schema, command, route,
alert state, notifier, or host behavior. Basis: repository
`main@2a3e29632b2cdb842d5d7dfb1efd32d023140893` and the
[alert lifecycle contract](alert-lifecycle-contract.md) read on 2026-09-21.

## Current boundary

[`megalodon/alert_lifecycle.py`](../megalodon/alert_lifecycle.py) implements
bounded v1 projection, transition, inert outbox, and `not_attempted` receipt
logic. `AlertLifecycleLedger` keeps its state in one process's memory; a restart
loses it, and it is not thread-safe. The synthetic contract and engine tests
exercise those pure transitions. They do not establish an operator identity,
durable transaction, alert created from a stored detection, or delivery.

[`megalodon/storage.py`](../megalodon/storage.py) has a v3 SQLite audit schema
for events, detections, policy-plan actions, and ingestion-run receipts. It has
no alert projection, transition ledger, or outbox tables. The
[`CLI`](../megalodon/cli.py) has no alert lifecycle command. The
[`dashboard`](dashboard-http-contract.md) projects bounded telemetry from a
read-only store; its only optional POST is the separately gated AI question
route. It has no alert acknowledgement, suppression, resolution, or delivery
route. A detector's existing `suppressed_reason` is not the proposed alert
lifecycle `suppressed` state.

## Proposed connections and decisions

| Boundary | Candidate connection | Review decision before implementation |
| --- | --- | --- |
| Detection to alert | Reference one already committed, immutable detection ID and an exact policy version; define when an alert is created | Which detections are eligible, how replay/duplicate creation is refused, and how a missing or reconciliation-required detection remains unprojected |
| SQLite writer | Version a new schema for projection, append-only transitions, inert outbox intent, and `not_attempted` receipts, with referential and uniqueness constraints | One transaction for projection/revision, ledger row, intent, and counters; explicit migration, rollback, capacity, restart, and uncertain-commit readback rules |
| CLI | Consider an explicit local operator workflow to read one alert and submit a transition with expected revision and idempotency key | Authenticating and authorizing the actor, protecting another user's alert, avoiding free-text `actor_id` as proof, and defining denial/confirmation receipts |
| Dashboard | Consider a bounded read-only alert projection after storage and privacy review | New API version, source/identity labels, row and byte caps, stale/unavailable/reconciliation states, and no implication that a displayed state grants authority; any write route needs separate authentication, CSRF/IDOR, and security review |
| Outbox | Persist only the contract's `not_configured`, zero-attempt intent and `not_attempted` receipt | Whether even inert intent should be stored; delivery, retries, destinations, and secrets remain a separate adapter-specific proposal |

The engine's `apply_transition` can inform a future storage transaction, but
its process-local ledger cannot itself be promoted into durable truth. The
current detection record must remain immutable when an alert transition fails.
An uncertain SQLite commit must return a reconciliation-required state, not
silently retry or report success. A UI read must not become an actor identity
or an acknowledgement action.

## Blocking controls and next evidence

The [security review's open-control register](../SECURITY_REVIEW.md) still
requires operator dashboard acceptance, finite retention-policy values on an
authorized host, native storage confidentiality where applicable, and the
independent review required by particular control rows. The lifecycle contract
also requires identity, authentication, authorization, and an adapter-specific
privacy/secret/egress/failure review before any delivery path. Closed contract
or resource-control issues do not discharge those obligations.

Before any implementation PR, obtain an operator/security decision on actor
identity and permissions, alert creation policy, retention/deletion order,
storage failure and reconciliation behavior, and whether a CLI or browser write
surface is acceptable. A later implementation would need exact-head tests for
replay, stale revisions, cross-alert references, restart, partial/uncertain
commits, capacity, privacy and access denials, plus an authorized-host receipt.
Those tests and decisions do not exist in this survey.

## What this does not establish

- Persistent alerts, a migration path, CLI or dashboard alert actions, or an
  operator-approved workflow.
- Notification attempts, delivery, retry, credentials, or external egress.
- Host acceptance, sensor health, release readiness, or platform support.
