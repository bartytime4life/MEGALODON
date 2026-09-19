# Alert lifecycle and delivery outbox contract

Status: **normative draft contract, plus a bounded in-memory decision engine.** This document and [`contracts/alert-lifecycle/v1`](../contracts/alert-lifecycle/v1/README.md) define vocabulary and structural bounds for issue #84. [`megalodon/alert_lifecycle.py`](../megalodon/alert_lifecycle.py) turns the transition/outbox/receipt logic that used to live only as a test oracle into a reusable, importable pure-Python API (`alert_projection`, `transition`, `apply_transition`, `outbox_intent`, `not_attempted_receipt`, and the process-local `AlertLifecycleLedger` helper), validated against the same checked-in fixtures in [`tests/test_alert_lifecycle_engine.py`](../tests/test_alert_lifecycle_engine.py). Neither the contract nor the engine implements alert creation from a live detection, assignment, escalation, notification, retry, credentials, external delivery, scheduler execution, remote access, persistence, or a database migration. `AlertLifecycleLedger` keeps state only in one process's memory; it is not the SQLite audit store in `storage.py`, is not thread-safe, and is not wired into detection ingestion, the dashboard, or the CLI.

## Decision

An accepted detection remains immutable evidence even when an alert projection, transition, outbox intent, or delivery attempt fails. A future alert workflow may reference a detection but cannot rewrite, enrich, suppress, or invalidate that evidence.

The v1 contract therefore keeps four future records separate:

1. **Alert projection:** mutable local operator state derived from one detection and a versioned policy.
2. **Transition ledger:** append-only record of a requested state change with its policy version, expected revision, actor placeholder, reason code, and idempotency key.
3. **Outbox intent:** durable local intent associated with one transition, distinct from whether anything was sent or received.
4. **Delivery receipt:** bounded outcome metadata. `attempted` is not `delivered`, and neither outcome changes detection evidence.

## State and concurrency boundary

The checked-in fixture matrix permits only these state edges: `open -> acknowledged`, `open -> suppressed`, `acknowledged -> resolved`, `acknowledged -> open`, and `suppressed -> open`. Projection revisions start at one; a candidate transition must name that exact current revision and use the next sequence value. The ledger also records the exact policy version in force so later projection changes cannot erase that decision basis. A future implementation must use one transaction for a successful projection update, ledger append, associated outbox intent, and relevant counters. The synthetic oracle rejects stale revisions, duplicate idempotency keys, cross-alert references, policy mismatches, clock rollback, unsupported edges, and out-of-order sequence values. Unknown actors, identity forgery, and authorization must fail closed once an identity boundary exists; this draft does not claim to provide one.

Terminal states are not reopened by this v1 matrix. Expiry is a delivery/lifecycle outcome that does not grant acknowledgement authority. Any new edge, assignment model, actor class, or policy exception is a versioned-contract change requiring its own review.

## Outbox and delivery boundary

The data contract contains no endpoint, URL, provider name, credential, header, message body, executable command, tool selection, or raw exception field. Its only destination class is `not_configured`, its only draft outbox status is `pending`, and `max_attempts` is exactly zero. This v1 object therefore cannot represent a configured retry plan. Receipt codes are a closed provider-neutral vocabulary: an ambiguous timeout is an explicit `failed` outcome, never `delivered`, and free-form provider errors cannot enter the receipt.

For any later adapter, a separate design must define destination allowlisting, secret custody, TLS verification, rate and queue limits, retry/backoff semantics, a local kill switch, replay behavior, clock changes, data minimization, and an auditable refusal state. It must never infer `delivered` from process completion or treat a notification receipt as a detection verdict.

## Retention and failure handling

The contract does not select retention values or perform deletion. A future policy must preserve immutable detections before mutable projections and must define bounded, identity-bound deletion order for projections, transitions, intents, and receipts. Disk pressure, queue exhaustion, clock rollback, process interruption, database corruption, and an uncertain commit are refusal/reconciliation conditions, not reasons to discard or rewrite evidence.

## What the fixtures prove

The contract tests prove only that the named JSON values conform to a closed schema, the selected transition/sequence/policy relationships remain explicit, an inert outbox cannot produce an attempt, and endpoint/secret fields, raw error text, ambiguous-delivery claims, and retry amplification are rejected. They do not prove storage atomicity, identity verification, IDOR/CSRF resistance, queue-exhaustion behavior, screen or API behavior, third-party delivery, notification receipt, continuous operation, or independent review.

The engine tests additionally prove that `megalodon.alert_lifecycle.apply_transition` reaches the same accept/reject outcome as the contract's semantic fixtures for every named case, that its outbox/receipt constructors reproduce the accepted fixture values byte-for-byte, and that the module's public surface names no delivery, notification, or endpoint operation. They do not prove anything about a future storage-backed, identity-bound, or dashboard-wired implementation.

## Adoption gates

Runtime adoption still needs an explicit operator identity/authentication/authorization design, native Windows storage confidentiality evidence where applicable, and one adapter-specific privacy/secret/egress/failure review. Closed #68 delivered bounded resource controls but did not select operator retention values or prove native sustained capacity. Closed #3 records the owner-directed review workflow, not an enforced independent-human approval floor. Apply the current control register and preserve separate operational acceptance. No code path may consume these fixtures as authorization.
