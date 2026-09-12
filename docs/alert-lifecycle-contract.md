# Alert lifecycle and delivery outbox contract

Status: **normative draft contract and synthetic test oracle only.** This document and [`contracts/alert-lifecycle/v1`](../contracts/alert-lifecycle/v1/README.md) define vocabulary and structural bounds for issue #84. They do not implement alert creation, acknowledgement, assignment, resolution, escalation, notification, retry, credentials, external delivery, scheduler execution, remote access, or a database migration.

## Decision

An accepted detection remains immutable evidence even when an alert projection, transition, outbox intent, or delivery attempt fails. A future alert workflow may reference a detection but cannot rewrite, enrich, suppress, or invalidate that evidence.

The v1 contract therefore keeps four future records separate:

1. **Alert projection:** mutable local operator state derived from one detection and a versioned policy.
2. **Transition ledger:** append-only record of a requested state change with its expected revision, actor placeholder, reason code, and idempotency key.
3. **Outbox intent:** durable local intent associated with one transition, distinct from whether anything was sent or received.
4. **Delivery receipt:** bounded outcome metadata. `attempted` is not `delivered`, and neither outcome changes detection evidence.

## State and concurrency boundary

The checked-in fixture matrix permits only these state edges: `open -> acknowledged`, `open -> suppressed`, `acknowledged -> resolved`, `acknowledged -> open`, and `suppressed -> open`. A future implementation must use an optimistic `expected_revision` check and one transaction for a successful projection update, ledger append, associated outbox intent, and relevant counters. A stale revision, duplicate idempotency key, unknown actor, unsupported edge, missing policy, or uncertain commit must fail closed and preserve existing evidence.

Terminal states are not reopened by this v1 matrix. Expiry is a delivery/lifecycle outcome that does not grant acknowledgement authority. Any new edge, assignment model, actor class, or policy exception is a versioned-contract change requiring its own review.

## Outbox and delivery boundary

The data contract contains no endpoint, URL, provider name, credential, header, message body, executable command, tool selection, or raw exception field. Its only destination class is `not_configured`, and the checked-in inert fixture has zero attempts. This makes the durable-intent shape reviewable without making a delivery path reachable.

For any later adapter, a separate design must define destination allowlisting, secret custody, TLS verification, rate and queue limits, retry/backoff semantics, a local kill switch, replay behavior, clock changes, ambiguous timeouts, data minimization, and an auditable refusal state. It must never infer `delivered` from process completion or treat a notification receipt as a detection verdict.

## Retention and failure handling

The contract does not select retention values or perform deletion. A future policy must preserve immutable detections before mutable projections and must define bounded, identity-bound deletion order for projections, transitions, intents, and receipts. Disk pressure, queue exhaustion, clock rollback, process interruption, database corruption, and an uncertain commit are refusal/reconciliation conditions, not reasons to discard or rewrite evidence.

## What the fixtures prove

The contract tests prove only that the named JSON values conform to a closed schema, that the selected transition matrix remains explicit, and that endpoint/secret fields and retry amplification are rejected. They do not prove storage atomicity, identity verification, screen or API behavior, third-party delivery, notification receipt, continuous operation, or independent review.

## Adoption gates

Runtime adoption remains blocked by the review-control work in #3, whole-service capacity and retention boundaries in #68, an explicit operator identity/authentication/authorization design, native Windows storage confidentiality evidence, and one adapter-specific privacy/secret/egress/failure review. No code path may consume these fixtures as authorization.
