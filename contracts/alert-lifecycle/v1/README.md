# Alert lifecycle contract v1

**Status:** normative draft, schema and synthetic-fixture boundary only. This
directory does not create an alert, change a detection, persist SQLite rows,
identify or authenticate an operator, send a notification, access a network,
or enable a scheduler, adapter, or response action.

This is the smallest source-only slice for [issue #84](https://github.com/bartytime4life/MEGALODON/issues/84). It deliberately separates immutable detection evidence from a future mutable alert projection, append-only transition ledger, delivery outbox intent, and delivery receipt. The checked-in schema and fixtures are contract evidence, not a runtime API or database migration.

## Shapes

| Definition | Purpose | Fixed boundary |
| --- | --- | --- |
| `alertProjection` | Mutable operator-facing state derived from one detection | Carries only stable IDs, policy version, state, revision, and timestamps; it contains no evidence payload or verdict. |
| `transition` | Future append-only state-change ledger entry | Requires the policy version in force, prior state, expected revision, actor placeholder, bounded reason, and idempotency key. |
| `outboxIntent` | Future durable intent associated with a transition | The only allowed destination class is `not_configured` and `max_attempts` is exactly zero; no endpoint, credential, provider, or message body exists. |
| `deliveryReceipt` | Future outcome record, independent of transition state | Uses a closed, provider-neutral code vocabulary. `not_attempted` is explicit; an ambiguous timeout is a failure code, never delivery proof. |

The deterministic transition cases allow `open -> acknowledged`, `open -> suppressed`, `acknowledged -> resolved`, `acknowledged -> open`, and `suppressed -> open`. Direct `open -> resolved`, terminal reopening, and acknowledgement after expiry are rejected. The semantic fixture oracle also rejects stale revisions, replayed idempotency keys, cross-alert references, policy-version mismatches, clock rollback, and out-of-order sequence values. A future implementation must enforce these relationships transactionally and must add an explicit, reviewed policy before changing them.

## Limits and exclusions

- All objects are closed; unknown fields fail validation.
- IDs are bounded logical identifiers, not filesystem paths, URLs, commands, credentials, or provider names.
- The future delivery vocabulary remains bounded to three attempts, but the supplied v1 outbox permits exactly zero attempts. The semantic fixture proves that even an ambiguous-timeout receipt cannot be attached as an attempted or delivered result to this inert intent.
- Receipts use a fixed provider-neutral code vocabulary, never raw exceptions, headers, destination values, secrets, packet content, or hashes.
- Schema validation cannot prove authentication, authorization, transactionality, optimistic-concurrency enforcement, ordering, retention, rate limiting, or delivery. Those require separately reviewed runtime work.

## Validation

```bash
python -m pytest -q tests/test_alert_lifecycle_contract.py
```

The test suite validates the JSON Schema, every positive and negative fixture, the legal transition matrix, semantic replay/stale/clock/policy refusal cases, inert receipt behavior, and the absence of runtime imports, network/client fields, or executable authority. It does not execute a notifier or create a storage surface.

## Next gate

Issue #84 remains blocked from runtime adoption by issue #3 review control, the whole-service capacity/retention decisions in #68, operator identity and authorization design, native Windows storage confidentiality, and an adapter-specific egress/secret review. Do not add a notifier, destination, retry worker, dashboard mutation, or provider credential to this v1 contract.
