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
| `transition` | Future append-only state-change ledger entry | Requires a prior state, expected revision, actor placeholder, bounded reason, and idempotency key. |
| `outboxIntent` | Future durable intent associated with a transition | The only allowed destination class is `not_configured`; no endpoint, credential, provider, or message body exists. |
| `deliveryReceipt` | Future outcome record, independent of transition state | `not_attempted` is explicit. Attempted, delivered, failed, expired, suppressed, and dead-lettered are descriptions, never proof that an alert transition or detection changed. |

The deterministic transition cases allow `open -> acknowledged`, `open -> suppressed`, `acknowledged -> resolved`, `acknowledged -> open`, and `suppressed -> open`. Direct `open -> resolved`, terminal reopening, and acknowledgement after expiry are rejected. A future implementation must enforce this graph transactionally and must add an explicit, reviewed policy before changing it.

## Limits and exclusions

- All objects are closed; unknown fields fail validation.
- IDs are bounded logical identifiers, not filesystem paths, URLs, commands, credentials, or provider names.
- `max_attempts` is capped at three. The supplied draft only permits an inert `not_configured` outbox intent with zero attempts.
- Receipts carry a fixed bounded code, never raw exceptions, headers, destination values, secrets, packet content, or hashes.
- Schema validation cannot prove authentication, authorization, transactionality, optimistic-concurrency enforcement, ordering, retention, rate limiting, or delivery. Those require separately reviewed runtime work.

## Validation

```bash
python -m pytest -q tests/test_alert_lifecycle_contract.py
```

The test suite validates the JSON Schema, every positive and negative fixture, the legal transition matrix, bounded retry behavior, and the absence of runtime imports, network/client fields, or executable authority. It does not execute a notifier or create a storage surface.

## Next gate

Issue #84 remains blocked from runtime adoption by issue #3 review control, the whole-service capacity/retention decisions in #68, operator identity and authorization design, native Windows storage confidentiality, and an adapter-specific egress/secret review. Do not add a notifier, destination, retry worker, dashboard mutation, or provider credential to this v1 contract.
