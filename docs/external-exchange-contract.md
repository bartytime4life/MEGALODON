# Threat context and SIEM/SOAR exchange contract

Status: **offline STIX reader implemented; SIEM projection and bounded local writer implemented; SOAR handoff remains contract-only; no network client, notifier, scheduler, or executor.**

## Decision

MEGALODON may gain interoperability without gaining remote authority. Version 1
defines three separate lanes and keeps all of them local, bounded, and
operator-invoked:

| Lane | v1 shape | Explicitly absent |
| --- | --- | --- |
| Threat context | Implemented `read_completed_bundle` API for one operator-supplied, completed STIX 2.1 JSON bundle with an exact SHA-256 digest; at most 16 MiB, 4,096 objects, 32 levels of nesting, and 15 seconds | TAXII, HTTP, credentials, automatic refresh, STIX pattern execution, persistence, attribution, blocking, model input, or detection authority |
| SIEM export | Implemented `to_ecs_record` / `to_ocsf_record` / `write_export` API projecting one already-accepted event/detection pair into a new local file containing at most 10,000 records and 16 MiB under fixed ECS 9.5.0 or OCSF 1.9.0 projection profiles | Network delivery, collector/agent control, credentials, `event.original`, payloads, raw log bodies, or acknowledgement |
| SOAR handoff | An inert local handoff that can only say `destination_class=not_configured`, `max_attempts=0`, and `status=not_attempted` | Endpoint, webhook, token, retry, scheduler, playbook, case mutation, host action, firewall action, or model authority |

The checked-in schema records limits and refusals. It does not consume the
accepted fixture as configuration or authorization.

## Trust and data rules

Threat-intelligence objects are untrusted context. The reader preserves a
closed immutable projection of object identity, source references,
created/modified times, confidence, labels, supported markings, and indicator
patterns. It verifies all retained object-marking references against marking
definitions in the same bundle. Granular markings are refused until they can
be preserved without ambiguity. Patterns remain inert text: the reader cannot
convert context into a verified detection, infer attribution, persist data,
invoke a model, or create an action.

SIEM projections are lossy, versioned views of already accepted metadata.
[`megalodon/siem_export.py`](../megalodon/siem_export.py) implements this as
two pure functions plus a bounded local-file writer: `to_ecs_record` and
`to_ocsf_record` carry MEGALODON evidence and run identifiers, source kind,
observed and ingested time, completeness/quality state, and the projection
version, each inside that standard's own sanctioned extension mechanism (a
free-form `megalodon` namespace for ECS, the `unmapped` object plus the
generic `activity_id: 99`/"Other" sentinel for OCSF), so neither profile
claims full upstream compliance. Neither function reconstructs a field
MEGALODON did not retain, and `event.original` is never produced because it
would preserve the raw source body. `write_export` validates the full record
count and byte ceiling before creating anything. It writes a private temporary
sibling, checks for a complete write, flushes and synchronizes the file, then
publishes it through an atomic hard link that cannot replace an existing
destination. The held parent directory must be root/current-user-owned and not
group/world writable unless protected by the sticky bit; a symlinked parent is
refused. The temporary name is removed and the directory synchronized before a
success receipt. A write, flush, close, file-sync or publication failure never
exposes a partial final export. Cleanup is bounded and best-effort: an interrupted
process or cleanup failure can leave a private `.megalodon-siem-*.tmp` sibling.
An `IO_ERROR` after publication can leave a complete destination whose durability
is unconfirmed; it must be inspected rather than overwritten or blindly retried.
Filesystems without the required hard-link/directory-sync operations fail closed.
The record profiles match [`contracts/external-exchange/v1/schema.json`](../contracts/external-exchange/v1/schema.json)'s
`ecsRecord`/`ocsfRecord` definitions and the fixtures in
[`contracts/external-exchange/v1/fixtures/siem-records`](../contracts/external-exchange/v1/fixtures/siem-records).
Neither function nor the writer performs a database read, a dashboard write,
or any network call; a caller must supply already-accepted domain objects
and an explicit destination path.

SOAR remains a vocabulary-only handoff. The existing alert-lifecycle v1 outbox
already proves that no delivery attempt can be represented when
`max_attempts=0`. Any future product-specific adapter requires its own reviewed
destination allowlist, identity and authorization model, secret custody, TLS
policy, queue and rate limits, replay/idempotency behavior, kill switch,
ambiguous-delivery reconciliation, and privacy review.

## Dependency-ordered adoption

1. **Implemented on `main` by merged PR #269:** bounded offline STIX reader against one
   private completed file, with exact digest, immutable output, fixed failures,
   adversarial fixtures, and zero network/process/persistence behavior.
2. **Implemented:** pure projection functions for ECS and OCSF
   (`megalodon/siem_export.py`) plus golden fixtures
   (`contracts/external-exchange/v1/fixtures/siem-records`); `write_export`
   writes only to a new private local file and fails before partial
   publication.
3. Connect neither path to the dashboard, a network destination, or a schedule
   until exact-head tests, independent review, and operator acceptance exist.
   The engine above is a standalone API only; no other module imports it.
4. Keep SOAR execution blocked. A later design starts with a provider-neutral,
   zero-attempt receipt and may not reuse model output or untrusted feed fields
   as an endpoint, command, target, or authorization decision.

## What the tests prove

The contract tests validate the closed schema, exact three-lane vocabulary,
fixed limits, and negative fixtures for live TAXII, network SIEM delivery/raw
retention, and active SOAR behavior. The reader tests additionally exercise
digest, file identity/mode/owner/link, UTF-8, duplicate-key, numeric, depth,
object-count, marking-resolution, immutability, deadline, output, and no-side-
effect boundaries. `tests/test_siem_export.py` additionally validates every
projected ECS/OCSF record against `schema.json`, that neither profile ever
contains `event.original`, a payload, or a credential-shaped field, the
closed severity mapping, and that `write_export` creates no file at all when
the record count or byte ceiling is exceeded or the destination already
exists. None of this proves semantic trust in a feed, complete STIX or
ECS/OCSF interoperability, storage atomicity, third-party delivery, threat
coverage, operational accuracy, independent review, release readiness, or
deployment.
