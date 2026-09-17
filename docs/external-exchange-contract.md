# Threat context and SIEM/SOAR exchange contract

Status: **offline STIX reader implemented; SIEM projection and SOAR handoff remain contract-only; no network client, notifier, scheduler, or executor.**

## Decision

MEGALODON may gain interoperability without gaining remote authority. Version 1
defines three separate lanes and keeps all of them local, bounded, and
operator-invoked:

| Lane | v1 shape | Explicitly absent |
| --- | --- | --- |
| Threat context | Implemented `read_completed_bundle` API for one operator-supplied, completed STIX 2.1 JSON bundle with an exact SHA-256 digest; at most 16 MiB, 4,096 objects, 32 levels of nesting, and 15 seconds | TAXII, HTTP, credentials, automatic refresh, STIX pattern execution, persistence, attribution, blocking, model input, or detection authority |
| SIEM export | A new local file containing at most 10,000 records and 16 MiB under fixed ECS 9.5.0 or OCSF 1.9.0 projection profiles | Network delivery, collector/agent control, credentials, `event.original`, payloads, raw log bodies, or acknowledgement |
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

SIEM projections are lossy, versioned views of already accepted metadata. They
must carry MEGALODON evidence and run identifiers, source kind, observed and
ingested time, completeness/quality state, and the projection version. They
must not reconstruct fields MEGALODON did not retain. In particular,
`event.original` remains absent because it would preserve the raw source body.

SOAR remains a vocabulary-only handoff. The existing alert-lifecycle v1 outbox
already proves that no delivery attempt can be represented when
`max_attempts=0`. Any future product-specific adapter requires its own reviewed
destination allowlist, identity and authorization model, secret custody, TLS
policy, queue and rate limits, replay/idempotency behavior, kill switch,
ambiguous-delivery reconciliation, and privacy review.

## Dependency-ordered adoption

1. **Implemented source candidate:** bounded offline STIX reader against one
   private completed file, with exact digest, immutable output, fixed failures,
   adversarial fixtures, and zero network/process/persistence behavior.
2. Add pure projection functions for ECS and OCSF plus golden fixtures; write
   only to a new private local file and fail before partial publication.
3. Connect neither path to the dashboard, a network destination, or a schedule
   until exact-head tests, independent review, and operator acceptance exist.
4. Keep SOAR execution blocked. A later design starts with a provider-neutral,
   zero-attempt receipt and may not reuse model output or untrusted feed fields
   as an endpoint, command, target, or authorization decision.

## What the tests prove

The contract tests validate the closed schema, exact three-lane vocabulary,
fixed limits, and negative fixtures for live TAXII, network SIEM delivery/raw
retention, and active SOAR behavior. The reader tests additionally exercise
digest, file identity/mode/owner/link, UTF-8, duplicate-key, numeric, depth,
object-count, marking-resolution, immutability, deadline, output, and no-side-
effect boundaries. They do not prove semantic trust in a feed, complete STIX
interoperability, SIEM projection correctness, storage atomicity, third-party
delivery, threat coverage, operational accuracy, independent review, release
readiness, or deployment.
