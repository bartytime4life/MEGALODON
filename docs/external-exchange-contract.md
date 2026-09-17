# Threat context and SIEM/SOAR exchange contract

Status: **contract-only; no runtime parser, exporter, network client, notifier, scheduler, or executor.**

## Decision

MEGALODON may gain interoperability without gaining remote authority. Version 1
defines three separate lanes and keeps all of them local, bounded, and
operator-invoked:

| Lane | v1 shape | Explicitly absent |
| --- | --- | --- |
| Threat context | One operator-supplied, completed STIX 2.1 JSON bundle with a recorded SHA-256 digest; at most 16 MiB, 4,096 objects, and 32 levels of nesting | TAXII, HTTP, credentials, automatic refresh, STIX pattern execution, attribution, blocking, or detection authority |
| SIEM export | A new local file containing at most 10,000 records and 16 MiB under fixed ECS 9.5.0 or OCSF 1.9.0 projection profiles | Network delivery, collector/agent control, credentials, `event.original`, payloads, raw log bodies, or acknowledgement |
| SOAR handoff | An inert local handoff that can only say `destination_class=not_configured`, `max_attempts=0`, and `status=not_attempted` | Endpoint, webhook, token, retry, scheduler, playbook, case mutation, host action, firewall action, or model authority |

The checked-in schema records limits and refusals. It does not consume the
accepted fixture as configuration or authorization.

## Trust and data rules

Threat-intelligence objects are untrusted context. A future reader must preserve
object identity, source, created/modified times, confidence, and markings while
keeping STIX patterns as inert text. Context may annotate an operator view but
cannot convert an observation into a verified detection, infer attribution, or
create an action.

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

1. Implement and fuzz the offline STIX reader against a private, completed file.
2. Add pure projection functions for ECS and OCSF plus golden fixtures; write
   only to a new private local file and fail before partial publication.
3. Connect neither path to the dashboard, a network destination, or a schedule
   until exact-head tests, independent review, and operator acceptance exist.
4. Keep SOAR execution blocked. A later design starts with a provider-neutral,
   zero-attempt receipt and may not reuse model output or untrusted feed fields
   as an endpoint, command, target, or authorization decision.

## What the tests prove

The tests validate the closed schema, exact three-lane vocabulary, fixed limits,
and negative fixtures for live TAXII, network SIEM delivery/raw retention, and
active SOAR behavior. They do not prove parser safety, projection correctness,
storage atomicity, interoperability with a SIEM, third-party delivery, threat
coverage, operational accuracy, independent review, release readiness, or deployment.
