# Roadmap and Current Limits

MEGALODON is a defensive MVP, not a finished enterprise IDS/IPS. Implemented
code, an open or closed issue, a passing test, and operational acceptance are
different evidence states.

## Delivered, with boundaries

- The loopback HUD now separates Home, Traffic, Findings, Apps, Reports, Evidence, and Help; historical traffic and local JSON reports remain bounded stored-data projections.
- SQLite schema-v3 migration plus explicit backup and restore-to-new-destination commands exist; activation, retention, native failure injection, and Windows ACL acceptance remain separate.
- Suricata has closed raw-EVE conversion, envelope validation, durable-consumer, reconciliation, and read-only dashboard projection APIs; there is no sensor, watcher, background service, CLI ingestion workflow, or IPS authority.
- The offline anomaly pipeline can preserve deterministic candidates alongside an optional bounded Qwen explanation; it is descriptive and uncalibrated.
- Static integration, readiness, posture, STIX, ECS/OCSF, alert-lifecycle, automation-schedule, and reference/evaluation slices remain limited to their documented contracts.

## Current product limits

The project does not currently provide:

- an authenticated remote UI or distributed sensor management;
- arbitrary rule authoring, threat-feed retrieval, TAXII polling, or SIEM/SOAR delivery;
- an active scheduler, unattended analysis, notification service, or automatic response;
- live firewall application, quarantine, remediation, or rollback orchestration;
- a continuous Suricata EVE watcher, sensor-health monitor, or retention worker;
- representative detection accuracy, false-positive, installed-sensor, or long-running capacity evidence;
- accepted native Windows parity or an accepted operator-owned Qwen/Ollama deployment.

Operational JSONL and Scapy inputs require finite event limits. Optional Linux
elapsed deadlines have explicit single-thread and signal-state restrictions and
cannot interrupt kernel-level uninterruptible sleep. The bundled IANA data is
registration context, and the synthetic corpus is deterministic regression
evidence, not a production benchmark.

## Active tracking at this refresh

At the 2026-09-21 readback, #254–#259 are closed completed, #260–#261 remain
open, and #327 is open for Zeek producer-profile qualification. The repository
basis is `main@bdddd427df3c06e30c0d7e6e3405a0e1932fc971`. Issue state
does not establish broader operational acceptance evidence.

| Issue | Remaining decision or evidence theme |
| --- | --- |
| [#258](https://github.com/bartytime4life/MEGALODON/issues/258) (closed) and [#327](https://github.com/bartytime4life/MEGALODON/issues/327) (closed 2026-09-22, see correction below) | Community ID vectors and bounded grouping are delivered; exact producer profiles and schema-drift fixtures remain the #327 gate. |
| [#259](https://github.com/bartytime4life/MEGALODON/issues/259) (closed) | Scoped owner acceptance covers the registry and synthetic report at `main@16742fed`; independent review and operational accuracy remain unproved. |
| [#260](https://github.com/bartytime4life/MEGALODON/issues/260) (closed 2026-09-22, see correction below) | Contract, packet tooling, and temporary synthetic installed-wheel recovery receipts are delivered; the complete candidate packet, artifact review, operator drill, and acceptance remain. |
| [#261](https://github.com/bartytime4life/MEGALODON/issues/261) (closed 2026-09-22, see correction below) | Contract and input repairs delivered; collector remains unbound pending exact model and authorized host acceptance. |

Apache-2.0 is selected and package metadata is aligned. Currentness, bounded
recovery and raw Suricata conversion are implemented; their original issues
are not a pending implementation backlog.

### Correction — 2026-09-25

#260, #261, and #327 closed on 2026-09-22, superseding the "remain open" /
"open" framing above; the 2026-09-21 readback and its table keep their
original text as a dated historical pin. Closure is a GitHub tracking-state
change, not new delivered evidence: #260 closed via
[#366](https://github.com/bartytime4life/MEGALODON/pull/366) as explicitly
**PARTIAL**; #261 closed via
[#364](https://github.com/bartytime4life/MEGALODON/pull/364) and
[#378](https://github.com/bartytime4life/MEGALODON/pull/378), which add a
cross-consistency readiness packet while the model binding config still
reports `UNBOUND`; #327 closed via
[#350](https://github.com/bartytime4life/MEGALODON/pull/350), an explicit
placeholder scaffold that selects no real Zeek producer version. The
"remaining decision or evidence theme" column above still applies unchanged
— only the issue tracking state moved. No successor issue currently tracks
the residual #261/#327 gap. See
[`docs/unified-roadmap-currentness.md`](../unified-roadmap-currentness.md)
for the full readback.

## Evidence still needed before broader claims

1. Retain the Apache-2.0 decision and verify exact release artifact notices and metadata.
2. Produce authorized native recovery, lock, interruption, exhaustion, and long-running evidence.
3. Qualify installed producers and privacy-reviewed representative data without turning a catalog entry into a connection claim.
4. Keep the scoped detector-report acceptance separate from independent review and obtain representative quality evidence before operational interpretation.
5. Complete Ubuntu release and native Windows evidence separately.
6. Verify the exact local model artifact and provider containment before calling Qwen an accepted capability.

Review the [open control register](../../SECURITY_REVIEW.md#open-control-register)
and the [development status](../../README.md#development-status-and-remaining-evidence)
before making release, deployment, continuous-monitoring, or production-readiness
claims.
