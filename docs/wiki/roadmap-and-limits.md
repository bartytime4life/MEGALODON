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

At the 2026-09-20 readback, #254–#258 are closed completed and #259–#261
remain open. The repository basis is `main@4c1d685` plus the local setup
alignment candidate. Issue state does not establish acceptance evidence.

| Issue | Remaining decision or evidence theme |
| --- | --- |
| [#258](https://github.com/bartytime4life/MEGALODON/issues/258) (closed) | Community ID vectors and bounded grouping are delivered; its body still lists producer-profile/schema-drift qualification. Closure supplies no missing receipt. |
| [#259](https://github.com/bartytime4life/MEGALODON/issues/259) | Registry/report delivered; scoped exact-head acceptance remains unrecorded. Synthetic counts are not accuracy. |
| [#260](https://github.com/bartytime4life/MEGALODON/issues/260) | Contract and #306 collector repair delivered; retained release evidence, recovery drill, SBOM/provenance and acceptance remain. |
| [#261](https://github.com/bartytime4life/MEGALODON/issues/261) | Contract and input repairs delivered; collector remains unbound pending exact model and authorized host acceptance. |

Apache-2.0 is selected and package metadata is aligned. Currentness, bounded
recovery and raw Suricata conversion are implemented; their original issues
are not a pending implementation backlog.

## Evidence still needed before broader claims

1. Retain the Apache-2.0 decision and verify exact release artifact notices and metadata.
2. Produce authorized native recovery, lock, interruption, exhaustion, and long-running evidence.
3. Qualify installed producers and privacy-reviewed representative data without turning a catalog entry into a connection claim.
4. Accept the versioned detector report at an exact head and obtain representative quality evidence before operational interpretation.
5. Complete Ubuntu release and native Windows evidence separately.
6. Verify the exact local model artifact and provider containment before calling Qwen an accepted capability.

Review the [open control register](../../SECURITY_REVIEW.md#open-control-register)
and the [development status](../../README.md#development-status-and-remaining-evidence)
before making release, deployment, continuous-monitoring, or production-readiness
claims.
