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

The following issues were still open on 2026-09-19. Their issue state does not
override the code and acceptance boundaries above.

| Issue | Remaining decision or evidence theme |
| --- | --- |
| [#254](https://github.com/bartytime4life/MEGALODON/issues/254) | Machine-readable repository currentness and maintainer disposition |
| [#255](https://github.com/bartytime4life/MEGALODON/issues/255) | Repository license and release metadata decision |
| [#256](https://github.com/bartytime4life/MEGALODON/issues/256) | Native and operator recovery evidence beyond the delivered contract/runtime |
| [#257](https://github.com/bartytime4life/MEGALODON/issues/257) | Raw Suricata EVE converter qualification beyond the delivered bounded API |
| [#258](https://github.com/bartytime4life/MEGALODON/issues/258) | Zeek profile qualification and correlation design |
| [#259](https://github.com/bartytime4life/MEGALODON/issues/259) | Detector registry and evidence-quality evaluation |
| [#260](https://github.com/bartytime4life/MEGALODON/issues/260) | Ubuntu 24.04 release-candidate evidence |
| [#261](https://github.com/bartytime4life/MEGALODON/issues/261) | Operator-owned Ollama/Qwen containment and acceptance |

## Evidence still needed before broader claims

1. Select the license and keep release metadata consistent.
2. Produce authorized native recovery, lock, interruption, exhaustion, and long-running evidence.
3. Qualify installed producers and privacy-reviewed representative data without turning a catalog entry into a connection claim.
4. Version and measure detector quality before operational interpretation.
5. Complete Ubuntu release and native Windows evidence separately.
6. Verify the exact local model artifact and provider containment before calling Qwen an accepted capability.

Review the [open control register](../../SECURITY_REVIEW.md#open-control-register)
and the [development status](../../README.md#development-status-and-remaining-evidence)
before making release, deployment, continuous-monitoring, or production-readiness
claims.
