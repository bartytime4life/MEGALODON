# Integrations and Local Qwen

MEGALODON owns the evidence model, receipts, local reports, and browser surface. Companion tools are bounded evidence sources, not embedded control consoles.

## Closed workflow map

`megalodon hub-plan` describes supported relationships without probing, installing, launching, networking, mutating storage, or changing the host.

Current workflow positions include:

- Core Python and SQLite metadata intake.
- Optional fixed-argument offline TShark metadata analysis.
- Optional closed Zeek connection-log import.
- Single-threaded Linux main-thread Suricata intake for one checksum-bound 8.0.7
  alert-only EVE file or one completed contract-envelope file, an explicit
  atomic transaction into one pre-created private store, and explicit read-only
  unknown-commit reconciliation; no mixed firehose, watcher, sensor, or IPS. A
  separate optional local-dashboard startup snapshot is available through
  `dashboard --suricata-db`; it never invokes the consumer.
- Optional Scapy metadata capture under its separate boundary.
- nftables planning only; live application refused.
- Manual ClamAV companion; no file/scan integration.
- Bounded offline STIX 2.1 completed-file reader, delivered by merged PR #269;
  immutable context only, with no TAXII fetch, persistence, pattern execution,
  detection, attribution, model, or action authority. ECS/OCSF projection and
  the zero-attempt SOAR handoff remain contract-only.
- Proposed osquery, Nmap, OSSEC, Greenbone, Zabbix, and Nagios relationships with no general runner.

Adding a utility requires a capability status, one closed workflow, explicit input/output contracts, data and action boundaries, negative tests, and separate approval for any egress, scheduler, privileged action, or remote listener.

## Local Qwen advisory

The optional local-model path is an advisory feature, not an analyst replacement or autonomous defensive agent.

- The provider boundary is the fixed numeric loopback address `127.0.0.1:11434`.
- The original run-count policy is an explicitly enabled library API. The separately versioned offline anomaly command can request one Qwen explanation with opt-in flags. Neither path starts a provider, polls it, schedules work or runs a background worker. See the [anomaly command](https://github.com/bartytime4life/MEGALODON/blob/0e71cd41627fe2d2bffde7c2ddd222b475f73bc1/docs/anomaly-triage.md).
- Input is a closed, size-limited projection of already validated local metadata and receipts.
- Outcomes are bounded: `ANSWER`, `ABSTAIN`, `DENY`, or `ERROR`.
- MEGALODON does not route model output into evidence, detections, tools, database writes, process launches, capture, firewall changes, quarantine or remediation. These application controls do not sandbox the separately operated Ollama/model process; provider filesystem access, egress and loaded-artifact identity require separate proof.

See the [integration hub contract](../integration-hub.md) and [local Qwen advisory contract](../local-model-advisory-contract.md).
