# Integrations and Local Qwen

MEGALODON owns the evidence model, receipts, local reports, and browser surface. Companion tools are bounded evidence sources, not embedded control consoles.

## Closed workflow map

`megalodon hub-plan` describes supported relationships without probing, installing, launching, networking, mutating storage, or changing the host.

Current workflow positions include:

- Core Python and SQLite metadata intake.
- Optional fixed-argument offline TShark metadata analysis.
- Optional closed Zeek connection-log import.
- Suricata contracts only; no runtime importer or sensor.
- Optional Scapy metadata capture under its separate boundary.
- nftables planning only; live application refused.
- Manual ClamAV companion; no file/scan integration.
- Proposed osquery, Nmap, OSSEC, Greenbone, Zabbix, and Nagios relationships with no general runner.

Adding a utility requires a capability status, one closed workflow, explicit input/output contracts, data and action boundaries, negative tests, and separate approval for any egress, scheduler, privileged action, or remote listener.

## Local Qwen advisory

The optional local-model path is an advisory feature, not an analyst replacement or autonomous defensive agent.

- The provider boundary is the fixed numeric loopback address `127.0.0.1:11434`.
- Application code must explicitly call the library with enablement; there is no CLI, startup call, polling loop, scheduler, or background worker.
- Input is a closed, size-limited projection of already validated local metadata and receipts.
- Outcomes are bounded: `ANSWER`, `ABSTAIN`, `DENY`, or `ERROR`.
- The model cannot create evidence or detections, invoke tools, write the database, launch a process, inspect traffic, change the firewall, quarantine files, or remediate a host.

See the [integration hub contract](../integration-hub.md) and [local Qwen advisory contract](../local-model-advisory-contract.md).
