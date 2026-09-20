# MEGALODON Documentation Wiki

MEGALODON is a local-first defensive network telemetry MVP. It accepts bounded
metadata, applies fixed deterministic rules, records a private SQLite audit
trail, and presents qualified evidence in a read-only loopback HUD.

This Wiki is a practical guide, not a second specification. The repository's
versioned [README](../../README.md), [specification](../../SPECIFICATION.md),
[security review](../../SECURITY_REVIEW.md), source, and tests remain
authoritative.

## Start here

- [Quick start](quick-start.md) - open an existing checkout without data, or follow the optional synthetic walkthrough
- [Operator guide](operator-guide.md) - read Home, Traffic, Findings, Apps, Reports, Evidence, and Help correctly
- [Security boundaries](security-boundaries.md) - understand the controls that must remain true
- [Integrations and Qwen](integrations-and-qwen.md) - distinguish a documented app, an evidence adapter, and an advisory model
- [Development and validation](development-and-validation.md) - make and verify a narrow change
- [Roadmap and current limits](roadmap-and-limits.md) - see what is delivered, still gated, or explicitly unsupported

## Current product snapshot

| Area | Current boundary |
| --- | --- |
| Inputs | Finite sample metadata, bounded JSONL replay, and optional explicit Linux Scapy capture |
| Detection | Three fixed metadata heuristics: `SYN_FLOOD`, `PORT_SCAN`, and `DNS_TUNNELING` |
| Storage | Private schema-v3 SQLite audit store with explicit migration, backup, and restore-to-new-destination commands |
| HUD | Read-only `127.0.0.1` interface with qualified traffic history, findings, app guidance, local JSON reports, and separate evidence views |
| Offline evidence | Linux-only TShark and Zeek analysis, plus closed Suricata file/store workflows under separate contracts |
| Integrations | A static 14-tool capability and workflow map; no general runner, installer, scheduler, or sensor manager |
| Response | Reviewable nftables plans only; every retained live-apply path refuses before host interaction |
| Local AI | Optional bounded Qwen explanation through literal loopback; no detection, evidence, tool, or action authority |

## Read status words literally

- **Unavailable** means no usable evidence was admitted.
- **Unknown** means the admitted evidence cannot answer the question.
- **Degraded** means some evidence is limited or incomplete.
- **Stale** means a saved view is old or a refresh failed.

None of these states means the network is safe, compromised, fully observed, or
being protected in real time.

## Evidence basis

Current alignment: [2026-09-20 source and document record](../document-alignment-2026-09-20.md),
based on `main@4c1d685` plus preserved local setup work. The original full-page
review was at `main@5ac382d` on 2026-09-19. Later source changes and dated
receipts remain distinct from a release or operational acceptance.

Wiki content is generated from `docs/wiki/`. The native GitHub Wiki is a public
projection of those reviewed source files, not an independent authority.
