# MEGALODON Documentation Wiki

MEGALODON is a local-first, metadata-only network-defense MVP. It accepts tightly bounded observations, produces deterministic detections, records local audit evidence, and offers a read-only dashboard on loopback.

This guide is a navigational layer. The repository's versioned [specification](../../SPECIFICATION.md), [security review](../../SECURITY_REVIEW.md), source, and tests remain authoritative.

## Start here

- [Quick start](quick-start.md) - synthetic local run and dashboard
- [Security boundaries](security-boundaries.md) - non-negotiable safety controls
- [Operator guide](operator-guide.md) - evidence reading and dashboard use
- [Integrations and Qwen](integrations-and-qwen.md) - closed workflow map and advisory boundary
- [Development and validation](development-and-validation.md) - contributor workflow
- [Roadmap and current limits](roadmap-and-limits.md) - gates before broader use

## Product in one minute

| Area | Current direction |
| --- | --- |
| Evidence | Bounded metadata, provenance, deterministic receipts |
| Storage | Private local SQLite audit trail |
| Interface | Read-only numeric-loopback dashboard |
| Integrations | Closed workflow map; no general runner or scheduler |
| Response | Plan-only; live firewall application is refused |
| Local AI | Optional bounded advisory with no action authority |

## Evidence basis

Initial content was reconciled against `main` at [ad35e0ada03a4c57923d8c0e956e8ff3b295f168](https://github.com/bartytime4life/MEGALODON/commit/ad35e0ada03a4c57923d8c0e956e8ff3b295f168) on 2026-09-15 UTC. It does not replace current source, checks, or independent review.

Integration and roadmap status was refreshed on 2026-09-17 against
[`77f082a`](https://github.com/bartytime4life/MEGALODON/commit/77f082a0548e64f97090c94dd11503a68ca05d99).
See the [document reconciliation](https://github.com/bartytime4life/MEGALODON/blob/main/docs/document-alignment-2026-09-17.md)
for source authority, historical checkpoints, and remaining gates. Wiki source
changes become published Wiki content through the main-branch workflow.
