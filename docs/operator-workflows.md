# Operator workflow index

Status: **IMPLEMENTED DOCUMENTATION INDEX; NO NEW RUNTIME OR OPERATIONAL
AUTHORITY.** This page adds no installation, data access, sensor, response,
release, or operational authority. Follow the linked document for the complete
limits and current acceptance state of each workflow.

## Local dashboard

**Authority:** [local PC setup](local-pc-setup.md),
[visual HUD and companion setup](hud-workflow.md), and
[dashboard operations](dashboard-operations.md).

The documented user install starts with `./scripts/install-local.sh`; a
temporary reviewed-checkout launch uses `./scripts/start-local.sh`. The local
loopback HUD can open before evidence exists and reads configured stores through
bounded, read-only projections.

The HUD's **Your next step** recommends an inspection path from current local
observations. **Review findings**, **Explore connections** and **Open reports**
open existing views; status refresh/resume controls affect display polling.
Returned sensor alert context routes to the connection lens, separate from the
saved Findings queue. Sensor summaries need not require packet capture to be
running. Unknown, stale and empty states retain their coverage limits.

Setup groups controls into **Overview**, **Traffic**, **Local AI**, **Apps**,
**Storage** and **Advanced**. Read the [GUI quick start](gui-quick-start.md) for
current category paths, optional tool disclosure and manual **Evidence →
Reference Library** lookup. AI is optional for inspecting facts and reports.

Opening a browser view does not authorize collection. A running installed HUD
can resume collectors from saved monitoring settings, and its fixed companion
worker has separate local defaults. Inspect [background workflows](background-tools.md)
and [local startup](local-pc-setup.md) before launch. A listener or readable file
does not prove source health, coverage or safety. The hosted Site does not read
the local HUD or its stores.

## Background startup and host review

Use [login startup](local-pc-setup.md#optional-start-the-installed-hud-at-login)
for the installed user service. Review [Lynis/AIDE and threat context](host-security.md)
for explicit host checks, and [model selection](local-model-selection.md) for
local advice. Service startup, saved collector preferences, tool presence,
accepted evidence and model qualification remain separate states.

## Bounded JSONL replay

**Authority:** [README event input](../README.md#event-input) and
[platform baseline](platform-baseline.md).

The documented example entry point is
`python -m megalodon run --source jsonl --input examples/events.jsonl --max-events 100`.
The implemented core path validates bounded metadata and records accepted
events, detection links, decisions, and terminal run evidence in the configured
audit store.

Replay does not capture live traffic, authenticate the input source, establish
complete network coverage, authorize a response, or prove detector accuracy.

## Saved capture

**Authority:** [offline metadata analysis](offline-analysis.md).

The documented entry point is
`python -m megalodon.offline --source tshark ...` with explicit private input
and new output paths. The implemented optional Linux adapter analyzes one
authorized saved PCAP or PCAPNG with fixed TShark and finite record, time, and
output limits, then writes private redacted reports.

This path does not perform live capture, replay packets, publish payloads,
write the core audit store, or grant authority to analyze a capture. Installed
tool compatibility and operational containment remain separate evidence.

## Suricata review

This section describes the separately selected startup snapshot, not the HUD's
recent live sensor context or managed alert-intake workflow. See
[background tools](background-tools.md) for those current source distinctions.

**Authority:** [dashboard operations](dashboard-operations.md#inspect-separately-stored-suricata-evidence)
and the [Suricata evidence projection](suricata-evidence-projection.md).

The documented entry point is
`megalodon dashboard --suricata-db /absolute/private/suricata.db`. The local
dashboard takes one bounded, immutable, read-only startup snapshot from an
explicitly selected compatible private consumer store.

The snapshot does not poll or start a sensor, ingest EVE, write or repair the
store, establish sensor health, turn an external alert into a MEGALODON
detection, or authorize a response. Restarting is required to select a newer
snapshot.

## Integration plans

**Authority:** [integration hub contract](integration-hub.md).

The documented entry point is `python -m megalodon hub-plan --platform linux`.
The implemented command reads the repository's static capability catalog and
closed workflow definitions, then prints a machine-readable plan.

A plan does not probe the host, find executables, install packages, start
services, make network requests, change a firewall, apply an integration, prove
compatibility, or grant production approval.
