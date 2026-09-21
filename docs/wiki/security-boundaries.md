# Security Boundaries

MEGALODON is evidence and decision support, not autonomous host control. The
following controls are product boundaries, not optional setup advice.

## Defaults that must remain true

- **Observe only.** Installation does not activate a service, scheduler, sensor, model, or firewall mutation.
- **Metadata only.** Packet payloads, payload-derived hashes, credentials, raw bodies, and arbitrary protocol trees do not enter core events, reports, prompts, or dashboards.
- **Closed and bounded inputs.** Every admitted source has a typed schema, quotas, provenance fields, and explicit rejection behavior.
- **Local telemetry reads.** The server binds to numeric loopback and reads an existing compatible core store through a constrained SQLite path. Core telemetry routes are read-only. The separately enabled, token-gated AI question POST writes only its private AI receipt ledger and bounded report snapshots; it has no firewall apply route.
- **No untrusted control plane.** Events, prompts, documents, model text, and browser fields cannot select arbitrary executables, arguments, SQL, credentials, endpoints, or actions.
- **Evidence is not proof.** A finding, signature alert, severity, registration, recommendation, or process observation does not authorize a response.
- **Fail closed.** Ambiguous identity, provenance, privacy, authority, schema, storage, or resource state is unavailable rather than partially accepted.

## Data and storage

The core audit store is private local SQLite. Supported writers use atomic
transactions and a finite high-water stop. Dashboard reads are separate,
least-data projections; a healthy HTTP response does not prove ingestion or
capture health.

Backup and restore are explicit operator commands. They use SQLite's online
backup API, new destinations, bounded manifests, and integrity checks. A restored
database is not automatically activated, and incomplete artifacts are preserved
for review rather than silently deleted.

## Network and browser boundary

Core telemetry, reference lookup, reports, and static integration maps have no
cloud upload path. The optional Qwen adapter can make one explicitly enabled,
bounded request only to literal `127.0.0.1:11434`; the separately operated model
provider still requires its own containment evidence.

The Apps viewer is an explicit browser navigation to a saved companion-console
URL. The frame or externally opened application may use the network and retains
its own permissions. MEGALODON does not proxy it, inspect its content, test the
connection, or treat a load event as success. Never place credentials in a saved
URL.

## Response boundary

Firewall output is plan-only. Retained `--apply` flags refuse before
configuration, executable lookup, privilege checks, process creation, or host
mutation. A plan, stored action record, Suricata `blocked` observation, or model
recommendation is not proof that MEGALODON changed the host.

## External evidence and AI

Offline TShark, Zeek, Suricata, STIX, SIEM projections, and Qwen each have
separate contracts. Catalog presence does not connect a data source. Qwen output
cannot become a finding, audit fact, command, tool call, database write, or
response action. Model denial or failure must preserve the deterministic
evidence independently.

## When to stop

Stop rather than weaken a control when the selected source, operator authority,
data sensitivity, filesystem ownership, model identity, installed-tool version,
or requested action is unclear. Passing tests and green CI are evidence about a
revision, not deployment approval.

Read the complete [security review](../../SECURITY_REVIEW.md) and [MVP safety
invariants](../../SPECIFICATION.md#2-safety-invariants) before changing these
boundaries.
