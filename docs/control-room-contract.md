# Local control room contract

## Repository basis and evidence

OBSERVED initial main: `4971d85a2c56d932fda9053873a42985b4233371`, tree
`efcb8f4e2d1d857196da8976503765f861e463b5` (2026-09-17).
The current mission authorizes read-only HUD improvements, draft branches and
the existing private reference Site. It does not authorize a merge or runtime
release. Attached roadmaps are planning inputs, never runtime authority.

## Traffic projection v1

`GET /api/traffic` takes no parameters. The CLI uses `TrafficDashboardStore`,
a subclass of the existing private, query-only, descriptor-pinned reader. Its
closed authorizer adds only named event metadata, detector IDs and run links;
the older five-field `/api/events` route is unchanged. One SQL statement gives
the newest 501 event candidates and 201 finding candidates a common snapshot;
only 500/200 can be published and an extra candidate signals truncation.
The existing one-second/one-million-instruction cooperative query budget and
250 ms lock/busy budgets cover fetching and projection. The JSON ceiling is
256 KiB. Budgets cannot interrupt a stalled filesystem.

Sample, unlinked, legacy-receipt and reconciliation-required event candidates
are excluded. Findings require an accepted event link and one of the three
fixed detector IDs. JSONL/scapy source is recorded provenance, not independent
authentication of a sensor or operator input. Unknown source quality cannot
become a clean-network verdict. No traffic is generated to fill a chart.

Responses include normalized IPs, ports, flags, closed protocol labels,
reported byte counts as exact decimal strings, source/run/record IDs and
termination state. Stored text is byte-bounded in SQLite before decoding.
Messages, evidence JSON, recommendations, metadata JSON, interface strings,
raw logs, packet bodies and model output are not selected. Malformed selected
metadata fails the complete projection; no partial valid prefix is returned.
Missing stores return a fixed 503 unavailable envelope, never zero counters.

Vantage, local-subnet scope, direction, connection state, producer/detector
versions, drops, rejected-record counts, clock accuracy and whole-network
completeness remain UNKNOWN because this store lacks the required provenance.
The reader reports a digest of its own source component, package version and
development base; it does not invent the installed checkout commit.

## Acceptance boundaries

Synthetic tests exercise the real writer/reader/HTTP boundary but are never
published as real telemetry. Native source authenticity, installed-tool
qualification, human accessibility acceptance and independent security review
remain separate gates. The hosted Site receives no local feed, record,
identifier, model output, health state, bookmark or report.
