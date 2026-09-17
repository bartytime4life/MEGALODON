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

## Control-room presentation (second draft slice)

Home, Traffic, Findings, Apps, Reports, Evidence and Help share one anchored,
keyboard-operable shell. A persistent Back to Main HUD link returns to Home.
The old audit inspector is explicitly separate in Evidence because it can
contain sample/unlinked rows. It is never the source of traffic visuals.

All traffic panels share a browser-only UTC time filter (maximum 31 days) over
one bounded `/api/traffic` response. Every panel includes range, source, unknown
vantage, fetch time, unit and quality. Counts describe returned metadata;
bytes use exact integers. Top lists are limited to ten entries (flows eight).
Empty bins do not prove absence of traffic. Direction, local network identity,
connection state, observed service identities, drops and clock accuracy remain
unavailable. Stale refreshes preserve the prior view with an explicit warning.
The default recorded window is historical, never a live capture claim.

The Reports tab is reserved for the subsequent reviewed export slice. Native
browser acceptance uses synthetic fixtures only; those fixtures never enter
production charts or the hosted reference console. Accessibility checks do not
by themselves certify WCAG conformance or a physical screen-reader experience.


## App capability truth matrix (third reviewed slice)

The Apps view keeps four different claims separate for every supported tool.
**Presence** is only the startup PATH observation returned by the bounded
readiness snapshot: green means an executable candidate was found, red means
none was found on the checked PATH, and gray means presence was not checked.
None of those states proves package installation, version compatibility,
configuration, usability, process state or health.

**MEGALODON support** describes whether the static integration profile has a
documented command contract. **Administration** remains external because the
HUD cannot install, update, remove or configure companion applications.
**Health** remains unverified because the HUD does not start, stop, attach to or
probe their processes or services. These rows must not be collapsed into one
overall readiness badge.

Operator console links are browser-only destinations. They open in a new tab so
the loopback HUD remains the stable return point; URL preferences stay in local
browser storage. The HUD never embeds a remote console, executes a package
manager, or converts roadmap text into runtime authority.
