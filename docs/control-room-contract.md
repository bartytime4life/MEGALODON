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
Missing, unsafe or unreadable stores return a fixed, complete 503 unavailable
envelope, never zero counters. The browser validates that closed envelope before
showing **Connected · read-only** separately from unavailable data coverage. A
malformed response or transport failure marks the local service unavailable and
preserves any prior valid snapshot as stale; it cannot become an empty or healthy
view. UTC timestamps must be real calendar instants, not values that JavaScript
silently normalizes (for example, 31 April).

Vantage, local-subnet scope, direction, connection state, producer/detector
versions, drops, rejected-record counts, clock accuracy and whole-network
completeness remain UNKNOWN because this store lacks the required provenance.
The reader reports a digest of its own source component, package version and
development base; it does not invent the installed checkout commit.

## Acceptance boundaries

Synthetic tests exercise the real writer/reader/HTTP boundary but are never
published as real telemetry. Native source authenticity, installed-tool
qualification, human accessibility acceptance and independent security review
remain separate gates. The hosted Site has no automatic local feed. It accepts explicitly selected
aggregate-only HUD summaries and readiness self-reports in page memory; these
are unauthenticated saved data, not a live connection. Raw traffic records,
addresses and model output are excluded from that summary contract.

## Control-room presentation (second draft slice)

HUD, Findings, Sensors, Setup, Reports, Evidence and Help share one anchored,
keyboard-operable shell. A persistent **Return to visual HUD** link returns to the HUD tab.
The old audit inspector is explicitly separate in Evidence because it can
contain sample/unlinked rows. It is never the source of traffic visuals.

The visual HUD contains the traffic and finding charts; its activity detail and
Findings retain detailed tables. The rolling-hour globe has its own selected minute.
The other traffic panels share a UTC range (maximum 31 days). Recorded window and
Now use the bounded `/api/traffic` response. Last hour, Today and Custom UTC
read database history through `/api/traffic-history`. Every panel includes range, source, unknown
vantage, fetch time, unit and quality. Counts describe returned metadata;
bytes use exact integers. Top lists are limited to ten entries (flows eight).
Empty bins do not prove absence of traffic. Direction, local network identity,
connection state, observed service identities, drops and clock accuracy remain
unavailable. Stale refreshes preserve the prior view with an explicit warning.
The default recorded window is historical, never a live capture claim.

The Reports tab is activated only by the fourth reviewed slice below. Native
browser acceptance uses synthetic fixtures only; those fixtures never enter
production charts or the hosted reference console. Accessibility checks do not
by themselves certify WCAG conformance or a physical screen-reader experience.


## Qualified finding evidence inspector

The Findings view offers an explicit inspection step for findings admitted by
the closed traffic-v1 projection. It joins the selected finding to its already
validated event and ingestion run. It does not read additional records, run a
detector, or infer incident severity beyond the stored label. A linked event is
not the full evidence window that caused the detector to fire.

Observation time, detection time, and projection generation time remain
separate. The displayed time range is a browsing filter, not a detector window.
Historical detector version and evaluation-window provenance remain unknown;
the current package version and current rule thresholds cannot fill those gaps.
Run status describes a recorded ingestion attempt, not a running process.
JSONL provenance identifies operator-supplied input, not authenticated capture.

The inspector keeps an unchanged selection and its controls stable during
refresh. A failed read preserves admitted metadata with an explicit stale
warning. A selection no longer present in the selected range or page becomes
unavailable; it is not silently rebound to another event. Managed history-v2
uses separate evidence references and clears the traffic-v1 inspector.

Fixed links lead to ingestion receipts, retained evidence, and Reports. They
browse those existing views; they do not select a matching receipt, generate a
report, start tools, or authorize any operation. The hosted Site remains an
aggregate-only saved-summary viewer and does not receive these event/run IDs.

This slice follows the Sensors activity overview delivered in PR #653. Three
opportunities were compared against the main tree at `4dc08723aa52eb92ba88f4847affcf9089e8021c`:

| Priority | Opportunity | Value and available data | Effort / security / cost |
| --- | --- | --- | --- |
| 1 | Qualified finding inspector | Completes finding-to-source review using existing validated links | Small read-only UI slice; bounded at 200 findings / 500 events; no dependencies or paid service |
| 2 | Independent source-state matrix | Clarifies installation, configuration, process and data freshness; #653 already supplies activity summaries | Requires reconciliation of differently timed snapshots; avoid one misleading health verdict |
| 3 | Unified saved-results desk | Makes tool results and receipts easier to find | Requires distinct identity and retention contracts; larger normalization and paging work |

Synthetic browser acceptance captures the unselected and selected candidate at
desktop and narrow widths. These are candidate interaction states, not a
before/after comparison with a deployed release. Screenshots, DOM assertions,
keyboard checks, and screen-reader acceptance are distinct evidence. No full
WCAG conformance or installed-host acceptance is implied.

## App capability truth matrix (third reviewed slice)

The Apps view keeps four different claims separate for every supported tool.
**Presence** in the Apps matrix is the startup PATH observation returned by the
bounded readiness snapshot. Home's **Check this computer** and software list
show separately timestamped, explicitly refreshed observations. In the matrix,
green means an executable candidate was found, red means
none was found on the checked PATH, and gray means presence was not checked.
None of those states proves package installation, version compatibility,
configuration, usability, process state or health.

**MEGALODON support** describes whether the static integration profile has a
documented command contract. **Administration** defaults to observation mode. A separately enabled non-root
Linux launch can run fixed install/start recipes with a per-launch operator
token and confirmation; update, removal and vendor configuration stay external.
See [tool management](tool-heartbeat.md).
**Health** remains unverified: process-name observation does not start, stop,
attach to, or request a response from a companion service. These rows must not be collapsed into one
overall readiness badge.

Operator console links are browser-only destinations. The local HUD's App viewer
loads one chosen console in a sandboxed HTTP(S) frame only after **View in HUD**.
Saving a link and loading the Apps map do not contact it. Every tool has a viewer
entry; tools without native web UIs show an explanation and accept a separately
configured viewer URL. Native desktop windows cannot be embedded directly.
Reload/close controls and an external-open link remain visible. Browser frame
restrictions and login requirements are respected; the HUD does not proxy a
console or claim it loaded successfully. URL preferences stay in local storage.
The hosted Site still opens consoles externally and receives no telemetry.

## Historical activity and refresh

`GET /api/traffic-history` requires `start` and `end` UTC ISO instants with a
maximum 31-day span and an end no later than one minute beyond server time. Its
optional canonical positive `before` event ID is exclusive. The existing UTC
writer representation and time index support the range query. Parameters are
bound; unknown, repeated or malformed fields are refused. Existing read-only
storage, query budgets and the 256 KiB response ceiling apply.

Each page selects up to 501 event candidates and 201 findings linked to its first
500 event candidates in one SQL snapshot. Published limits remain 500/200.
`candidate_count` and `next_before` expose candidate paging even if every row was
excluded. Ordering is by event ID, so out-of-order producer timestamps and newer
inserts do not shift an older-page cursor. The view is not a multi-page immutable
snapshot: retention and changed run receipts can affect later reads. Empty pages
and exhausted candidates do not establish no network activity. Expensive range
queries can fail their budget; narrow the range when necessary.

History pages remain fixed until refresh or navigation. Automatic latest polling
cannot overwrite the reviewed page. Activity detail lists every qualified event
in that page; reports summarize that same page. Failed reads preserve the prior
page with an explicit stale label. Range and cursor envelopes are validated in
the browser before a page is applied.

Latest polling shares one bounded traffic request between the HUD and the legacy
audit view. Concurrent manual reads of the same path share the in-flight request.
The persistent refresh/pause controls show the interval and separate fetch time
from latest observation time. Visibility suspends automatic polling; no sensor
is started. The HUD does not claim sensor liveness, link throughput, a complete
network map or distributed sensor aggregation.



## Bounded local report (fourth reviewed slice)

Reports are created only after an operator presses **Preview local report**.
The browser derives one closed `megalodon-local-report-v1` document from the
already validated traffic snapshot and the currently selected UTC range. An
empty selection is unavailable, not a zero-activity report.

The preview and downloaded JSON contain counts, exact reported-byte totals,
source labels, finding rule/severity aggregates, fixed limitations, range and
projection-build evidence. They omit addresses, ports, event/finding/run IDs,
packet bodies, raw logs, messages, recommendations, commands and model output.
The JSON is capped at 64 KiB. The preview is held in browser memory until the
operator creates a replacement, selects **Discard preview**, or leaves the page.
Refreshes and range changes do not alter its bytes or disable its download. A
visible label identifies its creation time, original range and freshness at
creation; it explicitly distinguishes the held preview from the current view.
A failed replacement clears the prior preview rather than presenting it as the
new selection. Discard removes the preview and disables download.

Freshness is assessed when the preview is created, not when it is downloaded.
A failed source refresh, age over five minutes, or generation timestamp more
than one minute in the future produces `stale`. This does not establish sensor
liveness. Browser download failures preserve the preview, expose a fixed retry
message without exception details, and release any created object URL.

Download is a browser `Blob` created only after preview. It does not call a
server endpoint, write through the MEGALODON process, upload data, send
telemetry or grant package/process/firewall/model authority. Browser acceptance
confirms that the downloaded bytes match the preview and that preview/download
make no page request; it is not OS-level egress containment or release approval.


## Automatic address case overview

The local Findings workspace assembles a case overview from the already validated
traffic projection and its shared time range. It initially selects the source
address of the first linked finding, or the first event source when no finding
is present. Advanced exposes the address selector. An address is not a verified
host identity, and shared-address grouping does not establish a single incident.

The summary and observation-ordered timeline update with the returned snapshot.
Finding buttons open the existing finding/event/run inspector. The view makes
no additional requests or writes and does not infer a learned baseline. It
shows at most 100 matching event rows and labels that display limit separately
from projection truncation and page-wide excluded candidates. Counts describe
only the admitted returned set; sensor liveness, loss and completeness remain
unknown. A missing selected address stays selected and is reported absent,
never silently replaced. Stale snapshots retain a visible stale label. Managed
history uses different references and clears this case view rather than mixing
records between projections.

This first integration does not persist case notes, export a case package, run
an AI model, or operate the host. Flight Lab remains a separate synthetic
prototype; its session notebook is not an installed-dashboard capability.
