# Local command center: operator and acceptance runbook

Status: read-only dashboard behavior and a manually loaded **static Integration
Map**. This guide does not authorize a deployment, remote listener, service,
capture, analyzer installation, or response action. See the
[HTTP contract](dashboard-http-contract.md) for exact request semantics and the
[integration hub contract](integration-hub.md) for workflow ownership.

## Read the interface in evidence order

The overview and trust strip lead into stored counters and detection triage.
Reference context follows triage instead of pushing the primary review task below
large lookup forms. Section navigation moves directly to overview, triage,
Reference Library, offline snapshot, and Integration Map. Navigation does not
change filters, fetch external data, or start an analysis.

There are four distinct read models. Do not combine their meanings:

| Surface | What it represents | What it does not prove |
| --- | --- | --- |
| Stored telemetry and triage | The current successful read of bounded stored metadata/detections | Current capture, ingestion, endpoint health, or incident uniqueness |
| Offline snapshot | One explicitly selected, validated report projection loaded at startup | A live analyzer connection or automatically refreshed run |
| Reference Library | Manual registration context from the installed verified IANA bundle | Observed protocol identity, endpoint safety, or maliciousness |
| Integration Map | Repository-defined capabilities, workflow contracts, and next gates for one profile | Installed programs, live connections, active sensors, or platform acceptance |

The high/critical counter compares sequential stored counts. An increase is not a
unique new incident; a decrease is not proof that a threat was remediated. The
bounded detection list can omit older rows. Search, severity, rule, and timeline
filters apply only to the returned view, not the entire history.

## Operate the Integration Map

Choose **Linux**, **Windows evaluation**, or **Other platforms**, then select
**Load integration map**. This makes one same-origin GET for static repository
constants. It does not discover executables, inspect devices, resolve hosts,
probe versions, install software, launch an adapter, or write to SQLite.

The profile selector is an explicit documentation choice, not operating-system
detection. Each successful map contains the eight closed hub workflows. Cards
show software, documented availability, input, output, and the next acceptance
gate. Expand a card to inspect its workflow ID, source kind, implementation
owner, launch policy, data boundary, action boundary, and inert command template.
A command displayed as text is not an executable control or a complete install
instruction for the selected profile.

Search filters at most eight cards in memory. The availability filter narrows
that same map. **Clear map filters** restores the full loaded map without another
request. A zero-result filter is explicitly different from a failed map load.
No filters are written to disk, local storage, the URL, or an external service.

Changing the selected profile does not relabel previously loaded cards. Until a
new load succeeds, the header identifies the last loaded profile and the status
message identifies the unfulfilled selection. A malformed or wrong-profile
response is not partly applied. After a failure, a prior map remains visible as
**stale**; without a prior map, the panel says unavailable. A failed map request
does not stop telemetry polling or destroy an offline snapshot.

### Filtering during a load or after failure

Search, availability filtering, and **Clear map filters** remain local operations
while a map request is pending. They must retain the loading message and the
profile captured when that request was dispatched. The loaded-profile label and
cards continue to describe the previous accepted map, not the pending profile.
The load button and profile selector remain disabled until that request settles;
filtering does not start another request.

A first-load failure remains **unavailable** after search, filter, clear, or
profile-selection changes. Those controls cannot turn failure into an ordinary
empty result. With a previous map, failure remains **stale**. A retry can display
both its pending request and the previous failure; only a validated successful
response clears the failure. When the request settles, the busy flag, disabled
controls, and status message are updated together so no completed load retains a
loading announcement.

The regression suite in
[`tests/test_integration_map_states.py`](../tests/test_integration_map_states.py)
executes the complete Integration Map JavaScript with synthetic DOM and request
promises. For rendered acceptance, repeat the filter/search/clear sequence during
a delayed first load and a delayed profile change, then after a failed first load.
Confirm both the visible message and the `aria-live` status remain truthful. A
component-only browser harness does not establish full-dashboard, real HTTP/CSP,
SQLite, assistive-technology, or native-platform acceptance.

Availability words are deliberately narrow:

- **Implemented/optional** describe a repository path, not an installed or running
  component. In particular, optional nftables support remains inert planning.
- **Evaluation only/guest only** preserve unproved or non-native platform status.
  They must not be promoted by a successful Linux test or by installing a tool.
- **Contract only/manual only/proposed/unsupported** remain non-runtime or limited
  relationships. Suricata has no runtime importer in this map; ClamAV is a manual
  companion; osquery remains proposed.

## Recognize unavailable, paused, and stale data

A successful API fetch updates the last-success time. That time is not the age
of every record and not a sensor heartbeat. Pausing automatic refresh preserves
data and marks it paused. Resuming changes the surface to checking until a
complete refresh succeeds. A failed refresh preserves the last successful view
as stale rather than replacing it with zeros or presenting old rows as current.

The reference snapshot has its own ready, no-match, unavailable, integrity-failure,
and stale-result states. An integrity failure must not fall back to partially
loaded registrations. A no-match lookup is context absence, not a security
verdict. The offline panel is independently not selected or unavailable; neither
state means that SQLite telemetry is empty.

Keep screenshots and operational notes explicit about which surface failed and
which last-success time applies. Avoid a single green "all systems healthy"
badge when only the dashboard HTTP endpoint has responded.

## Safe local acceptance procedure

Use a private, disposable synthetic dataset and the existing CLI documented in
[README](../README.md). Bind to numeric IPv4 loopback or `localhost` only. Do not
use a public tunnel, reverse proxy, remote address, or the refused legacy remote
flag to make an acceptance test convenient. Do not reuse a production database.

Record the application commit, Python/Node/browser versions, OS, viewport,
synthetic fixture identity, and relevant configuration. Verify the displayed
scope matches the configured event limit. Confirm the table still exposes only
the five public detection fields; do not attach raw evidence or private paths.

Exercise the following sequence without starting a real tool:

1. Load the dashboard, navigate by keyboard, apply and clear triage filters, pause
   and resume refresh, and inspect the last-success and returned-row messages.
2. Load all three integration profiles; search for a tool, select contract-only,
   create zero results, clear filters, and expand card boundaries. Confirm a
   pending profile choice never silently changes the loaded profile label.
3. Simulate an unavailable or malformed API response in a controlled harness.
   Confirm stale preservation, first-load unavailability, finite retry behavior,
   one in-flight map load, and recovery. Check reference and telemetry failures
   independently rather than treating one successful route as whole-app health.
4. At desktop and narrow mobile widths, verify no document-wide horizontal
   overflow, readable wrapped contract text, operable controls, and visible
   keyboard focus. Test reduced motion, zoom, forced colors, and a screen reader
   separately; automated layout checks are not a conformance certificate.

Capture only synthetic, public-safe screenshots. For the real storage acceptance
work, record read-only database access and concurrent-writer behavior separately.
Do not infer them from a fake reader, a Node DOM harness, or static asset tests.
Native Windows, installed TShark, independent review, resource exhaustion, and
release acceptance remain separate evidence gates.

## Troubleshooting without weakening the boundary

| Symptom | Interpretation | Safe next action |
| --- | --- | --- |
| Integration Map unavailable, telemetry works | The static-map request or contract failed independently | Retry once; inspect the local status and exact build/test evidence; do not enable a tool |
| Previous profile still shown | New selection is not successfully loaded | Read the loaded-profile label and load the selected profile |
| No cards match | In-memory filters excluded all documented workflows | Clear map filters |
| API request returns 400 | Invalid Host, request target, or query | Use the direct loopback URL and documented canonical arguments; do not remove validation |
| Reference integrity failure | The installed reference bundle failed its verification boundary | Diagnose or reinstall a verified package through the existing operator process; never bypass the manifest |
| Telemetry unavailable or stale | A successful current read is missing | Preserve the last-success evidence; inspect private local configuration/storage separately |

## What this interface deliberately does not do

There are no launch/install/connect buttons, credential fields, generic plugin
loader, arbitrary endpoint, external dashboard iframe, notification delivery,
alert acknowledgement, remote control, or live remediation. The durable alert
lifecycle/outbox design remains separate from the stored priority counter. A
future real connector must first supply its own versioned input contract, bounded
reader, privacy and completeness semantics, ownership, tests, and review. Adding
a card is not source admission or permission to execute its entry point.
