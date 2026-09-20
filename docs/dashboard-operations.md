# Local command center: operator and acceptance runbook

Status: read-only dashboard behavior and a same-origin **static Integration
Map**. This guide does not authorize a deployment, remote listener, service,
capture, analyzer installation, or response action. See the
[HTTP contract](dashboard-http-contract.md) for exact request semantics and the
[integration hub contract](integration-hub.md) for workflow ownership.

## Open the HUD

Run `python -m megalodon hud` from the installed environment and open
`http://127.0.0.1:8787` on that computer. There is no local cloud login or
subscription. Companion installations and a configuration file are optional.
The default store is `data/megalodon.db`, relative to the launch directory;
use the same working directory/configuration as your ingestion workflow.
An absent store opens an unconfigured workspace instead of creating a database
or sample data. The source notice explains the missing input; measurements
remain unavailable. Unsafe or invalid existing data is still refused.

Tool presence is checked once at launch, with no executable run, version probe
or service connection. Restart to recheck. Readiness describes the dashboard
process's PATH, not every installed package or other user's environment. The
original `dashboard` command still requires a store and omits tool checks.

The HUD also takes one bounded process-name snapshot at startup. **Executable
found** and **Process observed** are shown as separate facts. Process observation
does not establish service health, configuration, traffic coverage, or a working
integration; standalone tools show **Runtime not applicable**. The receipt omits
process IDs, command lines, paths, users, and host identity. Restart the HUD to
refresh this snapshot.

Use **Tools** to find a tool, open its official setup guide, inspect
copy-only verification/maintenance commands, or save its existing web-console
address once. Saved console links open the companion app in another tab, where
that app retains its own authentication and controls. Desktop-only tools still
use their normal application launcher or the displayed terminal commands.
MEGALODON does not install/start tools or embed their admin interfaces.
Addresses persist only in this browser and origin; the hosted Site and local HUD
have separate bookmarks. Remove a link from its editor. No credentials belong
in a saved address. No background connection test is performed.

On the local Linux dashboard, the Python/SQLite and Scapy maintenance cards
use the absolute Python executable running that dashboard. Copied commands work
from a new terminal without activating a virtual environment. When the package
is loaded from an identified MEGALODON source checkout, its reinstall command
names that checkout explicitly and retains an editable install; review that
checkout before running it. Without an identified checkout, use the original
reviewed package source to reinstall. These command paths are captured at startup
and displayed only in the local command cards. The hosted Site keeps generic
examples, which require activating the intended environment in each terminal.

The home **Choose existing data for the next launch** form prepares a command
for optional settings, completed offline evidence and a Suricata store. Fields
remain in page memory; editing invalidates the previous copy action until the
command is prepared again. Absolute Linux paths are shell-quoted. Stop with
Ctrl+C and run the prepared command; the form itself opens no path. Data ingestion
and sensor operation remain explicit separate workflows.

## Read the interface in evidence order

The command center stays pinned to one browser viewport. Its persistent tabs
switch among three internally scrolling workspaces without reloading the page:
**Overview** reads from top to bottom as data freshness, four stored counters,
bounded recent traffic, local data/tool observations, three common tasks, and
the stored-alert table. The report builder and advanced alert filters stay
collapsed until requested. **Investigate** keeps its Reference Library, offline
snapshot, optional Suricata evidence, and ingestion receipts closed until one
source is opened; the display-only Qwen receipt boundary remains visible at the
top. **Tools** presents every application as a compact row and reveals setup,
console, and data-boundary controls only for the row that is opened.
Switching workspaces preserves local filters and never fetches external data or
starts an analysis.

Existing fragment links continue to select the workspace that owns their target.
This includes live-review/detection, deep-analysis/reference/offline, and
integration-map fragments; browser back/forward fragment changes use the same
closed mapping and never choose an arbitrary selector or route.

The Analysis workspace shows one **Qwen advisory receipt** card. An embedding
caller may supply one already-produced frozen result when starting the server;
the dashboard validates and copies it before listening, then the browser reads
it once. If none is supplied, or the response is invalid, the card says
unavailable and shows no partial model output. This is a display boundary, not
a button, file loader, provider-health claim, or model invocation path. The
separate library-only adapter can still make only one explicitly enabled,
Airlock-admitted request to literal IPv4 loopback. The dashboard cannot start
that call, poll Qwen, inspect raw traffic, run analysis in the background, or
apply a response.

There are six distinct surfaces. Do not combine their meanings:

| Surface | What it represents | What it does not prove |
| --- | --- | --- |
| Stored telemetry and triage | The current successful read of bounded stored metadata/detections | Current capture, ingestion, endpoint health, or incident uniqueness |
| Stored traffic pulse | Up to 500 event candidates qualified by ingestion receipts; unavailable when none qualify | Wire speed, complete network visibility, payload content, or sensor continuity |
| Tool startup status | Separate executable-presence and process-name observations taken when `hud` starts | Package compatibility, configured service health, accepted data, or complete host inventory |
| Offline snapshot | One explicitly selected, validated report projection loaded at startup | A live analyzer connection or automatically refreshed run |
| Reference Library | Manual registration context from the installed verified IANA bundle | Observed protocol identity, endpoint safety, or maliciousness |
| Application interfaces | Fourteen repository-defined capability slots, workflow contracts, and next gates for one profile | Embedded vendor consoles, installed programs, live connections, active sensors, or platform acceptance |
| Qwen advisory receipt | One startup-supplied, validated, display-only bounded result | An installed/reachable model, an invocation control, live traffic analysis, an evidence source, or a response authority |
| Suricata evidence | A bounded startup snapshot from one explicitly selected separate durable store | A live sensor, continuous EVE feed, MEGALODON detection, independent source attestation, or applied response |

The stored traffic projection selects its newest 500 event candidates first,
then at most 200 finding candidates linked to that window. Newer findings for
older events cannot displace findings for the displayed window. A sentinel row
reports truncation; receipt qualification still excludes sample, unlinked, and
reconciliation-required events. History uses the same linked-window limit and
also filters finding timestamps to the requested UTC range. These are bounded
views, not complete detection totals; query-budget exhaustion remains unavailable.

## Inspect separately stored Suricata evidence

When an existing compatible private Suricata store has already been populated
through the explicit operator workflow, start the dashboard with its absolute
path. The dashboard still uses the core telemetry store selected by the ordinary
configuration; the two stores are separate:

```bash
megalodon dashboard --suricata-db /absolute/private/suricata.db
```

Open **Analysis → Suricata evidence**. **Not configured** means no Suricata
path was supplied; **Unavailable** means the chosen snapshot was refused or
could not be validated. Neither state means that the core telemetry store is
empty. An **available** empty store is shown separately and does not mean that
the network is free of threats.

The panel validates the newest five publications and displays at most fifty
signature alerts, newest publication first. Source provenance links lead to the
corresponding publication facts: sensor, run, declared ruleset/version, consumer
attempt, and committed alert count. The producer's `blocked` observation remains
separate from MEGALODON's `not_attempted` action state. These alerts are excluded
from the Overview alert and recorded-decision counters.

This is a startup snapshot. Periodic refresh, browser reload, and workspace
switches do not read the Suricata store again. Restart the dashboard to take a
new snapshot after reviewed operator ingestion. A busy store, unsafe path,
active sidecar, invalid evidence, or exhausted read budget fails the optional
snapshot closed without creating, repairing, or writing a database. See the
[projection contract](suricata-evidence-projection.md) for precise bounds.

The high/critical counter compares sequential stored counts. An increase is not a
unique new incident; a decrease is not proof that a threat was remediated. The
bounded detection list can omit older rows. Search, severity, rule, and timeline
filters apply only to the returned view, not the entire history.

## Create a bounded report

Open **Reports**, confirm the shared UTC range, then select **Preview local
report**. Review the metadata-only JSON and select **Download JSON report**.
The visible preview label records its original range, creation time and
freshness at creation. Automatic refresh and later range changes keep that
preview intact; select **Preview local report** again to replace it with the
current selection, or **Discard preview** to clear it from this tab.

A held report describes the data reviewed when it was created. It is not a
live report, a complete detection total, or proof of capture coverage. A failed
source refresh, an expired snapshot or a future-dated snapshot cannot establish
freshness. If a replacement has no qualified data, the previous preview is
cleared. A browser download error preserves the preview for retry or manual
copying and does not imply that a file was saved.

Reports are assembled in browser memory from validated projections already on
screen. The controls do not query additional private fields, POST data, write
the audit database or create a server-side report. Downloads contain the exact
reviewed JSON; they do not silently substitute data from a later refresh.

The separate **Evidence → Audit history → Create a report** builder also offers
CSV for spreadsheet review. Its export includes the source scope, last dashboard
refresh, row bounds and interpretation limits. CSV cells beginning with a control
character or a formula marker (`=`, `+`, `-`, `@`, including after whitespace or
controls) receive a leading apostrophe. This affects only the exported CSV;
stored evidence and JSON retain the original text. Spreadsheet import settings
can affect interpretation; import columns as text and use JSON when exact
original values are needed. The audit builder may include sample or unlinked
rows and is distinct from the qualified Reports workspace.

## Operate the Integration Map

Opening **Tools** loads the selected **Linux** profile once through a
same-origin GET for static repository constants. Choose **Windows evaluation**
or **Other platforms**, then select **Load integration map** to request that
profile. A failed first load requires an explicit retry. None of these steps
discovers executables, inspects devices, resolves hosts, probes versions,
installs software, launches an adapter, embeds a vendor console, or writes to
SQLite.

The profile selector is an explicit documentation choice, not operating-system
detection. Each successful map contains the 14 closed hub workflows. Cards show software, documented support, a separately labeled startup presence
result when available, evidence shortcuts and companion controls. Data connection
details contain input, output and the next acceptance gate. Expand a card to inspect its workflow ID, source kind, implementation
owner, launch policy, data boundary, action boundary, and inert command template.
A command displayed as text is not an executable control or a complete install
instruction for the selected profile.

Search filters at most 14 cards in memory. The availability filter narrows
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
  component. The Suricata status covers a completed contract-envelope reader and
  separate operator-invoked durable transaction and read-only reconciliation;
  an explicitly selected store can now supply the bounded startup evidence
  panel. Optional nftables support remains inert planning.
- **Evaluation only/guest only** preserve unproved or non-native platform status.
  They must not be promoted by a successful Linux test or by installing a tool.
- **Contract only/manual only/proposed/unsupported** remain non-runtime or limited
  relationships. Suricata has no live sensor integration; Qwen/Ollama is
  limited to one explicitly enabled library call with no dashboard invocation or CLI entry point;
  its receipt can only be supplied programmatically at dashboard startup;
  ClamAV is a manual companion; osquery, Nmap, OSSEC, Greenbone, Zabbix, and
  Nagios Core remain proposed.

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
| Suricata evidence unavailable | The optional startup snapshot was refused | Inspect the existing private store separately, then restart after resolving the local condition; do not initialize or repair it through HTTP |

## What this interface deliberately does not do

There are no launch/install/connect buttons, credential fields, generic plugin
loader, arbitrary endpoint, external dashboard iframe, notification delivery,
alert acknowledgement, remote control, or live remediation. The durable alert
lifecycle/outbox design remains separate from the stored priority counter. A
future real connector must first supply its own versioned input contract, bounded
reader, privacy and completeness semantics, ownership, tests, and review. Adding
a card is not source admission or permission to execute its entry point.

## Expensive stored-telemetry reads

A large ledger can exceed the dashboard's finite SQL work budget even when the
returned count has only four fields. The API reports telemetry unavailable;
existing browser values become stale rather than zero. An indexed recent list
may remain available while the summary cannot complete within its budget.
See [query budget limits and recovery](dashboard-query-budget.md). No data is
purged or modified to recover a read, and the deadline is cooperative rather
than a guarantee against filesystem or native stalls.

## Contradictory offline candidate reports

A complete offline report set can still contain contradictory candidate evidence.
Startup projection now checks candidates against the full baseline and refuses
absent-port claims, unsupported counts, duplicate identities and impossible
host ranks. See [candidate support and remaining proof limits](offline-candidate-consistency.md).
Regenerate a rejected report from source evidence; no automatic repair or partial
successful snapshot is performed.
