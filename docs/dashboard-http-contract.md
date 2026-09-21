# Dashboard HTTP and presentation contract

The implementation authority is [dashboard.py](../megalodon/dashboard.py).
[dashboard_assets.py](../megalodon/dashboard_assets.py) composes same-origin
presentation; [dashboard_connections.py](../megalodon/dashboard_connections.py)
owns the Integration Map markup, styles, and behavior. The public dashboard
module continues to export `INDEX_HTML`, `DASHBOARD_CSS`, and `DASHBOARD_JS` for
existing consumers and tests. No static CDN or additional server is introduced.

## Authority and transport

The server binds to numeric IPv4 loopback. The public `serve()` boundary refuses
non-loopback addresses, IPv6 for this IPv4 server, and any attempt to enable the
legacy remote override. Expected-Host validation happens before routing or store
access and rejects missing, duplicate, or unexpected Host values. This is a
local exposure guard, **not authentication or a multi-user authorization model**.

Requests must use an origin-form target. Parsed scheme, authority, path parameters,
or fragment components are refused rather than discarded as aliases. The server
retains its same-origin CSP, no-store responses, no-referrer policy, framing
prohibition, MIME sniffing protection, and restricted browser permissions. There
is no CORS permission or external script/font fetch.

`POST` is accepted only for the optional, token-gated `/api/ai/ask` route.
Other POST requests return 405 and `Allow: GET`. HEAD and other unsupported
methods remain unsupported. Unknown paths return 404. Fixed validation errors
do not echo request values, private paths, or stack traces. None of these HTTP
guards makes Python's threaded development-style HTTP server an Internet-facing
production service.

## Route inventory

| GET route | Query | Successful meaning |
| --- | --- | --- |
| `/` | No application query contract | Same-origin dashboard document |
| `/assets/dashboard.css` | No application query contract | Composed local stylesheet |
| `/assets/dashboard.js` | No application query contract | Composed local script, one final bootstrap |
| `/api/config` | None | Read-only flag, refresh interval, event limit, offline-selection availability |
| `/api/setup` | None | Startup source state plus optional executable-presence and process-name snapshots |
| `/api/local-checks` | None; requires `X-Megalodon-Check: 1` | Explicit HUD-only read of runtime versions, selected-store readability, executable presence and process names |
| `/api/summary` | None | Four stored counters; not a capture-health receipt |
| `/api/traffic` | None | Newest 500 event candidates and 200 finding candidates, qualified by ingestion receipts; bounded metadata including endpoints, ports and flags, never payloads |
| `/api/traffic-history` | Required `start`, `end`; optional `before` | Same qualified projection in a UTC range of at most 31 days, with a descending event-ID cursor |
| `/api/events` | Optional `limit` | Five-field projection of bounded recent detections |
| `/api/ingestion-runs` | Optional `limit` | Newest 1–25 stored ingestion receipts, not source liveness |
| `/api/offline-summary` | None | Not selected, or one startup-loaded offline projection |
| `/api/advisory-receipt` | None | Not supplied, or one startup-snapshotted display-only Qwen result |
| `/api/suricata` | None | Not configured, unavailable, or one startup snapshot of the separate Suricata store |
| `/api/reference/status` | None | Verified reference status or explicit unavailability |
| `/api/reference/port` | Exactly `transport` and `port` | One bounded registration-context lookup |
| `/api/reference/protocol` | Exactly `number` | One bounded IP-protocol registration lookup |
| `/api/integrations` | Optional `platform` | Existing static hub plan for one documentation profile |
| `/api/ai/status` | None; explicit check header and operator token | One optional local model status check |

`POST /api/ai/ask` has a separate fixed-question body and per-launch token,
Origin, Host, content-type, and length checks. It writes to the separate
private AI receipt ledger; see the [AI control plane](ai-control-plane.md).

Data routes with no query contract reject nonempty queries. UI/static asset URLs
are not parameterized application APIs. A bare empty query is equivalent to no
parameters. Never encode an action or secret in a query string.

## First-launch HUD and companion controls

`python -m megalodon hud` accepts the same configuration and read-view options
as `dashboard`. It additionally runs the existing readiness metadata check once
before listening. `/api/setup` returns immutable `dashboard-setup-v2` bytes:
`source_status` is `connected` or `not_configured`, and `readiness` is either a
closed `megalodon-tool-readiness-v1` report or null. `runtime` is either a closed
`megalodon-tool-runtime-v1` receipt or null. The runtime receipt reads only a
bounded set of Linux `/proc/*/comm` values once and returns closed tool/status
pairs; it omits process IDs, command lines, paths, users and host identity.
Standalone tools report `not_applicable`. Query arguments and POST are refused.
Repeated GETs and browser refresh never repeat either startup observation. The
client validates both receipts; no report import is needed locally.

**Check this computer** uses a separate `/api/local-checks` endpoint. It is
enabled only for `serve(..., inspect_tools=True)` (the `hud` command), accepts no
query options, and requires exactly one `X-Megalodon-Check: 1` header. The browser
calls it only on an explicit check click, using its five-second abort budget;
it is not part of startup or telemetry polling. No CORS permission is supplied.
The startup `/api/setup` snapshot remains unchanged.

The closed `dashboard-local-checks-v1` result contains `checked_at`, `environment`
(`python_version`, `sqlite_version`, `platform`), `source` (one `status`),
`readiness`, and `runtime`. Source status is `available`, `not_configured`, or
`unavailable`: a bounded summary read on the already selected reader establishes
readability only, not qualified traffic or collection health. A missing-at-start
source is not reopened. No request can choose a path, command, tool or target.

One collector per server serializes checks without waiting on its lock. An
in-flight check returns fixed HTTP 429 plus `Retry-After: 5`; successful bytes
are cached for five seconds. Missing header or non-HUD mode returns 403, invalid
query returns 400, and collection/serialization failure returns a fixed 503.
The response is at most 20 KiB. A failed refresh cannot return an expired cached
result as fresh. The browser validates the complete receipt and offers a local
JSON download; it reports failed/previous results as unavailable or stale.

Discovery uses fixed executable names and bounded PATH metadata operations.
Process observation reads at most 4,096 numeric `/proc` entries and at most 129
bytes from each `comm` file. These are operation/size bounds, not an OS or
filesystem latency deadline; browser abort does not cancel a kernel read. The
single collector prevents overlapping discovery if an underlying read stalls.
No executable is launched, imported or read for content; no network destination
is contacted by the collector and no configuration, database, service or
firewall is changed. Filesystem metadata can still resolve through host mounts.

Only `DASHBOARD_STORE:NO_DIRECTORY` and `DASHBOARD_STORE:NO_DATABASE` can produce
the unconfigured first-launch reader. It returns no telemetry; summary, events
and ingestion receipts remain unavailable. Existing unsafe/invalid stores refuse
startup, and ordinary `dashboard` retains its strict missing-store behavior.
No database, sample record, migration, sensor, model request or service is created.

`/api/traffic` is part of the periodic telemetry refresh. The current
`dashboard-traffic-v1` contract is defined in
[control-room-contract.md](control-room-contract.md). One read-only snapshot
selects at most 500 event candidates and 200 finding candidates, excludes
sample/unlinked/legacy/reconciliation-required events, and returns qualified
event IDs, UTC times, endpoints, ports, flags, reported byte counts, source/run
state, and linked fixed-rule findings. It excludes payloads, arbitrary metadata,
messages, interfaces, paths and model output. Responses are capped at 256 KiB;
byte counts are decimal strings to preserve SQLite integers in JavaScript.

A successful empty or sample-only projection returns HTTP 200 with
`status=unavailable`; a missing or failed store read returns a complete
unavailable envelope with HTTP 503. Neither becomes measured zero traffic.
The Evidence chart clears its measurements and report input on a validated
unavailable projection, while preserving reachable audit counters separately.
Transport or contract failure preserves the prior valid view as stale.

`/api/traffic-history` accepts an inclusive ordered UTC range ending no later
than one minute into the future, at most 31 days long, and an optional canonical
positive safe-integer `before` cursor. Its `dashboard-traffic-history-v1`
envelope discloses candidate count and the next cursor, even for excluded-only
pages. Invalid queries return 400; unavailable reads return 503. Browser requests
cannot choose a store, start ingestion or mutate evidence. Saved metadata is not
wire speed, capture continuity, service health or whole-network coverage.

Report creation remains browser-local. The overview, detection, and ingestion
presets use only already validated in-memory projections. JSON/CSV downloads,
clipboard copy, and print/PDF require an explicit user action and do not call a
write endpoint or create a server-side file.

The local and hosted HUDs share canonical controls, lifecycle text and parser in
`megalodon/dashboard_tool_assets.py`. `scripts/sync-hud-assets.py` materializes
the exact Site copies, with a byte-parity regression. Console bookmarks persist
only explicit validated HTTP(S) addresses for fourteen fixed tools in browser
localStorage; storage failure uses page memory and says so. Credentials, queries,
fragments, executable protocols and malformed saved values are rejected. No
telemetry, readiness report, command-builder path or filter is persisted there.
Links open a separate tab with no opener/referrer; they do not prove connectivity.
The optional startup form builds quoted Linux commands without path access or
execution. Clipboard operations require a user click and expose a manual-copy
fallback message.

Home's software list separates runtime essentials from optional workflows. Its
download buttons and Apps acquisition buttons open fixed publisher pages with
no opener/referrer. They do not fetch or execute installers. The hosted site
shares acquisition links only; it cannot invoke the localhost machine check.

## Optional Suricata evidence snapshot

`megalodon dashboard --suricata-db /absolute/private/suricata.db` selects an
existing dedicated Suricata store at process startup. The programmatic boundary
is `serve(..., suricata_db=...)`. No browser query, form, refresh control, or
endpoint can select another path, initialize a store, migrate it, ingest data,
or request a new database snapshot. Unsafe dashboard binds are refused before
this optional read.

The bounded reader fully validates at most the five newest committed
publications and their receipts, then projects at most 50 alerts in descending
publication/record order into a response of at most 65,536 bytes. It uses a
five-second cooperative deadline and fails closed when the safe read-only
snapshot cannot be obtained. See [Suricata evidence projection](suricata-evidence-projection.md)
for store, query, and evidence validation limits. Counts of older stored rows
do not constitute full validation of those older publications.

Before binding HTTP, the dashboard owns the result as immutable JSON bytes.
`GET /api/suricata` serves those bytes without opening SQLite or holding a
database lock. This route returns HTTP 200 for all three valid envelope
statuses: `not_configured`, `unavailable`, and `available`; the status describes
the optional evidence surface, not overall dashboard health. Missing or invalid
optional evidence does not disable core telemetry. Nonempty query strings are
rejected before route handling, including path, limit, and refresh parameters.
Host, origin-form request, GET-only, no-store, and CSP controls remain in force.

The browser requests the snapshot once during bootstrap through the existing
bounded UTF-8 response reader. It revalidates the closed response, finite row
counts, provenance references, numeric types and limits, timestamps, and action
boundaries before rendering text nodes. Failure clears the optional panel;
partial data is never displayed. This request does not join periodic telemetry
refresh. A browser reload reads the same startup bytes; restart the dashboard
under ordinary operator authority to obtain a new snapshot.

The Analysis panel identifies these as external Suricata signature alerts.
Every displayed row refers to its sensor, publication run, source record, and
declared ruleset/version provenance. Suricata's producer-reported `blocked`
value does not indicate a MEGALODON action; `action_status` remains
`not_attempted`. These alerts never contribute to core detection/action
counters, prove maliciousness, or attest that a sensor is installed or running.

## Qwen advisory receipt projection

The optional advisory value is supplied only through the programmatic
`serve(..., advisory_receipt=...)` boundary as an exact frozen
`QwenAdvisoryResult`. Before binding the server, the dashboard validates the
closed outcome/code relationship, 1,200-character plain-text fields, finite
unique limitations, literal local provider class, Qwen model ID, policy
version, and lowercase artifact SHA-256. It then takes an owned JSON copy and
bounds the complete response to 8 KiB. Later mutation of the source object
cannot change the served receipt.

The browser requests this route once during bootstrap. It checks a canonical
content length when present, reads the response stream through an 8 KiB
cumulative byte budget, and performs strict UTF-8 decoding before JSON parsing.
Its text-length checks count Unicode code points to match Python's contract.
It does not include the
receipt in periodic telemetry refresh, retain a stale prior value, offer a
retry or invocation control, or fetch it from another origin. The browser
revalidates the complete envelope, freezes its owned projection, and renders
every value through `textContent`/created text nodes. Missing or invalid data
has an explicit unavailable state and no partial model output is displayed.

The route does not call `invoke_qwen_advisory`, inspect provider health, start
or pull a model, read a file, query SQLite, execute a subprocess, change a
firewall, or grant tool/action authority. A displayed ANSWER remains untrusted
advice, not evidence, a detection, provider/artifact attestation, or a response
decision. Supplying the result and coordinating its lifetime remain the
embedding application's responsibility and require a separately reviewed
phase.

## Finite query parsing and numeric compatibility

Queries that accept parameters are limited to 256 raw query characters **before**
URL decoding, field allocation, or decimal conversion. Parsing uses a finite
field budget, strict field framing, strict UTF-8 decoding, and preserved blank
values so omitted and blank arguments cannot collapse into the same behavior.
Allowed names and multiplicity are checked explicitly; unknown or repeated fields
are rejected. These are per-request bounds, not a global concurrency budget.

Event limits use canonical ASCII decimal strings from 1 through 200. The default
remains the configured limit, normally 50. `1`, `50`, and `200` are valid; `0001`,
`1.0`, `+1`, whitespace, Unicode numerals, Boolean words, negative values, zero,
and oversized digit strings are not. Standard percent encoding of a valid
canonical value remains accepted after decoding.

**Compatibility change:** leading-zero event limits previously passed numeric
conversion. They now return 400. Canonical callers and the shipped dashboard are
unchanged. Do not disable Python's integer-string conversion protection to accept
an oversized request. The browser configuration reader likewise requires actual
JSON integers instead of coercing strings, booleans, arrays, or null through
`Number(...)`. Invalid configuration leaves the existing safe defaults in force.

Reference values retain canonical port 0–65535 and protocol 0–255 semantics with
normalized `tcp`, `udp`, `sctp`, or `dccp`. The direct Python transport method also
rejects wrong types, including unhashable lists/dictionaries, with the fixed
lookup error rather than leaking a TypeError. Lookup output-bound failures return
a fixed 503 response instead of escaping the request handler.

## Reference load failure disposition

A reference library is either fully loaded or unavailable for lookup. The
failure classification must explain why it was refused without returning
partial registry rows or internal diagnostics. `ReferenceLibrary.load()` uses
an exact exception-code decision, not a substring guess:

| Loader result | Public status | Fixed public error | HTTP result for a valid status or lookup request |
| --- | --- | --- | --- |
| Exact `REFERENCE_DATA:RESOURCE_IO` | `unavailable` | `reference bundle unavailable` | 503, no matches |
| Any other `ReferenceDataError` | `integrity_failure` | `reference bundle integrity failure` | 503, no matches |
| Valid complete bundle | Existing successful contract | None | Existing 200 response |

Integrity failure includes oversized resources, invalid resource names/sets,
malformed JSON/numbers, encoding/framing errors, duplicate keys, invalid records,
manifest/digest errors, and count/order failures. Unknown future validation
codes also fail closed as integrity failures. A code containing `RESOURCE_IO`
as only a prefix or substring is not ordinary resource-access unavailability.
Only the loader's declared `ReferenceDataError` is classified here; unrelated
programming exceptions are not silently hidden as a bundle-status result.

Both failure categories have the same closed seven-field status envelope:
`schema`, `available`, `status`, `error`, `network_access_performed`,
`persistence_status`, and `action_status`. Availability is false, outbound
network access is false, and persistence/action remain `not_attempted`.
Failure responses do not carry a bundle identity, provenance, match rows, a
filesystem path, or a raw loader exception. The lookup cache remains empty.
The existing Host, no-store and CSP controls still apply to the 503 response.

This corrects diagnostic truthfulness, not a previously permitted partial load:
both categories already refused lookup. An integrity failure is not proof of
malicious tampering; a damaged package or invalid resource can produce it too.
Likewise, a resource-access failure does not prove that the data would pass
validation once readable.

The default library caches its startup disposition within the process. Reading
status or attempting another lookup does not reload resources, redownload a
bundle, or repair an installation. Diagnose the local package/access problem,
restore reviewed resources through the existing maintenance process, and restart
the service only under ordinary operator authority. Do not edit expected digests,
accept partial shards, increase size limits, or bypass privacy checks to make
the status green. A healthy Integration Map or SQLite response does not repair
a failed reference bundle; these are separate read paths.

`tests/test_reference_failure_disposition.py` supplies positive resource-access
and negative validation-code cases, fixed-response/no-cache checks, real
loopback HTTP tests with an injected failing loader and a reader that refuses
any telemetry access, default-cache behavior, and preservation of unrelated
programming exceptions. These tests do not substitute for the existing real
reference-bundle tamper, distribution, browser, or platform acceptance suites.
No UI control, retry loop, dataset, cache-reset API or source integration is
added by this disposition correction.

## Integration projection contract

The route calls [hub.integration_plan](../megalodon/hub.py); it does not create a
second capability registry. `platform` is one of `linux`, `windows`, or `other`.
When omitted, the existing hub selects the coarse runtime-platform profile;
that selection uses an interpreter platform identifier, not host/tool discovery.
The browser always requests an explicit profile.

The existing `megalodon-integration-hub-v1` envelope and
`megalodon-capability-catalog-v1` reference are preserved. Each workflow carries
ID, component, software, selected status, source kind, owner, input/output,
nullable entry point, launch policy, data/action boundaries, and next gate.
The HTTP surface permits 14 workflows, string fields up to 512 characters,
and encoded responses up to 32 KiB. A budget failure returns a fixed 503 with no
partial map. Adding workflows requires a coordinated reviewed bound/contract/UI
change, not silently dropping rows or broadening a generic plugin loader.

The browser requires the complete 14-ID set, unique IDs, the exact envelope
and workflow keys, bounded field types, a known status, and a response matching
the profile captured when the request began. It requires
`hub_mode=static_plan_only`, `default_posture=observe_only`,
`action_status=not_attempted`, and false execution, outbound-network, and
host-change flags. These flags describe **plan construction**, not an assertion
that serving the loopback HTTP response involved no transport.

No integration route reads telemetry, opens a database, loads the IANA bundle,
probes executables, starts a subprocess, or performs an outbound connector call.
The same plan can be inspected through the existing `hub-plan` CLI. A successful
HTTP response is descriptive metadata, not an installation, compatibility,
source-admission, connection, or health receipt.

## UI state and safe rendering

The Integration Map is loaded on first entry to the **Tools & consoles** workspace or
by the explicit load button; it is not added to telemetry polling or the startup
critical path. It has one in-flight request, the
existing five-second browser abort budget, bounded in-memory filters, explicit
first-load unavailability, and preservation of a previous map as stale after a
failure. A selected profile and a successfully loaded profile are separate
values. Loading another profile never relabels old data as the new profile.

Text is rendered through created elements and `textContent`, not HTML parsing,
evaluation, generated handlers, or executable links. Inert command templates
remain text. Status messages are polite and atomic; keyboard navigation uses
native controls and focusable section targets. Responsive card columns and
wrapped text support narrow layouts without changing the read model. Actual
rendering, contrast, screen readers, zoom, and platform behavior still require
separate acceptance evidence.

The workspace router recognizes only the fixed fragment targets already owned
by the dashboard. Startup and `hashchange` restore the owning workspace before
scrolling to that local element; unknown, oversized, and non-fragment values do
not change workspace state or become selectors.

## Validation and residual risk

The optional, disabled-by-default AI routes are specified separately in
[AI control plane](ai-control-plane.md): `GET /api/ai/status` requires an
explicit check header and `POST /api/ai/ask` requires a per-launch operator
token, exact same-origin request, and one fixed question ID. They are not part
of the original read-only telemetry routes described above. The POST writes
only the separate private AI receipt ledger and bounded report snapshots;
it has no host-security or firewall apply capability.

`tests/test_dashboard_boundaries.py` covers oversized, duplicate, type-confused,
malformed, and aliased inputs; refusal before store access; post-error liveness;
existing projection fields; exact hub-plan parity; response budgets; static-plan
side-effect denial; strict configuration types; bounded text rendering; filter
empty states; wrong-profile rejection; overlap prevention; timeout; and stale
recovery. Existing dashboard tests remain authoritative for the inherited
reference, offline, triage, and privacy behavior. Full wheel/sdist checks must
prove that the newly separated Python asset modules ship and import correctly.

This change does not bound total request threads, close slow clients, solve disk
exhaustion, optimize detector state, establish native Windows behavior, prove
installed TShark containment, or complete independent review. Those are separate
evidence classes. Historical tracking included [#68](https://github.com/bartytime4life/MEGALODON/issues/68),
[#7](https://github.com/bartytime4life/MEGALODON/issues/7),
[#27](https://github.com/bartytime4life/MEGALODON/issues/27), and
[#3](https://github.com/bartytime4life/MEGALODON/issues/3).
Those issues are now closed with bounded dispositions; use the current
`SECURITY_REVIEW.md` control register for delivered controls and remaining
operational obligations rather than treating this original slice as current backlog.

## Primary design references, checked 2026-09-10

- [Python 3.11 URL parsing](https://docs.python.org/3.11/library/urllib.parse.html):
  parsing is not validation; strict framing and `max_num_fields` must be chosen.
- [Python integer-string conversion limitation](https://docs.python.org/3.11/library/stdtypes.html#integer-string-conversion-length-limitation):
  conversion can raise ValueError; application bounds should precede conversion.
- [OWASP DOM-based XSS prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html):
  choose text sinks rather than parsing untrusted values as HTML.
- [W3C status messages](https://www.w3.org/WAI/WCAG22/Understanding/status-messages.html)
  and [WCAG 2.2](https://www.w3.org/TR/WCAG22/): expose status programmatically and
  keep keyboard focus visible. These inform design, not a conformance claim.
