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

`POST` is refused with 405 and `Allow: GET`. Other unsupported methods remain
unsupported; this change does not add HEAD or a mutation API. Unknown paths return
404. Fixed validation errors do not echo request values, private paths, or stack
traces. None of these HTTP guards makes Python's threaded development-style HTTP
server an Internet-facing production service.

## Route inventory

| GET route | Query | Successful meaning |
| --- | --- | --- |
| `/` | No application query contract | Same-origin dashboard document |
| `/assets/dashboard.css` | No application query contract | Composed local stylesheet |
| `/assets/dashboard.js` | No application query contract | Composed local script, one final bootstrap |
| `/api/config` | None | Read-only flag, refresh interval, event limit, offline-selection availability |
| `/api/summary` | None | Four stored counters; not a capture-health receipt |
| `/api/events` | Optional `limit` | Five-field projection of bounded recent detections |
| `/api/offline-summary` | None | Not selected, or one startup-loaded offline projection |
| `/api/reference/status` | None | Verified reference status or explicit unavailability |
| `/api/reference/port` | Exactly `transport` and `port` | One bounded registration-context lookup |
| `/api/reference/protocol` | Exactly `number` | One bounded IP-protocol registration lookup |
| `/api/integrations` | Optional `platform` | Existing static hub plan for one documentation profile |

Data routes with no query contract reject nonempty queries. UI/static asset URLs
are not parameterized application APIs. A bare empty query is equivalent to no
parameters. Never encode an action or secret in a query string.

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
The HTTP surface permits eight workflows, string fields up to 512 characters,
and encoded responses up to 32 KiB. A budget failure returns a fixed 503 with no
partial map. Adding workflows requires a coordinated reviewed bound/contract/UI
change, not silently dropping rows or broadening a generic plugin loader.

The browser requires the complete eight-ID set, unique IDs, the exact envelope
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

The Integration Map is loaded only on operator request; it is not added to
telemetry polling or the startup critical path. It has one in-flight request, the
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

## Validation and residual risk

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
work items, especially [#68](https://github.com/bartytime4life/MEGALODON/issues/68),
[#7](https://github.com/bartytime4life/MEGALODON/issues/7),
[#27](https://github.com/bartytime4life/MEGALODON/issues/27), and
[#3](https://github.com/bartytime4life/MEGALODON/issues/3).

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
