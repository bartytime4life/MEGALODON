# Reference Library: recovery, provenance, and exact-query contract

Status: review candidate prepared on 2026-09-11 against
`f6df35421798b0eb6b1931b9ebc38a1407349eb1`. The touched source blobs were unchanged after PR #90. This document describes the accompanying
candidate, not an assertion that it has reached main or passed independent review.

## What this surface does

The Reference Library answers a manually submitted service/port or IP-protocol
lookup using the server's already loaded IANA bundle. It supplies registration
context. A registered service does not identify the software actually speaking
on that port, establish an incident, or certify an endpoint as safe. The
reference panel neither classifies traffic nor modifies a detection, run receipt,
rule, firewall, or report. [1, 2]

The browser and server have different verification responsibilities. The Python
loader checks the packaged manifest and data. The browser checks the returned
schema, limits, query identity, bundle identity, and stated action boundaries.
Matching claims between two API responses is **not independent verification of
on-disk bytes**, authentication of an upstream publisher, or a live IANA update.
The interface labels the SHA-256 as “reported by local API” for that reason.

## Operator workflow

Enter a canonical decimal value: for example `443`, not `00443`, for a port; or
`6` for an IP protocol number. Select TCP, UDP, SCTP, or DCCP for port lookups.
The accepted numeric intervals are 0–65535 for ports and 0–255 for protocols.
Submit explicitly; editing a field does not issue a request. During a request,
lookup and recovery controls are disabled to prevent overlapping operations.

The result identifies the exact submitted query. It shows zero, one, or multiple
registrations and at most eight records. A capped display says so. A zero-match
result is a successful lookup with no registration match, not a transport failure,
an unknown-host finding, or a safety verdict.

**Recheck local snapshot** makes another GET of the existing local status
endpoint. It never contacts IANA, rereads the bundle on disk, starts an analyzer,
or installs anything. A successful recheck deliberately clears the prior lookup
and establishes a fresh display context, even when the bundle identity is
unchanged. This prevents an old result from silently acquiring a new status.

**Clear displayed context** clears only this page's retained result and visible
records. It does not erase SQLite evidence, evict the server's small lookup cache,
remove a local file, or delete browser history. The verified status/provenance
context remains available. Neither button grants execution permission.

## Failure and recovery behavior

| Condition | Display behavior | Safe next action |
| --- | --- | --- |
| Initial status request fails | Lookup disabled; no result is claimed | Recheck local snapshot |
| Valid ready status | Enable lookup; show bundle provenance | Submit one explicit lookup |
| Lookup network/timeout/JSON parsing failure with a prior result | Keep that result, visibly stale and labeled with its original query | Retry the intended query or recheck status |
| Lookup fails without a prior result | State that no result is available | Retry or recheck; do not infer “no matches” |
| Successful JSON response fails schema/query/bundle checks | Reject it, clear prior display and retained result, disable lookup | Recheck local status; investigate repeat failures |
| Valid HTTP 503 unavailable envelope | Clear result, disable lookup, retain no partial rows | Check local service; repair/restart if bundle loading failed |
| Valid HTTP 503 integrity-failure envelope | Clear result and provenance; explain the declared integrity failure | Repair trusted local installation and restart before rechecking |
| Edited inputs with a displayed result | Explicitly identify the result's old query | Submit to replace it |

A malformed 503 body is **not** evidence of an integrity failure. Only an exact
status schema, fixed diagnostic, expected action flags, and the expected HTTP
status establish a declared server failure. An unrecognized error envelope is a
request failure; it cannot inject diagnostic text into the interface. Similarly,
malformed JSON is not parsed into a partial result. These distinctions avoid
turning “could not read a response” into either “bundle compromised” or “no data.”

The server's `ReferenceLibrary` is immutable in process and loaded once. Rechecking
cannot repair a failed initialization. Repair the local package/source of the
failure using the installation guidance, restart the dashboard process, and then
recheck. Do not delete or modify the telemetry database as a reference-library
recovery step. Do not suppress loader checks or substitute a partial registry.

A reference failure is scoped to this panel. It does not establish that telemetry
ingestion failed or that the Integration Map describes live tool health. [1, 2]

## Response acceptance rules

The existing exact-key schema checks remain in place. The candidate additionally
requires the following relationships before rendering a successful lookup:

- The result kind and normalized query equal the request actually submitted.
  Transport is part of the identity: `tcp/443` and `udp/443` are different queries.
- Bundle ID, version, manifest SHA-256, warning, and relevant source provenance
  agree with the most recently accepted status. The version is `v1`; the digest
  is exactly 64 lowercase hexadecimal characters.
- Status agrees with total match count. Returned count equals `min(total, 8)`;
  `truncated` is true exactly when total exceeds eight. A positive count cannot
  masquerade as an empty successful response.
- The status contains the two expected unique source IDs. A lookup contains the
  one source appropriate to its kind. A missing/duplicated/unrelated registry is
  not acceptable provenance.
- Each returned interval contains the queried number and stays within the domain
  range. Port records must use the requested transport. Interval endpoints and
  one-based source-row ordinals are integers, not numeric-looking strings.
- Both successful **and unavailable** envelopes state no external reference
  network access and no persistence/action attempt. Failure diagnostics use the
  fixed public vocabulary, not arbitrary upstream messages.

These are consistency checks on a bounded response, not a second full IANA
normalizer. The backend remains responsible for complete source validation,
record semantics, storage boundaries, response-byte limits, and host validation.
A compromised server could return mutually consistent false claims; this client
patch is not a defense against replacement of the trusted local installation.

## Provenance and time semantics

The expandable provenance panel shows the bundle identity, API-reported digest,
registry identifiers, registry URLs, registry update dates, retrieval timestamps,
retrieval-time basis, and interpretation warning. Registry URLs are **text only**.
They are not navigation controls and are never fetched by this feature.

“Registry last updated,” “retrieved at,” and “this page fetched a response” are
three different facts. A ready status means the local service has an acceptable
snapshot, not that its data is current on the Internet. The candidate does not
invent age thresholds, refresh deadlines, or an upstream freshness guarantee.
The displayed retrieval-time basis preserves the manifest's original qualification.

All dynamic provenance and registration fields use text nodes. The application
must not put these fields into `innerHTML`, script evaluation, event handlers,
or clickable URL attributes. This follows OWASP's untrusted-response guidance;
client validation does not replace server security controls. [3]

## Request policy and accessibility

The shared dashboard JSON helper retains its five-second AbortController timeout
and clears that timer in `finally`. It now requests `mode: 'same-origin'`,
`credentials: 'omit'`, `redirect: 'error'`, and `cache: 'no-store'`. The Integration
Map already calls this helper, so the same policy applies there without changing
its schema or turning its descriptions into connections. A timeout is a browser
request limit, not proof that server work has stopped. [2, 4]

Status text remains `role="status"`, polite, and atomic. Busy state is explicit
on the panel. Labels explain what is happening without relying on color. The
provenance disclosure uses native `details`/`summary`, with wrapping fields and a
single-column narrow-screen layout. These choices support accessible status
communication; they are not a claim of complete WCAG conformance. Keyboard,
zoom, screen-reader, and full-page behavior need rendered acceptance. [5]

## Validation and regression commands

On a complete patched checkout, use the repository's supported development
environment, with Node available, then run:

```bash
python -m unittest discover -s tests -p 'test_dashboard_reference_recovery.py' -v
python -m pytest
```

The Python wrapper checks asset wiring and executes the Node harness against
functions extracted from the production `DASHBOARD_JS` string. The harness uses
a synthetic DOM and explicit mock responses; it opens no socket and reads no
telemetry. Absence of Node skips that wrapper test, which is **not JavaScript
acceptance**. CI/package validation must confirm that the `.cjs` harness is in
the source distribution; `MANIFEST.in` is amended accordingly.

Local PR-preparation evidence is narrower than a full checkout: the actual
presentation sources were reconstructed and their complete Git blob identities
matched the pinned repository. Both Python wrapper methods passed, including
67 source-derived Node checks with no skips. All 34 rejection controls failed
against the original validators with “Missing expected exception”, distinguishing
the missing checks rather than missing helper functions. Python 3.11 grammar
and the complete emitted JavaScript syntax also passed.

That local execution used Python 3.13.5 and Node 22.16.0, not the supported
Python 3.11/3.12 CI matrix. A full clone failed DNS; full pytest, wheel/sdist,
actual backend routes, and native-platform acceptance were not run locally.
Exact-head hosted results belong in the accompanying PR receipt. Earlier
synthetic browser screenshots are historical component evidence, not a newly
executed full-dashboard acceptance result.

## Sources

1. [Pinned dashboard backend](https://github.com/bartytime4life/MEGALODON/blob/f6df35421798b0eb6b1931b9ebc38a1407349eb1/megalodon/dashboard.py), `ReferenceLibrary`, `_result`, and `default_reference_library`.
2. [Pinned presentation and Integration Map](https://github.com/bartytime4life/MEGALODON/tree/f6df35421798b0eb6b1931b9ebc38a1407349eb1/megalodon), `dashboard_assets.py` and `dashboard_connections.py`.
3. [OWASP AJAX Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AJAX_Security_Cheat_Sheet.html), consulted 2026-09-11.
4. [MDN Request mode](https://developer.mozilla.org/en-US/docs/Web/API/Request/mode) and [AbortSignal](https://developer.mozilla.org/en-US/docs/Web/API/AbortSignal), consulted 2026-09-11.
5. [W3C Understanding SC 4.1.3: Status Messages](https://www.w3.org/WAI/WCAG22/Understanding/status-messages), consulted 2026-09-11.
