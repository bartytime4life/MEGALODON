# Dashboard consumer and recovery state contract

This document describes the reference-consumer and request-recovery behavior in
this revision. Implementation remains in `megalodon/dashboard.py`; no frontend
framework, persistence schema, registry update mechanism, or producer authority
is introduced. The [specification](../SPECIFICATION.md#6-dashboard-contract)
owns the overall dashboard boundary. [Operator workflows](command-center-workflows.md)
explain how to use the three independent read paths.

Delivery and acceptance are separate: consult the exact PR head, its checks,
and submitted reviews before treating a candidate as accepted. This document is
not a rendered-browser, native-platform, or operational acceptance receipt.

## Separate states for separate evidence paths

The page must not compress database reachability, capture health, offline report
availability, and reference-bundle integrity into one green health indicator.
The connection label describes the dashboard API. The triage trust strip
qualifies the last successful data fetch. The reference panel has its own
request/bundle/result state. The offline panel describes a startup-only snapshot.
The Data connections guide is descriptive navigation, not a fourth sensor.

### Reference status transitions

| State or event | Controls | Data treatment | Next permitted read |
| --- | --- | --- | --- |
| Initial status request | Lookup and recheck disabled; panel busy | No selected result | Finish that request |
| Ready | Lookup and recheck enabled | Save bundle ID/version/digest, not an observation timestamp | One manual lookup or one status recheck |
| Manual lookup pending | Lookup and recheck disabled; panel busy | Any prior displayed result still belongs to its own query | Finish that request |
| Successful zero/one/multiple result | Controls enabled | Replace only after closed structural and semantic validation | Another explicit read |
| Invalid local input | Controls enabled | No request; prior query remains visibly distinct | Correct input |
| Lookup transport/validation failure | Controls enabled if bundle status was ready | Prior result is stale, or there is no result | Retry lookup or explicitly recheck status |
| Authoritative unavailable/integrity failure | Lookup disabled; recheck enabled after completion | Clear selected result, provenance and identity | Status recheck; operator package repair outside the browser |
| Explicit status recheck | Controls disabled; panel busy | Clear selected result and identity before request | On success, require a new lookup |

Status and lookup requests use separate booleans but one mutual-exclusion rule:
`loading || statusLoading` prevents starting the other request. Finishing either
request releases its flag and busy state in `finally`, including rejection and
exception paths. The existing five-second request timeout remains. There is no
new retry loop, scheduler, update mechanism, or cross-process lock.

Recheck is deliberately not a cache-reset endpoint. The server's once-per-process
bundle load and finite lookup cache are unchanged. Client state recovery after a
transport interruption is not proof that a damaged installed bundle was repaired.

## Success and failure validation

Both success and authoritative failure must declare:

```text
network_access_performed = false
persistence_status = not_attempted
action_status = not_attempted
```

An error body containing a plausible `status` string is insufficient. Validate
the complete closed failure shape and fixed error message before treating it as
an authoritative unavailable/integrity disposition. A malformed error response
follows the ordinary request-failure path; it must not inject a raw exception or
filesystem path into the display.

Successful status has the existing `reference-library-status-v1` shape. Cache
entries must be within the existing limit of 16. Service and protocol counts
stay within the loader's 20,000 and 512 maxima. Bundle version is `v1`, the
manifest digest is 64 lowercase hexadecimal characters, and required identity
text is finite and nonempty. Source provenance remains an at-most-two-item
closed array; duplicate source IDs are rejected. A response with no source
provenance is not embellished: the result display explicitly says it was not
supplied. The normal installed bundle supplies provenance through its manifest.

Successful lookup has the existing `reference-library-lookup-v1` shape. The
client checks exact request kind, closed echoed query, canonical transport and
numeric range; equality with the request actually sent and the successful
status snapshot's bundle ID/version/manifest digest; count/status/truncation
consistency; correctly typed record fields, unique positive source-row ordinals,
and ranges that cover the requested value; and the fixed no-egress/no-write/
no-action declarations before replacing the selected result.

In particular, `matches.length` must equal `min(match_count, 8)` and `truncated`
must equal `match_count > 8`. Status is `no_match` for zero records, `one_match`
for one, and `multiple_matches` otherwise. These related fields are not accepted
independently. A response to TCP/443 cannot be displayed as the answer to UDP/443
or TCP/80, even when each response would be valid in isolation.

The browser does not compute a service fingerprint, attach a CVE, infer a threat
actor, or change a detection based on these records. It verifies display
consistency with an existing bounded API. The server's resource verification and
HTTP controls remain the primary trust boundary. These checks do not defeat a
compromised local server or turn a digest echoed by that server into independent
publisher authentication.

## Loader failure classification

The backend maps only the exact fixed loader diagnostic
`REFERENCE_DATA:RESOURCE_IO` to ordinary `unavailable`. Every other
`ReferenceDataError` maps to `integrity_failure`, including unknown future
validation codes. Resource size/name/set failures, malformed JSON/numbers,
encoding/framing errors, duplicate keys, invalid records, count/order errors,
and manifest/digest failures must not be relabeled as routine access failures.

The response always uses one fixed public error message and contains no partial
rows, internal diagnostic, resource path, or raw exception. No lookup is cached
after an unsuccessful bundle load. The stricter classification changes the
operator's explanation, not the refusal itself: both categories keep lookup
disabled until an acceptable bundle is available through normal process startup.

## API framing correction

`/api/events` has a 256-character query-string cap **before** parameter-list
construction and integer conversion. Without a pre-conversion bound, a long
decimal can reach Python's integer digit-limit exception. The correction returns
a fixed 400 response without reaching storage. It does not change the 1–200
result limit, repeated/unknown parameter rejection, or accepted ordinary
leading-zero event-limit values.

Malformed URL targets that cause `urlparse` to raise `ValueError` receive a fixed
400 diagnostic before routing. This does not establish that every request-line,
header, connection, thread, or whole-service resource is bounded. Those wider
budgets remain separate work, notably issue #68.

The direct Python `ReferenceLibrary.lookup_port` boundary checks an exact string
type before set membership. Lists and dictionaries produce the domain's fixed
`ReferenceLookupError` rather than an incidental unhashable-type exception.
The HTTP parameter path already supplies strings; this direct-API robustness
correction is not an independently demonstrated remote exploit.

## Provenance presentation and accessibility intent

Use text nodes and semantic definition lists for manifest and retrieval fields.
Do not turn a source registry address into an iframe, automatic fetch, or image.
Preserve the always-visible interpretation warning. Use registry-record counts
without reclassifying reserved or unassigned rows as named services.

Section navigation is in normal document flow, not a sticky layer covering
focused content. Links have a 44-pixel minimum height. Target headings accept
programmatic focus with `tabindex=-1` without adding every heading to ordinary
Tab order. Status changes use the existing polite live status; busy state is
explicit on the reference panel. The retry label and its description explain
what the control does and does not do.

These are design and code properties. They do not establish WCAG conformance,
a correct accessibility tree in every browser, good contrast under every
rendering condition, or screen-reader acceptance. Verify the rendered page and
record browser/OS versions before making those claims.

## Acceptance evidence requirements

| Boundary | Repository check | Evidence limitation |
| --- | --- | --- |
| Wrong query, snapshot, count, range, field type, duplicate row, or forbidden posture | Positive and negative cases in `tests/test_dashboard_workflow_regressions.py` | Node VM exercises the complete dashboard script with synthetic DOM/transport; it is not a browser |
| Direct transport type and malformed/oversized request target | Domain-error and dispatch-before-storage tests in the same module | Direct dispatch tests are not a complete HTTP parser or network-server audit |
| Resource-access versus validation failure | Parameterized loader-error classification, empty-cache and path-free response tests | Injected fixed errors test mapping; full loader tamper/packaging coverage remains in existing suites |
| Pending, retry, stale, unavailable and integrity-failure state | Asynchronous status/lookup tests with closed synthetic responses | Does not prove native accessibility, screen-reader announcements, or layout |
| Main compatibility and surrounding safety invariants | Full repository pytest, compileall, dependency check and safe CLI smokes | Record the exact head, failures, skips and environment |
| Distribution behavior | Existing `test` and `wheel-smoke` CI jobs, including extracted-sdist tests and installed-wheel smokes | Green package CI is execution evidence, not independent approval |
| Human-visible recovery and navigation | Rendered-browser procedure below, issues #7/#27 | Native Windows and unsupported browser combinations need separate receipts |
| Service capacity and crash safety | Separately scoped #67/#68 evidence | This change does not close those gates |

The new Python regression test embeds its Node harness, so it does not require
a new standalone JavaScript test asset to be included in the sdist. It runs
against the imported complete `DASHBOARD_JS`, not a handwritten substitute.
Record local partial-module checks separately from full-checkout or hosted
execution; explicit dependency stubs are not evidence that storage or the real
bundle loader was reproduced. Keep session-specific counts and CI run IDs in
the PR evidence record rather than turning this contract into a stale receipt.

## Manual rendered-browser procedure

Use only synthetic metadata and the approved installed bundle. Record exact
commit, OS, browser/version, viewport and zoom, source selections, steps,
observed results, console errors and limitations. Navigate with keyboard only
from the skip link through section links, reference inputs, retry, triage and
the scrollable table. Check focus after in-page navigation and after disabled
controls become available again. Check narrow viewports and 200% zoom for
clipped provenance, horizontal overflow and readable table controls.

Simulate a local transport failure in an authorized disposable test environment,
then restore reachability. Verify retry recovers without reloading the page or
implying a registry update. Submit one successful query, then fail a different
query; confirm the prior displayed query remains visible and stale. Exercise
zero and multiple records. In a synthetic integrity-failure fixture, verify
prior results disappear and lookup stays disabled. Verify a reference failure
does not repaint SQLite data as fresh or change the selected offline run.

A managed-browser refusal is an environment limitation, not a passed test or
permission to bypass browser policy. Preserve the refusal and hand off the
procedure to an authorized local test environment. Never relax loopback, Host,
CSP, storage, or integrity controls to obtain a screenshot.

Design references: [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
and [WCAG 2.2](https://www.w3.org/TR/WCAG22/). These guide review; they do not
certify this implementation.
