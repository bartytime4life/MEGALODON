# Linux dashboard browser acceptance

> **Latest source-head observation — October 22, 2026:** main `2cb706039724d9ea0bda09cbd3c17698b15ba55c`, [Linux browser run 39878396547](https://github.com/bartytime4life/MEGALODON/actions/runs/39878396547), succeeded with the merged Playwright 1.64.0 compatibility profile. CI and CodeQL also succeeded at that source pin. This is observed hosted evidence, not a documentation-candidate or installed-host run. The earlier `0acdf72` timeout, #660/#661 macOS failures and older passing receipts retain their own identities; #662 changes fixture qualification without relaxing production ancestry policy.

This opt-in test executes the actual CLI, ingestion/service code, SQLite writer,
separate dashboard reader, HTTP handler, bundled assets, and a real browser.
It does not replace the application with a component fixture. Ordinary pytest
and package installation neither start this browser suite nor require Playwright.
Run results belong to their exact commit and environment; the existence of this
suite is not acceptance, independent review, or a supported-platform promise.

## Installed local check — October 1, 2026

The [installed-browser receipt](audit/browser-local-acceptance.json) records a
separate run through the supported Codex in-app browser against the real local
service. It covers responsive layouts, selected keyboard journeys, report
creation and downloads, chart tables, and truthful empty/failed-feed states.
Feed failure and recovery used a disposable CLI dashboard with synthetic
documentation addresses; the installed capture service continued running.

This run did **not** execute the native-focus driver described below. Native
hidden-window suspension, OS reduced-motion preference, print pagination and
live mapped geographic arcs remain unverified in that run. The receipt records
those limits explicitly. Browserless regression success is separate evidence.
Raw telemetry and screenshots remain local and are excluded from Git.

The subsequent [native Linux CI receipt](audit/browser-ci-acceptance.json)
records 83 passing checks on candidate `6f4187c`, including actual window
minimization/restoration and polling suspension/recovery. Its exact generated
merge commit, browser/runtime versions and driver-profile digests are recorded.
It complements the installed check and does not resolve print pagination.

## Prepared environment and execution

From an installed repository checkout on non-root Linux, with Chrome stable,
Xvfb/Openbox, and the test-only Playwright 1.64.0 package already installed,
use an X display already managed by Openbox:

```bash
python -m compileall -q megalodon tests
python -m pytest -ra
python tests/browser_native_profile.py
```

The companion `.github/workflows/browser-acceptance.yml` creates its own Xvfb
display, verifies Openbox readiness, and runs the last command
on Ubuntu 24.04 with Python 3.11, the runner's existing Chrome, and an isolated
browser profile. Its package-setup steps install the Openbox display manager and test
driver; they do not install a browser, sensor, daemon, or MEGALODON service. The core package gains
no dependency. The driver is pinned and Python inputs use the CI constraints;
the runner image and Chrome are not pinned; the emitted versions describe one execution, not reproducible
build or compatibility proof for every future Chrome release.

Chrome is headed under a virtual X display so native visibility can be
exercised. The test minimizes and restores the actual browser window through
Chromium's browser-level window-state API; it never assigns document.hidden or
dispatches visibility events as proof. The test reads native visibility through
bounded test-side polling, then waits separately for application refresh idle.
The workflow installs Openbox and x11-utils explicitly, then verifies Openbox
owns the X display before launching Chrome; Xvfb alone does not provide a window
manager. The acceptance receipt records Chrome's observed native window bounds
after each state change.
Failure labels identify the predicate that missed its deadline. It does not use
an in-page eval poller or add unsafe-eval to the application CSP. Chromium
sandboxing is explicitly requested. Missing Chrome/Xvfb,
root execution, sandbox failure, a policy-blocked loopback, timeout, or assertion
failure returns nonzero. There is no no-sandbox fallback, skip-as-pass path,
proxy, tunnel, browser download, or policy override. Keep the existing required
`test` check unchanged. This additional check is not automatically required by
branch protection and does not supply an independent approval.

## Native-focus driver profile (issue #97)

The test must remove automation's forced-visible behavior before measuring
native visibility. The reviewed Playwright 1.64.0 driver core bundle sets
`Emulation.setFocusEmulationEnabled` to `true` on its own CDP session.
[Chrome documents](https://developer.chrome.com/docs/devtools/rendering/apply-effects#emulate_a_focused_page)
that focus emulation keeps visibility at `visible` and suppresses visibility
changes. Minimizing the window or replacing its window manager does not undo
that automation setting. A second CDP session setting it to false does not
release the original session's browser-side capturer.

`tests/browser_native_profile.py` verifies the installed Playwright version and
both exact driver-module digests, copies the installed test package to a private
temporary directory, and changes only that initialization call from true to
false in the copy. It runs the unchanged acceptance suite in a subprocess using
that copy. The installed package, Chromium binary/policy, application assets,
CSP, sandbox request, visibility getters, events, and assertion deadlines are
unchanged. The copy is removed on completion. This is an explicitly modified
test-driver profile, not a stock-Playwright compatibility claim or vendored code.

The companion `MEGALODON_BROWSER_DRIVER_PROFILE` records the profile ID,
original/result SHA-256, preparation, and child exit status. A prepared profile
is not a passing test. Require both its terminal passed result and the complete
`MEGALODON_BROWSER_ACCEPTANCE` passed receipt. Unknown driver versions/bytes,
already-patched installations, copy failure, or child failure return nonzero.
The fixed hashes require fresh review when Playwright changes; do not merely
refresh them to accept unknown code. Pure regression tests run without a browser
or Playwright installation and cover mismatch, nonunique edits, preservation,
and child-failure propagation.

The stock-driver failure and the corrected-profile result must remain separate
historical observations. An empty-page A/B probe establishes driver behavior,
not MEGALODON acceptance; only the real-application lane establishes the latter.
The profile still has to observe native hidden and visible states and demonstrate
suspension/recovery through unchanged application logic. It never synthesizes
visibility to make an assertion pass.

## Playwright 1.64.0 qualification — October 21, 2026

PR #658 changed the dependency without updating the native-focus profile or
the closed browser-input policy. Its original Linux browser job
[118453184738](https://github.com/bartytime4life/MEGALODON/actions/runs/39369267773/job/118453184738)
refused `DRIVER_VERSION_MISMATCH`; that failure remains historical evidence.

The inspection candidate for [PR #660](https://github.com/bartytime4life/MEGALODON/pull/660),
`d4fe205058875f66f5f2831588572e39e16dd367`, downloaded through the existing
hash-required wheel closure and independently compared the selected wheel
against PyPI's exact-filename published digest in
[job 119465372132](https://github.com/bartytime4life/MEGALODON/actions/runs/39670090565/job/119465372132).
That inspection succeeded; the unchanged 1.63 profile then refused the new
version as expected. Inspection alone is not browser acceptance.

| Checked bytes | SHA-256 |
| --- | --- |
| `playwright-1.64.0-py3-none-manylinux1_x86_64.whl` | `5a59af1b230b234008524a5d42b613b233d4256f73bc1dd25bf3f11db0c81b75` |
| Stock `driver/package/lib/coreBundle.js` (3,585,406 bytes) | `829521b67ed7be90c7d6d6098ff39f2241562d47e4ad7ccab13710924a56001d` |
| Copy with the single protected focus call changed to false | `a08fe18c02c46ef364029a72ee5299529cea7e093b21f9f8ce69c8be64e8a2e6` |

The wheel contains exactly one copy of the protected initialization call.
The upstream Chromium source at
[v1.63.0](https://github.com/microsoft/playwright/blob/v1.63.0/packages/playwright-core/src/server/chromium/crPage.ts)
and [v1.64.0](https://github.com/microsoft/playwright/blob/v1.64.0/packages/playwright-core/src/server/chromium/crPage.ts)
keeps the normal-page main-frame focus condition and true-valued call.
Version 1.64 adds a service-worker bypass branch for storage-state pages before
that normal-page branch; the inspected bundle agrees. The transformation still
changes only the same driver-owned call. No new focus option, broad replacement,
dynamic digest admission, or fallback is introduced.

The lock retains only the checked Linux wheel hash. Dependabot's other-platform
hashes violated the existing single-hash inventory grammar; the grammar and
integrity checks remain unchanged. The source inventory is regenerated with
the reviewed browser pin. PR #657's Pluggy multi-hash lock failure is separate:
[its current CI run](https://github.com/bartytime4life/MEGALODON/actions/runs/39644482194)
reports `BUILD_INPUT_INVENTORY:INVALID_LOCK_ENTRY`, while
[main at 64da4f0](https://github.com/bartytime4life/MEGALODON/actions/runs/39611215270)
passes CI and [native browser acceptance](https://github.com/bartytime4life/MEGALODON/actions/runs/39611215256).
No Pluggy or general parser change belongs to this correction.

The final candidate must pass the unchanged Linux browser workflow with both
terminal receipts, including native hidden/visible polling suspension and
recovery. Read PR #660's checks for the final candidate SHA and results.
Historical 1.63 receipts linked earlier retain their original revision and scope.

## Exercised boundaries

The runner creates two new private temporary fixture stores through the real
JSONL CLI: an empty run and two documentation-address DNS-length detections.
It closes each writer before starting the dashboard. A separate synthetic Zeek
JSON record is processed by the existing offline CLI with an explicitly
operator-declared, unverified producer version. No Zeek binary or sensor runs.
The resulting completed report supplies the startup-only offline projection.

The checks cover missing-database startup refusal; actual five-field HTTP event
responses; invalid/repeated/unknown/out-of-range query and Host refusals;
no-store, MIME and no-inline CSP header presence; empty/nonempty rendering;
five cells with semantic time in each row; keyboard skip-link activation;
search and clear; reference lookup/clear; actual offline projection address
exclusions; static-map initial failure, retry and delayed-profile filtering;
pause, native hidden-window suspension/foreground recovery; peer-settlement
protection; the real five-second request-helper timeout and recovery; mobile
page overflow and rendered focus. The main database bytes must remain unchanged
through serving. SQLite's private WAL/SHM coordination is not claimed write-free.

Fault probes intercept only exact application routes to delay or abort requests.
Successful responses still come from the actual server; no requestJSON or
renderer is replaced. Baseline rendering precedes fault injection. Browser page
requests outside the selected numeric-loopback origin are blocked and cause
failure. This is page-request instrumentation, not proof that every browser or
operating-system background process is incapable of egress. Test setup's package
retrieval is separate from application operation.

## Receipt and exclusions

The final `MEGALODON_BROWSER_ACCEPTANCE` JSON line names the exact checked-out
commit/tree, OS, Python, Playwright, Chrome and SQLite library/source ID, viewports,
reduced-motion mode, passed checks, and terminal status. Failure output uses fixed
check labels rather than dumping application records or personal paths. No raw
telemetry, database, packet, trace, HAR or screenshot is uploaded by this lane.
Temporary data is synthetic and removed at termination. Read the job log as well
as its conclusion; a missing receipt is not a pass. Repository-native test and
packaging results remain separately attributable to the existing CI jobs.

Concurrent writer/checkpoint acceptance is deliberately **not attempted** in this
browser suite. Record vendor patch evidence before promoting a runtime for that
use: SQLite's [WAL-reset advisory](https://sqlite.org/wal.html#walresetbug) lists
upstream 3.51.3 and backports 3.44.6/3.50.7 as fixed. A lower version string alone
cannot establish the presence or absence of a distribution backport. This test
neither changes SQLite nor bypasses the separate acceptance decision.

A pass does not complete screen-reader/contrast testing, all malformed offline
report classes, installed TShark, native Windows, OS-level egress containment,
long-running storage/capture acceptance, or independent review. Existing native
unit/integration tests continue to cover their own privacy and storage-negative
cases. The current [specification](../SPECIFICATION.md),
[security review](../SECURITY_REVIEW.md), and
[operations runbook](dashboard-operations.md) define the product boundary.
Issue #7's historical closure is preserved; this suite supplies a separately
reviewable continuation, not retroactive proof of its original checklist.
