# Linux dashboard browser acceptance

This opt-in test executes the actual CLI, ingestion/service code, SQLite writer,
separate dashboard reader, HTTP handler, bundled assets, and a real browser.
It does not replace the application with a component fixture. Ordinary pytest
and package installation neither start this browser suite nor require Playwright.
Run results belong to their exact commit and environment; the existence of this
suite is not acceptance, independent review, or a supported-platform promise.

## Prepared environment and execution

From an installed repository checkout on non-root Linux, with Chrome stable,
Xvfb, and the test-only Playwright 1.57.0 package already installed:

```bash
python -m compileall -q megalodon tests
python -m pytest -ra
xvfb-run -a python tests/browser_acceptance.py
```

The companion `.github/workflows/browser-acceptance.yml` runs the last command
on Ubuntu 24.04 with Python 3.11, the runner's existing Chrome, and an isolated
browser profile. Its package-setup step installs the test driver; it does not
install a browser, sensor, daemon, or MEGALODON service. The core package gains
no dependency. The driver is pinned, but transitive packages and the runner image
are not locked; the emitted versions describe one execution, not reproducible
build or compatibility proof for every future Chrome release.

Chrome is headed under a virtual X display so native visibility can be
exercised. The test activates a separate headed browser context/window and
returns focus to the dashboard through real page activation; it never assigns
document.hidden or dispatches visibility events as proof. The test reads native
visibility through bounded test-side polling, then waits separately for
application refresh idle.
Failure labels identify the predicate that missed its deadline. It does not use
an in-page eval poller or add unsafe-eval to the application CSP. Chromium
sandboxing is explicitly requested. Missing Chrome/Xvfb,
root execution, sandbox failure, a policy-blocked loopback, timeout, or assertion
failure returns nonzero. There is no no-sandbox fallback, skip-as-pass path,
proxy, tunnel, browser download, or policy override. Keep the existing required
`test` check unchanged. This additional check is not automatically required by
branch protection and does not supply an independent approval.

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
