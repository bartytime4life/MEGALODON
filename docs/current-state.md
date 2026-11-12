# Current state and evidence boundaries

## November 11 source orientation

**Source basis:** [`main@418fa54474f3f77d0758e94aab5735a516d8c43b`](https://github.com/bartytime4life/MEGALODON/commit/418fa54474f3f77d0758e94aab5735a516d8c43b),
tree `f0e47918ed0f6715197e944e6cb18e221ea498d5`. PR [#774](https://github.com/bartytime4life/MEGALODON/pull/774)
merged at `2026-11-12T00:03:54Z` (November 11 in America/Chicago). This is the
current reading for maintained guides; the November 9 and October sections below
remain historical at their own pins.

| Task | Implemented behavior | Meaning / guide |
| --- | --- | --- |
| Choose the next evidence task | Guided HUD recommendation, direct Findings/connections/Reports routes, closed optional-app inventory | Uses a validated current snapshot; unavailable, stale, paused, stopped capture and empty sensor windows remain distinct. Navigation and refresh do not start tools. [HUD guide](dashboard-operations.md#read-the-interface-in-evidence-order) |
| Inspect sensor context | Connection-summary guidance works independently of packet-capture state; alert context routes to the connection lens | Sensor observations are separate from the saved Findings queue and from unique incidents. [Source and coverage](background-tools.md) |
| Search and change selection | Query and selection revisions reject obsolete successes and failures; reports retain only the current selection's document and findings | A→B→A and browser-history restoration are covered. [Knowledge](security-knowledge.md), [Reports](efficient-recording-reports.md), [Setup](setup-console.md) |
| Read local learning and setup status | Paused learning is labeled explicitly; failed configuration reads mark Traffic and Local AI unavailable without erasing the saved model | Saved baseline, explanation activity, app heartbeat and model readiness remain separate observations. [Setup](setup-console.md), [learning](security-knowledge.md) |
| Compare historical patterns | Indexed eligible history and exact count-based protocol-share comparisons | No rounded threshold decision, new risk score or field-accuracy claim. [Comparison arithmetic](security-knowledge.md#exact-comparison-arithmetic-and-indexed-history) |
| Read resource percentages and reports | CPU tick deltas aggregate before conversion; intermediate resource means retain precision until final output | Counts, denominators and missing values keep their own meaning. [Recording and reports](efficient-recording-reports.md) |

These changes follow [#769](https://github.com/bartytime4life/MEGALODON/pull/769),
[#771](https://github.com/bartytime4life/MEGALODON/pull/771),
[#772](https://github.com/bartytime4life/MEGALODON/pull/772),
[#773](https://github.com/bartytime4life/MEGALODON/pull/773) and
[#774](https://github.com/bartytime4life/MEGALODON/pull/774). The code paths and
regression selections are indexed in the [refresh record](documentation-refresh-2026-11-11.md).

### Verification and remaining gates

The merged tree is byte-identical to PR #774's tested candidate
`316ece33fe5067eeabf49a9ef5e7fd80ba563e34`. Its recorded local full suite passed
**7,843 tests and 743 subtests**, with **27 explicit native/platform skips**.
The candidate also passed **18 hosted technical checks**, including
[CI](https://github.com/bartytime4life/MEGALODON/actions/runs/43120825489),
[browser acceptance](https://github.com/bartytime4life/MEGALODON/actions/runs/43120825538)
and [CodeQL](https://github.com/bartytime4life/MEGALODON/actions/runs/43120825649).
These remain candidate receipts, not newly executed post-merge or documentation
checks. Synthetic desktop, tablet and phone checks and package verification
have their own [recorded limits](documentation-refresh-2026-11-11.md#application-evidence-carried-forward).

Fresh issue readback found [#750](https://github.com/bartytime4life/MEGALODON/issues/750)
(partial Stage 0 no-effect boundary), [#732](https://github.com/bartytime4life/MEGALODON/issues/732)
(model staging/library follow-up) and [#445](https://github.com/bartytime4life/MEGALODON/issues/445)
(exact Zeek producer qualification) open. This is a dated issue observation,
not permission to operate or a claim that these are the only remaining gates.
Operational model generation remains [UNBOUND](qwen-runtime-unbound.md);
source delivery, owner merge authorization, installation, real sensor/model
acceptance, release and deployment remain separate. The documentation refresh
does not change an installed PC or publish a Site.

## November 9 source orientation

**Source basis:** [`main@d03bc43d13a9f030cfcff7eb8beaea5fc318abae`](https://github.com/bartytime4life/MEGALODON/commit/d03bc43d13a9f030cfcff7eb8beaea5fc318abae).
This section describes the inspected source. It supplies no new hosted CI,
rendered-browser, installed-PC, native-parser or real-model acceptance result.
The October records below retain their original pins and check receipts.

| Task | Implemented source behavior | Boundary / guide |
| --- | --- | --- |
| Inspect a downloaded program | Signed-in Linux HUD submission; bounded structural and identification adapters; completed metadata survives a later adapter's isolation-setup refusal | Optional runtime and host isolation prerequisites; partial coverage stays visible; the submitted program is never launched and receives no safety verdict. [Inspection guide](file-inspection.md) |
| Prepare and review local model files | Explicit installed-model discovery/selection, offline file verification, pinned GGUF staging and source/license review controls | Maintenance and the separate fixed response diagnostic do not activate operational inference. The release fence remains **UNBOUND**, including for other model families. [Model library](model-library.md), [runtime hold](qwen-runtime-unbound.md) |
| Select the Stage 0 application boundary | A one-way, process-local latch exposes the in-memory status command and refuses ordinary CLI dispatch plus named HUD, provider, companion, installer, startup/reopen and native TShark entries | Partial [#750](https://github.com/bartytime4life/MEGALODON/issues/750) implementation; trusted Python entry fences are not OS network/filesystem containment or universal helper coverage. [Exact scope](offline-analysis.md#stage-0-application-entry-fence--issue-750) |

Use a fresh process for Stage 0. Selection cannot stop existing workers or undo
earlier activity; ordinary fresh-process installed operation retains its separate
authority. Synthetic regression coverage and boundary status do not supply
producer qualification, model provenance, loaded-byte verification, independent
review or owner acceptance. Historical issue closure does not lift the model
hold. The maintained guides above describe the current operator steps; the
[November 9 improvement record](project-improvements-20261109.md#follow-up-retained-history-and-setup-focus) preserves its
separate local validation scope.

## October 27 reading

**Source basis:** [`main@7c912322b12fe40fbe92de79b32fdc678054a3da`](https://github.com/bartytime4life/MEGALODON/commit/7c912322b12fe40fbe92de79b32fdc678054a3da);
tree `f56752b3cd5d4aa9e70d058f6474ae6c5a37f862`. Source files were reconstructed
in an isolated snapshot and all **1,033 Git blob identities** matched this tree
before editing. The primary checkout's unfinished application work was preserved.

| Read now | Observed source behavior | Limit |
| --- | --- | --- |
| [Findings](findings-review.md) | Refine a bounded returned page, inspect a finding, request optional local advice and save an assessment | Empty results, severity and model text do not establish safety or malicious intent |
| [Setup](setup-console.md) | Source/tool configuration and selected-model readiness controls | Presence, operation, admitted data and model qualification stay separate |
| [Atlas](live-connection-globe.md) | Recorded send/receive directions at approximate IP locations | Arcs are endpoint illustrations, not physical packet routes |
| [Recovery evidence](host-backup-evidence.md) | Two receipt hashes pinned by a separate operator-controlled trust record | Trust is not independently hash-pinned; rewriting all three files can forge evidence; no host-file restore |
| [Qwen record](https://github.com/bartytime4life/MEGALODON/blob/7c912322b12fe40fbe92de79b32fdc678054a3da/config/model-bindings/qwen.unbound.json) | Canonical owner binding remains UNBOUND / NOT_RECORDED | A working runtime model or zero-effect test does not complete canonical acceptance |

The [three investigation journeys](wiki/investigation-journeys.md) connect these
surfaces. [This documentation pass](documentation-refresh-2026-10-27.md) records
its tests, visual provenance and omissions. The October 22 implementation
inventory below remains historical at its own pin; it is not a fresh hosting,
queue, platform or installed-PC observation.

### October 27 source-head checks

These are observed GitHub results for the exact source SHA, separate from this
documentation candidate's checks:

| Workflow | Result | Meaning |
| --- | --- | --- |
| [CI 40552674917](https://github.com/bartytime4life/MEGALODON/actions/runs/40552674917) | success | Hosted repository checks; not installed-host acceptance |
| [CodeQL 40552674698](https://github.com/bartytime4life/MEGALODON/actions/runs/40552674698) | success | Static-analysis result; not independent security clearance |
| [Qwen zero-effect 40552674943](https://github.com/bartytime4life/MEGALODON/actions/runs/40552674943) | success | Named zero-effect workflow; not real-provider containment or canonical model acceptance |
| [Linux browser 40552674797](https://github.com/bartytime4life/MEGALODON/actions/runs/40552674797) | cancelled | No successful exact-source-head browser result claimed |

## Historical October 22 source orientation

**Documentation basis — October 22, 2026 (America/Chicago).**
Source: [`main@2cb706039724d9ea0bda09cbd3c17698b15ba55c`](https://github.com/bartytime4life/MEGALODON/commit/2cb706039724d9ea0bda09cbd3c17698b15ba55c);
tree `3c4773603fa90e13d627d0fb107b45f8e986b079`.

**OBSERVED** below means source or authoritative external state was read in this
pass. **VERIFIED** requires a named local check and its result. Code presence,
passing CI, approval, merge, publication and installed-host acceptance are
different facts. This page is descriptive; the specification and security
review retain their normative authority.

## What exists at this pin

| Area | OBSERVED implementation | Limit / primary source |
| --- | --- | --- |
| Metadata core | Typed `PacketEvent`, three fixed heuristics, private SQLite audit | No packet payloads or payload-derived hashes. [Models](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/megalodon/models.py), [detector](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/megalodon/detector.py), [specification](../SPECIFICATION.md) |
| Linux workspace | HUD, Findings, Sensors, Setup, Reports, Evidence and Help | Core reader and protected action routes have different authority. [HTTP contract](dashboard-http-contract.md) |
| Finding inspector | Finding → linked event → ingestion run; distinct clocks | Bounded returned-page evidence, not sensor liveness. [Control room](control-room-contract.md#qualified-finding-evidence-inspector) |
| History and reporting | Segments, compact summaries, local visual reports and fixed schedules | Defaults: 14 days / 20 GiB; reports 9 AM local time. Gaps and source units remain explicit. [Managed history](managed-evidence.md), [reports](efficient-recording-reports.md) |
| Sources and companions | Twelve catalog entries; bounded TShark, Zeek, Suricata and separate HUD collector paths | Installed/running/configured/admitted are distinct. Static plans execute nothing. [Offline analysis](offline-analysis.md), [background tools](background-tools.md) |
| Host review | Lynis, AIDE, hardening posture, persistence, passive gateway and own-account process/network context | Source-specific coverage and bounds; no compromise verdict. [Host security](host-security.md) |
| Recovery readiness | Validated AIDE projection; missing backups/causality/conflict evidence stays visible | Always `restore_eligible=False`, `backup_state=not_integrated`. [Projection](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/megalodon/recovery_readiness.py), [PR #664](https://github.com/bartytime4life/MEGALODON/pull/664) |
| External backup evidence | Read-only trust/backup/isolated-test receipt admission; raw-byte pins, identities, chronology and expiry | Opens no backup, runs no test and grants no host restore. [Contract](host-backup-evidence.md), [validator](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/megalodon/backup_evidence.py), [PR #665](https://github.com/bartytime4life/MEGALODON/pull/665) |
| Local models | Optional installed-model selection, bounded explanations, closed proposals; listener admission precedes inventory | Runtime selection is distinct from canonical Airlock acceptance. [Provider](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/megalodon/ai_provider.py), [PR #663](https://github.com/bartytime4life/MEGALODON/pull/663), [model selection](local-model-selection.md) |
| Firewall interfaces | Legacy CLI apply refuses; separate protected Linux HUD temporary containment exists | Documentation grants no permission to operate it. [Defense contract](visual-operations-defense.md) |
| Desktop lifecycle | Private per-user install/update/rollback; managed user HUD; optional login startup | Saved monitoring choices retain separate scope. [Setup](local-pc-setup.md) |
| Browser qualification | Playwright 1.64.0, exact native-focus driver profile and lock from merged #660 | No operational/platform acceptance follows from a dependency repair. [Dependency policy](dependency-policy.md), [browser acceptance](dashboard-browser-acceptance.md) |
| License | Apache-2.0 | Artifact notices, provenance and release gates remain separate. [LICENSE](../LICENSE), [NOTICE](../NOTICE) |

## Hosting observation

The Sites service was re-read in this pass: existing **PC Snapshot Console v67**,
owner-private access configuration, same Site identity and current URL. This is
an **OBSERVED metadata result**, not a rendered browser test or a new deployment.
No Site source, audience or deployment was changed. Current deployment-source
parity and installed-PC revision remain UNKNOWN. The
[documented viewer](../site/README.md) imports address-free summaries into tab
memory and has no live PC connection. Older empty-410 retirement records remain
historical; v67 metadata does not recreate their source proofs.

## Corrections to older orientation material

| Older claim | Present interpretation |
| --- | --- |
| “The whole application is read-only/plan-only” | True for named core reader / legacy CLI interfaces; protected Linux HUD workflows are separate |
| “No scheduler, feed or watcher exists” | General automation remains inert; fixed local schedules, configured collectors and explicit public reference refreshes exist |
| “File changes prove malware or recoverability” | AIDE differences lack malicious causality and host restoration authority |
| “Valid backup receipts mean backups are integrated” | They are external evidence admission only; no executable host-recovery integration |
| “A working local model completes Qwen acceptance” | Runtime selection is separate; canonical record remains UNBOUND / NOT_RECORDED |
| “Playwright 1.64.0 is an open proposal” | Superseded by merged #660; earlier 1.63.0 timeout and macOS fixture failures keep their original run identities |
| “No license” or old issue counts | Historical research; Apache-2.0 exists and live tracking must be re-read |

## Remaining public gates

At this readback there were two open issues and no open PRs before this
documentation branch. These queue facts are dated observations, not acceptance.

| Issue | Gate |
| --- | --- |
| [#445](https://github.com/bartytime4life/MEGALODON/issues/445) | One exact Zeek offline producer qualification; owner selection is not producer acceptance |
| [#446](https://github.com/bartytime4life/MEGALODON/issues/446) | Canonical Qwen binding, zero-effect, containment and evaluation acceptance; [record](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/config/model-bindings/qwen.unbound.json) remains UNBOUND / NOT_RECORDED |

Merged #662 changes the macOS fixture/workflow qualification, not production
ancestry policy. Native JSONL/browser, Intel, second-major-version and retained
operator evidence remain separate in the [macOS M-track](macos-core-acceptance.md).
Neither source presence nor synthetic Windows/macOS jobs establish Linux parity.

## Exact source-head checks observed

GitHub returned these completed results for the exact source SHA above:

| Workflow / run | OBSERVED result / scope |
| --- | --- |
| [CI 39878396530](https://github.com/bartytime4life/MEGALODON/actions/runs/39878396530) | success; repository workflow result, not installed-host acceptance |
| [Linux browser acceptance 39878396547](https://github.com/bartytime4life/MEGALODON/actions/runs/39878396547) | success; hosted browser suite, not a fresh documentation-candidate run |
| [CodeQL 39878396556](https://github.com/bartytime4life/MEGALODON/actions/runs/39878396556) | success; static-analysis workflow result, not whole-product security clearance |

The earlier `0acdf72` browser timeout and #660/#661 macOS `/var` failures
remain in their historical run/PR records. They are not current-head failures.
No native macOS/Windows, release, recovery, producer or real-model acceptance at
this pin is claimed from these three runs. The [owner lifecycle contract](exact-head-owner-lifecycle.md)
retains its workflow-trust and enforcement limits; no protection setting changed.

## What the visuals prove

Original Findings captures come from PR #654, candidate
`424d957472ad121becec635171bc281bec2de995`,
[run 39180659477](https://github.com/bartytime4life/MEGALODON/actions/runs/39180659477).
The animated walkthrough adds emphasis to a still image; it is not a recording
of a running session. Other new animations are technical diagrams built from
public constants. [Asset provenance](../assets/docs/README.md) records bytes,
scope and still alternatives. No private workstation or Drive data is published.

The October 1 98.1% write-reduction benchmark is a finite historical synthetic
measurement with increased query p95. It is not a current performance guarantee.
[Tradeoff and source](wiki/engineering-case-studies.md#1-recording-efficiency-with-a-visible-tradeoff).

## Keep the documentation current

Read code/tests at a named revision; update maintained guides when behavior
changes; preserve original dates, pins and results in historical records.
Validate the complete catalog, local links and generated Wiki. The Wiki's
post-merge publisher owns native publication; a draft does not update it live.
[Current polish scope](documentation-polish-2026-10-22.md) and
[earlier October 22 reconciliation](documentation-refresh-2026-10-22.md)
record separate passes, not interchangeable test receipts.
