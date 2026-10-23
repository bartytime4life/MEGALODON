# Current state and evidence boundaries

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
