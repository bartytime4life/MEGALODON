# Evidence Index


## Latest documentation reading — November 11

The current source reading is
[`418fa54474f3f77d0758e94aab5735a516d8c43b`](https://github.com/bartytime4life/MEGALODON/commit/418fa54474f3f77d0758e94aab5735a516d8c43b),
November 11 in America/Chicago (the #774 merge was November 12 UTC).
[Current source orientation](https://github.com/bartytime4life/MEGALODON/blob/main/docs/current-state.md#november-11-source-orientation)
and the [refresh record](https://github.com/bartytime4life/MEGALODON/blob/main/docs/documentation-refresh-2026-11-11.md)
separate implementation, prior candidate validation, merge identity and checks
performed for this documentation pass.

| Merged change | Exact source/test evidence | Limit |
| --- | --- | --- |
| [#769](https://github.com/bartytime4life/MEGALODON/pull/769), current report selection | [Report client](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/megalodon/dashboard_reports.py), [behavior tests](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/tests/test_dashboard_reports_ui.py) | Current identity/revision and pagination retry; not report completeness or installed acceptance |
| [#771](https://github.com/bartytime4life/MEGALODON/pull/771), exact/indexed hourly comparison | [Math tests](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/tests/test_pattern_comparison_math.py), [saved benchmark](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/docs/benchmarks/pattern-comparison-20261111.json) | Exact admission and finite synthetic timing/allocation evidence; no field accuracy or capacity claim |
| [#772](https://github.com/bartytime4life/MEGALODON/pull/772) / [#773](https://github.com/bartytime4life/MEGALODON/pull/773), resource arithmetic | [Telemetry tests](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/tests/test_host_telemetry.py), [report tests](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/tests/test_reporting.py) | Aggregation/rounding behavior; no additional measurement precision or sensor-health proof |
| [#774](https://github.com/bartytime4life/MEGALODON/pull/774), guided evidence and stale-state repair | [Guidance tests](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/tests/test_dashboard_guided_overview.py), [intelligence tests](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/tests/test_dashboard_intelligence_ui.py), [support tests](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/tests/test_dashboard_support_config_ui.py) | Source-mode guidance and current-view claims; no model/sensor execution or operator authorization |

Earlier #774 checks belong to candidate
`316ece33fe5067eeabf49a9ef5e7fd80ba563e34`. Its tree matches the merged #774
source, but identity agreement does not create a post-merge workflow run. The
refresh record retains the exact candidate results and fresh-check scope.

## Historical documentation reading — October 27

[Current source and exact workflow results](https://github.com/bartytime4life/MEGALODON/blob/main/docs/current-state.md#october-27-reading)
use source `7c912322b12fe40fbe92de79b32fdc678054a3da`.
[Validation and limits for this pass](https://github.com/bartytime4life/MEGALODON/blob/main/docs/documentation-refresh-2026-10-27.md)
are separate from the historical records below. The current-source browser run
was cancelled; a successful CI or CodeQL run does not supply the missing browser
result. The new moving visuals are labeled editorial compositions or diagrams,
with no new live-host claim.

> **Historical documentation orientation — 2026-10-22:** source `main@2cb706039724d9ea0bda09cbd3c17698b15ba55c`. The original October 11 case-study baseline below remains historical. That reading added Lynis/AIDE, dated threat context and the qualified-finding inspector. The separate Site was a PC Snapshot Console, superseding the historical retirement claim. [Current state](https://github.com/bartytime4life/MEGALODON/blob/main/docs/current-state.md) records the distinction.

## Verify the claim at its actual scope

Showcase baseline: GitHub `main@4da7fae0d8df2d8cd6b3ff93964055f7e14972bb`, read on October 11, 2026 UTC (October 10 in America/Chicago). The [baseline commit](https://github.com/bartytime4life/MEGALODON/commit/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb) includes merged PR #548. Case-study source links use this immutable revision. Current operator guides may advance after this snapshot.

| Claim | Primary evidence | What it proves |
| --- | --- | --- |
| Lower writes in a finite synthetic workload | [Benchmark JSON](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/docs/benchmarks/efficient-recording-comparison.json) | The saved comparison’s counts, timings, implementation hashes and scope |
| Bounded network visualization | [Atlas contract](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/docs/live-connection-globe.md), [Tests](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/tests/test_live_connections.py) | Documented behavior and regression assertions, not complete network visibility |
| Local reports and DST handling | [Source](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/megalodon/reporting.py), [Tests](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/tests/test_reporting.py), [#547](https://github.com/bartytime4life/MEGALODON/pull/547) | Implemented scheduling/report logic and the merged interval repair |
| Security fixes are merged | [#524](https://github.com/bartytime4life/MEGALODON/pull/524), [#525](https://github.com/bartytime4life/MEGALODON/pull/525), [#534](https://github.com/bartytime4life/MEGALODON/pull/534), [#538](https://github.com/bartytime4life/MEGALODON/pull/538) | Exact change/review history; no whole-product clearance |
| Model authority remains bounded | [Adapter](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/megalodon/qwen_advisory.py), [Sentinel tests](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/tests/test_qwen_zero_effect.py) | Scoped denial and advisory behavior, not native provider acceptance |
| Canonical Qwen acceptance is pending | [UNBOUND record](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/config/model-bindings/qwen.unbound.json), [#446](https://github.com/bartytime4life/MEGALODON/issues/446) | No owner binding decision is recorded in that source |
| Historical empty-410 retirement | [Retirement record](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/site/README.md), [Version 63 record](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/docs/site-source-alignment.md) | Historical source/publication provenance at that pin; later restored as a snapshot viewer |

## Status words carry meaning

**Implemented** means code exists. **Tested** needs a named check and revision. **Merged** is a repository state. **Published** is an externally verified artifact. **Installed** or **running** needs a host observation. **Accepted** requires the scoped decision/evidence. None automatically establishes the next.

**Unavailable** means no usable evidence is available; **unknown** means the evidence cannot answer the question; **degraded** means limited or incomplete; **stale** means old or refresh-failed. These are not safety or compromise verdicts.

## Remaining public tracking

At the October 22 readback, [#445](https://github.com/bartytime4life/MEGALODON/issues/445) (exact Zeek offline producer qualification) and [#446](https://github.com/bartytime4life/MEGALODON/issues/446) (Qwen Airlock binding/zero-effect acceptance) are open. [#345](https://github.com/bartytime4life/MEGALODON/issues/345) closed after #656; that does not establish full native macOS acceptance. Merged #660 supplies Playwright 1.64.0; source-head CI, Linux browser acceptance and CodeQL succeeded. Earlier failures keep their historical run identities. Later native producer or model evidence must be checked at its own revision; issue closure alone would not prove acceptance.

No customer count, employment credential, production detection rate, native platform parity, or independent certification is claimed by this showcase. Private Drive coordination records and local captures are not published as portfolio evidence. The public repository is the review surface.

## Original graphics

The two PNG diagrams are generated by [tools/render_wiki_showcase.py](https://github.com/bartytime4life/MEGALODON/blob/3c81889ba37953e997620c8bf15b3c1239bfc103/tools/render_wiki_showcase.py) using Pillow and local DejaVu fonts. They contain architecture text and checked-in synthetic benchmark aggregates, with no private telemetry, external assets or executable content. Their image links pin commit `3c81889ba37953e997620c8bf15b3c1239bfc103`. All essential information is also presented as Wiki text or tables.

[Case studies](engineering-case-studies.md) · [Security boundaries](security-boundaries.md) · [Roadmap](roadmap-and-limits.md)

## Historical October 22 additions and visual provenance

| Item | Identity | Interpretation |
| --- | --- | --- |
| Qualified finding inspector | [PR #654](https://github.com/bartytime4life/MEGALODON/pull/654), present in `2cb706039724d9ea0bda09cbd3c17698b15ba55c` | Bounded finding/event/run trace; no sensor-liveness claim |
| Actual desktop/mobile captures | Candidate `424d957472ad121becec635171bc281bec2de995`, [run 39180659477](https://github.com/bartytime4life/MEGALODON/actions/runs/39180659477) | Historical synthetic rendered evidence; no installed-host or fresh documentation-head browser acceptance |
| Lynis/AIDE and cached references | [Host-security contract](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/host-security.md), [collector](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/megalodon/support_workflows.py) | Explicit bounded workflows; suggestions, changes and feed matches remain context |
| Static companion catalog | [Source](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/megalodon/capabilities.py) | Twelve entries including Lynis/AIDE; listing does not prove installed tools |
| Snapshot viewer | [Site scope](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/site/README.md); last recorded October 17 Site readback reports v67; Sites metadata was re-read on October 22: v67, owner-private; no fresh rendered or deployment-source parity check | Separate address-free import viewer, without live PC access or source-parity claim |

The [asset record](https://github.com/bartytime4life/MEGALODON/blob/main/assets/docs/README.md)
binds screenshot hashes and viewport/state provenance. New image URLs pin immutable asset commit
`395f5f311799743bdf443a69bbb0f0b16e573654`; source bytes are versioned with this documentation packet. They are presentation
assets, not signed evidence or a telemetry feed. No private Drive contents or
private workstation telemetry are published.

## Historical October 22 source and animation additions

| Claim | Source / check | Exact limit |
| --- | --- | --- |
| Recovery readiness | [Projection](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/megalodon/recovery_readiness.py), [#664](https://github.com/bartytime4life/MEGALODON/pull/664) | Read-only; restore eligibility always false |
| External backup records | [Validator](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/megalodon/backup_evidence.py), [#665](https://github.com/bartytime4life/MEGALODON/pull/665) | Pinned-record agreement, no backup/test execution or safe-restore claim |
| Listener-first inventory | [Provider](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/megalodon/ai_provider.py), [#663](https://github.com/bartytime4life/MEGALODON/pull/663) | Scoped admission repair, no canonical model acceptance |
| Historical source-head workflows | [CI 39878396530](https://github.com/bartytime4life/MEGALODON/actions/runs/39878396530), [browser 39878396547](https://github.com/bartytime4life/MEGALODON/actions/runs/39878396547), [CodeQL 39878396556](https://github.com/bartytime4life/MEGALODON/actions/runs/39878396556) | Observed successes at `2cb706039724d9ea0bda09cbd3c17698b15ba55c`; no documentation-candidate or installed-host run |

Four new GIFs have matching PNGs and a [byte manifest](https://github.com/bartytime4life/MEGALODON/blob/b24c1d38e1d30b108a021a9ef1d78ef5afdd120c/assets/docs/motion-provenance.json).
They play twice for 4.8 seconds total with fixed labels; reduced-motion pictures
and still links are supplied. The inspector uses an annotated historical still;
the other three are explanatory diagrams. They do not fabricate live telemetry
or execute a workflow. Asset links pin `b24c1d38e1d30b108a021a9ef1d78ef5afdd120c`.
