# MEGALODON Documentation Wiki

## A workspace you can inspect

<picture>
  <source media="(prefers-reduced-motion: reduce)" srcset="https://raw.githubusercontent.com/bartytime4life/MEGALODON/b66b1d1458a1e1a564b4452f3ca46d4acc77374c/assets/docs/workspace-reel.png">
  <img src="https://raw.githubusercontent.com/bartytime4life/MEGALODON/b66b1d1458a1e1a564b4452f3ca46d4acc77374c/assets/docs/workspace-reel.gif" alt="Original historical synthetic desktop and mobile Findings views, with a finite editorial trace under finding, linked event, ingestion receipt and distinct-clock labels." width="1200">
</picture>

[Still image](https://raw.githubusercontent.com/bartytime4life/MEGALODON/b66b1d1458a1e1a564b4452f3ca46d4acc77374c/assets/docs/workspace-reel.png). One 4.8-second play, then a static view.
The screenshots are original PR #654 synthetic captures. Motion is editorial;
it does not depict a running current-head application or a new interaction.

**Choose a question:** [trace a finding](investigation-journeys.md#1-what-does-this-finding-actually-show),
[understand a connection](investigation-journeys.md#2-where-does-the-connection-picture-come-from),
or [review host changes](investigation-journeys.md#3-did-a-host-change-make-recovery-necessary-or-possible).
The [current source reading](https://github.com/bartytime4life/MEGALODON/blob/main/docs/current-state.md)
separates this pass from the historical evidence below.

![MEGALODON field guide: understand the signal, inspect the evidence, keep authority explicit.](https://raw.githubusercontent.com/bartytime4life/MEGALODON/395f5f311799743bdf443a69bbb0f0b16e573654/assets/docs/field-guide-cover.png)

## Local defense. Inspectable evidence. Human decisions.

MEGALODON brings bounded network metadata, private SQLite evidence, visual Linux
investigation and separately scoped host workflows into one workspace. It is
useful for investigating connections, understanding recorded findings, reviewing
host changes and preparing evidence-led reports. Optional local AI explains
bounded context; it cannot turn its own proposal into permission.

**Linux reference · Python 3.11+ · Apache-2.0 · No core subscription or cloud account**

| Start here | Go deeper |
| --- | --- |
| [Quick start](quick-start.md) — open the local app | [Technical deep dive](technical-deep-dive.md) — contracts, bounds, identity and authority |
| [Visual tour](visual-tour.md) — synthetic screenshots and animated explainers | [Engineering case studies](engineering-case-studies.md) — decisions and measurable tradeoffs |
| [Practical applications](practical-applications.md) — useful real-world tasks | [Evidence index](evidence-index.md) — exact revisions and interpretation limits |
| [Operator guide](operator-guide.md) — sources, findings and reports | [Security boundaries](security-boundaries.md) — what each interface can do |

## Follow the evidence

<picture>
  <source media="(prefers-reduced-motion: reduce)" srcset="https://raw.githubusercontent.com/bartytime4life/MEGALODON/b24c1d38e1d30b108a021a9ef1d78ef5afdd120c/assets/docs/finding-walkthrough.png">
  <img src="https://raw.githubusercontent.com/bartytime4life/MEGALODON/b24c1d38e1d30b108a021a9ef1d78ef5afdd120c/assets/docs/finding-walkthrough.gif" alt="Moving emphasis over a historical synthetic Findings capture identifies finding, linked event, ingestion receipt and distinct clocks." width="1200">
</picture>

[Still image](https://raw.githubusercontent.com/bartytime4life/MEGALODON/b24c1d38e1d30b108a021a9ef1d78ef5afdd120c/assets/docs/finding-walkthrough.png). Brief motion repeats twice and stops; all labels remain visible.

**Annotated still, not a live session.** The original rendered synthetic capture
is from PR #654 / `424d957` /
[run 39180659477](https://github.com/bartytime4life/MEGALODON/actions/runs/39180659477).
[Provenance and interpretation](visual-tour.md#actual-interface-synthetic-evidence).

## Understand the system

<picture>
  <source media="(prefers-reduced-motion: reduce)" srcset="https://raw.githubusercontent.com/bartytime4life/MEGALODON/b24c1d38e1d30b108a021a9ef1d78ef5afdd120c/assets/docs/evidence-flow.png">
  <img src="https://raw.githubusercontent.com/bartytime4life/MEGALODON/b24c1d38e1d30b108a021a9ef1d78ef5afdd120c/assets/docs/evidence-flow.gif" alt="Explanatory flow from bounded metadata through fixed heuristics and private SQLite evidence to the local inspector and reports." width="1200">
</picture>

[Still image](https://raw.githubusercontent.com/bartytime4life/MEGALODON/b24c1d38e1d30b108a021a9ef1d78ef5afdd120c/assets/docs/evidence-flow.png). Brief motion repeats twice and stops; all labels remain visible.

The three core heuristics identify SYN bursts, distinct-port patterns and long
DNS/UDP query-length metadata. They produce evidence for review, not malware
verdicts. Source qualification, ingestion completion and observation time stay
visible. [Architecture and exact thresholds](technical-deep-dive.md).

## Explore the current capabilities

| Area | Available in source | Keep this distinction |
| --- | --- | --- |
| Network investigation | Atlas, own-account program/socket context, finding inspector, managed history | Approximate geography and bounded observations are not whole-network visibility |
| Host review | Lynis/AIDE, hardening, persistence and passive gateway review | Differences and suggestions need operator interpretation |
| Local AI | Installed-model selection, listener posture admission, bounded advice | Canonical Qwen acceptance remains UNBOUND |
| Recovery evidence | Read-only readiness plus pinned backup/isolated-test receipts | No host restore, backup probing or malware causality |
| Explicit defense | Separate protected Linux workflows and temporary containment | No automatic or permanent blocking; legacy CLI apply still refuses |
| Hosted reference | Address-free snapshot viewer in tab memory | No live PC connection |

## Keep ambition and evidence together

The project explores how local visual investigation, deterministic records,
AI assistance and operator decisions can work together. Its value is the
inspectable connection between those parts. The [builder profile](builder-profile.md)
and [case studies](engineering-case-studies.md) connect design choices to public
artifacts without claiming customer deployment, independent certification or
production detection accuracy.

The historical October 1 benchmark recorded **98.1% fewer OS-written bytes** for
10,000 retained synthetic packet records; query p95 increased from 4.21 ms to
27.06 ms. [Both result and cost](engineering-case-studies.md#1-recording-efficiency-with-a-visible-tradeoff)
remain visible.

**Source basis:** [`main@2cb706039724d9ea0bda09cbd3c17698b15ba55c`](https://github.com/bartytime4life/MEGALODON/commit/2cb706039724d9ea0bda09cbd3c17698b15ba55c), October 22, 2026
(America/Chicago). [Current state](https://github.com/bartytime4life/MEGALODON/blob/main/docs/current-state.md) records
the source map, passing source-head CI/browser/CodeQL runs, open #445/#446 and
remaining host/platform gates. Historical captures and benchmarks keep their
own revisions. This Wiki is generated from `docs/wiki/` after review and merge.

[Local AI](integrations-and-qwen.md) · [Roadmap and limits](roadmap-and-limits.md) ·
[Development](development-and-validation.md) · [Every document](https://github.com/bartytime4life/MEGALODON/blob/main/docs/documentation-map.md)
