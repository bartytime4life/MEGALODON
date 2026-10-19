# MEGALODON Documentation Wiki

![MEGALODON field guide: understand the signal, inspect the evidence, keep authority explicit.](https://raw.githubusercontent.com/bartytime4life/MEGALODON/395f5f311799743bdf443a69bbb0f0b16e573654/assets/docs/field-guide-cover.png)

## A defense workspace you can inspect

MEGALODON connects bounded network metadata, a private SQLite evidence trail,
visual Linux investigation, and separately scoped local workflows. Its design
keeps three questions visible: **What was observed? What supports this finding?
Who authorizes the next step?**

Built under [Andy’s project direction](https://github.com/bartytime4life), this
is an inspectable portfolio of AI-assisted product design, systems engineering,
security judgment and evidence-led delivery.

## Take the two-minute tour

| Explore | What you will find |
| --- | --- |
| [Visual tour](visual-tour.md) | Actual synthetic desktop/mobile captures, architecture and readable limits |
| [Engineering case studies](engineering-case-studies.md) | Concrete problems, decisions, tradeoffs and source evidence |
| [Builder profile](builder-profile.md) | Product direction, collaboration method and technical interview prompts |
| [Evidence index](evidence-index.md) | Exact revisions, capture provenance, historical measurements and open gates |

## Follow a finding all the way back

![Synthetic Findings inspector showing one finding, linked event, ingestion receipt and separate timestamps.](https://raw.githubusercontent.com/bartytime4life/MEGALODON/395f5f311799743bdf443a69bbb0f0b16e573654/assets/docs/finding-inspector-desktop.png)

*Actual rendered synthetic candidate, PR #654 / `424d957` / run
[39180659477](https://github.com/bartytime4life/MEGALODON/actions/runs/39180659477).
No live PC telemetry is shown. [Read the capture scope](visual-tour.md#actual-interface-synthetic-evidence).*

## Choose your next step

| Task | Guide |
| --- | --- |
| Open the local Linux app | [Quick start](quick-start.md) |
| Understand sources, findings and reports | [Operator guide](operator-guide.md) |
| Understand what local AI and tools can do | [Integrations and local AI](integrations-and-qwen.md) |
| Review trust and authority | [Security boundaries](security-boundaries.md) |
| Inspect current capability limits | [Roadmap and current limits](roadmap-and-limits.md) |
| Build or improve the project | [Development and validation](development-and-validation.md) |
| Find every repository document | [Complete documentation catalog](https://github.com/bartytime4life/MEGALODON/blob/main/docs/documentation-map.md) |

## A measured tradeoff, openly reported

The October 1 synthetic benchmark recorded **98.1% fewer OS-written bytes** for
10,000 retained packet records; history-query p95 rose from 4.21 ms to 27.06 ms.
Both the result and cost are visible in the [storage case study](engineering-case-studies.md#1-recording-efficiency-with-a-visible-tradeoff).
It is a historical finite measurement, not a production-capacity promise.

**Documentation basis:** [`main@a380fe0d60f798106bf05c29729ca7cce91cca67`](https://github.com/bartytime4life/MEGALODON/commit/a380fe0d60f798106bf05c29729ca7cce91cca67),
2026-10-19 UTC / October 18 in America/Chicago. Historical case studies and
captures retain their own pins. [Current state](https://github.com/bartytime4life/MEGALODON/blob/main/docs/current-state.md)
explains what exists and what remains unproved. The host application is the
local Linux HUD; the separate [PC Snapshot Console](https://github.com/bartytime4life/MEGALODON/blob/main/site/README.md)
has no live host connection. This Wiki is generated from `docs/wiki/`.
