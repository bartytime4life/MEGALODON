# Visual Tour

## A visual language for evidence

MEGALODON uses a dark technical palette, luminous directional traffic, compact resource displays, and progressively disclosed detail. The goal is a workspace an operator can read, with uncertainty visible in the same interface as the attractive graphics.

The graphics on this Wiki are original architecture and benchmark illustrations. **They are not application screenshots or live telemetry.** The source-linked tour below describes implemented UI behavior without displaying private network records.

![Architecture illustration with observe, qualify, explain, local advice, and operator authority.](https://raw.githubusercontent.com/bartytime4life/MEGALODON/3c81889ba37953e997620c8bf15b3c1239bfc103/assets/wiki/evidence-architecture.png)

## 01 — Read the network, then inspect an endpoint

The full-width connection atlas presents recent accepted metadata at approximate IP locations. Directional light follows observed send/receive activity; incoming rings mark observed sources, without turning them into attack verdicts. The network directory below it separates interface groups and retains a searchable text roster.

Camera follow, rotation, drag and keyboard controls support exploration. Pause, reduced motion, hidden views and stale data suppress animation. Unmapped endpoints remain in the details. Geographic arcs are a presentation of endpoints, not measured packet routes.

Inspect [the atlas contract](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/docs/live-connection-globe.md), [globe implementation](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/megalodon/dashboard_globe.py), and [UI contract tests](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/tests/test_dashboard_live_globe.py).

## 02 — Give the operator a clear next action

HUD keeps the resource strip, network view and background-tools action close together. Findings separates detection results from advice. Sensors describes what tools are doing; Setup contains capture scope, storage, installed models and sign-in. Reports and Evidence provide deeper inspection without filling the main view with setup details.

Status must survive without color. The [merged status/accessibility repair #522](https://github.com/bartytime4life/MEGALODON/pull/522) adds visible distinctions, while [#523](https://github.com/bartytime4life/MEGALODON/pull/523) gives installed-but-idle apps a half-filled status dot. Labels still determine meaning; a green light alone cannot establish connected data or security.

Inspect [workspace behavior](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/docs/visual-operations-defense.md) and [the shared UI assets](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/megalodon/dashboard_assets.py).

## 03 — Turn observations into a shareable local report

Reports aggregate retained evidence across bounded source pages, identify gaps, and keep packet and sensor-flow units separate. The operator can save self-contained HTML or use the browser’s print dialog. Technical exports live under Advanced exports. Local daily/weekly scheduling runs with the HUD service and handles daylight-saving intervals.

Inspect [report rendering and scheduling](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/megalodon/reporting.py), [report and DST tests](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/tests/test_reporting.py), and [report evidence and limitations](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/docs/efficient-recording-reports.md). This tour does not claim native print pagination or fresh browser acceptance of the application.

## 04 — Show the cost of a design choice

![Benchmark illustration: OS-written bytes fell from 400,125,952 to 7,479,296, with 10,000 retained records in both runs and query p95 increasing from 4.21 to 27.06 ms.](https://raw.githubusercontent.com/bartytime4life/MEGALODON/3c81889ba37953e997620c8bf15b3c1239bfc103/assets/wiki/recording-result.png)

The chart uses one shared bar scale and names its workload and date. A matched text table and the full limitations appear in the [case study](engineering-case-studies.md). The design shows the tradeoff alongside the headline result.

[Meet the builder](builder-profile.md) · [Inspect the engineering](engineering-case-studies.md) · [Verify the evidence](evidence-index.md)
