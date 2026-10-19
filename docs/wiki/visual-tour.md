# Visual Tour

## Understand the signal. Inspect the evidence.

Deep blue surfaces, cyan highlights and restrained amber accents connect the
workspace to MEGALODON’s identity. Text labels carry meaning alongside color.
Progressive disclosure keeps source, timestamps, scope and uncertainty close
to the finding being reviewed.

## Actual interface, synthetic evidence

![Desktop synthetic Findings inspector: selected PORT_SCAN finding, linked event, ingestion-run receipt, three timestamps and metadata disclosure.](https://raw.githubusercontent.com/bartytime4life/MEGALODON/395f5f311799743bdf443a69bbb0f0b16e573654/assets/docs/finding-inspector-desktop.png)

This is an **actual browser capture**, not a concept mockup. It shows synthetic
documentation addresses in the candidate tested for [PR #654](https://github.com/bartytime4life/MEGALODON/pull/654).
Candidate `424d957472ad121becec635171bc281bec2de995`; workflow run
[39180659477](https://github.com/bartytime4life/MEGALODON/actions/runs/39180659477).
The capture is historical evidence from that run, not a fresh run of this
documentation head or evidence that the installed host works.

| In the picture | Why it matters |
| --- | --- |
| Finding → metadata event → ingestion run | The reader can inspect the recorded chain instead of accepting a severity label alone |
| Event, detection and projection timestamps | A refreshed screen cannot make an old observation new |
| “Historical metadata” and “sensor activity unknown” | Stored evidence is distinct from a working live source |
| Metadata and provenance disclosure | The bounded record and its acquisition limits are inspectable |
| Return to finding | Investigation retains a way back to the selected result |

### The narrow view keeps the same questions

<img src="https://raw.githubusercontent.com/bartytime4life/MEGALODON/395f5f311799743bdf443a69bbb0f0b16e573654/assets/docs/finding-inspector-mobile.png" alt="Actual 390-pixel synthetic inspector capture, reflowed to show the finding and recorded evidence without a desktop table." width="390">

The same run captured a 390 × 1000 viewport. This demonstrates that candidate’s
rendered reflow, not native browser zoom or screen-reader acceptance.
Captures use documentation addresses and contain no live host records.
Exact hashes and capture details are in [the asset record](https://github.com/bartytime4life/MEGALODON/blob/main/assets/docs/README.md).

## Architecture, with authority kept separate

![Architecture illustration: bounded inputs feed a deterministic evidence core and local visual HUD; local advice and operator authority remain separate.](https://raw.githubusercontent.com/bartytime4life/MEGALODON/3c81889ba37953e997620c8bf15b3c1239bfc103/assets/wiki/evidence-architecture.png)

This image is an **architecture illustration**, not a screenshot. Bounded inputs
pass validation and fixed rules before private storage. Views read qualified
evidence. Optional local models explain bounded context; they do not authorize
host actions. Fixed operator workflows have separate checks and outcomes.

## Explore the network without inventing certainty

The local connection atlas presents recent accepted metadata at approximate IP
locations. Direction follows observed send/receive activity. Unmapped endpoints
remain in the text roster; arcs do not measure physical packet routes. Pause,
reduced motion, hidden views and stale data constrain animation.

Inspect [the atlas contract](https://github.com/bartytime4life/MEGALODON/blob/a380fe0d60f798106bf05c29729ca7cce91cca67/docs/live-connection-globe.md),
[implementation](https://github.com/bartytime4life/MEGALODON/blob/a380fe0d60f798106bf05c29729ca7cce91cca67/megalodon/dashboard_globe.py) and
[UI tests](https://github.com/bartytime4life/MEGALODON/blob/a380fe0d60f798106bf05c29729ca7cce91cca67/tests/test_dashboard_live_globe.py). These links identify
source and test assertions; their existence is not an exact-head test result.

## Give each kind of evidence its own place

| Surface | What the operator reads | What remains separate |
| --- | --- | --- |
| HUD | Atlas, resources, source status and network directory | Geographic approximation and collection completeness |
| Findings | Fixed-rule findings and their event/run inspector | Advice, contextual reference hits and host observations |
| Setup / Sensors | Installed tools, configured scope and workflow status | Presence, health and admitted data |
| Host security | Lynis audit, AIDE changes and dated reference matches | Confirmed vulnerability, malware verdict or permission to act |
| Reports / Evidence | Local reports and bounded retained records | Missing intervals and incompatible packet/flow units |

See [host security](https://github.com/bartytime4life/MEGALODON/blob/a380fe0d60f798106bf05c29729ca7cce91cca67/docs/host-security.md),
[workspace behavior](https://github.com/bartytime4life/MEGALODON/blob/a380fe0d60f798106bf05c29729ca7cce91cca67/docs/visual-operations-defense.md), and
[the HTTP contract](https://github.com/bartytime4life/MEGALODON/blob/a380fe0d60f798106bf05c29729ca7cce91cca67/docs/dashboard-http-contract.md).

## Show the engineering cost alongside the win

![Historical synthetic benchmark: 98.1 percent fewer OS-written bytes with 10,000 records retained in both runs; history-query p95 increased from 4.21 to 27.06 milliseconds.](https://raw.githubusercontent.com/bartytime4life/MEGALODON/3c81889ba37953e997620c8bf15b3c1239bfc103/assets/wiki/recording-result.png)

This is a **historical benchmark illustration**, not a current health display.
Read the [measurement and tradeoff](engineering-case-studies.md#1-recording-efficiency-with-a-visible-tradeoff).
No production accuracy, SSD lifetime, live PC state, or independent certification
is claimed by these visuals.

[Quick start](quick-start.md) · [Case studies](engineering-case-studies.md) · [Evidence index](evidence-index.md)
