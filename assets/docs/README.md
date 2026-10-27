# Documentation visual sources

These assets are public documentation material, with no live PC records,
credentials, private paths or payloads. Image meaning is repeated in adjacent
Markdown text. No external font, analytics script or live data request is used.

| Asset | Origin | Meaning and scope |
| --- | --- | --- |
| `field-guide-cover.png` | Composition using the existing `assets/megalodon-github-hero-compact.png` identity and local DejaVu Sans type | Editorial cover, not a product screenshot, certification badge or status display |
| `finding-inspector-desktop.png` | Exact original `candidate-selected-1440-top.png`, PR #654 | Actual synthetic candidate browser viewport, 1440 × 1000; historical run, not live PC telemetry |
| `finding-inspector-mobile.png` | Exact original `candidate-selected-390-top.png`, PR #654 | Actual synthetic candidate browser viewport, 390 × 1000; no native zoom/screen-reader acceptance claim |
| `capture-provenance.json` | Selected fields/entries from the original browser manifest | Candidate SHA, run, HTML digest, image SHA-256, state, viewport, scroll location and limits |

The capture candidate is `424d957472ad121becec635171bc281bec2de995`, from
[workflow run 39180659477](https://github.com/bartytime4life/MEGALODON/actions/runs/39180659477).
The images retain their original bytes and documentation-only addresses. They
were inspected during this documentation pass. This reuse does not rerun browser
acceptance, certify the current main build, or prove installed-host behavior.

| Capture | SHA-256 |
| --- | --- |
| Desktop | `da6bd1a7ad79e5b3adee6852df0aaf925265aef12419690c32d9594caef665ce` |
| Mobile | `ae9cf8dae1a57c6fcdd94cf84cb59e3755de789f960278cfa07044b1eb960572` |

The older `assets/wiki/evidence-architecture.png` and `recording-result.png`
remain architecture/benchmark illustrations from
`tools/render_wiki_showcase.py`. Their historical source pin is preserved;
neither depicts live telemetry. The October 1 benchmark keeps its original
workload, timings, counts and tradeoff.

GitHub README images use repository-relative paths. Wiki image URLs use the
immutable asset commit; the Wiki is generated only through the normal
post-merge workflow. Do not publish Wiki source manually ahead of its reviewed
assets. Reverting this documentation commit removes only presentation changes;
there are no runtime migrations or data changes.

## Finite animated explainers — October 22, 2026

| GIF and matching PNG | Meaning / input |
| --- | --- |
| `evidence-flow` | Typed metadata, fixed rules, private evidence and bounded local inspection; explanatory diagram |
| `model-authority` | Listener-first admission, untrusted advice and separate operator authority; explanatory diagram |
| `recovery-evidence` | AIDE, external pinned records and held host restoration; explanatory diagram |
| `finding-walkthrough` | Entire historical synthetic desktop capture scaled proportionally with moving outlines and a separate annotation strip; no fabricated UI interaction |

These assets use public constants at `2cb706039724d9ea0bda09cbd3c17698b15ba55c` and the previously recorded
synthetic capture. No new private source, host read or Drive material is used.
[motion-provenance.json](motion-provenance.json) records exact bytes/digests.
Reproduce with `python tools/render_documentation_motion.py` using Pillow and
local DejaVu fonts; no application import or network is used.

Each GIF plays twice for 4.8 seconds total, then stops. Labels do not animate,
flash or disappear. PNGs show all emphasis regions simultaneously. README/Wiki
pictures request PNGs for reduced motion and always expose an explicit still
link; GitHub rendering behavior and client preferences may vary. All essential
meaning also appears in adjacent Markdown tables. No video player, script,
analytics, live badge or external rendering service is embedded.

Wiki motion URLs pin immutable asset commit `b24c1d38e1d30b108a021a9ef1d78ef5afdd120c`. The root README uses
relative paths so branch previews load their matching bytes. The native Wiki
publishes through its existing post-merge workflow, after those assets exist on
reviewed main. Reverting documentation does not change application state.


## October 27: moving paths, original screens

| Asset pair | Origin and interpretation |
| --- | --- |
| `workspace-reel.gif` / `.png` | The two original historical PR #654 captures resized proportionally, uncropped, on one editorial canvas. The moving trace is outside the screenshots. No UI interaction is fabricated. |
| `signal-path.gif` / `.png` | Original technical schematic of metadata admission, fixed rules, retained evidence and review at source `7c912322b12fe40fbe92de79b32fdc678054a3da`. Motion represents record direction, not measured routes or throughput. |

Both GIFs play once for **4.8 seconds** and retain a final still; no GIF loop
extension is present. Labels remain static. Reduced-motion picture sources and
explicit PNG links accompany their use. Each is below 1 MiB; the original
screenshots and their provenance remain unchanged.

Reproduce using a Pillow-compatible Python interpreter with local DejaVu fonts:

```bash
python tools/render_workspace_reel.py
python tools/render_signal_path.py
```

`workspace-reel-provenance.json` and `signal-path-provenance.json` record exact
asset hashes and source limits. Wiki images pin asset commit `b66b1d1458a1e1a564b4452f3ca46d4acc77374c`;
README image links follow the checked-out branch. These files add no runtime
dependency, external data request or service. Original captures are historical,
not evidence of installed-PC behavior or current-application acceptance.
