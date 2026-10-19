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
