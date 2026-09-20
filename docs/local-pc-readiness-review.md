# Local PC readiness review — 2026-09-19

Later alignment and publication: see [the 2026-09-20 record](document-alignment-2026-09-20.md)
and [the Site receipt](site-source-alignment.md). The results and pending-publication
statements below describe the original September 19 review.

Scope: the existing Ubuntu 24.04 checkout, manual foreground startup, local HUD,
and checked-in static reference site. Baseline:
`3bdcfb96a155d5dc4d7009e75f3b3c0986e5590b`, including upstream SQLite native-failure
fixes. Work is on `codex/local-pc-readiness`; the previous source-alignment branch
was preserved. No production or sensor acceptance is implied.

## Findings and corrections

| Finding | Correction |
| --- | --- |
| Startup checks and the launch builder were moved into Evidence → Audit history, while Help directed users to Home | Restore Data and tools to Home, with a working cross-workspace anchor and a structural regression test |
| The hosted installation journey used a historical branch and lacked environment preparation | Add Prepare / Launch / Review guidance, the Python requirement and existing canonical platform documentation links |
| A terminal could select the old default Python or a different working directory | Add `scripts/start-local.sh`, selecting an existing compatible interpreter and anchoring execution to this checkout |
| There was no compact check for the actual default store before launch | Add a read-only preflight that exercises reader admission and a bounded query; absent data remains absent |
| Normal Ctrl+C shutdown produced a traceback; occupied-port errors lacked a next step | Handle normal interruption after resource cleanup and give a `--port` recovery option |
| The repository ignore rules did not cover version-suffixed virtual environments | Ignore `.venv*/` and verify `.venv312` stays untracked |

The first sandboxed suite produced storage ancestry refusals because system
directories appeared owned by UID 65534. In the ordinary host context those
ancestors were root-owned and the baseline passed. No storage guard was relaxed.
The package smoke test also correctly refused a newly created group-writable
temporary working directory; making that disposable test directory private
allowed the smoke check to proceed.

## Validation

- Updated full Python suite: **2,697 passed, 1 skipped**. The skipped check is the
  explicit installed-TShark opt-in lane; it was not enabled for this review.
- After the final installed-wheel launch-message refinement: all **8 preflight
  and launcher tests passed** again.
- After the compact header refinement: **115 focused dashboard and launcher
  checks passed**.
- Static site's Node suites: **39 passed**. Assembled local dashboard JavaScript
  and static script syntax checks passed.
- Repository hygiene, build-input inventory, Python compilation and diff
  whitespace checks passed.
- Wheel and source distributions built using the repository's hash-locked build
  requirements in a disposable environment. The wheel installed without runtime
  dependencies outside the checkout; bundled reference verification passed.
  The source archive includes the executable launcher, guide, preflight and tests.
- Real process checks: occupied-port diagnostic, alternate localhost startup,
  SIGINT shutdown with exit zero and no traceback, and unchanged existing
  database bytes. A missing default store stayed absent.
- Rendered browser review passed for both pages at 1440, 768 and 375px widths,
  without horizontal overflow or console errors. It covered Home setup,
  collapsed disclosures and Help-to-setup navigation/focus. The final header
  puts data scope and refresh details under a closed disclosure: direct browser
  rechecks found 255px workspace height at 1280×720 and 191px at 375×812, with
  working toggling and a fully visible setup heading/eyebrow after navigation.
  The narrow HUD still relies on internal scrolling below fixed navigation.

The PC used `.venv312` with Python 3.12.3 and SQLite 3.45.1. This records the
observed environment, not an upgrade recommendation or security certification.

## Operator handoff

See [local PC setup](local-pc-setup.md). Launch manually with
`./scripts/start-local.sh`; open its printed localhost URL and use Ctrl+C to
stop. No login hook, background service, capture process or firewall operation
was installed. Existing sample audit data was preserved and stays separate from
qualified Traffic and Findings.

The static site changes remain local source pending publication. The historical
Sites deployment/provenance receipt was not changed. Optional tool installation,
live data acquisition and hosted publication are separate work.
