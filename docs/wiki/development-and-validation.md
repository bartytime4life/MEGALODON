# Development and Validation

> [Documentation field guide](https://github.com/bartytime4life/MEGALODON/blob/main/docs/README.md) · [Complete catalog](https://github.com/bartytime4life/MEGALODON/blob/main/docs/documentation-map.md). Preserve historical pins and counts; update maintained guides when behavior changes.

Keep changes narrow, source-pinned, and reviewable. Documentation, plans, issue
state, and model output are inputs; repository source, tests, and explicit human
decisions determine implementation status.

## Contributor setup

Use Python 3.11 or newer in an isolated environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[test]"
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q megalodon tests
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_PLUGINS='' PYTEST_ADDOPTS='' \
  .venv/bin/python -m pytest -ra
```

Do not add the capture extra or launch an external analyzer merely to run the
unit suite. Never use real captures, credentials, private paths, databases, or
sensitive telemetry as fixtures.

## Validation by change type

- **Core input or storage:** exercise success, rejection, interruption, capacity, identity, and no-side-effect paths.
- **Dashboard or HUD:** run focused dashboard/control-room suites, JavaScript syntax checks, real-browser acceptance when available, and a narrow mobile viewport check.
- **Adapters and integrations:** prove closed schemas, fixed arguments/endpoints, limits, provenance, and refusal of unreviewed execution or egress.
- **Security boundaries:** add exact refusal assertions and demonstrate that the prohibited side effect did not occur.
- **Documentation:** verify every command and link against the same revision; distinguish delivered code from operational acceptance.

For documentation changes, run the existing currentness and static-catalog
checks as well as Wiki projection; retain skipped/environment-only checks:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_PLUGINS='' PYTEST_ADDOPTS='' \
  .venv/bin/python -m pytest -q tests/test_documentation_currentness.py \
  tests/test_wiki_sync.py tests/test_capabilities.py tests/test_hub.py tests/test_readiness.py
python tools/build_input_inventory.py --check
```

Useful focused Wiki checks:

```bash
bash .github/scripts/sync-wiki.sh --validate
.venv/bin/python -m pytest -q tests/test_wiki_sync.py
git diff --check
```

The Wiki publisher transforms `docs/wiki/README.md` into `Home.md`, converts
Wiki-local links, regenerates `_Sidebar.md` and `_Footer.md`, and records an
ownership manifest. The native Wiki is a projection; edit the source packet so a
later publication cannot reintroduce stale content.

## Before review

- Record the exact base commit and branch head.
- List changed behavior, unchanged boundaries, negative controls, commands, outcomes, skips, and remaining gates.
- Check for overlapping work and preserve unrelated local changes.
- Keep proposed capabilities labeled as proposed.
- Treat green CI as revision evidence, not independent review, release approval, or deployment authorization.

The full contribution contract is in [CONTRIBUTING.md](../../CONTRIBUTING.md).

## Current regression map

The November source reading is `418fa54474f3f77d0758e94aab5735a516d8c43b`.
The following checks protect the recent merged behavior; listing a test does
not claim it was rerun for this documentation revision.

| Change | Focused checks | Negative controls to retain |
| --- | --- | --- |
| [#769](https://github.com/bartytime4life/MEGALODON/pull/769), report selection | `tests/test_dashboard_reports_ui.py` / `reports_selection_browser.cjs` | Automatic/manual replacement, expiry, A→B→A stale responses, failed-page retry at the same offset |
| [#771](https://github.com/bartytime4life/MEGALODON/pull/771), exact/indexed comparisons | `tests/test_pattern_comparison_math.py` | Exact/near-threshold rational expectations, large counts, source separation, duplicate hours, null inventory interface and one-pass history reads |
| [#772](https://github.com/bartytime4life/MEGALODON/pull/772) / [#773](https://github.com/bartytime4life/MEGALODON/pull/773), resource arithmetic | `tests/test_host_telemetry.py`, `tests/test_reporting.py` | Tick-sum overrun, missing process values, repeated compaction and metric-specific missing-sample weights |
| [#774](https://github.com/bartytime4life/MEGALODON/pull/774), guided and asynchronous UI | `tests/test_dashboard_guided_overview.py`, `tests/test_dashboard_intelligence_ui.py`, `tests/test_dashboard_support_config_ui.py`, `tests/test_dashboard_boundaries.py` | Summary mode with stopped capture, sensor/admitted-finding separation, delimiter collision, held-read focus, fragment history, stale search/device successes and failures, unavailable support summaries |

These JavaScript behavior checks require Node; a skip is missing coverage.
Rendered desktop/mobile checks additionally assess layout, focus and disclosure
behavior. Keep their fixture, viewport and exact source identity with the
receipt; browser mocks do not establish those rendered results.

On Linux where inherited capabilities affect acceptance tests, use the
[capability-free test-launch policy](../../CONTRIBUTING.md#controlled-pytest-execution-in-ci)
and an owner-private `--basetemp`. Do not enable capture, native analyzers or
model inference to eliminate an opt-in skip. Full source, wheel/sdist, hosted
technical, rendered-browser, installed-host and independent/owner acceptance
remain distinct proof lanes. The
[November refresh record](https://github.com/bartytime4life/MEGALODON/blob/main/docs/documentation-refresh-2026-11-11.md)
identifies which checks belong to the earlier candidate, merged tree or fresh
documentation pass.

## Documentation visuals and privacy

The finite explainers are reproduced with `python tools/render_documentation_motion.py`
using Pillow and local DejaVu fonts. They import no application runtime, read no
host telemetry and make no network requests. Confirm the byte manifest, dimensions,
GIF duration/loop count, PNG alternatives and sub-1-MiB binary limit before review.
Keep essential information in adjacent text and tables. Repository-relative README
assets and immutable Wiki asset URLs serve different rendering contexts.

Read every tracked Markdown document for inventory/link checks; reconcile current
entry pages and changed source contracts; keep old acceptance receipts, research
versions and original case-study pins intact. The complete catalog distinguishes
historical/design material from maintained operator guidance. Never copy private
coordination, real reports, credentials or workstation details into public examples.

## Layered review evaluation

The [offline evaluation guide](https://github.com/bartytime4life/MEGALODON/blob/main/docs/layered-evaluation.md)
describes the bundled 25-case corpus, separately declared labels, candidate
workload, reference correctness, stability and cost reports. Synthetic provenance
checks do not establish installed-PC detection usefulness or false-positive rates.
