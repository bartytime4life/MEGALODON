# Documentation refresh — November 11, 2026

## Source and scope

The source basis is merged
[`main@418fa54474f3f77d0758e94aab5735a516d8c43b`](https://github.com/bartytime4life/MEGALODON/commit/418fa54474f3f77d0758e94aab5735a516d8c43b),
tree `f0e47918ed0f6715197e944e6cb18e221ea498d5`. GitHub records PR
[#774](https://github.com/bartytime4life/MEGALODON/pull/774) merged at
`2026-11-12T00:03:54Z`, November 11 in America/Chicago. The primary checkout
is preserved; this refresh uses an isolated documentation branch.

The maintained README, field guide, operator instructions, security/API
references, technical chapters and Wiki source are reconciled to this source.
The complete [catalog](documentation-map.md) accounts for Markdown documents
across root, guides, contracts, templates, Site scope, fixtures and media
provenance. Dated plans, measurements, reviews and acceptance records retain
their original source pins and results. Catalog coverage is not a line-by-line
security audit or acceptance of every historical claim.

## Current behavior documented

| Area | Current reading | Source / regressions |
| --- | --- | --- |
| Guided HUD | State-derived next step; read-only Findings, connection and Reports routes; optional app inventory disclosed on demand | [Operations UI](../megalodon/dashboard_operations.py), [composition](../megalodon/dashboard_polish.py), [guided states](../tests/test_dashboard_guided_overview.py) |
| Evidence and navigation | Sensor alert context is separate from saved Findings; sensor summaries do not depend on packet capture; connection fragments restore the HUD through browser history | [Workspace mapping](../megalodon/dashboard_assets.py), [navigation tests](../tests/test_dashboard_boundaries.py) |
| Query and selection | Old successes and failures cannot overwrite a newer reference query or device selection; report documents/findings remain bound to the selected report and view revision | [Knowledge UI](../megalodon/dashboard_intelligence.py), [knowledge regressions](../tests/test_dashboard_intelligence_ui.py), [Reports UI](../megalodon/dashboard_reports.py) |
| Learning and setup | Paused learning, saved baseline and explanation activity are distinct; failed configuration reads invalidate Traffic/AI status without erasing model choice or independent app observations | [Configuration UI](../megalodon/dashboard_support_config.py), [Setup](../megalodon/dashboard_settings.py), [status regressions](../tests/test_dashboard_support_config_ui.py) |
| Pattern arithmetic | Indexed eligible history and exact integer count comparisons preserve threshold decisions | [Pattern engine](../megalodon/security_patterns.py), [math tests](../tests/test_pattern_comparison_math.py) |
| Resource arithmetic | Integer CPU tick aggregation precedes conversion; resource aggregation defers rounding until final output | [Host telemetry](../megalodon/host_telemetry.py), [reporting](../megalodon/reporting.py), [telemetry tests](../tests/test_host_telemetry.py), [report tests](../tests/test_reporting.py) |
| Setup and authorization | Six categories replace old paths; enabled tool sessions obtain their per-launch token automatically through a guarded local request; explicit confirmation and capability-specific request checks remain | [Setup guide](setup-console.md), [tool-management boundary](tool-heartbeat.md), [HTTP contract](dashboard-http-contract.md) |

The correction does not turn a port hint into an application identity, a sensor
label into an incident, a missing observation into safety, or a fixed model
diagnostic into operational inference acceptance.

## Application evidence carried forward

PR #774's candidate `316ece33fe5067eeabf49a9ef5e7fd80ba563e34` has exactly
the merged source tree above. The recorded candidate evidence is:

- Local CPython 3.12 full suite: **7,843 passed, 743 subtests passed, 27 skipped**
  in 257.45 seconds, with pytest plugin autoload disabled, inherited/ambient
  capabilities dropped and owner-private temporary storage.
- Wheel/sdist build and changed-source parity passed. An extracted-sdist
  selection passed **129 tests**; a fresh index-free wheel environment passed
  **nine shipped-JavaScript inert-DOM cases**. These are private disposable
  environments, not the user's installed HUD.
- **18 hosted technical checks passed** on that candidate, including
  [CI](https://github.com/bartytime4life/MEGALODON/actions/runs/43120825489),
  [Linux browser acceptance](https://github.com/bartytime4life/MEGALODON/actions/runs/43120825538)
  and [CodeQL](https://github.com/bartytime4life/MEGALODON/actions/runs/43120825649).
- Synthetic rendered review covered desktop 1440×1000, tablet 768×1024 and
  phone 390×844, keyboard disclosure, task routes, browser Back and stable
  Refresh focus. The preview refused all mutations and furnished no live
  telemetry. Independent visual review used root-captured screenshots because
  the reviewer's browser was unavailable; no different-provider reviewer was
  available. This is not full WCAG or screen-reader acceptance.

The 27 skips preserve opt-in native/private file-inspector, installed
TShark/ClamAV/socket, browser-component and platform conditions. These counts
belong to the application candidate; this prose refresh does not rerun or
relabel them as documentation-candidate, installed-PC or operational proof.

## Documentation validation

Fresh documentation-candidate validation used CPython 3.12 with pytest plugin
autoload disabled, inherited/ambient capabilities dropped and an owner-private
temporary directory. **440 tests passed** in 4.01 seconds, with no skips:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_PLUGINS='' PYTEST_ADDOPTS='' \
setpriv --inh-caps=-all --ambient-caps=-all .venv/bin/python -m pytest -o addopts= -ra \
  tests/test_documentation_currentness.py tests/test_repository_currentness.py \
  tests/test_wiki_sync.py tests/test_license_metadata.py \
  tests/test_heartbeat_controls.py tests/test_dashboard_boundaries.py \
  tests/test_ollama_model_test.py tests/test_qwen_runtime_gate.py \
  tests/test_stage0_boundary.py --basetemp=/absolute/owner-private/test-output
```

Use the reviewed environment's interpreter and create the owner-private parent
directory first. The selection checks documentation contracts, Wiki generation,
token behavior, navigation, the fixed diagnostic and refusal boundaries; it does
not operate a provider or native capture. The catalog matches all **190 Markdown
paths**. **1,282 local Markdown/image/HTML file targets and ATX/explicit anchors**
resolve with no missing target. External URLs are not crawled, and this static
check does not establish rendered link behavior. Wiki validation
prepares **16 files** without publishing; diff checks pass. Current application
source, tests, runtime configuration and historical media bytes are unchanged.

The broader static repository audit retains a known limitation: it exits 1 on
both the unchanged application tree and this candidate because it cannot resolve
the twelve `setup-app-*` targets generated by JavaScript. Both runs have 267
static controls, no duplicate IDs and the same twelve missing static anchors.
The [app-card generator](../megalodon/dashboard_integrations.py) creates those
IDs at runtime; the navigation/heartbeat tests remain the separate behavior
evidence. This result is preserved rather than reported as a clean static pass.

## Publication and historical material

The native GitHub Wiki is generated from `docs/wiki/` through the existing
post-merge publisher. Local projection validation and a documentation PR are
separate from public Wiki publication. Existing media remains historical or
explanatory as labeled; no private recordings, workstation data or Drive
excerpts are added to the repository.

Connected project coordination and blueprint documents receive a new dated
current-reading checkpoint while preserving earlier entries. Proposed native
platform work remains proposed. Source, tests, hosted CI, owner review/merge,
Wiki publication, installed state, native producer/model acceptance and Site
deployment retain separate meanings.
