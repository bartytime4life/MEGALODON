# Documentation polish and source reconciliation — October 22, 2026

Status: **documentation candidate; source behavior OBSERVED, local checks VERIFIED
only as recorded below.** Source basis:
[`2cb706039724d9ea0bda09cbd3c17698b15ba55c`](https://github.com/bartytime4life/MEGALODON/commit/2cb706039724d9ea0bda09cbd3c17698b15ba55c),
tree `3c4773603fa90e13d627d0fb107b45f8e986b079`.
Dates use America/Chicago. The earlier [October 22 reconciliation](documentation-refresh-2026-10-22.md)
retains its older pin, test counts and outcomes; this pass does not rewrite it.

## Public documentation scope

The root README and generated Wiki now lead with implemented capabilities,
realistic applications, source limits and technical evidence. Existing deep CLI
recipes remain available in the README's expandable reference. Two new Wiki
chapters cover technical internals and practical investigations. Current-state,
dependency, browser, HTTP, governing-document orientation and Site scope are
reconciled with merged #660/#662/#663/#664/#665. No application runtime,
dependency, schema, workflow, fixture or original acceptance receipt is changed.

All 164 Markdown documents are accounted for in the [complete catalog](documentation-map.md)
and read programmatically for inventory, local links and targeted stale-claim
searches. Current entry pages and the changed capability contracts were checked
against named implementation paths. This is not a manual technical audit of
every paragraph or a refresh of all historical research. Preserve historical
plans, case-study pins, upstream versions and result counts as historical.

The attached September architecture/research documents remain planning sources,
not public runtime evidence. Their new current-reading prefaces preserve the
prior bytes underneath and grant no host/model authority. Private coordination
content is kept out of public Markdown and visual examples.

## Capability corrections

| Area | Current source interpretation |
| --- | --- |
| Playwright | Merged #660 supplies 1.64.0 with an exact native-focus profile and wheel lock; it is no longer an open proposal |
| macOS fixture | Merged #662 qualifies safe temporary ancestry/writer readback without relaxing production checks; native platform parity remains separate |
| Local AI | Merged #663 admits listener posture before model inventory; no new model execution authority or canonical Airlock acceptance |
| Recovery readiness | Merged #664 projects AIDE evidence gaps with restore eligibility always false |
| External backup evidence | Merged #665 checks separately pinned private records only; it opens no backup, performs no test and enables no host restoration |
| Public queue | #445/#446 remain open; no open PR existed before this candidate. Queue state is not acceptance |
| Hosted viewer | Sites metadata re-read: existing PC Snapshot Console v67 with owner-private audience. No source, audience or publication change; no fresh visual or parity claim |

The source basis has observed successful CI `39878396530`, Linux browser
`39878396547` and CodeQL `39878396556`. These are not documentation-candidate
checks, a new security scan, installed-host evidence or independent clearance.
[Current-state table](current-state.md#exact-source-head-checks-observed).

## Motion, accessibility and privacy

Four finite GIFs explain evidence, AI authority, recovery evidence and a finding
inspector. They have matching PNGs, descriptive alt text, reduced-motion picture
sources and explicit still links. Every diagram label remains visible; only
emphasis moves. Motion repeats twice and stops after 4.8 seconds total. Binary
assets stay below the repository's 1 MiB limit. Clients may vary in their picture
handling, so the visible still links remain essential.

Three visuals are explanatory technical diagrams from public source constants.
The inspector animates emphasis over the entire historical synthetic PR #654
still; it does not fabricate a UI recording or prove current-head rendering.
The established cover and original captures retain their sources. See
[asset provenance](../assets/docs/README.md) and the
[motion byte manifest](../assets/docs/motion-provenance.json).

No real telemetry, account identity, private workstation capture, home-network
configuration, private contact, token, credential, customer record or Drive
excerpt was added as a public example. Fixed public repository identities and
synthetic documentation addresses are used. Hygiene checks are a bounded guard,
not proof that every possible private string can be detected automatically.

## Validation

From the reviewed repository root in an isolated Python 3.12 test environment:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_PLUGINS='' PYTEST_ADDOPTS='' \
  python -m pytest -o addopts='' -q \
  tests/test_documentation_currentness.py tests/test_wiki_sync.py \
  tests/test_capabilities.py tests/test_hub.py tests/test_readiness.py
bash .github/scripts/sync-wiki.sh --validate
python tools/build_input_inventory.py --check
python tools/check_repository_hygiene.py
python -m compileall -q tools/render_documentation_motion.py
git diff --check
```

The existing documentation/catalog/Wiki selection passed **88 tests**. A separate
source-claim check of recovery readiness, backup admission, listener consent and
the recovery panel passed **141 tests** (229 total across the two selections). Wiki validation generated
**15 files**, including sidebar/footer, without publishing. Build-input inventory
passed without regeneration. Local Markdown/HTML file and heading checks,
catalog coverage (164 files / 1,026 local targets), image bounds/bytes, GIF timing,
visual inspection and hygiene results are recorded in the candidate's PR. A local checker is verification
scaffolding, not a new runtime component. Test-environment installation used
package indexes and is not a hash-verified CI wheelhouse receipt.

No full pytest, fresh application-browser run, native platform, real model,
producer, external backup or installed-host acceptance was performed for this
prose/graphics change. The image review covers generated assets and source
layout; exact GitHub mobile rendering remains a separate presentation check.
External links were not globally crawled. No new Codex Security scan was run.

## Lifecycle and rollback

Changes live on an `agent/*` branch with a draft PR. Human GitHub review and
exact-head lifecycle gates precede a merge. The existing post-merge workflow
publishes Wiki source; this task does not manually push the native Wiki or
publish a Site. Rollback reverts documentation/tooling/assets only, with no
runtime migration or host change. No branch protection or approval setting was
changed. The safest next gate is review of the exact draft head.
