# Defense Console source alignment

Readback date: 2026-09-16. This record distinguishes the deployed static Site
from local Python runtime implementation and operational acceptance.

| Identity | Observed value |
| --- | --- |
| Existing Site | [MEGALODON Defense Console](https://megalodon-defense-console.blackbart-55.chatgpt.site) |
| Project | `appgprj_6aaa2be9d9288191a15a9c1d743af0b3` |
| Slug | `megalodon-defense-console` |
| Version | 10 — `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_5182e7ab02a0819192a007bc07c4072f` |
| Source commit | `bcdb20cd1458b8fcfa6a43a89163d77a02f36367` in the existing Sites source repository |
| Deployment | `appgdep_6aaaef2587f0819185b323ad8af3923d`, succeeded at `2026-09-16T19:34:14.399205Z` |
| Access | Owner-private, access revision 1; no viewer/editor groups or external shares |
| Server archive digest | `sha256:14c1c80bd1d2630653008726904182532f2ae2816bb89430a78ab55920549058` |
| Product baseline summarized | `98a708ae7b7fece400f529acc70bbf9f4b48c4fb` |
| Retained rollback | Version 9; source `205e898bcfc20ccc49b3742f8f27d662720656d9` |

## Mirror and boundaries

`site/` mirrors the nine source files byte-for-byte: `README.md`,
`.openai/hosting.json`, the six files under `dist/`, and the source-owned
`tests/readiness.test.cjs`. The deployed archive
contains seven files (hosting manifest and six assets), excluding README and
tests. The importer regressions live under `site/tests/readiness.test.cjs` and
`tests/test_site_readiness.py`, outside the deployable Site. Python source
distributions do not bundle the independent Site mirror; those two Site tests
explicitly skip when its assets are absent.

The Site remains a browser-only prototype. Its activity and linked evidence
records are labeled synthetic. The optional readiness report stays in page
memory and is never uploaded. Executable presence and manual notes do not prove
installation integrity, compatibility, a running sensor, or host protection.
The new readiness command is candidate code pending its GitHub draft review;
the deployed Site labels that dependency instead of implying it is on main.
The separate local Suricata dashboard candidate is not connected to this Site.

## Verification limits

JavaScript syntax, asset references, 25 Node contract tests, Python-to-Site
schema compatibility, and independent adversarial review passed. The Site
service confirmed successful deployment, exact source version and unchanged
access. This is not rendered-browser acceptance: Chromium download failed and
the available browser rejected local preview access. The deployment supplied
no v10 screenshot; an older cached screenshot is not evidence for this version.
Complete an owner-visible walkthrough before claiming visual acceptance.

A public GitHub source mirror does not change private Site access. No repository
merge, software release, remote local-dashboard exposure, sensor launch, model
request, installer, or host-control path is authorized by this record.
