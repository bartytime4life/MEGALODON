# Defense Console source alignment

Readback date: 2026-09-16. This record distinguishes the deployed static Site
from local Python runtime implementation and operational acceptance.

| Identity | Observed value |
| --- | --- |
| Existing Site | [MEGALODON Defense Console](https://megalodon-defense-console.blackbart-55.chatgpt.site) |
| Project | `appgprj_6aaa2be9d9288191a15a9c1d743af0b3` |
| Slug | `megalodon-defense-console` |
| Version | 11 — `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_f6bc47bdef348191a01fff8994f86945` |
| Source commit | `c0865c0cec760f66a694c04d1108e061bf739358` in the existing Sites source repository |
| Deployment | `appgdep_6aaaf2b73774819196049947252ea3fb`, succeeded at `2026-09-16T19:49:30.321770Z` |
| Access | Owner-private, access revision 1; no viewer/editor groups or external shares |
| Server archive digest | `sha256:f97c25aa7e46920c03fae14a2156158789c159ae6e98bdd3305d5355c8f72c1d` |
| Product baseline summarized | `5583ac1d7f465757a0375d64cf1c18ee7c47ade9` |
| Retained rollback | Version 10; source `bcdb20cd1458b8fcfa6a43a89163d77a02f36367` (version 9 also retained) |

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
The readiness command was merged in [#241](https://github.com/bartytime4life/MEGALODON/pull/241);
the local Suricata startup view was merged in
[#239](https://github.com/bartytime4life/MEGALODON/pull/239). Version 11 updates
only guidance, labels and provenance to reflect those deliveries. The hosted
Site is not connected to the local dashboard or Suricata store.

## Verification limits

JavaScript syntax, asset references, 25 Node contract tests, Python-to-Site
schema compatibility, and independent adversarial review passed. The Site
service confirmed successful deployment, exact source version and unchanged
access. This is not rendered-browser acceptance: Chromium download failed and
the available browser rejected local preview access. The normal deployed URL was also checked and showed the ChatGPT sign-in gate;
the app was not accessible in that browser session. No current app screenshot
was obtained; an older cached screenshot is not evidence for this version.
Complete an owner-visible walkthrough before claiming visual acceptance.

Historical checkpoint: v10 deployed at `2026-09-16T19:34:14.399205Z` from
`bcdb20cd1458b8fcfa6a43a89163d77a02f36367` as
`appgdep_6aaaef2587f0819185b323ad8af3923d`. Version 11 preserves its behavior
and removes the now-stale pending-merge wording after the owner-account merges.
This engineering run created draft PRs; it did not mark ready or merge them.

A public GitHub source mirror does not change private Site access. No repository
merge, software release, remote local-dashboard exposure, sensor launch, model
request, installer, or host-control path is authorized by this record.
