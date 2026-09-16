# Defense Console source alignment

Readback date: 2026-09-16. This receipt separates the hosted reference console,
local Python implementation and native operational acceptance.

| Identity | Observed value |
| --- | --- |
| Existing Site | [MEGALODON Defense Console](https://megalodon-defense-console.blackbart-55.chatgpt.site) |
| Project / slug | `appgprj_6aaa2be9d9288191a15a9c1d743af0b3` / `megalodon-defense-console` |
| Version | 14 — `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_b7c5ddfa657081918be5b6584f557006` |
| Source commit | `875b63b661f297c35162303f621349e727587f85` in the existing Sites source repository |
| Deployment | `appgdep_6aab03cd3be48191b3bb20f52330c894`, succeeded at `2026-09-16T21:02:27.150283Z` |
| Access | Owner-private, access revision 1; no viewer/editor groups or external shares |
| Server archive digest | `sha256:7968558e55f9b5f2e1b7893475292ffb842f30f1f6da98a7cb1b7e4ee29230d1` |
| Product baseline inspected | `0e71cd41627fe2d2bffde7c2ddd222b475f73bc1` |
| Retained rollback | Version 13; source `463c9d7e411ceaa86666babe1e24426cb88877f1`; contains the older demonstration and lifecycle defects |

## Exact source and artifact scope

`site/` matches all ten tracked Sites source files byte-for-byte: README,
`.openai/hosting.json`, seven `dist/` assets including the new `lifecycle.js`, and
`tests/readiness.test.cjs`. The archive contains eight files: the normalized
hosting manifest plus seven deployable assets. README and tests are not deployed.
The Python source distribution still excludes the independent Site mirror; its
two interoperability tests explicitly skip when those assets are absent.

Version 14 removes all generated network observations, charts, detection counts,
protocol shares, fixture receipts and the refresh interval. Missing telemetry
is **unavailable**, not zero, clean or healthy. Real stored evidence remains in
the local dashboard. No hosted connector or live sensor has been added.

The integration registry separates self-reported installation notes (persistent
browser `localStorage`) from unauthenticated readiness imports (page memory only).
Command identity, role selection, installation method and container lifecycle
labels were corrected. Copying a command neither executes it nor updates the
installation note. See [findings](evidence-alignment-review.md).

## Validation and limits

- Full repository pytest run passed: 2,240 tests, with three native/installed-tool
  skips; 2,243 tests collected. The unchanged parametrized subtest cases ran within
  that suite. No displayed lifecycle operation was executed.
- 32 Node checks passed, covering the parser, asynchronous import races, lifecycle
  identity/roles, empty telemetry and application startup/navigation with a DOM stub.
- Real Python readiness output parsed successfully through the Site validator.
- JavaScript syntax, ten-file parity, diff checks and nine-page Wiki validation passed.
- Sites confirmed successful deployment. This plain-static project has no compatible
  managed preview server. No current screenshot or rendered-browser acceptance is
  claimed; a DOM stub and the local Python dashboard's browser CI are different proof.

GitHub PR delivery and a successful Site deploy are distinct. This run uses a draft
PR and does not mark it ready, merge it, release software, change sharing, expose
the local dashboard or authorize host/model operations.

## Earlier checkpoints

Version 13/source `463c9d7e411ceaa86666babe1e24426cb88877f1` added lifecycle controls
through merged PR #243. Its three automated review findings are corrected here.
Version 11/source `c0865c0cec760f66a694c04d1108e061bf739358` was mirrored by merged
PR #242; the Wiki link repair #240 is also merged. Those are historical source
states, not the current Site. Older versions remain available in Site history.
