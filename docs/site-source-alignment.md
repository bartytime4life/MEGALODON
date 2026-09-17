# Defense Console source alignment

Readback refreshed: 2026-09-17 against repository
`main@c19f63f1fbb6d37bb44acb4880de3abb284b3131`, draft PR
[#264](https://github.com/bartytime4life/MEGALODON/pull/264), and the Sites
project record. This receipt separates the hosted reference console,
repository mirror, local Python implementation, and native operational
acceptance.

| Identity | Observed value |
| --- | --- |
| Existing Site | [MEGALODON Defense Console](https://megalodon-defense-console.blackbart-55.chatgpt.site) |
| Project / slug | `appgprj_6aaa2be9d9288191a15a9c1d743af0b3` / `megalodon-defense-console` |
| Version | 16 — `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_854e979de5d08191b476b33331359ef5` |
| Source commit | `e9f218760aec26bd092dd6d826da095903da3f5c` in the existing Sites source repository |
| Deployment | `appgdep_6aab835bb224819183dfabbea28633fd` succeeded at `2026-09-17T06:06:28.941490Z` |
| Access | `custom`, revision 1; only the owner account is allowed, with no groups, editors, or external visitors |
| Server archive digest | `sha256:11996ba0bfeec6a0f6e6af57b5a5a7e39e2cfbd21bb25444c2068a05b3e3d75e` |
| Hosted artifact baseline | Version 16 receipt at source `e9f218760aec26bd092dd6d826da095903da3f5c` |
| Current repository baseline | `c19f63f1fbb6d37bb44acb4880de3abb284b3131` |
| Draft repository mirror | PR #264 commit `d54687acc4ddf5340565a7fbbd7ca18251c8af42` |
| Repository/hosted equality | **VERIFIED for the thirteen `site/` source files** at the draft mirror commit; the ten-file server archive remains a separately normalized deployment artifact |
| Retained rollback | Version 15; source `cba088ceb88f3cf3ab718a2f2933d8b6fb5b16e6` |

## Exact source and artifact scope

The repository tracks thirteen Sites source files: README,
`.openai/hosting.json`, nine deployable assets (including
`site/dist/index.html` and `site/dist/styles.css`), and two Node test files. The
version 16 server archive receipt contains ten files: the normalized manifest
and nine assets; README and tests are excluded from deployment. A blob-by-blob
comparison confirmed that all thirteen files in the Sites source commit match
the draft repository mirror at `d54687a`. That comparison does not establish
that unmerged draft files are on repository `main`, and future repository edits
do not become a Sites deployment without a separate save and deploy operation.

Version 16 preserves the one-command local HUD launch, disconnected hosted
measurements, shared companion controls, and the repository storage map. It adds
a visible contract-only exchange map for offline STIX 2.1 threat context,
bounded local ECS 9.5.0 / OCSF 1.9.0 projections, and an inert SOAR handoff.
The page explicitly exposes no TAXII fetch, SIEM sender, endpoint, credential,
retry, scheduler, playbook, or host-action control.

The new exchange contract lives in draft PR #264. Deploying this reference UI
does not install the contract into a local checkout and does not implement a
parser, exporter, network client, notifier, scheduler, or executor.
Source parity does **not** establish runtime interoperability.

## Version 16 validation and current limits

- The external-exchange contract suite passed 7 focused tests.
- The complete static Site suite passed 38 Node tests after the final link
  update; JavaScript syntax checks also passed.
- JSON syntax and Python compilation checks passed for the contract artifacts.
- Thirteen-file repository/Sites source parity passed at draft commit
  `d54687acc4ddf5340565a7fbbd7ca18251c8af42`.
- The deployment reached terminal `succeeded`; no browser-rendered acceptance,
  native producer compatibility, runtime interoperability, operator acceptance,
  independent review, merge, release, or local deployment is claimed.
- No sensor, threat feed, SIEM destination, SOAR provider, lifecycle operation,
  firewall path, or model was invoked.

The project identity and access policy remain unchanged. Draft PR #264 remains
open and draft; this receipt does not mark it ready, approve it, merge it,
release it, expose the local HUD remotely, or grant runtime exchange authority.

## Earlier checkpoints

Version 15/source `cba088ceb88f3cf3ab718a2f2933d8b6fb5b16e6` added the
simplified HUD launch and shared companion controls. Version 14/source
`875b63b661f297c35162303f621349e727587f85` removed generated telemetry and
corrected lifecycle claims in merged PR #244. Version 13/source
`463c9d7e411ceaa86666babe1e24426cb88877f1` added lifecycle controls through
merged PR #243. Version 11/source
`c0865c0cec760f66a694c04d1108e061bf739358` was mirrored by merged PR #242;
the Wiki link repair #240 is also merged. Older versions remain available in
Site history.
