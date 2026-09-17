# Defense Console source alignment

Readback refreshed: 2026-09-17 against repository
`main@31919a8bfa6fbdd3adb8cc3474587617ad93450b` and the Sites project record.
This receipt separates the hosted reference console, repository mirror, local
Python implementation and native operational acceptance.

| Identity | Observed value |
| --- | --- |
| Existing Site | [MEGALODON Defense Console](https://megalodon-defense-console.blackbart-55.chatgpt.site) |
| Project / slug | `appgprj_6aaa2be9d9288191a15a9c1d743af0b3` / `megalodon-defense-console` |
| Version | 15 — `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_d0d5e2637d0c8191b16c87d32a7d6872` |
| Source commit | `cba088ceb88f3cf3ab718a2f2933d8b6fb5b16e6` in the existing Sites source repository |
| Deployment | `appgdep_6aab0ea730b48191b05014ce65b9231b` succeeded at `2026-09-16T21:49:12.831692Z` |
| Access | Owner-private, access revision 1; no viewer/editor groups or external shares |
| Server archive digest | `sha256:def68ff796d2c0f9a4b4d6759010750fc8a12cef0cfe55fe749041bb0e378c89` |
| Hosted artifact baseline | Version 15 receipt at source `cba088ceb88f3cf3ab718a2f2933d8b6fb5b16e6` |
| Current repository baseline | `31919a8bfa6fbdd3adb8cc3474587617ad93450b` |
| Repository/hosted equality | **UNVERIFIED** — repository `site/dist/index.html` and `site/dist/styles.css` advanced after the version 15 receipt; no later deployment receipt is authorized or recorded here |
| Retained rollback | Version 14; source `875b63b661f297c35162303f621349e727587f85`; lacks the simplified HUD launch and shared companion controls |

## Exact source and artifact scope

The repository still tracks thirteen Sites source files: README,
`.openai/hosting.json`, nine deployable assets, and two Node test files. The
version 15 server archive receipt contains ten files: the normalized manifest
and nine assets; README and tests are excluded from deployment. Those counts do
not establish byte equality with the current repository. In particular,
`site/dist/index.html` and `site/dist/styles.css` changed after the version 15
receipt, so current repository/hosted parity remains **UNVERIFIED** until a
separately authorized deployment produces a new source/version/archive receipt.
The Python distribution excludes `site/`; its packaged UI uses the canonical
constants in `dashboard_tool_assets.py`.

Version 15 puts a one-command local HUD launch and explicit local link first,
with disconnected hosted measurements under a disclosure. Tool search and saved
console filtering simplify navigation. Local/hosted companion controls share
lifecycle commands, official setup guidance, URL validation and display behavior.
Saved console links are browser bookmarks, not backend data connections.

The new Python `hud` command works before an audit store exists and checks
executable presence at startup without executing tools. Missing data remains
unavailable. The existing `dashboard` command retains its strict store requirement
and no-probe behavior. Setup paths prepare quoted commands only. Users need the
HUD source update installed to use the new command; deploying the hosted Site
does not install Python software on their computer.

## Historical version 15 validation and current limits

- Full repository suite: 2,251 tests and 150 subtests passed; three native/tool
  checks skipped (2,254 collected tests, 2,404 XML cases including subtests).
- 37 Node checks passed, including malformed saved links, storage failure,
  console save/remove, selected-role command copying, readiness races and startup.
- Real readiness/parser interoperability and local/hosted shared-asset parity
  passed for the version 15 receipt, not for the later repository mirror.
- Composed JavaScript syntax, unique element IDs, thirteen-file parity, diff
  checks and nine-page Wiki validation passed for that historical candidate.
- No lifecycle operation, sensor or model was run. Managed preview has no
  compatible server for this static Site; no rendered Site acceptance is claimed.
- Native producer compatibility, host acceptance and independent review remain
  separate from implementation tests and deployment.

The existing project identity, version 15 deployment and private audience remain
unchanged. This repository correction requires a draft PR and does not merge,
mark ready, deploy, change sharing, expose the local HUD remotely, or
install/control a companion tool.

## Earlier checkpoints

Version 14/source `875b63b661f297c35162303f621349e727587f85` removed generated telemetry and corrected lifecycle claims in merged #244.
Version 13/source `463c9d7e411ceaa86666babe1e24426cb88877f1` added lifecycle controls
through merged PR #243. Its three automated review findings are corrected here.
Version 11/source `c0865c0cec760f66a694c04d1108e061bf739358` was mirrored by merged
PR #242; the Wiki link repair #240 is also merged. Those are historical source
states, not the current Site. Older versions remain available in Site history.

Repository changes after the version 15 receipt, including PR #251, are source
history only. They do not become a Sites deployment without a separately
authorized save/deploy operation and terminal deployment readback.
