# Defense Console source alignment

Readback date: 2026-09-16. This receipt separates the hosted reference console,
local Python implementation and native operational acceptance.

| Identity | Observed value |
| --- | --- |
| Existing Site | [MEGALODON Defense Console](https://megalodon-defense-console.blackbart-55.chatgpt.site) |
| Project / slug | `appgprj_6aaa2be9d9288191a15a9c1d743af0b3` / `megalodon-defense-console` |
| Version | 15 — `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_d0d5e2637d0c8191b16c87d32a7d6872` |
| Source commit | `cba088ceb88f3cf3ab718a2f2933d8b6fb5b16e6` in the existing Sites source repository |
| Deployment | `appgdep_6aab0ea730b48191b05014ce65b9231b` succeeded at `2026-09-16T21:49:12.831692Z` |
| Access | Owner-private, access revision 1; no viewer/editor groups or external shares |
| Server archive digest | `sha256:def68ff796d2c0f9a4b4d6759010750fc8a12cef0cfe55fe749041bb0e378c89` |
| Product baseline inspected | `73d2a2e36ed4e110b7ecbdc138359ebc9b06c23c` (merged #244) |
| Retained rollback | Version 14; source `875b63b661f297c35162303f621349e727587f85`; lacks the simplified HUD launch and shared companion controls |

## Exact source and artifact scope

`site/` matches all thirteen tracked Sites source files byte-for-byte: README,
`.openai/hosting.json`, nine deployable assets, and two Node test files. The
archive contains ten files: the normalized manifest and nine assets. README and
tests are excluded from deployment. The Python distribution excludes `site/`;
its packaged UI uses the canonical constants in `dashboard_tool_assets.py`.

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

## Validation and limits

- Full repository suite: 2,251 tests and 150 subtests passed; three native/tool
  checks skipped (2,254 collected tests, 2,404 XML cases including subtests).
- 37 Node checks passed, including malformed saved links, storage failure,
  console save/remove, selected-role command copying, readiness races and startup.
- Real readiness/parser interoperability and local/hosted shared-asset parity pass.
- Composed JavaScript syntax, unique element IDs, thirteen-file Site parity,
  diff checks and nine-page Wiki validation passed.
- No lifecycle operation, sensor or model was run. Managed preview has no
  compatible server for this static Site; no rendered Site acceptance is claimed.
- Native producer compatibility, host acceptance and independent review remain
  separate from implementation tests and deployment.

The existing project identity and private audience are preserved. This update
uses a draft PR and does not merge, mark ready, change sharing, expose the local
HUD remotely or install/control a companion tool.

## Earlier checkpoints

Version 14/source `875b63b661f297c35162303f621349e727587f85` removed generated telemetry and corrected lifecycle claims in merged #244.
Version 13/source `463c9d7e411ceaa86666babe1e24426cb88877f1` added lifecycle controls
through merged PR #243. Its three automated review findings are corrected here.
Version 11/source `c0865c0cec760f66a694c04d1108e061bf739358` was mirrored by merged
PR #242; the Wiki link repair #240 is also merged. Those are historical source
states, not the current Site. Older versions remain available in Site history.
