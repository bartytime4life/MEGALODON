# Defense Console source alignment

Readback refreshed: 2026-09-17 against repository
`main@8ae0294a0fc89d5cddda454cb50df3339e599570`, candidate branch commit
`5310eeb5397571a6df6b81cfe4f42d7e5d9b1d0b`, and the Sites project record.
This receipt separates the hosted reference console, repository mirror, local
Python source candidate, and native operational acceptance.

| Identity | Observed value |
| --- | --- |
| Existing Site | [MEGALODON Defense Console](https://megalodon-defense-console.blackbart-55.chatgpt.site) |
| Project / slug | `appgprj_6aaa2be9d9288191a15a9c1d743af0b3` / `megalodon-defense-console` |
| Version | 17 — `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_706b9bc005cc8191aec7e17bd69448b9` |
| Source commit | `50d21d668ae5d86301040aa40c7b37dfb1e11d81` in the existing Sites source repository |
| Deployment | `appgdep_6aac008f26ec81919669f61df409945d` succeeded at `2026-09-17T15:00:39.758289Z` |
| Access | `custom`, revision 1; only the owner account is allowed, with no groups, editors, or external visitors |
| Server archive digest | `sha256:e0a9b9b76a6bd85d6479bf4765d661191780139a4adee05e67459bfb104c1227` |
| Hosted artifact baseline | Version 17 receipt at source `50d21d668ae5d86301040aa40c7b37dfb1e11d81` |
| Current repository baseline | `8ae0294a0fc89d5cddda454cb50df3339e599570` |
| Candidate repository mirror | Branch commit `5310eeb5397571a6df6b81cfe4f42d7e5d9b1d0b` |
| Repository/hosted equality | **VERIFIED for the thirteen `site/` source files** at the candidate mirror commit; the ten-file server archive remains a separately normalized deployment artifact |
| Retained rollback | Version 16; source `e9f218760aec26bd092dd6d826da095903da3f5c` |

## Exact source and artifact scope

The repository tracks thirteen Sites source files: README,
`.openai/hosting.json`, nine deployable assets (including
`site/dist/index.html` and `site/dist/styles.css`), and two Node test files. The
version 17 server archive receipt contains ten files: the normalized manifest
and nine assets; README and tests are excluded from deployment. A blob-by-blob
comparison confirmed that all thirteen files in the Sites source commit match
the candidate repository mirror at `5310eeb`. That comparison does not establish
that unmerged candidate files are on repository `main`, and future repository edits
do not become a Sites deployment without a separate save and deploy operation.

Version 17 preserves the one-command local HUD launch, disconnected hosted
measurements, shared companion controls, and the repository storage map. It now
distinguishes the bounded offline STIX 2.1 reader candidate from the
contract-only ECS 9.5.0 / OCSF 1.9.0 projection and inert SOAR handoff. The page
cannot select or upload a bundle and explicitly exposes no TAXII fetch, SIEM
sender, endpoint, credential, retry, scheduler, playbook, or host-action control.

The reader exists only in the repository review candidate until merge and local
installation. Deploying this reference UI does not install that reader into a
local checkout and does not add a Site-side parser, exporter, network client,
notifier, scheduler, or executor. Source parity does **not** establish runtime interoperability.

## Version 17 validation and current limits

- The threat-context reader and external-exchange contract suites passed 25
  focused tests.
- The complete static Site suite passed 38 Node tests after the final link
  update; JavaScript syntax checks also passed.
- Python compilation, documentation currentness, diff checks, and the complete
  repository suite outside four inherited environment-policy probes passed.
- The four probes fail only because their intentionally isolated child Python
  cannot import `pytest` in this workspace; they are not reader or Site failures.
- Thirteen-file repository/Sites source parity passed at candidate commit
  `5310eeb5397571a6df6b81cfe4f42d7e5d9b1d0b`.
- The deployment reached terminal `succeeded`; no browser-rendered acceptance,
  threat-intelligence authenticity, native operator compatibility, runtime
  interoperability, independent review, merge, release, or local deployment is
  claimed.
- No sensor, threat feed, SIEM destination, SOAR provider, lifecycle operation,
  firewall path, or model was invoked.

The project identity and owner-only access policy remain unchanged. This receipt
does not mark a pull request ready, approve it, merge it, release it, expose the
local HUD remotely, or grant runtime exchange authority.

## Earlier checkpoints

Version 16/source `e9f218760aec26bd092dd6d826da095903da3f5c` added the
three contract-only exchange lanes. Version 15/source
`cba088ceb88f3cf3ab718a2f2933d8b6fb5b16e6` added the
simplified HUD launch and shared companion controls. Version 14/source
`875b63b661f297c35162303f621349e727587f85` removed generated telemetry and
corrected lifecycle claims in merged PR #244. Version 13/source
`463c9d7e411ceaa86666babe1e24426cb88877f1` added lifecycle controls through
merged PR #243. Version 11/source
`c0865c0cec760f66a694c04d1108e061bf739358` was mirrored by merged PR #242;
the Wiki link repair #240 is also merged. Older versions remain available in
Site history.
