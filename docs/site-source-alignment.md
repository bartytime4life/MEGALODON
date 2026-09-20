# Defense Console source alignment

## Current readback — merged repairs and Console v21 source parity

Repository `main@555874468073a04a7711ec4a96c8cdf810e1051d` includes both
[#292](https://github.com/bartytime4life/MEGALODON/pull/292), recovery failure
classification and connection cleanup, and
[#293](https://github.com/bartytime4life/MEGALODON/pull/293), Site setup and
evidence wording. [#291](https://github.com/bartytime4life/MEGALODON/issues/291)
is closed as completed; its owner recorded scoped acceptance of #292. The
earlier draft and candidate-only statements below describe historical checkpoints.

**VERIFIED:** all thirteen tracked `site/` files at that exact main revision
match Sites source `d89b8af91405066cdffaa72b2491d07a3dd8b61b` byte-for-byte.
The existing owner-private project still reports live version 21, with the
version, archive and deployment identities recorded below. Its 39 Node tests
pass. This pass did not republish or change the Site's audience. Rendered-browser
acceptance and installation on the owner's computer remain unverified; source
parity and scoped issue closure do not establish either.

## Historical repair — Console v21, setup and evidence wording

Repository readback: PR [#290](https://github.com/bartytime4life/MEGALODON/pull/290)
is merged at `643cb30f058957aa87b84d2de89b6d1782d5c42d`. Its unavailable-traffic
repair is on main; installation on the owner's computer remains unverified.
The v20 source matches all thirteen tracked Site files at that main revision.
The earlier draft/no-review observations below are historical, not current.

The automated review of #290 identified a nonexistent Ubuntu setup fragment.
The current Site points directly to the README's existing
`#installation-and-first-run` section, which covers the missing core command.
It also corrects the Boundaries page: model advice is untrusted commentary,
never evidence or host authority. Detections remain evidence for review, not
proof of malicious activity.

**OBSERVED deployment:** the existing owner-private Defense Console v21
succeeded at `2026-09-19T21:08:03.361713+00:00`.

- Sites source: `d89b8af91405066cdffaa72b2491d07a3dd8b61b`.
- Version: `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_32da2a5c7e608191af75ec8969392f8e`.
- Deployment: `appgdep_6aaef9ae0b7881918479e639bf5dec48`.
- Archive: `sha256:6368b095bee52dfe6b56a3256a3f7f4e062b9647377e82d1f86ed0809815c128`; ten deployable files.
- URL: <https://megalodon-defense-console.blackbart-55.chatgpt.site>.

**VERIFIED source and checks:** all thirteen Site source files match the
`agent/site-setup-evidence-20260919` candidate; 39 Site tests, JavaScript syntax,
local asset references and the README section target pass. This is candidate
parity, not v21/main parity. Rendered-browser acceptance remains unverified
because this plain-static Site has no compatible managed preview. v20 is the
rollback reference; identity, audience and disconnected reference behavior are
preserved. No host installation, telemetry connection or model invocation occurs.

The separate recovery repair for [#291](https://github.com/bartytime4life/MEGALODON/issues/291)
is draft [#292](https://github.com/bartytime4life/MEGALODON/pull/292), not a Site
capability or a merged recovery acceptance. Site publication, code merge,
independent review, release and operator acceptance remain separate.

## Historical repair — Console v20, local telemetry candidate

Repository baseline: `main@3bdcfb96a155d5dc4d7009e75f3b3c0986e5590b`.
The bounded repair is on `agent/telemetry-site-errors-20260919`; the associated
draft PR records its exact head. It is not a merge or local installation.

**VERIFIED:** a new regression failed on the baseline because a valid HTTP 200
`status=unavailable` projection (including sample-only stores) rendered `0 B`
and remained reportable in the Evidence chart. The repaired client keeps
unavailable measurements and report input cleared, preserves reachable audit
counters independently, and recovers when qualified traffic returns. An
ingestion-receipt refresh cannot overwrite an unavailable/stale traffic badge.
The HTTP and operator documents now describe the actual 500-event/200-finding
projection and bounded history route instead of the superseded 240-row API.

The Site repair restores the brand's Home action, focuses headings after view
changes, updates saved-console filtering after bookmark changes, replaces the
stale setup-branch link and source pin, and explains that a phone's loopback
address cannot open the HUD on a Linux computer. No hosted telemetry connection
is added.

| Identity | Verified value |
| --- | --- |
| Site | [MEGALODON Defense Console](https://megalodon-defense-console.blackbart-55.chatgpt.site) |
| Version | 20 — `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_ee1f6834152481918ebddbaf243f56e8` |
| Sites source | `4157a6768180a34ac46e884ccc1eb3a787df7ef7` |
| Server archive | 10 files, 286,720 bytes; `sha256:4b9162e3b217e2886ade01a62d840f1bb8634d359531703be7d9caac316b3df3` |
| Deployment | `appgdep_6aaeeb1f6f8c819195645186d04b469e`, succeeded at `2026-09-19T20:05:56.716695+00:00` |
| Audience | Existing owner-only project, slug and URL; private deployment operation succeeded |
| Candidate source equality | All thirteen tracked `site/` files match the pushed Sites source byte-for-byte |
| Main equality | Not claimed: the repair remains a draft candidate |
| Rollback reference | v19, Sites source `3f21ee3d0a6ee83d54e8f791d6b47fa3612ecf46` |

Local Node tests, focused Python/JavaScript behavior and HTTP tests, syntax,
compilation, asset references, canonical asset parity, repository hygiene and
build-input inventory passed. Exact-head hosted checks and review belong to the
PR. Rendered-browser acceptance remains unverified: this static Site has no
compatible managed preview. Passing DOM-stub tests are not visual acceptance.
No sensor, model, firewall, host setup, real metadata ingestion or release was
performed. Publishing this reference Site does not install the local fix.

## Historical v18 audit — readback and comparison scope

The remainder preserves the earlier v18 audit and its observation basis.
Its uses of "current" refer to that historical checkpoint, not the repair above.

Readback captured on 2026-09-19 against repository
`main@440fc176238f6f4c5e4dbb7964f76c30a95bf39d` and the existing Sites project.
The project now reports version 19 as its latest saved and live version, so the
requested version 18 comparison is a historical provenance receipt rather than
a claim about the source currently served at the Site URL. Version 19 is noted
below only to prevent version 18 from being mistaken for the current
publication; no version 19 source-equality claim is made in this receipt.

The project remains `custom` access at revision 1: the owner account is the
only allowed user, with no groups, editors, or external visitors. This readback
did not change the audience, save a version, or deploy the Site.

## Historical version 18 provenance receipt

| Identity | Observed value |
| --- | --- |
| Existing Site | [MEGALODON Defense Console](https://megalodon-defense-console.blackbart-55.chatgpt.site) |
| Project / slug | `appgprj_6aaa2be9d9288191a15a9c1d743af0b3` / `megalodon-defense-console` |
| Version | 18 — `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_deed1835c49481918517a5e501536f99` |
| Source commit | `9d751a2aa97d313534493e9ef9f1ef8e7136f0a3` in the Sites source repository; committed at `2026-09-18T01:34:22Z` |
| Server archive | `tar`, 10 files, 286,720 bytes; `sha256:60f60a5cbe4c8ca9c299c198af0996a32fb14a09e426213c599b527744b5fbf8` |
| Deployment | `appgdep_6aac954de9e88191aa6571bb40dde8b0` succeeded at `2026-09-18T01:35:59.315321Z` |
| Candidate repository mirror | `29f3111cc113de7a4588e02802bca07c6bcef253` |
| Merged repository mirror | `main@ceef9817c0cd9de5f9253683603feaa5dc11fcf8` |
| Historical repository/source equality | **VERIFIED for the thirteen `site/` source files** at both named repository commits |
| Current `main` / version 18 equality | **NOT EQUAL**: 10 of 13 source files still match; two deployable asset sources and one test changed after version 18 |
| Current repository baseline | `440fc176238f6f4c5e4dbb7964f76c30a95bf39d` |

The version record binds the source commit, archive metadata, and deployment ID
above. A read-only checkout of the recorded Sites source commit contains exactly
thirteen files: README, `.openai/hosting.json`, nine deployable assets including
`site/dist/index.html` and `site/dist/styles.css`, and two Node test files. Git
blob IDs for all thirteen files match both the candidate repository commit and
the later merge to `main`.

Packaging that exact source with the current Sites packager produced the
expected ten-file shape: a normalized manifest and the nine `dist/` assets,
with each packaged file equal to its source input. README and tests are not
deployment inputs. The stored server tar remains a separately normalized
artifact identified by the server digest above; this pass did not substitute a
local gzip digest for it or claim a fresh download-and-byte-comparison of the
stored tar.

## Comparison with current main

Current `main` preserves ten of version 18's thirteen source blobs. These three
post-version-18 changes account for the complete delta:

| Path | Current-main provenance | Why the version 18 copy was not restored |
| --- | --- | --- |
| `site/dist/controls.js` | Merged commit `5ac382d9516d4c2e979c26ff3068939b8ed0debe` | Adds the shared control callbacks used by the later local HUD/app-viewer work. |
| `site/dist/lifecycle.js` | Merged commit `37d19db9d93def87a58168938e95abe4a388a98c` | Keeps current Python-environment and Nagios reference guidance plus the bounded local override hook. |
| `site/tests/readiness.test.cjs` | Merged commit `37d19db9d93def87a58168938e95abe4a388a98c` | Verifies the corresponding Nagios command ordering. |

No Site mirror asset is changed by this source-alignment PR. Restoring the
version 18 copies would reverse later merged work and would break the
repository's canonical HUD-asset equality check. Consequently, this receipt
does not claim that current `main` matches version 18, that version 18 is live,
or that later repository edits became a Sites deployment.

## Behavior and evidence limits

Version 18 preserved the one-command local HUD launch, disconnected hosted
measurements, shared companion controls, repository storage map, and bounded
offline STIX 2.1 reader status. Its page cannot select or upload a threat bundle
and exposes no TAXII fetch, SIEM sender, endpoint, credential, retry, scheduler,
playbook, or host-action control.

Deploying the hosted reference console does not install a reader into a local
checkout and does not add a Site-side parser, exporter, network client,
notifier, scheduler, or executor. Source parity does **not** establish runtime
interoperability, native producer compatibility, evidence authenticity,
operator acceptance, independent review, release status, or local deployment.
No sensor, threat feed, SIEM destination, SOAR provider, lifecycle operation,
firewall path, or model was invoked during this comparison.

Static validation for the current repository mirror is recorded in the source-
alignment pull request. The Node DOM stub is not rendered-browser acceptance,
and no current visual walkthrough is claimed.

## Adjacent checkpoints

Version 19 — `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_82f8538dddfc819196fe2defc126d764`
— succeeded at `2026-09-19T14:45:20.189204Z` from Sites source
`3f21ee3d0a6ee83d54e8f791d6b47fa3612ecf46`; its ten-file archive is recorded
as `sha256:ca77a9b793361e4153e3f9a0f40f9e1a74546f3d406d83bcec0ceb17fd74e2e1`.
That successor was the publication at this checkpoint, but its whole-source relationship to
later repository `main` is outside this version 18 equality receipt.

Version 17/source `50d21d668ae5d86301040aa40c7b37dfb1e11d81`
introduced the bounded reader status and retained version 16/source
`e9f218760aec26bd092dd6d826da095903da3f5c` as its predecessor. Version 15/source
`cba088ceb88f3cf3ab718a2f2933d8b6fb5b16e6` added the simplified HUD launch and
shared companion controls. Version 14/source
`875b63b661f297c35162303f621349e727587f85` removed generated telemetry and
corrected lifecycle claims. Older versions remain in Site history.
