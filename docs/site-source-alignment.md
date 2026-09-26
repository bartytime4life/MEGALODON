# Defense Console source alignment

## Current publication — Console v34, separate traffic volume lanes

OBSERVED 2026-09-26: the existing owner-only Console serves version 34 from
Sites source `4b81d72ade6e2fbedeff2ce1fa0c2b7b0898cc33`. Its globe view now has
separate normal and danger/critical volume tracks, both visibly disconnected.
The hosted page has no telemetry refresh loop or local data connection. Actual
meters in the accompanying local-HUD change read the existing bounded history
projection at the configured refresh interval (five seconds by default).

| Identity | Observed value |
| --- | --- |
| Project | `appgprj_6aaa2be9d9288191a15a9c1d743af0b3` |
| Version | 34 — `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_6ee0bfd20cc081919531228d7bef841f` |
| Sites source | `4b81d72ade6e2fbedeff2ce1fa0c2b7b0898cc33` |
| Deployment | `appgdep_6ab82e852ff08191b4d0be2b8224cf96`; succeeded 2026-09-26T20:43:54Z |
| URL | <https://megalodon-defense-console.blackbart-55.chatgpt.site> |
| Audience | Existing owner-only access |
| Rollback reference | v33 / `7b39459140b6f08cccf5a1bfbc5686b7e4a9ac95` |

VERIFIED: 44 Site Node checks and the repository suite (3,745 passed, five
environment-specific skips) passed before this receipt was appended. JavaScript
behavior covers lane separation, duplicate-finding deduplication, relative volume
thresholds, current-minute selection, partial/stale/paused/unavailable states,
bounded refresh, overlap refusal and recovery. These are synthetic behavior
checks, not a real network or rendered-browser acceptance receipt. The repository
change remains subject to PR review and merge; Site publication does not update
an installed local HUD.

## Historical publication — Console v33, globe reference and signal levels

OBSERVED 2026-09-26: the existing owner-only Console serves version 33 from
Sites source `7b39459140b6f08cccf5a1bfbc5686b7e4a9ac95`. The hosted Home view
renders the local HUD's bundled Natural Earth land mask as a rotatable geographic
reference and names the returned-record, review, and high-priority signal levels.
All are explicitly unavailable here because the hosted Site cannot read the local
HUD's stored traffic or optional IP map. No marker, count, or timestamp is
fabricated. The rolling-hour timeline and actual signals remain local-only.

| Identity | Observed value |
| --- | --- |
| Project | `appgprj_6aaa2be9d9288191a15a9c1d743af0b3` |
| Version | 33 — `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_8cc48214d6b88191b8ad3eafa0f01288` |
| Sites source | `7b39459140b6f08cccf5a1bfbc5686b7e4a9ac95` |
| Deployment | `appgdep_6ab826ddf3188191b5dc9efebefbf921`; succeeded 2026-09-26T20:11:15Z |
| URL | <https://megalodon-defense-console.blackbart-55.chatgpt.site> |
| Audience | Existing owner-only access; no external visitors |
| Rollback reference | v32 / `fd308cb9b4ba42b2f7c281ae046138694cfd5d4c` |

VERIFIED: 44 Site Node checks, JavaScript syntax, diff validation, Site source
push, and successful Sites deployment readback. Browser rendering and local HUD
operation were not exercised by this publication. The repository mirror is
proposed in this PR; merging it does not broaden source, host, or release
acceptance.

## Historical publication — Console v32, local feature guide

OBSERVED 2026-09-26: the existing owner-only Console serves version 32 from
Sites source `fd308cb9b4ba42b2f7c281ae046138694cfd5d4c`. The source began
with repository `main@a767e69bcaf7ac0020e03b89578e6c76ec264560`; its
Home view now points to that revision's local rolling-hour activity globe and
Actions workspace. The new text describes optional offline approximate IP
regions and copy-only scripts with a read-only recurrence preview. This hosted
page still has no local evidence, schedule, command, or firewall connection.
All 14 tracked `site/` files in this repository candidate match the pushed
Sites source; the candidate is not merged into `main` by this publication.

| Identity | Observed value |
| --- | --- |
| Project | `appgprj_6aaa2be9d9288191a15a9c1d743af0b3` |
| Version | 32 — `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_e7f249e6cec4819188e0b6742663f5eb` |
| Sites source | `fd308cb9b4ba42b2f7c281ae046138694cfd5d4c` |
| Stored archive | `sha256:67963f125642a00fbe8580d94cc2945afc5cb7deafae1bc59e2b00939b36fc2e`; 10 files, 317,440 bytes |
| Deployment | `appgdep_6ab8143e014881919b810e32ded7a560`; succeeded at `2026-09-26T18:51:51.093723+00:00` |
| URL | <https://megalodon-defense-console.blackbart-55.chatgpt.site> |
| Audience | Existing owner-only access; no external visitors |
| Rollback reference | v31 / `cd421d21435092f4571cc4d13b999fd0f6c62730` |

VERIFIED: 44 Site Node checks, JavaScript syntax, diff validation, source
equality, and Sites version and deployment readback passed. No new rendered
browser walkthrough or local-host operation was tested. Publication establishes
the hosted reference update, not telemetry, schedule execution, operational
acceptance, repository merge, or software release.

## Historical publication — Console v31, repository source refresh

OBSERVED 2026-09-25: the existing owner-only Console serves version 31 from
Sites source `cd421d21435092f4571cc4d13b999fd0f6c62730`. Its deployable
`dist/` files and `.openai/hosting.json` match repository
`main@799dc984cadf23990fb074f252b4c53a4534e855` byte-for-byte. This
candidate aligns the repository's `site/README.md` with the published source;
all 14 tracked `site/` files then match the Sites source commit. This source
refresh includes the merged hosted integration guidance from #403, the
bounded companion setup references, and the local-only status wording. It
does not connect the hosted page to the local HUD or grant host control.

| Identity | Observed value |
| --- | --- |
| Project | `appgprj_6aaa2be9d9288191a15a9c1d743af0b3` |
| Version | 31 — `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_aabdb14ce3388191a8ab8b9650f8105c` |
| Sites source | `cd421d21435092f4571cc4d13b999fd0f6c62730` |
| Archive | `sha256:f8f5f0711613f4b23c31d8095d9ec1254dca7f192b14151b653b7a3fce5ce163`; 10 files, 307,200 bytes |
| Deployment | `appgdep_6ab6b87c3940819184f2f364b50c361c`; succeeded at `2026-09-25T18:08:02.995357+00:00` |
| URL | <https://megalodon-defense-console.blackbart-55.chatgpt.site> |
| Audience | Existing owner-only access; no external visitors |
| Rollback reference | v30 / `7a96f64b8e9cd5974c9f872c5346726d129f91c0` |

VERIFIED: 44 Site Node checks, JavaScript syntax, 21 focused repository checks,
and a local browser preview passed on the source used for publication. After
deployment, browser readback showed the new Home wording and Integrations
view with its local-only boundary. This does not establish installed-tool
health, telemetry, local runtime acceptance, or a full rendered-browser
walkthrough. Site publication and this repository documentation change are
separate states until this candidate is merged.

## Historical local reference correction — unpublished at that checkpoint

Source basis: `ad3266562c647f0131ec62c4882895cd1951acca`, with the HUD
operator-authorization wording dependent on PR #392. This repository-only
change corrects stale local-HUD status descriptions and the ECS/OCSF writer
state. It changes no data connection, command execution, audience or Site
identity. The source now intentionally differs from the hosted publication.

OBSERVED on 2026-09-23: Sites still reports version 30, source
`7a96f64b8e9cd5974c9f872c5346726d129f91c0`, owner-only custom access and zero
external visitors. No version save, source push to Sites or deployment was
performed. Publication and rendered hosted acceptance require separate
authorization; the original v30 receipt below retains its historical basis.

## Historical publication — Console v30, merged installer links

OBSERVED 2026-09-21: the existing owner-only Console serves version 30. Its
install links use the immutable #323 merge
`16742fed020283aafad35e30238986c851d7542a` instead of the former candidate
branch. The Site source commit is `7a96f64b8e9cd5974c9f872c5346726d129f91c0`;
the changed `README.md`, `dist/index.html`, and `tests/install.test.cjs` have
the same bytes in this repository candidate. All 14 tracked `site/` files
match that pushed Site source. Repository `main@bdddd427df3c06e30c0d7e6e3405a0e1932fc971`
still contains the older v29 mirror in those three files until this change is
merged. Source matching is scoped to this candidate, not current `main`.

| Identity | Observed value |
| --- | --- |
| Project | `appgprj_6aaa2be9d9288191a15a9c1d743af0b3` |
| Version | 30 — `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_76f5c1587df48191b6a194fcc9024cc4` |
| Sites source | `7a96f64b8e9cd5974c9f872c5346726d129f91c0` |
| Archive | `sha256:65d619dabb7afd61e3ae39f12b5cfb6d76c6f7fc80f53287dd882f93385eed22`; 10 files, 296,960 bytes |
| Deployment | `appgdep_6ab15697cb048191ba52a40efd159581`; succeeded at `2026-09-21T16:09:02.243293+00:00` |
| URL | <https://megalodon-defense-console.blackbart-55.chatgpt.site> |
| Audience | Existing owner-only access, unchanged |
| Rollback reference | v29 / `49bfe9f527db5c7e71d0724d3e0b5b0e5c19295f` |

All 44 Site Node checks and JavaScript syntax checks passed on the pushed
source. They cover disconnected measurements and client behavior, not a
rendered hosted-browser walkthrough, live telemetry, a local installation, or
operator acceptance. The Site cannot reach the local HUD or establish sensor
health. See the [current alignment record](document-alignment-2026-09-21.md)
for the separate local telemetry test limit.

## Historical publication — Console v29, guided local install

OBSERVED 2026-09-21: the existing owner-private Defense Console now serves
version 29 from Sites source `49bfe9f527db5c7e71d0724d3e0b5b0e5c19295f`.
That source contains the exact 14 tracked files under `site/` on
`codex/local-pc-readiness@5d6970ed05844271a6d91d91e6013683a56b03ed`,
the head of draft [PR #323](https://github.com/bartytime4life/MEGALODON/pull/323)
at publication time. The Site now presents the reviewed user-scoped installer
as the primary local path, keeps the source launch available for contributors,
and links its copy actions to the same commands documented in the repository.

| Identity | Observed value |
| --- | --- |
| Project | `appgprj_6aaa2be9d9288191a15a9c1d743af0b3` |
| Version | 29 — `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_d3b4a30c7e888191bd3056a653a13d3c` |
| Sites source | `49bfe9f527db5c7e71d0724d3e0b5b0e5c19295f` |
| Archive | `sha256:3b83f512a250e4646d1ea3396acec086e24013ed4735593db87ae17a1328025a`; 10 files, 296,960 bytes |
| Deployment | `appgdep_6ab08ed39094819185340d3ac8bdcd52`; succeeded at `2026-09-21T01:56:43.208614+00:00` |
| URL | <https://megalodon-defense-console.blackbart-55.chatgpt.site> |
| Audience | Existing owner-only project; private publication succeeded |
| Repository mirror | All 14 tracked Site source files match the pushed Sites commit |
| Merge state | Draft PR #323; publication does not merge the repository candidate |
| Rollback reference | v28 / `5d03870143afab716e9e4a097273d2343fb0b6cc` |

VERIFIED: all 44 Site Node checks and JavaScript syntax checks pass. The hosted
console remains a disconnected reference interface: it cannot run the local
installer, inspect the computer, reach loopback telemetry, or prove that any
program is installed or running. Local installation, repository merge, software
release, rendered-browser acceptance, and operator acceptance remain separate.

## Historical navigation candidate — superseded by v29

At its original checkpoint, this candidate started from
`main@2d87e3f2890cd6c0200bffbde64c4932e0a85dac`.
It changes `site/dist/app.js` and `site/dist/styles.css` for navigation history,
session-only reading positions, and visible mobile navigation labels. It also
extends the existing application behavior test. At that checkpoint, candidate
source was **not equal to the deployed v28 source**, and no Sites version had
been saved or deployed. Version 29 later superseded that publication state; the
v28 records below remain historical evidence.

View URLs contain only a closed view name; scroll positions remain in page
memory and are cleared on reload. No telemetry, filter text, or tool address is
added to navigation history. Merge, publication and operator acceptance remain
separate decisions.


## Successor repository readback — merged v28 mirror

OBSERVED 2026-09-20: `main@d71fbc245729b968701fbeba4f7f679c8db24ac7`
includes the v28 mirror alignment through merged PR #308 (`03e0450`).
The `site/` tree is unchanged between that merge and this main pin.
Sites still reports version 28 at the existing URL with owner-only access.
The candidate-only and baseline-difference statements in the original v28
receipt below are historical. This readback checks repository continuity and
Sites metadata; it is not a fresh fetch of deployed source bytes, a rendered
browser test, or an installed-host acceptance. No Site edit or publication is
part of this successor record.

## Historical publication — Console v28, merged setup guidance

OBSERVED 2026-09-20: GitHub baseline `main@f3bf5d6a08c64363651e17fae07ff2e88386c0c0`
contains merged PR #307. All 13 tracked Site source files at that baseline
were verified byte-for-byte equal to v27 source
`efcbf5c40204fbcc3adbf89646665ed306a55531` before this correction.
The preceding v26 receipt below is historical, not the current publication.

The new publication changes only `README.md` and `dist/index.html`: setup
now links to the immutable #307 merge instead of its former working branch,
and source guidance records that the launcher has merged.

| Identity | Observed value |
| --- | --- |
| Project | `appgprj_6aaa2be9d9288191a15a9c1d743af0b3` |
| Version | 28 — `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_fbe533edca508191b881f6e00199b92c` |
| Sites source | `5d03870143afab716e9e4a097273d2343fb0b6cc` |
| Archive | `sha256:b116d8677c2c1bfce90d105f1a0c12e8f91b56baaf3c36350c9b02e8d37ff25b`; 10 files, 296,960 bytes |
| Deployment | `appgdep_6aaf9388e0208191989d1d8f917920ad`; succeeded at `2026-09-20T08:04:29.299330+00:00` |
| URL | <https://megalodon-defense-console.blackbart-55.chatgpt.site> |
| Audience | Existing owner-only project; private publication succeeded |
| Candidate mirror | All 13 tracked source files match the pushed Sites commit; exact candidate SHA belongs to the draft PR |
| Main equality | v28 differs from the baseline in the two paths above; candidate equality is not merged-main equality |
| Rollback reference | v27 / `efcbf5c40204fbcc3adbf89646665ed306a55531` |

VERIFIED: 41 Site Node checks, JavaScript syntax and local asset references pass.
No new rendered-browser or installed-host acceptance is claimed. The hosted
reference remains disconnected from local telemetry. Site publication does not
merge this candidate, publish a software release, invoke a model/sensor or
accept #259–#261. Historical test and deployment receipts below retain their
original scope.

## Historical readback — Console v26 and proposed repository mirror repair

Readback on 2026-09-20 pins the repository to
`main@9c2675b8dbc8bbae319525803e28a0542031c8b2` and the existing owner-private
Defense Console to v26. The historical checkpoints below retain their original
evidence; they do not describe the current publication or current PR states.

**OBSERVED:** deployment `appgdep_6aaf6adcb3348191ab0299a5c1c6e0e2` succeeded
at `2026-09-20T05:11:37.840507+00:00`.

- Project: `appgprj_6aaa2be9d9288191a15a9c1d743af0b3`.
- Version: `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_7da7c502755c8191b40b526c4d30d0a0`.
- Sites source: `64d626ac40e30e1bd10d18569918364a90e7176a`.
- Archive: `sha256:17736c30a7c5055baf2824900399444caaca0923c38c04de4661094ed4937d64`, ten deployable files.
- URL: <https://megalodon-defense-console.blackbart-55.chatgpt.site>.

**VERIFIED source comparison:** three of thirteen tracked `site/` files at the
pinned main differ from the deployed source: `site/README.md`,
`site/dist/index.html`, and `site/tests/readiness.test.cjs`. The candidate copies
exactly those three files from the pinned Sites source; all thirteen candidate
files then match. It restores the existing Apache-2.0 license disclosure and its
regression check to the GitHub mirror. It does not claim current-main equality
until an authorized merge and readback establish it.

**VERIFIED local checks:** 41 Node tests and JavaScript syntax checks pass.
**OBSERVED logs:** the error-only query for the preceding 1,440 minutes returned
no events. This does not prove a browser walkthrough, complete log retention,
host installation, telemetry availability, or operational health. No Site source
was edited, no version was published, and no audience changed in this repair.

The current runtime remains a disconnected reference console. Local telemetry,
model operation, release publication, and independent acceptance stay separate.

## Historical publication — Console v22 detector-evidence surface

Repository base `main@c8af8993fb258843e2001c1cbdfef1a430026d15`
contains the detector registry and synthetic evidence report from
[#294](https://github.com/bartytime4life/MEGALODON/pull/294). Its merged registry
misbound `source-cap-pressure-v1` to `DNS_TUNNELING` even though the scenario's
expected counts are DNS 0, port scan 0 and SYN flood 2. The current repair moves
that fixture to `SYN_FLOOD`, advances only the registry metadata version to
`1.0.1`, and adds a regression tied to the corpus expectation. The three rule
versions remain `1.0.0`; no detector behavior, threshold, ingestion path, model,
host action or runtime authority changes.

The same bounded repair adds a static Evidence Desk summary of the three rules
and the 12-scenario, 6,492-event bundled synthetic corpus. The page labels it as
a repository source feature, not runtime telemetry, and states that the corpus
does not establish classification metrics, real-network coverage, accuracy,
maliciousness or host safety. The hosted console remains disconnected from
operator telemetry and exposes no host-control path.

**OBSERVED deployment:** the existing owner-private Defense Console v22
succeeded at `2026-09-20T03:09:35.819131+00:00`.

- Sites source: `bcf11a8025dcefbaf1768406879e6d59783b0088`.
- Version: `appgprj_6aaa2be9d9288191a15a9c1d743af0b3~appgver_443cccd3a4308191adb02ad7fc5c047b`.
- Deployment: `appgdep_6aaf4e6acf20819182dd5432cf81cb13`.
- Archive: `sha256:4e35e9805c3f713b4f0d51f1fb6aef31a59ba8edfc3acd5c88bce730e2b0f35a`; ten deployable files.
- URL: <https://megalodon-defense-console.blackbart-55.chatgpt.site>.

**VERIFIED candidate evidence:** all thirteen tracked `site/` files match that
Sites source byte-for-byte; 40 Node tests, JavaScript syntax, local asset
references and repository/Site mirror equality pass. Focused registry and
reference tests also pass. The GitHub change remains a draft candidate until
its pull request is reviewed and merged. Site publication, repository merge,
release, local installation, independent acceptance and rendered-browser
acceptance remain separate.

## Historical readback — merged repairs and Console v21 source parity

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
