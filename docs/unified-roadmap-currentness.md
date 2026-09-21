# Unified roadmap: repository reconciliation

## Current readback — 2026-09-21, later main

At `main@374190a57791f9ac19afeefd78afbd18d9b68919` (tree
`376a6151a11faae2e055ec711a081de785e3f9e2`), #330 adds verification
before AI action-status readback, #331 retains exact-head temporary wheel/sdist
subjects, #332 adds source-qualified ingestion-run v2 reads, and #333 corrects
current Site/wiki copy about the optional AI POST. GitHub reports CI, Linux
browser acceptance, CodeQL, and wiki publication workflows successful on this
commit. Those are exact-revision execution receipts, not host, producer,
operator, platform, or release acceptance.

Issues #260, #261, and #327 remain open at this readback. The release packet
generator already produces digest-bound SBOM/provenance output from a complete
candidate; the newer subject workflow alone does not supply that candidate's
nine-check packet or disposition. No Zeek producer profile has been selected
in #327. The model containment gate in #261 remains open. The last documented
owner-only Console publication is v30 in
[the Site receipt](site-source-alignment.md); repository source changes and a
successful repository workflow do not establish a newer hosted version or local
telemetry connection. See the [proposed opportunity map](system-opportunity-map.md)
for candidate slices and their separate evidence gates.

## Earlier readback — 2026-09-21

At `main@bdddd427df3c06e30c0d7e6e3405a0e1932fc971`, the local desktop
installer and guided checks from #323 are merged, while the owner-only hosted
Console v30 remains a disconnected reference surface. GitHub records #259
closed after scoped owner acceptance; that accepts the bounded synthetic
registry/report implementation, not independent review or operational accuracy.
#327 is open for the exact Zeek producer profile and schema-drift evidence left
after #258 closed. #260 remains open despite #318–#322 and #324/#326 tooling
and synthetic CI recovery receipts. #261 remains open with an unbound collector.
See the [current alignment record](document-alignment-2026-09-21.md) for the
telemetry test limit and the [Site receipt](site-source-alignment.md) for the
publication identity. Due dates, release, sensor operation, and model
acceptance are not supplied by this readback.

## Historical readback — issue acceptance reconciliation

OBSERVED on 2026-09-20 at
[`main@f3bf5d6a08c64363651e17fae07ff2e88386c0c0`](https://github.com/bartytime4life/MEGALODON/commit/f3bf5d6a08c64363651e17fae07ff2e88386c0c0).
PRs #301–#307 are merged. The prior repair backlog below is historical.

| Issue | Delivered | Remaining gate |
| --- | --- | --- |
| #258 / M02 (closed completed) | #299 Community ID vectors and pure grouping; #302 bounded inputs, valid seeds and distinct-source matches. | Issue body still lists owner-selected producer profile and closed schema-drift fixtures; closure does not prove them. installed-producer/loss evidence remains separate. CLI integration is still proposed. |
| #259 / M02 | #294 registry/report and #296 corrected fixture mapping plus displayed corpus totals regression. All three rule versions remain 1.0.0; registry metadata is 1.0.1. | Exact-head scoped owner/independent acceptance remains unrecorded. Representative operational accuracy is outside this synthetic delivery and must not be inferred. |
| #260 / M03 | Currentness, SQLite recovery and Apache-2.0 prerequisites are delivered; #297 provides the closed evidence contract and incomplete identity collector. | Complete nine-check/two-artifact evidence, retained operator drill, SBOM/provenance and exact-candidate disposition. The collector crash and stale license blocker were repaired by merged #306. |
| #261 / M04 | #300 containment contract plus #301 corpus identity and deterministic malformed-input denials. | Exact owner-selected model bytes, authorized host collector, signed adversarial corpus and independent candidate security review. Collection remains unbound. |

GitHub now shows #259–#261 open and #258 closed completed. The latter
still describes missing producer qualification; preserve that evidence gap. No issue closure,
independent review, release, deployment or host acceptance is implied by tests.
The merged #260 collector repair preserves historical blocked-license packets but emits
`not_assessed` for new identity collection because it does not inspect license
or artifact metadata. All other gates and effect prohibitions remain fixed.

The local setup changes are delivered by merged PR #307. The hosted
Console is a separate owner-private static publication; current source and
publication identities are recorded in [the Site receipt](site-source-alignment.md).
See [the document alignment record](document-alignment-2026-09-20.md) for local,
GitHub, Wiki and Drive ownership. Matching source does not establish sensor
health or operator acceptance.

## Historical readback — merged contracts, remaining acceptance

OBSERVED on 2026-09-20 at
[`main@9c2675b8dbc8bbae319525803e28a0542031c8b2`](https://github.com/bartytime4life/MEGALODON/commit/9c2675b8dbc8bbae319525803e28a0542031c8b2).
The supplied architecture and research roadmap are historical planning inputs.
The September 17 baseline and delivery sequence below are retained as historical
evidence, not a current backlog or authority to operate a sensor or model.

| Track | Implementation now present | Remaining gate |
| --- | --- | --- |
| License | [#298](https://github.com/bartytime4life/MEGALODON/pull/298) merged Apache-2.0 and package metadata; #255 is closed. | Release artifacts, SBOM/provenance and publication are separate; do not repeat the old no-license blocker. |
| Suricata | Completed raw-EVE profile/converter, durable consumer and read-only projection are in source. | Native producer and operator acceptance remain distinct from synthetic tests; no sensor or watcher is started. |
| Zeek / #258 | [#299](https://github.com/bartytime4life/MEGALODON/pull/299) merged the offline Community ID API and literal vector tests. | Exact producer profiles, schema-drift fixtures and CLI/report integration remain open. Current correlation requires follow-up on invalid seeds, bounded source consumption and source identity. |
| Detector evidence / #259 | Registry metadata 1.0.1 and the corrected synthetic fixture mapping are present. | Exact-head owner/independent acceptance and representative operational evidence are separate; synthetic counts are not accuracy. |
| Ubuntu / #260 | Closed release-evidence schema, validator and incomplete identity collector are present. | Operator recovery and retained release evidence remain incomplete; identity collection does not publish a release. |
| Local model / #261 | [#300](https://github.com/bartytime4life/MEGALODON/pull/300) merged containment-contract scaffolding. The collector still emits unbound. | Corpus-ID completeness/schema parity and malformed-input refusals require repair. No exact model selection or provider containment acceptance follows from this contract. |
| Defense Console | Owner-private v26 is deployed from Sites source `64d626ac40e30e1bd10d18569918364a90e7176a`. | Three repository mirror files lag at this main pin; this candidate restores parity. No local runtime feed or host control is added. |

The open issue readback contains #258, #259, #260 and #261. PR #300 merged during
this inspection; its earlier non-draft/open state and original review findings
remain historical evidence. Its merged validator still accepts a missing
candidate corpus ID and an overlong ID, despite the review findings. Do not
equate merged scaffolding or passing checks with acceptance of #261.

The next reviewable work is bounded correlation repair, containment validator
repair, parser-test isolation, and this source/document alignment. Each belongs
in an `agent/*` draft PR with current-head tests. These independent slices do
not select model artifacts, invoke tools on the host, or expand runtime authority.
See [the current Site receipt](site-source-alignment.md) for exact source and
deployment identities. This readback is not a validated currentness manifest.

## Historical baseline — September 17

Status: **OBSERVED implementation baseline with remaining acceptance gates**, refreshed 2026-09-17.
Repository basis: [`main@77f082a0548e64f97090c94dd11503a68ca05d99`](https://github.com/bartytime4life/MEGALODON/commit/77f082a0548e64f97090c94dd11503a68ca05d99).
This record reconciles the supplied *MEGALODON — Unified Architecture, Safety,
and Roadmap* with code, contracts, and live GitHub issue dispositions. It does
not adopt the supplied document wholesale or replace the specification and
security review. Tests described below are existing evidence surfaces, not a
new claim of native operational acceptance.

## Historical synthesis assessment

Keep the local, metadata-only evidence appliance as the immediate product.
Separate source observations, fixed detections, policy plans, model advice, and
presentation. Grow integrations through bounded completed evidence with explicit
provenance and failure states. Preserve a read-only loopback dashboard, inert
firewall plans, operator-owned retention, and advisory-only AI. Core operation
must not require a subscription, vendor account, or hosted Site.

## Historical corrections against the September 17 baseline

| Source claim | Disposition at this pin | Repository evidence / remaining gate |
| --- | --- | --- |
| Trust-kernel work must first implement firewall containment, separate dashboard reads, and atomic events | **STALE as implementation backlog.** These controls exist; their acceptance limits remain separate. | `megalodon/firewall.py`, `dashboard_connections.py`, `storage.py`, `tests/test_storage_failures.py`, and the open-control register in `SECURITY_REVIEW.md`. Do not recreate them or claim every operating environment is accepted. |
| Suricata is only contract/import-level and needs its durable consumer | **STALE.** Completed-file reader, explicit atomic consumer, and exact unknown-commit reconciliation exist. | `megalodon/offline/suricata.py`, `suricata_consumer.py`, `suricata_store.py`; closed [#221](https://github.com/bartytime4life/MEGALODON/issues/221) and [#231](https://github.com/bartytime4life/MEGALODON/issues/231). No raw-EVE converter, watcher, sensor launch, or IPS follows. |
| An absolute storage ceiling is still undecided | **PARTLY STALE.** The dedicated Suricata v1 store has a fixed logical 512 MiB ceiling: 131,072 pages of 4 KiB, with no freelist credit. | `contracts/suricata-eve/v1/consumer/README.md`. Per-transaction reservation and free-space checks apply. This is not a whole-disk ceiling, retention duration, automatic deletion policy, or budget for every store. |
| The model process has no reachable filesystem writes or network egress beyond loopback | **UNPROVED.** Client admission and transport are bounded; the separately operated Ollama/model process is not confined by these Python controls. | `docs/model-containment-review.md`: provider identity, loaded-artifact attestation, host-wide concurrency, and direct/transitive provider egress need separate evidence. |
| Every Qwen invocation already lands in the evidence store | **NOT IMPLEMENTED by the original advisory API.** Caller-visible bounded receipts do not imply durable persistence. | `megalodon/qwen_advisory.py` and `docs/model-containment-review.md`; startup receipt display is separate from invoking or storing model results. |
| Q2 follow-up can reuse an advisory while no model output may become later model input | **CONFLICT.** The supplied Q2 wording does not define a consistent input boundary. | Keep Q2 proposed. Any future follow-up needs a closed question enum and original deterministic evidence references; no free-text prior model output or session transcript is authorized by this record. |
| Automation can progress from an inert contract to annotations, schedules, or notifications | **PROPOSED only.** Existing schema tests do not establish a runtime parser/evaluator/executor. | `contracts/automation/v1`, `docs/automation-contract.md`. Each runtime stage needs its own bounded contract, deterministic refusal cases, receipts, and review. |
| Apache-2.0 is settled pending sign-off | **UNDECIDED.** No root license is present at this pin; a recommendation is not a grant. | A license choice and any required attribution review remain an explicit owner decision. No license text is installed by this change. |
| macOS TShark support is a path/packaging question | **INCORRECT for the current Linux boundary.** Admission and descriptor access are Linux-specific. | `offline/common.py` requires Linux and `/proc/self/status`; `offline/tshark.py` uses `/proc/self/fd`. The corrected [macOS proposal](macos-core-acceptance.md) requires a native design and acceptance record. |

The source's references to a nonexistent section 16 and its inconsistent input
count are editorial defects, not missing repository requirements. Its supplied
incident case study is research input; this pass does not authenticate or repeat
its external incident claims. The existing source-pinned containment review
preserves the distinction between supplied bytes and publisher authenticity.

## Historical dependency-ordered delivery

Slices 1–3 were delivered by merged PRs #239/#241/#243 and corrected by #244.
Their presence is not installed-producer, visual or operational acceptance.
PR #245 delivered the simpler HUD launch. PR #269 delivered the bounded STIX
reader; PR #270 integrated the complete currentness schema; PR #271 delivered
the SQLite recovery contract. Deployment evidence remains separately pinned in
the source-alignment receipt.

| Priority | Candidate | Acceptance boundary |
| --- | --- | --- |
| 1 | **Delivered #239:** read-only Suricata evidence projection | Read one existing private exact-schema store, preserve descriptor identity and snapshot locks, bound query and output work, validate source-qualified run/receipt/alert data, and return unavailable without partial rows on ambiguity. Never invoke a consumer or migrate/repair a store. |
| 2 | **Delivered #241:** local tool-readiness report | Explicit operator command, fixed executable names, bounded PATH inspection, no execution/network. Executable presence is neither an installation attestation, compatibility proof, nor running-service health. Unchecked is distinct from missing. |
| 3 | **Delivered #241/#243; corrected by #244:** Defense Console readiness and lifecycle guidance | Hosted telemetry stays unavailable with no generated observations. Accept only a bounded locally selected readiness report in page memory; manual notes persist separately in browser storage. No upload, host probe, command execution or runtime data connection. Preserve private Site identity. |
| 4 | Installed-producer acceptance | Operator-supplied authorized completed evidence, exact producer/version/platform, representative negative cases and timing/resource receipts. A green synthetic parser test or PATH presence report cannot satisfy this gate. |
| 5 | Next adapter or AI field expansion | One closed versioned input proposal, privacy review, explicit source/count units, hostile fixtures, and independent review before broader operational claims. Keep Q2/Q4 and automation side effects proposed. |

The local dashboard and hosted Defense Console are separate products. The
dashboard may read bounded local evidence through explicit operator startup;
the Site is a static reference console with no runtime feed. A Site update or matching GitHub
source mirror cannot establish local sensor liveness or operational acceptance.

## Historical high-level sequence

A historical selected-field currentness capture at 2026-09-17T16:35:48Z–16:35:50Z,
against `2e5099fcec2d1a08007efab70b4607cd5ba652ac`,
observed eight open issues (#254–#261), zero open pull requests, zero releases,
four successful exact-head checks, three successful exact-head workflows, and
active ruleset 22394782 with strict required `test` but zero required
approvals. The manifest validated against the pinned commit/tree. It is not
owner acceptance or independent review, so #254 remains an explicit disposition
gate.

The later `77f082a` readback found the same eight open issues and no open PRs
or releases; all four exact-commit checks and three workflows succeeded.
PR #271 is merged, so recovery-contract delivery is complete even though #256
remains open. See [the alignment record](document-alignment-2026-09-17.md) for
the observation scope; this update is not a new validated currentness manifest.

| Order | Work | Smallest safe outcome |
| --- | --- | --- |
| 0 | #254 currentness disposition | Preserve the immutable receipt and obtain explicit maintainer disposition; do not promote selected-field validation into broad acceptance |
| 1 | #256 SQLite recovery | Contract and standalone engine are on `main`; review the explicit operator-workflow PR and retain native failure/operator acceptance as later evidence gates |
| 2 | #255 license decision | Obtain the owner's actual choice and only then align root/package/SBOM metadata; no release follows automatically |
| 3 | #257 Suricata raw-EVE profile | Select one exact producer profile and close a privacy-minimal converter contract before code or sensor integration |
| 4 | #258 Zeek/correlation qualification | Pin producer profiles and treat Community ID as a non-authoritative grouping hint |
| 5 | #259 detector registry/evaluation | Version the three existing deterministic rules and require corpus, denominator, quality, and uncertainty context |
| 6 | #260 Ubuntu release evidence plan | Define an evidence packet after recovery and license gates; do not tag, publish, or deploy |
| 7 | #261 Ollama/Qwen containment | Post-RC operator-host acceptance only; no new model, tool, persistence, or action authority |

This ordering favors recovery and truthful claims over new ingestion breadth.
The telemetry and model tracks may be designed in parallel, but their runtime
or acceptance claims remain blocked by their named prerequisites.

## Evidence and ownership handoff

For every candidate record the base and final head, changed paths, exact test
commands/results, inherited or environmental failures, draft PR URL and hosted
checks. For Site changes record project/version/source commit, unchanged access,
browser evidence, mirror equality and rollback version. Update the existing
Drive coordination log with those facts while preserving historical checkpoints.

Repository source changes use `agent/*` draft PRs. Green CI and an independent AI
review remain distinct from an owner merge decision and native operational
acceptance. No merge, release, protection change, model request, host operation,
automatic retention, or live-response authority is created by this roadmap.

Before adopting any later source-document stage, resolve its contradictions and
pin it again against current code. A blank approval appendix stays blank until
the actual owner makes that decision.
