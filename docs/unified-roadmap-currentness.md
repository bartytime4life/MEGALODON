# Unified roadmap: repository reconciliation

Status: **OBSERVED implementation baseline with remaining acceptance gates**, refreshed 2026-09-17.
Repository basis: [`main@2e5099fcec2d1a08007efab70b4607cd5ba652ac`](https://github.com/bartytime4life/MEGALODON/commit/2e5099fcec2d1a08007efab70b4607cd5ba652ac).
This record reconciles the supplied *MEGALODON — Unified Architecture, Safety,
and Roadmap* with code, contracts, and live GitHub issue dispositions. It does
not adopt the supplied document wholesale or replace the specification and
security review. Tests described below are existing evidence surfaces, not a
new claim of native operational acceptance.

## What the supplied synthesis gets right

Keep the local, metadata-only evidence appliance as the immediate product.
Separate source observations, fixed detections, policy plans, model advice, and
presentation. Grow integrations through bounded completed evidence with explicit
provenance and failure states. Preserve a read-only loopback dashboard, inert
firewall plans, operator-owned retention, and advisory-only AI. Core operation
must not require a subscription, vendor account, or hosted Site.

## Corrections against the pinned baseline

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

## Dependency-ordered delivery

Slices 1–3 were delivered by merged PRs #239/#241/#243. Their presence is not
installed-producer, visual or operational acceptance. This alignment pass removes
the hosted demonstration data and corrects lifecycle guidance; its PR/deployment
state is recorded separately in the source-alignment receipt.

| Priority | Candidate | Acceptance boundary |
| --- | --- | --- |
| 1 | **Delivered #239:** read-only Suricata evidence projection | Read one existing private exact-schema store, preserve descriptor identity and snapshot locks, bound query and output work, validate source-qualified run/receipt/alert data, and return unavailable without partial rows on ambiguity. Never invoke a consumer or migrate/repair a store. |
| 2 | **Delivered #241:** local tool-readiness report | Explicit operator command, fixed executable names, bounded PATH inspection, no execution/network. Executable presence is neither an installation attestation, compatibility proof, nor running-service health. Unchecked is distinct from missing. |
| 3 | **Delivered #241/#243; corrected in this pass:** Defense Console readiness and lifecycle guidance | Hosted telemetry stays unavailable with no generated observations. Accept only a bounded locally selected readiness report in page memory; manual notes persist separately in browser storage. No upload, host probe, command execution or runtime data connection. Preserve private Site identity. |
| 4 | Installed-producer acceptance | Operator-supplied authorized completed evidence, exact producer/version/platform, representative negative cases and timing/resource receipts. A green synthetic parser test or PATH presence report cannot satisfy this gate. |
| 5 | Next adapter or AI field expansion | One closed versioned input proposal, privacy review, explicit source/count units, hostile fixtures, and independent review before broader operational claims. Keep Q2/Q4 and automation side effects proposed. |

The local dashboard and hosted Defense Console are separate products. The
dashboard may read bounded local evidence through explicit operator startup;
the Site is a static reference console with no runtime feed. A Site update or matching GitHub
source mirror cannot establish local sensor liveness or operational acceptance.

## Current high-level sequence

A selected-field currentness capture at 2026-09-17T16:35:48Z–16:35:50Z
observed eight open issues (#254–#261), zero open pull requests, zero releases,
four successful exact-head checks, three successful exact-head workflows, and
active ruleset 22394782 with strict required `test` but zero required
approvals. The manifest validated against the pinned commit/tree. It is not
owner acceptance or independent review, so #254 remains an explicit disposition
gate.

| Order | Work | Smallest safe outcome |
| --- | --- | --- |
| 0 | #254 currentness disposition | Preserve the immutable receipt and obtain explicit maintainer disposition; do not promote selected-field validation into broad acceptance |
| 1 | #256 SQLite recovery | Land the contract, fixtures, reason codes, and fault runbook first; runtime backup/restore remains a separate PR |
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
