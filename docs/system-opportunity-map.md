# System opportunity map

Status: ◐ **Proposed sequencing, refreshed source dispositions below**. This is
a design record, not an acceptance receipt. Original ranking basis: GitHub
`main@97c5798f53b539bbcb487eaa7c8ff07ac0344041` (tree
`6384a3fe4e743cbce274d654b413f8a07c1e4cff`) and repository files read on
2026-09-21. Recheck mutable issue, PR, workflow, and Site state before acting.

Earlier source refresh retained as historical context:
`28436055449f8d7ba0662da699da24c53153ba09`, inspected 2026-09-23.
Windows/macOS synthetic jobs and the named governance files existed at that
snapshot; their old absence claims are superseded below. Job presence is not a
passing result or platform acceptance. The
[suite claims register](unified-roadmap-currentness.md#current-suite-claims-and-acceptance-register--2026-09-23)
owns the current coordination index; this map retains its historical ranking.
No mutable issue/check state was refreshed for that earlier snapshot.

## Current refresh — 2026-09-27

This refresh was read after merged PR #436 and before opening any follow-up
proposal. GitHub `main` was
`8aa0f0d0a7526c6a3d389868c01a1385130ef2eb` with tree
`54c12af58d9189bd4cbc2f050df44066913769dd`. The readback found one open
issue, [#345](https://github.com/bartytime4life/MEGALODON/issues/345), zero
open pull requests, zero open code-scanning alerts, and zero releases.
Code-scanning alert #3 is fixed on current `main`; this does not review every
regular expression or establish a broader security disposition.

The Sites project read API still reports Console version 40 as the live
publication, with custom access limited to one owner account and zero external
visitors, from Sites source
`5e5da36d53cfeb689878b2c5a841a188f3fa1d8a`. Repository `main` now also
contains PRs #434–#436, including the passive Activity evidence state and the
replacement of the hosted Runbooks view with repository workflow
documentation. Those later repository changes have no version/deployment
receipt here. A merged Site-source change is not a Site publication, and the
live version is not evidence of local telemetry, host acceptance, or source
parity beyond its recorded archive.

Later on 2026-09-27, a new Sites readback found owner-only version 41 published
successfully. Its source commit, archive digest, deployment and audience are
recorded in [the current Site receipt](site-source-alignment.md). This later
readback does not establish v41 source-byte parity or rendered acceptance; the
version-40 statement above remains the earlier snapshot, not current live state.

The structural backlog that motivated the original ranking is largely present:
governance/community files, ADR indexing, Windows and macOS synthetic jobs,
CycloneDX/provenance packet generation, the placeholder Zeek producer contract,
and the proposed alert-lifecycle wiring survey are checked in. Presence is not
enforcement, native acceptance, producer qualification, release evidence, or
operator approval.

## Ranked next gates — 2026-09-27

Rank reflects operator benefit, evidence available now, dependencies,
implementation risk, and the next receipt that would change the claim. Closed
issues remain closed; residual evidence gaps are described without reopening
or changing their disposition.

| Rank | Next gate and benefit | Evidence now; dependency / risk | Receipt still required |
| --- | --- | --- | --- |
| 1 | Reconcile #345 against the repaired macOS M1 sample | The macOS synthetic workflow now passes its hosted arm64 sample, while #345 remains the only open issue and retains its earlier `DATABASE_CHANGED` failure statement. This is an issue/currentness mismatch, not macOS acceptance. | Exact fix/candidate identity, retained 13/114 sample outcomes and native substitution/sidecar negative controls, followed by maintainer disposition. JSONL, browser, x86_64 and operator privacy gates remain separate. |
| 2 | Assemble the Ubuntu candidate evidence packet | The packet generator, exact-subject workflow, Apache-2.0 metadata and recovery tooling exist. Issue #260 closed with a partial disposition. | One retained exact-candidate nine-check/two-artifact packet, independent notice/license and provenance review, optional-source behavior evidence, operator recovery drill, and owner/independent disposition. No tag or release follows automatically. |
| 3 | Qualify one real Zeek producer profile | The checked-in producer contract deliberately uses a placeholder `0.0.0` profile; issue #327 closure did not select a producer. | Owner-selected version/build/field set, provenance, real JSON and TSV accepted/rejected fixtures, drift/truncation outcomes, and CLI/report evidence. |
| 4 | Decide adapter/count receipt semantics before schema work | Schema-v3 receipts already prove committed events, findings and action-plan records. [The proposed design](adapter-count-receipts-design.md) explains why `sample`, fail-fast JSONL and Scapy filtering cannot share invented accepted/rejected meanings. | Operator/security decision on per-source attempt/rejection definitions, bounded reason codes and rejection ceilings before any explicit migration, v2 successor, rollback proof, mixed-version query or source-switch/export test. Keep current fields `not_recorded` meanwhile. |
| 5 | Review alert lifecycle identity and persistence boundaries | The in-memory engine and [proposed wiring survey](alert-lifecycle-wiring-survey.md) exist; storage, CLI and dashboard wiring do not. | Operator/security review of identity, authorization, retention, atomic persistence, concurrency and uncertain commits before a migration or UI action. External delivery needs a separate adapter-specific review. |
| 6 | Retain the model containment hold | Cross-contract readiness can check internal packet consistency, but the canonical binding remains unbound and issue #261 closure does not select model bytes. | Exact owner-selected model/provider digests, loaded-runtime identity, filesystem/resource/egress observations, signed adversarial corpus and independent security disposition. |
| 7 | Complete native platform receipts | Windows and macOS jobs provide useful synthetic regression evidence without changing the Linux-reference catalog. | Windows 11 NTFS/loopback/browser checks and macOS architecture, JSONL/browser/privacy evidence on named native environments. |
| 8 | Verify the current Site publication against repository source | Owner-restricted v41 is live with a version, archive, deployment, audience and rollback receipt; v41 source-byte parity and rendered acceptance are unverified. | Review the exact v41 source bytes against the intended repository mirror and check the rendered owner-only page. Future edits need their own publication receipt. |

The current core ingestion path admits `sample`, `jsonl`, or `scapy`, commits an
event and its linked findings/action records with the run counter in one
transaction, and stores a terminal run reason. Source filtering in
`/api/ingestion-runs-v2` precedes its row limit; the v1 route remains separate.
Traffic/history apply their own receipt qualification and bounds. The HUD's
all-source receipt snapshot can feed a browser-local report, while a selected
source filter changes only the receipt panel. The store records neither an
adapter version/identity nor accepted/rejected input counts. A source label,
stored event, empty response, successful read, or report is not a sensor
heartbeat or a zero-traffic measurement. Future schema work must retain
`not_recorded` until the actual intake path can supply each field.

## Historical ranked candidate slices — 2026-09-23

Rank reflects operator benefit, evidence already available, dependencies,
implementation risk, and the receipt still needed. None is authorized by this
record alone.

| Rank | Candidate and benefit | Evidence now; dependency / risk | Next receipt still required |
| --- | --- | --- | --- |
| 1 | Windows synthetic CI receipt: expose portable core regressions earlier | **Job delivered:** `.github/workflows/windows-synthetic-core.yml` selects the matrix's `synthetic_reusable` tests on `windows-latest`, recording candidate and runner identity plus actual outcomes. | Retain exact-head results and named `native_receipt_required` gaps. Windows Server CI is not Windows 11 W1 acceptance; private NTFS, loopback/browser and unsupported-operation checks still need native review. |
| 2 | macOS M1 synthetic CI receipt: make the proposed first stage inspectable | **Job delivered:** `.github/workflows/macos-m1-synthetic.yml` runs bounded sample/demo paths and native storage negatives on `macos-latest`; `docs/macos-core-acceptance.md` owns the remaining stages. | Retain exact runner, architecture, Python and outcomes, including failed historical runs. One hosted result does not supply both architectures, JSONL/browser/privacy acceptance or M2/M3 support. |
| 3 | Governance and ADR discoverability: guide contributors and preserve decisions | **Files delivered:** `SECURITY.md`, `CODE_OF_CONDUCT.md`, community templates, root `CODEOWNERS`, `NOTICE` and `docs/adr/` exist. Their presence does not establish enforcement or independent approval. | Retain maintainer decisions, check template usability, and review the exact built subjects' attribution/notices. Preserve historical decisions rather than replacing them with a green check. |
| 4 | #260 exact Ubuntu candidate packet: support a bounded release decision | `tools/release_evidence_packet.py` already generates CycloneDX/in-toto output from a complete candidate; `.github/workflows/release-subject-evidence.yml` retains exact-head temporary wheel/sdist subjects. High dependency and review risk. | Complete nine-check/two-artifact packet, independent artifact notice/license and provenance review, supported-platform/optional-source behavior, retained operator recovery drill, and exact-candidate owner/independent disposition. No tag or release follows automatically. |
| 5 | #327 Zeek producer qualification: prevent silent conn.log drift | Pure Community ID work and offline Zeek adapters exist. `contracts/zeek-conn-log/v1/producer/README.md` explicitly identifies its profile as a placeholder scaffold; no qualified version or real JSON/TSV fixture set is supplied there. | Owner-selected version/build/field set and provenance, real positive and negative JSON/TSV fixture digests and schema-drift outcomes, source/units/timestamp checks, and CLI/report evidence on that profile. Issue closure cannot substitute for these receipts. |
| 6 | Core adapter/count receipts: explain attempted versus committed input | Current v3 run rows prove linked stored counts and terminal state only. Fail-fast intake does not retain every rejection or exact adapter version. High migration and semantics risk. | Reviewed per-source accepted/rejected definitions, failure/partial/replay behavior, schema migration and rollback proof, v1 compatibility, bounded v2 successor, and source-switch/export tests. |
| 7 | Alert lifecycle wiring survey: plan operator triage without delivery authority | `megalodon/alert_lifecycle.py` is process-local; `docs/alert-lifecycle-contract.md` says storage, CLI and HUD are unwired. Security review still lists operator identity, retention, native storage and external-delivery controls. Medium/high risk. | Operator/security review of identity, authorization, atomic persistence and uncertain commits before any storage migration or UI action; delivery needs a separate adapter-specific review. |
| 8 | #261 provider containment: keep model advice bounded | AI client and private receipt code exist, but exact model/provider containment is unproved. High host-security dependency. | Separately authorized exact model and host collector, provider filesystem/resource/egress evidence, adversarial corpus, and independent security disposition. Do not enable the provider from this record. |

NOTICE is present; the Apache-2.0 repository selection and a generated SBOM do
not themselves review third-party attribution or built-artifact notices.
Windows/macOS jobs report only what ran and do not change the platform catalog
without native acceptance.
No candidate here changes issue disposition; maintainers decide that separately.
