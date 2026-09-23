# System opportunity map

Status: ◐ **Proposed sequencing, refreshed source dispositions below**. This is
a design record, not an acceptance receipt. Original ranking basis: GitHub
`main@97c5798f53b539bbcb487eaa7c8ff07ac0344041` (tree
`6384a3fe4e743cbce274d654b413f8a07c1e4cff`) and repository files read on
2026-09-21. Recheck mutable issue, PR, workflow, and Site state before acting.

Source refresh: `28436055449f8d7ba0662da699da24c53153ba09`, inspected
2026-09-23. Windows/macOS synthetic jobs and the named governance files now
exist; their old absence claims are superseded below. Job presence is not a
passing result or platform acceptance. The
[suite claims register](unified-roadmap-currentness.md#current-suite-claims-and-acceptance-register--2026-09-23)
owns the current coordination index; this map retains its historical ranking.
No mutable issue/check state was refreshed here.

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

## Ranked candidate slices

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
