# System opportunity map

Status: **Proposed**. This is a design and sequencing record, not an
implementation or acceptance receipt. Basis: GitHub
`main@97c5798f53b539bbcb487eaa7c8ff07ac0344041` (tree
`6384a3fe4e743cbce274d654b413f8a07c1e4cff`) and repository files read on
2026-09-21. Recheck mutable issue, PR, workflow, and Site state before acting.

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
| 1 | Windows synthetic CI receipt: expose portable core regressions earlier | `contracts/platform/windows-core-v1/acceptance.json` names `synthetic_reusable` tests. No `windows-latest` job exists; platform-specific path/runner behavior needs an explicit skip and failure inventory. Medium risk. | Exact job head, Windows runner/Python, selected tests with pass/fail/skip, and named `native_receipt_required` gaps. Private NTFS, loopback/browser and unsupported-operation checks still need native review. |
| 2 | macOS M1 synthetic CI receipt: make the proposed first stage inspectable | `docs/macos-core-acceptance.md` defines M0/M1; no `macos-latest` job exists. Choose a narrow core-only command set and record architecture/version. Medium risk. | Exact runner, `sw_vers`, architecture, Python, commands and outcomes. A hosted runner result is one M1 execution receipt, not two-architecture acceptance or M2/M3 support. |
| 3 | Governance and ADR discoverability: guide contributors and preserve decisions | `SECURITY.md`, community templates, CODEOWNERS, NOTICE and `docs/adr/` are absent. Existing dated alignment and license decisions are available to index. Low code risk; disclosure contact, owners, conduct policy and legal notices need maintainer selection. | Maintainer-reviewed disclosure/ownership text, template usability, attribution inventory, and an ADR index that links existing documents without rewriting them. |
| 4 | #260 exact Ubuntu candidate packet: support a bounded release decision | `tools/release_evidence_packet.py` already generates CycloneDX/in-toto output from a complete candidate; `.github/workflows/release-subject-evidence.yml` retains exact-head temporary wheel/sdist subjects. High dependency and review risk. | Complete nine-check/two-artifact packet, independent artifact notice/license and provenance review, supported-platform/optional-source behavior, retained operator recovery drill, and exact-candidate owner/independent disposition. No tag or release follows automatically. |
| 5 | #327 Zeek producer qualification: prevent silent conn.log drift | Pure Community ID work and offline Zeek adapters exist; #327 selects neither an exact producer profile nor real JSON/TSV fixtures. High dependency on owner-selected version/build/field set. | Version/configuration provenance, real positive and negative JSON/TSV fixture digests and schema-drift outcomes, source/units/timestamp checks, and CLI/report evidence on that profile. |
| 6 | Core adapter/count receipts: explain attempted versus committed input | Current v3 run rows prove linked stored counts and terminal state only. Fail-fast intake does not retain every rejection or exact adapter version. High migration and semantics risk. | Reviewed per-source accepted/rejected definitions, failure/partial/replay behavior, schema migration and rollback proof, v1 compatibility, bounded v2 successor, and source-switch/export tests. |
| 7 | Alert lifecycle wiring survey: plan operator triage without delivery authority | `megalodon/alert_lifecycle.py` is process-local; `docs/alert-lifecycle-contract.md` says storage, CLI and HUD are unwired. Security review still lists operator identity, retention, native storage and external-delivery controls. Medium/high risk. | Operator/security review of identity, authorization, atomic persistence and uncertain commits before any storage migration or UI action; delivery needs a separate adapter-specific review. |
| 8 | #261 provider containment: keep model advice bounded | AI client and private receipt code exist, but exact model/provider containment is unproved. High host-security dependency. | Separately authorized exact model and host collector, provider filesystem/resource/egress evidence, adversarial corpus, and independent security disposition. Do not enable the provider from this record. |

NOTICE is listed with governance for inventory planning only. The Apache-2.0
repository selection and a generated SBOM do not themselves review third-party
attribution or built-artifact notices. Windows/macOS jobs would report what ran;
they would not change the unsupported platform catalog without native acceptance.
No candidate here changes issue disposition; maintainers decide that separately.
