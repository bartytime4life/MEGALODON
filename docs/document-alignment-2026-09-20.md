# Document and file alignment — 2026-09-20

## Authority and source preservation

The owner selected the current MEGALODON working files as the alignment authority,
with unfinished changes preserved. This checkout was advanced from
`3bdcfb96a155d5dc4d7009e75f3b3c0986e5590b` to
`4c1d685a967ed60d87adbef9fb548af96806e5bf` (merged PR #306), then the
20 original modified/new files were reapplied. A separate private backup and Git
stash retain the original bytes. Two Site conflicts were reconciled by keeping
the local Prepare / Launch / Review flow plus newer navigation, same-device
wording, detector evidence, and Apache-2.0 disclosure. Local work remains
uncommitted; a separate review snapshot is used for GitHub delivery.

This record concerns source and document consistency. It is not a repository
currentness manifest, a new security certification, independent acceptance, or
an installed-producer receipt. No private Drive body, runtime database, secret,
or local environment is copied into the public repository.

## Current implementation and remaining evidence

| Area | Observed state | Boundary |
| --- | --- | --- |
| Local PC | Manual `scripts/start-local.sh`, read-only `--check`, Home → Data and tools, clean interruption and occupied-port guidance are preserved | Python >=3.11; Linux reference; no installation, automatic startup, sensors or sample data |
| Recovery | Explicit bounded online backup/restore plus native-failure and destination-binding fixes are present | Operator drill, physical failure, sustained WAL and Windows evidence remain separate |
| License | Apache-2.0 and package metadata merged in #298; #255 closed completed | Artifact notices, SBOM/provenance and a release are separate |
| Detector evidence | Registry metadata 1.0.1; three rule versions 1.0.0; 12 synthetic scenarios / 6,492 events | #259 remains open for scoped exact-head acceptance; corpus counts are not operational accuracy |
| Ubuntu evidence | #306 merged; empty systemd identity output refuses and new license collection reports `not_assessed` | #260 remains open for complete nine-check/two-artifact evidence, retained recovery drill, provenance and acceptance |
| Correlation | #299/#302 provide bounded distinct-source grouping and Community ID vectors | #258 is closed completed in GitHub, but its body still lists producer-profile/schema-drift qualification as outstanding; closure alone supplies no missing evidence |
| Model containment | #300/#301 deliver contract and input/corpus validation; collector stays `unbound` | #261 remains open for exact model binding, authorized host observations, signed corpus and independent review |
| Hosted Console | Static, owner-private reference surface; no local telemetry feed | Publication and source equality require the separate [Site receipt](site-source-alignment.md) |

Live issue reads found #254–#258 closed completed and #259–#261 open. The
#258 lifecycle/body discrepancy is retained explicitly rather than converting
closure into producer acceptance. PR #306 is merged; references to reviewing
its draft are historical. The descriptions of #258 and #260 were corrected to reflect closure and the
#306 merge; issue states and acceptance checkboxes were preserved.

## Document ownership

- README, specification and security review describe the current source and link
  this record; specialized contracts retain their exact behavior and limits.
- The unified roadmap and repository-currentness runbook distinguish current
  delivery from dated observations. Historical receipts retain their original
  SHAs, tests and limitations.
- `docs/wiki/` is the reviewed source for GitHub's generated Wiki. Its launcher,
  roadmap and license guidance are refreshed; native publication follows the
  existing main-merge workflow.
- The existing Drive coordination log, command-center blueprint, platform
  roadmap and project instructions receive the same current alignment basis.
  Dated handoffs, proposals, original research and the unapplied milestone ZIP
  remain historical inputs; they are not renamed, moved, overwritten, or
  promoted into executable authority.
- `site/` retains the existing project and owner-only audience. Its setup guide
  links to the alignment branch because the local launcher is review-pending.
  The installed-package command remains available for older installations.

## Validation and delivery

On the reconciled source with Python 3.12.3:

- Full Python suite: **2,899 passed, 1 skipped** (installed-TShark opt-in).
- Focused launcher/HUD checks: **166 passed**; Site Node suites: **41 passed**.
- Generated Wiki validation: **9 pages**; newly linked setup/alignment documents
  are mapped by the existing publisher.
- Repository hygiene, deterministic build-input inventory, Python compilation,
  static JavaScript syntax and diff whitespace checks passed.
- Of the original 20 changed/new files, 12 retain identical bytes and 8 include
  reviewed upstream/alignment changes; no unrelated original file changed.

The original 2026-09-19 browser and package results remain in the local-PC
readiness review; they are historical, not fresh browser or installed-package
acceptance for this tree. Hosted CI belongs to the review snapshot's exact
commit and is reported by GitHub separately. Site publication identities are
recorded in [the Site receipt](site-source-alignment.md).
