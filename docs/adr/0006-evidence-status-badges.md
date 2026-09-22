# ADR-0006: Evidence status badges — a fixed five-level claim taxonomy

Status: **Proposed.** This record fully describes the decision and its
authority limits in prose; it defines no schema, code, or UI element, and
none is implemented by this file.

Decision state: **Proposed**. No owner or independent review has accepted
this decision. Do not infer acceptance from this record's presence, from a
later merge of this PR, or from a green workflow.

- Date: 2026-09-22
- Owner/reviewer: `not_recorded`
- Exact source basis: `main@f0056779b20326a7e3e696bf2d221f106250fc33` (tree
  `2e787aba7ea6863a0d0a84ee160b5697170cd4a1`)

## Context and decision needed

Every document in this repository already distinguishes **implemented**,
**proposed**, **contract only**, **synthetic**, and **native receipt
required** evidence, and refuses to let a passing test, a merged PR, or
green CI imply broader acceptance than it actually demonstrates. That
distinction is real and consistently applied — but it currently exists only
as free-text prose, restated with slightly different wording in almost every
file's opening paragraph (compare `docs/adapter-count-receipts-design.md`'s
"Status: **Proposed.**", `contracts/zeek-conn-log/v1/producer/README.md`'s
"Status: **Scaffold only.**", and `docs/detector-acceptance.md`'s "Status:
adopted bounded synthetic acceptance receipt."). A reader has to read each
document's opening sentence to learn how much to trust it; nothing lets them
tell at a glance, across a table, a README, or the dashboard UI, which claims
are which.

This is not a defect in any one document — each is precise on its own terms.
It is a missing shared vocabulary: the repository's most distinctive
property (refusing to overclaim) is not currently legible without reading
prose.

## Proposed decision

Adopt one fixed, five-level "Evidence status" taxonomy, and use it — as a
short glyph-plus-label pair, never a glyph alone — anywhere this repository
currently states or implies how much a claim is backed by:

| Glyph | Label | Grammar (always paired with the glyph) |
| --- | --- | --- |
| ● | Implemented | "Code and tests on `main` demonstrate this." |
| ◐ | Proposed | "Design only — no code implements this yet." |
| ◇ | Contract only | "Schema/fixtures exist — no runtime path uses them." |
| ▽ | Synthetic | "Exercised against fabricated data, not a real producer/host." |
| ◆ | Native receipt required | "Blocked on an owner-authorized host/model this record cannot supply." |

Rules that are part of the decision, not implementation detail:

1. **Shape-coded, not color-only.** Each glyph is a distinct shape so the
   badge survives grayscale rendering and colorblind viewers. Color (if used
   at all in a rendered surface) is a secondary reinforcement, never the only
   signal.
2. **Text is mandatory.** `◐ Proposed` is the unit; a bare glyph never
   appears alone in prose or UI. This stops the badge from becoming a status
   claim floating free of the sentence that justifies it — the same failure
   mode this repository already guards against for tests and merges.
3. **Closed vocabulary.** Exactly five levels. If a claim does not fit one of
   them, the document needs to say more, not add a sixth badge. This mirrors
   the fixed-enum discipline `megalodon/storage.py` already applies to
   `termination_reason` and `failure_code`.
4. **Per-claim, not per-document.** A document may carry an overall badge in
   its header and a different, more specific badge on an individual table row
   or sentence inside it — matching how existing docs already qualify one
   sentence at a time (for example `docs/detector-acceptance.md` closing a
   contract gate in one sentence while marking accuracy claims separately
   unproved).
5. **This ADR does not retire existing `Status:` prose.** The badge is a
   compact prefix alongside the existing explanatory sentence, not a
   replacement for it. Nothing here shortens or waters down an existing
   disclaimer.

## Alternatives considered

- **Color-only badges (e.g., a colored dot with no label).** Rejected:
  fails without color vision or in a printed/grayscale context, and
  a bare colored dot is exactly the kind of unexplained status signal this
  repository's culture exists to avoid.
- **Free-text status per document, left as-is.** Rejected as the status quo:
  precise but not scannable, and asks every new document to reinvent its own
  phrasing of the same five underlying levels this repository already uses
  informally and consistently.
- **A numeric or letter-grade scale (e.g., A/B/C/D confidence tiers).**
  Rejected: implies a continuous, comparable ranking ("B is 80% as good as
  A") that this repository's actual evidence levels do not support — contract
  only and synthetic are different *kinds* of gap, not different amounts of
  the same thing.
- **Reusing existing schema enums (`termination_reason`, `failure_code`,
  `basis` values like `synthetic_contract_fixture`/`collector_output`) as the
  display vocabulary directly.** Rejected as the single source: those are
  real, narrower, code-level enums for specific subsystems. This taxonomy is
  a superset used for human-facing communication across the whole repository,
  including documents with no corresponding schema at all (most `docs/*.md`
  files). A future mapping from a specific schema enum to one of these five
  badge levels is reasonable and left open, not decided here.

## Consequences and controls

- **Affected paths, if adopted:** doc headers across `docs/`, `SPECIFICATION.md`,
  `SECURITY_REVIEW.md`, and contract READMEs (a documentation-only change);
  the README's status tables; `.github/PULL_REQUEST_TEMPLATE.md` (adding one
  required field); and, as later, separate work, the dashboard UI
  (`megalodon/dashboard_assets.py` / the served HTML), which would need its
  own review since it touches rendered, CSP-governed output rather than only
  Markdown.
- **Compatibility obligations:** none of this changes any schema, API route,
  or stored data. It is a presentation convention layered over decisions
  that already exist.
- **Negative controls before adopting badges anywhere:** a linter or review
  check that every badge use is one of the five closed glyph+label pairs
  (catching drift or an invented sixth level); a check that no rendered
  surface uses the glyph without its label; a check that adding a badge to a
  document does not change or remove that document's existing `Status:`
  sentence.
- **Reversibility:** fully reversible. Removing a badge removes a prefix; the
  underlying prose disclaimers this ADR deliberately does not touch remain
  as the authoritative statement either way.
- **Review needed before implementation:** none of this requires security,
  host, license, or model-selection review — it is a documentation and UI
  presentation convention. It does need ordinary PR review for wording and
  placement, and, if applied to the dashboard, the same review any other
  dashboard-rendered-content change gets.

## Evidence and remaining gate

This ADR is prose only; no command output, test, or workflow run applies to
it. It establishes no operator, security, host, release, sensor, or platform
acceptance of anything the badges would later be attached to — a document
marked `● Implemented` under this taxonomy is exactly as implemented as it
already was before this ADR existed; the badge changes legibility, not
truth. What remains before this taxonomy is actually visible anywhere:

- Apply it to a first, narrow surface — proposed as a separate, single-scope
  PR that only prefixes existing `docs/*.md` `Status:` headers with the
  matching glyph, changing no other wording.
- A later, separate PR to add the required field to
  `.github/PULL_REQUEST_TEMPLATE.md`.
- A later, separate, larger PR to surface badges in the actual dashboard UI,
  which needs its own review of rendering, CSP, and accessibility, and is
  explicitly out of scope for this ADR.
- Maintainer disposition on whether this taxonomy is accepted at all; this
  record proposes it and does not itself accept it.

## Supersession

None. This is the first record of this decision.
