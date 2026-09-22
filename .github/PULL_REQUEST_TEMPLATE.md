Template status: **Contract only.** This form collects review evidence; the
submission's own status must be stated from its actual change and tests.

## Evidence level

State one badge from the fixed five-level taxonomy in
[ADR-0006](../docs/adr/0006-evidence-status-badges.md) for this PR's own
primary claim — the glyph and its label together, never the glyph alone:

- `● Implemented` — code and tests on `main` (after merge) demonstrate this.
- `◐ Proposed` — design only; no code implements this yet.
- `◇ Contract only` — schema/fixtures exist; no runtime path uses them.
- `▽ Synthetic` — exercised against fabricated data, not a real producer/host.
- `◆ Native receipt required` — blocked on an owner-authorized host/model
  this PR cannot supply.

If this PR's change does not fit exactly one of the five cleanly (for
example, it bundles two distinct claims, or it is documentation with no
capability claim at all), say so explicitly here rather than picking the
closest label.

## Defect or operator task

Describe the specific defect, evidence gap, or task. Link the motivating
contract, document, or issue. State whether this is implemented behavior,
proposed design, contract-only work, or synthetic evidence.

## What changes

List the exact paths and the narrow behavior or documentation change. Record
the base and head commit (and tree when the change is evidence-bound).

## Verification

- Focused command, environment, result, and skips:
- Full-suite command, environment, result, and skips:
- Hosted exact-head workflow/run links, or `not_run`:

## Negative controls

List malformed, stale, unavailable, failure, refusal-before-side-effect, or
other relevant cases exercised. Name any relevant case that remains untested.

## What remains unproved

- State the host, sensor, operator, release, platform, or producer acceptance
  claims this change does not establish.
- State any remaining privacy, security, migration, or rollback gate.

## Issue advanced

Name the open issue or `none`. Do not use this PR or a passing check to close
or resolve an issue; maintainers make that disposition.
