Template status: **Contract only.** This form collects review evidence; the
submission's own status must be stated from its actual change and tests.

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
