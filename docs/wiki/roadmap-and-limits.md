# Roadmap and Current Limits

## Implemented source, separate acceptance

Documentation basis: [`main@0acdf72663804c9ae8380522e344a515ac65978c`](https://github.com/bartytime4life/MEGALODON/commit/0acdf72663804c9ae8380522e344a515ac65978c),
October 22, 2026 (America/Chicago).

The inspected source includes the local Linux HUD, bounded metadata detection,
managed history and local reports, optional companion workflows and local-model
selection, Lynis/AIDE host checks, dated threat-reference context, and a
qualified finding → event → ingestion-run inspector. Core evidence reads,
legacy plan-only firewall interfaces and separately protected HUD actions have
different contracts. Implementation does not authorize operation.

[Current state](https://github.com/bartytime4life/MEGALODON/blob/main/docs/current-state.md)
maps these claims to source. [Case studies](engineering-case-studies.md) retain
their historical October 11 source pin and October 1 benchmark.

## The next evidence gates

| Open issue at this readback | Gate to satisfy |
| --- | --- |
| [#445](https://github.com/bartytime4life/MEGALODON/issues/445) | One exact Zeek offline producer qualification; candidate selection is not acceptance |
| [#446](https://github.com/bartytime4life/MEGALODON/issues/446) | Canonical Qwen Airlock binding and zero-effect/containment/evaluation evidence; record remains UNBOUND |

Issue #345 closed after PR #656 on October 19. Native macOS JSONL, browser,
Intel, second-major-version and operator acceptance remain separate. Open
Playwright PRs #658/#660 do not change main's 1.63.0 profile. Main's October 22
browser check timed out after driver preparation; core CI passed. Read the
[exact checks](https://github.com/bartytime4life/MEGALODON/blob/main/docs/current-state.md#exact-source-head-checks-observed)
before treating a historical passing receipt as current acceptance.

## A useful forward path

1. Verify the reviewed local installation and its evidence/recovery workflows.
2. Complete one named producer or model acceptance gate at an exact revision.
3. Retain results, failures, provenance and independent review before widening scope.

This sequence is **PROPOSED**, not approval to operate tools or alter the host.
Free local capabilities do not remove package, signature, data-sharing or
platform-acceptance obligations.

## Limits that remain visible

- No comprehensive malware elimination, attribution, whole-network visibility,
  representative production accuracy, or independent security certification.
- No model-generated execution, automatic retaliation, general SOAR executor,
  or permission derived from an alert, cached match or model answer.
- No native Windows/macOS parity or long-running capacity across installations
  established by synthetic fixtures.
- The separate **PC Snapshot Console** is an address-free browser import viewer,
  not a live hosted defense service or a connection to the operator PC.

Green CI, human approval, merge, release, installation and Wiki/Site publication
are separate facts. [Owner lifecycle limits](https://github.com/bartytime4life/MEGALODON/blob/main/docs/exact-head-owner-lifecycle.md)
also remain explicit. Read [security boundaries](security-boundaries.md) and
[the evidence index](evidence-index.md) before expanding a claim.
