# Local-model containment acceptance plan (future gate)

Status: adds the closed, machine-readable shape for the future
operator-owned acceptance gate [issue #261](https://github.com/bartytime4life/MEGALODON/issues/261)
asks for. It does not invoke a model, install or start Ollama, select an
artifact, enable persistence, expose the dashboard remotely, run a host-level
check, or authorize a release — none of which this change is permitted to do.
Advances #261; keep it open as post-RC work.

## Why this exists

The existing [local model advisory contract](local-model-advisory-contract.md)
and [incident-informed containment review](model-containment-review.md) prove
application-level boundaries: the closed request/result schema, the
fingerprint-pinned registry, and the one-request literal-loopback client. They
explicitly do not prove that the separately run Ollama/model *process* has no
external egress, filesystem mutation, artifact substitution, hostile
cancellation behavior, or host-wide concurrency — because no owner-approved
exact model alias/artifact exists yet to test, and testing it requires a real
host and a real process outside this Python application.

This change adds the packet shape that a future, operator-authorized
acceptance run would fill in, expressed the same way the
[Ubuntu 24.04 release-evidence contract](ubuntu-release-evidence.md) expresses
missing evidence: closed fields that start out honestly empty rather than a
schema that only exists once real evidence is ready.

## What is here

- [`contracts/local-model-containment/v1/schema.json`](../contracts/local-model-containment/v1/schema.json) —
  the closed `local-model-containment-acceptance-v1` shape: a model binding
  (alias, artifact digest, registry fingerprint, operator approval — `null`
  until one exists), wrapper reachability (loopback-only, outbound-deny test,
  no-cloud configuration), process boundary (identity, lifecycle, one-slot
  rejection, cancellation/timeout, filesystem-mutation absence, host-wide
  concurrency absence), an adversarial-corpus summary keyed to the seven
  categories #261 names (injection, fabricated evidence IDs, Unicode/control
  text, privacy, exhaustion, cancellation, out-of-distribution), evidence
  retention (`privacy_minimized_ids_only`, no raw advisory text), and two
  gates (operator model selection, independent security review).
- [`tools/local_model_containment.py`](../tools/local_model_containment.py) —
  `validate()` applies the semantic rules JSON Schema alone cannot express;
  `collect()` reports the fixed `unbound` state, because no operator-approved
  binding currently exists for it to describe.
- Fixtures under `contracts/local-model-containment/v1/fixtures/`: one
  accepted synthetic `unbound` packet and fifteen rejected semantic
  violations (an unexpected binding while unbound, a false effect claim, an
  inconsistent adversarial-corpus count, an unsupported corpus category, an
  invalid enum value, a polluted "empty" state, and more).
- [`tests/test_local_model_containment.py`](../tests/test_local_model_containment.py) —
  exercises every rejected fixture, a hypothetical fully-passed
  `candidate_evidence` shape (accepted only when `basis` is `collector_output`,
  never `synthetic_contract_fixture`), per-field completeness requirements for
  that acceptance state, and the CLI.

## What a `candidate_evidence` status would still not mean

Even a structurally complete, `collector_output`-basis packet is not an
attestation, an independent review, authentic publisher provenance of the
model bytes actually loaded, or authorization to enable, schedule, or expose
the provider. `validate()` rejects `basis: synthetic_contract_fixture` with
`status: candidate_evidence`, but that is a consistency rule, not origin
authentication. A hand-written JSON file can claim `basis: collector_output`,
fill the required fields and pass validation. Neither that string nor an
`operator_approved: true` or review `recorded` field authenticates its claim.

The CLI's outer `status: validated` means only that the supplied packet passed
structural and semantic checks. `manifest_sha256` identifies canonical packet
bytes; it is not a signature, publisher verification, independent checkpoint,
or proof that any observation occurred. Treat supplied packets as untrusted
self-reports until a separately reviewed evidence-ingestion process verifies
origin, exact candidate identities, corpus signatures, execution receipts and
independently attributable owner/reviewer decisions. Do not close #261 from
these fields alone or relabel a synthetic packet to satisfy a gate.

`collect()` still emits only the fixed `unbound` packet. Validating or editing a
supplied packet does not change that state or cause host inspection. The packet's
`effects` fields describe the helper's non-effects, not measured zero prohibited
effects over a provider corpus; those observations need their own signed,
privacy-minimized receipts and executed denominators. NOT_RUN is not a passing
`0/N` claim. The schema, validator rules, receipt shape and runtime authority
remain unchanged by this clarification.

The [trust-boundary regressions](../tests/test_local_model_containment_trust_boundary.py)
exercise these distinctions with synthetic identities: a self-claimed origin can
validate without attestation, fixed collection cannot be promoted, placeholder
bindings and unrecorded review remain refused, and in-memory operations touch
no monitored file, network, process or thread entry point. These tests do not
inspect or certify the operator's host, provider, model or corpus.

## What remains before #261 is addressed

- An owner-approved exact local model alias and artifact digest (there is
  currently none; `collect()` can only report `unbound`).
- A real collector that performs the wrapper-reachability, process-boundary,
  and adversarial-corpus checks against that approved model on an authorized
  host, and fills this packet from actual observation instead of a fixed
  empty state.
- The signed adversarial corpus itself (injection, fabricated evidence IDs,
  Unicode/control text, privacy, exhaustion, cancellation, out-of-distribution
  cases) — this change defines where its results are recorded, not the corpus.
- Independent security review of the exact accepted candidate.

## Reproduction

```bash
python -m compileall -q megalodon tests tools
python -m pytest tests/test_local_model_containment.py tests/test_local_model_containment_trust_boundary.py
python tools/local_model_containment.py collect
```
