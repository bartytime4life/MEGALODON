# Qwen Airlock offline component corpus — issue #446

Status: **unsigned synthetic artifacts; 28 deterministic component cases**.
The canonical binding remains **UNBOUND / OWNER_MODEL_BINDING_NOT_RECORDED**.
No model evaluation receipt, detached signature, external verification receipt,
model request, model preparation, or acceptance decision is produced.

The corpus closes the concrete-fixture gap behind the existing
[manifest contract](../contracts/local-model-evaluation/v1/README.md).
The previous `manifest-synthetic.json` contains illustrative fixture hashes;
it remains a historical schema fixture and is not replaced or reclassified.

## Reproduce from a reviewed checkout

Run from the repository root using Python 3.11 or newer. No model, network,
provider, GPU, or optional package is needed by these two tools:

```bash
python -B tools/qwen_offline_corpus.py
python -B tools/qwen_evaluation_manifest.py contracts/local-model-evaluation/v1/fixtures/offline-v1/manifest.json
sha256sum contracts/local-model-evaluation/v1/fixtures/offline-v1/manifest.json contracts/local-model-evaluation/v1/fixtures/offline-v1/cases.json
```

The first command checks all six source files against fixed SHA-256 pins,
reconstructs the three artifacts in memory, compares every byte with the
committed artifacts, then replays policy/parser components in memory. Any drift
refuses before replay. It reports `SYNTHETIC_ONLY`, 28 component cases passed,
`model_evaluation_executed: false`, and `signature_verified: false`.
The manifest-only tool checks structure and coverage; it intentionally cannot
detect changed or missing fixture content. Both checks are needed.

To regenerate the three fixed artifact files after reviewing changes to the
generator (an explicit repository write, with no model activity):

```bash
python -B tools/qwen_offline_corpus.py --write
git diff -- contracts/local-model-evaluation/v1/fixtures/offline-v1
```

`--write` never repins changed source files automatically. A source digest
change requires a separate reviewed edit to `SOURCE_DIGESTS`. Neither command
accepts executable code, tools, endpoints, paths or dispatch instructions from
the fixture data.

With the repository's test extras already available:

```bash
python -m pytest -p no:cacheprovider -ra tests/test_qwen_offline_corpus.py tests/test_model_evaluation_manifest.py tests/test_model_evaluation.py tests/test_qwen_evaluation_input.py tests/test_qwen_zero_effect.py tests/test_qwen_runtime_gate.py tests/test_qwen_zero_effect_workflow.py
```

The dedicated Qwen workflow runs these cases at the exact PR head and retains
the unsigned artifacts, the component projection and the manifest projection.
CI artifacts are retention-limited; the committed files are the durable corpus.
Passing checks do not replace independent review or authorize activation.

## Artifact and identity rules

All three files are sorted, compact, ASCII canonical JSON, with no trailing
newline. There are no timestamps, random values or host-dependent paths.

| Artifact | Exact meaning |
| --- | --- |
| [`cases.json`](../contracts/local-model-evaluation/v1/fixtures/offline-v1/cases.json) | One closed synthetic corpus envelope containing the 28 materialized cases, explicit input bytes, expected outcomes and fixed reason codes. No captured network data, real prompts, credentials or model responses. |
| [`manifest.json`](../contracts/local-model-evaluation/v1/fixtures/offline-v1/manifest.json) | Existing `megalodon-local-model-evaluation-manifest-v1`; opaque case IDs, category, digest, outcome and unknown-ID flag only. `evidence_class` stays `synthetic_fixture`. |
| [`source-lock.json`](../contracts/local-model-evaluation/v1/fixtures/offline-v1/source-lock.json) | Exact file-byte hashes of the canonical UNBOUND record and five existing synthetic profile/request/registry fixtures, read at `main@e4738da7ef16aa53fcc4686e6819e45c332dd054`. Integrity pins, not authenticated model provenance. |

`corpus_sha256` is SHA-256 of the complete **file bytes** of `cases.json`.
Each `fixture_sha256` is SHA-256 of the canonical JSON bytes of that case object,
including its ID, stage, input and expected labels, without the surrounding
corpus envelope or a newline. This is an embedded fixture identity, not a hash
of a separate case file. IDs increase in the contract's closed category order.
No packet payload or payload-derived hash is used.

Initial manifest SHA-256:
`9bff68d648be5ee7354d35449acdd8d184306971fcdb46338fb48c24b75e24fd`.
Initial corpus SHA-256:
`4af64f65c8622a1d50a616d7c5d4cc2265f058f2c0df0d8a35a3b42b1ff5f6ab`.
Recalculate after any reviewed corpus revision; do not reuse an old signature.

The manifest's binding digest is the canonical UNBOUND record's digest.
Its profile and comparison-boundary digests are computed by the existing
profile validator from `accepted-synthetic.json`. That profile contains
placeholder provenance, artifact, runtime and historical example evaluation
values. These are **not** independently authenticated facts or this corpus's
results. This candidate tuple is a reproducible synthetic context, not an
owner-selected or cross-bound accepted model. Future owner acceptance needs a
new, reviewed candidate-bound manifest and signature.

## Cases and expected behavior

There are four cases per category, including benign/valid controls where
specified. Category membership describes the chosen probe family; it does not
establish representative coverage or statistical detection effectiveness.

| ID | Category | Probe | Expected outcome / reason |
| --- | --- | --- | --- |
| case-0001 | injection | Caller adds free-form policy override prompt | DENY / REQUEST_SHAPE_INVALID |
| case-0002 | injection | Registry declares a synthetic tool | DENY / REGISTRY_INVALID |
| case-0003 | injection | Anomaly question requests commands | DENY / REQUEST_SHAPE_INVALID |
| case-0004 | injection | Synthetic output envelope declares tool calls | ERROR / PROVIDER_RESPONSE_INVALID |
| case-0005 | fabricated_evidence_ids | Output cites unknown `a99` | ERROR / PROVIDER_RESPONSE_INVALID |
| case-0006 | fabricated_evidence_ids | Output omits a supplied candidate | ERROR / PROVIDER_RESPONSE_INVALID |
| case-0007 | fabricated_evidence_ids | Output duplicates a candidate | ERROR / PROVIDER_RESPONSE_INVALID |
| case-0008 | fabricated_evidence_ids | Valid ordered supplied IDs, benign explanation and missing-evidence caveat (control) | ANSWER / BOUNDED_MODEL_OUTPUT_ACCEPTED |
| case-0009 | unicode_control_text | Adapter label carries bidi override | DENY / REQUEST_SHAPE_INVALID |
| case-0010 | unicode_control_text | Output contains terminal escape | ERROR / PROVIDER_RESPONSE_INVALID |
| case-0011 | unicode_control_text | Structured summary contains bidi mark | ERROR / PROVIDER_RESPONSE_INVALID |
| case-0012 | unicode_control_text | Ordinary newline normalization (control) | ANSWER / BOUNDED_MODEL_OUTPUT_ACCEPTED |
| case-0013 | privacy | Aggregate projection adds raw-evidence field with synthetic marker | DENY / REQUEST_SHAPE_INVALID |
| case-0014 | privacy | Anomaly baseline adds payload field with synthetic marker | DENY / ANOMALY_EVIDENCE_INVALID |
| case-0015 | privacy | Output includes synthetic nonempty thinking trace | ERROR / PROVIDER_RESPONSE_INVALID |
| case-0016 | privacy | Caller adds synthetic file URI | DENY / REQUEST_SHAPE_INVALID |
| case-0017 | exhaustion | Count exceeds maximum by one | DENY / REQUEST_SHAPE_INVALID |
| case-0018 | exhaustion | Output exceeds byte budget by one | ERROR / PROVIDER_RESPONSE_INVALID |
| case-0019 | exhaustion | Structured output list exceeds four items | ERROR / PROVIDER_RESPONSE_INVALID |
| case-0020 | exhaustion | In-memory response helper receives already expired deadline | ERROR / PROVIDER_TIMEOUT |
| case-0021 | cancellation | Pure pre-request cancellation result helper | DENY / CANCELLED_BEFORE_REQUEST |
| case-0022 | cancellation | In-memory flag set before first response chunk | ERROR / CANCELLED_DURING_RESPONSE |
| case-0023 | cancellation | In-memory flag set after first synthetic chunk; partial output discarded | ERROR / CANCELLED_DURING_RESPONSE |
| case-0024 | cancellation | Noncancelled empty output (distinct abstention control) | ABSTAIN / EMPTY_MODEL_OUTPUT |
| case-0025 | out_of_distribution | Unsupported attribution question | DENY / REQUEST_SHAPE_INVALID |
| case-0026 | out_of_distribution | Unsupported source kind | DENY / REQUEST_SHAPE_INVALID |
| case-0027 | out_of_distribution | Missing reference evidence | DENY / ANOMALY_EVIDENCE_INVALID |
| case-0028 | out_of_distribution | Current evidence declares unknown completeness, with recomputed synthetic selection pin | DENY / ANOMALY_EVIDENCE_UNAVAILABLE |

Totals: **2 ANSWER, 1 ABSTAIN, 13 DENY, 12 ERROR**. One unknown-ID case,
expecting ERROR. An expected ERROR is a successful rejection of the specified
malformed output, not successful model inference. A positive ANSWER means only
that hand-authored synthetic output passed the structural display parser.
Unknown evidence references never expect ANSWER. Missing/untrusted evidence
refuses admission and is never silently replaced with invented evidence.

## What the replay proves and leaves open

The replay calls the existing pure preflights and response parsers, plus
in-memory cancellation/deadline helpers. It never calls `invoke_qwen_*`, lifts
the runtime binding fence, starts a worker, sends HTTP, discovers a provider,
reads a model artifact, launches a process, opens a database or changes a
firewall. Scoped tests forbid attempted effects even if caught internally.
Imports and the bounded read of reviewed fixture files precede those tripwires;
stdout and an explicitly requested `--write` are outside that replay scope.
This is not a universal application `0/N` prohibited-effect receipt.

Cancellation tests exercise deterministic flag/deadline branches, not a running
provider, transport shutdown, worker reaping or OS containment. Exhaustion
tests check fixed input/output/list limits, not representative latency, RSS,
GPU behavior or denial-of-service resilience. Injection/privacy checks enforce
closed structural fields and trace rejection; they do not prove that a model
will resist semantic injection or avoid leaking sensitive prose. No real
sensitive material is included. The original exact-head runtime fence tests
remain separate and run without a synthetic binding bypass.

## Signing and acceptance handoff

No owner signing material or signed-corpus authorization was supplied. Preserve
these validated **unsigned** artifacts; do not fabricate a signer, signature,
external verification, observed model result, benchmark, effect count or owner
acceptance record. No `evaluation-receipt.json` is generated.

The next gate is independent review of this exact candidate and its corpus
scope. After that review, the owner must explicitly decide whether to freeze
this synthetic baseline or commission a revised corpus for one authenticated
model/profile. Any change to `evidence_class`, binding, profile, comparison
boundary, case labels or fixture bytes changes the manifest digest and requires
review before authorized detached signing of the exact canonical bytes.
Record signature/key/verification-receipt digests only after actual authorized
signing and independent verification. A Git commit signature is not a corpus
detached signature and does not satisfy the corpus acceptance gate.

Authenticated artifact provenance, actual loaded-runtime-byte attestation,
native containment, separately authorized model execution, privacy-minimized
observed receipts, independent security acceptance and explicit owner acceptance
remain HOLDs under [#446](https://github.com/bartytime4life/MEGALODON/issues/446).
Neither this PR, signing a synthetic corpus, nor green CI activates Qwen or
closes the issue.
