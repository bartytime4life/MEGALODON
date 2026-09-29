# Issue #446: Qwen Airlock owner-decision packet

Status at `main@0430df5b9dd07599ef0bd5b7f5c21f0c70102305` (2026-09-28):
**UNBOUND / OWNER_MODEL_BINDING_NOT_RECORDED**. This packet nominates one
historically observed, already-local candidate for a future owner decision;
it does not record that decision. The canonical
[`qwen.unbound.json`](../config/model-bindings/qwen.unbound.json) stays unchanged.
No model or host was inspected or operated for this packet.

## Candidate and evidence limits

The [2026-09-21 host observation](ai-host-observation-2026-09-21.md) recorded
the installed tag `qwen2.5:7b-instruct-fp16`, local manifest digest
`59805ce4a4046be2d8f63231a78daacd2e66f5dccf1a64d0d138ebeeb26ff16c`,
and the active `/usr/local/bin/ollama` reporting version `0.24.0`. A disabled
Snap Ollama `0.32.14` was also present. These are dated observations, not
fresh byte measurements, an owner selection, or provenance verification.
The observed wildcard listener and absent effective egress/resource controls
are containment failures for a future provider acceptance claim. The
[`bound.example.json`](../tests/fixtures/local_model_binding/bound.example.json)
uses synthetic identifiers and hashes and must never be promoted to a binding.
The proposed `local:qwen-2.5-7b-instruct-fp16-v1` is a *logical alias proposal*;
the observed tag is not an alias-resolution receipt. The disabled default in
[`settings.toml`](../config/settings.toml) also does not constitute approval.

The narrow eventual target is only `local-model-anomaly-advisory-v1` with the
fixed `explain_anomalies` question and one pinned synthetic metadata selection.
The generic advisory, AI doctor probe, HUD AI routes, run-count policy, tools,
detectors, responses, scheduling, and release are outside that acceptance.
No alias creation or model operation follows from recording this target.

## Values the operator would need to supply

| Binding field | Current evidence | Still required before BOUND |
| --- | --- | --- |
| `logical_alias`, `artifact.installed_tag` | Proposed alias and historically observed exact FP16 tag above | Owner selects this one local artifact and records exact alias-to-tag/component resolution. No mutable `:latest`. |
| `provider.version`, `executable_sha256`, `provenance_ref` | Historical active version `0.24.0` and path only | Current executable SHA-256, serving-process/build identity, installer/source provenance; distinguish disabled Snap. |
| `artifact.manifest_sha256`, `model_weight_sha256`, `components`, `provenance_ref`, `license_refs` | Historical manifest digest only | Rehash actual local manifest bytes; define and hash the weight bytes, every referenced component with size/role, publisher/source/revision and license/notice evidence. Do not copy the manifest digest into a weight field. |
| `host_profile` | Historical Ubuntu 24.04.5, x86_64 and announced CUDA 13.0/RTX 5080 | Exact named execution profile, backend/driver/runtime and effective configuration digest on the candidate host; historical GPU visibility does not prove use. |
| `registry.registry_id`, `fingerprint_sha256` | Proposed single-entry `qwen-anomaly-registry-v1`, no owner-pinned fingerprint | Closed one-entry registry with exact alias/artifact/limits, empty tools, canonical SHA-256 and independently retained pin; match request and containment receipts. The checked-in example registry is synthetic. |
| `operator_decision` | `NOT_RECORDED` | Owner's explicit selection of the completed identity chain, named actor/time and authenticated evidence references. A nomination or document merge is insufficient. |

Collect a closed Ollama identity observation only under later authorization:
hash the raw `/api/version`, `/api/tags`, and `/api/show` responses separately;
compare tag, digest, details, template, parameters, license, capabilities and
binary identity per [identity intake](ollama-identity-intake.md). Keep raw
responses and local paths outside public receipts. The
[profile](../contracts/local-model-profile/v1/README.md) must bind the same
artifact/provenance/runner and containment digest. The
[readiness assessor](local-model-readiness.md) compares binding, identity,
profile, containment, evaluation and deterministic request. Even complete
offline consistency reaches at most `CANDIDATE_PACKET_CONSISTENT`.

## Disabled / UNBOUND regression boundary

At this exact head, `settings.toml` defaults AI to disabled. The doctor and
inventory disabled tests in `tests/test_ai_doctor_consent.py` require no
provider request; doctor is a separate receipt-writing diagnostic and is not
a universal zero-write claim. The direct advisory disabled test in
`tests/test_qwen_advisory.py` requires `DENY / EXPLICIT_ENABLEMENT_REQUIRED`,
`provider_request_performed=false`, and no HTTP construction. The offline
binding/readiness tests require `UNBOUND`,
`OWNER_MODEL_BINDING_NOT_RECORDED`, and refusal of evidence smuggled alongside
an unbound record. The containment collector remains fixed at unbound.

For an issue-level zero-effect regression, run those entry points with
sentinels on DNS, HTTP/provider socket construction, subprocess/shell,
filesystem and SQLite writes, service/firewall actions, and thread/background
start; assert deterministic denial or readiness HOLD before any sentinel.
Exercise enabled invalid-airlock inputs separately to prove their DENY before
provider I/O. Distinguish mocked entry-point evidence from native provider
containment; neither `UNBOUND` in the offline assessor nor the disabled default
automatically gates every enabled call to `invoke_qwen_advisory`. A runtime
binding admission gate would require its own implementation and review.
No observed `0/N` corpus effect count exists yet.

## Signed evaluation manifest to freeze later

Freeze a privacy-minimized manifest with schema/version, exact candidate
binding/profile/comparison-boundary digests, corpus ID, ordered case IDs,
per-case fixture SHA-256, category, expected `ANSWER`/`ABSTAIN`/`DENY`/`ERROR`,
and total denominator. Cover `injection`, `fabricated_evidence_ids`,
`unicode_control_text`, `privacy`, `exhaustion`, `cancellation`, and
`out_of_distribution`, including unknown evidence IDs and distinct outcome
states. Keep prompts, raw evidence, provider responses and advisory text out
of the public manifest and receipt. Hash the frozen corpus and manifest;
record detached signature algorithm, signature digest, signer-key fingerprint,
and separately hashed external verification receipt. None of those hashes,
case denominators, signature, verification, or execution results are present
in this packet. Mark them **NOT_RUN / NOT_RECORDED**, never `0/N` or passed.
The [evaluation contract](qwen-adversarial-evaluation.md) checks receipt
consistency only; it neither reads cases nor verifies signatures.

## Later holds and decision

Evidence-origin authentication must connect the named operator, exact host,
provider responses, artifact/component bytes, signed corpus and execution
receipts. Independently attest the bytes loaded during the specific generation;
tag/manifest lookup and Ollama self-report do not do that. Rehearse direct and
transitive no-egress, loopback access, no provider-side mutation, finite
resource use, cancellation and host-wide concurrency under a separately
authorized plan. Then obtain exact-head independent security review of code,
artifact, provider, effective configuration and results, followed by a
separate owner acceptance decision. Release, deployment, Site publication,
host changes, model operation and detector/action authority remain separate.

**Owner decision pending:** select the one already-local candidate (or decline
it) only after the missing exact values and authenticated references above are
available. Until then the canonical record remains `UNBOUND`.
