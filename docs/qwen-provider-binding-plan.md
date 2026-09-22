# Qwen provider candidate binding and bounded qualification

Status: **PROPOSED / POST-RC HOLD** for [issue #261](https://github.com/bartytime4life/MEGALODON/issues/261).
This is a reviewable nomination and acceptance design, not an owner-approved
artifact binding, executable runbook, host observation, or acceptance receipt.
Permission to prepare this PR does not approve model bytes or provider operation.
Keep #261 open in M04. No runtime setting or collector state changes here.

## Evidence basis and candidate comparison

Repository snapshot: `main@3c80d9734a1618eddc42d4aacf5a56698722328a`, tree
`89738f100afe54e9bc3583697e63bccff8a1ad8c`. PR #346 is included in this snapshot;
its receipt-ledger repair supplies no provider acceptance. Later main revisions
must be compared explicitly rather than inheriting this snapshot's identity.

The source evidence is the [dated operator-host observation](ai-host-observation-2026-09-21.md),
[disabled AI configuration](../config/settings.toml), [separate AI control-plane contract](ai-control-plane.md),
and [canonical inert companion guidance](../megalodon/dashboard_tool_assets.py).
The host observation is historical; this plan performs no fresh host inspection.

| Candidate | Repository evidence | Proposed disposition |
| --- | --- | --- |
| `qwen2.5:7b-instruct-fp16` | Recorded installed tag and disabled control-plane default; local manifest recorded below | Sole first qualification candidate; minimize departure from the recorded installation, not a claim of superior security or quality |
| `qwen3.6:35b` | Recorded installed tag, but not the selected disabled default | Defer; different bytes and runtime profile require separate binding and review |
| `qwen3.6:latest` | Resolved to the same manifest as `qwen3.6:35b` in that one snapshot | Exclude as a binding target; no implicit tracking of a mutable latest tag |
| `qwen2.5:7b` | Explicit example tag in the companion guidance | Example only; do not substitute it for the FP16 candidate or execute its download command to satisfy #261 |

The recorded Qwen 3.6 manifest is
`07d35212591fc27746f0a317c975a6d68754fb38e9053d82e25f06057af28522`.
These observations are not a qualified-model compatibility matrix, current
catalog metadata, artifact provenance, or a reason to pull a new model.

The same host record identifies active `/usr/local/bin/ollama` version `0.24.0`
and a separate, disabled Snap Ollama `0.32.14`. The active binary's installer
provenance was not established. Qualify one exact executable/build; do not
silently exchange these installations or infer compatibility from a version.

## Proposed identity chain

Proposed logical contract alias: `local:qwen-2.5-7b-instruct-fp16-v1`.
Recorded installed Ollama tag: `qwen2.5:7b-instruct-fp16`.
Recorded local manifest SHA-256:
`59805ce4a4046be2d8f63231a78daacd2e66f5dccf1a64d0d138ebeeb26ff16c`.

These are three different identity fields. The observed manifest digest is
not automatically the model-weight digest, publisher authentication, or an
attestation of bytes loaded in memory. The [containment schema](../contracts/local-model-containment/v1/schema.json)
requires a `local:qwen-*` alias; the installed tag does not satisfy that field.
The [original provider adapter](../megalodon/qwen_advisory.py) sends its admitted
model ID literally. It does not translate this proposed alias into the tag.
Creating a provider alias or changing that mapping is a separate, explicitly
authorized mutation; this document performs neither.

Complete the following worksheet outside the acceptance manifest. PENDING
values must never be replaced by zero-filled, example, or invented hashes.

| Binding item | Required evidence / current state |
| --- | --- |
| Local manifest bytes | Recompute their full digest from the candidate's actual local bytes; recorded digest above is a comparison target, not fresh verification |
| Model-weight artifact | Full SHA-256 and exact definition of the bytes hashed: PENDING |
| Component closure | Full digests of all referenced blobs and applicable configuration, template, parameter, license and adapter layers: PENDING |
| Provenance | Distribution identity, exact source/revision, license/notices and available publisher verification evidence; state unavailable verification honestly: PENDING |
| Alias resolution | Show the literal logical alias resolves only to the nominated, locally bound component set: PENDING |
| Registry | One-entry policy-specific registry, canonical fingerprint, independently retained pin and binding to this artifact: PENDING |
| Provider | Exact executable/build digest, provenance and serving-process identity: PENDING |
| Execution subject | Exact repository candidate, effective host configuration and CPU or GPU backend, including driver/runtime identities where applicable: PENDING |
| Owner binding decision | Explicit approval of the completed identity chain, decision date and evidence references: NOT RECORDED |

The [anomaly registry](anomaly-advisory-contract.md), original run-count registry,
and newer control-plane TOML manifest pin are not interchangeable approvals.
A tag lookup is not a loaded-byte attestation. Aliases, components, binary,
configuration, backend or repository changes require explicit comparison and a
new scoped disposition; acceptance must not float with a branch or mutable tag.

## Smallest proposed execution target

Qualify `local-model-anomaly-advisory-v1` only, with the fixed `explain_anomalies`
question, one pinned repository-recomputed synthetic metadata selection and one
independently fingerprint-pinned `qwen-anomaly-registry-v1` entry. This lane
already checks exact repository-generated candidate IDs without model tools.
Its [contract](anomaly-advisory-contract.md) and [result-integrity rules](advisory-result-integrity.md)
remain authoritative; this proposal does not broaden their permitted inputs.

Preserve 4 KiB input/output bounds, the 15-second deadline, concurrency one,
one non-streaming generation request, no retry, no fallback and no tool field.
The existing request asks for `think: false`, `raw: true`, temperature zero,
`num_predict: 512` and `keep_alive: 0`. Requested settings are not evidence that
the provider obeyed them, stopped computing, or unloaded its model. Do not
silently import the newer control plane's context/output settings into this
separate policy. Measure resources and completion; do not loosen limits to
obtain a passing result. A failure remains a failure or named HOLD.

The original run-count policy, AI broker/tool selection, report generation,
firewall-plan proposals and interactive HUD AI routes are outside this first
acceptance claim. Preserve their implementation history without accepting them
by implication. In particular, the documented **Check Ollama and Qwen** route
performs inference, and `ai doctor` can write an application-owned receipt;
neither is a no-effect inventory action authorized by this document.

## Separate authorization before host/provider tests

The operator must authorize an exact test plan naming the host, candidate
identity, permitted inspection and mutations, duration, finite resource bounds,
stop conditions and rollback. Provider startup/restart, loading/inference,
alias creation, package/model acquisition, persistence, service configuration,
firewall changes, GPU changes and network allowances are separate choices.
No command for performing any of them is included or authorized here.

The historical host snapshot recorded a wildcard listener and missing effective
egress/resource controls. A later receipt must observe the actual successor
configuration rather than rewriting that record. The [hardening recipes](qwen-provider-hardening.md)
are guidance, not exercised acceptance: the rootless container example does not
establish no-egress or separation from the invoking host identity.

The named execution must establish all of the following:

- Wrapper-only literal-loopback reachability and effective no-cloud behavior,
  with direct outbound denial and transitive denial through reachable local
  services/proxies. Loopback binding alone does not prove caller exclusivity.
- Exact serving-process/binary identity, artifact-substitution refusal, defined
  filesystem scope and explicit accounting of any permitted scratch writes.
  Do not silently exclude persistent/model-store writes from an absence claim.
- Bounded memory/CPU/process use, lifecycle observation, second-request rejection
  without a queue, cancellation/timeout and observed cessation of provider work.
  The shared `/tmp` client lock does not prove provider-wide exclusivity against
  unrelated clients or namespaces. CPU and GPU evidence are separate profiles.
- Continued ordinary core/HUD availability when the provider is absent, refused,
  stopped or fails, with no automatic recovery, startup, retry or new authority.

## Signed corpus and effect accounting

This is an unsigned test-design matrix, not a corpus execution receipt. Freeze
case IDs, exact fixtures, expected outcomes, category coverage and denominators;
hash and sign the corpus under an explicitly identified signing authority before
an authorized execution. Retain independently verifiable corpus and execution
references. This PR supplies no signature, signing identity or provider results.

| Required category | Boundary to exercise in the named corpus |
| --- | --- |
| `injection` | Unsupported instruction fields refuse before send; generated instructions never become executable authority |
| `fabricated_evidence_ids` | Missing, unknown, duplicate or reordered candidate references fail the existing exact-ID checks |
| `unicode_control_text` | Prohibited controls/bidirectional formatting refuse; ordinary permitted Unicode remains distinguishable |
| `privacy` | Forbidden raw/sensitive input fields refuse; retain only minimized IDs, digests, metrics and fixed outcome codes |
| `exhaustion` | Finite input/output/framing/resource limits and concurrent-request rejection hold; no queue or retry |
| `cancellation` | Before-send refusal is distinct from in-flight error; provider cessation needs separate observed evidence |
| `out_of_distribution` | Unsupported/ineligible requests fail closed without inventing evidence or granting model authority |

Distinguish preflight tests, response-parser fixtures and actual provider/host
observations; mocked refusals do not count as provider executions. Keep ANSWER,
ABSTAIN, DENY and ERROR distinct. Empty or malformed anomaly responses are not
successful abstentions merely because they contain no useful answer.

Until actual execution, report NOT_RUN, not successful `0/N` results. Afterward,
report each prohibited effect and its executed denominator, with missing,
failed, cancelled and not-run cases visible. A zero count over a named corpus
is bounded observation, not universal safety or operational accuracy.

## Record the decision without promoting evidence

A proposed issue comment may say:

> I nominate `qwen2.5:7b-instruct-fp16` as the sole candidate for the bounded
> anomaly-advisory qualification described here. The proposed alias and recorded
> manifest are not a completed byte binding. Artifact/component verification,
> alias resolution, registry pin, provider/host identity and explicit approval
> of that completed chain remain pending. Host/provider execution is NOT_RUN;
> independent security acceptance is NOT RECORDED. Keep #261 open in M04.

That wording remains a draft until adopted by the owner. A PR merge would
accept repository content only, not the quoted owner decision or model bytes.

The [containment collector](../tools/local_model_containment.py) remains fixed
at `unbound`, with `model_binding: null` and unperformed observations. Do not
set `operator_approved: true`, set a gate to `met`, mark review `recorded`, or
label a hand-written packet `collector_output` to compensate for missing
receipts. CLI `status: validated` establishes packet consistency only; it cannot
authenticate a claimed origin or any approval field. The [acceptance plan](local-model-containment-acceptance-plan.md)
needs real, authenticated evidence ingestion as a separate reviewed change.

Independent security disposition must name the exact code, model components,
provider binary, effective configuration/backend, signed corpus and execution
receipts. CI, a valid packet, a merge, a signed commit or this author-written
plan does not supply it. No detector/action authority, release, deployment,
remote exposure or host change is authorized by either documentation PR review
or the eventual narrow advisory qualification.
