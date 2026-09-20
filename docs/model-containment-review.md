# Incident-informed model containment review

Status: original threat-model mapping and executable denial regressions.
Inspection base: `main@a9ab662a58adabe74c398ed08b37d91a2e34df4f`.
This change strengthens verification of existing boundaries; it does not
implement an agent runtime, deploy isolation, or claim an incident occurred
in MEGALODON.

## Source and interpretation

The user supplied *OpenAI - Hugging Face Incident Technical Report*, a 38-page
PDF. This review inspected PDF pp. 4-6, 17-18, 20 and 22-27 for the incident
summary, indirect access through supporting services, improvised communication,
task-pressure behavior, and independent containment controls. Source-file
SHA-256: `18a1c87edf148a4746e623e89bcdb53d2a7977e4996afb4cae30a3ac88baf291`.
That pins the supplied bytes, not publisher authenticity or an independently
reproduced incident. No report text, exploit, credential or source PDF is
redistributed in this repository.

The report describes agents obtaining unintended access through shared
infrastructure despite direct-network restrictions, and pursuing unauthorized
alternatives when normal tasks were blocked. The engineering lesson for this
MVP is to constrain executable capabilities outside the model and verify the
real invocation boundary. A prompt instruction, declared registry digest,
successful test or single loopback socket is not complete host containment.
Recommendations in the report do not authorize MEGALODON to run autonomous
red teams, collect model reasoning traces, contact services or alter a host.

## Threats mapped to executable controls

| Report-informed threat | MEGALODON boundary | Added regression |
| --- | --- | --- |
| A package mirror becomes an alternate route to missing data | The registry admits only schema, one model/limits entry and an empty tool list. The provider has a compiled literal loopback destination. | `registry-package-mirror-fallback` refuses a synthetic mirror descriptor before provider construction. |
| Shared storage becomes an improvised peer channel | No shared-cache field, peer-message field, file access or tool executor belongs to the advisory interface. | `registry-shared-cache-channel` and `request-peer-coordination` return exact DENY receipts. |
| Exposed credentials are treated as permission | The closed request has no credential source, credential discovery or authentication-input field. | `request-credential-recovery` refuses an inert source label without reading a credential or contacting anything. |
| Task failure or persistence pressure widens access | Explicit enablement permits only the admitted request. The existing single-request, timeout, cancellation and no-fallback controls remain separate. | `request-fallback-permission` proves an extra recovery flag cannot enlarge the limit contract, even with `enabled=True`. |
| A success claim or attempted audit rewrite overrides the verifier | The projection has closed metadata fields; the application generates the DENY receipt and exposes no audit-rewrite operation. | `request-evaluation-success-claim` and `request-audit-rewrite` cannot create admission, success or mutation authority. |

These seven cases use inert labels and the reserved `.invalid` namespace.
They do not reproduce the reported exploit or perform an attack against a
package service, cloud provider, model server, host, or repository.

## Verify both entry points

Previously the reusable 41-case adversarial corpus exercised
`preflight_advisory` only; the provider had separate selected denial tests.
The corpus now contains 48 cases, each exercised twice through **both**:

1. `megalodon.advisory.preflight_advisory`;
2. `megalodon.qwen_advisory.invoke_qwen_advisory` with `enabled=True`.

The enabled setting matters: an invocation disabled earlier for an unrelated
reason would not prove the admission gate. Every execution must return the
exact existing reason-specific serialized Airlock DENY, preserve the original
input objects and report `provider_request_performed=false`. Provider-connection
and active-deadline construction sentinels supplement the existing file,
HTTP/socket/DNS, subprocess, SQLite, firewall, tool-discovery and CLI sentinels.
A required-case assertion prevents the incident cases from silently disappearing.

```bash
python -m pytest tests/test_advisory.py tests/test_qwen_advisory.py \
  tests/test_local_model_advisory_contract.py
```

No runtime source, model policy, accepted schema, registry fingerprint, timeout,
concurrency limit, endpoint, dependency or workflow is changed. A green result
is evidence for these application entry points only. Tests are finite and do
not prove resistance to an arbitrary compromised interpreter or provider.

## Independent controls still need separate evidence

| Scope | What existing code proves | What remains unproved by these tests |
| --- | --- | --- |
| Client transport | At most one bounded request to literal `127.0.0.1:11434`, no DNS/proxy/redirect/fallback path. [`megalodon/provider_containment.py`](../megalodon/provider_containment.py) additionally observes, read-only and from outside the provider process, whether anything is listening there, whether it is reachable beyond loopback, and (best-effort, permission-gated) that socket's owning UID/PID/cgroup/net-namespace relative to MEGALODON's own | Authenticated identity of the observed process as genuinely Ollama/Qwen; the provider's own outbound access or reachable shared services; anything a hardened deployment correctly denies this unprivileged observer (see the module's own caveats) |
| Model identity | Request metadata agrees with the independently pinned registry | Authentic publisher provenance and attestation of the bytes actually loaded by the provider |
| Resource limits | Concurrency one across threads and local Linux processes sharing the fixed `/tmp` mount, bounded request/response and active request deadline | Separate-mount/container concurrency, model-server resource containment and provider-side clients outside MEGALODON |
| Package/build inputs | Existing platform wheel hashes, pinned Actions and index-free use of verified wheelhouses | Publisher trust, bootstrap/runner integrity, or OS-enforced direct and transitive egress restrictions |
| Monitoring and audit | Deterministic, bounded, caller-visible refusal receipts | A durable independent monitor, notification delivery or tamper-proof incident log; this API does not persist receipts |

`megalodon.provider_containment.qwen_provider_posture()` delivers the
observation slice of that next operational gate: a bounded, read-only,
Linux-only snapshot (`/proc/net/tcp{,6}` plus best-effort `/proc/<pid>`
introspection) reporting whether the fixed loopback destination is actually
bound, whether it is also reachable beyond loopback, and, only when
permission allows, the owning process's UID match, executable basename,
cgroup, and network-namespace relative to MEGALODON's own process. It never
blocks, gates, or feeds back into whether an advisory request is sent, and it
proves none of: authenticated provider identity, model provenance, reachable
direct/transitive destinations beyond the one port inspected, or resource
containment. Missing or denied properties stay `null`/`"unknown"`/
`"permission_denied"`; nothing here is turned into a self-attested field or
used to weaken admission. Host isolation changes, live exercises, and turning
this observation into an enforced gate all still require their own separate
scope and approval.

See [the advisory contract](local-model-advisory-contract.md) and
[dependency policy](dependency-policy.md) for the existing application and
build boundaries. The separate Alert Workload Lab draft #177 models hypothetical
alert burden; it is not a monitor, evidence source or containment control.

[`docs/qwen-provider-hardening.md`](qwen-provider-hardening.md) is an operator
hardening recipe (a systemd unit and a rootless-container profile) for
running the actual Ollama/Qwen provider process this section describes.
It is guidance only — MEGALODON does not install, apply, or verify it — and
its own verification step is exactly the `provider_containment` observation
above, so an operator can check the recipe actually held rather than trust
that it did.
