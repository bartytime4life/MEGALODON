# Qwen completion and result integrity

MEGALODON treats a finished provider request, a usable explanation, and a
validated consumer receipt as different facts. Both Qwen policies share the
same response parser. The anomaly command and original v1 dashboard share
owned result validation, without sharing policy authorization.

## Defects and repairs

The inspected main `8d72b1dc0a417dffee2ca54297a7aa4c3baeb674` included the
#187 recovery and #186 offline candidate coherence. Three synthetic probes
reproduced gaps after those changes: `done_reason="length"` was accepted as
answer text, a bidi override survived summary processing, and a provider
returning `None` escaped triage as `AttributeError` after evidence construction.
No real provider was called to reproduce them.

| Boundary | Required behavior |
| --- | --- |
| Provider completion | `done=true` remains required. If `done_reason` is present, only exact string `stop` is admitted. Other values discard partial text and return `PROVIDER_RESPONSE_INVALID`. |
| Optional metadata | Present `thinking`, `created_at`, `done_reason` and `context` fields must meet their types; explicit null is not omission. Existing accounting and envelope limits remain. |
| Display text | Python, JSON Schema and browser reject C0/C1 controls, bidi direction/override/isolate controls, line/paragraph separators, isolated surrogates and BOM. Empty/whitespace-only fields are rejected. |
| Typed results | Copy an exact `QwenAdvisoryResult`; validate outcome/code, policy/model fields, text, limits, accounting and anomaly candidate identities. Arbitrary objects and field subclasses do not supply methods. |
| Triage handoff | Validate against the anomaly policy and selected model receipt, then serialize inside the provider isolation boundary. Any malformed return retains the completed dossier and marks request completion unknown. |
| Dashboard | Reuse the owned validator while retaining the original v1 policy, 8 KiB envelope, startup-only snapshot, text-only rendering and GET-only route. |

The anomaly policy additionally requires one closed JSON object whose candidate
IDs exactly equal the recomputed dossier order. It validates bounded summary,
benign-alternative, and missing-evidence fields before constructing display
text. Empty or whitespace-only response text is invalid rather than an
unstructured abstention. This prevents unsupported candidate references and
executable fields; it does not prove that free prose is factually correct or
semantically action-free.

The [Ollama generate API](https://docs.ollama.com/api/generate) distinguishes
`done` from the reason generation stopped. MEGALODON's exact-stop allowlist is
a conservative local acceptance rule, not a claim that every upstream reason
is an error in Ollama. Legacy responses omitting the optional reason remain
compatible; they do not prove natural termination. The endpoint, fixed request,
512-token ceiling, time/byte budgets, cancellation, the nonblocking in-process
gate and stable `/tmp` directory-inode Linux lock, and no-retry policy remain
fixed. Optional upstream fields are not new local capabilities.

Tab, CR and LF in a provider response may be normalized to spaces. Other
disallowed controls are checked before whitespace normalization so it cannot
erase evidence of an invalid reply. Ordinary accented, CJK and Arabic text,
emoji and emoji joiners remain accepted. Literal markup remains inert text.
These checks do not detect all confusable characters or make generated text
factually trustworthy. Browser mocks test behavior, not screen-reader output.
Model aliases and artifact digests also require a true end of string in the
original v1 result schema and browser, matching Python's full-token check. A trailing newline
cannot exploit regular-expression end-of-line behavior to pass either check.

## Failure accounting

A valid provider error after a request keeps `provider_request_performed=true`
and excludes partial model output. A valid preflight denial keeps false.
An exception or malformed return that prevents validated accounting produces
`PROVIDER_COMPLETION_UNKNOWN`, null request accounting and exit 3. It must not
claim a confirmed no-request from an untrusted or missing result. The dossier,
its identity, candidates and limitations are preserved unchanged. No retry,
alternate provider, indirect method call or response action follows.

An answer's recorded raw UTF-8 output count must cover the normalized summary's
UTF-8 size. Whitespace normalization can shorten the output, not produce more
encoded text than was received. DENY and ERROR results cannot claim accepted
output bytes. These are necessary consistency checks, not reconstruction of
the discarded raw response.

Validation proves structural consistency only. A registry/model digest is
still an operator assertion about separately operated model bytes. Result
validation does not bind a copied receipt cryptographically to a run, establish
model accuracy or attest the provider's own egress. Missing observed coverage
and uncalibrated detection thresholds remain explicit limitations.

## Alignment and next gates

The supplied Advancement Blueprint requires bounded failure and evidence
preservation; the Local Command Center blueprint separates native evidence
from model interpretation and execution authority. Their old repository pins
remain historical. The repository-analysis framework informs exact source and
test inspection; it supplies no missing implementation facts.

#187 reached main as `fa55906dc327c0bb0cde9366ac99a8f031d19484` on September 15,
2026. The earlier integration checkpoint remains a dated historical record.
The current pipeline guide now distinguishes delivered command/policy code
from still-undelivered anomaly dashboard integration.

Before adding that display, separately specify evidence identity binding,
recomputation inputs, stale/missing receipt states and text-only projection.
Before operational efficacy claims, obtain representative temporal evaluation
and operator-owned model acceptance. This repair starts no model, scheduler,
sensor, host-control path or deployment. Exact validation receipts belong in
its draft PR; green checks do not establish independent review or a release.
