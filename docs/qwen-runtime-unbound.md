# Qwen runtime UNBOUND fence — issue #446

This release has no accepted owner model binding. `megalodon/local_model_runtime.py`
therefore returns `OWNER_MODEL_BINDING_NOT_RECORDED` without reading files,
consulting a provider, acquiring a process lock or starting a worker. The release
fence is tied by a regression test to the canonical sorted compact JSON digest
of `config/model-bindings/qwen.unbound.json`. It is **not** a dynamic binding
loader, authentication mechanism or evidence that a model is accepted.

There is deliberately no BOUND path, environment override or operator toggle.
`enabled = true`, another model/tag/digest, a caller-supplied pinned registry,
or editing a binding JSON file cannot lift this release's hold. Future runtime
admission requires a reviewed implementation and the outstanding acceptance
evidence. The setting alone must not resume model operation after an upgrade.

## Entry points

| Entry | Behavior while UNBOUND |
| --- | --- |
| AI provider admission, generation and preparation | Raise the fixed binding failure before posture, queue ownership, cancellation, observations or I/O. Exact disabled settings retain `DISABLED` precedence. |
| Provider inventory and status | Return binding failure; status is `unbound`, inference false and provider/listener availability unknown. False inventory presence/digest fields with an error do not establish absence. |
| Catalog, loaded allocation and internal fixed HTTP request | Refuse before provider access, including explicit Setup refresh. |
| Original and anomaly Airlock invocation | Pure preflight denials retain precedence; admitted and explicitly enabled calls return `DENY / POLICY_DENIED` with the fixed binding failure before locks or transport. The supplied model identity is unaccepted preflight data. |
| AI fixed questions | Refuse before broker dispatch or receipts. CLI does so after config loading but before receipt-store/reader construction. Authorized HUD requests return 503 before body reads or audit-store creation. Existing HTTP authentication still precedes the binding denial. |
| Model telemetry | Return `needs_setup / unbound` without a refresh thread; cached success cannot imply readiness. Queued refresh also rechecks the hold. |
| Keep-ready lifecycle | No worker start, provider inspection, retry, cancellation or change callback. Snapshot reports the hold, with no retry countdown. |

These are model-entry boundaries, not a universal application no-effect claim.
Imports and input/config preparation are outside the guarded invocation. CLI
`ai doctor` still intentionally reads host diagnostics, runs its two fixed
read-only commands and writes its audit receipt. Explicit broker tools still
retain their own authority and audit contracts. Other defensive collection or
analysis workers are not stopped by this change; their model calls are refused.
No host, firewall, service, existing external model process or data is changed.

## Evidence and remaining gates

`tests/test_qwen_runtime_gate.py` uses prepared fixtures and forbids file opens,
sockets/DNS, subprocesses, database access, provider transport, process locks,
thread starts and firewall actions during the scoped calls. It also checks
queue/cancellation/observation preservation, fixed-question refusal, stale
telemetry and keep-ready behavior. `tests/test_qwen_zero_effect.py` retains the
separate disabled/preflight evidence. Both run in the exact-head Qwen workflow.

Existing synthetic provider suites explicitly opt into the test-only
`synthetic_runtime_binding` fixture to exercise dormant lower layers. That
monkeypatch is not a production activation interface or acceptance evidence.
The runtime gate suite never requests it. This preserves transport, deadline,
framing and policy regression coverage without pretending a binding exists.

Issue #446 remains **HOLD**. The canonical owner decision is still UNBOUND;
model provenance/authentication, actual loaded-byte verification, the signed
seven-category adversarial corpus, independent review and owner acceptance
remain separate gates. No model or provider was operated for this change.
