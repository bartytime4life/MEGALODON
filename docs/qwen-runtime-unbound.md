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
| Runtime catalog, loaded allocation and internal fixed HTTP request | Refuse before provider access. |
| Explicit Setup model refresh and selection | One bounded `GET /api/tags` to an admitted literal-loopback listener; save a freshly matched tag/digest and compute preferences. No `/api/show`, `/api/ps`, generation, model load or binding change. Passive snapshots never initiate this read. |
| Original and anomaly Airlock invocation | Pure preflight denials retain precedence; admitted and explicitly enabled calls return `DENY / POLICY_DENIED` with the fixed binding failure before locks or transport. The supplied model identity is unaccepted preflight data. |
| AI fixed questions | Refuse before broker dispatch or receipts. CLI does so after config loading but before receipt-store/reader construction. Authorized HUD requests return 503 before body reads or audit-store creation. Existing HTTP authentication still precedes the binding denial. |
| Model telemetry | Return `needs_setup / unbound` without a refresh thread. Explicitly refreshed choices are cached separately and cannot imply runtime readiness. Queued runtime refresh also rechecks the hold. |
| Keep-ready lifecycle | No worker start, provider inspection, retry, cancellation or change callback. Snapshot reports the hold, with no retry countdown. |

These are model-entry boundaries, not a universal application no-effect claim.
Imports and input/config preparation are outside the guarded invocation. CLI
`ai doctor` still intentionally reads host diagnostics, runs its two fixed
read-only commands and writes its audit receipt. Explicit broker tools still
retain their own authority and audit contracts. Other defensive collection or
analysis workers are not stopped by this change; their model calls are refused.
Model-choice and readiness preferences are explicit private application writes.
No firewall, service or existing external model process is changed.

## Choose other installed Ollama models

In **Setup → Local AI**, press **Refresh installed models**, choose an installed
local artifact, select CPU or Ollama automatic compute, and press **Save model**.
This works for other valid local model names as well as Qwen. No model is pulled,
loaded or given a prompt. The list is a metadata observation, not publisher or
completion-capability verification. Changing models cannot lift UNBOUND.

The discovery exception accepts only the exact bodyless tag-list GET, with a
three-second deadline and the existing bounded response, concurrency and literal
loopback transport. Unknown/wildcard listener posture refuses before the request.
Cloud-backed and non-GGUF catalog entries are omitted. Selection re-reads the
list and rejects missing/changed tags before persistence. A failed refresh clears
the old choices. Passive status reads neither contact Ollama nor start a worker.
The protected support route retains its session, origin, host, token and closed
action/body checks. Runtime catalogs, preparation, generation and AI questions
continue to refuse. This exception revises explicit discovery only; historical
#704 zero-effect evidence retains its original source and scope.

## Verify the installed candidate's files before binding

`tools/qwen_local_artifact.py` is an explicit offline evidence collector. It
closes one missing step in #446: measuring a real local model's manifest,
referenced components and provider executable. Run it from the reviewed
checkout, using the actual model store configured for Ollama:

```bash
python3 -B tools/qwen_local_artifact.py \
  --store /var/snap/ollama/common/models \
  --model qwen2.5:7b-instruct-fp16
```

The directory above is an example of a configured store, not a fallback or a
discovered installation. Supply your actual absolute `OLLAMA_MODELS` path.
The provider defaults to `/usr/local/bin/ollama`; `--provider` selects the
executable file to hash, never execute. Python 3.11 or newer is required.
The command reads files and prints a bounded JSON observation. It does not
contact Ollama, load a model, update signatures, modify the selected model or
enable Local AI. It refuses `:latest`, links, pipes, unsupported components,
missing files, inconsistent sizes, digest mismatches and observed replacement.
At most 32 components and 32 GiB total are read, using 1-MiB chunks and a
cooperative 120-second deadline. A kernel-blocked filesystem operation cannot
be interrupted by that deadline.

`ARTIFACT_BYTES_VERIFIED` means the file bytes matched their local manifest.
It does not mean Qwen is running, accepted or safe. The output keeps
`binding_status: UNBOUND`, reports all runtime authority as false, omits
paths and file contents, and names the remaining gates. Optional
`--manifest-sha256` and `--provider-sha256` compare independently retained
pins. A stale pin produces `MANIFEST_PIN_MISMATCH` or `PROVIDER_PIN_MISMATCH`
before weight reads; it is never replaced with the newly observed value.
Ollama layer `from` labels are bounded input metadata, never a URL to fetch,
a path to open, or publisher authentication.

Retain actual observations privately. Before binding, independently review
the selected tag, measured bytes and source/license evidence. Signing and
executing the adversarial corpus, native containment, loaded-byte attestation,
exact-head independent security review and separate owner acceptance remain
required. A reviewed runtime admission implementation is also still needed;
this collector deliberately does not modify the release fence.

## Evidence and remaining gates

`tests/test_qwen_runtime_gate.py` uses prepared fixtures and forbids file opens,
sockets/DNS, subprocesses, database access, provider transport, process locks,
thread starts and firewall actions during the scoped calls. It also checks
queue/cancellation/observation preservation, fixed-question refusal, stale
telemetry and keep-ready behavior. `tests/test_qwen_zero_effect.py` retains the
separate disabled/preflight evidence. Both run in the exact-head Qwen workflow.
`tests/test_model_choices.py` separately exercises the explicit discovery
exception, changed/missing choices, private preference persistence and restart,
without a synthetic runtime binding or model execution. The browser regression
clicks refresh, chooses another family, saves compute preferences, and confirms
that all execution buttons remain held.

Existing synthetic provider suites explicitly opt into the test-only
`synthetic_runtime_binding` fixture to exercise dormant lower layers. That
monkeypatch is not a production activation interface or acceptance evidence.
The runtime gate suite never requests it. This preserves transport, deadline,
framing and policy regression coverage without pretending a binding exists.

Issue #446 remains **HOLD**. The canonical owner decision is still UNBOUND;
model provenance/authentication, actual loaded-byte verification, the signed
seven-category adversarial corpus, independent review and owner acceptance
remain separate gates. Model choice does not satisfy any of them.
