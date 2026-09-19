# Local Qwen advisory contract

This document describes the original `local-model-advisory-v1` run-count
policy. The separately versioned [anomaly explanation policy](anomaly-advisory-contract.md)
and [one-shot analyst command](anomaly-triage.md) have their own registry and
input contract; they do not expand this v1 policy or its two approved questions.

The [incident-informed containment review](model-containment-review.md) maps
shared-service escape and unauthorized recovery threats to the closed interface.
Its reusable denial corpus exercises both preflight and explicitly enabled
provider entry points. Those tests establish application refusal behavior;
provider-process isolation and direct/transitive egress containment require
separate evidence.

**Status:** the proposed data-only contract boundary from
[issue #145](https://github.com/bartytime4life/MEGALODON/issues/145) is joined
by the no-network preflight from
[issue #154](https://github.com/bartytime4life/MEGALODON/issues/154) and the
fingerprint-pinned registry hardening from
[issue #161](https://github.com/bartytime4life/MEGALODON/issues/161), plus one
explicit library-only provider adapter. The v1
[schema and fixtures](../contracts/local-model-advisory/v1/README.md) validate
the permitted shapes. [`megalodon/advisory.py`](../megalodon/advisory.py) can
validate one closed local-model registry against an independently supplied
SHA-256 pin and construct one canonical in-memory prompt.
[`megalodon/qwen_advisory.py`](../megalodon/qwen_advisory.py) can make exactly
one explicitly enabled request to `127.0.0.1:11434/api/generate` after that
preflight admits the prompt. It adds no CLI, daemon, scheduler, monitor,
detector, file scanner, sandbox, tool, or response action.
[`megalodon/provider_containment.py`](../megalodon/provider_containment.py) is a
separate, read-only observation of whatever is bound to that same fixed
loopback destination — see [the containment review](model-containment-review.md)
for its scope. Neither module imports the other, and the observation never
gates or feeds back into an advisory request.

MEGALODON may use a locally hosted Qwen model as an explicit,
operator-requested explanation surface. The model is an advisory reader of a
small, validated metadata projection. It is not an antivirus, endpoint agent,
malware classifier of record, source of evidence, or authority to make a
security decision.

## Product boundary

| Question | Contract answer |
| --- | --- |
| Where can the model run? | Only behind the fixed numeric IPv4 loopback provider `127.0.0.1:11434`, expected to be a separately operated Ollama instance. |
| When can it run? | Only when application code directly calls the library function with `enabled=True`. No CLI, startup action, polling, background job, service, or scheduler is provided. |
| What may it receive? | A closed, size-limited projection of already validated local metadata and receipts. |
| What can it return? | A bounded explanation with one of four outcomes: ANSWER, ABSTAIN, DENY, or ERROR. |
| Can it make detections or evidence? | No. Deterministic detectors and immutable receipts remain the evidence source. |
| Can it operate tools or change the host? | No. It has no shell, subprocess, network, capture, scanner, database-write, firewall, process, quarantine, or remediation authority. |
| Can it contact the Internet? | The MEGALODON adapter can open only the fixed numeric loopback socket. The independently operated Ollama process remains a separate trust and egress boundary. |

The phrase "protective agent" is therefore limited to helping an operator
interpret bounded local evidence. It must never mean continuous monitoring,
automatic endpoint isolation, process termination, file quarantine, code
execution, vulnerability scanning, or automatic incident response.

## Proposed input projection

The no-network preflight constructs the prompt itself from a typed projection.
The provider caller must use that canonical prompt without appending raw
evidence or treating any input as instructions. All scalar fields have finite
limits before prompt construction.

| Allowed field class | Examples | Limit |
| --- | --- | --- |
| Run provenance | source kind, adapter version, terminal status, time basis | Fixed allowlist and bounded strings |
| Aggregate counts | accepted/rejected records, detections by fixed rule, dropped/partial counts | Non-negative bounded integers; a failed run may use JSON `null` only for an unknown rejected-record count |
| Fixed detector context | rule name, severity, threshold, cooldown, explicit limitation | Repository-owned constants only |
| Operator question | `explain_run` or `explain_rule_limitations` | Repository-selected purpose text; no free-form prompt, tool instruction, or data query language |
| Model receipt | logical model ID, provider class, model artifact digest/version, and fixed limits copied from the pinned one-entry registry | Metadata only; no provider secret or endpoint in output |

The projection must exclude:

- packet payloads, packet-derived hashes, raw PCAP/PCAPNG bytes, raw Zeek,
  TShark, Suricata, or osquery output;
- files, scripts, macros, command lines, credentials, tokens, headers,
  cookies, environment values, private filesystem paths, URLs, IP addresses,
  hostnames, or user identifiers;
- free-form model instructions from evidence, documents, HTTP input, or
  another model;
- unbounded history, retrieval documents, embeddings, training data, or chat
  transcripts.

The v1 data schema rejects unknown fields, control characters, raw-evidence
fields, provider substitution, and values outside the fixed v1 byte, timeout,
and concurrency limits. It contains no endpoint, credential, prompt, tool,
action, filesystem, capture, database, or firewall field.

The Python preflight is deliberately stricter than the structural schema. It
accepts only these repository-owned source/adapter pairs:

| Source kind | Advisory adapter ID |
| --- | --- |
| sample | `sample-packet-v1` |
| jsonl | `jsonl-packet-v1` |
| scapy | `scapy-packet-v1` |
| tshark | `tshark-fields-v1` |
| zeek-json | `zeek-conn-json-v1` |
| zeek-tsv | `zeek-conn-tsv-v1` |

The TShark and Zeek IDs match the implemented offline adapter constants. The
sample, JSONL, and Scapy IDs name only the advisory projection shape; they do
not add a new capture or ingestion path.

A completed run must report `rejected_records` as a bounded integer. A failed
run may preserve that field as JSON `null` when the offline receipt could not
determine the count. `null` means unknown, not zero, and the canonical prompt
retains that distinction. `accepted_records` and `candidate_count` are always
bounded integers.

## Outcome envelope

The model result is display-only and must be treated as untrusted text. A
provider adapter may accept only this conceptual envelope:

~~~json
{
  "outcome": "ANSWER | ABSTAIN | DENY | ERROR",
  "summary": "bounded plain text",
  "limitations": ["bounded plain text"],
  "model_receipt": {
    "provider_class": "local_loopback",
    "model_id": "local:qwen-approved-v1",
    "model_artifact_sha256": "operator-recorded lowercase SHA-256",
    "policy_version": "local-model-advisory-v1"
  }
}
~~~

No field can hold an executable, command, argument list, URL, endpoint,
credential, SQL, firewall target, file path, code block, tool call, action
request, raw model trace, or confidence score that changes a deterministic
detection. HTML is not rendered. The dashboard must display the response as
plain text and label it as "AI advisory; not evidence or an action."

- **ANSWER** means the model returned a bounded explanation of the supplied
  projection.
- **ABSTAIN** means the projection lacks enough allowed context for a useful
  explanation.
- **DENY** means the operator request or configured model/provider violates
  policy before a model request is made.
- **ERROR** means an expected local-only operation failed; it reports a fixed,
  non-sensitive code rather than raw provider output.

Neither ANSWER nor an apparent model refusal proves a host is safe, malicious,
infected, contained, or remediated.

## Provider and execution controls

Ollama and Qwen are operator-installed companion software, not MEGALODON
dependencies. The fixed request shape follows Ollama's official
[`/api/generate`](https://docs.ollama.com/api/generate) contract. Ollama defaults
that API to localhost, but MEGALODON narrows the address further to the numeric
IPv4 loopback literal and does not use the cloud API.

The explicit provider adapter requires all of the following before any model
request:

1. explicit enablement for one invocation; the default is disabled;
2. a literal loopback endpoint and a single configured provider path;
3. a closed one-entry local model registry, canonically serialized and matched
   to an independently supplied lowercase SHA-256 pin before request validation;
4. the fixed 4 KiB input cap, 4 KiB output cap, 15-second timeout, and
   concurrency-one policy;
5. no automatic model pull, model update, model discovery, fallback provider,
   cloud API, environment-secret read, or outbound DNS/HTTP request;
6. a fresh, deterministic preflight that rejects the request before contacting
   the provider when any control fails; and
7. one bounded advisory receipt that records only policy/model metadata,
   outcome, and fixed error code.

The initial runtime uses a direct, schema-checked local request only. It exposes
no generic chat endpoint, arbitrary prompt box, tool-use mode, retrieval store,
agent loop, function calling, model-selected model name, or streaming
transcript. A model provider being installed or reachable does not upgrade the
manual-only capability to an automatic or healthy state.

The preflight authenticates the registry bytes with its independently supplied
fingerprint and matches the operator-recorded artifact digest before HTTP. The
provider adapter then applies a non-blocking process-local concurrency-one gate,
one actively enforced shared 15-second deadline, an optional explicit
per-invocation cancellation event, a 4 KiB UTF-8 model-output cap, an 8 KiB
status/header/chunk-framing/trailer cap applied during standard-library
parsing, and a 32 KiB body cap. The fixed request asks the provider to unload after the call,
uses temperature zero and a 512-token generation ceiling, and has no tool
field. The adapter fails closed on partial, late, redirected, encoded,
malformed, duplicate-key, tool-bearing, or oversized responses.

The [result-integrity contract](advisory-result-integrity.md) closes the
completion-to-display handoff. An explicit `done_reason` must equal `stop`;
token-limited, cancelled, lifecycle or unknown reasons are errors, not answers.
Legacy omission remains accepted and is not proof of natural completion.
Present optional response fields must retain their declared types, not null.
Control and bidirectional-format characters cannot reach model summaries,
the result contract or the dashboard; ordinary Unicode and emoji remain valid.
The dashboard and anomaly command share owned result/accounting validation
but retain separate policy admission and unchanged endpoint authority.

Ollama's generate response does not attest the loaded artifact digest, so this
one-call slice cannot independently prove that the separately operated provider
loaded those exact bytes. The operator must verify the local model before
pinning the registry. Likewise, MEGALODON's socket can reach only numeric
loopback, but it cannot attest the egress policy of an independently configured
Ollama process; the approved `local:qwen-*` alias must resolve to a genuinely
local model, never a cloud model.

## Security and red-team controls

| Risk | Required control |
| --- | --- |
| Prompt injection in telemetry or imported logs | Construct prompt from typed fields; never interpolate raw evidence or user-provided instructions. |
| Model hallucinates a verdict or action | Separate advisory text from evidence and actions; always render limitations and an untrusted-output label. |
| Model requests tools or remediation | No tool schema, no executor, and no model-selected command/action field. |
| Data disclosure | Metadata-only projection, deny sensitive fields by schema, private local storage, and no egress. |
| Endpoint redirection or cloud use | Accept only a validated literal loopback endpoint; no redirects, proxy settings, or fallback provider. |
| Resource exhaustion | Fixed request, response, timeout, concurrency, and report-display bounds; cancellation and failure tests. |
| Model/provider substitution | Require the request receipt and limits to match the sole entry in a structurally closed, fingerprint-pinned local registry. |

## Delivery sequence

1. **Delivered in this contract slice:** v1 JSON Schema plus accepted/rejected
   fixtures for the input projection and result envelope.
2. **Delivered in this contract slice:** data-only tests for closed fields,
   sensitive-field refusal, outcome bounds, and absent executable/provider
   authority.
3. **Delivered in the no-network preflight slices:** closed repository-owned
   source/adapter pairs, one fingerprint-pinned local registry with exactly one
   model receipt, fixed 4 KiB input/output limits, a 15-second timeout,
   concurrency one, and no tools; canonical prompt construction; immutable
   ADMIT/DENY decisions; a reusable adversarial denial corpus; and deterministic
   side-effect negative controls. ADMIT authorizes prompt construction only; no
   request is made.
4. **Delivered in the explicit provider slice:** one opt-in literal-loopback
   provider call with redirect, proxy, DNS, timeout, response-size,
   concurrency, and cancellation controls. It does not start Ollama, download
   a model, discover models, or change Qwen configuration.
5. **Delivered in the display-only receipt slice:** one startup-supplied
   `QwenAdvisoryResult` is validated, copied, served through a bounded GET-only
   route, and rendered as text in **Deep analysis & context**. The dashboard
   cannot invoke Qwen, load a receipt from disk, poll the provider, or retry an
   analysis; absence or invalid data produces an explicit unavailable state.
6. Consider any active host, network, file, or response integration only as a
   separately authorized product phase with durable intent, authorization,
   readback, reconciliation, and independent security review.

The existing Qwen identifiers and artifact digest in the contract fixtures
remain synthetic placeholders. They do not mean that Qwen is installed,
configured, approved, or allowed to perform any protective action. An operator
must supply a separately verified registry and its independently stored pin;
the repository fixture is not production approval.

## Verification target

This contract slice proves, without a local model installation or network request:

~~~bash
python -m pytest -q tests/test_local_model_advisory_contract.py
python -m pytest -q tests/test_advisory.py
python -m pytest -q tests/test_qwen_advisory.py
python -m megalodon capabilities --platform linux
python -m megalodon hub-plan --platform linux
~~~

Those checks should validate data shapes and static catalog truth only. They
must not probe an Ollama endpoint, start a model, inspect a host, capture
traffic, read files, write SQLite, or mutate a firewall.
