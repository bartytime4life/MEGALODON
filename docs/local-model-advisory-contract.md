# Local Qwen advisory contract

**Status:** proposed, documentation-only boundary for
[issue #145](https://github.com/bartytime4life/MEGALODON/issues/145). This
document does not add a model runtime, Ollama request, API client, daemon,
scheduler, monitor, detector, file scanner, sandbox, or response action.

MEGALODON may eventually use a locally hosted Qwen model as an explicit,
operator-requested explanation surface. The model is an advisory reader of a
small, validated metadata projection. It is not an antivirus, endpoint agent,
malware classifier of record, source of evidence, or authority to make a
security decision.

## Product boundary

| Question | Contract answer |
| --- | --- |
| Where can the model run? | Only on an explicitly configured local loopback provider, initially expected to be a separately operated Ollama instance. |
| When can it run? | Only after an operator invokes a future explicit advisory command. No startup action, polling, background job, service, or scheduler is allowed. |
| What may it receive? | A closed, size-limited projection of already validated local metadata and receipts. |
| What can it return? | A bounded explanation with one of four outcomes: ANSWER, ABSTAIN, DENY, or ERROR. |
| Can it make detections or evidence? | No. Deterministic detectors and immutable receipts remain the evidence source. |
| Can it operate tools or change the host? | No. It has no shell, subprocess, network, capture, scanner, database-write, firewall, process, quarantine, or remediation authority. |
| Can it contact the Internet? | No. A future adapter must reject non-loopback endpoints and make no external request. |

The phrase "protective agent" is therefore limited to helping an operator
interpret bounded local evidence. It must never mean continuous monitoring,
automatic endpoint isolation, process termination, file quarantine, code
execution, vulnerability scanning, or automatic incident response.

## Proposed input projection

A future adapter must construct the prompt itself from a typed projection. It
must not append raw evidence or treat any input as instructions. All scalar
fields have finite limits before prompt construction.

| Allowed field class | Examples | Limit |
| --- | --- | --- |
| Run provenance | source kind, adapter version, terminal status, time basis | Fixed allowlist and bounded strings |
| Aggregate counts | accepted/rejected records, detections by fixed rule, dropped/partial counts | Non-negative bounded integers |
| Fixed detector context | rule name, severity, threshold, cooldown, explicit limitation | Repository-owned constants only |
| Operator question | one explicit bounded question selected from an allowlisted purpose | Plain text, no tool instruction or data query language |
| Model receipt | configured logical model ID, provider class, model artifact digest/version, timeout, result outcome | Metadata only; no provider secret or endpoint in output |

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

A future data schema must reject unknown fields, control characters, nested
objects not explicitly listed, and values that exceed the selected byte, token,
or cardinality limits.

## Outcome envelope

The model result is display-only and must be treated as untrusted text. A
future adapter may accept only this conceptual envelope:

~~~json
{
  "outcome": "ANSWER | ABSTAIN | DENY | ERROR",
  "summary": "bounded plain text",
  "limitations": ["bounded plain text"],
  "model_receipt": {
    "provider_class": "local_loopback",
    "model_id": "local:qwen-approved-v1",
    "model_artifact": "operator-recorded identifier",
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
dependencies. A future implementation must require all of the following before
any model request:

1. explicit enablement for one invocation; the default is disabled;
2. a literal loopback endpoint and a single configured provider path;
3. a closed local model identifier bound to a recorded model artifact
   identifier, version, or digest;
4. a strict request timeout, input-byte cap, output-byte cap, token cap, and
   concurrency cap;
5. no automatic model pull, model update, model discovery, fallback provider,
   cloud API, environment-secret read, or outbound DNS/HTTP request;
6. a fresh, deterministic preflight that rejects the request before contacting
   the provider when any control fails; and
7. one bounded advisory receipt that records only policy/model metadata,
   outcome, and fixed error code.

The initial runtime must use a direct, schema-checked local request only. It
must not expose a generic chat endpoint, arbitrary prompt box, tool-use mode,
retrieval store, agent loop, function calling, model-selected model name, or
streaming transcript. A model provider being installed or reachable does not
change MEGALODON's static capability catalog.

## Security and red-team controls

| Risk | Required control |
| --- | --- |
| Prompt injection in telemetry or imported logs | Construct prompt from typed fields; never interpolate raw evidence or user-provided instructions. |
| Model hallucinates a verdict or action | Separate advisory text from evidence and actions; always render limitations and an untrusted-output label. |
| Model requests tools or remediation | No tool schema, no executor, and no model-selected command/action field. |
| Data disclosure | Metadata-only projection, deny sensitive fields by schema, private local storage, and no egress. |
| Endpoint redirection or cloud use | Accept only a validated literal loopback endpoint; no redirects, proxy settings, or fallback provider. |
| Resource exhaustion | Fixed request, response, token, timeout, concurrency, and report-display bounds; cancellation and failure tests. |
| Model/provider substitution | Record operator-approved logical ID and artifact identifier; reject unapproved values. |

## Delivery sequence

1. Add a versioned JSON Schema and accepted/rejected fixtures for the input
   projection and result envelope.
2. Add data-only tests proving closed fields, sensitive-field refusal, outcome
   bounds, and the absence of executable/provider authority.
3. Add an opt-in local adapter with loopback preflight and deterministic
   negative controls. It must not start Ollama, download a model, or change
   Qwen configuration.
4. Add a read-only dashboard projection only after the adapter's data,
   privacy, error, and browser bounds are proven.
5. Consider any active host, network, file, or response integration only as a
   separately authorized product phase with durable intent, authorization,
   readback, reconciliation, and independent security review.

Until steps 1–3 are complete, the existing Qwen identifiers in the automation
fixtures are placeholders only. They do not mean that Qwen is installed,
configured, invoked, or allowed to perform any protective action.

## Verification target

The first code PR for this issue should be able to prove, without a local model
installation or network request:

~~~bash
python -m pytest -q tests/test_local_model_advisory_contract.py
python -m megalodon capabilities --platform linux
python -m megalodon hub-plan --platform linux
~~~

Those checks should validate data shapes and static catalog truth only. They
must not probe an Ollama endpoint, start a model, inspect a host, capture
traffic, read files, write SQLite, or mutate a firewall.
