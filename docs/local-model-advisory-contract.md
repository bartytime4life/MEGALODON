# Local Qwen advisory contract

**Status:** the proposed data-only contract boundary from
[issue #145](https://github.com/bartytime4life/MEGALODON/issues/145) is joined
by the no-network preflight from
[issue #154](https://github.com/bartytime4life/MEGALODON/issues/154). The v1
[schema and fixtures](../contracts/local-model-advisory/v1/README.md) validate
the permitted shapes. [`megalodon/advisory.py`](../megalodon/advisory.py) can
validate an exact operator-approved model identity and construct one canonical
in-memory prompt. Neither surface adds a model runtime, Ollama request, API
client, daemon, scheduler, monitor, detector, file scanner, sandbox, or
response action.

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

The no-network preflight constructs the prompt itself from a typed projection.
A future provider caller must use that canonical prompt without appending raw
evidence or treating any input as instructions. All scalar fields have finite
limits before prompt construction.

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

1. **Delivered in this contract slice:** v1 JSON Schema plus accepted/rejected
   fixtures for the input projection and result envelope.
2. **Delivered in this contract slice:** data-only tests for closed fields,
   sensitive-field refusal, outcome bounds, and absent executable/provider
   authority.
3. **Delivered in the no-network preflight slice:** closed repository-owned
   source/adapter pairs, exact model ID and artifact-digest approval, canonical
   prompt construction, a 4 KiB input gate, immutable ADMIT/DENY decisions, and
   deterministic side-effect negative controls. ADMIT authorizes prompt
   construction only; no request is made.
4. Add an opt-in literal-loopback provider call only after separately reviewing
   redirect, proxy, DNS, timeout, response-size, concurrency, and cancellation
   controls. It must not start Ollama, download a model, or change Qwen
   configuration.
5. Add a read-only dashboard projection only after the adapter's data,
   privacy, error, and browser bounds are proven.
6. Consider any active host, network, file, or response integration only as a
   separately authorized product phase with durable intent, authorization,
   readback, reconciliation, and independent security review.

The existing Qwen identifiers in the automation fixtures remain placeholders.
The v1 contract does not mean that Qwen is installed, configured, invoked, or
allowed to perform any protective action. A runtime remains blocked on step 3.

## Verification target

This contract slice proves, without a local model installation or network request:

~~~bash
python -m pytest -q tests/test_local_model_advisory_contract.py
python -m pytest -q tests/test_advisory.py
python -m megalodon capabilities --platform linux
python -m megalodon hub-plan --platform linux
~~~

Those checks should validate data shapes and static catalog truth only. They
must not probe an Ollama endpoint, start a model, inspect a host, capture
traffic, read files, write SQLite, or mutate a firewall.
