# Local Qwen advisory contract

**Status:** the proposed data-only contract boundary from
[issue #145](https://github.com/bartytime4life/MEGALODON/issues/145) is joined
by the no-network preflight from
[issue #154](https://github.com/bartytime4life/MEGALODON/issues/154) and the
fingerprint-pinned registry hardening from
[issue #161](https://github.com/bartytime4life/MEGALODON/issues/161), and the
literal-loopback provider boundary from
[issue #165](https://github.com/bartytime4life/MEGALODON/issues/165). The v1
[schema and fixtures](../contracts/local-model-advisory/v1/README.md) validate
the permitted shapes. [`megalodon/advisory.py`](../megalodon/advisory.py) can
validate one closed local-model registry against an independently supplied
SHA-256 pin and construct one canonical in-memory prompt.
[`megalodon/advisory_provider.py`](../megalodon/advisory_provider.py) may then
make one explicitly enabled request to the compiled literal loopback provider.
There is still no CLI command, dashboard/API route, daemon, scheduler, monitor,
detector, file scanner, sandbox, persistence, tool, or response action.

MEGALODON can use a separately operated local Qwen model through this internal,
operator-requested explanation boundary. The model is an advisory reader of a
small, validated metadata projection. It is not an antivirus, endpoint agent,
malware classifier of record, source of evidence, or authority to make a
security decision.

## Product boundary

| Question | Contract answer |
| --- | --- |
| Where can the model run? | Only behind the compiled literal IPv4 loopback tuple `127.0.0.1:11434`, using the fixed Ollama generate path. The endpoint is not configurable. |
| When can it run? | Only when application code explicitly calls the internal API with per-invocation enablement after Airlock admission. No CLI/dashboard route, startup action, polling, background job, service, or scheduler is added. |
| What may it receive? | A closed, size-limited projection of already validated local metadata and receipts. |
| What can it return? | The data contract supports ANSWER, ABSTAIN, DENY, or ERROR. The first runtime receipt produces only application-owned ANSWER, DENY, or ERROR outcomes. |
| Can it make detections or evidence? | No. Deterministic detectors and immutable receipts remain the evidence source. |
| Can it operate tools or change the host? | No. Apart from the one fixed loopback provider transport, it has no shell, subprocess, network target, capture, scanner, database-write, firewall, process, quarantine, or remediation authority. |
| Can it contact the Internet? | No. The adapter constructs an IPv4 socket directly for the numeric loopback tuple and exposes no endpoint, proxy, redirect, DNS, or fallback-provider path. |

The phrase "protective agent" is therefore limited to helping an operator
interpret bounded local evidence. It must never mean continuous monitoring,
automatic endpoint isolation, process termination, file quarantine, code
execution, vulnerability scanning, or automatic incident response.

## Proposed input projection

The no-network preflight constructs the prompt itself from a typed projection.
The provider adapter uses that canonical prompt without appending raw
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

The model result is display-only and must be treated as untrusted text. The
adapter returns the closed `advisoryInvocationReceipt` shape:

~~~json
{
  "outcome": "ANSWER | DENY | ERROR",
  "code": "ADVISORY_ANSWER | POLICY_DENIED | LOCAL_PROVIDER_ERROR",
  "reason_code": "finite application-owned reason",
  "summary": "bounded plain text",
  "limitations": ["bounded plain text"],
  "model_receipt": {
    "provider_class": "local_loopback",
    "model_id": "local:qwen-approved-v1",
    "model_artifact_sha256": "operator-recorded lowercase SHA-256",
    "policy_version": "local-model-advisory-v1"
  },
  "registry_sha256": "lowercase SHA-256 or null",
  "provider_request_performed": true
}
~~~

No field can hold an executable, command, argument list, URL, endpoint,
credential, SQL, firewall target, file path, code block, tool call, action
request, raw model trace, or confidence score that changes a deterministic
detection. HTML is not rendered. The dashboard must display the response as
plain text and label it as "AI advisory; not evidence or an action."

- **ANSWER** means the model returned a bounded explanation of the supplied
  projection.
- **ABSTAIN** remains part of the data-only result vocabulary for future
  application-owned classification; the first provider adapter does not let raw
  model output select that outcome.
- **DENY** means the operator request or configured model/provider violates
  policy before a model request is made.
- **ERROR** means an expected local-only operation failed; it reports a fixed,
  non-sensitive code rather than raw provider output.

Neither ANSWER nor an apparent model refusal proves a host is safe, malicious,
infected, contained, or remediated.

## Provider and execution controls

Ollama and Qwen are operator-installed companion software, not MEGALODON
dependencies. The internal provider implementation requires all of the following
before any model request:

1. explicit enablement for one invocation; the default is disabled;
2. the compiled literal loopback endpoint and single fixed provider path;
3. a closed one-entry local model registry, canonically serialized and matched
   to an independently supplied lowercase SHA-256 pin before request validation;
4. the fixed 4 KiB input cap, 4 KiB output cap, 15-second timeout, and
   concurrency-one policy;
5. no automatic model pull, model update, model discovery, fallback provider,
   cloud API, environment-secret read, DNS lookup, or non-loopback HTTP request;
6. a fresh, deterministic preflight that rejects the request before contacting
   the provider when any control fails; and
7. one bounded advisory receipt that records only policy/model metadata,
   outcome, and fixed error code.

The initial runtime uses a direct, schema-checked local request only. It does
not expose a generic chat endpoint, arbitrary prompt box, tool-use mode,
retrieval store, agent loop, function calling, model-selected model name, or
streaming transcript. Installing or reaching a provider does not expand the
repository-owned catalog beyond this bounded optional adapter.

The fixed provider body contains only `model`, `prompt`, `stream: false`,
`think: false`, `keep_alive: 0`, and fixed `temperature: 0` / `num_predict: 512`
options. HTTP
redirects are never followed; non-200 status, unexpected content type or
encoding, duplicate/unknown JSON fields, a mismatched model ID, incomplete
generation, non-empty reasoning output, tool-call fields, non-printable output,
and every size breach return
finite non-sensitive receipts. Raw provider bodies and exceptions are not copied
into those receipts. `provider_request_performed: true` records that the adapter
crossed the request-attempt boundary; it does not claim the provider received or
completed a request.

The exact installed-model artifact remains an operator trust obligation. The
runtime uses the registry-bound logical model ID as the exact Ollama model name
and checks the same ID in the response, but it performs no model discovery or
second `/api/show` request and therefore does not independently attest installed
model bytes. The repository fixture ID and digest are synthetic and must not be
treated as a usable installation receipt.

The preflight rejects a request unless both its registry snapshot and its request
snapshot carry those four exact limits; it also measures the constructed prompt
as UTF-8 before admission. The provider boundary independently enforces its
request, response, token, timeout, concurrency, cancellation, and terminal-state
budgets against the one literal-loopback call.

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
4. **Delivered in the provider-boundary slice:** one internal opt-in
   literal-loopback call with redirect, proxy, DNS, timeout, response-size,
   concurrency, cancellation, fixed-request, lifecycle, and non-echoing error
   controls. It does not start Ollama, download a model, or change Qwen
   configuration.
5. **Third PR:** expose only the immutable read-only receipt in the existing
   **Deep analysis & context** panel after the adapter's data, privacy, error,
   and browser bounds are proven.
6. Consider any active host, network, file, or response integration only as a
   separately authorized product phase with durable intent, authorization,
   readback, reconciliation, and independent security review.

The existing Qwen identifiers in the fixtures remain placeholders. The presence
of the internal adapter does not mean that Qwen is installed, configured, invoked,
or allowed to perform any protective action. A user-facing route remains blocked
on step 5 and on a real operator-owned model alias/artifact receipt.

## Verification target

The tests prove the data and provider boundaries without a live Ollama installation
or any external network request:

~~~bash
python -m pytest -q tests/test_local_model_advisory_contract.py
python -m pytest -q tests/test_advisory.py
python -m pytest -q tests/test_advisory_provider.py
python -m megalodon capabilities --platform linux
python -m megalodon hub-plan --platform linux
~~~

Those checks use a fake provider boundary and a direct socket-construction probe;
they must not contact an Ollama instance, start a model, inspect a host, capture
traffic, write SQLite, or mutate a firewall.
