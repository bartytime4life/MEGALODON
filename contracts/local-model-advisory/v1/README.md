# Local model advisory contract v1

This directory contains the **data-only v1 contract** delivered through issue #145 and
extended for the bounded invocation receipt in issue #165. It validates the small
metadata projection, display-only result envelope, and runtime receipt described in
[`docs/local-model-advisory-contract.md`](../../../docs/local-model-advisory-contract.md).

Schema validation is not an adapter. It does not connect to Ollama, install or start
Qwen, read a capture or a file, query a database, start a process, expose an
endpoint, or grant an action capability.

## What is allowed

- one closed metadata projection describing a completed or failed bounded run;
- one selected explanation purpose, not a free-form model prompt;
- one fingerprint-pinned `local-model-registry-v1` containing exactly one local
  model receipt, its fixed v1 resource limits, and an empty tool list; and
- one bounded, untrusted result with a closed outcome and fixed result code; and
- one immutable invocation receipt that distinguishes policy denial, local-provider
  error, and a bounded answer without retaining raw provider output.

`rejected_records` is a bounded integer for a completed run. A failed run may
instead carry JSON `null` when the offline receipt could not determine the
count. That unknown value is preserved as unknown; it is never rewritten to
zero. The other counts always remain bounded integers.

## What is rejected

Unknown fields, raw evidence, free-form prompts, provider addresses, credentials,
tool/action fields, URLs, paths, commands, and mutable host controls have no
place in the schema or registry. A registry cannot carry an endpoint, URL,
command, path, credential, prompt, or tool. The runtime adapter reruns this
contract's stricter Python Airlock **before** it makes any explicitly authorized,
loopback-only local request.

Run the contract suite with:

~~~bash
python -m pytest -q tests/test_local_model_advisory_contract.py
~~~

The fixtures are synthetic and contain no captures, payloads, host identifiers,
credentials, local paths, or provider configuration.

## No-network preflight

Issue #154 adds a deterministic Python preflight around this contract. Issue
#161 replaces its two loose model-approval arguments with one structurally
closed registry and an independently supplied lowercase SHA-256 pin. The
preflight validates and canonically fingerprints the registry before it validates
the request, then requires the request receipt and limits to match the sole
registry entry exactly. It uses repository-owned source/adapter pairs and
constructs one canonical in-memory prompt. An `ADMIT` decision authorizes prompt
construction only. It is not a provider request, model result, detection,
evidence item, or action authorization.

The preflight deliberately contains no provider client, endpoint, socket,
subprocess, filesystem read, database access, capture path, tool call, or host
mutation. Run its negative controls with:

~~~bash
python -m pytest -q tests/test_advisory.py
~~~

The reusable adversarial denial corpus is
`fixtures/adversarial/denials.json`. It covers every finite DENY class and the
forbidden registry-field matrix, including a validly shaped artifact-digest
tamper. Each case runs twice and must return the same exact serialized receipt
without changing its inputs. HTTP/socket, subprocess, firewall, SQLite,
filesystem read/write, tool-discovery, and command-entry sentinels fail on any
attempted side effect.

## Literal-loopback provider boundary

[`megalodon/advisory_provider.py`](../../../megalodon/advisory_provider.py) adds
one internal, explicitly enabled request boundary. It accepts the closed request,
registry, and independent registry pin; reruns preflight internally; and then can
send only the admitted prompt and exact registry model ID to literal
`127.0.0.1:11434/api/generate`.

The adapter has no endpoint, URL, model override, raw prompt, header, credential,
transport, tool, or action parameter. It does not use proxy environment values,
DNS, redirects, streaming, discovery, model pull/update, subprocesses, files,
SQLite, capture, or firewall code. One process-wide nonblocking lock enforces
concurrency one; a monotonic end-to-end deadline is 15 seconds; `num_predict` is
512; `think` is false; `keep_alive` is zero; raw response and decoded model text
are separately bounded. A short-lived guard shuts down the fixed active socket
when the deadline expires or the caller cancels, including during blocked header
and body reads.

Provider output is accepted only from one terminal HTTP 200 JSON response with
the exact model ID, `done: true`, no non-empty reasoning field, a closed provider
metadata shape, and bounded printable text. Unknown fields—including tool
calls—fail closed. The text is
whitespace-normalized and wrapped in the application-owned
`advisoryInvocationReceipt`; it remains untrusted and non-executable.

Run the provider boundary tests without a live Ollama instance:

~~~bash
python -m pytest -q tests/test_advisory_provider.py
~~~

The fixture model ID and artifact digest are synthetic. The adapter records the
registry-bound identity and rejects a mismatched response model ID, but it does
not discover or attest installed Ollama model bytes. An operator must establish
the exact local alias/artifact binding separately before real use.
