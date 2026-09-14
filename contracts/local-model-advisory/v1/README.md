# Local model advisory contract v1

This is a **data-only, proposed** contract delivered through issue #145. It
validates the small metadata projection and display-only result envelope described in
[`docs/local-model-advisory-contract.md`](../../../docs/local-model-advisory-contract.md).

Validation is not an adapter.  It does not connect to Ollama, install or start
Qwen, read a capture or a file, query a database, start a process, expose an
endpoint, or grant an action capability.

## What is allowed

- one closed metadata projection describing a completed or failed bounded run;
- one selected explanation purpose, not a free-form model prompt;
- one fingerprint-pinned `local-model-registry-v1` containing exactly one local
  model receipt, its fixed v1 resource limits, and an empty tool list; and
- one bounded, untrusted result with a closed outcome and fixed result code.

`rejected_records` is a bounded integer for a completed run. A failed run may
instead carry JSON `null` when the offline receipt could not determine the
count. That unknown value is preserved as unknown; it is never rewritten to
zero. The other counts always remain bounded integers.

## What is rejected

Unknown fields, raw evidence, free-form prompts, provider addresses, credentials,
tool/action fields, URLs, paths, commands, and mutable host controls have no
place in the schema or registry. A registry cannot carry an endpoint, URL,
command, path, credential, prompt, or tool. A later runtime adapter must pass
this contract **before** it makes any explicitly authorized, loopback-only local
request.

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

## Explicit Qwen provider adapter

`megalodon.qwen_advisory.invoke_qwen_advisory` is a separate, library-only
runtime boundary. It reruns the Airlock preflight, requires literal
`enabled=True`, takes a non-blocking concurrency-one gate, and then makes at
most one request to `127.0.0.1:11434/api/generate`. Its request fixes
`stream=false`, `think=false`, `raw=true`, `keep_alive=0`, temperature zero,
and a 512-token generation ceiling; it supplies no tools, credentials, URLs,
arbitrary prompts, model discovery, retry, redirect, fallback, model pull, or
process action.

The adapter applies one actively enforced 15-second deadline, accepts an
optional per-invocation cancellation event, bounds the status line and headers
to 8 KiB before standard-library parsing, bounds the JSON body to 32 KiB, and
accepts at most 4 KiB of UTF-8 model text. Provider JSON has a closed field set;
duplicate keys, tool-call fields, and non-empty thinking traces fail closed. Its
display value is the closed `advisoryResult` shape. The operator-recorded
artifact digest is checked against the fingerprint-pinned registry before HTTP,
but the generate response does not independently attest loaded model bytes. The
fixtures remain synthetic and are not a model installation or approval.

Run the adapter boundary tests with:

~~~bash
python -m pytest -q tests/test_qwen_advisory.py
~~~
