# Local model advisory contract v1

This is a **data-only, proposed** contract for issue #145.  It validates the
small metadata projection and display-only result envelope described in
[`docs/local-model-advisory-contract.md`](../../../docs/local-model-advisory-contract.md).

Validation is not an adapter.  It does not connect to Ollama, install or start
Qwen, read a capture or a file, query a database, start a process, expose an
endpoint, or grant an action capability.

## What is allowed

- one closed metadata projection describing a completed or failed bounded run;
- one selected explanation purpose, not a free-form model prompt;
- an operator-recorded local model receipt and fixed v1 resource limits; and
- one bounded, untrusted result with a closed outcome and fixed result code.

## What is rejected

Unknown fields, raw evidence, free-form prompts, provider addresses, credentials,
tool/action fields, URLs, paths, commands, and mutable host controls have no
place in the schema.  A later runtime adapter must pass this contract **before**
it makes any explicitly authorized, loopback-only local request.

Run the contract suite with:

~~~bash
python -m pytest -q tests/test_local_model_advisory_contract.py
~~~

The fixtures are synthetic and contain no captures, payloads, host identifiers,
credentials, local paths, or provider configuration.