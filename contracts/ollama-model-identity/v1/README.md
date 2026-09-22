# Ollama model identity observation contract v1

Status: **contract and offline validator; native observation still required**.

The contract records privacy-minimized, operator-supplied observations from an
already authorized local Ollama provider. The repository tool validates and
hashes those observations; it does not contact Ollama or authenticate their
origin.

The observation keeps three identities separate:

1. the MEGALODON binding alias (`local:qwen-*`);
2. the exact Ollama model tag used for `/api/tags` and `/api/show`;
3. the separately acquired artifact and provenance hashes.

It also binds hashes of the raw `/api/version`, `/api/tags`, and `/api/show`
responses, the Ollama binary, model metadata, parameters, template, license,
and model-info blocks. Raw templates, parameters, licenses, local paths, and
provider responses are intentionally excluded from the public fixture and the
projected receipt.

A validated observation is not runtime-byte attestation. Ollama generation
responses do not independently prove which bytes were loaded, and API metadata
can be copied or self-reported. Provider containment, independent artifact
verification, owner binding, independent security acceptance, release, and
deployment remain separate HOLDs.
