# Offline Ollama identity intake

Status: ● **implemented offline validation; no provider observation accepted**  
Related gate: issue #261

`tools/ollama_identity_lab.py` converts one explicit JSON observation into a
privacy-minimized identity receipt. It performs no network request, process
inspection, model pull, service start, filesystem search, host mutation, or
approval transition.

```bash
python tools/ollama_identity_lab.py observation.json
```

The observation is prepared outside this tool only after separate operator
authorization. It should bind:

- the exact MEGALODON `local:qwen-*` alias;
- the exact Ollama tag;
- the Ollama version response and binary hashes;
- the `/api/tags` response hash, matching tag identity, manifest digest, size,
  format, family, parameter size, and quantization;
- the `/api/show` response hash, matching details, capabilities, modification
  time, and hashes of parameters, template, license, and model-info content;
- separately acquired artifact and provenance hashes.

The raw provider responses remain outside the receipt. The tool emits only
normalized identities and digests, plus explicit HOLDs.

## Why `/api/tags` and `/api/show` are both needed

`/api/tags` provides the local model-list identity and digest. `/api/show`
exposes the selected model's details, capabilities, parameters, template,
license, and model-info fields. Cross-checking their shared details detects
simple alias or metadata substitution. It still does not authenticate the
snapshot source or attest the exact bytes loaded during a generation.

Official API references:

- https://docs.ollama.com/api/tags
- https://docs.ollama.com/api/show
- https://docs.ollama.com/api/version

## Authority boundary

A receipt state of `IDENTITY_OBSERVATION_VALIDATED` means only that the supplied
closed document is internally consistent. It does not approve the binding,
prove no egress, start a provider, attest loaded bytes, authorize a model
request, close issue #261, or authorize release or deployment.
