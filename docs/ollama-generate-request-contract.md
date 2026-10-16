# Deterministic Ollama/Qwen generate-request contract

Status: ● **canonical request construction wired into the advisory transport;
acceptance remains HOLD**
Related gate: issue #446

MEGALODON's Qwen adapter limits requests to one literal loopback endpoint, one
`/api/generate` call, no redirects, no retries, no model pull/start, and no
tool execution. The live transport now imports this builder, so generic and
anomaly advisories use the same canonical bytes that the offline contract
hashes and validates.

```bash
python tools/ollama_generate_contract.py request-input.json
```

The command validates the input and emits only a privacy-minimized receipt. It
does not print the prompt or request body and performs no provider, process,
filesystem, package, service, firewall, GPU, or host operation.

## Two request modes

### Generic advisory

The generic mode preserves the current bounded plain-text advisory path. It
sets deterministic runtime controls but deliberately omits `format`.

### Anomaly advisory

The anomaly mode adds an Ollama structured-output schema to `format`. The
schema:

- fixes the exact candidate IDs and their order;
- uses an array-level `const` compatible with the pinned Ollama 0.24 schema
  converter, avoiding unsupported boolean `items` handling;
- rejects additional response properties;
- requires `summary`, `benign_alternatives`, and `missing_evidence`;
- limits the summary to 600 characters;
- limits each supporting list to one through four unique strings of at most
  300 characters.

MEGALODON still validates the returned JSON independently, checking each
field against these limits and the shared display-control rules. The joined
anomaly display text is not held to the generic 1,200-character v1 summary
limit; an answer at every per-field limit is accepted. Provider-side
structured output is defense in depth, not a replacement for the existing
closed parser.

## Fixed runtime profile

The builder fixes this exact body posture:

```json
{
  "keep_alive": 0,
  "options": {
    "num_ctx": 4096,
    "num_predict": 512,
    "seed": 0,
    "temperature": 0
  },
  "raw": true,
  "stream": false,
  "think": false
}
```

No `tools` field is emitted. A listed model capability never becomes tool,
detector, shell, firewall, or action authority.

The 4,096-token context is MEGALODON's bounded operational context, not a claim
about the model's maximum context capacity. The final canonical request must
fit the existing 6,144-byte request budget after JSON escaping.

Official Ollama references:

- `format`, `stream`, `think`, `raw`, `keep_alive`, and `options`:
  https://docs.ollama.com/api/generate
- JSON Schema structured output and temperature-zero guidance:
  https://docs.ollama.com/capabilities/structured-outputs
- `num_ctx`, `seed`, `temperature`, and `num_predict` parameter semantics:
  https://docs.ollama.com/modelfile

## Remaining runtime gate

`megalodon/qwen_advisory.py` imports this builder rather than duplicating its
settings. Regression tests prove byte-for-byte parity for generic and anomaly
requests, forbid tool/memory extension fields, and retain the independent
response parser, literal-loopback, cancellation, timeout, concurrency,
proxy/DNS, partial-response, and no-tool controls.

`RUNTIME_PROVIDER_WIRING` nevertheless remains a HOLD until exact-head
independent security review and owner acceptance are recorded. Test-backed
construction parity is not model binding, provider containment, or permission
to perform inference.

Model binding, provider containment, signed evaluation, owner acceptance,
release, deployment, and host operation remain separate decisions.
