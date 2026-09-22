# Deterministic Ollama/Qwen generate-request contract

Status: ● **implemented offline request construction; provider wiring not changed**  
Related gate: issue #261

MEGALODON's existing Qwen adapter already limits requests to one literal
loopback endpoint, one `/api/generate` call, no redirects, no retries, no model
pull/start, and no tool execution. This slice isolates the request-body
contract before modifying that security-dense transport.

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
- rejects additional response properties;
- requires `summary`, `benign_alternatives`, and `missing_evidence`;
- limits the summary to 600 characters;
- limits each supporting list to one through four unique strings of at most
  300 characters.

MEGALODON still validates the returned JSON independently. Provider-side
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

This PR intentionally does not edit `megalodon/qwen_advisory.py`. A successor
wiring PR must:

1. import this builder rather than duplicate request settings;
2. prove byte-for-byte request compatibility for generic advisories;
3. prove anomaly responses still satisfy the existing independent parser;
4. rerun literal-loopback, cancellation, timeout, concurrency, proxy/DNS,
   partial-response, and no-tool negative controls;
5. obtain exact-head independent security review.

Model binding, provider containment, signed evaluation, owner acceptance,
release, deployment, and host operation remain separate decisions.
