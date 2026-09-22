# Deterministic Ollama generate-request contract v1

Status: ● **implemented offline builder and receipt; runtime wiring remains held**.

This contract turns one already-admitted MEGALODON advisory prompt into an
exact, bounded Ollama `/api/generate` request body without performing the
request. It is a prerequisite for a later, separately reviewed change to the
existing literal-loopback Qwen transport.

## Fixed request controls

Every request fixes:

- `keep_alive: 0`;
- `stream: false`;
- `think: false`;
- `raw: true`;
- `options.num_ctx: 4096`;
- `options.num_predict: 512`;
- `options.seed: 0`;
- `options.temperature: 0`;
- no `tools` field and no tool authority.

`generic_advisory` produces bounded plain text and therefore omits `format`.
`anomaly_advisory` adds a closed JSON Schema in `format`. That schema binds the
exact candidate-ID order and permits only `candidate_ids`, `summary`,
`benign_alternatives`, and `missing_evidence`, with the same list and length
bounds enforced by MEGALODON's existing response parser.

The canonical request body must be no larger than 6,144 bytes. The builder
refuses oversized inputs after JSON escaping, so a Unicode prompt cannot evade
the final wire-size limit.

## Files

- `schema.json` defines the closed builder input.
- `fixtures/generic-synthetic.json` and
  `fixtures/anomaly-synthetic.json` contain fabricated examples only.
- `megalodon/ollama_generate_contract.py` validates and constructs the
  canonical request.
- `tools/ollama_generate_contract.py` emits a privacy-minimized receipt; it
  never prints the prompt or full request body.

## Authority boundary

A `REQUEST_CONTRACT_VALIDATED` receipt proves only deterministic construction
of the supplied input. It does not contact Ollama, prove that Ollama honors the
schema, bind a real runner or model artifact, start or pull a model, authorize
tools, establish provider containment, accept a model, or authorize release or
deployment.

Runtime provider wiring, exact model/runner binding, signed adversarial
evaluation, independent security acceptance, and release/deployment remain
separate HOLDs.
