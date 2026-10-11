# Local Ollama/Qwen readiness packet v1

Status: ● **implemented offline cross-binding; native provider acceptance remains held**.

This contract joins the repository's already separate local-model records into
one privacy-minimized consistency packet. It does not replace their validators
or broaden their authority.

The assessor accepts an exact local-model binding plus optional validated:

- Ollama identity observation;
- model profile;
- provider-containment packet;
- signed adversarial-evaluation receipt; and
- deterministic generate-request input.

For a bound candidate it cross-checks the MEGALODON alias, installed Ollama
tag, manifest, model artifact, runner, registry fingerprint, model profile,
containment digest, evaluation profile/boundary/corpus/count/resource values,
and request alias/runtime controls. When both a profile and a request are
supplied, the request must also run inside the profiled posture:

- `REQUEST_CONTEXT_PROFILE_MISMATCH`: `options.num_ctx` differs from the
  profile's `operational_context`;
- `REQUEST_CONTEXT_EXCEEDS_PROFILE_WINDOW`: `options.num_ctx` exceeds the
  profile's `context_window`; and
- `PROFILE_STRUCTURED_OUTPUT_FORMAT_MISSING`: the profile records
  `structured_output: true` but the request carries no `format` schema (for
  example a `generic_advisory` request).

The profile's `model_family` and `quantization` are **not** cross-checked
against the identity observation's Ollama `details`. Ollama reports API family
names (a Qwen 2.5 model reports `qwen2`) and quantization labels such as `F16`,
while profiles use free-form names such as `qwen2.5` and `fp16`; both sides are
unconstrained free text, so equality would refuse genuine candidates without
proving anything. Reviewers compare those fields manually.

The binding file is read with the same bounded, strict decoding as the other
evidence: oversized input, duplicate keys, `NaN`/`Infinity`, invalid UTF-8,
integers beyond the interpreter digit limit, and excessive nesting all refuse
with exit 2 and the fixed `BINDING_INVALID` code, as do binding timestamps that
are not real UTC calendar times.

## States

- `UNBOUND`: the canonical repository binding still records no owner-selected
  model. No other evidence may be supplied alongside this state.
- `EVIDENCE_HOLD`: the binding is present but evidence is missing, synthetic,
  incomplete, or contradictory.
- `CANDIDATE_PACKET_CONSISTENT`: all supplied records describe one candidate
  and their local hard gates report complete.

`CANDIDATE_PACKET_CONSISTENT` is not model acceptance. The packet always
retains evidence-origin authentication, loaded-runtime-byte attestation,
runtime provider wiring, independent security currentness, owner final
acceptance, and release/deployment HOLDs. Every authority flag is fixed to
`false`. `RUNTIME_PROVIDER_WIRING` stays held because the live advisory
transport does not yet send the request contract's `num_ctx`, `seed`, or
`format` controls, so a consistent request contract does not describe what a
provider call would carry.

## Operator commands

Current repository posture:

```bash
python tools/local_model_readiness.py \
  --binding config/model-bindings/qwen.unbound.json
```

A complete candidate assessment supplies all six explicit files:

```bash
python tools/local_model_readiness.py \
  --binding binding.json \
  --identity identity.json \
  --profile profile.json \
  --containment containment.json \
  --evaluation evaluation.json \
  --request request.json \
  --require-consistent
```

The tool performs no discovery and never contacts or controls Ollama. It does
not print prompts, provider responses, local paths, model contents, or advisory
text.
