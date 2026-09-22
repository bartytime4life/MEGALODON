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
and request alias/runtime controls.

## States

- `UNBOUND`: the canonical repository binding still records no owner-selected
  model. No other evidence may be supplied alongside this state.
- `EVIDENCE_HOLD`: the binding is present but evidence is missing, synthetic,
  incomplete, or contradictory.
- `CANDIDATE_PACKET_CONSISTENT`: all supplied records describe one candidate
  and their local hard gates report complete.

`CANDIDATE_PACKET_CONSISTENT` is not model acceptance. The packet always
retains evidence-origin authentication, loaded-runtime-byte attestation,
independent security currentness, owner final acceptance, and release/deployment
HOLDs. Every authority flag is fixed to `false`.

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
