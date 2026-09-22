# Operator-owned local model binding

Status: 📜 contract only — the repository remains `UNBOUND`; no model or provider
was inspected, pulled, installed, started, aliased, invoked, or approved.

Issue #261 requires a completed identity chain before provider containment can
advance. `megalodon.local-model-binding/v1` records that chain separately from
the existing containment-observation packet:

- logical `local:qwen-*` alias;
- exact Ollama version, executable digest, and provenance reference;
- immutable installed tag, local manifest digest, model-weight digest, complete
  component closure, artifact provenance, and license references;
- exact host/backend profile and effective-configuration digest;
- policy registry identity and fingerprint; and
- an explicit operator approval record with evidence references.

The checked-in `config/model-bindings/qwen.unbound.json` is intentionally empty.
It is the canonical repository posture until an operator supplies authenticated
values and separately approves the completed chain.

```bash
python tools/local_model_binding.py validate \
  config/model-bindings/qwen.unbound.json
python tools/local_model_binding.py collect-unbound
```

A `BOUND` record refuses mutable `:latest` tags, duplicate component identities,
missing component closure, a weight digest that differs from the sole weight
component, missing license/provenance/host/registry data, or an absent operator
decision. Structural validation does not authenticate the named actor, receipts,
provider binary, or model bytes.

All effect fields are fixed to `false`. This contract cannot pull or start a
model, create an alias, change host configuration, grant detector/action
authority, establish no-egress containment, record independent security
acceptance, authorize release/deployment, or close issue #261 by itself.
