# Qwen/Ollama profile lab and upgrade strategy

Status: ● **implemented offline lab; no provider or model admitted**  
Related gate: issue #261

MEGALODON already has a literal-loopback, fingerprint-pinned Qwen advisory
transport. The highest-value next step is not a broader chat box or automatic
model pull. It is a reproducible way to bind one operator-owned model artifact,
compare bounded candidates, and preserve the difference between model quality,
provider containment, and operational authority.

## What this slice adds

`tools/qwen_profile_lab.py` accepts only explicit operator-supplied JSON files.
It never discovers models, contacts Ollama, starts inference, or changes the
host.

```bash
python tools/qwen_profile_lab.py validate profile.json
python tools/qwen_profile_lab.py packet profile.json
python tools/qwen_profile_lab.py compare candidate-a.json candidate-b.json
```

The output is canonical one-line JSON. Refusals use fixed error codes and do
not echo paths, profile contents, or exception text.

The profile binds:

- exact Ollama model tag and observed manifest digest;
- separately hashed model artifact and provenance record;
- separately hashed provider-containment receipt;
- Ollama runner version and binary digest;
- model family, quantization, full context capacity, and MEGALODON's narrower
  operational context;
- structured-output and no-thinking posture;
- exact adversarial corpus digest and result counts;
- p95 latency and peak resident memory as comparison observations.

The comparison order is intentionally conservative: closed schema, citation,
and refusal gates outrank speed or memory. The comparison never chooses a
winner; `selection` is always `null`.

## Like-for-like comparison only

Each validated profile derives a `comparison_boundary_sha256` over the exact
workload and execution boundary:

- evidence class;
- provider and literal loopback endpoint;
- purpose and operational context;
- structured-output and no-thinking posture;
- runner name, version, and binary digest;
- adversarial corpus digest and sample count.

The comparison command refuses mixed corpora, runner drift, purpose drift,
operational-context drift, or synthetic/operator evidence mixing. Model tag,
family, quantization, context capacity, latency, and memory remain candidate
attributes and may differ. This prevents a faster model from ranking ahead only
because it was measured against an easier corpus or different runtime.

## Recommended capability lanes

These lanes are planning guidance, not admitted aliases.

| Lane | Intended use | Runtime posture | Admission posture |
|---|---|---|---|
| Stage 0 advisory baseline | Alert explanation | Structured JSON, temperature 0, thinking disabled, 4,096-token operational context | Continue the existing exact Qwen 2.5 binding until an owner changes it |
| Reasoning evaluation | Difficult offline explanation tests | Separate corpus; thinking output neither persisted nor treated as evidence | Research-only candidate |
| Coding assistant | Repository development and review | Separate workstation tool; no product evidence or host-action authority | Outside MEGALODON runtime |
| Vision evaluation | Screenshot or document understanding | Requires a distinct image/redaction contract and fixtures | HOLD until policy and evidence lanes exist |

Ollama's API supports a JSON Schema in the `format` field and deterministic
generation controls. MEGALODON should use that feature for machine-facing
advisories, while keeping human explanations bounded and visibly advisory.
Ollama also exposes model templates and runtime parameters through Modelfiles;
those settings belong in the exact profile and must not be inferred from a tag
alone.

Primary implementation references:

- Ollama structured outputs:
  https://docs.ollama.com/capabilities/structured-outputs
- Ollama generate API:
  https://docs.ollama.com/api/generate
- Ollama Modelfile:
  https://docs.ollama.com/modelfile
- Qwen model documentation:
  https://qwen.readthedocs.io/

## Operator workflow

1. Acquire Ollama and a Qwen artifact through an owner-approved process outside
   this tool. Do not add a pull or service-start command to MEGALODON.
2. Record the exact tag, `/api/tags` manifest digest, artifact digest,
   provenance digest, Ollama binary version/digest, and separately produced
   containment-receipt digest.
3. Run the signature-bound adversarial corpus and record exact counts. A
   partial result stays `EVALUATION_HOLD`.
4. Run `validate` and `packet`; preserve both the input profile and output
   packet as owner evidence outside public fixtures.
5. Compare alternatives only when the tool emits the same comparison-boundary
   digest for every profile. Do not override a boundary mismatch.
6. Make owner binding, independent security acceptance, release, deployment,
   and host-operation decisions separately.

## Security and truth boundary

The lab validates consistency of operator-supplied data. It does not attest the
bytes behind a digest, prove Ollama has no egress, prove process ownership,
prove GPU or memory isolation, verify the evaluation was actually run, or
establish model accuracy. Those remain explicit evidence and review tasks.

No real model, runner, host path, private receipt, or environment observation
belongs in the checked-in synthetic fixture.
