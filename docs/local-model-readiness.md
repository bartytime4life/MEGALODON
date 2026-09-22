# Local Ollama/Qwen readiness integration

Status: ● **implemented offline evidence integration; provider acceptance remains HOLD**  
Tracking issue: #261

MEGALODON now has separate contracts for binding, identity, candidate profiles,
provider containment, adversarial evaluation, and deterministic request
construction. Those separations are security controls, but they previously
left reviewers to compare digests and aliases manually.

`tools/local_model_readiness.py` adds the missing integration layer. It invokes
the existing validators, then emits one deterministic packet showing whether
the records describe the same local Ollama/Qwen candidate.

## Cross-record invariants

For a bound candidate the assessor checks:

1. the binding alias equals the identity and containment aliases and the
   deterministic request model ID;
2. the installed Ollama tag equals the identity and profile tags;
3. manifest, model-artifact, runner-version, and runner-binary digests align;
4. the containment binding uses the same artifact and registry fingerprint;
5. the profile hashes the exact containment packet;
6. the evaluation binds the exact profile and comparison-boundary hashes;
7. corpus identity, sample count, p95 latency, and peak memory agree between
   the profile, evaluation, and containment records; and
8. the request retains `num_ctx=4096`, `num_predict=512`, `seed=0`,
   `temperature=0`, `keep_alive=0`, `raw=true`, `stream=false`, `think=false`,
   and no `tools` field.

A model may advertise a tools capability. The packet records that observation
but fixes `tools_used_or_authorized` to `false`; capability discovery never
becomes tool, shell, detector, firewall, or response authority.

## Why issue #261 remains open

The repository's code and contracts can prove shape, bounded behavior, and
cross-record consistency. They cannot manufacture an operator-owned artifact,
authenticate supplied host observations, attest the bytes loaded during a
specific generation, perform an outbound-deny/provider-containment rehearsal,
execute the signed corpus on the owner's machine, or provide independent
security acceptance.

The strongest offline state is therefore `CANDIDATE_PACKET_CONSISTENT`, not
`ACCEPTED`, `READY`, `RELEASED`, or `DEPLOYED`.

## Next native evidence sequence

1. Record the exact owner-selected binding and artifact component closure.
2. Generate the operator-observed Ollama identity record.
3. Produce authenticated containment evidence on the named host profile.
4. Execute and externally verify the signed seven-category corpus.
5. Run this readiness assessor with `--require-consistent`.
6. Obtain independent review of the exact packet and candidate.
7. Record owner acceptance separately from release, deployment, and operation.

No step in this document authorizes model installation, startup, inference,
network access, systemd/firewall changes, remote exposure, release, or
deployment.
