# Local Ollama/Qwen profile candidate contract v1

Status: **candidate contract and offline proof only**.

This contract gives MEGALODON one closed shape for comparing an
operator-observed Ollama/Qwen model alias, manifest digest, artifact digest,
provenance receipt, provider-containment receipt, runner identity, bounded
runtime profile, and adversarial evaluation counts. It exists to make the
remaining owner decision in issue #261 precise. It does not make that decision.

## Files

- `schema.json` is the closed JSON Schema for
  `megalodon-local-model-profile-v1`.
- `fixtures/accepted-synthetic.json` is deliberately labeled
  `synthetic_fixture`; all hashes and versions are test values, not real
  software or artifact claims.
- `megalodon/model_profile.py` applies stricter runtime checks, including
  cross-field count bounds, operational-context limits, deterministic hashing,
  and fixed separate HOLDs.
- `tools/qwen_profile_lab.py` validates, emits a binding-candidate packet, or
  compares two or more profiles without contacting Ollama.

## Required distinctions

A profile can be:

- `SYNTHETIC_ONLY`: schema and validator proof using test identities;
- `EVALUATION_HOLD`: operator-observed identity whose evaluation counts are
  incomplete;
- `CANDIDATE_VALIDATED`: closed shape and all three local evaluation counts
  complete.

None means selected, admitted, accepted, installed, running, released, or
deployed. Every packet retains these independent holds:

1. provider-containment acceptance;
2. independent artifact-provenance verification;
3. owner model binding;
4. independent security acceptance;
5. release and deployment authority.

The profile lab performs no model pull, process start, socket connection,
filesystem discovery, service management, host change, firewall action,
approval transition, release, or deployment.
