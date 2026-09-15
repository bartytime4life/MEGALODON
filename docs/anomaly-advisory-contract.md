# Qwen anomaly explanation contract

`local-model-anomaly-advisory-v1` is a separately admitted evidence explanation
policy delivered to main in #187. The original `local-model-advisory-v1`, its
two questions and registry remain separate. Both policies share the tightened
[completion and result-text checks](advisory-result-integrity.md). Neither policy's
registry implicitly authorizes the other.

`preflight_anomaly_advisory` accepts one `qwen-anomaly-request-v1`: the original
closed anomaly input, one approved model receipt, fixed limits and one of
`explain_anomalies` or `explain_anomaly_limitations`. It recomputes the dossier
from both baselines. Caller-supplied dossiers, scores, prompts, paths, URLs,
commands, log strings, payloads, secrets and tool fields are rejected. Empty,
stale or otherwise ineligible evidence never triggers a model request.

The sole `qwen-anomaly-registry-v1` entry must match the model receipt and the
4 KiB input/output, 15-second, concurrency-one limits. Canonical registry JSON
must match an independently supplied SHA-256 pin. Its policy must be exactly
`local-model-anomaly-advisory-v1`. The contract's fixture registry is synthetic
test data, not an operator approval or an installed-model attestation.

The JSON Schema checks the closed structure. Runtime validation additionally
enforces exact primitive types, count consistency, source/adapter pairing,
window eligibility, fingerprint agreement and a recomputed evidence identity.
Only repository-generated candidate IDs, rule names, counts, denominators,
declared windows and fixed context enter the canonical prompt. These are
aggregate metadata, with no raw network addresses or packet contents.

`invoke_qwen_anomaly_advisory` repeats preflight and requires `enabled=True`
per invocation. It shares the original provider implementation, including the
same lock, deadline, cancellation and strict response parser. There is no
second transport implementation. The sole request uses literal
`127.0.0.1:11434/api/generate`, no tools, no streaming and no retry. Ollama's
[generation contract](https://docs.ollama.com/api/generate) describes the
upstream fields; MEGALODON narrows and validates them independently.

Provider output remains untrusted plain text. The prompt asks for supporting
candidate IDs and benign alternatives, but generated citations and reasoning
are not independently verified. The deterministic dossier is retained
separately and cannot be changed or suppressed by an answer, refusal or error.
The result retains the new policy version, so an old dashboard must reject it
until an explicit consumer compatibility change is reviewed. Shared result
validation does not authorize the v1 dashboard to accept anomaly receipts.

Runtime model bytes, the independent provider's egress controls, useful answer
quality on the installed Qwen and operational anomaly detection accuracy remain
unproved. No actual Qwen request is required for this PR's mocked transport and
adversarial acceptance tests. See [the pipeline plan](anomaly-pipeline.md) for
the ordered remaining integration and evaluation gates.
