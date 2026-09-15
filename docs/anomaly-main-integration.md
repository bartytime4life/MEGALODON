# Main integration of the anomaly and Qwen pipeline

This record explains a delivery repair, not a new detection algorithm or an
operational release. On September 15, 2026, the inspected default branch was
`45e841587095608b8bbc82415fe7eea21198cd2a`, tree
`dd3728d414b981e5ea8966f57dc0aee01e9c212a`. It contained the deterministic
anomaly dossier, but neither `megalodon/anomaly_advisory.py` nor
`megalodon/offline/triage.py`.

## The merged status was not default branch delivery

| Pull request | Recorded merge | Merge destination | Integration meaning at the inspected main |
| --- | --- | --- | --- |
| [#178](https://github.com/bartytime4life/MEGALODON/pull/178) | `07a3df248c94d8f26c0339163e888d71b9ac942d` | `main` | Dossier builder present, including the candidate-limit repair |
| [#180](https://github.com/bartytime4life/MEGALODON/pull/180) | `d8a41c9cfe3f8e21d03871b346ab77ef8fc2e08f` | `agent/anomaly-evidence-v1-20260915` | Qwen policy merged only into a feature branch |
| [#181](https://github.com/bartytime4life/MEGALODON/pull/181) | `33d12a38bb485550aaff83fa63f8181a2686122e` | `agent/qwen-anomaly-airlock-v1-20260915` | Analyst command merged only into a feature branch |

The recovery integrates the tree at #181's merge into the inspected main,
which already includes the anomaly evidence, workload lab, original Qwen
denial corpus, JSONL admission repair, and bounded dashboard queries. Existing
main changes are retained; the scorer and its repaired thresholds are not
reimplemented. The integration PR targets `main` directly. No historical PR
is reopened, relabeled as unmerged, or treated as a default-branch receipt.

GitHub's [pull-request reference](https://docs.github.com/en/pull-requests/reference/pull-requests)
distinguishes the proposal, head, base and temporary merge refs. Here, live
PR metadata plus the actual default-branch file tree establish the gap;
the word "merged" alone does not establish where a capability is available.

## Research decisions

The [Hugging Face disclosure](https://huggingface.co/blog/security-incident-july-2026)
describes LLM-assisted telemetry triage and locally hosted open-weight forensic
analysis. It does not provide a MEGALODON adapter or prove Qwen performance.
Its [technical timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline)
also reports that signal correlation did not correctly trigger criticality
and on-call escalation. The engineering inference is to evaluate detection,
explanation and alert delivery separately, not to let model text suppress or
replace evidence. This integration has no alert-delivery or severity path.

The supplied Advancement Blueprint prioritizes bounded evidence and explicit
authority. The Local Command Center Integration Blueprint separates native
read models from optional tools and gives models no action authority. Their
historical repository pins are not current implementation evidence. The
Repository Research Analysis Framework was written without a repository;
its useful contribution here is exact-revision source and workflow inspection.
No supplied document is redistributed in this change.

[Scikit-learn's anomaly-detection guidance](https://scikit-learn.org/stable/modules/outlier_detection.html)
distinguishes potentially contaminated outlier training data from a clean
novelty reference and warns against evaluating novelty detection on training
observations. Accordingly, representative source-qualified labels and a
time-separated holdout remain prerequisites for new statistical scoring.
The existing exact share thresholds remain descriptive and uncalibrated;
no ML dependency, model training or efficacy claim is added.

The [Ollama generation API](https://docs.ollama.com/api/generate) is only the
protocol reference for the existing transport. Supporting a field upstream
does not admit it into MEGALODON's closed contract. This recovery retains the
fixed loopback endpoint, no tools, no redirects, no retry, and separate
registry pin. It does not install, inspect, start or call an actual model.

## Integration acceptance

- Keep the original run-count policy and its newer denial corpus unchanged.
- Recompute anomaly evidence from validated baselines before model admission.
- Exercise malformed, indirect-resource and authority-spoofing fields at the
  explicitly enabled anomaly provider entry point with zero-I/O sentinels.
- Prove the repaired low-support port-churn case also keeps the command out
  of the registry/provider path even when `--qwen` was requested.
- Preserve non-root/capability-free preflight, bounded selected-file reads,
  default-disabled AI, deterministic evidence on model failure, and unknown
  request accounting after an unexpected provider escape.
- Run full tests, build-input and hygiene guards, wheel/sdist tests, real
  non-root hosted acceptance, browser acceptance, and CodeQL on the
  main-targeted exact head. A filtered-out CodeQL run is missing evidence.

Exact results belong in the integration PR and dated coordination checkpoint.
Green checks are not independent approval, model efficacy or deployment.

## Next bounded work after integration

First review and land this repair through the owner's normal PR workflow.
Then consider one evidence-bound anomaly receipt projection in the existing
Deep analysis panel, with recomputed dossier identity, separate AI labeling,
missing/stale states, text-only rendering, and no invocation endpoint.
The current dashboard remains a v1 receipt consumer until that separate work
passes acceptance. Do not imply that the new command is already a dashboard
feature.

Representative temporal evaluation and operator-owned model acceptance remain
separate. Measure abstention, precision/recall and false alerts against known
labels and actual observation coverage; use source-hours only when attested
coverage supplies that denominator. The workload lab's hypothetical numbers
are not observed accuracy. Scheduling, continuous operation, sensor control,
notification delivery, firewall changes and deployment remain out of scope.
