# AI-assisted anomaly pipeline

Status: ● offline candidate evidence, separate Qwen admission, and the explicit
[one-shot analyst command](anomaly-triage.md) reached main through
[#187](https://github.com/bartytime4life/MEGALODON/pull/187), merge
`fa55906dc327c0bb0cde9366ac99a8f031d19484` on 2026-09-15 UTC.
Operational efficacy and anomaly dashboard integration remain unproved.

The [main-integration record](anomaly-main-integration.md) distinguishes code
merged into a feature branch from code available on the default branch. The
record retains the historical integration bases; the merge above establishes
delivery, not deployment or independent approval. Shared baseline realizability
and offline candidate coherence were also merged in #185 and #186.
The [result-integrity contract](advisory-result-integrity.md) defines completion,
display and failure-isolation checks without expanding model authority.

MEGALODON should generate reproducible metadata candidates first, then let a
pinned local Qwen explain that evidence for an analyst. Qwen must never create
a detection, suppress the deterministic evidence, or authorize a response.

## Research and repository reconciliation

[Hugging Face's July disclosure](https://huggingface.co/blog/security-incident-july-2026)
reports that LLM triage correlated security telemetry to surface the intrusion.
It also describes locally hosted open-weight models for subsequent analysis.
This supports the design pattern; it is not a released MEGALODON-compatible
detector, a benchmark for Qwen, or evidence of efficacy on this host. The
[technical timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline)
motivates isolation between imported data, model interpretation and tools.
No exploit payload or credential from that account is imported here.

The supplied Advancement Blueprint and Local Command Center Integration
Blueprint favor bounded evidence, separate read models and explicit integration
gates. Their September 9 repository pins are historical. The supplied Repository
Research Analysis Framework explicitly had no repository; its checklist is
methodology, not evidence about current MEGALODON. Current code already has
offline TShark/Zeek baselines, source-qualified comparison, the v1 Airlock and
literal-loopback Qwen transport. Merged PR #176 supplies the immutable v1
dashboard receipt display. It does not accept the separate anomaly policy;
do not treat it as anomaly integration.

The first scorer uses exact counts and fractions with explicit thresholds.
Training a new model is deferred until representative, labeled, temporally
separated local data exists. [Scikit-learn's distinction between novelty and
outlier detection](https://scikit-learn.org/stable/modules/outlier_detection.html)
explains why a contaminated reference cannot simply be labeled normal. No
scikit-learn or model-training dependency is added.

Merged PR #177's offline Alert Workload Lab is complementary evaluation work;
its hypothetical base-rate projections are not measurements of this scorer.
Merged PR #179 strengthens the original Qwen denial corpus at the enabled
provider boundary. The integration preserves both changes and adds enabled
anomaly-policy denial checks without expanding either policy's authority.

Hugging Face's technical timeline reports that AI correlation identified an
attack signal but failed to raise its criticality and call the on-call team.
Detection, model explanation, severity, and delivery therefore need separate
acceptance. This command implements only evidence and optional explanation;
it does not notify, assign severity, or replace an incident-response process.

## Candidate evidence

`megalodon.offline.anomaly.build_anomaly_dossier` takes a closed
`offline-anomaly-input-v2` object with `reference`, `current`, `as_of`, and an
independently approved selection fingerprint. Each side contains an existing
`offline-baseline-v1`, its normalized aggregate SHA-256, and a declared `window`:
`source_id` (`source-0001` style pseudonym), canonical UTC `started_at` and
`finished_at`, and `completeness` (`complete`, `incomplete`, `unknown`).

The `offline-anomaly-selection-v2` manifest binds both normalized baseline
fingerprints to their windows and `as_of`; its canonical SHA-256 must match the
separately supplied pin at the command and advisory API boundaries. The pure
dossier builder validates the embedded binding, while those outer boundaries
provide the independent trust input. This detects file substitution and
cross-selection mixing. It does not attest that an operator declaration is true
or authenticate the original sensor. Both adapters, record kinds and declared
source IDs must match. Never combine
packet and flow counts, infer cross-source identity, or silently deduplicate
different sensors. Baseline membership, source identity and loss-free collection
are not attested by these declarations; operators must verify them separately.
Windows are nonoverlapping, equal-duration and at most 24 hours. The reference
gap is at most seven days and current completion is within one hour of the
explicit `as_of`. Baseline relative bins must fit within their window. At least
20 accepted records per side are required. These are versioned eligibility
rules, not a claim of statistical sufficiency or an operational latency target.

Candidates include a destination port absent in the reference with at least
five current records, changes of at least 20 percentage points in destination
port or protocol shares, and changes in the large-record share. Comparisons
use integer cross multiplication. Candidate rows retain counts and denominators;
they have no probability, confidence, threat severity, or attribution field.
Eight candidates is the display limit. Overflow returns the eight rows with the
largest exact share deltas, then support and original deterministic order,
sets `truncated=true`, and records the complete `candidate_total`. Truncated
evidence is never sent to Qwen. Cold start, incompleteness, stale windows and
incompatible sources abstain. No candidates never means safe. The dossier ID
hashes normalized validated aggregate meaning plus the pinned selection, so
equivalent list orderings have one identity. It is neither a packet-payload hash
nor source attestation.

The pure API performs no I/O. It does not change the existing live detectors,
SQLite schema, actions, capture loop, dashboard or provider behavior.

## Dependency order and acceptance

| Slice | Deliverable | Required evidence |
| --- | --- | --- |
| 1 | Bounded source-qualified anomaly dossier | Exact threshold, cold-start, stale/incomplete, contradictory, overflow and no-side-effect tests |
| 2 | Separately versioned Qwen anomaly explanation admission | Canonical evidence-only prompt; independent registry pin; old v1 rejects new shape; shared deadline/concurrency; malformed and injection-shaped input denied |
| 3 | Explicit one-shot offline analyst command | Selected files only; non-root/capability-free gate; bounded read; evidence emitted with AI disabled, denied or failed; no retry or persistence |
| 4, proposed | Integrate receipts with #176's read-only display | Current-main reconciliation; new policy/receipt validation; text sinks; missing/stale states; browser acceptance; no invocation endpoint |
| 5, proposed | Temporal evaluation and optional repeated operation | Operator-selected representative data; immutable reference; time-separated holdout; false alerts per source-hour, precision/recall, abstention rate, coverage, p95 latency and peak memory; reviewed budget/queue/drop policy |

TShark and Zeek contribute only their existing admitted baseline formats.
Suricata, Wazuh, osquery, other catalog tools and external feeds need separate
adapters and source contracts; a catalog connection is not an active input.
There is no scheduler, monitor, model installation, automatic model update,
cloud inference, external telemetry upload, firewall action, or deployment in
these slices. Local provider readiness and representative detection accuracy
must be measured on the operator's system before operational acceptance.
