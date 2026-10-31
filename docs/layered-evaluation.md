# Offline layered-review evaluation

`python -m megalodon.evaluation layered-report` measures the investigation workload,
evidence links and reproducibility of the retained-flow analyzer and layered
correlator. It reads only the bundled synthetic corpus, writes JSON to stdout,
and requires no network, collector, model, working database or host action.

This is **synthetic evaluation, not operational detection acceptance**. The
25 cases contain ten ordinary, ten useful-to-investigate and five indeterminate
case-hours. A review is a request to investigate, not a malicious verdict.

## Reproduce

From a reviewed clean checkout with its test environment:

```bash
python -m megalodon.evaluation layered-report \
  --source-commit "$(git rev-parse HEAD)" \
  --source-tree "$(git rev-parse 'HEAD^{tree}')" \
  --repeats 5 --benchmark > /tmp/layered-evaluation.json
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_PLUGINS= PYTEST_ADDOPTS= \
  python -m pytest -ra tests/test_layered_evaluation.py tests/test_layered_review.py \
  tests/test_pattern_provenance.py tests/test_host_fanout.py tests/test_flow_identity_review.py
python tools/replay_security_patterns.py
python tools/replay_layered_review.py
python tools/replay_pattern_provenance.py
```

The installed `megalodon-evaluate layered-report` entry point is equivalent.
Commit/tree fields are caller declarations; a dirty checkout or arbitrary SHA
is not an attestation. The report also hashes eight relevant installed source
files and both corpus files so a baseline plus evaluation-harness overlay is
visible. Those hashes identify on-disk bytes, not interpreter integrity or the
complete transitive execution environment.

Two to ten repeats are accepted. Each repeat also runs a seeded permutation.
Separate-process tests vary Python's hash seed. Candidate-list order is normalized
for comparison, while IDs, measurements, reference-page order, dependencies and
coverage remain sensitive to changes. `deterministic_sha256` excludes `cost`;
wall time, process CPU time and a separate Python-allocation tracing pass are
observations, never deterministic assertions. No timing threshold gates CI.

Exit 0 / `all_match: true` means the corpus's evidence and stability checks pass.
It does **not** mean all useful cases were detected or all ordinary cases avoided
review. Exit 1 preserves a completed report with a regression; exit 2 rejects
invalid arguments or fixture integrity. No arbitrary input path is accepted.

## Labels and denominators

[Cases](../megalodon/reference/layered-v1/cases.json) describe synthetic flow
metadata. The separately hashed [label manifest](../megalodon/reference/layered-v1/labels.json)
records scenario intent and a rationale. Labels do not enter the analyzer;
changing labels changes scores, not predictions. They are assistant-authored
scenario labels, **not independent human adjudication**. Independent here means
separate from detector output, not an independent author or blinded test team.

The support oracle also stays outside the detector. It checks reference resolution,
rule support, source/interface/address/hour scope, reference counts, segment
sets and layered unions. Its mutation tests deliberately substitute unrelated
or missing references, dependency segments and action states. Passing proves
agreement with this synthetic oracle; it cannot authenticate a producer.

| Coverage | Examples |
| --- | --- |
| Authorized activity | Discovery, scheduled health checks, scheduled DNS, ordinary background traffic |
| Useful synthetic sequences | Unauthorized discovery plus callbacks, unusual port-53 activity plus discovery/callbacks, a callback without a second family |
| Timing limitations | Jittered callbacks; a burst split by a bin boundary; the matching no-anchor control |
| Identity ambiguity | Same-hour address reuse; different-interface control; overlapping declared sensors |
| Provenance | Simultaneous starts; late fanout after unrelated noise; 30 supporting records beyond the 24-reference page |
| Incomplete evidence | Missing interface/start, conflicting flow identity, declared source loss, empty hour |
| Currentness | Old connection starts with current periodic updates |

The unit is **one case-hour**, not a packet, person, attack, host-day or independent
sample from deployed traffic. TP/FP/FN/TN compare the presence of at least one
layered candidate against useful/ordinary labels; the five indeterminate cases
are excluded, even if they produce candidates. Counts of all individual and
layered candidates, including excluded cases, are reported separately.
A false alert here means investigation workload in an ordinary case. A missed
case means no layered candidate in a useful case; an individual finding may
still exist. The 796 checked reference occurrences include references repeated
across individual and combined reviews; they are not 796 independent samples.

## Measured synthetic results and bounded fixes

Baseline: `main@c86ca0d4e4421233f3c7fc2cc15ed0b1bbf3a285`, after PRs #709–#711.
The new evaluation harness was overlaid on that baseline without changing its
analyzer/correlator. Replaying the same corpus against the repaired analyzer gives:

| Measurement | Baseline | Repaired |
| --- | ---: | ---: |
| Individual candidates | 38 | 38 |
| Layered candidates, including indeterminate cases | 12 | 12 |
| Useful cases with / without layered review | 7 / 3 | 7 / 3 |
| Ordinary cases with / without layered review | 4 / 6 | 4 / 6 |
| Cases with permutation-sensitive evidence | 18 | 0 |
| Incorrect dependency sets | 9 | 0 |
| Checked reference occurrences | 796 | 796 |

The analyzer now sorts the already bounded timing batch by observation time,
segment and record number before selecting representatives. Fanout dependencies
now contain only the sixteen qualifying destination representatives' segments.
The sort is bounded by the existing 2,048-record group limit; it does not reorder
or expand admission before truncation, change thresholds, rewrite stored reviews,
or promise order independence when a work limit truncates the input.

Unrelated dependencies could cause a valid fanout review to disappear when an
unrelated segment retired. The existing storage validity check requires every
listed segment to remain retained. Removing unrelated dependencies preserves
that check; retiring an actual support segment still invalidates the review.
The retained segment/record reference format, source separation, source-start
retention boundary, 24-reference individual page, 48-reference combined page,
64-candidate hourly priority and 24-hour fingerprint cooldown remain unchanged.

These repairs improve provenance and deterministic reporting. **They do not
improve the confusion counts.** In particular:

- Identical authorized/suspicious metadata remains indistinguishable. Intent,
  approved schedules and independently supported identity are absent.
- One family alone cannot create a layered review, even if investigation is useful.
- The fixed cadence spread tolerance misses the stipulated jittered callback.
- Port-53 burst bins remain anchored to the first observation: adding unrelated
  early traffic can split a qualifying burst. A future sliding-window change
  needs its own workload/cooldown and evidence tests, rather than silent tuning.
- Same-hour address reuse joins unrelated machines. Overlapping sensors do not
  establish independence. Neither should be 'fixed' by inferring identity.
- Five cases remain indeterminate because incomplete observation is not a clean
  negative. Work limits and missing start times can suppress timing analysis.

A local Linux x86-64 / Python 3.12.3 exploratory run of these small cases measured
roughly 0.6 ms median per analyzer-plus-correlator call, about 1.2 ms maximum and
about 61 KiB peak traced Python allocations. These are illustrative local samples,
not throughput, RSS, installed-PC or comparative performance acceptance. Each
CI artifact contains its own exact environment and cost samples.

## Evidence qualification after PR #713

Comparison base: PR #713's merge, `e4738da7ef16aa53fcc4686e6819e45c332dd054`,
tree `17673411a48f4b02bb3baf93ad6c4e13f5102e96`. The corpus, labels,
detector rules and correlation selection are unchanged. The additional
[qualification](layered-activity-review.md#evidence-qualification) reports
reference-page overlap, full support extents and unavailable authorization
context without filtering findings or assigning a likelihood/priority score.
The evaluator checks qualification against fixture observations independently
of the correlator's timing facts and includes it in repeated/permuted digests.

| Ordinary case producing a review | Reliable metadata available now | Independent context still needed |
| --- | --- | --- |
| `authorized_discovery_and_schedule` | Disjoint reference pages; support extents separated by 285 seconds. Input is byte-identical to `suspicious_sweep_and_callback`. | A time/scope-qualified inventory and scheduled-job authorization record. The label's rationale is withheld from the analyzer. |
| `scheduled_dns_connections` | Both signals cite the same 20 retained observations. Input is byte-identical to `suspicious_dns_and_callback`. | Approved resolver/job context; port 53 and regular timing cannot establish intent or application identity. |
| `address_reuse_same_hour` | Support extents are separated by 2,985 seconds. This is a temporal gap, not proof of two machines. | Time-qualified address ownership and authorized-task records for both intervals. |
| `overlapping_sensor_observations` | The selected pair reuses 20 references; extra sensor labels do not authenticate separate vantage points. | Producer/vantage identity and overlap context. Distinct references from two sensors can still describe the same traffic. |

All four remain reviews. The available metadata can distinguish evidence
relationships, but cannot resolve any of these four into a defensible safe or
malicious verdict. In particular, suppressing the two byte-identical ordinary
cases also suppresses their useful counterparts. A temporal cutoff would be an
unvalidated heuristic: separated support can still belong to one useful sequence.
No new collection, authorization-file importer or suppression mechanism is added.

| Measurement, unchanged 25-case corpus | PR #713 | Qualified |
| --- | ---: | ---: |
| Individual candidates | 38 | 38 |
| All layered candidates | 12 | 12 |
| Useful cases with / without layered review | 7 / 3 | 7 / 3 |
| Ordinary cases with / without layered review | 4 / 6 | 4 / 6 |
| Indeterminate cases excluded from confusion counts | 5 | 5 |
| Evidence errors / permutation-sensitive cases | 0 / 0 | 0 / 0 |
| Checked reference occurrences | 796 | 796 |

Four of twelve reviews now disclose shared selected references (two ordinary,
two useful). Eight disclose separated support extents (two ordinary, five useful,
one indeterminate). Every review reports unavailable authorization context.
These categories describe evidence, not precision improvements. Operational
accuracy and false-positive rate remain null. All individual candidate objects
and combined reference/dependency unions are preserved.

A local Linux x86-64 / Python 3.12.3 comparison alternated five fresh processes
per revision, reversing order each round, with five repeats of all 25 cases per
process: 625 timed analyzer/correlator calls per revision. The median of process
wall medians was 0.589 ms at #713 and 0.597 ms qualified (about +1.3%); CPU
medians were 0.589 and 0.596 ms. Maximum wall observations were 1.195 and 1.498 ms;
maximum separately traced Python allocations were 61,302 and 61,102 bytes.
These small shared-runtime samples include scheduling noise and are not a
throughput, memory-improvement or performance acceptance claim. Costs exclude
fixture/oracle work, disk I/O and installed-service admission. CI retains its
own candidate measurements; there is no timing threshold.

Local focused checks and the bounded Findings projection pass. The wider
managed-storage/Findings suite is environment-blocked: the same 38 fixture setup
errors reproduce on #713 (untrusted `/tmp` ancestry or read-only home). Guards
were preserved. Native candidate CI must establish persistence/restoration
acceptance; synthetic projection checks cannot substitute for it.

## Integration and remaining boundary

Ordinary source and extracted-sdist pytest suites include this evaluation. The
existing CI test job runs all three older replays and retains a five-repeat
benchmark JSON. Wheel and sdist installed commands run outside their checkouts;
their deterministic JSON must match, and both reports are retained as artifacts.
No new dependency, separate evaluation service or model binding is introduced.

The evaluation stops before persistence and admission cooldown. It does not
exercise packet detectors, learned-baseline change rules, disk I/O, restart,
retention load or the eight-second service deadline. Existing managed-evidence
and Findings integration tests cover persistence/restoration separately. Their
native CI results must be read at the candidate head; a restricted local storage
fixture failure must never be bypassed or described as acceptance.

Related rationale: [issue #259](https://github.com/bartytime4life/MEGALODON/issues/259)
requires corpus, label, denominator, quality and revision context; [issue #258](https://github.com/bartytime4life/MEGALODON/issues/258)
separates source correlation from identity/independence; [issue #3](https://github.com/bartytime4life/MEGALODON/issues/3)
preserves advisory AI review and owner-directed GitHub advancement. Read the
[layered contract](layered-activity-review.md), [timing provenance](pattern-evidence-provenance.md)
and [storage layout](storage-layout.md) alongside this report.

## What authorized operational evaluation would need

This is a proposed acceptance design, not collection authorization. Before any
operational work, the owner must explicitly select the machines, interfaces,
existing metadata sources, collection/import scope, retention and reviewers.
Stage 0 remains offline, with no model activation or host/firewall action.

1. **Representative complete windows.** Start with consenting Linux PCs across
   routine work, idle time, software updates, backups, scheduled jobs and approved
   discovery. Include VPN/interface transitions, DHCP reuse, overlapping sensors,
   outages and restart/rotation. Record observed host-hours and source coverage;
   a planning target such as two weeks is not a statistically sufficient sample
   by itself. Sample unflagged windows as well as flagged ones.
2. **Minimal retained evidence.** Preserve producer/version/configuration identity,
   clock provenance, interface/vantage, flow start and update times, immutable
   segment/record references, loss/gap counters, import receipts and relevant
   authorized change/schedule context. Exclude payloads, credentials and unnecessary
   personal data. Keep real observations out of public repository fixtures.
3. **Independent adjudication.** Reviewers label usefulness from approved task
   records and supporting context before seeing MEGALODON's prediction. Use two
   reviewers where feasible, record disagreements and adjudication, and keep
   unknown/incomplete windows separate. Address-to-device evidence must cover
   the actual time interval; an address alone is insufficient.
4. **Separate challenge data.** Use separately authorized, isolated experiments
   or existing consented/redistributable traces with verified labels for detection
   sensitivity. Never run suspicious sequences on production machines to populate
   this corpus. Keep synthetic challenges separate from ordinary host-hour rates.
5. **Freeze and hold out.** Pin the build, corpus, source quality and label manifest.
   Reserve machines and later time windows for held-out testing before tuning.
   Treat related windows from one device/job as clustered, not independent trials.
6. **Measure operator burden and loss.** Report ordinary-case false-review fraction,
   false reviews per observed host-day, useful-review yield, missed useful windows,
   abstention/coverage gaps, duplicate reviews, review time and time to useful
   evidence. Include pre-admission candidates and post-cooldown displayed reviews,
   with separate denominators and uncertainty intervals. Track reference resolution,
   retention/restart correctness, CPU, wall time, memory and dropped work under
   realistic load. Never fill absent labels or observation time with zeroes.
7. **Acceptance decision.** Agree workload and usefulness targets with the owner
   before the holdout run. Publish limitations, negative results and confidence
   intervals, then obtain human operational acceptance. Synthetic success, merged
   code and advisory AI review cannot grant deployment or response authority.
