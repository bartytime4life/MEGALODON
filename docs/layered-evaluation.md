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

## Five-connection execution and scope experiment

From the repository root, run `python3 -B -m megalodon.evaluation cadence-scope`
(or the installed `megalodon-evaluate cadence-scope`). This separate Stage 0
replay needs Python 3.11+ and accepts no arguments or external records.

The scheduled health-check and suspicious cadence-only fixtures supply identical
five-connection inputs to the existing detector. Each produces one unreviewed
`REGULAR_INTERVAL` finding and zero layered reviews. The replay preserves the
full original finding and shows the same 13 alternative evidence conditions on
each case. Scenario IDs select the pair. Labels, rationales and expected results
are excluded from the comparison that decides scope.

| Result | Evidence required | Operator interpretation |
| --- | --- | --- |
| `scope_match` | All five connection starts have one matching socket witness apiece for the same execution. One time-valid job record explicitly permits the observed address, port and protocol. | A match describes only those connections and the declared scope. |
| `scope_mismatch` | The execution and time still match, but a witnessed destination differs from the sole permitted endpoint. The report lists the affected starts and the permitted destination. | Inspect the conflicting facts before drawing conclusions about intent. |
| `unknown` | Ownership or authorization is missing, partial, contradictory, self-reported, expired, or bound to a different execution. | Obtain a separate socket observation at each start and one authoritative job scope covering that host, boot, invocation and interval. |

The synthetic socket witness joins on vantage, interface, local address/port,
remote address/port/protocol and exact connection-start time. The two fixtures
share a clock by construction. The job interval includes its start and excludes
its end. A present-day process snapshot or PID alone cannot bind older traffic.
Producer identities, clock agreement and exclusive policy scope are stipulated
for this experiment. They have no authentication or retroactive authority on a
real host.

Exit 0 means both twins agree and every fixture outcome meets its expectation.
Exit 1 reports a replay discrepancy. Exit 2 rejects invalid arguments, corpus
integrity failures or an unexpected baseline shape. No runtime collector, policy
importer, dashboard action, suppression or model execution participates. The
original 25-case workload measures are separate; this experiment supplies no
operational accuracy estimate.

### Checking sender identity on Linux

From a clean source checkout, as an ordinary Linux user, run:

```bash
python3 -I -B tools/replay_linux_sender_identity.py
```

This separate lab tests one assumption behind the synthetic scope comparison.
A parent creates five unnamed Unix sequenced-packet socket pairs. Two disposable
children of the same account inherit the same five sending endpoints and send
the same fixed job label. The parent registers the first child, holds both
identities during observation, and classifies each message from its Linux
`SCM_CREDENTIALS` record. The channel and the label are identical for both
children. Only the credential distinguishes them. A connection-time peer credential would
describe the socket-pair creator. Per-message credentials describe the sender.
See [Linux unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html).

The second child supplies its own PID with `sendmsg` as a positive control,
then attempts the identical operation using the registered child's PID. Passing
requires five registered-sender and five other-sender observations, one of each
on every channel, explicit `EPERM` on the other-PID attempt, and no extra record.
Output contains only fixed statuses and counts. No process or user IDs are
retained. The probe creates no IP sockets, public listener or background service.

Exit 0 means the bounded native experiment passed. Exit 1 means observed
behavior disagreed with the expected result. Exit 2 means the platform,
account, kernel permissions or available evidence were insufficient. In
particular, a sandbox that prohibits credential delivery cannot supply a pass.
The existing Linux CI test job runs the native command and requires exit 0.

This establishes the sender of a local message under these test conditions.
The children's identities are known because the harness started them. Executable
integrity, the truth of an observer's report, job authorization and ownership
of historical TCP flows remain unverified. No local message enters the
production evidence store or changes a finding.

### Does the identified job have permission on this channel?

Run the bounded job grant experiment from the repository root on Linux:

```bash
python3 -I -B tools/replay_linux_sender_identity.py --job-scope
```

Before either child starts, the parent grants the first invocation permission
to submit the fixed fixture record on channels 1, 2, 4 and 5 for the duration
of the eight-second lab budget. The grant lives only in the parent’s policy
comparison and refers to its child-process object and receiver objects. A PID,
descriptor number or job label supplied in a message cannot transfer it to
another invocation. The second child has the same account, endpoints and
message bytes, but receives no grant.

The parent checks permission **at receipt**, using its own monotonic clock. It
revokes the grant before reading channel 4. Messages there can already be queued.
The experiment makes no claim about permission at the time of transmission.

| Receiving channel | Registered sender | Second sender |
| --- | --- | --- |
| 1 and 2 | Within the active scope | No matching grant |
| 3 | Outside the permitted channel set | No matching grant |
| 4 and 5 | Grant revoked before receipt | No matching grant |

The receiver compares all ten decisions against the expected sender and channel.
A pass requires the original kernel-identity checks plus two simulated permits,
eight simulated denials and zero unsupported permits. Unknown credentials grant
nothing. An incomplete native run yields no positive job result. Only this one
fixed option is accepted; no external policies, identifiers or requests are
parsed. Running without the option still gives the original sender-only report.

This is a supervisor-issued **fixture** grant. No request is forwarded or executed,
and no production job, TCP connection, firewall decision or model is involved.

### Which process holds a TCP socket at observation time?

From the repository root on Linux, run this as your ordinary user:

```bash
python3 -I -B tools/replay_linux_tcp_holder.py
```

The supervisor binds a listener and a client to ephemeral ports on IPv4
loopback. A child connects the client. The observer closes its client copy and
keeps the accepted peer. No application bytes are sent over TCP. Separate
local control messages hold the child at three checkpoints. The observer only
examines two designated descriptor slots in that child.

| Checkpoint | Original slot | Spare slot | Independent control |
| --- | --- | --- | --- |
| Open | Observed holder | Unknown | The established client matches the fixture's initial socket inode. |
| Moved | Unknown | Observed holder | The same TCP socket stays established. The original slot now holds an unrelated Unix socket. |
| Closed | Unknown | Unknown | The child stays alive after closing the last client descriptor. |

Each observation reads both `/proc/<child>/fd` links before and after an exact
`SOCK_DIAG_BY_FAMILY` kernel query. The request names the loopback address and
port at both ends and requests no table dump. Only a stable link matching the
established socket inode qualifies. The first reply supplies the kernel socket
cookie for subsequent queries. The TCP fixture's initial inode is an additional
test check; it cannot supply a missing observation. See [Linux socket
diagnostics](https://man7.org/linux/man-pages/man7/sock_diag.7.html) and
[descriptor links](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html).

The JSON reports the checkpoint results and whether descriptor reuse occurred.
It omits PIDs, addresses, ports, inodes and cookies. Exit 0 means all checkpoints
and controls passed. Exit 1 signals an unexpected observed result. Exit 2 means
the platform, privileges, diagnostic evidence or synchronization was insufficient.
This test accepts no target arguments and never enumerates other processes or
connections. The production HUD continues to exclude loopback traffic.

`observed_holder` means the named descriptor held that socket during the
controlled observation. `unknown` means these reads cannot establish the link.
Neither outcome identifies who opened a historical flow, grants job permission
or classifies malware.

### End-to-end Linux cadence case

From the root of a clean source checkout, run as an ordinary Linux user:

```bash
python3 -I -B tools/replay_linux_cadence_case.py
```

This prints one read-only JSON case report. A supervised child opens five TCP
connections to one disposable IPv4 loopback listener at scheduled three-second
intervals. The parent timestamps each actual accept with its monotonic clock
and maps elapsed time to a single UTC anchor. These are first-observation times.
The test does not timestamp SYN packets. The existing retained-hour analyzer
runs in memory on the five observed tuples and timestamps using a one-hour
evaluation window beginning at the first observation rounded down to a second.
If scheduling jitter prevents its unchanged rule from firing, the command
returns inconclusive. It never substitutes scheduled timestamps or retries
until the detector produces a finding.

Start with `finding`: its ID, five evidence references, unreviewed state and
action status come directly from the detector. Each context explains the same
references. The exclusive grants were issued as alternatives before launch;
both name the same child invocation and finite interval. TCP tuple comparisons
use the observed addresses and ports. The report calls the real listener
`fixture-listener` and the distinct bound, unused endpoint `reserved-alternate`.
The child sends no application bytes over TCP.

| Case | What the operator should see |
| --- | --- |
| Matching grant | All five references have bracketed live socket-holder observations for the registered child at the permitted destination. |
| Conflicting destination | All five references show the observed listener and a different permitted endpoint. |
| Delayed fifth lookup | The first four retain their live observations. A fresh fifth kernel lookup runs after the child acknowledges close. The report names that unresolved reference and returns `unknown`. |

For live ownership the supervisor uses the pinned child descriptor directory
and an exact TCP diagnostic query per flow. It checks stable descriptor links
on both sides of the query and verifies the fixture inode. The grant must cover
the accepted connection through the witness observation, before the parent
releases that socket for closure. The delayed lookup does not borrow the
earlier positive witness. A pass also requires the last slot to have cleared.
The report omits PIDs, raw endpoints, inodes and socket cookies. Finding IDs,
per-run references and measured timing can differ between runs.

Exit 0 means the original finding and all three evidence outcomes passed.
Exit 1 means a completed case disagreed with the expected outcome. Exit 2
means the kernel, timing or available evidence could not produce the case.
These are fixture grants and contemporaneous holder observations. The case
does not establish ownership of an earlier unobserved connection, legitimate
intent or malware. It neither persists records nor controls a host.

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
