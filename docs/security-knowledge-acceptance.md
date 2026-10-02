# Local knowledge and patterns: acceptance record

Date: 2026-10-01 America/Chicago (2026-10-02 UTC).

This record describes a bounded local implementation, not universal attack
detection or a high-volume server certification. Public references are context;
model proposals have no authority to run commands or change network access.

## Reference data

- Offline starter: 202 selected documents with licenses and source digests.
- Live fixed-source update: 6,306 validated records, 19,771,882 bytes including
  indexes and compressed inputs in the isolated acceptance store. First update
  18.09 seconds; unchanged check 7.45 seconds retained the same generation.
- Installed HUD also successfully updated to 6,306 records. The starter remains
  the previous generation for rollback. No peer telemetry accompanies requests.
- Corruption, interrupted activation, budget exhaustion, invalid formats, unsafe
  YAML, JSON expansion/encoding bypasses, cancellation and slow-download bounds
  are exercised by focused tests. This is simulated fault testing, not filling
  the user's actual disk.

## Recording comparison

Command: `tools/benchmark_intelligence.py`, with and without `--enabled`.
Both runs use the same 10,000 synthetic metadata records, eight prepared
historical hours and concurrent history/search reads. Private temporary stores
are required. The enabled run processes those hours while recording.

| Measurement | Pattern work off | Pattern work on |
|---|---:|---:|
| Retained records | 10,000 | 10,000 |
| Recording throughput | 25,571 / s | 20,507 / s |
| Recording time | 0.391 s | 0.488 s |
| Query p95 | 10.22 ms | 13.96 ms |
| Peak process RSS | 34,464 KiB | 37,020 KiB |
| OS bytes written | 9,916,416 | 10,784,768 |
| Write system calls | 3,708 | 3,987 |
| Packet batch commits | 40 | 40 |
| Unconfirmed records / write failures | 0 / 0 | 0 / 0 |

Eight-hour catch-up completed in 0.794 seconds. These short replays measure
additional analysis work, not a drive lifetime, packet-capture throughput, or
LLM inference overhead. Query samples were 14 and 26 respectively. OS counters
do not measure physical media wear. The benchmark source SHA-256 was
`dd6286494d1d55130d69c70377ed9e3af0a89ab35e320920c7a1bb80d6a5a829`.

## Ordinary and suspicious scenarios

Reproduce with `tools/replay_security_patterns.py`. Four deliberately selected
ordinary scenarios produced three review candidates: a periodic backup,
scheduled health check and update using a newly observed port. Streaming packet
timing did not become a recurring-connection candidate. Both selected suspicious
connection scenarios produced candidates. Three supplied existing detector
findings (scan, SYN burst and unusual DNS) remained available through the adapter.

Thus **3 of 4 ordinary fixtures also required review**. This is intentional
evidence of ambiguity, not an acceptable production false-positive claim.
The corpus is hand-built and too small to estimate a population rate. The
existing-finding cases test preservation, not detector recall. Every candidate
remained `not_attempted`; none caused a host action.

## Regression and security review

The complete regression run passed before rendered rollout checks (4,419
collected tests, three configured skips, plus subtests). A first attempt had
44 legacy provider checks denied by the shared inference slot; the isolated
retry and full rerun passed without weakening the lock.

Final regression after the live-history and output-contract fixes:
**4,417 passed, three skipped, 204 subtests passed**, in 122.96 seconds.

Focused Codex Security scan:
`7df2ba33-dcfb-40df-ab6a-85e2257c3768`. Six initial candidates were corrected and
independently re-reviewed: public parser expansion, slow downloads, derived
history expiration, repeated-flow cadence, heuristic overload, and seven-day
dependency capacity. The sealed report has no unresolved finding in those
reviewed surfaces. Its prepared snapshot predates the fixes; its follow-up
receipt identifies this distinction. It is not a whole-repository certification.

Live acceptance additionally found repeated coverage messages exceeding a
managed-record size limit. Messages are now deduplicated and bounded, with a
regression test. Oversized baseline distributions are withheld from learning;
their coverage limitation remains visible. No storage bound was relaxed.
An independent supplemental review of these post-scan corrections and the
short-response/citation schema found no authority or retention regression.

## Selected model and rendered checks

The existing selected model, `qwen2.5:7b-instruct-fp16-recovery-20260929`, produced
a validated local response with observation and ATT&CK citations. An installed
HUD manual review also completed with `ready` state and `not_attempted` action
status. Initial failed/busy attempts remained visible, preserved their measured
patterns, and counted against the automatic budget. Manual review remained
available after that budget. Cancellation was exercised through the HUD.

Desktop and 390-pixel mobile views were rendered in the in-app browser. Checked
Setup navigation, compact checkbox rows, update status, local reference search,
Findings review cards, readable details/actions, and keyboard activation.
The mobile document stayed within the viewport; review cards and buttons fit.
No console errors were returned. Temporary viewport overrides were reset.
This is acceptance of the new surfaces, not a new visual audit of every HUD tab.

A new installed local report processed 15,921,335 retained records and rendered
21 pattern reviews with the three plain-language sections. The job completed;
the saved report correctly remains **incomplete** because its historical
coverage has gaps. The four earlier reports remain available.

## Offline packaging

The ATLAS parser uses PyYAML 6.0.3. The test and native installer wheel profiles
include its exact CPython 3.11/3.12 Linux wheel hashes from
[the publisher's PyPI release](https://pypi.org/project/PyYAML/6.0.3/#files).
The build-input inventory and isolated-environment checks include this reader;
CI does not depend on a copy incidentally installed on the runner. The existing
locked installer wheelhouse was checked with hash-required downloads.

## Rollout and practical limits

The updater builds and activates the local package through the existing verified
release mechanism. Settings-file identity, selected model, 14-day / 20-GiB policy,
existing report identifiers, and monitoring are checked before and after.
The verified feature release is `0.1.0-20261002T032411Z-b6737252`; its installed
package content matches the checkout. Settings-file digest and the four
pre-existing report identifiers were preserved, and capture was running.

This PC's retained busy/incomplete hours can be excluded from baseline learning.
A zero eligible-hour count does not mean no traffic and is not a safety verdict.
The HUD displays the reason under Coverage and learning. Qualified future hours
can establish the required 24-sample comparison.

The GPT Site remains retired. Generated reports and telemetry remain local.
