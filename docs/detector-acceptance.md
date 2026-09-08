# Fixed-detector synthetic acceptance receipt

Status: bounded test/evidence slice of [issue #26](https://github.com/bartytime4life/MEGALODON/issues/26).
No detector, threshold, configuration, response policy or runtime reporting
feature changes. This confirms specified rule behavior, not malware accuracy,
prevention effectiveness, representative false-positive rates or approval.

## Detector-only source and fixture identity

Inspection base: `a177c13ade3b4a727a0514afac21575fd0f10e08`.
The exact tested detector blob is `452906e830c509bc428ea7603308dee4f892a50a`;
configuration implementation blob `663eb9f5d25ab71cbae1d492595d6ea32629bc7b`;
shipped TOML blob `4ab57c7ea25fe57d3ac89a9259a074460df1e5e4`.
The test reads the shipped TOML and checks parity with the evaluated defaults,
including disabled blocking and sample input. Future receipts must re-pin code,
configuration and the test file, not carry these hashes forward as current.

Fixture version: `detector-acceptance-v1`, defined by the named `BOUNDARIES`
cases in [tests/test_detector_acceptance.py](../tests/test_detector_acceptance.py).
Each case starts with a new detector and one documentation-only source address.
Events are constructed as typed metadata, never captured packets or payloads.
SYN and port cases use millisecond-spaced observations; DNS cases use one event.
No real addresses, query names, packet bytes, payload hashes or datasets are
required. Changed-file hashes and execution environments belong in the PR receipt.

## Boundary receipt

The six below/at/above SYN and port cases plus three DNS cases matched the
following independent expectations on the inspected implementation:

| Fixture IDs | Input quantity below / at / above | Input events | Emitted detections below / at / above |
| --- | --- | --- | --- |
| syn-below / syn-at / syn-above | 99 / 100 / 101 SYN-without-ACK events | 99 / 100 / 101 | 0 / 1 / 1 |
| ports-below / ports-at / ports-above | 19 / 20 / 21 distinct TCP destination ports | 19 / 20 / 21 | 0 / 1 / 1 |
| dns-below / dns-at / dns-above | DNS query metadata lengths 49 / 50 / 51 | 1 / 1 / 1 | 0 / 1 / 1 |

These are nine independent synthetic source/rule scenarios, 363 input metadata
events and six emitted detections. Input events, scenario counts and emitted
alerts are different denominators. They are not unique packets, network flows,
external sensor alerts or an estimate of real-world malicious/benign prevalence.
Above-threshold cases still emit once because the 30-second cooldown applies.
Numeric evidence, rule IDs and ALERT recommendations are asserted as well.

Legitimate load testing can match the SYN cases; legitimate multi-port
administration can match the port cases; legitimate long-query metadata can
match the DNS cases. These are benign-lookalike interpretations of synthetic
inputs, not independently labeled representative traffic. A rule firing cannot
distinguish those explanations from malicious activity. No confusion matrix or
production false-positive percentage is claimed.

## Further confirmed boundaries and limits

The 39 tests cover inclusive time-window cutoffs, exact cooldown reopening,
explicit-offset normalization, multi-source independence, expired-window reset,
repeated events versus distinct ports, protocol/flag eligibility, LRU cooldown
reset, finite event caps and shipped-configuration parity. The evaluation
patches process-launch and socket entry points to fail on invocation; it calls
the detector, not a firewall or service action adapter. No evaluation outcome
is execution authority. Existing service action-state tests remain separate.

Repeated SYN metadata is counted again: this detector does not deduplicate
packets. Evicting a source discards its cooldown history. A configured event
cap below the threshold can prevent that threshold ever being reached. These
are interpretation limits, not evidence that an attack stopped or was blocked.

UNASSESSED: reordered timestamps. Deque trimming assumes chronological input;
this test-only slice does not establish correct out-of-order window semantics,
reject or sort reordered input, or change cooldown policy. Finite synthetic
service-to-ledger coverage is recorded below; representative privacy-reviewed
evaluation remains separate. No completed #26 closure is claimed.

## Reproduction and discriminating controls

From the repository root in the supported test environment:

```bash
python -m compileall -q megalodon tests
python -m pytest tests/test_detector.py tests/test_detector_acceptance.py
```

Before adding the configuration-parity case, all 38 detector cases passed.
Five isolated local changes to the source were then detected: making the SYN,
port or DNS threshold exclusive caused 10, 9 or 6 failures respectively;
excluding the exact time-window cutoff caused 2 failures; keeping the exact
cooldown boundary closed caused 3 failures. Each mutation was restored, never
committed. The final 39-case suite passes against the original detector.
These are negative-control experiments, not failures in the delivered source.

Local reproduction used identity-verified partial source files and pytest 9,
outside the repository's unchanged pytest constraint. Full supported-environment
CI, exact-head independent review and representative operational interpretation
must be recorded separately. Preserve the required Linux test gate. No capture,
analyzer installation, scheduler, telemetry sharing or firewall apply is added.

## Service-to-ledger receipt: service-acceptance-v1

Inspection base: `16dc49b82aff43a29480f858b80ba4b703128f21`, after #34/#35.
The detector-only inspection and execution receipts above retain their original
scope. This extension adds [tests/test_service_acceptance.py](../tests/test_service_acceptance.py)
without changing runtime code, thresholds, configuration, dependencies or CI.
Tested service blob: `4a9665117c0f3ed8b388e1e9eac74bce5e637ced`;
firewall blob: `8f40f8783af9b937c8ffbf5c495a5c47b2dcd8c3`;
storage blob: `d15a7122a6877fa6ada720e9f006a1fb0a81a635`.
The PR receipt separately pins the delivered test/documentation head and checks.

The 48 policy scenarios cross three fixed rules, IPv4/IPv6 and eight named
policy configurations. Each starts a fresh service and temporary SQLite store.
Real typed events, detector, service, target validation, planner and audit writes
are used. A spy observes planner calls without replacing its return values.
After closing the store, a separate read-only connection checks exact detection
and action rows, numeric evidence, event linkage, reasons and expiry.
Every scenario adds one repeated event inside cooldown: it is stored as an
input event, but adds no second detection, plan or action row.

| Named policy fixtures | Scenarios | Expected and observed action status | Real planner calls per scenario |
| --- | --- | --- | --- |
| observe / disabled-auto / enabled-no-auto | 18 | not_attempted | 0 |
| plan / direct-live-flags | 12 | planned | 1 |
| allowlisted / allowlisted-non-global | 12 | suppressed | 0 |
| non-global | 6 | failed | 1 (refused validation) |

Those scenarios contain 1,984 input metadata events, 48 detections and 48
persisted action rows. The fixture counts are not packet, flow or external-alert
counts, and are not a production accuracy measure. `failed` here means a refused
plan for a non-global source, not an attempted live block. Allowlisting takes
precedence even for non-global sources. `direct-live-flags` bypasses TOML via
programmatic settings only to prove the service still cannot apply; it does not
make that configuration supported or recommend enabling it.

Three further below-threshold cases produce no detection, action or plan. Three
minimum-severity cases retain all detections but plan only the CRITICAL DNS
case under the default minimum. Three synthetic SQLite stage failures propagate
without a normal service return or successful action receipt. Their surviving
(event, detection, action) row counts are (0,0,0), (1,0,0), and (1,1,0).
These 57 cases distinguish stage-local rollback from whole-service atomicity:
earlier committed stages can remain, and detector state is not rolled back.
They do not prove disk-full, ACL, interruption or power-loss recovery; see
[the storage failure policy](storage-failure-policy.md).

Event time and audit time are distinct fixed UTC clocks. Every plan must contain
the exact IPv4/IPv6 set argv, a 900-second timeout and matching finite expiry in
both the action row and details JSON. No configuration values are changed.
Global address literals are generated synthetic metadata, not observed hosts,
contacted endpoints or threat claims. No query names, captures, payloads,
payload-derived hashes or real telemetry are used. Test guards fail on block,
install, apply-requirement, executor, executable probe, process or socket calls.
This guards the exercised Python entry points; it is not an OS containment proof.

From the repository root in the supported test environment:

```bash
python -m compileall -q megalodon tests
python -m pytest tests/test_service.py tests/test_service_acceptance.py
```

Local focused execution passed 60 cases (57 new, three existing). Five isolated
negative controls were detected: invoking block instead of plan caused 20
failures; skipping allowlist suppression 12; ignoring enabled policy 6; recording
applied for a plan 13; omitting the detection audit 53. The block-entry guard
stopped the first mutation before any operation. All experiments used disposable
copies; no weakened source was committed. No new runtime defect is claimed.
Local evidence used identity-checked partial sources, Python 3.13.5, SQLite
3.46.1 and pytest 9.0.2 with plugin autoload disabled; pytest 9 is outside the
unchanged supported constraint. Full supported-environment hosted results belong
in the exact-head PR receipt, not in an inferred pass here.

Remaining gates: designated human review, GitHub approval/control handling under
#3, reordered-time semantics and representative provenance/privacy-reviewed
interpretation. These tests neither close #26 nor authorize apply, scheduling,
external data sharing, host changes or deployment.
