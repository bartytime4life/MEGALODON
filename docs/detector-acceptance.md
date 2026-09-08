# Fixed-detector synthetic acceptance receipt

Status: bounded test/evidence slice of [issue #26](https://github.com/bartytime4life/MEGALODON/issues/26).
No detector, threshold, configuration, response policy or runtime reporting
feature changes. This confirms specified rule behavior, not malware accuracy,
prevention effectiveness, representative false-positive rates or approval.

## Source and fixture identity

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
reject or sort reordered input, or change cooldown policy. Whole-service
not_attempted/suppressed/planned receipts and representative privacy-reviewed
evaluation remain distinct acceptance work. No completed #26 closure is claimed.

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
