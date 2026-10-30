# Timing-review evidence

Completed-hour `REGULAR_INTERVAL` and `PORT_53_BURST` reviews now cite the
observations that support their own measurements. A late-hour signal no longer
inherits the first 24 records for the address, which may concern unrelated ports
or destinations. These evidence links carry through the existing SQLite history,
Findings projection and optional admitted local explanation path.

The change is based on `main@3ac8c26dae990fbbc5d7ae237cc3b3327448ae15`.
Synthetic regression checks at that base reproduced unrelated evidence links
and reviews of old connection starts whose periodic updates arrived this hour.
Those checks establish reproducible behavior, not exploitation or operational
false-positive rates.

## Measurement and reference boundaries

| Review | Measured observations | Linked support |
| --- | --- | --- |
| `REGULAR_INTERVAL` | At least five distinct connection-start times for one source, destination, transport and destination port; existing median/spread thresholds | One representative per distinct time, in time order |
| `PORT_53_BURST` | At least 20 transport-qualified port-53 observations in an existing 60-second bin | Every contributing observation, subject to the reference-page cap |
| `HOST_FANOUT` | Existing connection-start sweep | Existing 16 distinct-destination representatives |

All retained timing checks use only observations in `[hour start, hour end)`.
Flows use `first_seen`; packets use their observation time. A flow update's
arrival time cannot move an old connection start into the current hour.
Existing conflicting-identity exclusion, periodic-update deduplication and
source/interface/measurement separation still apply. Packet cadence does not
become a connection-cadence review.

Cadence and burst facts now include absolute `first_seen` and `last_seen`.
Burst facts replace an ambiguous relative minute with absolute `window_start`
and `window_end`. Bins remain anchored to the earliest in-hour observation in
the source group; this change does not implement a sliding burst detector.
These are bounded measurements of the supplied metadata, not claims of complete
traffic visibility, confirmed DNS queries, malware or successful connections.

The existing candidate reference page remains limited to 24 entries. Facts
report `references_omitted`, and a coverage note discloses any omission. Segment
dependencies cover the full supporting set, including support beyond that page;
unrelated early segments no longer become cadence/burst dependencies. Existing
hourly retention and retirement rules remain in force. The Findings UI may show
a smaller reference preview than the stored page.

An internal opt-in on the pure offline analysis function carries record numbers
to the retained-hour adapter. That path refuses over 20,000 records; the retained
adapter's existing per-group limit is 2,048. Default offline report shapes and
their strict reader remain unchanged. No database migration, new data input,
model call, detector threshold, response permission or host operation is added.

## Safe reproduction

From the reviewed MEGALODON checkout with its existing Python test environment:

```bash
python -m compileall -q megalodon tests tools/replay_pattern_provenance.py
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_PLUGINS= PYTEST_ADDOPTS= \
  python -m pytest -ra tests/test_pattern_provenance.py tests/test_host_fanout.py \
  tests/test_flow_identity_review.py tests/test_layered_review.py tests/test_security_patterns.py
python tools/replay_pattern_provenance.py
```

The replay uses six synthetic cases without external data, sensors, persistence,
model inference or host actions. Persistence tests require a Linux environment
that satisfies the repository's private-storage ancestry checks. Those checks
must not be bypassed to make a restricted workspace pass.

Existing saved reviews are not rewritten. The corrected logic applies when an
hour is newly processed; existing checkpoint and cooldown behavior still apply.
Operational usefulness and representative authorized replay remain unproven.
