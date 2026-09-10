# Offline reference data and synthetic corpus

Status: versioned, offline analysis assets. These resources add bounded context
and repeatable detector checks; they do not add telemetry collection, threat
intelligence fetching, response authority, or a claim of production accuracy.

## Safety and interpretation boundary

The IANA data answers a narrow question: what service name or protocol number
is registered for a value? A registration is an analyst context hint. It is not
evidence that the registered service was observed on a host, that traffic is
safe, that a party had malicious intent, or that a MEGALODON finding is a
security verdict. In particular, a port lookup must never be promoted to
service identification without independent observation.

The synthetic corpus answers a different narrow question: does the current
fixed detector produce the recorded rule counts for deterministic metadata
scenarios? Its expected findings are regression assertions, not ground-truth
malware labels. Evaluation results carry `synthetic-only` and `uncalibrated`
labels because the corpus cannot establish real-world accuracy, prevalence,
coverage, or false-positive and false-negative rates.

Both asset families are local package resources. Loading, lookup, and
evaluation perform no runtime network access or update. The evaluator does not
construct a `Store`, persist rows, plan or apply an action, launch a subprocess,
or call a firewall adapter. Every response explicitly reports no network access
and `not_attempted` action and persistence status.

## Pinned IANA sources

The `iana-v1` bundle is derived from two exact IANA CSV snapshots. Retrieval
times below are UTC connector receipt facts, not filesystem modification times.
The raw bytes and normalized artifacts are SHA-256 pinned. That verifies the
bytes accepted by this repository, but it is not a cryptographic verification
of publisher authenticity.

| Registry | Canonical CSV | Registry date | Retrieved | Raw bytes | Raw SHA-256 | Data rows |
| --- | --- | --- | --- | ---: | --- | ---: |
| Service Name and Transport Protocol Port Number | `https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv` | 2026-09-07 | 2026-09-10T19:10:11.051Z | 1,157,044 | `9777be6d2451ab61ac3c64443b0cfb968bbdeddea3cc5e640eb81f3ec045b7a4` | 14,535 |
| Protocol Numbers | `https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv` | 2026-03-09 | 2026-09-10T19:13:32.727Z | 9,230 | `e704ee14e69347681b3a6271af02195a9741236074fc311449ebb032101bdf2c` | 152 |

The registry data is used under the IANA licensing terms, with bundle license
identifier `CC0-1.0`: <https://www.iana.org/help/licensing-terms>. This scope is
limited to the IANA service-name/port-number and protocol-number registry data.
Linked RFC text and third-party material are excluded.

### Privacy-minimized projection

The normalizer retains only fields needed for offline context:

- Service records retain service name, port or port range, transport,
  description, registration date, and modification date.
- Protocol records retain decimal number or range, keyword, protocol name, and
  the IANA IPv6-extension-header marker.
- Service assignee, contact, reference, service code, unauthorized-use report,
  and assignment notes are omitted. Protocol references are omitted.
- Rows without both a usable port value and one of `tcp`, `udp`, `sctp`, or
  `dccp` are excluded. The pinned input yields 12,577 normalized service
  records and 152 protocol records; 1,958 service-registry rows are excluded.
- Numeric ranges remain ranges. They are not expanded into fabricated
  per-number assignments, and duplicate registered keys are not collapsed.
- `source_row` retains only the one-based source CSV row ordinal as a stable
  provenance pointer and tie-breaker; it does not retain source contact data.
- `record_kind` distinguishes structural `named`, `reserved`, `unassigned`,
  and `unnamed` rows, plus the protocol registry's `experimental` entries. A
  missing keyword alone is not treated as proof that a protocol number is
  unassigned.

The raw CSV files are deliberately not shipped: the service registry source
contains assignee, contact, and free-form fields that this runtime does not
need. Instead, the manifest and maintainer tool pin each raw file's exact byte
length, SHA-256, ordered header, data-row count, retrieval facts, and retained
field allowlist. CI exercises representative ranges, duplicate keys, blank
keywords, experimental values, and raw-digest refusal without republishing the
excluded source fields. A maintainer can perform full byte-for-byte regeneration
only after separately acquiring the exact pinned raw snapshots.

### Integrity and resource limits

Normalized JSON Lines are deterministically split into shards no larger than
76 KiB (77,824 bytes). The manifest declares the complete shard set and pins
the byte length, row count, schema, and SHA-256 digest of each shard. Before a
lookup is answered, the loader verifies the pinned manifest, rejects missing or
unexpected resources, checks every declared shard, enforces aggregate and
per-line limits, and validates every record against its closed schema. A
failure anywhere invalidates the whole bundle; lookup never falls back to a
partially loaded dataset.

This snapshot has 73 service-port shards and one protocol-number shard totaling
2,651,866 derived bytes. Its manifest SHA-256 is
`cb3254221886266c2fc6efe7f458c12cd35b97a1e5fc6cb284bf7b4c9972e6ff`.

The loader also rejects duplicate JSON object keys, unsupported numeric forms,
invalid framing or encoding, unknown fields, out-of-range numbers, unexpected
ordering, and totals that disagree with the manifest. These constraints bound
local work and make a changed resource fail closed.

## Read-only commands

Run the evaluator from the repository root. Output is one JSON object and is
safe to redirect to a file if a maintainer wants a local receipt.

```bash
python -m megalodon.evaluation reference verify
python -m megalodon.evaluation reference port tcp 443
python -m megalodon.evaluation reference protocol 6
python -m megalodon.evaluation corpus
python -m megalodon.evaluation corpus --scenario dns-protocol-gates-v1
```

`reference verify` validates the entire IANA bundle. Port and protocol commands
also validate the entire bundle before returning bounded matches. `corpus`
validates every scenario resource before running either all scenarios or the
selected scenario. Resource failures and unknown scenario IDs produce a fixed
JSON error object without echoing data or local paths. Command-line syntax and
type errors exit 2 with a bounded JSON error containing `INVALID_ARGUMENTS` on
stderr before an operation begins.

## Synthetic scenario corpus

`corpus-v1` contains 6,492 `PacketEvent`-shaped metadata records in 12
deterministic scenarios. Timestamps are fixed UTC values beginning
2020-01-01T00:00:00Z; the evaluation clock is fixed separately. IPv4 addresses
come only from the RFC 5737 documentation blocks `192.0.2.0/24`,
`198.51.100.0/24`, and `203.0.113.0/24`. IPv6 addresses come only from the RFC
3849 documentation prefix `2001:db8::/32`.

The events contain typed routing and detector inputs such as addresses, ports,
protocol, TCP flags, byte count, and DNS-query length. They contain no captured
packet bytes, payload, DNS name, real operator telemetry, external alert, or
threat indicator; the free-form metadata object is empty. Scenario files use
the same deterministic, manifest-pinned shard discipline as the IANA bundle.
The corpus occupies 30 shards and 1,670,793 event-data bytes; its manifest
SHA-256 is
`04870e2d602ed4dd8bc4ef36adc61b62f3ed904ba92afea1267620b07c6438be`.

| Scenario | Records | Exact expected findings (DNS / port / SYN) | Intended coverage |
| --- | ---: | ---: | --- |
| `routine-dual-stack-v1` | 480 | 0 / 0 / 0 | IPv4/IPv6 routine-shaped metadata below thresholds |
| `threshold-matrix-v1` | 363 | 2 / 2 / 2 | Below, exact, and above fixed thresholds |
| `cooldown-boundaries-v1` | 243 | 2 / 2 / 2 | Exact 30-second cooldown boundaries |
| `mixed-triage-v1` | 624 | 4 / 3 / 2 | Multiple findings mixed with routine-shaped events |
| `authorized-lookalikes-v1` | 121 | 1 / 1 / 1 | Benign alternative contexts that still meet thresholds |
| `ipv6-parity-v1` | 121 | 1 / 1 / 1 | IPv6 equivalents for all three rules |
| `syn-window-cutoff-v1` | 100 | 0 / 0 / 1 | Inclusive ten-second SYN window cutoff |
| `syn-window-outside-v1` | 100 | 0 / 0 / 0 | Just-outside-window negative control |
| `port-distinct-ipv6-v1` | 20 | 0 / 1 / 0 | Exact distinct-port boundary |
| `port-repeated-ipv6-v1` | 20 | 0 / 0 / 0 | Repeated-port distinctness negative control |
| `dns-protocol-gates-v1` | 4 | 2 / 0 / 0 | DNS length and eligible-protocol gates |
| `source-cap-pressure-v1` | 4,296 | 0 / 0 / 2 | 4,096-source cap, eviction, and cooldown reset |

Finding counts are ordered as `DNS_TUNNELING`, `PORT_SCAN`, and `SYN_FLOOD`.
The authorized-lookalike interpretation is information supplied by the
scenario author; it is not visible to the detector and does not prove that a
similar live event is authorized.

## Maintainer-only regeneration

Regeneration is an explicit repository maintenance operation, never a runtime
update path. Place the two exact pinned CSV files in one local directory using
their canonical filenames, then run:

```bash
python tools/build_reference_assets.py \
  --iana-source-root /path/to/pinned-iana-csvs \
  --output-root megalodon/reference
```

The builder performs no network access. It refuses a raw source whose byte
length, SHA-256 digest, or CSV header differs from the receipt embedded in the
tool, and emits canonical ASCII JSON with stable ordering and deterministic
shards. It builds both bundles in a private staging directory, checks existing
components of the output, staging, and destination paths for symlinks, rejects
unexpected existing entries, and publishes each closed bundle with directory
renames. If the staged-to-target rename raises an in-process exception, including
`KeyboardInterrupt`, the builder attempts to restore the previous target before
propagating the exception. The component checks occur before filesystem changes
and assume a trusted maintenance workspace is not concurrently swapping paths.

This is a bounded maintenance safeguard, not an atomic or crash-safe transaction.
Abrupt process or power loss between renames can leave the target absent and its
previous version at `.iana-v1.previous` or `.corpus-v1.previous`; an interrupted
cleanup can also leave that backup beside a successfully published target. The
IANA and corpus directories are published separately, not as one transaction.
A source refresh therefore requires deliberate review of the destination state,
the new upstream snapshot, field projection, licensing scope, limits, generated
manifests, tests, and interpretation warnings. Updating a digest solely to make a
changed file pass is not a valid refresh.

## Future dataset candidate: CISA KEV

CISA's Known Exploited Vulnerabilities catalog is a useful next candidate for
offline vulnerability context, but it is not included in this bundle and the
current CLI does not query it. The investigated reproducibility candidate is
the `cisagov/kev-data` repository at commit
`f6fafe2585c7cc2a7568d13d08024cf142b37d3a`, catalog version `2026.09.09`:
1,710,800 raw JSON bytes, 1,703 CVE entries, SHA-256
`399e43c1b3652c76df40493e25f36e4133fca04e34a4d920f86049b141b53c93`,
under CC0.

Any later KEV import must preserve these semantic limits:

- Inclusion means the vulnerability is known to have been exploited
  somewhere. It does not prove that the affected product exists locally, that
  the local instance is vulnerable or exposed, or that a local attack occurred.
- A CVE must never be inferred from a port or IANA service-name match.
- `knownRansomwareCampaignUse` value `Unknown` must remain unknown; it must not
  be normalized to `No`.
- The undocumented `forensicTriage` field must be omitted from a maintained
  projection unless CISA publishes a stable contract for it.

Before KEV can become active data, its exact source, license, privacy projection,
closed schema, deterministic shards, limits, and manifests require the same
fail-closed implementation and review as the IANA bundle.
