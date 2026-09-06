# Offline metadata analysis v1

This optional command is an isolated analysis path, not an ingestion change to
`megalodon run`. It produces private local reports. It does **not** write to the
existing SQLite store, change fixed MVP rules, serve HTTP, capture live traffic,
replay packets onto a network, plan/apply a firewall action, or export to a SIEM.
The proposed automation contract is not implemented by this command.

Implementation is not deployment approval. Keep the delivery PR draft and do
not merge until the independent-review control tracked in issue #3 is repaired
and verified, and the exact change has independent review.

## Isolated analyst operations

Analyze only captures/logs that the operator has authority to handle. Use a
separate Linux analyst VM with no network egress, no shared credentials, no
cloud-synchronized input/report directories, and no access to production
management interfaces. Run as a non-root, capability-free account. The command
rejects root and nonzero inherited/permitted/effective/ambient capabilities;
it does not create a VM, network namespace, seccomp policy, or resource cgroup.

Install and security-update the OS and Wireshark in a separate maintenance
phase, then disconnect the analysis environment before loading hostile input.
Verify the installed vendor package and record its exact version in the local
case record. Only `/usr/bin/tshark` is accepted; symlink executables, non-root
ownership, writable group/world permissions, set-ID bits, and file capabilities
are rejected. System-wide native plugins, dissectors, libraries, and preferences
remain trusted dependencies. A private HOME/config directory and `-n` reduce
accidental user-configuration/name-resolution behavior; they are **not an OS
sandbox or proof of zero egress from a compromised analyzer**.

Use encrypted local storage with a finite retention period, per-case quotas,
backups restricted to the same policy, and operator-reviewed deletion. Set
independent VM/cgroup memory, CPU, process, and disk limits. The Python parent
bounds input/output and record counts, but does not cap the native analyzer's
address space. Do not analyze on network filesystems or concurrently edited
captures. Descriptor-relative opens reject symlinks at every path component,
traversal, devices, FIFOs, directories, and multi-link files. Size and inode/time
checks detect ordinary input mutation; this is not an atomic filesystem snapshot
or protection against a malicious kernel/root owner.

Wireshark desktop is a separate, manual deep-inspection surface in the isolated
VM. Capture filters can reduce collection scope; display filters, columns,
coloring rules, Expert Info, and I/O graphs are analyst views, not MEGALODON
rules. Set capture/ring-buffer quotas in the collection tool before collection.
This command neither configures a collector nor imports packet-byte views,
comments, extracted objects, DNS names, TLS names, or HTTP content.

## Run commands

Working directory: the reviewed MEGALODON checkout on the analyst Linux host.
The examples assume `~/Projects/MEGALODON`, an already-created `.venv`, and an
operator-created local input directory. Replace paths and case identifiers with
non-sensitive local values. Do not run with sudo. The output directory must not
exist; its parent must already exist and must not contain symlink components.

```bash
cd "$HOME/Projects/MEGALODON"
. .venv/bin/activate
python -m megalodon.offline --help

python -m megalodon.offline \
  --source tshark \
  --input-root "$HOME/Analysis/case001/input" --input capture.pcap \
  --output "$HOME/Analysis/case001/run001" --case case001 \
  --max-records 10000 --timeout 30
```

For a separately produced Zeek JSON `conn.log`:

```bash
cd "$HOME/Projects/MEGALODON"
. .venv/bin/activate
python -m megalodon.offline \
  --source zeek-json \
  --input-root "$HOME/Analysis/case001/input" --input conn.log \
  --output "$HOME/Analysis/case001/zeek001" --case case001 \
  --zeek-version 8.2.2
```

`8.2.2` is an example, not a supported-version certification: supply the actual
producer's three-part version. It is recorded as **operator-declared,
unverified**. Use `--source zeek-tsv` for classic tab-separated `conn.log`.
One run selects one source; no joining, packet reconstruction, or cross-source
deduplication is performed. Never add packet and flow record counts together.

To compare against a previous local baseline, deliberately copy only that
reviewed `baseline.json` under the input root and add
`--reference-baseline baseline.json`. The previous output directory remains
read-only to the command. Baseline identity is schema/adapter/kind-qualified;
a packet baseline cannot be used for flows, and JSON/TSV adapter identities are
not interchangeable in v1. No ambient baseline is loaded or updated.

## Fixed limits and file boundary

| Boundary | Default and hard ceiling |
| --- | --- |
| One input file | 64 MiB, nonempty regular file, one hard link |
| Accepted input record/frame scan ceiling | 10,000; operator may lower it |
| Analyzer stdout | 8 MiB total, retained only in bounded memory |
| Analyzer stderr | 32 KiB total, counted and discarded |
| Zeek input line | 16 KiB; ASCII JSON/TSV only |
| TShark field row | 1,024 bytes, or a smaller configured line limit |
| Replay subprocess timeout | 30 seconds; operator may lower it |
| Separate version probe | 5 seconds, 8 KiB stdout, 4 KiB stderr |
| Complete report set including manifest | 16 MiB |
| Candidate findings | 256; overflow fails the run |
| Reference baseline | 1 MiB, JSON nesting at most four levels |

The replay and version probe have separate deadlines; 30 seconds is **not**
the entire command's end-to-end deadline. File reads, report writes, and bounded
post-processing are not protected against uninterruptible kernel I/O. A Zeek
read deadline is checked between bounded line reads. Process groups are killed
and the direct child reaped on completion or failure. Host process supervision
remains necessary for kernel-level hangs and power-loss recovery.

TShark reads an already-open file descriptor through `/proc/self/fd/N`, never an
input-selected command. Only uncompressed `.pcap`/`.pcapng` with recognized magic
are allowed. It scans at most the requested record ceiling **plus one**; that
extra frame detects overflow and causes failure rather than a successful prefix.
Both pipes are drained together, with no shell and no raw diagnostic echo.

## Versioned typed adapters

### `tshark-fields-v1`: packets

Fixed argv uses `-n -l -r /proc/self/fd/N -c LIMIT_PLUS_ONE -T fields`, no header,
tab separator, no quoting, and all field occurrences with comma aggregation.
The exact field allowlist is:

```text
frame.time_epoch ip.src ip.dst ipv6.src ipv6.dst ip.proto ipv6.nxt
 tcp.srcport tcp.dstport udp.srcport udp.dstport tcp.flags frame.len
```

Parsing requires exactly thirteen scalar fields. Addresses, ports, timestamps,
protocol numbers, eight supported TCP flag bits, and frame lengths are bounded
and typed before construction of `PacketEvent`. Multi-valued/tunneled addresses,
ambiguous transports, unexpected columns, unsupported flag bits, and malformed
rows fail closed. Non-IP frames and transport fragments without ports are
explicitly counted as skipped, not fabricated as valid events. IPv6 extension
chains and encapsulation are not comprehensively normalized by this profile.
Frame length is capped at 262,144 bytes. Timestamp range is Unix epoch through
2100 exclusive, truncated to microseconds; missing timestamps are not replaced
with the current time.

The profile deliberately omits DNS query length and TLS enrichment: it never
requests names or payload strings merely to derive their lengths. Raw PCAPs,
raw analyzer stderr, packet bytes, and capture/payload hashes are not copied,
persisted, or printed by MEGALODON. Raw capture custody remains a separate,
protected analyst responsibility.

### `zeek-conn-json-v1` / `zeek-conn-tsv-v1`: flows

These adapters import logs without invoking Zeek. Each record is a distinct
`FlowRecord`, never a `PacketEvent`. They require source/destination address and
port, timestamp, protocol, connection state, original/response packet counts,
and original/response IP-byte counts. `byte_count` is the sum of the two IP-byte
counts, not packet frame length. The manifest records this unit basis.

The known standard conn fields are explicitly allowlisted in `zeek.py`.
Unknown site extensions fail with a schema mismatch rather than silently
changing interpretation. All present fields are bounded and validated; UID,
service, history, tunnel identifiers, and other non-report fields are discarded.
JSON duplicate keys, nonfinite numbers, excessive nesting, invalid types,
unsupported protocols, and oversized lines fail. Decimal time/duration parsing
avoids binary-float timestamp conversion. Durations must be below seven days;
packet counters are below 2^31 and per-direction IP bytes below 2^40.

TSV requires the standard tab/comma separators, `(empty)` and `-` markers,
`#path conn`, matching `#fields`/`#types`, and a closing `#close` record. Schema
resets, duplicate headers, data after close, and incomplete logs fail. This is
not a generic Zeek log parser: files, HTTP, DNS, extracted artifacts, arbitrary
schemas, and mixed-source enrichment remain out of scope.

## Run manifests and redacted local reports

A successful run writes a new mode-0700 directory containing mode-0600 files:

- `records.jsonl` and `records.csv`: the same fixed typed metadata columns;
- `baseline.json` and `candidates.jsonl`: deterministic local analysis;
- `manifest.json`: the terminal receipt, written last as the completion marker.

`offline-run-v1` records a random run ID, non-sensitive case ID, source/adapter,
record kind, tool/version provenance, configured limits, analysis start/end UTC,
input byte size, accepted/scanned/skipped/rejected counts, candidate count,
reference-baseline use, byte-count basis, and `action_status: not_attempted`.
No input/output paths or input hashes enter the receipt. Analysis start/end times
are receipt times, not exact capture observation timestamps.

Reports replace IPs with deterministic rank labels such as `host-00001`, discard
the mapping, and use microsecond offsets relative to the earliest observation.
No raw address, absolute observation timestamp, arbitrary metadata dictionary,
interface, name, credential, or free-text analyzer diagnostic is exported.
CSV cells come only from numeric fields, fixed enums, and generated labels;
untrusted spreadsheet formulas cannot be copied into report cells.

**Redaction is not anonymization or permission to share.** Rank labels expose
structure/order, may correlate across overlapping inputs, and protocol/port/time
patterns and byte counts can still identify activity. Case IDs and receipt
times can also be sensitive. All reports stay local until a separate approved
sharing policy and human review authorize a specific release.

Malformed input, analyzer nonzero exit, timeout, overflow, or input mutation
rejects the run; no accepted prefix or candidate evidence is published. When a
private output directory can be created and written, failure produces only a
failed manifest with a fixed diagnostic code, zero accepted records, and an
unknown (`null`) rejected count rather than an invented total. Preflight or
storage failures can prevent a manifest; the console explicitly reports
`manifest_written: false`. Never treat missing manifests, failed manifests, or
partially written directories after an external interruption as complete runs.
These filesystem writes are not a multi-file transactional snapshot.

## Deterministic baselines and candidates

`offline-baseline-v1` contains source-qualified record counts, protocol and
TCP/UDP destination-port distributions, byte-size bands (<512, <4096, otherwise
large), total bytes, and relative one-minute activity bins. It is deterministic
for the same normalized input, including input reordering. Report record order
and random run IDs/receipt timestamps are not claimed to be deterministic.

Candidates are review items with no severity escalation or policy authority:

| Candidate | Fixed condition | Important limitation |
| --- | --- | --- |
| `NEW_DESTINATION_PORT` | A destination protocol/port absent from an explicitly supplied compatible baseline with at least five records | Novel is not malicious; a small or poisoned baseline is unreliable |
| `REGULAR_INTERVAL` | At least five unique observations for one endpoint/protocol/port group; median interval 1 second to 1 hour, interval spread <=5% of median | Scheduled benign traffic is expected to match |
| `PORT_53_BURST` | At least twenty port-53 records from a source in one relative minute bin | Port 53 does not prove DNS; flows and packets have different meanings |

No machine learning, DNS-content heuristic, TLS fingerprint, attribution, fixed
MVP rule change, automatic block, or permanent response is added. Synthetic
positive/negative tests demonstrate specified behavior, not detection accuracy
on real traffic. Representative benign fixtures, false-positive measurement,
operator interpretation, and independent review remain required before any
operational reliance. Baseline provenance is local/operator-selected, not a
cryptographically authenticated chain of custody.

## Read-only dashboard summaries

**Implemented:** local report summaries described above. **Unchanged:** the
existing loopback dashboard reads its existing SQLite counts/detections only;
it does not ingest offline reports or display these runs. No new HTTP endpoint,
file browser, report upload, remote bind, or control button is added.

A later, separately reviewed dashboard integration may project only a validated
complete manifest, source-qualified counts, relative observation window,
protocol/port distributions, candidate status, tool provenance, and limitations.
It must preserve packet/flow units, label candidates rather than malware,
exclude raw addresses and capture paths, cap every response, remain read-only
and loopback-bound, and never allow a web request to launch an analyzer or
firewall operation. That projection and its authorization tests are PROPOSED,
not delivered by the current command.

## SIEM/SOAR data-sharing and egress gate

Status: **NOT APPROVED; exporter NOT IMPLEMENTED**. There is no destination,
credential, HTTP client, outbox, automatic send, or `--enable-export` switch.
Local JSONL/CSV generation does not authorize external transmission. The
manifest states `egress: not_implemented_policy_required`.

Before a separate export adapter can be implemented or enabled, approve a
versioned policy identifying the accountable owner/approver, purpose, legal and
collection authority, exact allowed fields and redactions, sensitivity review,
retention/deletion rules, permitted recipients and destination allowlist, and
cross-boundary handling. Define TLS/authentication, secrets outside events and
prompts, payload and rate limits, timeout/retry/backoff classes, idempotency,
local outbox retention, auditable blocked/failed/delivered states, revocation,
and a disabled-by-default kill switch. Validate those controls with negative
cases before release. No event, prompt, model, document, or candidate may select
an endpoint, credential, tool, or response action. First-stage delivery must be
report-only; SOAR response automation needs its own explicit approval boundary.

## Validation and evidence limits

Repository-native checks remain:

```bash
cd "$HOME/Projects/MEGALODON"
. .venv/bin/activate
python -m compileall -q megalodon tests
python -m pytest
python -m megalodon.offline --help
```

Focused tests use synthetic metadata, empty/header-only fixtures, and controlled
Python child processes. The optional actual-analyzer test is skipped unless
explicitly enabled in a non-root Linux environment with the operator-reviewed
system TShark installed:

```bash
MEGALODON_TEST_TSHARK=1 python -m pytest -q tests/test_offline.py -k system_tshark_headers_only
```

Record the repository SHA, system package provenance, exact tool version, and
result when running that lane. It is a minimal header-only compatibility probe,
not proof of safe behavior on arbitrary captures. The ordinary CI job must not
install or implicitly trust an unpinned analyzer. No test uses a live firewall,
sudo, real network capture, external endpoint, or production traffic.

## Official format and tool references

- [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Wireshark security advisories](https://www.wireshark.org/security/)
- [Zeek conn.log reference](https://docs.zeek.org/en/current/reference/logs/conn.html)

These define external formats/tool behavior, not MEGALODON compatibility
certification, review approval, isolation enforcement, or deployment status.
