# Zeek 8.0.10 declared conn.log producer profile

Status: **implemented digest-bound admission API; native producer NOT QUALIFIED**.
This is one declared profile for the private 8.0.10 candidate selected in
[PR #519](https://github.com/bartytime4life/MEGALODON/pull/519).
It advances [#445](https://github.com/bartytime4life/MEGALODON/issues/445);
it does not close its provenance, independent review or owner-acceptance gates.
The earlier 0.0.0 placeholder remains in Git history.

## Exact declaration

| Pin | Value or artifact |
| --- | --- |
| Producer profile | `zeek-8.0.10-conn-json-tsv-v1` |
| Declared producer version | `8.0.10` |
| Source archive | SHA-256 `dbb1cb6c1eac27a8883ee4bd229a378b2f1253fa18e16cdeaaef8a00f124ddf1` |
| Recorded private binary | SHA-256 `9a373fa2f32469432273af0c793455af59a34195a88beb9963c8d2e0e648f161` |
| Historical build cache | SHA-256 `f6a73802a870a526528ddda446669bf73f2e56e0eeb133d3b958e2cfb328ca12` |
| Declared configuration | [configuration.json](configuration.json), SHA-256 `be7b117ee3a229884e6a6289fc3140ae32373df26a7b58b1616e87ce4092b0ed` |
| Admission schema | [schema.json](schema.json), definition `admission` |
| API | [read_completed_conn](../../../../megalodon/offline/zeek_profile.py) |
| Synthetic admissions | [fixtures/admissions.json](fixtures/admissions.json) |
| Metadata fixtures | [digest-bound candidate packet](../qualification/README.md) |

Archive, binary and build-cache bytes were read without executing Zeek and match
the historical selection inventory. Non-sensitive Boolean build options are
recorded in the configuration artifact; the complete cache is bound by digest,
without publishing its operator paths. This is recorded identity, not an
authenticated archive-to-binary chain.

The configuration artifact declares one field set and JSON/classic-ASCII modes.
It does **not** prove those settings were loaded by an installed process.
Its digest pins the declaration required by this API, not a runtime probe.

## Field and writer contract

The 22-field TSV order/types are fixed in configuration.json and must match
the existing closed importer table. Headers include open/close metadata. This
is classic ASCII conn.log, not the writer's header-only TSV mode.

JSON omits unset optional fields and uses epoch-number timestamps. UID and
missed_bytes must be present; present JSON numeric fields must be numbers,
not numeric strings. Null fields and an incompatible field inventory refuse.
The existing adapter remains authoritative for addresses, state, protocol,
ICMP family/type/code, counters, escapes, and time bounds. The schema's
profileConnJsonRecord definition supplements the shared generic record shape.

The versioned upstream [ASCII writer reference](https://docs.zeek.org/en/v8.0.10/scripts/base/frameworks/logging/writers/ascii.zeek.html)
and [Conn::Info reference](https://docs.zeek.org/en/v8.0.10/scripts/base/protocols/conn/main.zeek.html)
were read for this contract. A declared size analyzer and required counters do
not establish that a native producer emitted them. Package-added fields refuse;
the profile does not silently discard schema drift.

| Measurement | Meaning |
| --- | --- |
| ts | Unix epoch seconds; normalized to integer microseconds |
| duration | Seconds, below seven days; sub-microseconds truncate |
| orig_pkts / resp_pkts | Packet counters; a connection remains one flow |
| Normalized byte_count | Sum of orig_ip_bytes and resp_ip_bytes, IP-level bytes |
| ICMP source/destination port slots | Message type and code, each an octet |
| Community ID | Separate non-authoritative grouping hint; not an allowed added field |

## Admission and failure behavior

`read_completed_conn(root, relative, *, admission, limits=Limits())`
requires all ten closed admission fields. Unknown profiles, version/build/archive
or configuration pins, malformed digests, extra fields, invalid IDs and counts
refuse before source-path or privilege inspection. Source/run IDs are bounded
labels, never paths, endpoints or commands.

The source root must be private and owned by the current user. The source must
be a current-owner regular single-link file with mode 0400 or 0600. Existing
descriptor-relative no-symlink, path, file-identity and byte-limit guards apply.

The operator supplies an independently retained expected source digest and
record count before reading. The reader hashes exactly the bytes parsed in one
bounded pass and returns only after digest/count, source/directory identity,
deadline and descriptor-close checks. Removing complete JSON records, or TSV rows
while retaining its close marker, therefore refuses against the original
expectation. Recomputing expectations from already-shortened input cannot prove
that missing earlier evidence ever existed. This is custody-relative integrity,
not capture completeness or a signature.

Limits remain 64 MiB input, 10,000 records, 16 KiB lines and a cooperative
30-second budget, all reducible. Empty evidence is not admitted by this profile.
A stalled kernel read is not interruptible by this cooperative deadline.

The result is an in-memory Batch plus an immutable receipt with immutable copied
provenance. It reports operator_declared_unverified producer identity,
matches_operator_expectation byte integrity, metadata_unchanged_not_atomic
source status, native_qualification not_run, and no attempted action or durable
write. It is not a healthy-source attestation. Admission labels do not supply
replay suppression or make duplicate input a fresh independent observation.

The generic Zeek CLI remains available with its unverified source-quality
warning; it does not automatically opt into this API. The new API has no CLI,
dashboard, database publication or host-control integration.

## Validation and remaining acceptance

From the repository root, Python 3.11 or newer:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_zeek_profile_admission.py -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_zeek_candidate_packet.py -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_zeek_tsv_atomic.py -v
```

The new tests exercise both formats, all 37 malformed-file cases, malformed
admission before I/O, writer/field drift, count and digest refusals, source
mutation, private modes, links and resource bounds. Existing network,
subprocess/exec/signaling, SQLite, watcher/process and source-write tripwires
surround the exercised reader paths. Privilege checks are stubbed for these
finite synthetic tests; this is application-path evidence, not OS containment.

The schema tests run with the repository pytest/jsonschema prerequisites.
Missing local prerequisites are NOT_RUN; no package installation is required
or authorized by this document. The public fixtures contain fabricated metadata,
not packet payloads, payload-derived hashes or private captures.

Keep #445 open pending authenticated source/build/output provenance,
same-profile native JSON/TSV or independently reviewed equivalent evidence,
exact-head independent acceptance and a separate owner disposition.
Native installed-producer compatibility, operational loss/asymmetry, release,
deployment and host authority remain separate.

This work launches no Zeek process, reads no live interface, installs no package,
creates no service, mutates no source or database, and applies no firewall change.
