# Zeek 8.0.10 candidate fixture packet - NOT QUALIFIED

This packet advances [#445](https://github.com/bartytime4life/MEGALODON/issues/445)
with **synthetic metadata evidence**. The separate exact declared
[producer admission contract](../producer/README.md) now pins 8.0.10 and its
configuration, with a digest/count-bound API. Neither packet authenticates an installed
producer, or satisfy independent review or owner disposition.

Repository basis: main commit `f492d784879168c6a96037eef5f10db0e3f02550`, tree
`51c744bb8c5198d541f72d73aa757eb95ace12d4`. The
[selection packet](../../../../docs/zeek-producer-selection-packet-2026-10-04.md)
and [PR #519](https://github.com/bartytime4life/MEGALODON/pull/519) record the
owner's existing selection of the private Zeek **8.0.10** candidate. The archive
digest in this manifest is historical selection evidence, not a new build-chain
attestation. No second producer is selected.

## What the packet verifies

[manifest.json](manifest.json) binds the exact size and SHA-256 of the three
fixture files. They contain invented connection metadata, documentation-range
addresses, and no packets, payloads, payload-derived hashes, private captures,
hostnames, or operator paths. Digests cover these synthetic metadata files only.
The four positive records exercise TCP/IPv4, UDP/IPv6, ICMPv4 and ICMPv6.
JSON and TSV must produce the same normalized records and redacted record
reports, including one-microsecond time precision, absent duration, zero duration,
packet counts and IP-byte totals. Flow counts stay flow counts; ICMP type/code
stay octets rather than transport ports.

The 22-field order and types are explicit in the manifest. JSON omits unset
optional fields; TSV uses unset/empty markers, typed metadata headers and a
closing marker. The local installed script was read as source to check the
declared writer semantics: epoch JSON timestamps, omitted unset JSON fields and
metadata headers for classic ASCII output. These are source declarations,
**not observed loaded settings**. The versioned upstream
[Conn::Info reference](https://docs.zeek.org/en/v8.0.10/scripts/base/protocols/conn/main.zeek.html)
documents flow/ICMP semantics and optional packet/IP-byte counters. The
[writer reference](https://docs.zeek.org/en/v8.0.10/scripts/base/frameworks/logging/writers/ascii.zeek.html)
is the corresponding configuration reference; retrieval was rate-limited during
this pass. Native field order, enabled size analyzer, loaded scripts, writer
precision and JSON key sets remain unproven.

The 37 raw negative cases cover missing/invalid timestamps, milliseconds supplied
as epoch seconds, missing required counters, unsupported transport, protocol
number mismatch, invalid duration bounds, boolean/port/count errors, non-octet
ICMP type, package/unknown fields, malformed escapes, duplicate JSON keys,
terminal-record truncation, TSV type drift, header reset, missing close and
post-close data. Record-level failures follow four valid records; header failures
occur before records. Each case declares the exact adapter error code. Whole-file
replay must refuse; the CLI may write only a failed manifest with zero accepted
records and no success reports.

Finite tests place tripwires around DNS/sockets, subprocess/exec/signaling,
SQLite connections, thread/process starts and source mutation. Direct replay
permits no writes; CLI tests permit only fixed report names in a new disposable
directory. Source bytes, inode, size and modification/change times must stay
unchanged. Linux privilege checks are stubbed, matching existing offline tests:
this proves exercised Python paths, not native containment.

## Complete parsing is not complete source evidence

JSONL shortened exactly between records remains syntactically valid. Original
length or intended record count cannot be reconstructed from remaining bytes.
TSV's close marker detects some truncation; it does not attest that earlier rows
were never removed. Numeric intervals inside permitted bounds cannot reveal
their producer's intended units.

Successful Zeek CLI summaries and offline-run-v1 manifests therefore expose:

```json
"source_quality": {
  "status": "unverified",
  "producer_profile": "not_qualified",
  "completeness": "not_attested"
}
```

A complete run status describes completed local parsing/report publication only.
It does not mean a healthy, complete, authenticated or qualified source.
Syntactically valid unknown producer versions remain operator-declared and
unverified with the same visible quality. The generic CLI does not opt into the
separate [profile-admission API](../producer/README.md), which requires explicit
source digests, counts and pinned provenance declarations.
Malformed input still fails with existing codes. TShark output is unchanged.
Community ID remains a separate non-authoritative grouping hint; adding its
field to this closed importer still refuses.

The read-only projection reader accepts this exact additive quality declaration
for Zeek only and continues accepting legacy manifests. False/extra declarations
are rejected; the projected dashboard response shape remains unchanged.

## Reproduce and remaining gate

From the repository root, with Python 3.11 or newer:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_zeek_candidate_packet.py -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_zeek_tsv_atomic.py -v
```

Native fixture generation and installed-producer parity are **NOT_RUN**.
Discovery mistakenly invoked zeek --version, which reported 8.0.10; this was
outside #445's no-launch scope and supplies no qualification evidence. No further
Zeek command, live capture, package installation, service operation, database
mutation or firewall action was performed. Test reports use disposable files.
Reading installed scripts does not authenticate them against the historical
archive or establish which scripts wrote an existing log.

Historical PR #701 validation: the local environment disconnected before publication. All three fixture files
were recovered with their exact previously tested SHA-256 identities. The final
projection compatibility change and reconstructed test module subsequently passed
hosted CI at ccd70f05958bfbb947d196e9f9b3bbffe1bf01e9 (6,605 tests, four skips,
318 subtests). These are historical results, not validation of later admission changes.

Keep #445 open. The next evidence gate is a same-build native JSON/TSV packet
with authenticated archive/build/executable/script provenance, actual writer
settings, and source custody/completeness evidence. Missing artifacts must be
supplied or generated under separately authorized finite offline work; this
packet grants no execution authority. Exact-head independent review and explicit
owner disposition remain separate gates. Installed sensor loss/asymmetry,
release, deployment and host authority remain held.
