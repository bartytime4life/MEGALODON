# Bounded Suricata EVE reader contract v1

**Status: ADOPTED / INERT CONTRACT, SYNTHETIC FIXTURES, AND TEST ORACLE ONLY.**

The design gate tracked in issue #24 is closed on `main`. That closure adopts
these requirements for future work; it does not claim the runtime behavior
exists. Capability and hub output must therefore remain `contract_only` and
`no_runtime_importer`.

This directory closes the design gate for a future local reader. It does not add
a runtime importer, open a source file, run or configure Suricata, launch a
process, use the network, write SQLite, update the dashboard, schedule work, or
request or execute an action. Delivery of this contract did not change anything
under `megalodon/`.

The parent [record contract](../README.md) remains authoritative for each
`suricata-eve-alert-input-v1` envelope and its `external-alert-v1` normalized
form. Ordinary Suricata EVE JSON is not this input contract. An operator must
prepare the deliberately narrow, closed envelope before any future reader may
accept it; this proposal does not add a producer, scrubber, capture path, or
compatibility claim.

`schema.json` closes the policy and completed-receipt shapes. The fixture and
test oracle make the run rules executable without creating a production API.
Schema validity alone is not reader conformance.

## 1. Fixed resource budget

The v1 policy is a constant contract, not caller-tunable configuration.

| Budget | Limit | Measurement |
| --- | ---: | --- |
| selected source | 1 file | One explicit absolute Linux path |
| total input | 67,108,864 bytes | Bytes read from the descriptor, including record terminators |
| records | 10,000 | Non-empty logical records in the selected file |
| logical record | 65,536 bytes | JSON bytes plus optional LF or CRLF |
| JSON nesting | 4 | Object/array depth outside quoted strings |
| integer token | 10 digits | Decimal digits, excluding an optional minus sign |
| buffered raw input | 65,536 bytes | At most one logical record |
| retained normalized batch | 16,777,216 bytes | Sum of each normalized record's compact UTF-8 JSON serialization |
| elapsed read/validation | 30,000 ms | Monotonic time from the first source check through the final check |
| diagnostic | 64 bytes | Fixed prefix and code only |

The record-count limit is independent of the parent schema's
`source_record_index` range. An ordinal of 10,000 is a valid field value; it does
not prove that a stream contains at most 10,000 records. A conforming reader must
enforce both limits.

The raw-input and normalized-serialization limits are the portable memory
budgets. A runtime must also use bounded collections and must not retain original
JSON. Language-specific object overhead is not claimed to equal the serialized
size, but it is bounded by the fixed record count and closed, bounded field sets.
An implementation that buffers the entire 64 MiB source, retains diagnostics or
labels, or emits records incrementally is non-conforming.

The deadline is checked before opening, during bounded reads and validation, and
before completion. Crossing it fails the entire run with `TIME_LIMIT`; a timeout
does not authorize partial output.

## 2. Source-file boundary

Only Linux is proposed for v1. The caller supplies exactly one absolute path.
There is no directory scan, glob, watcher, stdin mode, URL, named pipe, device,
socket, archive, or recursive input.

A future implementation must walk from a trusted root descriptor and open each
path component with no-follow semantics. Ancestors must be directories and no
component may be a symbolic link. The final component is opened read-only with
close-on-exec, no-follow, and nonblocking flags before type validation so a FIFO
cannot block the process. After opening, `fstat` must show:

- a regular file;
- `st_uid == geteuid()`;
- permission bits exactly `0400` or `0600`; and
- a size no greater than the total-byte budget.

The implementation retains the descriptor and directory descriptors. Identity
checks compare device/inode pairs at the descriptor boundary rather than
reopening by pathname. Before the first read and after the last validation it
compares at least device, inode, owner, mode, link count, size, nanosecond mtime,
and nanosecond ctime. A mismatch, replacement, truncation, growth, or component
identity change fails with `SOURCE_CHANGED`. The cumulative bytes-read counter
still enforces the total limit so metadata is not trusted as the only bound.

These checks reduce path substitution and observable concurrent-change risk.
They do **not** create or claim an atomic filesystem snapshot: a same-size write
may evade portable metadata comparisons, and a file owner can mutate the file.
The operator must supply a closed, quiescent private file. A later implementation
must document the filesystem assumptions it actually relies on and must not call
this contract atomic.

No pathname, descriptor number, device/inode value, mode, owner, timestamp, or
exception text enters a receipt or diagnostic.

## 3. Stream and record rules

The selected file contains one JSON value per logical record. LF and CRLF are
accepted terminators, and the final record may be unterminated. Empty input,
empty records, bare carriage returns, embedded physical newlines, a UTF-8 BOM,
malformed UTF-8/JSON, duplicate keys, depth greater than 4, floating/exponent or
non-finite numeric tokens, and integers longer than 10 digits are rejected.

Every decoded value must pass the complete parent input contract, including
explicit IPv4, IPv6, and date-time format assertions plus its semantic rules.
The reader does not weaken, repair, drop, or default a field. Optional upstream
`signature` and `category` labels remain transient and are absent from normalized
output, diagnostics, and receipts.

The first `source_record_index` is 1 and subsequent indexes are exactly
contiguous. Every record's complete `source` object is byte-value equivalent
after JSON decoding. A gap, duplicate, reordering, or source change fails the
entire run. The reader accepts at least one and at most 10,000 records.

Normalization is exactly the parent contract. Each record counts as one alert.
Producer-reported `blocked` is counted only in `producer_blocked_count`; it never
changes `action_status`, which is always `not_attempted`.

## 4. Run identity and replay

The run identity is the exact validated `source` object shared by every record:
engine, adapter profile, declared version and basis, sensor ID, run ID, ruleset
ID, and ruleset basis. It contains no path, file metadata, payload, rule label,
or content hash. The provenance remains operator-declared, not authenticated.

Before publishing a completed batch, a future coordinator supplies a read-only
set of previously completed run identities. An exact match fails with `REPLAY`.
The reader does not mutate or persist that set. Relabeling identical content with
a new run identity is considered a new operator claim; v1 neither hashes content
nor claims content-level deduplication.

A later durable consumer must commit the normalized batch and its run identity
in one transaction with a uniqueness constraint. That transaction and registry
are explicitly outside this slice. Until they exist, a successful receipt means
only that the bounded read completed against the supplied replay view; it is not
evidence of durable replay prevention across processes or time.

## 5. All-or-nothing completion

The reader validates and normalizes into a bounded private batch. It must not
yield, callback, log, persist, or otherwise publish an individual record while
the source is being read. Only after all records pass, the output budget remains
within bounds, the replay check passes, the deadline remains valid, and the
post-read source checks match may it publish one immutable batch plus one
`suricata-eve-reader-receipt-v1` receipt.

The completed receipt is deliberately narrow:

- `status` is exactly `complete`;
- record and normalized-alert counts are equal and nonzero;
- `producer_blocked_count` cannot exceed that count;
- `count_unit` is `alert`;
- `action_status` and `durable_write_status` are `not_attempted`;
- `source_snapshot_status` is `metadata_unchanged_not_atomic`; and
- `replay_status` is `fresh`.

Any error discards the private batch and produces no completed receipt. There is
no failed receipt carrying context and no partially completed status. This slice
performs no durable write, so its tests can prove only the publish boundary of
the synthetic oracle, not database atomicity.

## 6. Fixed diagnostics

Failure output is exactly `SURICATA_READER_V1:<CODE>`, where `<CODE>` is one of
the schema's `$defs/errorCode` values. Codes are stable categories, not exception
messages. A diagnostic must never include input bytes, decoded values, rule
labels, paths, file metadata, JSON parser text, or chained exception text.

| Boundary | Codes |
| --- | --- |
| source selection | `SOURCE_PATH`, `SOURCE_SYMLINK`, `SOURCE_TYPE`, `SOURCE_OWNER`, `SOURCE_MODE`, `SOURCE_CHANGED` |
| quotas/framing | `TOTAL_BYTES`, `RECORD_LIMIT`, `RECORD_BYTES`, `EMPTY_INPUT`, `EMPTY_RECORD`, `FRAMING`, `UTF8`, `DUPLICATE_KEY`, `DEPTH`, `JSON_NUMBER`, `JSON` |
| contract/run | `SCHEMA`, `SEMANTIC`, `RUN_IDENTITY`, `RECORD_SEQUENCE`, `REPLAY`, `COUNT_MISMATCH`, `OUTPUT_LIMIT`, `TIME_LIMIT` |

Mapping a low-level failure to a code must happen at the boundary. Unexpected
exceptions fail closed to an approved fixed code and are never stringified into
operator-visible output.

## 7. Fixtures and verification boundary

`fixtures/accepted.json` contains the exact policy and bounded completed receipts.
`fixtures/rejected.json` applies data-only mutations that try to weaken resource,
file, side-effect, completion, and action boundaries. All content is synthetic.

`tests/test_suricata_reader_contract.py` is an in-memory conformance oracle. It
validates the new schema and fixtures, uses the parent record schema with local
resolution and explicit format assertions, checks contiguous indexes and one run
identity, models a read-only replay view, and verifies that a late failure
publishes nothing. It denies socket creation and process launch. It does not open
or mutate filesystem objects and must never be imported by runtime code.

From the repository root:

```bash
python -m pytest -q \
  tests/test_suricata_contract.py \
  tests/test_suricata_formats.py \
  tests/test_suricata_reader_contract.py
python -m compileall -q megalodon tests
python -m pytest -ra
python -m megalodon capabilities --platform linux
python -m megalodon hub-plan --platform linux
```

Passing these tests proves the inert artifacts in the tested revision only. It
does not prove the future descriptor walk, filesystem race resistance, memory or
deadline behavior under hostile load, durable transactionality, Suricata
installation or compatibility, detection quality, privacy of arbitrary logs,
or deployment safety. The capability and hub status must remain
`contract_only`/`no_runtime_importer` after this change.

## 8. Still out of scope

This contract does not add a runtime reader, sensor control, capture, rule
download, source conversion or scrubbing, watcher, scheduler, root privilege,
production input, SQLite integration, dashboard projection, endpoint mapping,
severity-to-response logic, model call, firewall planning or execution, network
egress, or automatic action. Those require separately authorized and reviewed
changes after repository controls and the remaining project gates are satisfied.
