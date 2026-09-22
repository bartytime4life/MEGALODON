# Adapter identity and accepted/rejected count receipts: design note

Status: ◐ **Proposed.** This is a design note for review, not a schema change,
a migration, or an implementation. No code, table, index, or API route is
altered by this document. It answers rank 6 of
[`docs/system-opportunity-map.md`](system-opportunity-map.md): "Core
adapter/count receipts: explain attempted versus committed input." The map
marks that rank high migration/semantics risk and asks for this review before
any schema change. [`SPECIFICATION.md`](../SPECIFICATION.md) and
[`SECURITY_REVIEW.md`](../SECURITY_REVIEW.md) remain authoritative for the
implemented boundary until a change like this is separately accepted.

## What exists today

`ingestion_runs` (schema `SCHEMA_VERSION = 3` in
[`megalodon/storage.py`](../megalodon/storage.py)) records, per run: `source`
(`sample`, `jsonl`, or `scapy`), `status`, `processed_count`,
`detection_count`, `action_count`, `receipt_version` (`2` or `3`, for
mixed-vintage rows), `failure_code`, and `termination_reason`
(`source_exhausted`, `event_limit_reached`, `interrupted`, `failed`, or
`reconciliation_required`). One event, its detections, its policy-plan
action, their links, and the run counters commit or roll back together in
one transaction, per
[`docs/storage-failure-policy.md`](storage-failure-policy.md).

The dashboard's `/api/ingestion-runs-v2` route already ships a fixed
`"not_recorded": ["adapter_identity", "accepted_count", "rejected_count"]`
marker in every response (`megalodon/dashboard.py`), naming exactly the three
fields this note is about. `/api/ingestion-runs` (v1) does not carry that
marker or these fields at all. Both routes are read-only projections of the
same `ingestion_runs` rows; neither can supply a field the store does not
have.

The CLI run loop (`_run` in `megalodon/cli.py`) is currently **fail-fast**:
it iterates the selected adapter's event generator and calls
`service.process()` once per event, incrementing an in-memory `processed`
counter. Any exception raised while producing or validating one event
(`CaptureError`, `OSError`, `ValueError` — which covers
`megalodon.validation.ValidationError`, `sqlite3.Error`) escapes the loop and
ends the **entire run** as `failed` with a fixed `failure_code`. There is no
per-record "this one input was rejected, continue with the next" path today,
and no adapter reports a version or build identity anywhere in the run
receipt. `sample` is a deterministic in-process generator with no external
input to reject. `jsonl` parses one 64 KiB-bounded line at a time; a
malformed line currently fails the whole run rather than being counted and
skipped. `scapy`'s capture callback already silently discards a packet whose
TCP-flag bitmask does not decode into the closed FIN/SYN/RST/PSH/ACK/URG/
ECE/CWR vocabulary, before that packet ever becomes a candidate `PacketEvent`
— that discard is invisible today: it is not an event, not a rejection
record, and not counted anywhere.

## Why this is high migration/semantics risk

Adding `accepted_count`/`rejected_count` is not just two new columns. It
requires deciding, for each of three structurally different adapters, what
"attempted" and "rejected" mean, and it requires changing the CLI's run loop
from fail-fast to a shape that can keep going after one bad record — a
behavior change, not only a storage change. Both change the meaning of an
existing receipt that operators and the dashboard already read.

## Per-source accepted/rejected definitions (proposed)

- **`sample`.** Every emitted record is accepted by construction; there is no
  external input to reject. `accepted_count` should equal `processed_count`
  and `rejected_count` should be a fixed `0`. This adapter does not exercise
  the new rejection path and should not be used alone to validate it.
- **`jsonl`.** "Attempted" is one line read from the file or stdin, up to the
  existing 64 KiB bound. "Rejected" is a line that fails size, JSON-syntax,
  schema, or field-bounds validation (`ValidationError` and the specific
  oversize/decoding failures already distinguished in
  `megalodon/validation.py`). A rejected line must not become a `PacketEvent`
  and must not be silently dropped either: it needs a bounded, closed reject
  *reason code* (for example, `OVERSIZE_LINE`, `INVALID_JSON`,
  `SCHEMA_VIOLATION`, `FIELD_OUT_OF_BOUNDS`) recorded in aggregate per run,
  not the offending line content itself — the run ledger must stay free of
  raw untrusted input, matching the existing no-payload/no-raw-exception
  policy for run receipts.
- **`scapy`.** Two different things currently share the word "reject" and
  must not be merged into one counter: (a) a packet whose capture-layer flag
  decode fails, discarded before it is a candidate event, and (b) a
  candidate event that fails the same field validation `jsonl` uses. Only
  (b) is analogous to a "rejected input" in the `jsonl` sense; (a) is a
  capture-adapter-internal filter with its own separate counter (for example
  `capture_filtered_count`) so it is not confused with validation rejection.
  The 1,024-event callback-queue overflow remains a run-ending failure
  (`CAPTURE_ERROR`), not a per-item rejection, and this note does not propose
  changing that fail-closed behavior.

## Failure, partial, and replay behavior (proposed)

Keep the existing `termination_reason` enum and fail-closed failure paths
unchanged for anything that is not a per-record content rejection: storage
errors, I/O errors, interruption, and the reconciliation-required path all
keep ending the run exactly as they do today. Add one new, narrower
behavior: a **content-level** per-record rejection (bad JSON, bad schema, bad
field) advances `rejected_count` and continues to the next record, up to a
fixed per-run ceiling on rejections (proposed: reuse an existing bound such
as `MAX_EVENTS_PER_SOURCE_WINDOW`, or define a dedicated small ceiling) past
which the run still fails closed rather than accepting an unbounded run of
garbage input as "mostly successful." This is a new `termination_reason`
value (for example `rejection_limit_reached`), not a repurposing of an
existing one.

Replay determinism: replaying the same `jsonl` file against the same
adapter/schema version must reproduce the same `accepted_count`,
`rejected_count`, and per-reason breakdown. Replaying an **older** file
against a **newer** validation schema may legitimately reject records the
original run accepted; the run receipt must record the adapter/schema
version it ran under (see below) precisely so that difference is
attributable and not mistaken for nondeterminism or storage corruption.

## Adapter version/identity (proposed)

"Adapter identity" here means MEGALODON's own ingestion code path — a fixed
string such as `sample/v1`, `jsonl/v1`, or `scapy/v1`, versioned independently
per adapter and bumped when that adapter's accept/reject semantics change —
**not** an upstream producer's version. This is a different concept from
Suricata's or Zeek's own producer version (see rank 5's separate
qualification work); MEGALODON does not run those tools and this field must
not be presented as if it identifies them. `adapter_identity` should be a
fixed value looked up from a small in-code table keyed by `source`, not a
free-text or environment-derived string, so it cannot leak host detail into
the audit store.

## Schema migration and rollback (proposed)

This would be a new `SCHEMA_VERSION = 4` addition to `megalodon/storage.py`,
following the same pattern as the existing v1→v2 and v2→v3 migrations:
additive nullable columns on `ingestion_runs`
(`adapter_identity TEXT`, `accepted_count INTEGER`, `rejected_count
INTEGER`, plus a bounded reject-reason breakdown — likely a small satellite
table rather than open-ended JSON, to keep the same "no arbitrary field"
discipline as the rest of the store) with `CHECK` constraints mirroring the
existing `receipt_version`/`termination_reason` pattern, a new
`receipt_version = 4` branch in the existing status/termination `CHECK`,
and an explicit `database-migrate`-style backup-then-migrate-in-one-
transaction path — never an implicit migration on ordinary startup. Existing
`receipt_version 2` and `3` rows are not rewritten or backfilled: their
`adapter_identity`/`accepted_count`/`rejected_count` stay `NULL`, which the
API layer continues to surface as `not_recorded` for exactly those rows.
Rollback follows the existing pattern: verify the pre-migration backup before
touching the live database, and refuse to migrate (rather than repair or
guess) a database that has already been partially or differently migrated.

## v1/v2 (and future v3) route compatibility (proposed)

`/api/ingestion-runs` (v1) must keep returning exactly its current fields;
it must not gain these three fields silently, since existing v1 consumers do
not expect them. `/api/ingestion-runs-v2` keeps its `not_recorded` marker,
but the marker becomes **per-run-conditional** instead of a blanket
constant: a `receipt_version 4` row with real values reports them normally,
while any older row (or a `receipt_version 4` row from an adapter that has
not yet started reporting, if that is ever possible) keeps reporting
`not_recorded` for exactly the fields it genuinely lacks — never a
zero-filled or synthesized value standing in for missing data. A source
filter (`?source=`) continuing to work unchanged for all `receipt_version`
values is a required regression check, not an incidental property.

## What this note does not do

It does not select final column names, reason-code enums, or ceiling values
as final; those are implementation-review decisions, not settled by this
note. It does not change `megalodon/storage.py`, `megalodon/cli.py`,
`megalodon/dashboard.py`, or any test. It does not claim an operator benefit
beyond "attempted vs. committed input becomes attributable"; it does not
establish detection accuracy, sensor health, or production readiness. Any
implementation following this note still needs its own review, its own
negative-control tests (oversize line, truncated JSON, schema violation,
rejection-limit boundary, mixed old/new `receipt_version` rows in one
query), and its own PR separate from this design note.
