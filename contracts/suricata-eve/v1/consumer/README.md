# Transactional Suricata durable-consumer contract v1

**Status: IMPLEMENTED BOUNDED TRANSACTION, SYNTHETIC ORACLE, AND EXPLICIT
STORE INITIALIZER. RECONCILIATION API AND DASHBOARD PROJECTION REMAIN DEFERRED.**

This directory defines the durable boundary after the bounded Linux reader.
`megalodon.suricata_store` explicitly creates and validates the dedicated v1
SQLite layout. `megalodon.offline.suricata_consumer.consume_publication`
validates one immutable reader publication, opens one explicitly selected
existing store, applies the fixed capacity gate, and atomically commits its run
identity, normalized alerts, and terminal receipt. There is no migration of an
existing store, command, dashboard projection, watcher, scheduler, sensor
process, network access, model request, retention action, or response action.

The reader publishes one immutable `external-alert-v1` batch and one
`suricata-eve-reader-receipt-v1`. Its replay view is caller supplied and is not
durable. The consumer closes that gap by committing the validated batch, the
complete run identity, and one terminal consumer receipt in a single local
SQLite transaction.

## 1. Input boundary

A conforming consumer accepts exactly one already-completed reader publication:

- one non-empty tuple of 1 through 10,000 `external-alert-v1` records;
- one schema-valid `suricata-eve-reader-receipt-v1`;
- one complete run identity shared by the receipt and every record;
- contiguous `source_record_index` values starting at 1;
- exact record, blocked-action, and compact normalized-byte counts; and
- `action_status=not_attempted` for every record and the reader receipt.

The consumer does not reopen the source file, accept raw EVE JSON, repair or
coerce records, or trust receipt counts without recomputing them from the
bounded normalized batch. Paths, original input, payloads, payload-derived
hashes, rule labels, credentials, and low-level exception text are forbidden.

## 2. Transaction and replay invariant

The implementation uses one `BEGIN IMMEDIATE` transaction to insert:

1. the complete eight-field run identity under a uniqueness constraint;
2. every normalized alert, keyed by that run and its record index; and
3. the terminal durable-consumer receipt and exact counts.

The replay registry and alert rows are one atomic unit. A duplicate complete run
identity is `REPLAY`; relabeling content with a new identity remains a new
operator claim. The contract deliberately forbids content or payload hashes.

A preflight failure before `BEGIN IMMEDIATE` writes nothing and reports
`not_started`/`not_attempted`. A failure after the transaction starts but before
confirmed commit rolls back the entire attempt. If commit may have succeeded but
acknowledgement or readback is lost, the only truthful result is
`reconciliation_required`. The caller must read back the exact attempt and run
identity before retrying. Blind retry after an unknown commit is forbidden; the
uniqueness constraint remains the final replay backstop.

## 3. Receipt states

`schema.json` closes one policy shape and one receipt union:

| Receipt status | Transaction | Durable write | Replay | Meaning |
| --- | --- | --- | --- | --- |
| `committed` | `committed` | `committed` | `recorded` | Exact batch, registry identity, and receipt passed readback |
| `rejected` | `not_started` | `not_attempted` | `duplicate` | Pre-transaction replay check found the complete run identity |
| `rejected` | `rolled_back` | `rolled_back` | `duplicate` | Authoritative in-transaction replay check found a race |
| `failed` | `not_started` | `not_attempted` | `not_recorded` | Preflight failure wrote no durable rows |
| `failed` | `rolled_back` | `rolled_back` | `not_recorded` | Post-begin, pre-commit failure left no durable rows |
| `reconciliation_required` | `unknown` | `unknown` | `unknown` | Commit disposition cannot yet be claimed |

Every receipt keeps `action_status=not_attempted` and uses one fixed failure code
or `null`. Diagnostics are exactly `SURICATA_CONSUMER_V1:<CODE>`, contain no
source data or storage details, and are at most 64 ASCII bytes.

## 4. Fixed limits

The v1 policy inherits the reader publication ceiling: 10,000 alerts and
16,777,216 compact normalized UTF-8 bytes. Store validation, preflight, lock
wait, transaction, and required readback share a fixed 30,000 ms monotonic
cooperative deadline. The connection uses the remaining time as its SQLite busy
timeout, installs a VM progress handler, and checks the deadline before and
after transaction stages. A single SQLite or kernel filesystem call can return
after the deadline under uninterruptible I/O; such a late return never becomes
a verified success. It rolls back before commit or returns
`reconciliation_required` after commit uncertainty. This is a bounded consumer
policy, not a hard process-termination SLA. Limits are not caller tunable.

The v1 logical store ceiling is 131,072 pages of exactly 4,096 bytes, or
536,870,912 bytes. Before `BEGIN IMMEDIATE`, the consumer computes the
batch reservation as:

```text
reservation_bytes = (4 * normalized_batch_bytes) + 8,388,608
reservation_pages = ceil(reservation_bytes / 4,096)
```

At the maximum admitted batch, this reserves 75,497,472 bytes, or 18,432 pages.
The multiplier and fixed overhead conservatively cover normalized alert rows,
indexes and receipts, SQLite page amplification, and transaction side effects;
they are an admission budget, not a claim that every filesystem write is
predictable.

The preflight uses the same consumer connection to require
`page_size=4096`, set `PRAGMA max_page_count=131072`, verify that the returned
limit is exactly 131,072, and then read `page_count` and `freelist_count`, all
before beginning a transaction. SQLite does not persist `max_page_count` for a
future connection, so relying on the initializer or a prior connection is
forbidden. A page-size mismatch is `SCHEMA_INCOMPATIBLE`; failure to bind the
fixed ceiling, an already-oversized store, invalid counts, or insufficient
headroom is `STORAGE_CAPACITY`. Counts must be internally valid. Freelist pages
are recorded for diagnosis but receive no admission credit:
`131072 - page_count` must be at least `reservation_pages`. The containing
filesystem must also report at least
`reservation_bytes` available. Insufficient or unavailable capacity evidence is
`STORAGE_CAPACITY`, writes nothing, and reports `not_started`/`not_attempted`.
The checks remain advisory against a concurrent filesystem race, so SQLite
write failures still fail closed under the transaction rules.

This contract does not alter the explicit initializer, persist a page ceiling,
migrate an existing file, reserve operating-system disk space, or select a purge schedule. Retention
and capacity admission are separate gates; reaching the ceiling stops new
consumption rather than deleting evidence. Ordinary application startup must
not create, initialize, repair, resize, or purge this store implicitly.

## 5. Explicit production schema initializer

`megalodon.suricata_store.initialize_suricata_store` remains the only schema
writer. An operator must call it explicitly with a new path. It creates an
owner-private database and atomically reserves:

- one run table with unique complete eight-field run identity and attempt ID;
- one alert table keyed by run and positive source-record index; and
- one terminal-receipt table keyed by run with a unique attempt ID.

`validate_suricata_store` opens an existing file read-only and query-only, then
checks the exact version, SQL, columns, indexes, foreign keys, uniqueness,
foreign-key integrity, and SQLite quick check. Its coordinated read-only open
includes committed WAL pages; incomplete WAL sidecars and active rollback
journals fail closed. Missing, partial, future, or weakened layouts fail closed.
Initialization refuses every existing database;
there is no implicit upgrade or ordinary-startup hook. This is storage
reservation evidence, not a consumer transaction, replay decision, retention
policy, or operational migration.

## 6. Runtime and synthetic conformance

`tests/test_suricata_consumer_contract.py` validates the closed schema and
fixtures with local-only references. Its in-memory SQLite oracle models the
transaction boundary. `tests/test_suricata_consumer_runtime.py` exercises the
production implementation against the explicit store. Together they prove:

- an exact two-record publication commits once;
- the implemented reader's immutable publication is accepted directly;
- a duplicate identity is rejected without new rows;
- an attempt-ID collision for a different run is not misclassified as replay;
- a capacity, deadline, or failed-begin refusal never claims a rollback;
- an injected pre-commit failure rolls back registry and alert rows together;
- a simulated lost acknowledgement after commit produces only
  `reconciliation_required` until explicit readback; and
- a retry before reconciliation cannot duplicate the batch.

The oracle is test code, not a reusable database layer, and production code does
not import it. Passing local tests is not installed-Suricata, operational,
release, deployment, or independent-review evidence.

From the repository root:

```bash
python -m pytest -q \
  tests/test_suricata_contract.py \
  tests/test_suricata_formats.py \
  tests/test_suricata_reader_contract.py \
  tests/test_suricata_consumer_contract.py \
  tests/test_suricata_consumer_preflight.py \
  tests/test_suricata_consumer_runtime.py \
  tests/test_suricata_store.py
python -m compileall -q megalodon tests
python -m pytest -ra
```

## 7. Remaining gates

The runtime transaction does not supply the separate reconciliation API needed
to resolve an unknown commit, and it intentionally has no CLI or background
entry point. Exact-head hosted checks and independent review remain required.
After those gates, the next dependency-ordered implementation is an explicit
reconciliation API; dashboard projection remains a later read-only slice.
