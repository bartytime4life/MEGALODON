# Transactional Suricata durable-consumer contract v1

**Status: PROPOSED CONTRACT, SYNTHETIC ORACLE, AND EXPLICIT STORE INITIALIZER.**

This directory defines the next gates after the implemented bounded Linux
reader. `megalodon.suricata_store` now explicitly creates and validates
the dedicated v1 SQLite layout, but it exposes no alert-write or consumer API.
There is still no production consumer, migration of an existing store, command,
dashboard projection, watcher, scheduler, sensor process, network access, or
response action.

The reader publishes one immutable `external-alert-v1` batch and one
`suricata-eve-reader-receipt-v1`. Its replay view is caller supplied and is not
durable. A future consumer may close that gap only by committing the validated
batch, the complete run identity, and one terminal consumer receipt in a single
local SQLite transaction.

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

The future implementation must use one `BEGIN IMMEDIATE` transaction to insert:

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
| `rejected` | `not_started` | `not_attempted` | `duplicate` | Complete run identity already exists |
| `failed` | `not_started` | `not_attempted` | `not_recorded` | Preflight failure wrote no durable rows |
| `failed` | `rolled_back` | `rolled_back` | `not_recorded` | Post-begin, pre-commit failure left no durable rows |
| `reconciliation_required` | `unknown` | `unknown` | `unknown` | Commit disposition cannot yet be claimed |

Every receipt keeps `action_status=not_attempted` and uses one fixed failure code
or `null`. Diagnostics are exactly `SURICATA_CONSUMER_V1:<CODE>`, contain no
source data or storage details, and are at most 64 ASCII bytes.

## 4. Fixed limits

The v1 policy inherits the reader publication ceiling: 10,000 alerts and
16,777,216 compact normalized UTF-8 bytes. A future transaction and its required
readback have a fixed 30,000 ms monotonic budget. These are contract limits, not
caller-tunable settings.

The contract requires a capacity check before `BEGIN IMMEDIATE`. The separate
store-initializer slice reserves production schema version 1, but it does not
choose a page budget or retention policy and does not migrate an existing file.
Ordinary application startup must not create, initialize, or repair this store
implicitly.

## 5. Explicit production schema initializer

`megalodon.suricata_store.initialize_suricata_store` is the only writer
in the production module. An operator must call it explicitly with a new path.
It creates an owner-private database and atomically reserves:

- one run table with unique complete eight-field run identity and attempt ID;
- one alert table keyed by run and positive source-record index; and
- one terminal-receipt table keyed by run with a unique attempt ID.

`validate_suricata_store` opens an existing file read-only and query-only, then
checks the exact version, SQL, columns, indexes, foreign keys, uniqueness,
foreign-key integrity, and SQLite quick check. Missing, partial, future, or
weakened layouts fail closed. Initialization refuses every existing database;
there is no implicit upgrade or ordinary-startup hook. This is storage
reservation evidence, not a consumer transaction, replay decision, retention
policy, or operational migration.

## 6. Synthetic conformance oracle

`tests/test_suricata_consumer_contract.py` validates the closed schema and
fixtures with local-only references. Its in-memory SQLite oracle models the
future transaction boundary and proves:

- an exact two-record publication commits once;
- the implemented reader's immutable publication is accepted directly;
- a duplicate identity is rejected without new rows;
- an attempt-ID collision for a different run is not misclassified as replay;
- a capacity, deadline, or failed-begin refusal never claims a rollback;
- an injected pre-commit failure rolls back registry and alert rows together;
- a simulated lost acknowledgement after commit produces only
  `reconciliation_required` until explicit readback; and
- a retry before reconciliation cannot duplicate the batch.

The oracle is test code, not a reusable database layer. Production code must not
import it, and its passing tests are not runtime, migration, installed-Suricata,
operational, release, or deployment evidence.

From the repository root:

```bash
python -m pytest -q \
  tests/test_suricata_contract.py \
  tests/test_suricata_formats.py \
  tests/test_suricata_reader_contract.py \
  tests/test_suricata_consumer_contract.py \
  tests/test_suricata_store.py
python -m compileall -q megalodon tests
python -m pytest -ra
```

## 7. Next gate

A runtime consumer requires a separate issue and PR. That work must use this
exact reserved schema, implement fixed diagnostics and capacity/deadline
behavior, prove rollback and commit-unknown reconciliation under injected
failures, preserve database identity and private permissions, and pass
exact-head review. Dashboard projection remains a later read-only slice.
