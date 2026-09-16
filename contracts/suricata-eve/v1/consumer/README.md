# Transactional Suricata durable-consumer contract v1

**Status: PROPOSED CONTRACT AND SYNTHETIC ORACLE ONLY.**

This directory defines the next gate after the implemented bounded Linux reader.
It does not add a production consumer, SQLite migration, command, dashboard
projection, watcher, scheduler, sensor process, network access, or response
action. The future runtime described here is not implemented.

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

A failure before confirmed commit rolls back the entire attempt. If commit may
have succeeded but acknowledgement or readback is lost, the only truthful result
is `reconciliation_required`. The caller must read back the exact attempt and
run identity before retrying. Blind retry after an unknown commit is forbidden;
the uniqueness constraint remains the final replay backstop.

## 3. Receipt states

`schema.json` closes one policy shape and one receipt union:

| Receipt status | Transaction | Durable write | Replay | Meaning |
| --- | --- | --- | --- | --- |
| `committed` | `committed` | `committed` | `recorded` | Exact batch, registry identity, and receipt passed readback |
| `rejected` | `not_started` | `not_attempted` | `duplicate` | Complete run identity already exists |
| `failed` | `rolled_back` | `rolled_back` | `not_recorded` | Pre-commit failure left no durable rows |
| `reconciliation_required` | `unknown` | `unknown` | `unknown` | Commit disposition cannot yet be claimed |

Every receipt keeps `action_status=not_attempted` and uses one fixed failure code
or `null`. Diagnostics are exactly `SURICATA_CONSUMER_V1:<CODE>`, contain no
source data or storage details, and are at most 64 ASCII bytes.

## 4. Fixed limits

The v1 policy inherits the reader publication ceiling: 10,000 alerts and
16,777,216 compact normalized UTF-8 bytes. A future transaction and its required
readback have a fixed 30,000 ms monotonic budget. These are contract limits, not
caller-tunable settings.

The contract requires a capacity check before `BEGIN IMMEDIATE`, but this slice
does not choose a production database schema version, migration number, page
budget, or retention policy. Those belong to the later runtime/migration review.
Ordinary application startup must not create or repair a migration implicitly.

## 5. Synthetic conformance oracle

`tests/test_suricata_consumer_contract.py` validates the closed schema and
fixtures with local-only references. Its in-memory SQLite oracle models the
future transaction boundary and proves:

- an exact two-record publication commits once;
- a duplicate identity is rejected without new rows;
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
  tests/test_suricata_consumer_contract.py
python -m compileall -q megalodon tests
python -m pytest -ra
```

## 6. Next gate

A runtime consumer requires a separate issue and PR. That work must reserve and
migrate the production schema explicitly, implement fixed diagnostics and
capacity/deadline behavior, prove rollback and commit-unknown reconciliation
under injected failures, preserve database identity and private permissions, and
pass exact-head review. Dashboard projection remains a later read-only slice.
