# Audit-write failure and retention boundaries

Status: implemented per-write transaction handling with synthetic regression
coverage. [Issue #28](https://github.com/bartytime4life/MEGALODON/issues/28) is
closed as a documentation/test gate; operator retention choices and operational
acceptance remain OPEN. This is not production approval. The [specification](../SPECIFICATION.md) and
[security review](../SECURITY_REVIEW.md) remain authoritative.

Current repository interpretation: the write methods close or roll back their
own transaction before returning or propagating an error, and service acceptance
tests preserve detector cooldown across the exercised detection/action audit
failures. Neither property makes the three service stages one transaction or
selects a retention policy. The remaining operator-policy and operational-failure
decisions are not closed by issue lifecycle state.

The application schema is explicitly marked as SQLite `user_version = 2`.
Startup validates the closed set of application tables and indexes, rejects
additional non-internal tables, indexes, triggers, and views, and checks the
normalized declared DDL, column, foreign-key, required-index, primary-key, and
uniqueness shape before enabling WAL. A fresh database is created atomically.
Exact v1 and unversioned-v1
layouts fail with `STORAGE_SCHEMA:MIGRATION_REQUIRED`; they are not changed by
ordinary startup. Partial, altered, extended, unsupported, and future layouts
also fail closed with fixed schema errors instead of being repaired or downgraded.

The explicit `database-migrate` command is the only v1-to-v2 path. Run it with all
other MEGALODON processes stopped. On POSIX, the database must be in an
operator-owned directory that is not group- or world-writable. The migration
refuses symlink sources and missing files, opens the source and newly created
backup with no-follow descriptors, and keeps those descriptors bound through
SQLite backup and validation. It fails if either pathname stops identifying its
opened file. The command creates a sibling `<database>.pre-v2.bak` without
overwriting any existing path, verifies it with SQLite `quick_check` and the v1
structural contract, checks that the source did not change, and applies the
additive table migration and version marker in one transaction. A pre-migration
failure removes only the backup path that still identifies the file it created;
a migration-stage failure rolls back the source and retains the verified backup.
POSIX creation uses mode 0600. Platforms without a stable descriptor-backed
SQLite path still require an operator-controlled private directory and path
identity checks; Windows confidentiality and replacement resistance remain part
of the separately unverified private-directory/NTFS ACL control. Re-running
against v2 is an idempotent no-op.

The success receipt reports only the fixed backup state `created`, not the
configured filesystem path. The operator can derive the local sibling name from
the reviewed configuration and fixed `.pre-v2.bak` suffix without copying a
personal or case directory into shared logs.

Retain the backup until operational verification. To recover, stop all MEGALODON
processes, preserve the failed database and its `-wal`/`-shm` sidecars for
investigation, copy the backup to a new private path, and point a reviewed config
at that copy. Run `database-migrate` on the copy if it is v1, then point the
reviewed runtime config at the migrated copy. Do not overwrite either database in
place. This repository does not automatically restore, delete, rotate, upload, or
claim secure erasure of backups.

## What a successful write means

`Store.record_event()`, `record_detection()` and `record_action()` each hold the
store lock through their SQLite transaction. A method returns its row ID only
after its transaction commits. A statement or commit exception propagates;
the connection context attempts rollback instead of leaving a failed method's
tentative rows available for a later successful call to commit.

Do not convert an exception into an audited-success receipt or retry blindly.
A failure at one stage of `MegalodonService.process()` can leave earlier,
separately committed event or detection rows. These three methods do not form
one all-or-nothing service transaction, and detector state is not rolled back.
There is no new retry, duplicate suppression, recovery service or error ledger.
If SQLite cannot perform rollback, recovery is unproved: stop using the affected
connection and require operator investigation rather than claim clean state.
No software receipt here guarantees survival of power loss or faulty storage.

## Retention decision matrix

These are two independent policy decisions. Neither currently has an operator-
selected duration or byte budget, and a decision for one row does not authorize
the operation in the other.

| Data class | Included evidence | Cutoff/budget basis | Authorized surface today | Required operator decision |
| --- | --- | --- | --- | --- |
| Live SQLite audit | `events`, `detections`, `actions`, plus the database's WAL/SHM sidecars | One timezone-aware cutoff normalized to UTC; separate finite database/disk stop budget | Internal atomic `Store.purge_before()` hook only; no CLI, timer, preview receipt, or automatic call | Retention duration, capacity threshold, intake-stop point, backup interaction, owner, review/confirmation and recovery procedure |
| Standalone offline reports | One complete private `offline-run-v1` report set and its fixed files | Case/run policy based on completion and operator inventory; never SQLite row timestamps | No deletion API, filesystem sweep, scheduler, or dashboard control | Retention duration, case closure authority, storage budget, backup/export relationship, exact selected run sets and recovery procedure |

Any future preview must bind the data class, canonical store identity, UTC cutoff,
relevant row/file inventory, and a freshness token that can be checked immediately
before deletion. Because SQLite can change after a count and files can be replaced,
an unbound count or path list cannot authorize later deletion. The destructive
operation and confirmation protocol remain a separately authorized code slice.

## Failure behavior matrix

| Failure | Required observable outcome | Recovery boundary |
| --- | --- | --- |
| SQLite page budget / storage exhaustion | The failing write raises; no row ID or success receipt is returned; prior committed rows remain truthful | Stop intake, preserve the store, free or provision reviewed local capacity, then reopen/verify before resuming |
| Database open/create permission denial | Initialization raises and no usable `Store` is returned | Correct the selected private location/permissions outside MEGALODON; no fallback directory or upload |
| Statement or commit failure | The active method rolls back and cannot leak a tentative row into the next commit | Investigate the cause; a later write may proceed only after connection/state checks pass |
| SQLite interruption | The active write raises and rolls back | Treat external cancellation, shutdown and physical interruption as distinct; this synthetic case is not power-loss durability proof |
| Rollback or connection integrity unknown | No clean-state claim and no automatic retry | Stop using the connection and require operator recovery/integrity review |

Diagnostics and shared receipts must remain bounded and metadata-only. They may
name a fixed failure class, counts, UTC cutoff and synthetic test identity, but
must not include audit rows, addresses, packet material, credentials, or personal
paths.

## Reproducible synthetic confirmation

From the repository root in its supported test environment:

```bash
python -m compileall -q megalodon tests
python -m pytest tests/test_storage.py tests/test_storage_failures.py tests/test_storage_schema.py
```

The failure suite covers each of the three write methods with a statement
failure, a deferred-constraint commit failure, and SQLite query-only refusal.
It also exercises a real fixed SQLite page budget until `SQLITE_FULL`, an
injected connection permission denial, and SQLite progress interruption. The
transaction cases verify closure, prior-row preservation, visibility from a
separate connection, successful recovery writes and reopened-database counts.
They prevent tentative failed rows being committed by the next call.
Existing aware-cutoff and all-table purge rollback tests are retained unchanged.
Only synthetic temporary databases and fixed test triggers are used.
The schema-lifecycle cases separately cover fresh creation, explicit legacy
migration, required-migration refusal, backup preservation/non-overwrite,
idempotence, partial and altered schema refusal, future-version non-mutation, and
atomic rollback for both initial creation and v2 migration.

The inspected baseline was `a177c13ade3b4a727a0514afac21575fd0f10e08`, with
storage blob `c6b45bea5bf61462dbbeb0f71a281fb49db3e3ca`. All nine new cases
failed on that baseline because a transaction remained open. The corrected
source passes those cases. The PR execution receipt must separately record its
exact head/base, environment, full-suite result and independent review state.
Injected permission denial is not an operating-system ACL test; SQLite's page
budget is not a physical disk-full test; progress interruption is not a process
crash or power-loss test. Those native environments remain unproved.

## Retention decisions still required

The operator must separately choose finite retention periods and storage
budgets for the SQLite audit database and for standalone offline report sets.
No values are selected by this document. SQLite/WAL/SHM files are not offline
reports, and permission to remove one class never authorizes deleting another.
Use explicit timezone-aware UTC-normalized cutoffs; no ambient local timezone,
scheduler, default cleanup, live purge or destructive command is introduced.

A future preview/deletion workflow must define database identity, snapshot and
cutoff binding, stale-preview refusal, exact confirmation, failure recovery and
audit semantics before implementation. Counting rows in a live database does
not by itself bind a later deletion to the same state. Preserve the existing
atomic `purge_before()` hook without exposing it as an operator command here.
Deletion is not a secure-erasure or backup-retention guarantee. Private parent
directories and SQLite sidecars require deployment review; native Windows ACL
acceptance is separately tracked in #27. Stop intake on unresolved storage
failure; do not silently redirect evidence, purge history or upload a backup.

Independent review, physical storage-exhaustion/permission/interruption evidence,
operator policy values and #3 review-control repair remain separate gates.
No timer, filesystem sweep, live database deletion, firewall action or telemetry
sharing is authorized by these tests or this document.

## Transaction semantics references

- [Python 3.11 SQLite connection context manager](https://docs.python.org/3.11/library/sqlite3.html#how-to-use-the-connection-context-manager).
- [SQLite FAIL conflict behavior](https://www.sqlite.org/lang_conflict.html).
- [SQLite deferred foreign-key constraints](https://www.sqlite.org/foreignkeys.html#fk_deferred).
