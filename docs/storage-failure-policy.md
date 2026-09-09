# Audit-write failure and retention boundaries

Status: implemented per-write transaction handling with synthetic regression
coverage; operator retention choices and operational acceptance remain OPEN.
This is a bounded slice of [issue #28](https://github.com/bartytime4life/MEGALODON/issues/28),
not production approval. The [specification](../SPECIFICATION.md) and
[security review](../SECURITY_REVIEW.md) remain authoritative.

Current repository interpretation: the write methods close or roll back their
own transaction before returning or propagating an error, and service acceptance
tests preserve detector cooldown across the exercised detection/action audit
failures. Neither property makes the three service stages one transaction or
selects a retention policy. Issue #28 therefore remains the live operator-policy
and operational-failure gate.

The application schema is explicitly marked as SQLite `user_version = 2`.
Startup validates the exact application table, foreign-key, and required-index
shape before enabling WAL. A fresh database is created atomically. Exact v1 and
unversioned-v1 layouts fail with `STORAGE_SCHEMA:MIGRATION_REQUIRED`; they are not
changed by ordinary startup. Partial, altered, unsupported, and future layouts
also fail closed with fixed schema errors instead of being repaired or downgraded.

The explicit `database-migrate` command is the only v1-to-v2 path. Run it with all
other MEGALODON processes stopped. It refuses symlink sources and missing files,
creates a new sibling `<database>.pre-v2.bak` without overwriting any existing
path, verifies that backup with SQLite `quick_check` and the v1 structural
contract, checks that the source did not change, and applies the additive table
migration and version marker in one transaction. A pre-migration failure removes
the backup it created; a migration-stage failure rolls back the source and retains
the verified backup. POSIX creation uses mode 0600; Windows confidentiality still
requires the separately unverified private-directory/NTFS ACL control. Re-running
against v2 is an idempotent no-op.

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
The CLI run ledger records a bounded terminal failure code and derives counts
from committed run/event associations; it does not make the service stages
atomic or prove the failed input was safe to retry. There is no new retry,
duplicate suppression, or recovery service.
If SQLite cannot perform rollback, recovery is unproved: stop using the affected
connection and require operator investigation rather than claim clean state.
No software receipt here guarantees survival of power loss or faulty storage.

## Reproducible synthetic confirmation

From the repository root in its supported test environment:

```bash
python -m compileall -q megalodon tests
python -m pytest tests/test_storage.py tests/test_storage_failures.py tests/test_storage_schema.py tests/test_ingestion_runs.py
```

The nine write-failure cases cover each of the three write methods with a statement
failure, a deferred-constraint commit failure, and SQLite query-only refusal.
The first six verify transaction closure, prior-row preservation, visibility
from a separate connection, successful recovery writes and reopened-database
counts. They prevent tentative failed rows being committed by the next call.
Existing aware-cutoff and all-table purge rollback tests are retained unchanged.
Only synthetic temporary databases and fixed test triggers are used.
The schema-lifecycle cases separately cover fresh creation, explicit legacy
migration, required-migration refusal, backup preservation/non-overwrite,
idempotence, partial and altered schema refusal, future-version non-mutation, and
atomic rollback for both initial creation and v2 migration.
The ingestion-run cases cover completed and failed terminal transitions,
run-to-event provenance, derived counts, closed sources/failure codes, invalid or
terminal run refusal, malformed JSONL after a valid prefix, storage-write failure,
and interruption without a traceback. They use only synthetic metadata and
temporary databases.

The inspected baseline was `a177c13ade3b4a727a0514afac21575fd0f10e08`, with
storage blob `c6b45bea5bf61462dbbeb0f71a281fb49db3e3ca`. All nine new cases
failed on that baseline because a transaction remained open. The corrected
source passes those cases. The PR execution receipt must separately record its
exact head/base, environment, full-suite result and independent review state.
Query-only refusal is not an operating-system ACL test; deferred constraints
are not a physical disk-full or crash test. Those environments remain unproved.

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

Independent review, actual storage-exhaustion/permission/interruption evidence,
operator policy values and #3 review-control repair remain separate gates.
No timer, filesystem sweep, live database deletion, firewall action or telemetry
sharing is authorized by these tests or this document.

## Transaction semantics references

- [Python 3.11 SQLite connection context manager](https://docs.python.org/3.11/library/sqlite3.html#how-to-use-the-connection-context-manager).
- [SQLite FAIL conflict behavior](https://www.sqlite.org/lang_conflict.html).
- [SQLite deferred foreign-key constraints](https://www.sqlite.org/foreignkeys.html#fk_deferred).
