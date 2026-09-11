# Audit-write failure and retention boundaries

Status: implemented per-event ingestion transaction handling plus standalone
write regression coverage. [Issue #28](https://github.com/bartytime4life/MEGALODON/issues/28) is
closed as a documentation/test gate; operator retention choices and operational
acceptance remain OPEN. This is not production approval. The [specification](../SPECIFICATION.md) and
[security review](../SECURITY_REVIEW.md) remain authoritative.

Current repository interpretation: one service event, all of its detections,
one policy-plan action per detection, their links, and run counters commit or
roll back in one transaction. Detector state is staged and advances only after
that commit succeeds. Standalone low-level writes retain their narrower
transaction boundary. These properties do not select a retention policy or
prove exactly-once ingestion, power-loss durability, or continuous operation.
The remaining operator-policy and operational-failure decisions are not closed
by issue lifecycle state.

## Capacity high-water stop

The writer `Store` accepts a bounded `max_database_bytes` setting. The checked-in
configuration defaults to 256 MiB and operators may select another value between
1 MiB and 4 GiB. The guard measures the private SQLite main database plus any
`-wal`, `-shm`, and rollback-journal sidecars through the already-verified
database directory. Before each event-bearing write, it rechecks identity under
the store lock and refuses the write with the fixed
`STORAGE_CAPACITY:HIGH_WATER` error when the observed size plus a bounded
256 KiB one-write reserve would cross the configured budget. No event transaction
is opened, no row ID is returned, and the writer does not purge, redirect,
compress, upload, or silently discard evidence. Run-finalization writes remain
available so a capacity-stopped intake can record a failed terminal receipt.

This is a preflight high-water control, not proof against a physical disk-full
condition or a guarantee that filesystem growth cannot race the next write.
The existing SQLite rollback and uncertain-commit handling remains authoritative;
a native storage-exhaustion test is still not a physical disk or power-loss test.

The application schema is explicitly marked as SQLite `user_version = 3`.
Startup validates the closed set of application tables and indexes, rejects
additional non-internal tables, indexes, triggers, and views, and checks the
normalized declared DDL, column, foreign-key, required-index, primary-key, and
uniqueness shape before enabling WAL. A fresh database is created atomically.
Exact v1, unversioned-v1, and v2
layouts fail with `STORAGE_SCHEMA:MIGRATION_REQUIRED`; they are not changed by
ordinary startup. Partial, altered, extended, unsupported, and future layouts
also fail closed with fixed schema errors instead of being repaired or downgraded.

The explicit `database-migrate` command is the only v1/v2-to-v3 path. Run it with all
other MEGALODON processes stopped. On POSIX, the database must be in an
operator-owned mode-`0700` directory, and the source must be an owner-private,
regular, single-link database (normally mode `0600`). The migration refuses
symlink sources, hardlinks, public modes, unsafe sidecars, and missing files,
opens the source and newly created
backup with no-follow descriptors, and keeps those descriptors bound through
SQLite backup and validation. It fails if either pathname stops identifying its
opened file. The command creates a sibling `<database>.pre-v3.bak` without
overwriting any existing path, verifies it with SQLite `quick_check` and the
matching v1 or v2 structural contract, checks that the source did not change,
and applies the schema migration and version marker in one transaction. A pre-migration
failure removes only the backup path that still identifies the file it created;
a migration-stage failure rolls back the source and retains the verified backup.
POSIX creation uses mode 0600. Writer and reader startup require a stable
descriptor-backed SQLite path through `/proc/self/fd` or `/dev/fd`; absence is a
fixed refusal. Path ancestors must be owned by root or the runtime user and must
not be group/world-writable unless a trusted sticky directory prevents another
user from renaming the next entry. Windows confidentiality and replacement
resistance remain part of the separately unverified private-directory/NTFS ACL
control. Re-running against v3 is an idempotent no-op. Version-2 run receipts
retain their original state with `receipt_version = 2` and a null reason; the
migration does not invent source exhaustion for an ambiguous legacy completion.

## Dashboard read isolation

`DashboardStore` is separate from the writer `Store`. It requires an existing
schema-v3 database and never creates a directory/database, initializes or
migrates schema, changes `user_version`/journal mode, or exposes a write method.
On POSIX it anchors and rechecks the private parent and regular single-link
database descriptors, and validates any WAL/SHM coordination files before and
after reads. A missing, unsafe, linked, corrupt, replaced, or incompatible store
is refused before serving with a fixed, path-free error. Native NTFS ACL and
replacement evidence remains open under issue #27. Supported POSIX serving also
requires `/proc/self/fd` or `/dev/fd`; an environment without either stable
descriptor path receives `DASHBOARD_STORE:DESCRIPTOR_PATH_UNAVAILABLE`.

When no sidecars are observed, startup uses a short-lived
`mode=ro&immutable=1` connection only to validate the static schema without
creating WAL/SHM. This is not a quiescence claim: a writer starting during the
descriptor-path connect or changing entries after the stable generation sample
causes refusal; a writer accepted between those points is revalidated through
the later normal connections. The immutable connection is never used for served
data. An unserved normal connection next
establishes any required WAL/SHM files and validates them as private, regular,
single-link files. While that connection remains open, startup opens the final
`mode=ro&cache=private` connection. Before any schema query, SQLite's
`database_list` must report the configured private path for the held database
descriptor. Final schema validation, closing the coordination connection, and
every served read must preserve the same parent directory-entry generation and
path/descriptor identity. Use a dedicated database directory: any entry-level
change, including an unrelated file rename, forces restart rather than letting
SQLite retain an unlinked main or sidecar file.

The served connection enables `PRAGMA query_only=ON` and installs a
deny-by-default SQLite authorizer. It permits only `SELECT`, `count`, and reads
of the summary inputs or the five public detection columns; it denies `ATTACH`,
DDL/DML, write PRAGMAs, internal row-ID reads, and private-column reads. SQLite
3.22.0 is the minimum because that release added supported read-only WAL access.

Summary counts are four scalar counts in one `SELECT`, hence one SQLite read
snapshot. Recent detections select exactly `detected_at`, `rule_id`, `severity`,
`src_ip`, and `message`, ordered by the indexed public `detected_at` field;
private destination/evidence/recommendation/suppression columns and internal IDs
are neither selected nor decoded. Successful WAL reads can create private
coordination entries during the unserved startup step and can later update their
contents in the already verified directory. They do
not mutate the main database, schema, version, journal mode, or application
rows. Missing or incompatible no-sidecar databases and unsafe symlink paths are
refused without creating WAL/SHM. A runtime identity, sidecar, or directory
generation refusal returns a fixed generic HTTP `503`; it does not disclose the
diagnostic cause or configured path to the browser.

`/api/summary` and `/api/events` are separate reads, not a shared SQLite
snapshot. A browser comparison of successive `high_or_critical` summary totals
is not an ingestion receipt, unique-alert count, or terminal alert lifecycle;
[#67](https://github.com/bartytime4life/MEGALODON/issues/67) now has this
per-event integrity slice, but exact-head review remains a gate and no durable
alert lifecycle follows. The 200-row API ceiling and 12-bin browser timeline bound
only this projection and do not close the detector/capture/storage resource gate
in [#68](https://github.com/bartytime4life/MEGALODON/issues/68).

The success receipt reports only the fixed backup state `created`, not the
configured filesystem path. The operator can derive the local sibling name from
the reviewed configuration and fixed `.pre-v3.bak` suffix without copying a
personal or case directory into shared logs.

Retain the backup until operational verification. To recover, stop all MEGALODON
processes, preserve the failed database and its `-wal`/`-shm` sidecars for
investigation, copy the backup to a new private path, and point a reviewed config
at that copy. Run `database-migrate` on the copy if it is v1 or v2, then point the
reviewed runtime config at the migrated copy. Do not overwrite either database in
place. This repository does not automatically restore, delete, rotate, upload, or
claim secure erasure of backups.

## What a successful write means

`Store.record_event_bundle()` holds the store lock from `BEGIN IMMEDIATE` through
one explicit commit. The transaction inserts one event, its run association, all
detections, one action decision for each detection, each detection/action link,
and increments processed/detection/action counters. Any exception before commit,
including an interruption, rolls the transaction back. A success row ID is
returned only after commit.

`MegalodonService.process()` serializes detector evaluation and uses a bounded
undo journal for provisional window, exact port-frequency, and cooldown
changes; it does not copy or traverse a whole source port window per event.
Only one unresolved preparation is allowed, and reentrant preparation is
refused. High-water and source-LRU changes wait for commit. Removing a synthetic
storage fault and retrying the same event therefore produces the same decision;
the failed attempt did not consume state.
Policy planning remains non-executing and may run before persistence, but no host
action is authorized or applied.

Do not convert an exception into an audited-success receipt or retry blindly.
If commit outcome is uncertain, the writer is poisoned and returns the fixed
`INGESTION_RUN:RECONCILIATION_REQUIRED` result. No later write is accepted on
that connection. After reopen, bounded readback exposes `running` and already
classified receipts; an exact run-ID/started-at operation can preserve its rows,
re-derive counts, and mark it `reconciliation_required`. It cannot label the run
complete or decide whether an upstream event should be replayed.

Run finalization re-derives all three counters from run, detection, and action
links. A mismatch becomes `reconciliation_required`, never the requested
terminal success. Once terminal, those counters are historical ingestion
receipts and are not decremented by later use of the internal retention hook.
Natural source exhaustion, operator event limit, interruption,
and failure have distinct closed reasons. These guarantees are per event, not
one transaction for a whole run. There is no upstream ID, automatic retry,
duplicate suppression, or exactly-once recovery. A crash after database commit
but before detector-state commit can lose in-memory continuity on restart. No
software receipt here guarantees survival of power loss or faulty storage. See
[ingestion integrity and reconciliation](ingestion-integrity.md) for the exact
state matrix and operator sequence.

## Retention decision matrix

These are two independent policy decisions. Neither currently has an operator-
selected duration or byte budget, and a decision for one row does not authorize
the operation in the other.

| Data class | Included evidence | Cutoff/budget basis | Authorized surface today | Required operator decision |
| --- | --- | --- | --- | --- |
| Live SQLite audit | `events`, `detections`, `actions`, plus the database's WAL/SHM sidecars | One timezone-aware cutoff normalized to UTC; separate finite database/disk stop budget | Configured `Store` high-water intake stop plus internal atomic `Store.purge_before()` hook; no CLI, timer, preview receipt, or automatic purge call | Retention duration, capacity threshold, intake-stop point, backup interaction, owner, review/confirmation and recovery procedure |
| Standalone offline reports | One complete private `offline-run-v1` report set and its fixed files | Case/run policy based on completion and operator inventory; never SQLite row timestamps | No deletion API, filesystem sweep, scheduler, or dashboard control | Retention duration, case closure authority, storage budget, backup/export relationship, exact selected run sets and recovery procedure |

Any future preview must bind the data class, canonical store identity, UTC cutoff,
relevant row/file inventory, and a freshness token that can be checked immediately
before deletion. Because SQLite can change after a count and files can be replaced,
an unbound count or path list cannot authorize later deletion. The destructive
operation and confirmation protocol remain a separately authorized code slice.

## Failure behavior matrix

| Failure | Required observable outcome | Recovery boundary |
| --- | --- | --- |
| Configured SQLite high-water | The preflight raises before the event transaction; no row ID or success receipt is returned and prior committed rows remain truthful | Stop intake, preserve the store, review the budget or retention decision, then reopen/verify before resuming |
| SQLite page budget / physical storage exhaustion | The failing write raises; no row ID or success receipt is returned; prior committed rows remain truthful | Stop intake, preserve the store, free or provision reviewed local capacity, then reopen/verify before resuming |
| Database open/create permission denial | Initialization raises and no usable `Store` is returned | Correct the selected private location/permissions outside MEGALODON; no fallback directory or upload |
| Bundle statement failure | The event, detections, actions, links, and counters all roll back; detector state does not advance | Investigate the fixed failure class; do not retry until input identity and policy permit it |
| Commit outcome uncertain | No clean-state claim; the writer is poisoned and the run remains discoverable | Stop intake, reopen for bounded readback, and explicitly reconcile the pinned run without replay |
| Handled interruption | The active bundle rolls back and finalization records `failed/interrupted` when possible | SIGINT/SIGTERM handling is not power-loss or kill-proof durability evidence |
| Hard kill, rollback failure, or terminal-write uncertainty | No automatic completion or retry; a `running` receipt blocks a new run | Preserve database and sidecars, stop every writer, then perform exact operator reconciliation |

Diagnostics and shared receipts must remain bounded and metadata-only. They may
name a fixed failure class, counts, UTC cutoff and synthetic test identity, but
must not include audit rows, addresses, packet material, credentials, or personal
paths.

## Reproducible synthetic confirmation

From the repository root in its supported test environment:

```bash
python -m compileall -q megalodon tests
python -m pytest tests/test_storage.py tests/test_storage_failures.py tests/test_storage_schema.py tests/test_dashboard_store.py tests/test_dashboard_binding.py tests/test_cli.py tests/test_ingestion_runs.py
```

The failure suite covers standalone writes plus every event-bundle stage with a
statement failure, an uncertain commit, and SQLite query-only refusal.
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
atomic rollback for initial creation and the v1/v2-to-v3 migration.
The dashboard-store cases cover no-create refusal, private path/object identity,
URI encoding, query-only/authorizer enforcement, incompatible no-sidecar refusal,
exact-field indexed SQL, one-statement summary snapshots, coherent returned
counts when a WAL commit overlaps execution, committed-versus-uncommitted WAL
visibility, a writer starting during immutable preflight, transient public-path
replacement, between-request
sidecar ABA replacement, and fixed browser-facing read failure.
The ingestion-run cases cover source exhaustion, event-limit, interruption, and
failed terminal reasons; event/detection/action provenance; derived counters;
malformed reached and deliberately unread suffixes; stage rollback; detector
retry state; uncertain-commit poisoning; concurrent-start refusal; bounded orphan
readback; target-pinned idempotent reconciliation; and legacy v2 preservation.
They use only synthetic metadata and temporary databases.

The PR execution receipt must separately record its exact head/base, environment,
full-suite result, and independent review state.
Injected permission denial is not an operating-system ACL test; SQLite's page
budget is not a physical disk-full test; progress interruption is not a process
crash or power-loss test. Those native environments remain unproved.

## Retention decisions still required

The operator must separately review finite retention periods and storage
budgets for the SQLite audit database and for standalone offline report sets.
The checked-in writer default is a 256 MiB high-water stop; an operator may
select a different bounded value in configuration before collection. The
high-water stop does not purge rows or sidecars. SQLite/WAL/SHM files are not
offline reports, and permission to remove one class never authorizes deleting
another.
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
- [SQLite URI filenames and `mode=ro`](https://www.sqlite.org/uri.html).
- [SQLite `PRAGMA query_only`](https://www.sqlite.org/pragma.html#pragma_query_only).
- [SQLite read-only WAL behavior](https://www.sqlite.org/wal.html#read_only_databases).
