# SQLite backup and restore-to-new-destination contract

Status: **Contract delivered on `main` by merged PR #271; a bounded standalone runtime engine now implements it (not wired into the CLI, dashboard, `storage.py`, or `service.py`).**

Issue [#256](https://github.com/bartytime4life/MEGALODON/issues/256), M01.
The contract was prepared from
`main@2e5099fcec2d1a08007efab70b4607cd5ba652ac` after the bounded
repository-currentness tool validated that commit and tree. That receipt does
not supply owner acceptance, independent review, release authority, or native
recovery evidence.

Delivery readback on 2026-09-17: PR #271 merged as
`77f082a0548e64f97090c94dd11503a68ca05d99`. Issue #256 remains open;
contract delivery does not establish runtime recovery or maintainer acceptance.

## Implemented engine

[`megalodon/sqlite_recovery.py`](../megalodon/sqlite_recovery.py) implements
`backup_database` and `restore_backup` against this contract: SQLite's
online-backup API only (never an ordinary file copy), a descriptor-safe
owner-private source/artifact open, an exclusively created owner-private
destination that is never overwritten or restored in place, a full
`PRAGMA integrity_check` plus `PRAGMA foreign_key_check` on both sides before
any success claim, and exactly one closed terminal receipt validated in
[`tests/test_sqlite_recovery_engine.py`](../tests/test_sqlite_recovery_engine.py)
against this directory's own `schema.json`. It is a standalone Python API a
caller invokes with explicit paths; it adds no CLI subcommand, API route,
dashboard control, timer, watcher, service, or scheduler, and no other module
in `megalodon/` imports it. `MAX_BUSY_RETRIES` remains a policy constant only:
CPython's `sqlite3` module does not expose a per-step busy-retry count, so
this implementation bounds the whole operation by the monotonic deadline
instead of counting retries separately. A destination created but not
verified complete is always left in place; nothing here ever deletes it.

## Outcome and authority boundary

The contract closes the vocabulary and evidence shape needed before code may
back up the schema-v3 local audit database or restore a reviewed backup into a
new database. It does not:

- add a CLI, API, dashboard control, timer, watcher, service, or scheduler;
- copy, open, create, delete, migrate, repair, or restore any runtime database;
- select a retention period or delete an incomplete artifact;
- authorize network access, remote storage, credentials, release, or deployment;
- prove POSIX crash, disk-full, power-loss, or Windows ACL behavior.

The existing v1/v2 migration backup remains a separate migration safeguard.
It is not the general recovery flow specified here.

## Fixed v1 bounds

| Control | Contract value |
| --- | --- |
| Source and artifact ceiling | 4 GiB each |
| Free-space reserve after the planned artifact | 16 MiB |
| Monotonic operation deadline | 300,000 ms |
| Busy/lock retries | at most 60 |
| SQLite backup step | at most 1,024 pages |
| Supported application schema | exactly SQLite `user_version = 3` |
| Destination | new, nonexistent, owner-private, single-link regular file |
| Copy mechanism | SQLite online-backup API only |
| Success checks | full integrity plus foreign-key check |
| Digest scope | reviewed backup artifact and bounded manifest only |

The 4 GiB ceiling matches the current maximum configured audit-store
high-water setting. A later implementation must prove that page-count and byte
accounting fit this ceiling before creating a destination; it must not silently
raise the limit.

## Future operator runbook

These are requirements for a later implementation, not commands available now.

1. Record one explicit operator request and a unique bounded operation ID.
2. Admit the source through the same trusted-ancestry, ownership, mode,
   regular-file, single-link, descriptor/path identity, schema-v3, integrity,
   and foreign-key boundaries used by the audit store.
3. For backup, use SQLite's online-backup API so committed WAL state is copied
   coherently. Never copy a live database plus WAL/SHM files with ordinary file
   operations.
4. For restore, first validate the selected artifact digest and manifest.
   Restore only into a new path; never overwrite or restore in place.
5. Before destination creation, prove the configured byte ceiling and free
   reserve. Create the owner-private destination exclusively, bind its
   descriptor identity, and refuse collision, symlink, FIFO, device, hardlink,
   or unsafe ancestry.
6. Copy in bounded page steps under a monotonic deadline and retry ceiling.
   Wall-clock timestamps are recorded as untrusted operator-clock context.
7. Recheck source and destination identity, schema version, page count, logical
   bytes, full `integrity_check`, and `foreign_key_check`.
8. Digest only the completed backup artifact and bounded manifest. Never hash
   packet payloads or raw telemetry merely to place them in a receipt.
9. Emit exactly one closed terminal receipt. Uncertainty, interruption, clock
   rollback, or incomplete verification is failure, never success.
10. Leave any incomplete created destination preserved for operator review.
    This v1 contract grants no automatic deletion or cleanup authority.

Restore requires all MEGALODON writer and dashboard processes to be stopped
before the new store is selected for later use. Creating a valid destination
does not change configuration or activate it.

## Closed reason codes

| Reason | Meaning |
| --- | --- |
| `COMPLETED` | Every success condition and post-copy check passed |
| `INPUT_INVALID` | Request or bounded manifest failed closed validation |
| `SOURCE_UNAVAILABLE` | Required source could not be opened/read |
| `SOURCE_UNSAFE` | Source ancestry or file type was unsafe |
| `SOURCE_NOT_PRIVATE` | Required owner/mode/link boundary failed |
| `SOURCE_IDENTITY_CHANGED` | Path and held descriptor stopped naming the same source |
| `SCHEMA_INCOMPATIBLE` | Application or SQLite structure/version was unsupported |
| `SOURCE_CORRUPT` | Source integrity verification failed |
| `DESTINATION_UNSAFE` | Destination ancestry or created object was unsafe |
| `DESTINATION_EXISTS` | Exclusive new-destination creation found a collision |
| `SAME_FILE_REFUSED` | Source and destination resolved to the same object |
| `LOCK_TIMEOUT` | Busy/lock retry ceiling was exhausted |
| `DEADLINE_EXCEEDED` | Monotonic operation deadline expired |
| `DISK_RESERVE_INSUFFICIENT` | Artifact plus required reserve would not fit |
| `ARTIFACT_LIMIT_EXCEEDED` | Planned or observed artifact exceeded 4 GiB |
| `ARTIFACT_CORRUPT` | Backup artifact failed digest or integrity verification |
| `FOREIGN_KEY_VIOLATION` | Full foreign-key check returned one or more rows |
| `CLOCK_ROLLBACK` | Wall clock moved backward during the operation |
| `INTERRUPTED_BEFORE_CREATE` | Operation stopped before destination creation |
| `INTERRUPTED_AFTER_CREATE` | Operation stopped after creating an incomplete destination |
| `CLEANUP_FAILED` | A future implementation could not safely disposition its incomplete artifact; preserve it |
| `COMPLETION_UNCERTAIN` | Commit/copy outcome could not be proven |
| `IO_ERROR` | Bounded local I/O failed without a more specific closed reason |

## Fault matrix

| Fault | Required receipt and disposition | Claim withheld |
| --- | --- | --- |
| WAL changes during backup | Use online-backup snapshot semantics; identity and checks must still pass or fail closed | No claim that ordinary copies are coherent |
| Lock contention | `LOCK_TIMEOUT` after at most 60 retries; no success receipt | No unbounded waiting guarantee |
| Monotonic deadline | `DEADLINE_EXCEEDED`; preserve any incomplete destination | No whole-kernel-stall guarantee |
| Disk full or reserve shortfall | `DISK_RESERVE_INSUFFICIENT` or `IO_ERROR`; never redirect/upload | No native disk-full acceptance |
| Interruption before destination creation | `INTERRUPTED_BEFORE_CREATE`, destination not created | No retry or scheduling |
| Interruption after destination creation | `INTERRUPTED_AFTER_CREATE`, incomplete destination preserved | No automatic cleanup |
| Corrupt backup | `ARTIFACT_CORRUPT`; never select it for restore | No repair |
| Wrong schema/version | `SCHEMA_INCOMPATIBLE`; source unchanged | No migration |
| Foreign-key failure | `FOREIGN_KEY_VIOLATION`; never report completed | No partial acceptance |
| Wall-clock rollback | `CLOCK_ROLLBACK`; monotonic duration retained | No trusted-time claim |
| Cleanup/disposition failure | `CLEANUP_FAILED`; incomplete artifact preserved for operator review | No deletion authority |
| Uncertain copy/commit outcome | `COMPLETION_UNCERTAIN`; destination state unknown | No success or activation |

## Validation and next gate

From the repository root:

```bash
python -m compileall -q megalodon tests
python -m pytest tests/test_sqlite_recovery_contract.py
python -m pytest tests/test_sqlite_recovery_engine.py
python -m pytest -ra
```

The focused contract suite validates the schema, all accepted/rejected
fixtures, the exact reason registry, cross-field receipt invariants,
documentation coverage, packaging, and that no *other* module references this
contract yet. The engine suite exercises `megalodon/sqlite_recovery.py`
directly against real SQLite files: a full backup/restore round trip with
content and non-mutation verification, every failure reason reachable without
special privileges, and every produced receipt validated against this
directory's `schema.json`. Neither suite performs a database backup or
restore against any real MEGALODON audit store; both operate only on paths
explicitly passed to them.

Wiring this engine into a CLI subcommand, API route, or scheduled operation
remains a separate, not-yet-reviewed change requiring its own explicit
decision, native failure-injection evidence (crash, disk-full, power-loss),
exact-head CI, and independent or owner acceptance. Existence of the engine
does not authorize that wiring or close those gates.
