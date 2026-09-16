# Read-only Suricata consumer reconciliation contract v1

**Status: IMPLEMENTED EXPLICIT READ-ONLY API.**

`megalodon.offline.suricata_consumer.reconcile_publication` resolves the
durable disposition of one consumer attempt that previously returned
`reconciliation_required`. The operator must supply the exact immutable reader
publication and the exact consumer attempt identifier. The consumer never calls
this API automatically.

The operation admits only Linux, non-root, capability-free execution before any
store access. It opens the explicitly selected, already owner-private v1 store
through a descriptor-pinned SQLite `mode=ro`, `query_only` connection. It does
not create a database or sidecar, repair permissions, migrate schema, retry a
transaction, complete partial evidence, retain or delete rows, launch Suricata
or another process, use a network or model, mutate a dashboard, or execute a
response action.

Reconciliation first holds a nonblocking Linux open-file-description read lock
over SQLite's complete PENDING, RESERVED, and SHARED locking region on the
pinned read-only descriptor. Existing writers fail closed, and no writer or
journal-mode transition can start before the descriptor closes. While that lock
is held, reconciliation requires the initialized rollback-journal database
header and no coordination sidecars before SQLite opens the file. A persistent-
WAL header is refused before SQLite can create `-wal` or `-shm` in the writable
owner directory.

## Result invariant

The result vocabulary is closed:

| Disposition | Required proof |
| --- | --- |
| `committed` | One exact run identity and attempt ID plus the complete ordered normalized-alert sequence and byte-exact canonical terminal consumer receipt |
| `not_committed` | One validated read snapshot in which both the exact run identity and exact attempt ID are absent |
| `indeterminate` | Every lock, deadline, replacement, sidecar, permission, schema, corruption, collision, malformed row, read, or identity ambiguity |

The two absence queries and every exact-evidence query run inside one read-only
SQLite snapshot. A partial match is never absence. A run under another attempt,
an attempt attached to another run, missing or altered alerts, or a changed
stored receipt is `EVIDENCE_AMBIGUOUS` and `indeterminate`.

## Fixed resource and authority boundary

Open, exact-schema validation, lock waiting, query execution, and final
descriptor verification share the consumer-owned 30,000 ms monotonic
cooperative deadline. The limit is not caller tunable. SQLite VM work uses a
progress handler and each lock wait is rebound to the remaining deadline. A
single kernel or filesystem call may return late; a late return cannot produce
`committed` or `not_committed`.

All diagnostics are fixed codes in the reconciliation receipt. The receipt
retains `action_status=not_attempted`; reconciliation conveys evidence only and
grants no write or response authority.

## Conformance

`schema.json` closes the policy and result shapes. The fixtures cover all three
terminal dispositions and reject extra fields, contradictory states, caller
limits, and side-effect authority. `tests/test_suricata_reconciliation.py`
exercises lost acknowledgement, proven rollback/absence, collisions, damaged
evidence, schema drift, locks, deadlines, replacement, permission refusal, and
real SQLite read-only behavior.

Passing these tests does not prove installed-Suricata compatibility, raw-EVE
conversion, sensor operation, dashboard projection, release readiness, or
independent review. Those remain separate gates.
