# SQLite recovery contract v1

Status: **implemented runtime contract** for issue #256. The
`database-backup` and `database-restore` commands produce terminal documents
from this schema; `megalodon/sqlite_recovery.py` provides the standalone engine
and `megalodon/sqlite_recovery_workflow.py` enforces the stricter CLI workflow.

The closed JSON Schema admits exactly five document families:

1. the fixed recovery policy;
2. an explicit operator backup request;
3. an explicit operator restore-to-new-destination request;
4. a completed, fully verified terminal receipt; and
5. a failed terminal receipt with one closed reason.

The accepted fixtures demonstrate both operations and both terminal outcomes.
The rejected fixtures prove that ordinary copying of a live SQLite/WAL set,
overwrite, in-place restore, network access, automatic deletion, raw-telemetry
digests, ambiguous success, and inconsistent failure state are outside the
contract.

Successful receipts require source and destination identity, SQLite and
application schema versions, page counts and logical byte counts, full
`integrity_check`, `foreign_key_check`, a monotonic elapsed time, and
digests for the reviewed artifact and manifest. They disclose no filesystem
path. The digest scope is the backup artifact or bounded manifest only, never
packet payloads, captured telemetry, audit rows, or another raw input.

Failed receipts never become partial success. A created but incomplete
destination is preserved for operator review or marked unknown; this contract
does not authorize deleting it. `COMPLETION_UNCERTAIN` and
`CLOCK_ROLLBACK` must be recorded explicitly.

See [the operator runbook](../../../docs/sqlite-recovery-contract.md)
for the fault matrix, reason-code meanings, validation command, and the
remaining native acceptance gates.
