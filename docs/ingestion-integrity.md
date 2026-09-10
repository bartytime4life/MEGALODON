# Ingestion integrity and reconciliation

Status: implemented Stage 0 integrity slice for issue #67. This is a local audit
property, not production approval, continuous-monitoring proof, alert delivery,
or authority to change the host. Independent review under issue #3 and finite
whole-service resource controls under issue #68 remain separate gates.

## Commit boundary

For each accepted metadata event, `MegalodonService.process()` now follows one
ordered boundary:

1. validate the event and prepare detector results with a bounded reversible
   mutation journal;
2. build one non-executing policy-plan `ActionRecord` for every detection;
3. commit the event, run/event link, all detections, all actions, each
   detection/action link, and all three run counters in one SQLite transaction;
4. only after that commit succeeds, install the prepared detector state; and
5. only after both steps succeed, emit detection log messages.

An insert, trigger, constraint, or counter-update failure rolls the whole event
bundle back. It cannot leave a run-scoped event without its detections/actions,
and it cannot consume a detector window, source high-water mark, LRU position,
or alert cooldown. The legacy low-level methods remain for standalone tests and
manual plan receipts, but `record_event(..., run_id=...)` and a later
`record_detection()` against a run-linked event fail with
`INGESTION_RUN:ATOMIC_WRITE_REQUIRED`.

The bundle API accepts only concrete list/tuple collections with equal lengths,
typed records, and at most three detections/actions—the closed number of fixed
Stage 0 rules. It rejects a generator or oversized collection before iteration
or database mutation, so the transaction boundary is not an unbounded
materialization surface.

Preparation does not copy a source's whole SYN/port deque. It appends and trims
provisionally, retaining references only to entries removed by that event, the
exact pre-event values of touched port-frequency keys, and the prior values of
changed cooldown keys. Deque mutation bookkeeping detects an interruption on
either side of append/removal, so rollback restores the exact queue and Counter
state. Success discards the journal, touches the source LRU, and advances the
high-water mark. Successful window maintenance is therefore amortized rather
than O(window); a failure pays only to restore work performed for that event.
Only one unresolved preparation is permitted per detector. The service
serializes prepare/resolve; overlapping direct or reentrant preparation is
refused before another provisional mutation. The detector retains the matching
handle until resolution, allowing the service to roll it back even if a handled
signal arrives after `prepare()` returns but before the caller receives it.

This is **per-event atomicity**, not a whole-run transaction. Earlier committed
events remain evidence if later input fails. It is also not exactly-once input
delivery: the program does not assign upstream event IDs, retry an ambiguous
event, or deduplicate replays.

## Schema v3

SQLite `user_version = 3` adds:

- closed, versioned run-receipt states and terminal reasons;
- an action counter maintained with each accepted event decision; and
- `detection_actions`, a one-to-one link between a detection and the policy
  decision created for it.

Standalone firewall-plan actions are intentionally allowed to remain unlinked
and are not counted in an ingestion run. Counts are never inferred from those
standalone rows.

New version-3 receipts use this matrix:

| Status | Termination reason | Failure code | Meaning |
| --- | --- | --- | --- |
| `running` | `NULL` | `NULL` | Started, with no durable terminal decision |
| `completed` | `source_exhausted` | `NULL` | The selected iterator ended naturally |
| `incomplete` | `event_limit_reached` | `NULL` | The operator limit stopped intake after its Nth accepted event |
| `failed` | `interrupted` | `INTERRUPTED` | A handled SIGINT/SIGTERM interruption reached finalization |
| `failed` | `failed` | fixed class | Capture, I/O, storage, or validation failed |
| `reconciliation_required` | `reconciliation_required` | `NULL` | Completion cannot be asserted; inspect preserved evidence |

`processed_count`, `detection_count`, and `action_count` advance in the same
transaction as the rows they describe. Finalization re-derives all three counts
from links. On a mismatch, the committed evidence rows remain unchanged, the
receipt counters are corrected to those rows, and the anomaly is classified
`reconciliation_required`; it is never reported as completed or silently
overwritten with a requested success reason.

## Migration boundary

Ordinary startup never migrates. `database-migrate` accepts only an exact v1,
unversioned-v1, or v2 schema and creates a verified sibling
`<database>.pre-v3.bak` before changing the source. It never overwrites an
existing backup. The backup must pass `quick_check`, version validation, and the
exact source-schema contract. The migration then uses one exclusive transaction,
validates the final exact schema and foreign keys, sets `user_version = 3`, and
commits. A migration-stage failure rolls back the source and retains the
verified backup.

Version-2 receipts are copied with `receipt_version = 2`, their original status,
timestamps, counters, and failure code, and a `NULL` termination reason. In
particular, an old `completed` value is **not** rewritten to
`source_exhausted`: the old CLI also used `completed` after an event limit, so
that inference would invent evidence. An old `running` row remains visible for
explicit reconciliation.

## Ambiguous commits and orphaned runs

SQLite can report a commit failure without letting this process prove whether
the commit became durable. The store therefore poisons that open writer and
returns only `INGESTION_RUN:RECONCILIATION_REQUIRED`. It does not retry and does
not advance detector state. Stop using that connection, preserve the database
and sidecars, and reopen before inspection.

A hard kill, power loss, or terminal-receipt failure can also leave a `running`
row. Store construction remains available for inspection, but a new run uses
`BEGIN IMMEDIATE` and refuses while any receipt is still `running`. This also
serializes concurrent attempts so two CLI writers cannot both create active run
receipts.

After stopping every ingestion process, list bounded metadata-only candidates:

```bash
python -m megalodon database-reconciliation-status --config settings.toml
```

The reconciliation commands require an existing exact v3 database. They do not
create a directory, database, schema, or migration as a side effect of inspection.

Then pin the exact run ID and `started_at` value returned by that readback:

```bash
python -m megalodon database-reconcile 7 \
  --started-at 2026-09-10T12:34:56.000000+00:00 \
  --config settings.toml
```

The write checks both fields in its transaction, re-derives linked counts,
preserves every committed row, and marks only that running receipt
`reconciliation_required`. Repeating the exact operation is idempotent. A stale
timestamp or a different terminal state is refused. Reconciliation does not
claim whether the last input was processed and does not authorize replay.

`reconciliation_required` is a terminal, evidence-preserving integrity
classification in this slice, not an active-writer state and not an alert
acknowledgement workflow. It does not block a later run and is retained in
readback for operator visibility. Because readback is capped at 100 rows, any
`running` receipt is ordered before historical reconciliation classifications;
old rows therefore cannot hide the run that is blocking new intake, and the
remaining capacity shows the most recent preserved classifications. There is
no `resolved` transition here: ownership, acknowledgement, and
evidence-disposition state belong to a separately reviewed alert/incident
lifecycle.

## CLI completion semantics

- Natural iterator exhaustion records `completed/source_exhausted`.
- `--max-events N` records `incomplete/event_limit_reached` immediately after
  the Nth accepted event. It does not peek at or discard the next live event.
- A malformed suffix behind an event limit remains unread; the run is incomplete,
  not falsely complete and not falsely failed.
- A malformed record that intake reaches records `failed/failed` with the fixed
  `CAPTURE_ERROR` class.
- A handled SIGINT returns 130 and a handled SIGTERM returns 143 after recording
  `failed/interrupted` when finalization succeeds.
- A hard kill or ambiguous terminal write can leave `running`, which blocks the
  next run until explicit reconciliation.

Diagnostics and shared receipts contain only closed status values, fixed failure
classes, timestamps, counts, and source names. They do not include packet
payloads, input paths, raw exceptions, credentials, or database paths.

## Deliberate limits

This slice does not add a scheduler, notifier, alert acknowledgement/resolution
lifecycle, Suricata runtime importer, network lookup, firewall application,
automatic retry, process lease, storage quota, retention job, or distributed
coordination. A crash after the SQLite commit but before detector-state commit
can cause a fresh process to rebuild state only from later inputs; the database
rows remain truthful, but no exactly-once detector continuity is claimed.

Synthetic tests exercise stage-by-stage rollback, action linkage, run-counter
atomicity, detector retry behavior, unknown commit poisoning, bounded orphan
readback, pinned/idempotent reconciliation, concurrent-start refusal, truthful
event-limit/exhaustion receipts, and exact v1/v2-to-v3 backup migration. They do
not substitute for physical disk-loss, power-loss, OS signal, or native Windows
ACL acceptance.
