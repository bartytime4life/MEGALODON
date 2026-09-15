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

- Natural iterator exhaustion records `completed/source_exhausted` after
  owned-source cleanup returns without error.
- JSONL/stdin and Scapy sources require an explicit positive `--max-events N`
  ceiling from 1 through 10,000,000 before the audit store or source is opened.
  The finite repository-owned sample generator may omit it.
- A JSONL iterator accepts at most 65,536 skipped blank/comment lines across the
  full stream. Internal callers may lower this budget; the first excess line
  fails with `CAPTURE_ERROR`, preserves the committed prefix, and leaves the
  suffix unread.
- On supported Linux runtimes, optional `--max-seconds N` values from 1 through 86,400
  arm one process alarm before source acquisition and keep it active through
  iteration, event processing, and owned-source cleanup. Expiry attempts cleanup,
  preserves the committed prefix, and records `failed/failed` with
  `CAPTURE_ERROR`. Unsupported runtimes, unavailable `/proc/self/task`, signal-mask,
  or pending-signal inspection, a blocked or pre-existing pending `SIGALRM`, and more than one OS thread refuse
  the option before configuration, store, or source work; the alarm mask and OS
  thread count are rechecked inside protected setup before handler or timer
  installation. A pending alarm is checked again after arming and dispatched under
  the deadline handler as `CaptureError` if the new deadline already expired.
  Interrupted setup masking or protected pending-signal inspection restores the
  observed mask, interrupted handler installation is restored, and interrupted arming is treated as live until
  teardown cancels it. Interrupted competing-timer restoration is not cancelled
  again. An already active
  process interval timer produces the same pre-I/O
  refusal. The arming return value detects and restores a timer installed after
  preflight while `SIGALRM` is blocked across the handler/timer swap;
  teardown blocks the signal before cancellation and retains the deadline handler
  until the original mask is restored. A deadline dispatched at cleanup-mask
  entry is re-raised only after teardown completes. Cancellation restores the prior handler
  only after disarming succeeds or timer inactivity is confirmed. A failed disarm with a still-live or uninspectable
  timer retains the deadline handler. Threaded Scapy capture refuses the option.
- `--max-events N` stops intake after the Nth accepted event, then records
  `incomplete/event_limit_reached` after cleanup. It does not peek at or discard
  the next live event.
- A malformed suffix behind an event limit remains unread; when cleanup succeeds,
  the run is incomplete, not falsely complete and not falsely failed.
- A malformed record that intake reaches records `failed/failed` with the fixed
  `CAPTURE_ERROR` class.
- A handled SIGINT returns 130 and a handled SIGTERM returns 143 after recording
  `failed/interrupted` when finalization succeeds.
- A hard kill or ambiguous terminal write can leave `running`, which blocks the
  next run until explicit reconciliation.

Diagnostics and shared receipts contain only closed status values, fixed failure
classes, timestamps, counts, and source names. They do not include packet
payloads, input paths, raw exceptions, credentials, or database paths.

## CLI-owned source lifetime

The CLI holds its selected event iterator explicitly. Exhaustion, an event-limit
break, an input failure, a service/storage failure, or a handled interruption
leaves the ingestion block through the same ownership boundary. Its `close()`
method, when present, is invoked before any terminal run write or terminal JSON
output. Closure stays inside the scoped SIGTERM handler and, when selected, the
Linux run-deadline alarm. An iterator without a close method remains supported;
this does not assert that an arbitrary producer has released native resources.

The JSONL file path has two owners: the CLI owns the event iterator, and that
iterator owns the text stream it opens. The file is opened lazily on first
iteration and closed on exhaustion, failure, or explicit early iterator closure.
Closing an unstarted iterator opens nothing. By contrast, stdin is borrowed:
closing the JSONL parser must not close `sys.stdin`. This change does not widen
the existing JSONL line limit, validate a new source format, or add new filesystem
identity/permission guarantees for input files.

### Failure ordering

| Ingestion outcome | Source close outcome | CLI disposition |
| --- | --- | --- |
| Natural exhaustion | Returns normally | Existing `completed/source_exhausted` receipt |
| Event limit | Returns normally | Existing `incomplete/event_limit_reached` receipt; no read-ahead |
| No earlier failure | Ordinary close exception | Fixed `CaptureError`; `failed/failed` with `CAPTURE_ERROR`, exit 2, no success JSON |
| Capture, I/O, validation, or storage failure | Also raises | Preserve the primary exception and its existing failure category; attach one fixed cleanup note at each failing ownership boundary |
| Handled SIGINT/SIGTERM | Also raises | Preserve the interruption path and exit 130/143 when finalization succeeds |
| Reconciliation-required failure | Either | Preserve the refusal; do not retry or write a normal terminal receipt on the poisoned writer |
| No earlier failure | `KeyboardInterrupt` or `SystemExit` during close | Preserve control flow rather than converting it to an ordinary capture failure |

The fixed cleanup diagnostic is
`event source cleanup failed; shutdown is unverified`. It contains no path,
interface, source record, or upstream exception text. `CAPTURE_ERROR` here can
mean a source-lifecycle failure; it is not a security detection and does not mean
that previously committed events were rejected. The existing per-event audit
prefix remains intact. Cleanup failure does not authorize replay, deletion,
reconciliation, a process restart, or another attempt to close the source.

A consumer exception occurs outside its generator. The ownership boundary
therefore preserves it while explicitly closing the generator, rather than
assuming garbage collection will convey the consumer failure into the producer.
`GeneratorExit` used for an ordinary close is not itself treated as a primary
failure: otherwise it could hide an actual file-close failure. A source that
already masked an error internally before returning to the CLI needs its own
producer-side correction; caller ownership cannot recover the lost exception.

Exception notes are not persisted as a new audit field and are not printed by
the CLI's fixed-category error reporter. Standard traceback display can show
notes. Suppressed exception context is still inspectable in memory; it is not
redaction or permission to serialize exception internals. The existing receipt
schema has no separate shutdown-verification field. Historical terminal
receipts also do not establish that this newer ownership boundary executed.

### Validation and remaining limits

`tests/test_cli_source_ownership.py` keeps explicit references to sources and
checks close-before-finalization order, no read-ahead, primary-error identity,
interruption, reconciliation, fixed errors, lazy file opening, nested generator
close failures, borrowed stdin, deadline signal/close ordering, blocked-mask,
OS-thread, and threaded-Scapy refusal, conditional prior-handler restoration,
cancellation failure, and preflight plus
arm-time active-timer refusal. A real subprocess holds stdin open and
verifies that the Linux alarm
interrupts the blocked read into a fixed failed SQLite receipt. Six additional
real CLI/service/SQLite cases verify
that committed prefix counts and links survive failure and that ordinary close
errors cannot produce either a completed or event-limit success receipt. Test
producers are synthetic; no Scapy installation, live capture, socket, DNS lookup,
or installed-environment execution is needed by these tests.

This is deterministic ownership, finite returned-line work, and an opt-in Linux
elapsed deadline—not a portable or native-shutdown receipt. Without
`--max-seconds`, a blocking `next()` or `close()` can still block. Even with the
option, kernel-level uninterruptible sleep and C/native work that prevents Python
signal handling remain outside the proof. Async sniffer death, partial
startup cleanup, bounded stop/join, kernel loss, repeated-signal resilience,
physical disk/power loss, native Windows behavior, and continuous operation
remain outside this correction under issue #68 and the existing acceptance
program. Unexpected programming errors still propagate rather than being
misreported as clean completion; a run left `running` needs the existing
operator reconciliation procedure after all ingestion has stopped.

Python's [context-manager cleanup pattern](https://docs.python.org/3.11/library/contextlib.html#contextlib.closing),
[generator close semantics](https://docs.python.org/3.11/reference/expressions.html#generator.close),
and [exception notes](https://docs.python.org/3.11/library/exceptions.html#BaseException.add_note)
explain the language mechanisms. They do not establish installed-producer or
operational acceptance for MEGALODON.

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
