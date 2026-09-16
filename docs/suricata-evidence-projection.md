# Suricata evidence projection v1

`megalodon.suricata_projection.read_suricata_projection(path)` reads one bounded
snapshot from an explicitly selected existing Suricata consumer store. Passing
`None` returns `not_configured` without opening storage. The API returns a
JSON-serializable dictionary and exposes no caller-selectable query, limit,
producer command, source file, write, migration, retention, or response control.

The dashboard may capture this projection once at startup for its separate
Suricata evidence panel. Its immutable HTTP snapshot does not rescan the store
on polling; restart with the same explicit selection to obtain a newer snapshot.
This is stored external signature-alert evidence. It does not report a live
sensor, traffic rate, installed-tool status, core detector result, or successful
MEGALODON block. Producer-reported `blocked` remains an external producer claim;
all projected MEGALODON action states remain `not_attempted`.

## Closed result

The version is `suricata-evidence-projection-v1`. The top-level keys are exactly:

| Field | Meaning |
| --- | --- |
| `schema_version` | Fixed projection version |
| `status` | `available`, `unavailable`, or `not_configured` |
| `failure_code` | Fixed refusal code or `null` |
| `provenance` | `external_suricata_signature_alerts` |
| `action_status` | `not_attempted` |
| `limits` | Fixed query, row, and response limits |
| `summary` | Stored row counts and selected validation counts, or `null` |
| `recent_runs` | At most five validated run summaries |
| `recent_alerts` | At most 50 bounded normalized alert projections |

An unavailable response discards every partial summary, run, and alert. Refusal
codes are `UNSUPPORTED_RUNTIME`, `STORE_UNAVAILABLE`, `INVALID_EVIDENCE`,
`QUERY_TIMEOUT`, and `RESPONSE_LIMIT`. No path, SQLite diagnostic, raw EVE record,
producer rule label/category, payload, or payload-derived hash is exposed.

Available summaries include `stored_runs`, `stored_alerts`,
`validated_recent_runs`, `validated_recent_alerts`, and `shown_alerts`.
The first two are physical table counts in the read snapshot, not claims that
all historical alert content has passed the selected-run projection validation.
The five newest run rows are ordered by database insertion identity, and
alerts by descending run row identity and descending `source_record_index`.
“Recent” therefore means publication order, not newest observation timestamp.

Run summaries retain bounded `run_id`, `sensor_id`, `ruleset_id`,
`declared_version`, `consumer_attempt_id`, and the integer `run_row_id`.
`version_basis` and `ruleset_basis` remain `operator_declared`. Counts are
`alert_count` and `producer_reported_blocked_count`.
Alerts retain the run/sensor association, source index, normalized UTC timestamp,
canonical source/destination IP addresses and ports, TCP/UDP protocol, numeric
rule GID/signature ID/revision/severity, producer-reported action, signature-match
evidence kind, and `not_attempted` action state. Stored IP metadata is local to
the existing loopback dashboard boundary; it is not copied into the public Site.

## Read and integrity boundary

Before storage access, the API requires Linux, a non-root user, and no inherited,
permitted, effective, or ambient capabilities. It reuses the durable consumer's
owner-private directory/database checks, descriptor pinning, exact v1 schema,
foreign-key/integrity checks, 4,096-byte pages, and 512 MiB store ceiling.
It never creates a missing store or normalizes unsafe permissions.

The [reconciliation reader](../contracts/suricata-eve/v1/reconciliation/README.md)
holds a nonblocking Linux OFD read lock over SQLite's complete locking region.
Existing writers are refused; competing writers and journal-mode conversions
cannot proceed while the snapshot owns the lock. Persistent WAL mode and all
coordination sidecars are refused before the SQLite connection opens. The
connection uses `mode=ro`, `query_only`, and a projection-specific deny-by-default
SQL authorizer. A single read transaction covers all counts and rows.

For every selected run, the API checks the complete ordered alert sequence, not
only the 50 visible rows. It reuses consumer identity and alert validators,
requires canonical JSON, contiguous indices, one through 10,000 alerts, and at
most 16,777,216 compact normalized bytes per run. It recomputes alert count,
producer-reported blocked count, and normalized bytes, then requires a byte-exact
canonical committed consumer receipt for the same identity and attempt.
Missing, contradictory, malformed, or altered selected evidence refuses the
entire projection. This is consistency evidence, not independent authenticity
proof: an owner can rewrite both private metadata and its receipt. It does not
resolve a prior unknown commit against the original immutable publication; use
the separate explicit reconciliation API for that decision.

## Fixed bounds

The whole open, schema validation, read transaction, final identity checks, and
connection closure share a 5,000 ms monotonic cooperative budget. SQLite VM work
uses a progress handler; the opener binds lock waiting to the remaining budget.
Late return from filesystem work cannot produce an available result. This is
not a hard process-termination guarantee for uninterruptible kernel I/O.

At most five runs and 50,000 complete normalized alerts are validated, with at
most 50 alerts retained for output. Each JSON cell is sliced to 4,097 bytes
inside SQLite before Python receives it; a cell beyond 4,096 bytes is refused.
Declared identifiers are similarly sliced before validation. The serialized
response is limited to 65,536 UTF-8 bytes. No caller can raise these limits.

Holding the snapshot lock can briefly refuse a concurrent consumer write.
Capturing the dashboard snapshot once at startup avoids repeated query or lock
work from HTTP polling. An unavailable snapshot is not a finding of zero alerts
or a healthy sensor; operator review or an explicit later restart is needed.

## Verification and remaining acceptance

`tests/test_suricata_projection.py` covers exact consumer publications, empty and
unconfigured states, bounded ordering, corruption outside the visible alert
window, inconsistent counters, huge or invalid JSON cells, schema and permission
refusal, symlink and identity replacement, sidecars/WAL, concurrent writers,
denied SQL writes/attachments/functions, deadlines, and unchanged database
bytes/mode/mtime. Fixtures use synthetic documentation addresses and bypass the
runtime privilege gate only to isolate storage behavior; gate refusal is tested
separately. No installed producer or real traffic is required by these tests.

Passing these checks does not prove installed-Suricata acceptance, live EVE
privacy/source provenance, sensor operation, unknown-commit reconciliation,
independent human review, release, or deployment readiness.

```bash
python -m pytest -q tests/test_suricata_projection.py
python -m compileall -q megalodon/suricata_projection.py
```
