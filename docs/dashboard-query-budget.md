# Bounded dashboard SQLite reads

The dashboard's small result sets do not imply small database work. In the
inspected main `caf7e4bd441ddd33facd2b7d406e4abe5e7e72c9`, the summary's
high/critical count scans stored detections. The existing connection timeout
limits lock contention, not query execution. Repeated polling could therefore
spend increasing time computing four counters as the audit ledger grows.

Each served `summary()` or `recent()` call now owns a fresh cooperative budget:

| Limit | Behavior |
| --- | --- |
| Reader lock acquisition | Refuse after 250 ms instead of waiting behind another read indefinitely. |
| SQLite busy wait | Dashboard connections use 250 ms; writer/migration timeouts remain unchanged. |
| SQLite VM work | Abort at the callback reaching 1,000,000 VM instructions, with callbacks every 1,000 instructions. |
| Elapsed SQL work | Check a one-second monotonic deadline in callbacks and again before returning a completed result. |
| Result publication | Return the full existing result or a bounded error; never partial counters, truncated successful data or invented zeros. |

The progress handler is installed and removed under the reader lock. Cursors
are closed before removal, including exception paths. A budget refusal raises
`DASHBOARD_STORE:READ_BUDGET_EXCEEDED`; contention raises
`DASHBOARD_STORE:READ_BUSY`. Existing HTTP handling maps these to status 503 with
`{"error":"telemetry unavailable"}` and `Cache-Control: no-store`. Other SQLite
errors retain `DASHBOARD_STORE:READ_FAILED`. Later reads receive a new budget.
The browser's existing unavailable/stale behavior remains authoritative.

These are fixed protective defaults, not benchmark-derived latency promises or
an operator-tunable SQL interface. Progress callbacks are cooperative: a single
SQLite instruction, OS/filesystem stall, setup/schema validation, path-identity
checks, scheduling or cleanup can take longer. The deadline checks prevent late
results from being published but cannot forcibly interrupt every native stall.
The VM threshold is not a portable row-count threshold. Large legitimate
summaries can be unavailable while the indexed recent list remains available.

No truncation or automatic purge is used to make a count fit. Operators should
inspect capacity and use the existing separately authorized retention workflow,
or evaluate a separately reviewed aggregate strategy. Do not bypass read-only
or privacy checks to obtain a green dashboard. This change retains the exact
SQL projections/authorizer, one-statement summary snapshot, schema, WAL identity
checks and database evidence; it adds no SQL writes or migrations.

## Validation and source basis

Synthetic tests interrupt real SQLite work for both public reads, check
post-fetch expiry even below the callback interval, recover after failure,
exercise concurrent lock contention, preserve the writer's data and authority
checks, and verify HTTP 503/recovery. A 260,500-row synthetic ledger exceeds the
default summary VM budget while a 200-row indexed recent query still succeeds.
The existing overlapping WAL commit test continues to verify coherent counts.

The supplied Advancement Blueprint's storage/resource sections and Local
Command Center Blueprint's degraded-state contract motivate this bounded read
boundary. *Advanced SQL Concepts*, supplied pp. 54–55, motivates investigating
query cost; *Efficient R Programming*, pp. 22–23, motivates measuring the actual
bottleneck. No database-specific optimization advice is assumed portable.
Python's [SQLite progress-handler documentation](https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.set_progress_handler)
describes cooperative VM interruption; its [connection documentation](https://docs.python.org/3/library/sqlite3.html#sqlite3.connect)
distinguishes busy waits. No new dependency, model, sensor, endpoint or service
is required. This is application-level availability hardening, not a hard
real-time guarantee or native SQLite vulnerability fix.
