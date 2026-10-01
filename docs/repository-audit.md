# Repository audit and correction — October 1, 2026

## Scope and preservation

The supported application is the **local Linux HUD**. Double-click
`Start-MEGALODON.sh` (Run in Terminal when requested by the desktop) to install
once and open the HUD directly. Setup owns software preparation; the HUD keeps
operational startup. The former Site is retired with an empty HTTP 410 response,
no redirect and no duplicate dashboard. Its hosting registration remains because
the connector does not provide deletion/unpublication.

The starting working tree contained 800 files, including 38 new files. All were
preserved in commit `4b5f8f8` and an owner-private backup before reconciliation.
The fetched main tree matched the previous branch's squashed source exactly;
merge `7b6cead` reconciled ancestry while preserving unfinished work. The old
hosted assets remain recoverable in that preservation commit.

[The file ledger](audit/repository-files.json) accounts for every tracked/new
non-ignored file and retired baseline path. It records purpose, dependency
references, digest, disposition, static verification and related tests. Dated
records and intentionally invalid fixtures remain identified. The ledger itself
is listed by this document; its recursive self-digest is deliberately omitted.
Run `python tools/repository_audit.py --write` to refresh it.

Every file was read and classified using structured checks. This is not a claim
of an independent manual review of every line or a guarantee that no defects
remain. Source tracing concentrated on the user journeys and risk areas below.
Ignored virtual environments, runtime evidence and private build output are not
repository source and are excluded from the public ledger.

## Corrections delivered

| Area | Correction | Verification |
| --- | --- | --- |
| Installation | Fresh private build inputs exclude stale generated modules; package-content identity and supported extra preservation; stop/flush, activate, restart, health verification and rollback; verified unused release retirement | Installer tests, isolated real installation rehearsal, installed identity check |
| Upgrade identity | Readiness must match the expected package and the managed service's own loopback listening socket; an unrelated responder cannot bless an upgrade | Original-code HTTP reproduction and regression tests |
| Release use | A read-only directory descriptor identifies the imported release after the `current` alias changes; uncertain older processes prevent retirement | Process-descriptor fixture and retention tests |
| Setup and Sensors | Shared discovery includes known private locations such as Zeek; saved Qwen advice cannot override current readiness; stale manual-only instructions corrected | Python and browserless JavaScript workflow tests |
| Historical charts | Versioned retained-history reader spans segments and compact summaries, with qualified IDs, paging, interval limits and missing-source indications | Cross-segment HTTP, rendering and source qualification tests |
| Read cost | Chart requests open only visited segment files, require the local check header, and cap rows and output; reporting uses bounded background aggregation | Request-protection and history tests |
| Compaction | Original/summary deduplication, retained findings and receipts; unqualified/sample input cannot become qualified through compaction | Count, recovery, sample exclusion and actual reclamation tests |
| Reports | Shared source-qualified history, local cached visual reports, existing schedule and cancellation retained | Report aggregation, HTTP, schedule and rendering tests |
| Product scope | Duplicate hosted build/tests/scripts removed; canonical local compatibility tests retained; historical publications clearly separated | Reference search, syntax and package checks |
| Dependencies | Test dependency minimum excludes the known pytest advisory; development environment uses the existing hash-pinned pytest 9.1.1 | [Version-specific advisory check](audit/dependency-check.json), lock inventory and pip consistency check |

Storage remains **14 days / 20 GiB**; reports remain **daily at 9 AM local time**.
No automatic cloud upload was added. Known publishers and licenses remain
recorded in the capability references and third-party notices. A public advisory
lookup is evidence about those exact versions on that date, not a vulnerability-
absence certification.

## Measured workload envelope

The repeatable fixtures use temporary owner-private stores and synthetic metadata.
They do not create external traffic or benchmark simultaneous operating-system
sockets. The live projection intentionally holds only 512 tracked / 128 returned
connections; its evictions are not persisted-evidence losses.

| Workload | Throughput | Concurrent query p95 | Result |
| --- | ---: | ---: | --- |
| 100,000 Suricata summaries, burst | 7,071 records/s | 11.5 ms | All retained, zero final backlog, about 30.3 MiB peak process RSS |
| 100,000 Zeek summaries, burst | 7,012 records/s | 13.2 ms | All retained, zero final backlog, about 31.2 MiB peak process RSS |
| 100,000 Suricata summaries, paced at 3,000/s | 2,957/s including final drain | 45.0 ms | All retained; final drain about 0.49 seconds |

Detailed results: [Suricata](benchmarks/repository-audit-suricata.json),
[Zeek](benchmarks/repository-audit-zeek.json),
[paced ingestion](benchmarks/repository-audit-sustained.json),
[balanced recording](benchmarks/repository-audit-recording.json), and
[compaction](benchmarks/repository-audit-compaction.json).

The compaction fixture preserves all 50,000 represented packet records and
measures temporary working space and verified file reclamation. Compression
varies with endpoint diversity and findings. Existing
[controlled before/after recording results](benchmarks/efficient-recording-comparison.json)
show reduced OS write counters and sync calls; they are a separate dated run.
Neither OS write counters nor these finite tests establish physical drive wear,
24/7 throughput, or a capacity guarantee for a different server.

## Acceptance record

The complete Python 3.12 regression run passed **4,329 tests and 203 subtests**,
with three conditional skips. The installed-TShark case passed when explicitly
enabled; the other two skips require an OS layout where `/tmp` is a symlink.
Both wheel and source archive built successfully. Tests include storage exhaustion, rollback,
rotation/readers, compaction restart, source overlap, IPv4/IPv6 topology,
missing sensor data, report cancellation, downtime and daylight-saving scheduling.

The static HUD inventory currently has 158 controls, no duplicate element IDs
and no broken internal anchors. Dynamic controls have browserless handler and
request tests. Actual privileged installs/removals are tested with fixed-command
stubs and isolated installer rehearsals; installed support tools are not removed
or reconfigured merely to exercise a button.

### External acceptance limits

Rendered desktop, ultrawide, laptop, mobile, keyboard/focus and printed-report
acceptance remains **unverified**: the browser access policy previously blocked
this session's inspection. No alternative browser mechanism was used to bypass
that restriction. DOM/JavaScript tests and readable report HTML are not visual
acceptance. A reviewer must still verify those views at normal display scale.

Physical power interruption, actual full host disks, long-running server traffic
and every optional publisher installation are not performed on this working PC.
Their deterministic failure tests and finite replays establish only the tested
envelope. The hosted registration remains an external administrative limitation.

## Focused Codex Security review

Completed scan `76c7a1f7-eeb5-4c15-8f64-1a7c862c472d` covered the immutable
correction diff `7b6cead..7be7eeb`: 15 changed source review items plus necessary
supporting controls. It found one low-severity local upgrade identity issue.
A disposable HTTP responder reproduced false acceptance by the old verifier;
the complete cross-user port race was not attempted. Commit `17eadde` adds
managed process/socket ownership checks and focused positive/negative tests.
This is a focused diff review, not an exhaustive security certification of the
whole repository. The sealed report retains the original finding and revision.

The plugin's cumulative three-thread usage receipt reports 15,942,004 tokens,
including 15,292,160 cached input tokens; it includes shared conversation context
and is not a count of newly generated review text.

### Real installation rehearsal

The offline, owner-private rehearsal at source `a8984e4` passed real initial
installation, same-source replacement, missing-launcher repair, refusal of
modified artifacts, injected manifest failure, rollback, installed CLI/import
identity, settings/data preservation, and uninstall. Its disposable paths were
removed afterward. The [receipt](audit/installer-rehearsal.json) records exact
source and wheel hashes. The first rehearsal caught a stale generated module;
the installer now builds from fresh private source and verifies all package files
before activation. Two final explanatory strings were then corrected and their
focused tests passed; they do not change the verified installation procedure.

### Installed local acceptance

Release `0.1.0-20261001T200909Z-f1febb77` is running from the corrected source.
All 239 installed package files match the checkout. The managed service owns
the verified local listener. Settings are byte-for-byte unchanged; the 14-day /
20-GiB policy, 9 AM America/Chicago schedule, oldest evidence and all three saved
reports are preserved. All three report HTML downloads remain readable, including
the report already marked incomplete. Recording resumed and accepted additional
traffic with zero reported write failures or unconfirmed records at inspection.

Two live historical pages returned 128 records each without duplicate IDs. Their
coverage notice correctly identifies an older incomplete capture receipt; this
does not assert complete historical coverage. Setup now finds the private Zeek
installation. Live workflow checks show accepted TShark, Zeek, Suricata, Nmap and
osquery observations; ClamAV was collecting when checked. See the sanitized
[installed validation receipt](audit/runtime-validation.json). Rendered and print
acceptance remains unresolved as described above.

The installed acceptance probe also exposed an intermittent Ollama GPU-memory
failure: readiness used the provider's default 512-token processing batch while
defense requests already used 64. The control adapter now uses 64 for readiness
and ordinary advice too. A real request with the same pinned model then returned
the exact readiness response. Loopback restrictions, timeouts, context/output
limits and defense authorization are preserved; the separate legacy advisory
wire contract is unchanged. The focused provider/companion/defense tests and the final complete regression
suite passed. The installed adapter also returned a verified readiness response.
