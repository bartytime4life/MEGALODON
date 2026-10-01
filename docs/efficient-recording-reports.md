# Efficient recording and automatic visual reports

## Everyday use

Open **Reports** to read the latest saved report. **Make report now** covers the last 24 hours by default. Choose Today, Last 7 days, or custom dates when needed. **Save report** downloads a self-contained visual HTML file; **Print / save PDF** uses the browser's print dialog. Technical CSV, JSON, and the address-free hosted summary are under **Advanced exports**.

Automatic reports run in the local HUD service at **9 AM in this PC's time zone**, even with the browser closed. After downtime, the service catches up on the latest missed reporting interval once. Schedule settings allow daily or weekly reports and a different time. Reports identify missing or expired evidence; an empty interval does not prove inactivity.

**Setup → Apps & connections** holds console addresses, downloads, availability checks, installation, configuration, verification, and removal guidance. Sensor views keep observed status and a Configure shortcut. **Start background tools** remains in the HUD.

Reports and telemetry remain local. Downloaded copies belong to the user and are outside managed cleanup. The private hosted Site remains a separate reference and manual aggregate-summary viewer; it does not gain access to this PC.

## What Balanced recording changes

Ordinary packet metadata is evaluated immediately and saved in batches after two seconds, 256 events, or 1 MiB, whichever comes first. A finding flushes its event, prior buffered events, and linked action records immediately. A normal stop flushes the remaining batch. A sudden process or power failure can lose the unsaved batch; the HUD shows buffered and saved counts separately.

Detector state advances provisionally within a batch and becomes committed only after the evidence transaction succeeds. On a failed transaction, committed detector windows and cooldowns remain unchanged. Import checkpoints commit with their source records. Action and Qwen receipt chains retain their immediate durability rules.

SQLite uses WAL with `synchronous=FULL`. Active generic segments keep their writer connection open. Passive checkpoints run at an 8-MiB outstanding-WAL threshold or after 60 seconds of outstanding writes; reused WAL allocation does not trigger repeated checkpoints. Frame-generation hints follow the [SQLite WAL format](https://www.sqlite.org/fileformat2.html#walformat), while SQLite validates and checkpoints the actual records; segment closure reclaims the WAL. Reader pressure is visible and stops admission at the bounded pressure limit instead of permitting uncontrolled growth. Reconstructible catalog counters are coalesced for up to 30 seconds; structural changes and receipt boundaries are saved immediately. Startup recovery reconstructs committed counts and positions from segments.

**Disk activity** uses existing OS process counters. Daily figures project the currently observed rate and remain provisional. Inaccessible companion counters are unavailable. These counters do not measure flash-cell write amplification, remaining endurance, or a drive's lifespan.

## Measured write comparison

The [saved measurements](benchmarks/efficient-recording-comparison.json) compare the pre-change source snapshot with Balanced recording on this workstation. Each run uses a fresh private temporary store, 10,000 synthetic records, the same policy, and concurrent bounded history reads. No captured user traffic or network scans are used.

| Workload | Before: OS written bytes | Balanced: OS written bytes | Reduction | Retained records |
|---|---:|---:|---:|---:|
| UDP packet metadata | 400,125,952 | 7,479,296 | 98.1% | 10,000 / 10,000 |
| Connection-summary metadata | 8,306,688 | 4,681,728 | 43.6% | 10,000 / 10,000 |

Packet history-query p95 increased from 4.21 ms to 27.06 ms while batching; the measured run shortened from 18.64 seconds to 0.91 seconds. Summary-query p95 was 27.45 ms before and 22.10 ms after. Neither workload produced a query error or lost a retained record.

System-call tracing reported packet `fdatasync` calls falling from 10,266 to 54 and summary calls from 211 to 55. Tracing includes initialization and final closure; the OS write-byte interval covers ingestion and final closure. Tracing adds overhead. These finite synthetic cases demonstrate a reduction in this workload, not a guaranteed saving for every sensor, alert rate, filesystem, or disk.

Reproduce current measurements with `tools/benchmark_recording.py`, using `--records 10000` and `--kind packets` or `--kind summaries`. For a before/after comparison, `--baseline-dir` accepts an explicitly preserved pre-change source directory containing `storage.py` and `evidence_storage.py`; the report records their SHA-256 hashes. Run comparisons sequentially. Trace `fsync`, `fdatasync`, `pwrite64`, and `write` separately when system-call counts are needed. Keep owner and private-path checks enabled.

## Report evidence and limits

Reports read retained source segments at fixed row watermarks in bounded pages. They do not use the dashboard's newest 500-record slice. Packet observations and each sensor's flow summaries remain separate. Cumulative flow counters can describe connection lifetimes beginning before the selected interval; their labels disclose this. Interface-speed readings include local-network traffic.

Report jobs yield between pages and can be cancelled. Work, output, finding-detail, and source-count limits are disclosed as partial coverage when reached. Generated report records, schedule state, and reserved working space are included in the managed budget. Reports expire according to their source observations; making a new report does not extend source retention. Existing 7–30-day policies and capacity settings are preserved.

HTML escapes source text and carries no executable report scripts or remote assets. Downloads use server-generated identifiers. Local report mutations use the existing Host, Origin, request-type, and per-launch token checks. CSV cells are protected against spreadsheet formula interpretation.

Automated checks cover batching and failed-write rollback, persistent-WAL recovery, concurrent-reader pressure, multi-segment report totals, source separation, scheduling and daylight-saving transitions, cancellation, expiry, and export/request safety. Browser automation was administratively unavailable; source/DOM checks do not establish rendered appearance or printed pagination.


## Delivery checks — October 1, 2026 UTC

- Combined regression gate: **384 passed, 2 skipped**. The two skips require a platform where `/tmp` is a compatibility symlink. A further two Storage UI checks passed after clarifying cumulative checkpoint-pressure wording.
- Independent source/DOM evaluation: passed after chart-label, report-selection, mobile and print-CSS corrections. No browser rendering or print-dialog automation was performed.
- Codex Security scan `a39c39e5-581e-475b-8ccd-2da482819cc6` sealed with zero confirmed security findings. It reviewed this turn's immutable 36-file diff, with a hash-qualified addendum for the checkpoint, failure-counter, schedule-durability and status-copy corrections. The plugin's canonical coverage remains **partial** because it retained an obsolete temporary `final-coverage` entry; the sealed artifacts were not rewritten. Focused review is not a whole-product security certification.
- The local installer preserved the settings fingerprint and previous release. Fourteen installed modules were verified byte-for-byte against reviewed source before restarting `megalodon-hud.service`. The active service reports Balanced recording, visible pending/saved counters, and the existing Home policy of 14 days / 20 GiB.
- Scheduling was observed enabled at 09:00 America/Chicago, with the latest missed scheduled interval generated once after startup. Local reports and evidence are not uploaded.
- Matching Setup organization was privately published to the existing MEGALODON Defense Console from Site source commit `e88c10d911f547df8aa5671a36bfc343aad24bea`. Owner-only deployment succeeded; this is separate from local telemetry and local report execution.
- Installed-service report verification processed **6,141,245 retained records** with complete aggregation across the available selected interval. HTML, JSON, and CSV downloads succeeded; repeated HTML retrieval was byte-identical and did not start another job. The report explicitly marks the earlier part of the requested 24 hours as unavailable because retained observations began later. The saved HTML contains embedded print styling and no executable scripts.
