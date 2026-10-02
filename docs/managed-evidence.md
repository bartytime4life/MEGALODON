# Expanded local HUD and managed evidence

## Operator workflow

Open the **HUD** for the enlarged globe, local network directory, selected-interface upload/download speeds, traffic trends, resource use and storage coverage. **Start background tools** stays in the primary controls. Speeds come from the existing host sampler; they include local-network traffic on that interface. They are not an Internet speed test.

The network view groups this computer's addresses and identifies its router, then separates addresses with observed traffic from those whose traffic is not visible. Select a device to read its captured sent/received totals and available connection details in place. These totals describe the returned observation window, not a speed measurement. Address counts are not unique physical-device counts. Unknown device names stay unknown; DNS, TLS and HTTP names are shown as observed service associations. Filters, technical address tables and sources are available under details.

The [network-view acceptance record](audit/network-comprehension-acceptance.json) records the browser checks, regression results and installed release for this presentation change.

Open **Setup → Local network discovery** to select an authorized, currently on-link private scope. Discovery stays off until selected. Passive interfaces, routes and neighbor observations remain visible without scanning. The fixed discovery worker runs every 15 minutes, splits IPv4 scopes into at most 256-address jobs (4,096 addresses total), and accepts IPv6 discovery only for known individual private peers. VPN/container interfaces are separate groups. A discovery result establishes a host observation, not visibility into exchanges between other devices.

Open **Setup → Storage & history**, select a profile and limits, choose **Preview changes**, then **Apply policy**. The preview includes existing packet/receipt databases and saved cases. A changed deletion impact requires a fresh preview. No automatic deletion is enabled on first launch until this step succeeds.

| Profile | Suggested history | Suggested space | Recording detail |
|---|---:|---:|---|
| Home / workstation | 14 days | 20 GiB | Detailed packet metadata and linked findings |
| Home lab / small office | 14 days | 100 GiB | Detailed packet metadata and linked findings |
| Busy server | 7 days | 500 GiB | Source-qualified connection summaries and structured findings |

History can be any integer from **7 through 30 days**. Custom caps range from **1 GiB through 4 TiB**. Profile switches explicitly change recording detail. These sizes are starting suggestions; they do not reserve physical disk or guarantee a duration.

Longer histories help investigate delayed discoveries and compare recurring patterns. They consume more disk, retain sensitive metadata longer, and increase historical-query work. The HUD warns when measured growth suggests the cap will fall short, with a critical warning below seven days. Estimates remain provisional until 24 hours of growth observations; reported coverage and gaps remain authoritative.

## What shares the budget

Managed packet metadata, event/finding/action relationships, sensor connection summaries, structured alerts, compact per-device observation rows (and retained legacy topology snapshots), collector results, resource samples, saved cases and Qwen/response receipts share one policy. Cases preserve the original observation time and do not pin records indefinitely. Database indexes, WAL/journal/SHM sidecars, the catalog and bounded temporary sensor output are included in accounting. Admission reserves 16 MiB for the next transaction/catalog replacement and preserves 2 GiB of free disk.

The original Suricata EVE source in `/var/log/suricata`, user-selected source reports, user exports, installed programs and Ollama model files are separately identified external inputs/assets. MEGALODON retains normalized metadata from those sources; it does not remove their original files or alter the OS service's log-rotation policy. Temporary Zeek output normally disappears after each bounded sample. Unexpected or unaccountable working files require review rather than being silently excluded from the cap.

The **Evidence** tab shows category usage and retained history across segments. Export oldest records first when preserving expiring evidence. Each export is capped at 10,000 records and 32 MiB; **Continue export** saves another portion. The export manifest states whether it is partial, its continuation and known gaps. User-exported files sit outside automatic retention.

## Segments, cleanup and recovery

The private store is `~/.local/share/megalodon/evidence`. A versioned catalog registers exact files and identities. One process owns a nonblocking file lease. New SQLite segments rotate after an hour or around 512 MiB; the total budget spans segments. Core events, findings, actions and ingestion receipts remain in the existing atomic schema. New metadata batches contain at most 256 records with a 32 KiB per-record bound. History pages return at most 100 records and traverse at most 64 segments per request.

Recording admits a bounded transaction only after checking space. Closed eligible units expire by observation age. At capacity, verified packet detail rotates before its smaller compact conversations and saved evidence; all categories still obey the shared cap. A closed hourly unit can expire up to one segment early; the original legacy database is initially one retained unit and can therefore expire earlier as a whole. Preview uses the same priority order as cleanup. The maintenance worker checks every 30 seconds. Missing/changed identities or a failed space check are visible failures, not evidence of reclaimed space. [Compact packet history](compact-history.md) describes the derived evidence and its recovery rules.

Cleanup checkpoints and closes the database, writes a deletion intent, removes the registered file and sidecars, verifies disappearance and records reclaimed bytes/records. Restart finishes an interrupted deletion with the same identity and accounting. It does not rely on SQL row deletion to shrink a file; SQLite explains why deleted rows ordinarily leave free pages in the existing file: [SQLite VACUUM documentation](https://www.sqlite.org/lang_vacuum.html).

Generic imports commit source checkpoints in the same transaction as their records. A generation counter resolves checkpoints across categories after restart. Core recovery verifies integrity, foreign keys and existing ingestion receipt counters, then records an interrupted run as failed/incomplete coverage. Damaged or inconsistent segments stay protected and visibly require review. Abrupt forward/backward clock changes pause maintenance rather than unexpectedly expiring evidence.

Receipt chains have explicit retained boundary anchors when completed ledger units expire. A committed unfinished workflow is protected. On exclusive startup, it receives an `unknown_after_restart` terminal receipt; no host action is retried or claimed rolled back. Its original attempt remains available for review. As with the previous receipt implementation, local hashes detect corruption against a trusted head; they are not signatures against an owner who can rewrite both files and anchors.

## Migration and rollback boundary

Before apply, legacy databases stay at their original paths and are readable by the previous release. Preview is read-only. Apply first drains the HUD capture/flow workers, serializes local mutation requests, checks receipt/integrity readiness, and enrolls the original files without rewriting their event relationships. Future writes use new segments. Validation failure preserves the prior policy and original files.

Keep the previous installed application release until the update is accepted. Code rollback before policy-driven expiry preserves the original database; an older application cannot display newer segmented history. Export required evidence before reducing limits. Once an approved cleanup removes expired files, code rollback cannot recreate them. Protected uncertain data can temporarily prevent a cap from being met and pause collection; its warning is intentional.

## Server data and coverage

Server mode chooses a recent readable Suricata flow source, otherwise a recent Zeek connection file, otherwise bounded Zeek samples. One primary flow source supplies a live view at a time; sensor findings remain separately qualified. Cumulative summaries establish a baseline and use counter deltas only when comparable. Completed flows do not animate as current traffic. Unknown counters remain unknown. Summary updates carry their observation interval and are not interpreted as packet-arrival times.

Suricata findings retain the bounded structured alert object, source flow ID, addresses, ports, protocol, optional application label and supplied flow context. Raw packet content is excluded. [Suricata's EVE format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html) defines the source fields and correlation IDs. Invalid/oversized records count as rejections. Source rotations, bounded initial tail admission, discard resynchronization and sampled coverage are explicit gap counters. A stale source is not labeled healthy.

Live visuals deliberately track at most 512 connections and return at most 128, with a reported truncation/eviction count. The paginated evidence store retains the full admitted record stream subject to the reviewed policy. Packet-history charts and the Evidence tab use bounded retained history across segments and verified compact summaries. See [measured capacity](managed-evidence-capacity.md) for the synthetic ingestion envelope and its limits.

## Earlier verification boundary

The following describes the original implementation session. Current browser and installation receipts are in [repository acceptance](repository-audit.md).

The changes have native filesystem/API tests, browserless DOM/interaction checks and synthetic ingestion benchmarks. Browser automation was administratively denied in this session. Desktop/ultrawide/laptop/mobile rendered appearance, perceptual frame smoothness and final visual acceptance are therefore **unverified**, even though responsive rules, backing-surface resizing, projection synchronization, keyboard controls, hidden-view suspension and reduced-motion behavior have source/behavior checks.

## Local activation evidence — 2026-10-01 UTC

The user-scoped installed wheel was rebuilt and the existing HUD service restarted. Installed module contents were checked against the working checkout. The default Home policy was applied only after the live preview reported **0 eligible records / 0 eligible bytes**. All **4,133,070 pre-existing records** remained retained; the eviction counter stayed at zero. The next verification observed more than 4.3 million total records and active ingestion into the segmented store.

The loopback API reported capture and background monitoring running on the previously selected `enp11s0` interface. The existing host sampler returned measured receive and send rates. The native topology endpoint returned interface/neighbor nodes and observed traffic edges; active discovery remained disabled. The packet chart endpoint returned its bounded 500-event window and the new history endpoint returned records across categories. This verifies backend data delivery, not the appearance of an already-open browser tab; reload the local HUD to load the new frontend.

The implementation is separated into independently testable surfaces:

- UI/API: dashboard composition, globe/network/storage behavior harnesses, and checked local HTTP actions.
- Storage: `tests/test_evidence_storage.py` covers all 7–30 day boundaries, reviewed legacy enrollment, physical capacity eviction, source identities, cases, history cursors, audited restart recovery, interrupted core receipts, clocks, working space and net growth accounting.
- Ingestion: `tests/test_flow_ingestion.py` and `tests/test_support_sensors.py` cover normalization, source selection, cumulative deltas, completion/staleness, bounded samples, checkpoint recovery and malformed/oversized inputs.
- Capacity: the reproducible burst and paced workloads in `tools/benchmark_flow_ingestion.py` publish source-qualified results separately from packet-capture performance.

## Device observations — current behavior

The directory defaults to local device addresses, with an optional view including
internet peers. Search covers addresses, MACs, observed names and service protocols.
The full address table and technical sources are collapsed initially; selection
opens one device's activity in place instead of drawing every relationship.
Local discovery accepts native Nmap XML’s inert
`DOCTYPE nmaprun`; external/internal DTDs and entities remain rejected. Unicast
addresses are used for device placement. Prior responding devices remain in the
live inventory for up to 24 hours with their actual last-discovery time; a failed
probe is not an offline verdict.

Each minute, the worker saves compact per-device rows in bounded batches. It no
longer attempts to put a whole large topology into one 32-KiB evidence record.
These saved observations share the existing retention/cap policy. History errors
are visible separately from a functioning live feed. A selected address offers
saved observations and a continuation for earlier evidence. Source-qualified
Suricata application protocols are context, separate from packet byte totals.
An observed TLS/HTTP/DNS protocol is not proof of a particular installed app.

Google/Nest Wifi’s local status surface provides router health. Google documents
connected-device usage in the [Google Home app](https://support.google.com/googlehome/answer/6263633?hl=en); MEGALODON does not currently import those app-private counters.
Seeing peer-to-peer or other devices’ internet traffic needs an appropriately
placed mirrored-port capture, router flow feed, or endpoint sensor. A sensor
outside NAT usually cannot recover individual private-device identity. Discovery
alone does not establish this coverage. No router configuration, port forwarding,
account credentials, or network interception was changed by this work.
