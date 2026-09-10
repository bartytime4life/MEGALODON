# MEGALODON Defense MVP

**MEGALODON** = **M**alware **E**limination **G**ateway **A**nd **L**ayered
**O**perations **D**efense **O**nline **N**etwork.

MEGALODON is a local-first defensive network telemetry MVP with a Python
metadata core and separately scoped tool integrations. It validates bounded
network metadata, applies three fixed detection heuristics, stores an SQLite
audit trail, and offers a read-only localhost dashboard projection. Live capture, offline
analysis, and firewall planning are separate choices, not mandatory parts of
every configuration. The evaluation-release candidate is plan-only and does
not support live firewall application.

Linux is the current implementation and CI reference, not a claim that every
workflow requires Ubuntu or every platform has equal support. Native Windows
core use is an unverified evaluation target; Linux-specific adapters remain
Linux-specific. Choose a workflow and then check its platform boundary below.

MEGALODON is not an autonomous antivirus, malware-attribution engine,
threat-intelligence service, packet-forensics suite, or authorization to change
a host. A detection or offline candidate is evidence for review, not proof of
malicious activity.

## Safety defaults

- observe only: a fresh configuration does not mutate the firewall;
- metadata only: packet payloads and payload-derived hashes are not represented;
- closed event extensions: `PacketEvent.metadata` is limited to reviewed adapter
  provenance and cannot carry arbitrary payload-like fields;
- local only: the dashboard defaults to `127.0.0.1:8787` and has no write API;
- isolated dashboard storage: on POSIX, serving requires an existing compatible private
  database opened with SQLite `mode=ro`, `query_only`, and a deny-by-default SQL
  authorizer; it cannot create or migrate the audit database;
- no egress: there are no threat-feed, cloud analytics, SIEM, or SOAR calls;
  bundled reference verification and synthetic evaluation perform no runtime
  download or update;
- no shell interpolation: untrusted event values never become shell code;
- finite response: block plans require validated global targets and an expiry;
- contained application: retained firewall `--apply` options explicitly refuse
  before configuration, host, executable, privilege, or process handling;
- allowlist first: loopback, private IPv4, and unique-local IPv6 are protected by
  default.

Read [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md) for the threat assessment and
[`SPECIFICATION.md`](SPECIFICATION.md) for the implemented MVP contract and
production-readiness gaps.

## Documentation map

Use one document as the authority for each kind of decision. Issue and PR pages
record delivery state; they do not override the checked-in contracts.

| Need | Canonical document |
| --- | --- |
| Product boundary, commands, and first run | This README |
| Runtime behavior and acceptance boundary | [`SPECIFICATION.md`](SPECIFICATION.md) |
| Threat model and production controls | [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md) |
| Red/blue/purple validation and future AI gates | [`docs/red-blue-security-guide.md`](docs/red-blue-security-guide.md) |
| Platform choices and installation evidence | [`docs/platform-baseline.md`](docs/platform-baseline.md) |
| Native Windows core acceptance matrix | [`docs/windows-core-acceptance.md`](docs/windows-core-acceptance.md) |
| Offline analyst operation and report semantics | [`docs/offline-analysis.md`](docs/offline-analysis.md) |
| Static integration vocabulary | [`docs/integration-hub.md`](docs/integration-hub.md) |
| Offline reference data and synthetic detector evaluation | [`docs/reference-data.md`](docs/reference-data.md) |
| Automation design and Stage 0 schema | [`docs/automation-contract.md`](docs/automation-contract.md) and [`contracts/automation/v1`](contracts/automation/v1/README.md) |
| Suricata record and bounded-reader gates | [`contracts/suricata-eve/v1`](contracts/suricata-eve/v1/README.md) and [`reader`](contracts/suricata-eve/v1/reader/README.md) |
| Detector and storage evidence receipts | [`docs/detector-acceptance.md`](docs/detector-acceptance.md) and [`docs/storage-failure-policy.md`](docs/storage-failure-policy.md) |
| Per-event ingestion atomicity and orphan recovery | [`docs/ingestion-integrity.md`](docs/ingestion-integrity.md) |

## Choose a configuration

Start with the work you need, rather than installing every listed utility.
These are combinations of existing commands and documented evaluation targets,
not new named profiles, automatic installers, or a universal security suite.

| Workflow | Components and output | Availability and boundary |
| --- | --- | --- |
| Learn or develop with synthetic data | Core Python package; sample/JSONL metadata, fixed detections, SQLite; optional local UI | Implemented on Linux; native Windows core evaluation only. No capture tool, driver, firewall privilege, GPU, or cloud account required |
| Verify bundled reference data or exercise detector boundaries | Separate `megalodon-evaluate` command; pinned IANA context and deterministic synthetic corpus | Read-only, offline, in-memory evaluation. It does not use the service store, alter Stage 0 ingestion, or establish operational detection accuracy |
| Replay authorized metadata, without live capture | `run --source jsonl`; audit database; optional local UI | Existing Linux core path. Windows evaluation uses synthetic fixtures only until native acceptance; arbitrary sensor logs are not this input contract |
| Observe an explicitly selected interface | Core plus the optional Scapy `capture` extra | Linux capture path; separate capture authority and permission review. Not enabled by installation or sample replay |
| Analyze saved packet captures | Separate `megalodon.offline --source tshark`; private local reports | Linux-only adapter and fixed system TShark path; non-root isolated analyst environment. Windows desktop Wireshark use is separate, not adapter support |
| Analyze separately produced connection logs | Separate offline `zeek-json` or `zeek-tsv` adapter; flow reports | Linux-only importer; MEGALODON does not launch Zeek. Packet, flow, and alert counts are different units |
| Inspect integration or response plans | Static `capabilities` / `hub-plan`, or the separate nftables planner | Catalog/hub output executes nothing. Firewall plans are Linux-backend plans and record local audit decisions; live application is unsupported in the evaluation-release candidate |

The core can run **headless**: `run` does not start `dashboard`. A local desktop
can use both commands, and the dashboard can be started later against the same
configured SQLite database. Offline reports remain a separate data path; only
one explicitly selected completed run can supply a startup-only UI summary.
Installing an upstream tool does not create a MEGALODON importer or orchestrator.

## Platform and environment choices

[`docs/platform-baseline.md`](docs/platform-baseline.md) remains the canonical
installation and configuration guide: feature matrix, software/license choices,
pinned recipes, storage permissions, and acceptance gates. This README is the
entry point, not a replacement platform contract.

| Environment | What can be considered | Evidence / support boundary |
| --- | --- | --- |
| Linux workstation or headless host | Core metadata workflows, optional capture, separate offline analysis, and plan-only nftables response | Current reference implementation. CI uses Ubuntu 24.04 / Python 3.11; L1 proposes Ubuntu 24.04 x86-64 / Python 3.12. Neither validates every installed tool or host; live firewall application is unsupported |
| Other Linux distributions or architectures | Evaluate the same bounded workflows where prerequisites and safety checks hold | Not certified by the Ubuntu CI lane. Validate Python, filesystem/privilege behavior, tool paths, and each selected integration; do not remove guards to make a recipe run |
| Native Windows 11 x64 | W1: Python 3.13 synthetic sample/JSONL, SQLite, and loopback UI evaluation; separately operated companion tools | **UNVERIFIED / evaluation only.** No native MEGALODON capture, offline adapter, or Windows firewall backend. Windows acceptance is tracked separately |
| A separately prepared Linux VM | Linux workflow inside the guest; W2 documents a Windows-host evaluation option | **PROPOSED configuration / guest validation required.** Not native host support, complete host-traffic visibility, or host-firewall authority; other host/guest pairings need their own evidence |
| WSL2 | Development evaluation under the documented W2 limits | Not the hostile-capture isolation baseline or proof of Windows-host monitoring/enforcement |
| macOS, BSD, and other native systems | Read the `other` catalog and identify future port/acceptance work | Core runtime and network adapters are **unsupported in the current catalog**; Python or upstream-tool availability alone does not establish support |
| Containers or unattended services | Possible future packaging/operations work | No supported deployment profile is established here. Container privilege, mounts, networking, lifecycle, and isolation need separate review; no service or scheduler is installed by these instructions |

The catalog distinguishes `implemented`, `optional`, `evaluation_only`,
`contract_only`, `manual_only`, `guest_only`, `proposed`, and `unsupported`.
Inspect alternative profiles from an already working runtime:

```text
python -m megalodon capabilities --platform linux
python -m megalodon capabilities --platform windows
python -m megalodon capabilities --platform other
python -m megalodon hub-plan --platform windows
```

`--platform` selects a **static description**, not a runtime backend, host probe,
portability test, or permission to execute a tool. The default follows the Python
runtime's platform family, so a Linux guest describes Linux, not its host.
See [`docs/integration-hub.md`](docs/integration-hub.md) for the closed workflow map.
The baseline excludes Npcap from its open-source dependencies and omits native
Windows live capture; manual saved-capture analysis is a different workflow.

## Implemented capabilities

| Area | Capability in this revision |
| --- | --- |
| Inputs | Built-in sample metadata, bounded JSONL replay, and optional Linux interface-specific Scapy capture |
| Detection | Fixed `SYN_FLOOD`, `PORT_SCAN`, and `DNS_TUNNELING` metadata heuristics with bounded per-source state and cooldowns |
| Audit | SQLite events, detections, and action decisions using parameterized WAL writes; each accepted event decision and its run counters commit atomically |
| Dashboard | Read-only loopback UI backed by a separate read-only SQLite projection, bounded recent-detection triage controls, and an optional privacy-safe summary of one completed offline run |
| Firewall boundary | Plan-only isolated `inet megalodon` nftables proposals; retained `--apply` options refuse before configuration or host/process interaction |
| Offline analysis | Separate, Linux-only non-root TShark PCAP/PCAPNG replay and Zeek JSON/TSV `conn.log` import with private redacted reports |
| Capability catalog | Static, read-only Linux/Windows/other status for selected free/open-source tools; performs no host probe or installation |
| Integration hub | Closed, machine-readable workflow plans for every selected utility; plan-only and non-executing |
| Suricata contract | Closed EVE-alert schema plus bounded-reader policy/receipt contract, synthetic fixtures, and deterministic contract tests; no runtime reader/importer or sensor operation |
| Automation design | Stage 0 normative-draft JSON Schema, accepted/rejected fixtures, and deterministic schema tests; no scheduler or executor |
| Reference and evaluation | Manifest-pinned, privacy-minimized IANA service/port and protocol context plus a bounded synthetic detector corpus; separate read-only CLI with no network, store, persistence, action, or subprocess path |
| CI | Ubuntu 24.04 / Python 3.11 install, dependency check, compilation, pytest, and non-mutating CLI smokes, plus Python 3.12 sdist/wheel builds, an extracted-sdist full test, and installed-package smokes, on pushes to `main` and pull requests |

## Requirements and programs used

| Requirement | Purpose | Status |
| --- | --- | --- |
| Python 3.11 or newer | CLI, validation, detectors, SQLite store, dashboard, and offline adapters | Package minimum, not proof of every Python/OS combination |
| Python `venv` and `pip` | Isolated editable installation | Recommended |
| SQLite (`sqlite3`) | Local audit database | Included in the Python standard library; the dashboard refuses SQLite older than 3.22.0 because read-only WAL support is required |
| Scapy `>=2.5,<3` | Optional Linux live metadata capture | Install with the `capture` extra only for that workflow |
| TShark at `/usr/bin/tshark` | Optional Linux offline `.pcap`/`.pcapng` adapter | Reviewed system package; not a Python dependency or a portable executable-path setting |
| Zeek | Producing optional `conn.log` input | Not invoked or required by MEGALODON; the producer version is operator-declared |
| Suricata | Optional future EVE alert source | Contract and synthetic fixtures only; not invoked, imported, or required |
| ClamAV | Separate manual file scanning | Optional companion; no MEGALODON file intake, quarantine, or result importer |
| osquery | Future endpoint-metadata evaluation | Proposed only; no query pack, scheduler, remote enrollment, or importer |
| nftables | Review of Linux firewall table/block plans | Optional; not invoked by the evaluation-release candidate, and no firewall privilege is needed for plan mode |
| pytest `>=8,<9` and jsonschema `>=4.23,<5` | Repository tests and automation-contract validation | Install with the `test` extra |

The core Python package currently has no third-party runtime dependency. Git is
needed for a source checkout; no analyzer, antivirus, capture driver, or firewall
package is required for the synthetic core demonstration. The list above is a
menu of roles, not an install-all bundle. Install only the extras needed for the
selected, reviewed workflow, using that environment's Python:

```bash
python -m pip install -e .                 # core MVP
python -m pip install -e ".[test]"        # development and validation
python -m pip install -e ".[capture]"     # optional Scapy capture
python -m pip install -e ".[capture,test]" # both optional groups
```

## Installation and first run

For a **new checkout**, use the pinned, failure-checked
[Linux recipe](docs/platform-baseline.md#4-l1-linux-installation-and-validation)
or [Windows evaluation recipe](docs/platform-baseline.md#5-w1-windows-installation-and-evaluation).
Check the recipe's recorded revision before use; it is not a floating-current-main
installation claim. Do not overwrite an existing checkout or virtual environment.

The following are shorter **synthetic core** examples from the root of an
already reviewed checkout, with a suitable Python installed and no existing
`.venv`. Record `git rev-parse HEAD`. Run as an ordinary user in private local
storage, not as root/Administrator or in a cloud-synced/shared folder. Follow the
baseline's POSIX permission or Windows NTFS ACL checks first.

### Linux reference — Bash

```bash
(
  set -euo pipefail
  umask 077
  [ "$(id -u)" -ne 0 ] || { echo 'Use a non-root account.'; exit 1; }
  [ ! -e .venv ] && [ ! -L .venv ] || { echo '.venv already exists; stop.'; exit 1; }
  python3 -m venv .venv
  .venv/bin/python -m pip install -e .
  .venv/bin/python -m megalodon run --source sample --max-events 13
  .venv/bin/python -m megalodon run --source sample --demo-threat --max-events 114
  .venv/bin/python -m megalodon dashboard --host 127.0.0.1 --port 8787
)
```

### Native Windows evaluation — PowerShell

**UNVERIFIED W1 recipe, synthetic data only.** Use the baseline's standard
CPython 3.13 and `py` launcher. Stop on failure; do not change execution policy,
install a capture driver, disable protection, or elevate to make it work.

```powershell
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath '.venv') { throw '.venv already exists; stop.' }
py -3.13 -m venv .venv
if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed.' }
& .\.venv\Scripts\python.exe -m pip install -e .
if ($LASTEXITCODE -ne 0) { throw 'Package installation failed.' }
& .\.venv\Scripts\python.exe -m megalodon run --source sample --max-events 13
if ($LASTEXITCODE -ne 0) { throw 'Synthetic sample failed.' }
& .\.venv\Scripts\python.exe -m megalodon run --source sample --demo-threat --max-events 114
if ($LASTEXITCODE -ne 0) { throw 'Synthetic detection sample failed.' }
& .\.venv\Scripts\python.exe -m megalodon dashboard --host 127.0.0.1 --port 8787
if ($LASTEXITCODE -ne 0) { throw 'Dashboard failed.' }
```

Skip the final dashboard command for headless use. When started, it remains in
the foreground; stop it with Ctrl+C. In later generic examples, `python` means
the selected virtual environment's interpreter: `.venv/bin/python` on Linux or
`& .\.venv\Scripts\python.exe` in Windows PowerShell. A virtual environment can
be used without activation; see the [Python venv documentation](https://docs.python.org/3/library/venv.html).
Bash pipelines and Linux-only adapter/firewall examples are not Windows recipes.

### Local dashboard and storage

Open <http://127.0.0.1:8787/> after starting the dashboard. The first sample run
is benign. `--demo-threat` adds synthetic SYN-flood and long-DNS-query metadata
so detections appear in the audit store and UI; it is not a diagnosis of the
host network.

The default database is `data/megalodon.db`. Repeated runs append to the same
database until the operator deliberately uses another configuration/database or
applies a reviewed retention procedure. The store marks its current layout with
SQLite `user_version = 3`. New databases include a versioned ingestion-run
ledger and detection/action links. On POSIX, the writer creates a missing leaf directory with mode `0700`
and database with mode `0600`; it refuses symlinked ancestors, hard-linked or
foreign-owned databases, and an immediate database directory with group/other
access. Every ancestor must be owned by root or the runtime user and must not be
group/world-writable unless it is a trusted sticky directory. Both writer and
reader require a stable `/proc/self/fd` or `/dev/fd` SQLite path on POSIX so the
opened inode cannot drift from SQLite's journal path. Existing exact v1,
unversioned-v1, or v2 databases require the explicit
`database-migrate` command; ordinary startup does not migrate them. The command
first creates and verifies a sibling backup ending in `.pre-v3.bak`, never
overwrites an existing backup, and then applies the schema migration in one
transaction. Its JSON receipt reports only `backup: created`, not the configured
filesystem path. The backup is created mode `0600` on POSIX; Windows confidentiality
still depends on the private-directory/NTFS ACL acceptance tracked separately.
POSIX migration also requires an operator-owned mode-`0700` parent and mode-`0600`
regular, single-link database, and keeps no-follow source/backup descriptors bound
through backup verification. Stop other MEGALODON processes before migrating and
retain the backup until the new database has been operationally verified.
Partial, altered, extended, or newer application schemas are refused rather than
repaired or downgraded.

The dashboard command refuses a disabled configuration before reading an offline
projection or opening storage. When enabled, it requires that database to exist
with the exact current schema and private path boundary. A no-sidecar immutable
schema preflight prevents failed compatibility checks from creating SQLite
coordination files. An unserved normal connection then establishes and validates
any required private WAL coordination before the final `mode=ro` connection can
serve committed WAL rows. On supported POSIX hosts, the opened descriptor pins
the database inode while SQLite's own `database_list` must resolve it to the
configured private path. The parent directory's entry generation must remain
stable from final open through every served read; replacement or sidecar-entry
changes force a fixed refusal and a generic HTTP `503` rather than a path-bearing
traceback. `PRAGMA query_only=ON` and a closed SQL authorizer block writes, DDL,
`ATTACH`, internal row-ID reads, and private-column reads. Summary counts come from
one SQLite statement, and recent detections select and order only by public data:
`detected_at`, `rule_id`, `severity`, `src_ip`, and `message`. Compatible WAL
reads may create or update private `-wal`/`-shm` coordination files inside the
verified mode-`0700` directory; they do not change the main database, schema,
`user_version`, or journal mode. Windows ACL enforcement remains issue #27.

For an existing POSIX installation, stop every MEGALODON process before the
first post-upgrade open. Inspect the literal configured directory, database, and
any `-wal`/`-shm` files: each must be owned by the runtime user, must not be a
symlink or non-regular file, and the database/sidecars must have exactly one hard
link. Only after those checks, a conventional `data/megalodon.db` installation
can be normalized with `chmod 700 -- data` and
`chmod 600 -- data/megalodon.db`. Do not apply those commands to an unverified,
shared, linked, or redirected path; preserve unexpected sidecars for recovery
review or copy the stopped database to a newly created private location. Writer
startup normalizes an already owner-controlled database and sidecars to mode
`0600`, but deliberately refuses to change an existing public parent directory.
Use a dedicated private database directory: while a dashboard reader is serving,
any directory-entry addition, removal, or rename requires a reader restart.
The [`storage-failure-policy`](docs/storage-failure-policy.md) keeps SQLite audit
and standalone offline-report retention separate and defines fail-closed
outcomes; it selects no deletion value or automatic job.

Each `run` command writes a closed lifecycle receipt before consuming input.
Natural exhaustion records `completed/source_exhausted`; an operator event limit
records `incomplete/event_limit_reached`; handled interruption and bounded
failures have distinct reasons. Every accepted event, all detections, one
non-executing action decision per detection, their links, and the event/detection/
action counters commit in one transaction. Detector windows and cooldowns advance
only after that transaction succeeds. Raw exceptions, input paths, command lines,
packet contents, and credentials are not stored in the run ledger or echoed by
the run failure diagnostic. A row left `running` means completion is unknown and
blocks another run until explicit, target-pinned reconciliation. See
[`docs/ingestion-integrity.md`](docs/ingestion-integrity.md) for the exact state,
migration, ambiguous-commit, and recovery boundaries.

On the Linux analysis profile, add one completed offline run to the read-only
dashboard by selecting its absolute private report directory when the server starts:

```bash
python -m megalodon dashboard \
  --offline-run "$HOME/Analysis/case001/run001"
```

The dashboard loads and validates the summary inputs once; it does not browse
directories, watch files, read or serve record rows, launch an analyzer, expose
candidate evidence details, or add a control endpoint. All dashboard binds are
loopback-only; the legacy `--allow-remote` flag now refuses startup. Restart
the dashboard to select another run.

Every dashboard `GET` request also requires one `Host` header that names the
exact numeric loopback listener, optionally with its actual port. `localhost` is
accepted only for a `127.0.0.1` listener. Missing, duplicate, foreign,
non-canonical, and wrong-port values are rejected before routing or audit-store
reads, limiting DNS-rebinding exposure. This check does not turn a proxy,
tunnel, or port forward into a supported remote-access path.

The recent-detection triage view operates only on the bounded array returned by
`/api/events`. It combines local search, grouped or exact severity, a dynamically
derived exact-rule filter, and at most 12 chronological timestamp bins. Invalid
timestamps remain visible in an otherwise unfiltered table but are excluded
from the timeline with an explicit count. Returned-row, high/critical-row, and
distinct-rule chips describe that array only; they are not full-history rates.
Filters exist only in browser memory and do not alter SQLite, write files, or
add an export path. Polling is suspended while the page is hidden, requests time
out after five seconds, and an in-flight refresh is never overlapped. The safe
built-in defaults can be replaced by an explicit `--config` file or overridden
for one launch:

```bash
python -m megalodon dashboard --refresh-seconds 12 --event-limit 125
```

`refresh_seconds` accepts 2–300 and `event_limit` accepts 1–200. The dashboard
serves its CSS and JavaScript from same-origin, no-store asset endpoints so its
content-security policy does not require inline-script or inline-style access.
The recent-events API projects only detection time, rule ID, severity, source IP,
and message. Destination IP, evidence, recommendation, and suppression details
remain in the local audit store and are not served to the browser.

After each successful summary fetch, the page compares the stored
`high_or_critical` count with the preceding successful value. It reports an
initial baseline or a sequential increase/decrease only. This is not unique-new
alert detection, deduplication, acknowledgement, assignment, resolution,
incident state, or evidence that capture/ingestion is healthy. Summary and event
rows come from separate HTTP reads and are never presented as one coherent
snapshot. A partial or malformed refresh preserves the prior rows, filters,
last-success timestamp, and count baseline while marking the display stale.

## Commands

| Command | Effect |
| --- | --- |
| `capabilities [--platform linux\|windows\|other]` | Print a static support/free-software catalog without probing or changing the host |
| `hub-plan [--platform ...] [--workflow ...]` | Print a closed integration workflow plan; never probes, installs, launches, networks, or mutates |
| `run --source sample [--demo-threat]` | Process built-in synthetic metadata |
| `run --source jsonl [--input FILE]` | Replay validated JSONL from a file or stdin |
| `run --source scapy --interface IFACE` | Perform optional Linux live metadata capture |
| `database-migrate [--config PATH]` | Explicitly back up and migrate an exact v1 or v2 audit database to v3; never overwrites its backup |
| `database-reconciliation-status [--config PATH]` | Read bounded metadata for `running` or reconciliation-required run receipts; does not mutate them |
| `database-reconcile RUN_ID --started-at UTC [--config PATH]` | After stopping ingestion, mark one exactly pinned running receipt as reconciliation-required while preserving evidence |
| `dashboard` | Serve the loopback dashboard from an existing compatible database through the separate read-only projection |
| `firewall-plan IP` | Validate a target and print a non-mutating, time-limited block plan |
| `firewall-install` | Print the isolated nftables table plan; the retained `--apply` option explicitly refuses and executes nothing |
| `block IP --reason TEXT` | Print one block plan; the retained `--apply` option explicitly refuses and executes nothing |
| `python -m megalodon.offline ...` | Run the separate Linux-only private offline-analysis workflow |
| `megalodon-evaluate reference verify` | Validate every declared bundled IANA shard, count, digest, and record before reporting the snapshot summary |
| `megalodon-evaluate reference port TRANSPORT PORT` | Return bounded registration context for one validated service/port key |
| `megalodon-evaluate reference protocol NUMBER` | Return bounded registration context for one validated IP protocol number |
| `megalodon-evaluate corpus [--scenario ID]` | Validate the complete bundled synthetic corpus and run the fixed detector in memory, optionally reporting one scenario |

The operational main CLI subcommands accept optional `--config PATH`; omitting
it uses the complete safe built-in settings and works from an installed wheel.
The static
`capabilities` and `hub-plan` commands do not read configuration.
`run --max-events N` provides an operator stop limit from 1 through 10,000,000;
zero retains the explicit no-limit mode. Use `python -m megalodon --help` and
`python -m megalodon.offline --help` for the complete operational argument
surface, and `megalodon-evaluate --help` for the separate evaluation surface.

The bundled reference snapshot contains 12,577 normalized IANA service/port
records and 152 protocol-number records in deterministic data shards no larger
than 76 KiB. Registrations are analyst context hints: they do not establish the
service observed on a port, endorsement, safety, malicious intent, or a detector
verdict. The separate corpus contains 6,492 metadata-only events across 12
scenarios, uses only RFC 5737 IPv4 and RFC 3849 IPv6 documentation addresses,
and is labeled `synthetic-only` and `uncalibrated`. Manifests, the complete
declared shard set, counts, digests, and records are validated before lookup or
detector execution. See [`docs/reference-data.md`](docs/reference-data.md).

## Event input

JSONL replay accepts one JSON object per line:

```json
{"observed_at":"2026-09-06T15:00:00Z","src_ip":"8.8.8.8","dst_ip":"192.0.2.10","protocol":"TCP","src_port":40000,"dst_port":22,"tcp_flags":["SYN"],"byte_count":60}
```

```bash
python -m megalodon run --source jsonl --input examples/events.jsonl
cat examples/events.jsonl | python -m megalodon run --source jsonl
```

The adapter caps each JSONL record at 64 KiB. IP addresses, ports, timestamps,
flags, text, byte counts, detector evidence, action details, severities, and action
statuses are typed and bounded before persistence. SQLite-facing counts cannot
exceed its signed 64-bit integer range, and mutable JSON fields are revalidated
at the storage boundary. Successful CLI output reports run-scoped `processed`
and `detections` counts plus a separate `totals` object for the whole database.
Detector state is capped at 4,096 tracked sources and 4,096 events per source
window by default. Port-scan distinctness is maintained incrementally with one
bounded frequency index per tracked source; expiry, capacity eviction, and
source eviction update the queue and index together instead of rebuilding a set
from the full window for every TCP event. These are processing and memory
bounds, not evidence that a source is scanning or that traffic was blocked.

For optional Linux live capture (`eth0` is an example, not an assumed interface):

```bash
python -m pip install -e ".[capture]"
python -m megalodon run --source scapy --interface eth0
```

Live capture requires the normal Linux permissions for the selected interface.
The adapter extracts addresses, ports, protocol, TCP flags, sizes, and DNS-name
length; it does not persist or print payloads. Scapy's compact TCP flag value is
decoded from its numeric bitmask into the closed FIN/SYN/RST/PSH/ACK/URG/ECE/CWR
event vocabulary; unsupported bits discard that malformed packet. The callback
queue holds at most 1,024 metadata events. Its first overflow stops publication
with a fixed error instead of blocking the capture callback, growing memory, or
silently continuing after loss. Use only on traffic the operator is authorized
to observe.

## Detection rules

| Rule | Default trigger | Severity | Response |
| --- | --- | --- | --- |
| `SYN_FLOOD` | At least 100 TCP SYN-without-ACK events from one source in 10 seconds | HIGH | Alert only |
| `PORT_SCAN` | At least 20 distinct TCP destination ports from one source in 5 seconds | MEDIUM | Alert only |
| `DNS_TUNNELING` | DNS/UDP query metadata length of at least 50 | CRITICAL | Alert only |

[`config/rules.toml`](config/rules.toml) documents these fixed rules. It is a
reference, not an arbitrary rule-expression engine. Runtime thresholds and
bounds use safe built-in defaults or an explicitly selected
[`config/settings.toml`](config/settings.toml).

## Settings and configuration composition

To customize a workflow, start with a private copy of the complete
[`config/settings.toml`](config/settings.toml) and change only the settings
needed. These are ordinary TOML files, not a profile inheritance/merge system.
Pass `--config PATH` **after**
the operational subcommand; use the same configuration for `run` and `dashboard`
when they should share an audit database. CLI source/interface and dashboard
view options override the corresponding settings for that invocation.

| Choice | Configuration mechanism | Boundary |
| --- | --- | --- |
| Synthetic demo or JSONL replay | `[capture].source` or `run --source`; JSONL file via `--input`, otherwise stdin | `--max-events N` is a CLI stop limit; it is not a total disk quota |
| Headless or local UI | Run only the processing command; start `dashboard` separately when needed | `[dashboard].enabled` controls serving, not automatic startup; retain loopback-only binding |
| Separate lab/case audit stores | A complete private TOML per context with a distinct `[app].db_path` | Repeated runs append; retention is operator-owned, not an automatic purge |
| Offline packet/flow reports | Separate offline command with explicit input root and new output directory | Not configured by the service TOML, not SQLite ingestion, and not input to automatic response |
| Observe or review a response plan | Preserve conservative `[blocking]` defaults; use the separate Linux planner for manual review | A plan is not application. Firewall CLI plan commands can write SQLite audit records without changing firewall state |

Default configuration and database paths are relative to the **working directory**,
not the TOML file's directory. Use a deliberate working directory or literal
absolute paths; TOML does not expand `~`, `$HOME`, or `%LOCALAPPDATA%`. On Windows,
use forward slashes or TOML literal strings for paths. Do not add imaginary
`platform`, `suricata`, or `windows_firewall` keys: changing text settings cannot
supply a missing backend. Keep the existing allowlist and bounded defaults unless
a separately reviewed change requires otherwise.

| Section | Important defaults | Notes |
| --- | --- | --- |
| `[app]` | `db_path = "data/megalodon.db"`, `log_level = "INFO"` | Writer startup creates a missing private leaf directory; dashboard startup never creates the directory or database |
| `[capture]` | `source = "sample"`, empty `interface` | The CLI can override the source and interface per run |
| `[detection]` | 10-second/100-event SYN threshold; 5-second/20-port scan threshold; DNS length 50; cooldown 30 seconds | TOML integers only; windows max at 3,600s, cooldown at 86,400s, DNS length at 65,535, and both state ceilings at 65,536. Thresholds cannot exceed the per-source event ceiling |
| `[blocking]` | `enabled = false`, `dry_run = true`, `auto_block = false`, timeout 900 seconds, `public_only = true` | Timeout is a TOML integer from 1–604,800s; `auto_block = true` is rejected unless `dry_run = true`; detections can plan but cannot apply |
| `[dashboard]` | `enabled = true`, `host = "127.0.0.1"`, `port = 8787`, `refresh_seconds = 5`, `event_limit = 50` | Polling accepts 2–300 seconds; recent rows accept 1–200; only numeric IPv4 loopback or the literal `localhost` alias is accepted; `--allow-remote` refuses startup |

The dashboard accepts dotted-decimal IPv4 addresses in `127.0.0.0/8`. The
literal `localhost` is mapped directly to `127.0.0.1`, without DNS resolution.
Other hostnames, wildcard/LAN/public addresses, and IPv6 (including mapped and
scoped forms) are refused by this IPv4 server. The legacy `--allow-remote` flag
is retained only to give a fixed startup refusal, even with a loopback host.
Remove it and use `--host 127.0.0.1`; do not expose the unauthenticated server
through proxies, tunnels or port forwarding. Firewall allowlist changes,
and public-target policy changes require separate review. Live application is
unsupported; any future restoration must satisfy the gate below.

## Dashboard UI and API

The current UI is a responsive dark-theme status view with:

- summary cards for stored events, detections, action records, and high/critical
  counts, with action records explicitly distinguished from live application;
- a five-column recent-detections table: time, severity, rule, source, and message;
- combined local search, priority/exact-severity and exact-rule filters, plus a
  maximum 12-bin timeline over valid timestamps in the returned set;
- returned-set scope chips and a sequential stored high/critical count-change
  signal that explicitly does not claim unique alerts or incident state;
- manual refresh, clear-filter controls, and pause/resume polling;
- bounded five-second polling by default, suspended while the page is hidden;
- an optional schema-checked, privacy-bounded summary of one explicitly selected
  completed offline run;
- a truthful operator-status strip that separates dashboard API reachability
  from unmeasured capture/ingestion health and marks preserved data stale; and
- DOM text-node rendering rather than raw HTML insertion.

The server exposes only these read routes:

| Route | Response |
| --- | --- |
| `GET /` | Static dashboard HTML |
| `GET /assets/dashboard.css`, `GET /assets/dashboard.js` | Same-origin no-store assets |
| `GET /api/config` | Immutable polling, row-budget, and offline-summary availability metadata |
| `GET /api/summary` | SQLite event, detection, action, and severity counts from one read snapshot |
| `GET /api/events?limit=N` | Five-field recent-detection projections with strict query validation and a 200-row ceiling |
| `GET /api/offline-summary` | Availability plus one startup-validated, capped offline summary; never record rows or capture paths |

Responses use `Cache-Control: no-store`, a self-only Content Security Policy
without `unsafe-inline`, opener/resource isolation headers,
`X-Content-Type-Options: nosniff`, and `X-Frame-Options: DENY`. The UI cannot
start capture, run analysis, apply firewall actions, edit settings, choose a
filesystem path, or browse local files. [Issue #7](https://github.com/bartytime4life/MEGALODON/issues/7)
preserves the implementation and validation handoff.

## Linux firewall boundary

This optional backend is not a prerequisite for metadata analysis. Inspect plans
without root or firewall mutation; these CLI commands still record local audit rows:

```bash
python -m megalodon firewall-plan 8.8.8.8 --reason "manual review"
python -m megalodon firewall-install
python -m megalodon block 8.8.8.8 --reason "manual review"
```

Detection-driven policy can record a proposed block only when configured. It
never supplies confirmation or invokes `nft`. The retained
`firewall-install --apply` and `block IP --apply` options explicitly refuse
before reading configuration, probing the host, resolving an executable,
checking privilege, or creating a process. No host mutation is attempted and no
`applied` receipt is written; plan and audit receipts remain the only supported
firewall outcomes in the evaluation-release candidate.

Preserve the host's existing firewall manager and endpoint protection on every
platform. An nftables plan is not a Windows Firewall or macOS/BSD firewall rule.
Live application may be restored only through a separately reviewed change that
adds durable intent before mutation, terminal outcome and reconciliation states,
finite expiry, and operator recovery. It must also bind process construction to
a reviewed absolute executable and fixed environment, then pass disposable
Linux network-namespace tests for failure handling, PATH hijacking, expiry,
readback, rollback, and recovery. Plan-mode success alone does not satisfy this
restoration gate.

## Isolated offline analysis

The offline command is separate from `megalodon run` and must run on Linux as a
non-root, capability-free account. It neither writes the SQLite service database
nor drives live dashboard polling or firewall policy. A completed report can
separately supply the startup-only, operator-selected dashboard summary; record
rows are not ingested or served.

```bash
python -m megalodon.offline \
  --source tshark \
  --input-root /absolute/private/input \
  --input capture.pcap \
  --output /absolute/private/new-run-directory \
  --case case001 \
  --max-records 10000 \
  --timeout 30
```

Use `--source zeek-json` or `--source zeek-tsv` with
`--zeek-version X.Y.Z` for a separately produced `conn.log`. An optional reviewed
`baseline.json` under the input root can be selected with
`--reference-baseline RELATIVE_PATH`.

The command accepts one nonempty regular input file up to 64 MiB, uses fixed
adapter schemas and limits, and creates a new mode-0700 output directory with
mode-0600 files:

- `records.jsonl` and `records.csv` with deterministic per-run host labels and
  relative times;
- `baseline.json` with source-qualified deterministic distributions;
- `candidates.jsonl` with bounded `NEW_DESTINATION_PORT`, `REGULAR_INTERVAL`, and
  `PORT_53_BURST` review candidates;
- `manifest.json`, written last as the completion marker.

Redaction is not anonymization and does not authorize sharing. No exporter is
implemented. See [`docs/offline-analysis.md`](docs/offline-analysis.md) for the
full isolation model, fixed limits, typed adapter fields, report semantics,
failure behavior, and optional installed-TShark compatibility probe.

## Automation contract: schema only

[`contracts/automation/v1`](contracts/automation/v1/README.md) contains the
dependency-closed Stage 0 contract now present on `main`: JSON Schema Draft
2020-12 definitions plus positive/negative fixtures for draft definitions,
activated definitions, and immutable run snapshots.

This is a normative draft data contract, not a scheduler. It does not calculate
recurrences, resolve DST, persist automation definitions/runs, invoke models,
publish output, expose a CLI/API, or execute jobs. Network and firewall
capabilities are fixed to `false`, `requested_actions` is empty, and no arbitrary
command, path, endpoint, or tool field exists. See
[`docs/automation-contract.md`](docs/automation-contract.md) for the proposed
staged design.

## Development status and open issues

This selected, non-exhaustive table is a repository checkpoint, not a substitute
for the live issue. Closed design/test gates can still leave runtime and
operational work unbuilt.

| Issue | Current repository meaning |
| --- | --- |
| [#3 — independent-review enforcement](https://github.com/bartytime4life/MEGALODON/issues/3) | Open governance gate; do not treat green CI or a merge as independent approval |
| [#7 — offline dashboard and operator controls](https://github.com/bartytime4life/MEGALODON/issues/7) | Tracks this implementation and its remaining review and compatibility evidence |
| [#9 — Suricata EVE contract and fixtures](https://github.com/bartytime4life/MEGALODON/issues/9) | Closed contract gate; record schema/tests are on `main`, without a runtime importer |
| [#24 — bounded Suricata reader](https://github.com/bartytime4life/MEGALODON/issues/24) | Closed contract gate; fixed reader policy, receipt, fixtures, and oracle are on `main`, without filesystem/runtime implementation |
| [#25 — installed TShark compatibility](https://github.com/bartytime4life/MEGALODON/issues/25) | Open evidence gate for the optional system analyzer |
| [#26 — detector acceptance](https://github.com/bartytime4life/MEGALODON/issues/26) | Closed bounded synthetic acceptance gate; representative accuracy and operational interpretation are not established |
| [#27 — native Windows core acceptance](https://github.com/bartytime4life/MEGALODON/issues/27) | Open platform gate; machine-readable matrix and Linux-run unsupported-operation controls exist, but native Windows/NTFS/browser receipts remain unperformed |
| [#28 — retention and storage failure policy](https://github.com/bartytime4life/MEGALODON/issues/28) | Closed documentation/test gate; separate data-class and failure matrices plus synthetic transaction/exhaustion/permission/interruption tests exist, but no retention values or automatic cleanup are selected |
| [#65 — contain live firewall application](https://github.com/bartytime4life/MEGALODON/issues/65) | Open containment gate; executor removal and fail-closed apply refusal are on `main`; independent review and any separately designed restoration gate remain required |
| [#66 — isolate dashboard reads](https://github.com/bartytime4life/MEGALODON/issues/66) | This revision separates dashboard reads from the writer, validates private database identity/schema, and constrains SQL to the five-field projection; independent review and native Windows ACL evidence remain open |
| [#67 — atomic ingestion receipts](https://github.com/bartytime4life/MEGALODON/issues/67) | Per-event atomic event/detection/action/link/counter commits, explicit terminal reasons, detector rollback behavior, and pinned orphan reconciliation are implemented in this slice; exact-head review and issue disposition remain separate, and no alert lifecycle or delivery follows |
| [#68 — whole-service resource bounds](https://github.com/bartytime4life/MEGALODON/issues/68) | Open availability gate; incremental bounded port accounting removes one detector hot-path rescan, but capture liveness, long-running storage, overload, retention, and notifier behavior remain unresolved |

Open issues and branches are coordination/evidence records, not shipped features
or deployment approval. Review the current issue readback before acting because
heads, validation evidence, and governance state can change after this document.

## Validation

Repository-native checks for the existing **Linux reference lane** are below.
Install the `test` extra in that environment first. Windows requires its separate
core/ACL/UI/unsupported-operation acceptance work; do not treat this full suite
as a portable Windows recipe or suppress Linux-specific failures to claim parity.

```bash
python -m compileall -q megalodon tests
python -m pytest
python -m megalodon capabilities --platform linux
python -m megalodon capabilities --platform windows
python -m megalodon hub-plan --platform linux
python -m megalodon run --source sample --max-events 13
python -m megalodon run --source sample --demo-threat --max-events 114
python -m megalodon firewall-plan 8.8.8.8 --reason "CLI smoke"
megalodon-evaluate reference verify
megalodon-evaluate reference port tcp 443
megalodon-evaluate reference protocol 6
megalodon-evaluate corpus
```

The evaluation commands validate all bundled data before performing bounded
lookups or an in-memory detector run. They do not fetch updates, use SQLite,
persist output, invoke a response action, or start a subprocess. The smoke
commands use synthetic data and a non-mutating firewall plan. They do
not prove live-capture compatibility, installed-TShark behavior, firewall safety
on a specific host, corpus representativeness, calibrated detection accuracy,
independent review, or production readiness. Printing a Windows/other catalog
on Linux is not execution on those platforms. Record the exact revision,
OS/architecture, Python and dependency versions, selected extras, passed
checks, and skips for every configuration claim.

## Project layout

```text
.github/workflows/           hosted CI
config/                      conservative typed defaults and fixed-rule reference
contracts/automation/v1/     inert automation schema, fixtures, and contract notes
contracts/suricata-eve/v1/   inert alert and bounded-reader contracts, fixtures, and tests
docs/                        platform baseline, integration hub, automation design, offline analyst guide
examples/                    bounded JSONL replay fixture
megalodon/                   validation, capability/hub catalogs, capture, detection, storage, policy, CLI, UI
megalodon/offline/           isolated TShark/Zeek adapters and private reports
megalodon/reference/         pinned offline IANA context and synthetic evaluation corpus
tests/                       safety, behavior, offline, and schema contract tests
SECURITY_REVIEW.md           architecture threat assessment and required controls
SPECIFICATION.md             implemented MVP contract and acceptance boundary
```

## Current limits

This is a defensive MVP, not a finished enterprise IDS/IPS. The fixed detections
are simple heuristics. There is no authenticated remote UI, arbitrary rule
authoring, threat-feed or SIEM/SOAR integration, distributed sensor management,
automatic retention job, production rollback orchestration, model execution,
active scheduler, Suricata runtime importer, alert acknowledgement/resolution/
escalation lifecycle, notification dispatcher, or continuous capture-health
monitor on `main`.

The bundled IANA snapshot is not runtime service discovery or a vulnerability
feed, and it has no automatic update path. The synthetic corpus tests deterministic
boundary behavior; it is not representative traffic, a benchmark against named
products, an accuracy claim, or evidence that an alert is malicious.

Before operational deployment, use representative authorized replay data to
measure false positives; validate live capture and TShark separately; define
retention and data-sharing policies; keep firewall operation plan-only unless
the restoration gate above is implemented and independently reviewed; and
obtain independent security/operations review.
