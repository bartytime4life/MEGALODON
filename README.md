# MEGALODON Defense MVP

**MEGALODON** = **M**alware **E**limination **G**ateway **A**nd **L**ayered
**O**perations **D**efense **O**nline **N**etwork.

MEGALODON is a local-first, Linux-oriented defensive network telemetry MVP. It
validates bounded network metadata, applies three fixed detection heuristics,
stores an SQLite audit trail, and exposes a read-only localhost dashboard.
Firewall planning and application are separate, operator-controlled paths.

MEGALODON is not an autonomous antivirus, malware-attribution engine,
threat-intelligence service, packet-forensics suite, or authorization to change
a host. A detection or offline candidate is evidence for review, not proof of
malicious activity.

## Safety defaults

- observe only: a fresh configuration does not mutate the firewall;
- metadata only: packet payloads and payload-derived hashes are not represented;
- local only: the dashboard defaults to `127.0.0.1:8787` and has no write API;
- no egress: there are no threat-feed, cloud analytics, SIEM, or SOAR calls;
- no shell interpolation: untrusted event values never become shell code;
- finite response: block plans require validated global targets and an expiry;
- explicit application: MEGALODON never invokes `sudo` or supplies confirmation;
- allowlist first: loopback, private IPv4, and unique-local IPv6 are protected by
  default.

Read [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md) for the threat assessment and
[`SPECIFICATION.md`](SPECIFICATION.md) for the implemented MVP contract and
production-readiness gaps.

## What is implemented on `main`

| Area | Current capability |
| --- | --- |
| Inputs | Built-in sample metadata, bounded JSONL replay, and optional interface-specific Scapy capture |
| Detection | Fixed `SYN_FLOOD`, `PORT_SCAN`, and `DNS_TUNNELING` metadata heuristics with bounded per-source state and cooldowns |
| Audit | SQLite events, detections, and action decisions using parameterized writes and WAL mode |
| Dashboard | Read-only summary cards and a recent-detections table served from localhost |
| Firewall boundary | Non-mutating plans by default; isolated `inet megalodon` nftables table and time-limited sets for explicit application |
| Offline analysis | Separate, non-root TShark PCAP/PCAPNG replay and Zeek JSON/TSV `conn.log` import with private redacted reports |
| Automation design | Stage 0 normative-draft JSON Schema, accepted/rejected fixtures, and deterministic schema tests; no scheduler or executor |
| CI | Python 3.11 install, compilation, pytest, and non-mutating CLI smoke checks on pushes to `main` and pull requests |

## Requirements and programs used

| Requirement | Purpose | Status |
| --- | --- | --- |
| Python 3.11 or newer | CLI, validation, detectors, SQLite store, dashboard, and offline adapters | Required |
| Python `venv` and `pip` | Isolated editable installation | Recommended |
| SQLite (`sqlite3`) | Local audit database | Included in the Python standard library; no separate pip package |
| Scapy `>=2.5,<3` | Optional live metadata capture | Install with the `capture` extra |
| TShark/Wireshark at `/usr/bin/tshark` | Optional offline `.pcap`/`.pcapng` parsing | Reviewed system package; not a Python dependency |
| Zeek | Producing optional `conn.log` input | Not invoked or required by MEGALODON; the producer version is operator-declared |
| nftables and an already-root process | Explicit firewall table/block application | Optional; never needed for observe, dashboard, or plan mode |
| pytest `>=8,<9` and jsonschema `>=4.23,<5` | Repository tests and automation-contract validation | Install with the `test` extra |

The core Python package currently has no third-party runtime dependency. Install
only the extras needed for the intended task:

```bash
python -m pip install -e .                 # core MVP
python -m pip install -e ".[test]"        # development and validation
python -m pip install -e ".[capture]"     # optional Scapy capture
python -m pip install -e ".[capture,test]" # both optional groups
```

## Quick start

```bash
git clone https://github.com/bartytime4life/MEGALODON.git
cd MEGALODON
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[test]"

python -m megalodon run --source sample
python -m megalodon run --source sample --demo-threat
python -m megalodon dashboard
```

Open <http://127.0.0.1:8787/> after starting the dashboard. The first sample run
is benign. `--demo-threat` adds synthetic SYN-flood and long-DNS-query metadata
so detections appear in the audit store and UI; it is not a diagnosis of the
host network.

The default database is `data/megalodon.db`. Repeated runs append to the same
database until the operator deliberately uses another configuration/database or
applies a reviewed retention procedure.

## Commands

| Command | Effect |
| --- | --- |
| `run --source sample [--demo-threat]` | Process built-in synthetic metadata |
| `run --source jsonl [--input FILE]` | Replay validated JSONL from a file or stdin |
| `run --source scapy --interface IFACE` | Perform optional live metadata capture |
| `dashboard` | Serve the read-only dashboard using configured host and port |
| `firewall-plan IP` | Validate a target and print a non-mutating, time-limited block plan |
| `firewall-install` | Print the isolated nftables table plan; `--apply` is required to execute it |
| `block IP --reason TEXT` | Print one block plan; `--apply` plus exact target confirmation is required to execute it |
| `python -m megalodon.offline ...` | Run the separate private offline-analysis workflow |

All main CLI subcommands accept `--config PATH`. `run --max-events N` provides an
operator stop limit. Use `python -m megalodon --help` and
`python -m megalodon.offline --help` for the complete argument surface.

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
flags, text, byte counts, and metadata are typed and bounded before persistence.
Detector state is capped at 4,096 tracked sources and 4,096 events per source
window by default.

For optional live capture:

```bash
python -m pip install -e ".[capture]"
python -m megalodon run --source scapy --interface eth0
```

Live capture requires the normal Linux permissions for the selected interface.
The adapter extracts addresses, ports, protocol, TCP flags, sizes, and DNS-name
length; it does not persist or print payloads. Use only on traffic the operator
is authorized to observe.

## Detection rules

| Rule | Default trigger | Severity | Response |
| --- | --- | --- | --- |
| `SYN_FLOOD` | At least 100 TCP SYN-without-ACK events from one source in 10 seconds | HIGH | Alert only |
| `PORT_SCAN` | At least 20 distinct TCP destination ports from one source in 5 seconds | MEDIUM | Alert only |
| `DNS_TUNNELING` | DNS/UDP query metadata length of at least 50 | CRITICAL | Alert only |

[`config/rules.toml`](config/rules.toml) documents these fixed rules. It is a
reference, not an arbitrary rule-expression engine. Runtime thresholds and
bounds are loaded from [`config/settings.toml`](config/settings.toml).

## Settings

| Section | Important defaults | Notes |
| --- | --- | --- |
| `[app]` | `db_path = "data/megalodon.db"`, `log_level = "INFO"` | Database parent directories are created locally as needed |
| `[capture]` | `source = "sample"`, empty `interface` | The CLI can override the source and interface per run |
| `[detection]` | 10-second/100-event SYN threshold; 5-second/20-port scan threshold; DNS length 50; cooldown 30 seconds | All numeric values must be positive; state ceilings default to 4,096 |
| `[blocking]` | `enabled = false`, `dry_run = true`, `auto_block = false`, timeout 900 seconds, `public_only = true` | `auto_block = true` is rejected unless `dry_run = true`; detections can plan but cannot apply |
| `[dashboard]` | `enabled = true`, `host = "127.0.0.1"`, `port = 8787` | Port must be 1–65535; non-loopback binding additionally requires `--allow-remote` |

Do not treat `--allow-remote` as production exposure support. The current server
has no authentication, authorization, or CSRF control, so remote binding is not
recommended. Firewall allowlist changes, public-target policy changes, and live
application should receive separate operator review and isolated testing.

## Dashboard UI and API

The current UI is a small dark-theme status view with:

- summary cards for stored events, detections, actions, and high/critical counts;
- a five-column recent-detections table: time, severity, rule, source, and message;
- automatic refresh every three seconds;
- DOM text-node rendering rather than raw HTML insertion.

The server exposes only these read routes:

| Route | Response |
| --- | --- |
| `GET /` | Static dashboard HTML/CSS/JavaScript |
| `GET /api/summary` | SQLite event, detection, action, and severity counts |
| `GET /api/events?limit=N` | Recent detection records, capped by storage at 200 |

Responses use `Cache-Control: no-store`, a Content Security Policy, and
`X-Content-Type-Options: nosniff`. The UI cannot start capture, run analysis,
apply firewall actions, edit settings, or browse local files.

Expanded filtering, refresh controls, configuration metadata, stricter asset
isolation, and privacy-safe offline-run projection are tracked as branch-only
work in [Issue #7](https://github.com/bartytime4life/MEGALODON/issues/7); they are
not current `main` behavior.

## Firewall boundary

Inspect plans without root or mutation:

```bash
python -m megalodon firewall-plan 8.8.8.8 --reason "manual review"
python -m megalodon firewall-install
python -m megalodon block 8.8.8.8 --reason "manual review"
```

Detection-driven policy can record a proposed block only when configured. It
never supplies confirmation or invokes `nft`. Live application remains a
separate operator action after review:

```bash
sudo -E .venv/bin/python -m megalodon firewall-install --apply --confirm MEGALODON
sudo -E .venv/bin/python -m megalodon block 8.8.8.8 \
  --reason "approved incident response" --apply --confirm 8.8.8.8
```

These examples do not authorize applying them. MEGALODON requires an
already-root process, exact confirmation, a valid global target outside the
allowlist, and a finite timeout. It never invokes `sudo`, edits another firewall
table, or creates permanent automatic blocks. Test the nftables path and rollback
in a disposable network namespace before operational use.

## Isolated offline analysis

The offline command is separate from `megalodon run` and must run on Linux as a
non-root, capability-free account. It neither writes the SQLite service database
nor feeds the dashboard or firewall policy.

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

| Issue | Status represented in this README |
| --- | --- |
| [#3 — independent-review enforcement](https://github.com/bartytime4life/MEGALODON/issues/3) | Open governance gate; do not treat green CI or a merge as independent approval |
| [#7 — offline dashboard and operator controls](https://github.com/bartytime4life/MEGALODON/issues/7) | Validated branch-only work; not implemented on `main` |
| [#9 — Suricata EVE contract and fixtures](https://github.com/bartytime4life/MEGALODON/issues/9) | Proposed branch-only contract/tests; no runtime Suricata importer on `main` |

Open issues and branches are coordination/evidence records, not shipped features
or deployment approval. Review the current issue readback before acting because
heads, validation evidence, and governance state can change after this document.

## Validation

Repository-native checks are:

```bash
python -m compileall -q megalodon tests
python -m pytest
python -m megalodon run --source sample --max-events 13
python -m megalodon run --source sample --demo-threat --max-events 114
python -m megalodon firewall-plan 8.8.8.8 --reason "CLI smoke"
```

The smoke commands use synthetic data and a non-mutating firewall plan. They do
not prove live-capture compatibility, installed-TShark behavior, firewall safety
on a specific host, detection accuracy, independent review, or production
readiness.

## Project layout

```text
.github/workflows/           hosted CI
config/                      conservative typed defaults and fixed-rule reference
contracts/automation/v1/     inert automation schema, fixtures, and contract notes
docs/                        proposed automation design and offline analyst guide
examples/                    bounded JSONL replay fixture
megalodon/                   validation, capture, detection, storage, policy, CLI, UI
megalodon/offline/           isolated TShark/Zeek adapters and private reports
tests/                       safety, behavior, offline, and schema contract tests
SECURITY_REVIEW.md           architecture threat assessment and required controls
SPECIFICATION.md             implemented MVP contract and acceptance boundary
```

## Current limits

This is a defensive MVP, not a finished enterprise IDS/IPS. The fixed detections
are simple heuristics. There is no authenticated remote UI, arbitrary rule
authoring, threat-feed or SIEM/SOAR integration, distributed sensor management,
automatic retention job, production rollback orchestration, model execution,
active scheduler, or Suricata runtime importer on `main`.

Before operational deployment, use representative authorized replay data to
measure false positives; validate live capture and TShark separately; define
retention and data-sharing policies; test firewall interaction and rollback in
an isolated environment; and obtain independent security/operations review.
