# MEGALODON Defense MVP

**MEGALODON** = **M**alware **E**limination **G**ateway **A**nd **L**ayered
**O**perations **D**efense **O**nline **N**etwork.

MEGALODON is a local-first defensive network telemetry prototype. It captures
metadata, evaluates a small fixed set of bounded detection rules, stores an
audit trail in SQLite, and serves a read-only local dashboard.

The safe default is **observe only**:

- no firewall mutation;
- no packet payload storage;
- no external threat-intelligence calls;
- no remote dashboard bind;
- no shell command construction from network data;
- no permanent automatic blocks.

The supplied architecture document remains useful as a product direction, but
the original code examples should not be run unchanged. See
[`SECURITY_REVIEW.md`](SECURITY_REVIEW.md) and
[`SPECIFICATION.md`](SPECIFICATION.md) for the completed assessment and
operational contract.

## Quick start

```bash
cd MEGALODON
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[test]"
python -m megalodon run --source sample
python -m megalodon run --source sample --demo-threat
python -m megalodon dashboard
```

Open <http://127.0.0.1:8787/> after starting the dashboard. The sample source
is deterministic enough for a smoke test; `--demo-threat` adds synthetic
SYN-flood and long-DNS-query events so the dashboard has detections to display.

To add one completed offline run to the read-only dashboard, select its absolute
private report directory when the server starts:

```bash
python -m megalodon dashboard \
  --offline-run "$HOME/Analysis/case001/run001"
```

The dashboard loads and validates the summary inputs once; it does not browse
directories, watch files, read or serve record rows, launch an analyzer, expose
candidate evidence details, or add a control endpoint. Offline summaries are
refused on non-loopback binds, even when `--allow-remote` is present. Restart
the dashboard to select another run.

The database is created at `data/megalodon.db`. It stores packet metadata,
detection evidence, and action decisions, but never raw packet payloads.

## Event input

For offline replay, send one JSON object per line:

```json
{"observed_at":"2026-09-06T15:00:00Z","src_ip":"8.8.8.8","dst_ip":"192.0.2.10","protocol":"TCP","src_port":40000,"dst_port":22,"tcp_flags":["SYN"],"byte_count":60}
```

```bash
python -m megalodon run --source jsonl --input examples/events.jsonl
cat examples/events.jsonl | python -m megalodon run --source jsonl
```

The JSONL adapter rejects records larger than 64 KiB per line. Detector state is
bounded to 4,096 tracked sources and 4,096 events per source window.

The optional live source uses Scapy and requires the extra dependency plus the
normal Linux permissions for packet capture:

```bash
python -m pip install -e ".[capture]"
python -m megalodon run --source scapy --interface eth0
```

The live adapter extracts only addresses, ports, protocol, flags, sizes, and
DNS name length. It does not persist or print payloads.

## Firewall boundary

The firewall path is deliberately separate from detection. First inspect a
non-mutating plan:

```bash
python -m megalodon firewall-plan 8.8.8.8 --reason "manual review"
python -m megalodon firewall-install
python -m megalodon block 8.8.8.8 --reason "manual review"
```

Detection-driven policy can record a proposed block, but it never supplies its
own confirmation or invokes `nft`. Setting `auto_block=true` therefore remains
plan-only and requires `dry_run=true`; live application is available only through
the explicit `block --apply` command below after operator review.

The isolated `inet megalodon` table uses timeout-enabled IPv4 and IPv6 sets.
It has an accept policy and adds only its own set-drop rules. Applying it is an
explicit root operation and requires confirmation:

```bash
sudo -E .venv/bin/python -m megalodon firewall-install --apply --confirm MEGALODON
sudo -E .venv/bin/python -m megalodon block 8.8.8.8 \
  --reason "approved incident response" --apply --confirm 8.8.8.8
```

The application does not invoke `sudo`, does not prompt for credentials, and
does not edit another firewall table. The default allowlist protects loopback,
private IPv4, and unique-local IPv6 ranges. The default policy also rejects
non-global targets. Review those boundaries before any live use.

## Commands

| Command | Effect |
| --- | --- |
| `run --source sample` | Process built-in benign sample metadata |
| `run --source sample --demo-threat` | Add synthetic detections |
| `run --source jsonl` | Replay validated JSONL metadata |
| `run --source scapy --interface IFACE` | Optional live metadata capture |
| `dashboard` | Start the responsive read-only localhost dashboard |
| `dashboard --offline-run ABSOLUTE_PATH` | Add one validated complete offline summary snapshot |
| `firewall-plan IP` | Print a non-mutating time-limited block plan |
| `firewall-install` | Print the isolated nftables table plan |
| `block IP --reason TEXT` | Print a block plan; `--apply` is required to mutate |

## Project layout

```text
config/             typed TOML defaults and fixed rule reference
examples/           offline JSONL fixture
megalodon/        validation, capture, detection, storage, policy, CLI, UI
tests/              unit tests for the safety boundary and rules
SECURITY_REVIEW.md  assessment of the supplied design
SPECIFICATION.md    completed MVP and future-system contract
```

## Current limits

This is a safe implementation scaffold, not a finished enterprise IDS/IPS.
The three rules are intentionally simple heuristics. Threat feeds, ML, maps,
full rule authoring, clustering, distributed collection, authentication,
retention jobs, and production-grade firewall rollback still require separate
review and tests. The `nftables` table should be installed and exercised in an
isolated test environment before it is considered operational.

## Documentation

- [Automation Contract](docs/automation-contract.md) — proposed scheduling, execution, audit, and safety contract for future automation work. It is not an implementation or authorization to enable autonomous response.

## Isolated offline analysis

`python -m megalodon.offline` is a separate, non-root Linux command for bounded
TShark capture-file replay or versioned Zeek JSON/TSV `conn.log` import. It writes
local redacted JSONL/CSV, run manifests, deterministic metadata baselines, and
review-only candidate findings. It does not change the three-source MVP service,
write its SQLite database, automatically feed its dashboard, or invoke firewall
policy. The dashboard can explicitly load one completed private report snapshot
at startup without ingesting the records into SQLite.

Read [Offline metadata analysis v1](docs/offline-analysis.md) for exact commands,
fixed limits, typed schemas, isolated analyst operations, redaction limitations,
and the read-only dashboard projection. TShark is an optional reviewed
system executable, not a Python dependency. No SIEM/SOAR exporter exists; external
sharing remains blocked pending an explicit approved data-sharing/egress policy.
The new command does not implement or override the proposed automation contract.
