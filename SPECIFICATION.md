# MEGALODON MVP specification and proposed platform extension

MEGALODON means **Malware Elimination Gateway And Layered Operations Defense
Online Network**. The name describes the system’s defensive mission; it does
not change the evidence and safety boundaries below.

The Linux implementation contract and its safety invariants remain in force.
The Windows extension in section 10 is **PROPOSED**, not an implemented or
validated port. The canonical installation, application-selection, and platform
configuration baseline is [docs/platform-baseline.md](docs/platform-baseline.md).

## Document status and authority

This specification describes behavior present in the repository unless a
section is explicitly labeled proposed, contract-only, optional, or a future
production gate. The README is the operator entry point; the security review
owns the threat/control analysis; specialized documents own their versioned
offline, automation, platform, and Suricata boundaries. A merged contract or a
green test run does not by itself create a runtime integration or deployment
approval.

## 1. Mission and boundary

MEGALODON provides local defensive network telemetry and bounded response for
a Linux host. It is an evidence-producing assistant, not an autonomous
authority to change the host’s network policy.

The MVP supports three sources (sample, JSONL replay, and optional Scapy),
three fixed detection rules, SQLite audit storage, a local read-only dashboard,
and an explicit nftables plan/application boundary.

Optional Scapy intake uses a fixed 1,024-event metadata queue. The callback does
not block; the first overflow makes the consumer stop with a bounded error and
does not publish queued events after the loss boundary. This is application
backpressure behavior, not proof of kernel capture-buffer sizing or loss-free
operation under production load.

### Non-goals for the MVP

- deep-packet inspection or payload retention;
- malware attribution or geolocation claims;
- threat-intelligence feed ingestion;
- machine-learning model training or automatic model decisions;
- remote multi-user control;
- replacing the host firewall manager;
- silently changing routes, DNS, services, or kernel settings.

## 2. Safety invariants

1. **Observe by default.** A fresh configuration cannot mutate the firewall.
2. **Validate before action.** IP addresses, ports, flags, timestamps, and
   reasons are parsed before persistence or command construction.
3. **No shell interpolation.** Network-derived values never become shell code.
4. **Allowlist wins.** A source in the configured protected networks cannot be
   blocked by the MVP action path.
5. **Expiry is mandatory.** A block plan has a finite timeout; permanent blocks
   are not an MVP operation.
6. **Evidence is metadata-only.** Payloads and payload hashes are outside the
   event model.
7. **Audit every decision.** Alert, suppression, non-attempt, planned, applied,
   and failed actions are written to the action ledger.
8. **Dashboard is read-only.** The HTTP surface has no mutation endpoint.
9. **Loopback binds only.** The dashboard refuses non-loopback addresses and
   the legacy remote opt-in. It does not provide remote authentication.
10. **Fail closed for unsafe response.** Invalid targets, unavailable nft, lack
    of root, missing confirmation, and protected networks refuse the action.
11. **Offline projection stays local.** A selected offline run must be a complete,
    private, bounded report set. Its dashboard projection is never available on
    a non-loopback bind.
12. **Event time fails closed.** Core records are nondecreasing per normalized
    source and no more than 60 seconds ahead of the detector's aware UTC clock.
    Rejected chronology does not mutate detector state or enter the event ledger.

## 3. Data contracts

### PacketEvent

```text
observed_at: timezone-aware UTC timestamp
src_ip, dst_ip: normalized IPv4 or IPv6 address
protocol: uppercase protocol label
src_port, dst_port: optional integer 0..65535
tcp_flags: subset of FIN/SYN/RST/PSH/ACK/URG/ECE/CWR
dns_query_length: optional non-negative metadata length, at most 2^63 - 1
byte_count: non-negative integer, at most 2^63 - 1
interface: optional bounded label
metadata: immutable, closed adapter provenance; empty or source_adapter=tshark-fields-v1
```

### DetectionResult

```text
bounded rule_id; severity in LOW/MEDIUM/HIGH/CRITICAL; source/destination;
bounded message and recommendation; bounded JSON evidence; optional bounded suppressed_reason
```

Detection is evidence, not proof of malicious intent. In particular, a long DNS
name can be legitimate and a high SYN count can be a load test.

### ActionRecord

```text
UTC created_at; bounded action, target, reason and details; optional UTC expires_at;
status in not_attempted/suppressed/planned/applied/failed
```

Statuses include `not_attempted`, `suppressed`, `planned`, `applied`, and
`failed`. The ledger is the authoritative record of what MEGALODON did and
did not do.

## 4. Fixed MVP rules

| ID | Trigger | Severity | Evidence | Default response |
| --- | --- | --- | --- | --- |
| `SYN_FLOOD` | At least 100 TCP SYN-without-ACK events from one source in 10 seconds | HIGH | count and window | alert only |
| `PORT_SCAN` | At least 20 distinct TCP destination ports from one source in 5 seconds | MEDIUM | distinct-port count and window | alert only |
| `DNS_TUNNELING` | DNS/UDP query metadata length at least 50 | CRITICAL | observed length and threshold | alert only |

Rules use bounded in-memory deques and emit at most one alert per source/rule
within the configured cooldown. That reduces duplicate noise; it does not
prove the activity stopped.

## 5. Operational modes

### Observe

The default mode. Events are validated, detections are stored, and action
decisions are recorded as `not_attempted`. No root permission is needed for
sample or JSONL input.

### Plan

The CLI prints a fully validated nftables command or isolated-table script but
does not execute it. This is the required review step before live enforcement.

### Apply

An operator explicitly invokes `--apply` and an exact confirmation value. The
process must already be running as root; it never invokes `sudo`. The isolated
table uses timeout-enabled sets and an accept policy. Existing firewall state is
not rewritten.

### Automatic planning and explicit response

The service may create an auditable, time-limited block plan when `enabled=true`,
`auto_block=true`, and `dry_run=true`. It never supplies its own confirmation or
invokes `nft`; `auto_block=true` with `dry_run=false` is rejected as unsafe.
Application remains a separate operator CLI action requiring `--apply`, exact
target confirmation, and already-held root. Unattended response is not an MVP
operation.

## 6. Dashboard contract

The IPv4 server accepts only dotted-decimal addresses in `127.0.0.0/8` or the
literal `localhost`, mapped directly to `127.0.0.1` without DNS. IPv6, mapped or
scoped addresses, other hostnames, wildcards and non-loopback addresses are
refused before socket creation. `--allow-remote` (and programmatic
`allow_remote=True`) is retained only for a bounded startup refusal, even with
a loopback address. The CLI checks the bind before opening the audit store or
loading an offline report; `serve()` independently enforces the same boundary.
This does not authorize a proxy, tunnel or port-forwarding workaround.

The dashboard exposes only:

- `GET /` — static local dashboard;
- `GET /assets/dashboard.css` and `GET /assets/dashboard.js` — same-origin,
  no-store presentation assets;
- `GET /api/config` — a non-sensitive `dashboard-config-v1` view contract;
- `GET /api/summary` — event, detection, action, and high/critical counts;
- `GET /api/events?limit=N` — recent detections, with one decimal integer from
  1 through 200; malformed, repeated, out-of-range, and unknown query fields
  fail with `400` rather than being silently coerced. Each returned detection
  contains only `detected_at`, `rule_id`, `severity`, `src_ip`, and `message`;
  stored destination addresses, evidence, recommendations, and suppression
  reasons are excluded from the browser contract;
- `GET /api/offline-summary` — either `available: false` or one immutable,
  validated `dashboard-offline-summary-v1` snapshot selected at startup.

`dashboard.refresh_seconds` is an integer from 2 through 300 and
`dashboard.event_limit` is an integer from 1 through 200. The matching
`--refresh-seconds` and `--event-limit` command options override configuration
for one launch. The browser uses a single non-overlapping timeout loop, pauses
polling while hidden or when the operator selects pause, and retains the last
successfully rendered rows across a refresh failure. Search and severity
filters operate only on the bounded in-memory recent set; they do not query new
fields, persist preferences, change SQLite, or create an export.

All configuration counters are native TOML integers; booleans, floats, and
numeric strings are rejected instead of coerced. Detector windows are capped at
3,600 seconds, cooldown at 86,400 seconds, DNS metadata length at 65,535, and
tracked-source/per-source-event state at 65,536 each. Firewall timeout is capped
at 604,800 seconds. CLI ports, polling controls, and event limits enforce their
documented bounds during argument parsing.

`--offline-run ABSOLUTE_PATH` accepts only a complete `offline-run-v1` report
directory with private ownership and permissions, no symlink components, fixed
report names, matching source/adapter/unit contracts, and bounded manifest,
baseline, and candidate files. Record files receive fixed-name, type, ownership,
permission, and size checks but are neither parsed nor served. The API includes
run/source identity, counts, tool provenance, relative time coverage, capped
protocol/port distributions,
candidate-rule counts, and fixed interpretation limits. It excludes addresses,
paths, record rows, packet bytes, and candidate evidence. A web request cannot
select a path, reload a run, launch an analyzer, or invoke firewall policy.

Responses are `no-store` and carry restrictive content-security, opener,
framing, referrer, permissions, cross-origin-resource, and MIME-sniffing
headers. CSS and JavaScript are separate same-origin resources; the policy does
not allow inline scripts or inline styles. Data is inserted into the page with
DOM text nodes rather than raw HTML interpolation. Search, severity, refresh,
and pause controls are labeled for keyboard and assistive-technology use, and
timestamps use semantic `time` elements.

## 7. Retention and privacy

The store keeps normalized metadata and evidence JSON. It must be assigned a
retention period and finite capacity/stop budget before production use. The
internal `Store.purge_before()` hook can atomically delete matching audit rows,
but no CLI, preview receipt, scheduler, default cleanup, or automatic caller is
provided. SQLite audit data and standalone offline report sets have independent
operator-owned retention decisions; authority over one never covers the other.

External feed lookups, IP geolocation, and cloud analytics are not enabled. Any
future integration must document what identifiers leave the host and require
an explicit configuration switch.

## 8. Validation and acceptance

The MVP is acceptable for local experimentation when:

- unit tests pass;
- malformed IPs and ports are rejected;
- allowlisted and non-global block targets are refused;
- plan mode produces no firewall subprocess;
- dashboard rejects unsafe binds and legacy overrides before socket creation;
- offline summaries reject incomplete, public, linked, mismatched, or tampered
  report sets and remain unavailable on remote binds;
- sample replay produces a database and no firewall mutation;
- `--demo-threat` creates detection and action records;
- no code path uses `shell=True`.

Before any production rollout, add integration tests against a disposable
network namespace, verify interaction with the host’s existing nftables owner,
measure detection false positives on representative replay data, and document
operator approval and rollback.

## 9. Implemented extensions and separate evidence paths

`python -m megalodon.offline` provides a separate Linux-only, non-root,
capability-free analysis path. Fixed
TShark fields produce packet metadata; separately versioned Zeek JSON/TSV
connection adapters produce flow records. Private local reports, source-qualified
baselines, review candidates, and a last-written completion manifest follow
[docs/offline-analysis.md](docs/offline-analysis.md).

This path does not populate the service SQLite database, drive its fixed-rule
policy, drive live dashboard polling, or apply firewall actions. An explicitly
selected completed report may separately supply the startup-only dashboard
summary described in section 6; its record rows are neither ingested nor served.
Packet, flow, and future sensor-alert counts must not be conflated. A candidate is review evidence, not
an action or malware finding. No packet payload or payload-derived hash is
admitted by adopting an external analyzer.

[contracts/automation/v1](contracts/automation/v1/README.md) contains an inert
normative-draft schema and fixtures. It is not scheduler execution, recurrence
calculation, model access, or permission to use commands, endpoints, or tools.
[contracts/suricata-eve/v1](contracts/suricata-eve/v1/README.md) contains an
inert EVE-alert schema, synthetic fixtures, conformance tests, and the adopted
[bounded-reader contract](contracts/suricata-eve/v1/reader/README.md). These
closed contract gates specify record, filesystem, quota, replay, and completion
requirements for later work. They remain contract-only: there is no production
reader/importer, sensor operation, ruleset manager, durable consumer, or IPS
path. The offline dashboard projection is implemented independently and does
not accept or display Suricata alert records.

`megalodon capabilities` returns a deterministic static catalog of these
boundaries for Linux, Windows, or another platform family. It performs no host
probe, installation, process launch, network access, capture, or configuration
change. A catalog status is not installed-tool or platform compatibility proof.

`megalodon hub-plan` composes that catalog into the closed workflow map defined
in [docs/integration-hub.md](docs/integration-hub.md). It is implemented as a
static, non-executing plan: entry points identify existing owners but are not
commands selected from input or authorization to run them. The plan reads no
input, configuration, evidence, executable, or host-state files and performs no
probe, subprocess, network request, persistence, capture, or host mutation. It
cannot upgrade a component's platform status.

## 10. Proposed Windows/Linux platform contract

The [platform baseline](docs/platform-baseline.md) defines L1 (Ubuntu 24.04),
W1 (native Windows 11 synthetic core evaluation), and W2 (a separately validated
Linux analysis guest on Windows). A platform is not supported merely because
Python or an upstream analyzer installs there. The current CI workflow has an
Ubuntu 24.04/Python 3.11 job; there is no Windows validation lane.

The first native Windows implementation slice is limited to validation,
sample/JSONL processing, fixed detections, SQLite, and a read-only loopback UI.
It must preserve the same bounded metadata and action-state contracts. It must
also provide explicit, tested rejection of unsupported operations without
raising privilege, choosing a substitute tool, or changing security settings.
The static capability catalog makes unsupported and evaluation-only states
explicit, but it does not implement or certify native Windows portability.

The [Windows core acceptance matrix](docs/windows-core-acceptance.md) identifies
the reusable test set and required native receipts. Windows attempts to select
Scapy capture, nftables, offline analysis, or offline dashboard projection now
fail before optional imports, executable/privilege checks, subprocesses, or
POSIX file access. These Linux-run negative controls do not promote the Windows
core beyond evaluation-only status.

Windows offline analysis requires its own reviewed file-handle/identity,
reparse-point, local-path, ACL, subprocess-tree, timeout, and resource-boundary
implementation. Removing Linux platform/capability checks or replacing the
TShark executable string is not acceptance. Guest Linux execution is not native
Windows support and cannot establish visibility into all host traffic.

Windows firewall response remains unavailable. A future backend needs explicit
operator authority, target validation, allowlist precedence, non-global
rejection, exact confirmation, already-held privilege, finite expiry under
restart/sleep/failure, ownership/conflict checks, rollback, and truthful audit
states. A best-effort scheduled deletion is not proven expiry. Do not modify
Windows Firewall, endpoint protection, services, or capture drivers as setup.

Before any Windows support claim, record an exact-head Linux regression result,
Windows core test result, dependency/install receipt, private-storage ACL
review, loopback UI/API checks, and unsupported-feature rejection tests.
Preserve the required Linux `test` check; a Windows lane adds evidence rather
than renaming, bypassing, or weakening it. Installed-analyzer tests, independent
review, and operational deployment each remain separate gates.

Optional Suricata, Zeek, ClamAV, and osquery use does not authorize raw log or
file-content ingestion. Every future integration requires its own versioned,
bounded schema and privacy review. All profiles remain observe-only by default,
local-first, metadata-only, and without autonomous response or telemetry egress.
