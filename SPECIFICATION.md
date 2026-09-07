# MEGALODON completed specification

MEGALODON means **Malware Elimination Gateway And Layered Operations Defense
Online Network**. The name describes the system’s defensive mission; it does
not change the evidence and safety boundaries below.

## 1. Mission and boundary

MEGALODON provides local defensive network telemetry and bounded response for
a Linux host. It is an evidence-producing assistant, not an autonomous
authority to change the host’s network policy.

The MVP supports three sources (sample, JSONL replay, and optional Scapy),
three fixed detection rules, SQLite audit storage, a local read-only dashboard,
and an explicit nftables plan/application boundary.

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
9. **Local bind by default.** A non-loopback dashboard bind requires an explicit
   command-line opt-in and remains unauthenticated, so it is not recommended.
10. **Fail closed for unsafe response.** Invalid targets, unavailable nft, lack
    of root, missing confirmation, and protected networks refuse the action.
11. **Offline projection stays local.** A selected offline run must be a complete,
    private, bounded report set. Its dashboard projection is never available on
    a non-loopback bind.

## 3. Data contracts

### PacketEvent

```text
observed_at: timezone-aware UTC timestamp
src_ip, dst_ip: normalized IPv4 or IPv6 address
protocol: uppercase protocol label
src_port, dst_port: optional integer 0..65535
tcp_flags: subset of FIN/SYN/RST/PSH/ACK/URG/ECE/CWR
dns_query_length: optional non-negative metadata length
byte_count: non-negative integer
interface: optional bounded label
metadata: JSON object with non-payload metadata only
```

### DetectionResult

```text
rule_id, severity, source/destination, message,
evidence, recommendation, suppressed_reason
```

Detection is evidence, not proof of malicious intent. In particular, a long DNS
name can be legitimate and a high SYN count can be a load test.

### ActionRecord

```text
created_at, action, target, status, reason, expires_at, details
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

The dashboard exposes only:

- `GET /` — static local dashboard;
- `GET /api/summary` — event, detection, action, and high/critical counts;
- `GET /api/events?limit=N` — recent detections, capped at 200;
- `GET /api/offline-summary` — either `available: false` or one immutable,
  validated `dashboard-offline-summary-v1` snapshot selected at startup.

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

Responses are `no-store` and carry restrictive content-security, framing,
referrer, permissions, cross-origin-resource, and MIME-sniffing headers. Data is
inserted into the page with DOM text nodes rather than raw HTML interpolation.

## 7. Retention and privacy

The store keeps normalized metadata and evidence JSON. It must be assigned a
retention period before production use. The `Store.purge_before()` hook exists
for a scheduled retention job but no scheduler is enabled automatically.

External feed lookups, IP geolocation, and cloud analytics are not enabled. Any
future integration must document what identifiers leave the host and require
an explicit configuration switch.

## 8. Validation and acceptance

The MVP is acceptable for local experimentation when:

- unit tests pass;
- malformed IPs and ports are rejected;
- allowlisted and non-global block targets are refused;
- plan mode produces no firewall subprocess;
- dashboard binds only to loopback by default;
- offline summaries reject incomplete, public, linked, mismatched, or tampered
  report sets and remain unavailable on remote binds;
- sample replay produces a database and no firewall mutation;
- `--demo-threat` creates detection and action records;
- no code path uses `shell=True`.

Before any production rollout, add integration tests against a disposable
network namespace, verify interaction with the host’s existing nftables owner,
measure detection false positives on representative replay data, and document
operator approval and rollback.
