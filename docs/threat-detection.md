# Threat-signal detection layer

MEGALODON's three **core specification rules** (`SYN_FLOOD`, `PORT_SCAN`,
`DNS_TUNNELING`) are a published, corpus-qualified contract and are unchanged.
The **threat-signal layer** runs beside them on every accepted `PacketEvent` and
adds the five detections a defender most often expects from a network sensor:

| Rule | Default trigger | Severity | Response party | ATT&CK |
| --- | --- | --- | --- | --- |
| `BRUTE_FORCE` | 15 connection attempts from one source to **one host's authentication service** within 60 s | HIGH | source | T1110 |
| `HOST_SWEEP` | one source contacts 24 distinct **internal** hosts within 15 s | MEDIUM | source | T1018, T1046 |
| `DATA_EXFILTRATION` | an internal host sends ≥ 100 MiB of reported bytes to **one public address** within 300 s | HIGH | destination | T1041, T1048 |
| `BEACONING` | 8 consecutive connection starts from an internal host to one public `address:port` at a near-constant interval (≤ 10 % deviation from the median, 5 s – 3600 s) | MEDIUM | destination | T1071, T1573 |
| `IOC_MATCH` | the source or destination matches an operator-supplied **local watchlist** indicator | HIGH (configurable) | matched address | T1071 |

Every finding is a **heuristic for human review**, not a malware verdict. Each
row in the table above has well-known legitimate look-alikes, which the
Findings view shows next to the finding:

* `BRUTE_FORCE` — reconnecting clients, health checks, configuration-management runs.
* `HOST_SWEEP` — inventory scanners, backup agents, printer/NAS discovery.
* `DATA_EXFILTRATION` — cloud backup, file sync, video calls, large uploads.
* `BEACONING` — update checks, telemetry, keep-alives, monitoring agents.
* `IOC_MATCH` — stale indicators, shared hosting, reassigned addresses.

## Exact semantics

* **Connection attempt / start** — TCP with `SYN` and without `ACK`, or a
  flagless TCP flow record. Replies and established-session packets never count.
* **Authentication services** are a fixed code list (SSH 22/2222, Telnet, FTP,
  RDP, VNC, SMB/NetBIOS, Kerberos, LDAP/LDAPS, WinRM, SMTP/submission, POP3/IMAP
  and TLS variants, MySQL, PostgreSQL, MSSQL, Oracle, Redis, MongoDB, Winbox). A
  reference-data update can never widen it. `megalodon detectors` prints it.
* **Internal** means RFC 1918, carrier-grade NAT (100.64.0.0/10), IPv4/IPv6
  link-local and IPv6 unique-local (fc00::/7) unicast. Documentation ranges
  (RFC 5737/3849), loopback, multicast and broadcast are *not* internal.
  **Public** means globally routable unicast.
* `HOST_SWEEP` counts TCP connection attempts, ICMP/ICMPv6 and UDP. UDP to
  service-discovery ports (DNS, DHCP, NTP, NetBIOS, SSDP, mDNS, LLMNR) is exempt.
* `DATA_EXFILTRATION` counts only bytes whose **source** is internal and whose
  destination is public (upload direction), in exact one-second buckets.
* `BEACONING` collapses connection starts that arrive less than
  `beacon_min_interval_seconds` after the previous one, so SYN retransmissions
  and parallel sockets are one contact, not a fast beacon.
* Windows are event-time and inclusive; time is exact integer microseconds.
  A source/key cooldown (default 600 s) suppresses repeats.

## Atomicity and bounds

The layer uses the same staged `prepare → commit / rollback` protocol as the core
detector. If the event's audit bundle does not commit, an undo journal restores
every window, byte total and cooldown exactly. Each key holds at most its own
threshold of entries (e.g. 15 attempt timestamps, 24 hosts, ≤ window-seconds
byte buckets), and one LRU (`max_tracked_keys`, default 8192) caps all keys.

## Response planning

Automatic block planning (still **plan-only** in this release) targets the
*response party* recorded as `evidence.response_target`: the attacking source
for brute force and sweeps, the remote public peer for exfiltration, beaconing
and destination watchlist hits. A finding whose response target is allowlisted
is still recorded, with `suppressed_reason` `source_allowlisted` or
`target_allowlisted`.

## Configuration

```toml
[threat_detection]
enabled = true
brute_force_window_seconds = 60
brute_force_attempts = 15
host_sweep_window_seconds = 15
host_sweep_distinct_hosts = 24
exfiltration_window_seconds = 300
exfiltration_threshold_mib = 100
beacon_min_intervals = 8
beacon_min_interval_seconds = 5
beacon_max_interval_seconds = 3600
beacon_jitter_percent = 10
alert_cooldown_seconds = 600
max_tracked_keys = 8192
# Optional owner-private indicator file; empty disables IOC_MATCH.
watchlist_path = ""
watchlist_severity = "HIGH"
```

Every value is bounded and validated; out-of-range values refuse to load.

## Local IOC watchlist

The watchlist is a plain text file you control. No feed is fetched.

```text
# one IP or CIDR per line; text after # is a label shown with the finding
203.0.113.66            # reported C2 host
198.51.100.0/24         # scanner range
2001:db8:bad::/48
```

Rules: the file must be an owner-owned regular file (symlinks refused), not
group- or world-writable, ≤ 8 MiB and ≤ 200 000 indicators. Networks broader
than IPv4 /8 or IPv6 /16 are refused so that `0.0.0.0/0` cannot flag everything.
IPv4-mapped IPv6 is folded to IPv4. Matching is longest-prefix first.

```bash
megalodon watchlist check --path ~/.config/megalodon/watchlist.txt
```

```bash
megalodon watchlist match --path ~/.config/megalodon/watchlist.txt --address 203.0.113.66
```

### Importing from a STIX 2.1 bundle

```bash
megalodon watchlist import-stix --bundle intel.json --digest sha256:<hex> --output ~/.config/megalodon/watchlist.txt
```

The bundle is read by the existing bounded, digest-pinned STIX reader. Only
whole-pattern IP equality comparisons are converted, for example
`[ipv4-addr:value = '203.0.113.5' OR ipv4-addr:value = '198.51.100.0/24']`.
Domain, file, URL, compound `AND`/`FOLLOWEDBY` and every other pattern is
counted as *skipped* and never evaluated. Revoked and expired indicators are
skipped. The output is written atomically with mode 0600 and is never
overwritten without `--replace`.

## Trying it

```bash
megalodon run --source sample --demo-threat
```

The synthetic demo now also produces a brute-force burst, an internal host
sweep, an upload large enough for `DATA_EXFILTRATION` and a regular beacon.
`megalodon detectors` prints the threat-signal registry document.

## Boundaries

* Packet metadata only: no payload, credential, TLS or DNS-name inspection.
* Byte counts are *reported* bytes; a sensor that drops packets under-counts.
* A NAT gateway can make many internal hosts look like one source.
* Thresholds are uncalibrated defaults; tune them to your network.
* Absence of findings does not establish that a host or network is safe.
