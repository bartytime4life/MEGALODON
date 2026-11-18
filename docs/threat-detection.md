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
| `DECOY_TOUCH` | anything contacts a configured **decoy port** or **unassigned decoy address** | CRITICAL | source | T1046, T1018 |
| `IOC_MATCH` | the source or destination matches an operator-supplied **local watchlist** indicator (an address, or with `dns_names` a looked-up domain) | HIGH (configurable) | matched address, or the querying host | T1071 |
| `DGA_DOMAIN` | *(opt-in `dns_names`)* a looked-up domain has two or more machine-generated spelling signals | MEDIUM | querying host | T1568.002 |
| `DNS_TUNNEL_CHURN` | *(opt-in `dns_names`)* one host queries 30 distinct subdomains of one domain within 60 s | HIGH | querying host | T1071.004, T1048.003 |
| `TLS_WITHOUT_SNI` | *(opt-in `tls_fingerprints`)* an internal host opens TLS directly to a public address without a server name | LOW | the bare server | T1573, T1071.001 |

Every finding is a **heuristic for human review**, not a malware verdict. Each
row in the table above has well-known legitimate look-alikes, which the
Findings view shows next to the finding:

* `BRUTE_FORCE` — reconnecting clients, health checks, configuration-management runs.
* `HOST_SWEEP` — inventory scanners, backup agents, printer/NAS discovery.
* `DATA_EXFILTRATION` — cloud backup, file sync, video calls, large uploads.
* `BEACONING` — update checks, telemetry, keep-alives, monitoring agents.
* `DECOY_TOUCH` — a misconfigured client, a stale DNS or ARP entry, or your own test.
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

## Decoys (tripwires)

A decoy is something no legitimate client should ever touch, so a contact is
a high-confidence signal with very few false alarms. MEGALODON detects decoy
contact from captured metadata alone: **nothing listens, nothing answers and
no new attack surface is opened.**

* **Decoy ports** — pick ports that no real service on your network uses, for
  example `2222`, `3390` or `4455`. A TCP connection attempt (SYN without ACK, or
  a flagless flow record) or any UDP packet to that port on any host trips it.
* **Decoy addresses** — reserve a few unassigned internal addresses (outside
  your DHCP pool) and list them. Any packet to them trips it; this is a small
  "darknet" sensor for internal scanning and lateral movement.

```toml
[threat_detection]
decoy_ports = [2222, 3390, 4455]
decoy_addresses = ["192.168.1.250", "192.168.1.251"]
```

Up to 64 ports and 256 addresses; addresses must be unicast and non-loopback.
Each (source, decoy) pair alerts once per cooldown. Decoys only see what the
capture sees: put the sensor where the traffic to them flows.

For host-side tripwires (bait files) and authentication-log review, see
[host tripwires and login review](host-tripwires.md).

## DNS domain names (opt-in)

MEGALODON's capture **does not read DNS query names by default**: they are a
record of every site the computer visits. Turn it on only if you want
domain-based detection:

```toml
[threat_detection]
dns_names = true
dns_churn_window_seconds = 60
dns_churn_distinct_subdomains = 30
```

When enabled:

* **Where names come from.** The HUD's TShark capture adds `dns.qry.name` and
  `dns.flags.response`, and `megalodon run --source scapy` reads the query
  name. Only *queries* count: responses echo the client's question, and rows
  with several questions are ambiguous, so neither yields a name. JSONL input
  may carry a `dns_query_name` field.
* **Whole packets.** With names on, the HUD capture keeps whole packets
  (snapshot length 65535 instead of the metadata-only 256 bytes), so a long
  query name is not cut off. Packets still go only through a pipe to TShark
  and are never written to disk.
* **What is kept.** Names stay in memory for detection. The events table
  never stores them. A domain is retained only when it triggers a finding,
  inside that finding's evidence. A test checks the raw database bytes for
  routine lookups.
* **`DGA_DOMAIN`** reuses the reviewed spelling scorer in `domain_signals.py`
  (entropy, length, digit mixing, consonant runs, hexadecimal, stacked or
  deep labels). It fires at its `review` level: two or more signals, and not
  under a provider that generates names by design (CloudFront, Akamai,
  Fastly, Azure, Google user content, reverse-lookup zones).
* **`DNS_TUNNEL_CHURN`** counts distinct subdomains per (host, registrable
  domain), the pattern used by iodine and dnscat2 and by DNS exfiltration.
  Reverse lookups, `.local`, `.lan`, `.internal` and generated-name
  providers are exempt.
* **Domain watchlist entries** (for example `evil.example`) match the name
  and every subdomain. A bare TLD is refused. `import-stix` converts
  `[domain-name:value = '…']` patterns too.
* **The core `DNS_TUNNELING` length rule** also receives the query length
  from TShark capture once names are enabled.

**Limits:**

* The registrable domain is approximated (the last two labels, or three under
  common two-label suffixes such as `co.uk`), not taken from the full public
  suffix list.
* DNS over HTTPS or TLS, and resolver caching, hide queries from the sensor.
* The sensor must see the client's queries: run it on that computer, or
  between it and its resolver.

## TLS client fingerprints (opt-in)

TLS ClientHellos travel in clear text. A **JA3** or **JA4** fingerprint
summarizes the client's TLS stack (versions, ciphers, extensions, ALPN), so a
malware family or offensive tool can be recognized even when it changes IP
addresses. The **server name (SNI)** names the site being visited, so this is
**off by default**:

```toml
[threat_detection]
tls_fingerprints = true
```

When enabled:

* **Capture.** The HUD's TShark capture reads `tls.handshake.type`,
  `tls.handshake.ja3`, `tls.handshake.ja4` and
  `tls.handshake.extensions_server_name`, from single ClientHellos only. It
  keeps whole packets (snapshot length 65535 instead of 256 bytes): a
  ClientHello is usually over 500 bytes, and when one is cut TShark computes no
  fingerprint at all. Packets go only through a pipe to TShark, never to disk.
* **Field probing.** TShark refuses to start on an unknown field, and JA4
  needs Wireshark 4.2 or later. Each capture therefore first probes which of
  these fields the installed TShark accepts, using a header-only pcap on stdin,
  and uses that subset. With JA3 only, everything except JA4 matching still
  works.
* **Other inputs.** JSONL input may carry `tls_ja3`, `tls_ja4` and `tls_sni`
  (for example exported from Zeek or Suricata). The Scapy source does not
  compute fingerprints.
* **What is kept.** Fingerprints and names stay in memory. Only one that
  triggers a finding is kept, in that finding's evidence. A test checks the
  raw database bytes.
* **Fingerprint watchlist.** Add lines such as
  `ja3:72a589da586844d7f0818ce684948eea # known C2 client` or
  `ja4:t13d1516h2_8daaf6152771_02713d6af862`. A match raises `IOC_MATCH`
  against the client host. Published fingerprint lists (for example
  abuse.ch SSLBL) go stale and collide with legitimate software, so verify
  before acting.
* **SNI checks.** The SNI goes through the same domain-watchlist and
  generated-name (`DGA_DOMAIN`) checks as DNS names. These still work when
  DNS itself is encrypted (DNS over HTTPS or TLS).
* **`TLS_WITHOUT_SNI`** (LOW) flags an internal host opening TLS straight to
  a public IP without naming a server, a common command-and-control trait.

**Limits:** Encrypted Client Hello (ECH) hides the real server name, and
QUIC/HTTP-3 handshakes are not fingerprinted. A fingerprint identifies a TLS
library and configuration, not a program.

## LAN integrity: ARP, neighbour discovery, rogue DHCP and routers (opt-in)

ARP, IPv6 neighbour discovery, DHCP and DHCPv6 have no authentication, so
any device on the LAN can claim to be the gateway or hand out its own gateway
and DNS server. That puts it in the middle of everyone's traffic. IPv6 is on
by default on most home and office networks, even where nobody uses it, so it
is an easy way in. MEGALODON can watch for all of these, **off by default**:

```toml
[threat_detection]
lan_integrity = true
arp_rebind_seconds = 300
dhcp_window_seconds = 3600
dhcp_servers = ["192.168.1.1"]   # optional; empty means learn them
ipv6_routers = ["fe80::1"]       # optional; empty means learn them
router_window_seconds = 3600
```

When enabled:

* **Capture.** The HUD's TShark capture adds `arp.opcode`,
  `arp.src.hw_mac`, `arp.src.proto_ipv4` and `arp.dst.proto_ipv4`, and the
  DHCP message type and server identifier (`dhcp.option.dhcp`,
  `dhcp.option.dhcp_server_id`). For IPv6 it adds the neighbour-discovery
  type, router lifetime, advertised target and link-layer address options
  (`icmpv6.type`, `icmpv6.nd.ra.router_lifetime`,
  `icmpv6.nd.na.target_address`, `icmpv6.opt.src_linkaddr`,
  `icmpv6.opt.target_linkaddr`) and the DHCPv6 message type
  (`dhcpv6.msgtype`). Each group is probed and used only when the
  installed TShark accepts all of its fields. The capture keeps whole
  packets, because DHCP options start after byte 256. Packets go only
  through a pipe to TShark.
* **ARP frames become events.** An ARP frame is recorded as an `OTHER` event
  from its sender address to its target address, so it is counted like any
  other packet. Only the binding checks and decoys run on it: an ARP request
  for a decoy address raises `DECOY_TOUCH`, which catches LAN ARP scans. ARP
  frames never count toward traffic rules such as host sweeps.
* **`ARP_SPOOFING`** (HIGH, ATT&CK T1557.002) fires when an IPv4 address is
  claimed by a different hardware address within `arp_rebind_seconds` of the
  previous one answering for it. Tools such as arpspoof, Ettercap and
  bettercap repeat their claims every few seconds, so they trip this
  immediately. ARP probes from `0.0.0.0` claim nothing and are ignored. A
  binding older than the window is treated as a replaced device or a new
  lease.
* **`NDP_SPOOFING`** (HIGH, ATT&CK T1557) is the IPv6 counterpart. A
  neighbour advertisement claims its target address, and a neighbour
  solicitation or router advertisement claims its sender's address, through
  the link-layer address option it carries. The rule fires when an IPv6
  address is claimed by a different hardware address within
  `arp_rebind_seconds` of the previous claim. Duplicate address detection
  (sender `::`) and messages without a link-layer address claim nothing.
* **`ROGUE_DHCP`** (HIGH, ATT&CK T1557.003) checks DHCP OFFER and ACK
  replies from port 67, and DHCPv6 ADVERTISE and REPLY messages from port
  547. With `dhcp_servers` set, any other server is flagged. Without it,
  MEGALODON learns the servers it sees and flags a server that answers while
  another was active within `dhcp_window_seconds`. IPv4 and IPv6 are checked
  separately: listing only IPv4 servers leaves DHCPv6 in learned mode. A
  DHCPv6 server is known by the address its replies come from, usually a
  link-local `fe80::` address. For DHCP, the server identifier option is
  preferred over the packet's source, and a relayed reply records the relay
  address. Rogue DHCPv6 replies are how tools such as mitm6 make themselves
  the DNS server for Windows hosts that never use IPv6 otherwise.
* **`ROGUE_IPV6_ROUTER`** (HIGH, ATT&CK T1557) checks every router
  advertisement. With `ipv6_routers` set, an advertisement from any other
  address is flagged. Without it, MEGALODON learns the routers it sees and
  flags one that advertises while another was active within
  `router_window_seconds`. A rogue advertisement can make its sender every
  IPv6 host's default gateway and hand out its own prefixes and DNS. An
  advertisement with a router lifetime of 0 withdraws a default route
  instead, which is how a router-advertisement flood cuts hosts off. The
  finding records the lifetime and the advertised hardware address.
* **What is kept.** Hardware addresses and server identities stay in memory.
  A binding or server is retained only inside a finding's evidence. A test
  checks every database file's raw bytes for a routine binding.
* **Other inputs.** JSONL may carry `arp_opcode`, `arp_sender_mac`,
  `dhcp_message_type`, `dhcp_server_id`, `nd_type` (134, 135 or 136),
  `nd_mac`, `nd_target` and `ra_router_lifetime`. The Scapy source does not
  read them.

**Limits:** The sensor sees only what reaches its interface. On a switched
network, that is broadcast ARP plus its own traffic, so run it on the
gateway or a mirror port for full coverage. Learned DHCP mode trusts the
first server it sees, and learned router mode the first router. Set
`dhcp_servers` and `ipv6_routers` if a rogue server or router could be present
when monitoring starts. Failover pairs, virtual machines, docking stations,
mesh Wi-Fi nodes and phone hotspots can produce look-alike findings. A router
advertisement that spoofs the real router's address passes the router check,
but its different hardware address raises `NDP_SPOOFING` when it carries one.
Neighbour-discovery messages are checked only without IPv6 extension headers.
Switch-level defences (RA Guard, DHCPv6 Guard, dynamic ARP inspection) stop
these attacks; MEGALODON only reports them.

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

The watchlist is a plain text file you control. Detection never fetches anything. To keep it current
from threat feeds you choose, `megalodon feeds refresh` builds a labeled watchlist on a schedule
(see [threat-feed refresh](threat-feeds.md)).

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
