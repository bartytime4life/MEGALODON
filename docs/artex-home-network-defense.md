# ARTEX defense on a Google Wifi home network

Use MEGALODON to inspect available evidence, improve visibility, and choose a
bounded response. No rule pack or router setting guarantees that ARTEX is
defeated. The first deployment question is which traffic reaches the sensor.

This guide was checked against primary sources on **November 16, 2026**. Its
capability baseline is repository revision `5755d83`; candidate changes need
their own validation and installed-version readback. This document does not
establish that a sensor, rule, firmware update, or response was deployed.
Keep device addresses, MAC addresses, screenshots, captures, and installation
paths in private operator records, outside the repository.

For other router families and the read-only Setup → Traffic selector, see
[router compatibility and capture placement](router-compatibility.md). A profile
selection does not configure a router or establish network-wide coverage.

## What to defend against

The [FBI's November 13 ARTEX advisory](https://www.ic3.gov/CSA/2026/261113.pdf)
describes automated scanning, exploitation of exposed applications, credential
abuse, persistence, and collection. Priorities include reducing exposed
management surfaces, patching applications, limiting permissions, protecting
secrets, and retaining investigation evidence. Historical infrastructure
indicators need current corroboration before blocking: hosted addresses can be
reassigned. Ordinary LLM connections and common scripting clients alone do not
identify ARTEX.

[CERT-EU's November 5 guidance](https://www.cert.europa.eu/blog/from-penetration-testing-to-cyber-threat-beware-of-artex)
emphasizes patching internet-facing assets, isolating management interfaces,
monitoring privileged activity, MFA, and endpoint protection. Apply those
controls to the actual devices and services in use. A home network monitor
cannot patch a router, protect an unrelated cloud tenant, or replace endpoint
security merely by observing traffic.

| Reported behavior | Available MEGALODON evidence | Gap or required control |
| --- | --- | --- |
| Rapid reconnaissance and scanning | Bounded packet metadata and fixed SYN-rate / distinct-destination-port rules; optional passive Suricata summaries | Requires a valid capture path. Many HTTP requests on one port need application-aware evidence; port diversity is not equivalent to web enumeration. |
| Exploiting exposed applications | Suricata alerts when the installed rules recognize visible traffic; local configuration and file-change reviews | Patch and restrict the affected application. Encrypted application payloads are not recovered by passive capture. A signature match is a lead, not attribution. |
| Suspicious DNS or command-and-control traffic | DNS-length heuristic, observed hostname and TLS metadata, dated local reference context | A long name, certificate issue, or reference match does not prove malicious intent. Encrypted DNS, VPN tunnels, and unavailable handshake fields limit visibility. |
| Credential abuse and privileged cloud changes | No Google Wifi traffic view supplies a tenant audit trail | Review identity/service-principal sign-ins and cloud audit records in the relevant service. No supported Entra/Graph ingestion is established by this guide. |
| Data collection or exfiltration | Observed byte counts, retained connection context, and sensor alerts | Volume does not establish sensitive content, unauthorized access, or complete network totals. Correlate endpoint/application records. |
| Response to an observed hostile public endpoint | Separate operator-reviewed, temporary firewall containment on the local Linux PC | Does not block another device, modify Google Wifi, or filter forwarded mesh traffic. |

The baseline packet rules are defined in [the fixed rule reference](../config/rules.toml).
For source and observation limits, see [visual operations](visual-operations-defense.md)
and [support configuration](support-configuration.md). Live EVE summaries remain
separate from [qualified Suricata evidence admission](suricata-evidence-projection.md).
Operational local-model generation remains subject to the
[UNBOUND fence](qwen-runtime-unbound.md); no model is needed to read evidence.

The candidate source adds producer-reported sensor/interface labels to retained
Suricata observations and keeps different producer scopes separate during
deduplication, baseline review and layered review. These labels are not
authenticated engine, run or rule identities. It also adds optional local desktop
hints and explicit staged rule controls under
[support configuration](support-configuration.md). These source features require
installation and acceptance; this guide does not claim they are running.

The ConnectWise campaign matters only if those applications were authorized in
a Microsoft 365 tenant you administer. [Microsoft's investigation guidance](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/)
distinguishes attempted sign-ins, successful authentication, application changes,
and data access. App presence or authentication alone does not establish
exfiltration. Review current and dormant integrations, subsequent Graph activity,
credential additions, and privilege changes. Do not use home-router telemetry
as a substitute for those records. Follow the
[current ConnectWise advisory](https://www.connectwise.com/company/trust/advisories):
its November 4 update describes restoration with new applications and
reauthorization. Previously disabled applications should not be re-enabled;
vendor remediation does not remove unauthorized access created inside a tenant.

## Preserve the Google Wifi mesh

For a wireless mesh, retain this arrangement:

```text
Modem/ONT -- Ethernet --> primary Google Wifi (router/NAT mode)
                              |
                              +~~ wireless mesh ~~> additional Google Wifi points
                              |
                              +-- optional LAN switch --> wired devices
```

Do not put the primary Google Wifi into bridge mode to add a monitoring device.
Google supports that mode only for a single Wifi device; a multi-point mesh
requires its primary to remain in router mode.
[Google bridge-mode documentation](https://support.google.com/googlehome/answer/6240987?co=GENIE.Platform%3DAndroid&hl=en)

If wired backhaul is introduced later, Google's supported order is modem,
primary Wifi, downstream switch, then points/devices. A managed switch must
support the documented STP/BPDU configuration; do not change loop prevention
without reviewing the wiring. Nest Wifi points lack Ethernet ports, while
Google Wifi points support them. Verify the model rather than relying on a
shared product-family name.
[Google hardwiring guide](https://support.google.com/googlehome/answer/7215624?hl=en),
[Google switch guide](https://support.google.com/googlehome/answer/6274262)

As checked November 16, Google's current-version table lists **Google Wifi
14150.376.32**. Its September 2022 release date does not make a newer **Nest Wifi
router** version applicable to Google Wifi. Check each device's model and
version in Google Home and recheck the release page before deciding an update
is missing. Updates are automatic and can be staged. This is a vendor-version
comparison, not proof of installed firmware, vulnerability absence, or protection
against ARTEX.
[Google firmware release notes](https://support.google.com/googlehome/answer/13800967)

Google Home provides connected-device details and per-device data usage; its
network totals describe Internet/WAN traffic.
[Google usage documentation](https://support.google.com/googlehome/answer/6263633?hl=en)
These statistics are not packet captures or an IDS event feed. No supported
consumer Google Wifi SPAN, syslog, or remote packet-export configuration was
identified in the official documentation reviewed for this guide. Treat a
native MEGALODON router feed as unverified, not as an available integration.

## Review Google Home security settings

These are manual Google Home controls; MEGALODON does not read or change them.
In **Home → Wifi → Settings → Advanced Networking**, review **Port management**
for both IPv4 forwarding and IPv6 openings. Keep only services deliberately
exposed and maintained. Remove unused entries after recording their purpose
and confirming the affected service can stop being reachable from the Internet.
[Google port-management documentation](https://support.google.com/googlehome/answer/6274503?hl=en)

Review **UPnP** on the same page. It is enabled by default and lets devices
request Internet-facing port openings. Disable it if those automatic openings
are unnecessary; games, casting and device discovery may need compatibility
checks. Do not replace it with broad manual forwarding.
[Google UPnP documentation](https://support.google.com/googlehome/answer/6274337?hl=en)

Use a strong, unique Wi-Fi password. Consider **Use Wi-Fi Protected Access 3**
under Advanced Networking after checking client compatibility; Google warns
that some older WPA2 devices have trouble with WPA3 transition mode. This
protects wireless access, not compromised application credentials or exposed
services. Record any change and test required devices before considering it
complete.
[Google wireless-security guidance](https://support.google.com/googlehome/answer/9216542?hl=en),
[Google WPA3 control and compatibility](https://support.google.com/googlehome/answer/6293481?hl=en-CA)

## Choose and verify a capture path

An ordinary Wi-Fi connection to the network does not provide a copy of all
other devices' traffic. Promiscuous mode alone does not make a switch or access
point forward that traffic to the sensor. The following coverage differences
are engineering inferences from packet paths, to be verified on the installation:

| Placement | Expected evidence | Missing coverage / attribution |
| --- | --- | --- |
| Existing host interface | Traffic delivered to or sent by that host, plus some broadcast/multicast | Other clients' unicast traffic is not established. |
| Mirror of primary Google Wifi's LAN Ethernet link | Traffic crossing that cable, including connected wired devices and wired-backhaul traffic | Primary Wi-Fi Internet traffic and wireless-backhaul paths can bypass the cable. Local traffic elsewhere remains unseen. |
| WAN-side TAP or external switch mirror | Internet traffic crossing the primary's uplink, including wireless mesh clients | IPv4 is after NAT, usually exposing one router address rather than original client addresses. Local-only traffic never crosses this link. |

IPv6 needs separate treatment: Google Wifi supports dual stack and clients can
receive globally routed addresses. A WAN observation may retain a client's IPv6
address; it still needs time-bound device mapping and may change. Do not label
every WAN flow as attributable to a stable device, or assume IPv4 NAT hides IPv6.
[Google IPv6 documentation](https://support.google.com/googlehome/answer/6361450?hl=en)

For whole-mesh Internet observation while preserving wireless backhaul, the
candidate topology is:

```text
Modem/ONT -- suitable network TAP -- primary Google Wifi WAN
                     |
                     +-- copied traffic --> sensor CAPTURE_IFACE

sensor MANAGEMENT_IFACE -- protected LAN --> MEGALODON / local EVE review
```

This is a design, not an installed or Google-certified integration. No purchase
is assumed. First inventory available hardware, Ethernet handoff requirements,
link speed, IPv6, and sensor interfaces. Check TAP direction aggregation and
capacity; alternatively, verify an existing external switch's bidirectional
mirroring, management isolation, and throughput. Never connect an ordinary
management interface to the WAN segment. Keep the capture interface without
normal host addressing or routing, separate from protected management. A
copy-only sensor should not become a new traffic-forwarding dependency.

Before an authorized wiring change, record the original cable path and direct
reconnection rollback. After installation, verify both traffic directions from
a device on the primary and from each mesh point, using benign traffic between
owned endpoints. Check IPv4 and IPv6 where enabled, timestamps, packet/drop
counters, and sustained rate. Record which paths were tested and which were
not. A running process, one alert, or zero alerts does not establish coverage.
An overloaded mirror or sensor can lose packets.

Configure `HOME_NET` for addresses visible at the capture position. A WAN-side
sensor must not assume that private LAN IPv4 addresses remain visible. Recheck
address/prefix changes. `CAPTURE_IFACE`, `MANAGEMENT_IFACE`, `192.0.2.0/24`, and
`2001:db8::/32` are documentation placeholders, not install values or scan targets.

MEGALODON's [live Suricata setup](support-configuration.md) configures a passive
service for a selected interface and retains existing rules; a successful setup
does not prove the mirror exists. The [offline configuration guide](installing-suricata.md)
instead prepares saved-capture configuration and does not start a sensor. Use
the correct workflow. Suricata distinguishes passive IDS observation from
inline IPS filtering; a copy-only sensor cannot stop the original packet.
[Suricata IPS concepts](https://docs.suricata.io/en/latest/ips/ips-concept.html)

## Respond within the verified control scope

Review timestamp, source, coverage, expected activity, and corroborating
evidence before acting. Do not automatically block historical campaign IPs,
ordinary LLM services, or shared infrastructure solely because of a reference
match. Record suspected, confirmed, attempted, and completed outcomes separately.

For a currently observed public endpoint, the existing
[local containment workflow](visual-operations-defense.md#temporary-containment)
creates a 60-second, single-use preview. Apply is a separate operator action
with OS authorization. The resulting five-minute input/output block affects
this PC, with readback and an explicit Release path; shared services at that
address can also be interrupted. Protected/local endpoints are refused. This
helper has no forwarded-traffic rule and does not quarantine mesh clients.

Google Home's **Pause device** is documented as pausing Internet access. It
does not establish LAN isolation, and randomized device addresses can impair
Family Wi-Fi identification. Do not label Pause as verified quarantine.
[Google Internet Pause documentation](https://support.google.com/googlehome/answer/7535858?hl=en)
For a confirmed compromised device, an authorized operator can disconnect its
network connection and investigate it with appropriate endpoint tools. Verify
all alternate connections before recording it as isolated; preserve evidence
and document the action's effect. MEGALODON does not perform that router or
physical action through this guide.

## Record acceptance as separate states

| State | Evidence needed before claiming it |
| --- | --- |
| Source implemented | Reviewed revision, behavior and limits, plus tests of the actual change. This guide alone adds no detector or capture path. |
| Candidate validated | Exact tests, synthetic fixtures, rule/config validation and results tied to that revision. Synthetic success is not field accuracy. |
| Installed | Installed package/binary/config/rule identities and service readback. Source edits do not update the running application. |
| Sensor observing | Authorized capture, representative client/path checks, both directions, timestamps and loss measurements. Record gaps explicitly. |
| Response authorized | Specific target, operator decision, intended effect, interruption risk and rollback. An alert or model proposal is not authorization. |
| Response verified | Control readback and observed effect within its actual scope, with expiry/release status. Host block, Internet pause and LAN isolation are different claims. |

Keep operational receipts local. Revisit this guide when topology, firmware,
rules, cloud integrations, or installed software changes. Passing documentation
or software tests does not establish that the home network is monitored,
uncompromised, or protected against every ARTEX workflow.
