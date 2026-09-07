# MEGALODON architecture security review

## Executive result

The supplied architecture is a useful decomposition for a defensive product,
but its example implementation is not safe to deploy. The highest-risk defects
are command injection, unrestricted automatic blocking, lack of rollback, and
an unauthenticated remote-capable dashboard. The MVP in this folder retains the
capture → analysis → policy → audit → dashboard shape while making observation
the default and putting every enforcement action behind explicit validation.

## Findings and corrections

| Severity | Original design issue | Consequence | MVP correction |
| --- | --- | --- | --- |
| Critical | `subprocess.Popen(..., shell=True)` builds a capture command from interface/filter input | Shell injection and ambiguous tshark argument parsing | No shell; optional Scapy adapter and typed JSONL input |
| Critical | Firewall commands interpolate an IP into shell strings | Command injection and malformed rules | `nft` argv is built from validated `ipaddress` values; no `shell=True` |
| High | Critical findings permanently auto-block an IP | False positives can cut off users, services, or an upstream network | Auto-block disabled by default; proposed blocks use timeout sets and explicit confirmation |
| High | No allowlist precedence or protected-network policy | A detector can block loopback, private ranges, or management paths | Allowlist is checked before enforcement; non-global targets are rejected by default |
| High | No rollback, expiry, or action ledger | Operators cannot explain or safely undo a response | Every block is time-limited and recorded in SQLite; table is isolated as `inet megalodon` |
| High | GUI design does not define authentication or bind address | A dashboard could expose threat data and controls on the LAN/WAN | Read-only dashboard binds to `127.0.0.1` and has no control endpoints |
| High | Raw payload hash/contents are part of the capture concept | Payload-derived identifiers can still disclose sensitive data; storage creates a forensic liability | Metadata-only event model; payloads are not represented or stored |
| Medium | Promiscuous capture is treated as a convenience | Requires privilege and may capture traffic outside the operator’s authority | Optional live capture is explicit, interface-specific, and documented as privileged |
| Medium | External feeds are called synchronously with no privacy contract | IP/domain disclosure, rate-limit failures, stale reputation, and API-key leakage | Feeds are out of MVP scope; later adapters must be cached, signed, rate-limited, and opt-in |
| Medium | YAML rules imply arbitrary field/operator expansion | Unvalidated rules can create denial-of-service or unsafe actions | MVP rules are fixed and typed; a future rule schema must be allowlisted and versioned |
| Medium | No IPv6 handling in the firewall examples | Incomplete protection and accidental IPv4-only assumptions | Separate validated IPv4/IPv6 nftables sets |
| Medium | No database schema, retention, or transaction policy | Unbounded growth and incomplete evidence | SQLite schema, WAL mode, parameterized writes, and a retention hook |
| Medium | GUI threat map can create a false precision problem | IP geolocation can expose or misrepresent people and locations | No map in MVP; future map must show uncertainty and avoid precise residential claims |
| Low | `sqlite3` is listed as a pip requirement | It is part of Python’s standard library; install instructions are misleading | No runtime dependency for SQLite |
| Low | `tshark>=1.4.0` is treated as a normal Python package | System Wireshark availability and bindings are different concerns | Scapy is an optional Python extra; tshark is not required by the MVP |

## Threat model

The MVP assumes an operator is defending a Linux host or small lab network and
may receive malformed or adversarial network metadata. It protects against:

- malformed event input and invalid addresses;
- accidental command execution through event fields;
- accidental blocking of local management networks;
- stale, repeated, or noisy detections overwhelming the action path;
- dashboard exposure caused by a careless bind address;
- loss of an audit trail when an action is planned, suppressed, or refused.

It does not yet protect against a compromised kernel, a malicious root user,
kernel-level packet forgery, an attacker who can write directly to the database,
or a distributed sensor fleet. Those require a separate trust-boundary design.

## Required controls before production use

1. Threat-feed adapters need a written data-sharing policy, cache freshness,
   feed signature verification, API-key isolation, and failure behavior.
2. Live capture needs a privilege model, service account, systemd sandboxing,
   resource limits, and a packet-volume backpressure policy.
3. Firewall application needs a tested rollback command, conflict detection with
   the host’s existing firewall manager, and an operator approval workflow.
4. The dashboard needs authentication and CSRF protection if it ever exposes
   control operations or binds beyond localhost.
5. Detections need replay fixtures, false-positive measurements, and an explicit
   evidence quality label before operational interpretation. Neither a detection
   nor a quality label authorizes automated response.

## Windows/Linux extension: proposed controls, not completed validation

The [platform baseline](docs/platform-baseline.md) is the canonical proposed
configuration and installation guide. The review above concerns the Linux MVP
and original design findings; it is not independent Windows security approval.
At the pinned base `d94b40918908a8a275581f0c2690aef21d09adee`, the offline
implementation depends on Linux privilege/capability checks, descriptor-based
file access, `/proc`, process groups, and a fixed `/usr/bin/tshark`. The firewall
apply path is nftables-specific and calls `os.geteuid()`. Native Windows parity
is unproven; existing Linux checks must not be removed to advertise it.

| Boundary | Required Windows/guest control | Current status |
| --- | --- | --- |
| Local storage | Private local NTFS ACLs; reject unsafe shared/redirected locations; review database/WAL/report permissions | Proposed Windows acceptance work; POSIX modes alone are insufficient |
| Hostile input files | Reviewed handles and identity; reparse-point, device, UNC, alternate-stream and race defenses; finite limits | No native Windows offline adapter is approved |
| Analyzer execution | Fixed executable/argv, trusted configuration, bounded pipes/runtime/resources, reliable child-tree termination, no egress | A Windows executable path alone does not supply containment |
| Capture drivers | Verify maintenance, signed provenance, privileges, licensing, and explicit operator capture authority | Native Windows live capture excluded; Npcap is not an open-source baseline dependency |
| Guest networking | Validate guest/host scope and loopback behavior; no assumption of full host visibility or firewall control | WSL is development-only here, not the hostile-capture isolation baseline |
| Host response | Preserve existing firewall/endpoint protection; prove expiry/recovery and operator authorization separately | No Windows apply backend; no services or scheduled cleanup installed |
| Sensor/file tools | Separate packet, flow, alert and file-scan semantics; allowlist fields; never import payloads or payload hashes | Suricata, ClamAV and osquery runtime integrations not implemented at the pinned base |

The core demonstration needs neither root nor Administrator. Windows evaluation
must use synthetic inputs until native compatibility and privacy gates pass.
The dashboard remains read-only and loopback-bound; no remote exposure exception
is created. External application installation is not evidence that MEGALODON
has gained that application's protection or detection capability.

Software/rule/signature downloads require a deliberate maintenance process,
not telemetry uploads. Keep raw captures, sensor logs, SQLite data, and personal
paths out of repository and Drive evidence packets. Redaction does not authorize
sharing. Upstream licensing/platform sources and exact configuration requirements
are recorded in the baseline; do not silently bundle restricted components.

Acceptance requires Linux regression evidence, native Windows tests and ACL/UI
readback, installed-tool compatibility where applicable, and independent human
review. Issue #3's review-control gate remains separate from green CI. Nothing
here authorizes a firewall operation, driver installation, scheduled task,
remote listener, autonomous response, merge, release, or deployment.
