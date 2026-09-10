# MEGALODON architecture security review

## Executive result

The supplied architecture is a useful decomposition for a defensive product,
but its example implementation is not safe to deploy. The highest-risk defects
are command injection, unrestricted automatic blocking, lack of rollback, and
an unauthenticated remote-capable dashboard. The MVP in this folder retains the
capture → analysis → policy → audit → dashboard shape while making observation
the default. For the evaluation-release candidate, firewall response is
plan-only and every retained live-apply route fails closed before it can inspect
or change the host.

This review separates three evidence levels: implemented safeguards in the
current code, adopted but inert contracts, and controls still required before
operational use. Passing CI or closing a contract/test issue does not promote a
proposal into a runtime capability or satisfy independent review.

See the [red, blue, and purple security practice](docs/red-blue-security-guide.md)
for authorized adversarial validation and future-AI gates. That guide adds no
model runtime, tool authority, or firewall authorization.

## Findings and corrections

| Severity | Original design issue | Consequence | MVP correction |
| --- | --- | --- | --- |
| Critical | `subprocess.Popen(..., shell=True)` builds a capture command from interface/filter input | Shell injection and ambiguous tshark argument parsing | No shell; optional Scapy adapter and typed JSONL input |
| Critical | Firewall commands interpolate an IP into shell strings | Command injection and malformed rules | Plan-only output uses fixed `nft` argv built from validated `ipaddress` values; live application is unsupported in the evaluation-release candidate |
| High | Critical findings permanently auto-block an IP | False positives can cut off users, services, or an upstream network | Automatic and operator-requested live blocking are unsupported; proposed blocks remain time-limited plans only |
| High | No allowlist precedence or protected-network policy | A detector can block loopback, private ranges, or management paths | Allowlist precedence and non-global rejection are enforced while producing plans; no live action follows |
| High | No rollback, expiry, or action ledger | Operators cannot explain or safely undo a response | Supported plans are recorded in SQLite and block plans are time-limited; an unsupported apply request produces no false `applied` receipt, and live mutation stays disabled until the restoration gate below is met |
| High | GUI design does not define authentication or bind address | A dashboard could expose threat data and controls on the LAN/WAN | Read-only dashboard binds to `127.0.0.1`, has no control endpoints, uses a separate `mode=ro`/`query_only`/SQL-authorized store, bounds its polling and recent-row budget, selects only the five recent-detection fields used by the UI, validates closed response shapes before replacing state, and serves same-origin assets under a no-inline CSP |
| High | A loopback listener trusts any HTTP `Host` value | DNS rebinding could let a foreign browser origin read local telemetry | Every dashboard `GET` requires one exact bound-loopback `Host` value and is rejected before routing or SQLite access when the value is missing, repeated, foreign, non-canonical, or names the wrong port |
| High | Offline reports could become a path-driven disclosure or analyzer trigger | A web request could expose case data, traverse local files, or start hostile-input processing | One operator-selected private report set is checked and its summary inputs are validated at startup; paths, records, evidence details, remote binds, uploads, and analyzer controls are excluded |
| High | Raw payload hash/contents are part of the capture concept | Payload-derived identifiers can still disclose sensitive data; storage creates a forensic liability | Metadata-only event model; payloads are not represented or stored |
| Medium | Promiscuous capture is treated as a convenience | Requires privilege and may capture traffic outside the operator’s authority | Optional live capture is explicit, interface-specific, and documented as privileged |
| Medium | External feeds are called synchronously with no privacy contract | IP/domain disclosure, rate-limit failures, stale reputation, and API-key leakage | Feeds are out of MVP scope; later adapters must be cached, signed, rate-limited, and opt-in |
| Medium | YAML rules imply arbitrary field/operator expansion | Unvalidated rules can create denial-of-service or unsafe actions | MVP rules are fixed and typed; a future rule schema must be allowlisted and versioned |
| Medium | No IPv6 handling in the firewall examples | Incomplete protection and accidental IPv4-only assumptions | Plan generation uses separate validated IPv4/IPv6 nftables sets; this does not imply live enforcement |
| Medium | No database schema, retention, or transaction policy | Unbounded growth and incomplete evidence | Exact SQLite schema, parameterized WAL writes, private POSIX writer/migration paths, a separately constrained dashboard reader, and a retention hook; finite capacity and operational retention values remain open |
| Medium | GUI threat map can create a false precision problem | IP geolocation can expose or misrepresent people and locations | No map in MVP; future map must show uncertainty and avoid precise residential claims |
| Low | `sqlite3` is listed as a pip requirement | It is part of Python’s standard library; install instructions are misleading | No runtime dependency for SQLite |
| Low | `tshark>=1.4.0` is treated as a normal Python package | System Wireshark availability and bindings are different concerns | Scapy is an optional Python extra; tshark is not required by the MVP |

### Evaluation-release firewall containment ([#65](https://github.com/bartytime4life/MEGALODON/issues/65))

Live firewall application is unsupported in the evaluation-release candidate.
The retained `firewall-install --apply` and `block --apply` CLI routes exit with
status 2 and the fixed diagnostic
`megalodon: live firewall application is unsupported in this evaluation release`
before configuration loading or backend construction. The corresponding direct
backend calls raise `FirewallError` with
`live firewall application is unsupported in this evaluation release` before
platform or host inspection, target/reason/confirmation validation, executable
lookup, privilege checks, or process creation.

The compatibility flags remain parsed so an old or scripted apply request fails
explicitly instead of silently becoming a dry run. The refusal opens no audit
store and emits no fabricated `applied` receipt. Non-apply install and block
planning, including their existing `planned` SQLite receipts, remain available
and do not execute `nft`.

Issue #65 therefore has an implemented evaluation-containment boundary, not a
restored mutation capability or production approval. Its exact-head validation,
independent review, and issue lifecycle remain separate gates.

## Threat model

The MVP assumes an operator is defending a Linux host or small lab network and
may receive malformed or adversarial network metadata. It protects against:

- malformed event input and invalid addresses;
- accidental command execution through event fields;
- accidental host-firewall mutation, including through retained apply routes;
- stale, repeated, or noisy detections overwhelming the action path;
- dashboard exposure caused by a careless bind address;
- loss of an audit trail for supported planning and suppression decisions.

It does not yet protect against a compromised kernel, a malicious root user,
kernel-level packet forgery, an attacker who can write directly to the database,
or a distributed sensor fleet. Those require a separate trust-boundary design.

## Required controls before production use

1. Threat-feed adapters need a written data-sharing policy, cache freshness,
   feed signature verification, API-key isolation, and failure behavior.
2. Live capture has a fixed fail-closed 1,024-event application queue, but still
   needs a privilege model, service account, systemd sandboxing, kernel-buffer
   loss telemetry, and production resource/load acceptance.
3. Firewall application is unsupported for the evaluation-release candidate.
   Restoring it requires an independently reviewed design with durable intent
   recorded before mutation, exact operator authority and target, allowlist precedence,
   non-global rejection, conflict detection with the host’s existing firewall
   manager, finite expiry, post-action readback, a terminal outcome, tested
   rollback, and explicit reconciliation for uncertain or interrupted attempts.
   Passing plan-only tests or closing #65's containment slice does not satisfy
   that restoration gate.
4. The dashboard needs authentication and CSRF protection if it ever exposes
   control operations or binds beyond localhost.
5. The repository has bounded synthetic detector and service-to-ledger fixtures,
   but still needs representative privacy-reviewed replay, false-positive
   measurement and an explicit evidence-quality label
   before operational interpretation. Neither a detection nor a quality label
   authorizes automated response.

## Open control register

| Gate | Repository evidence | Remaining control |
| --- | --- | --- |
| Independent review ([#3](https://github.com/bartytime4life/MEGALODON/issues/3)) | CI and merge history exist | Enforce and evidence an independent approval path |
| Firewall containment ([#65](https://github.com/bartytime4life/MEGALODON/issues/65)) | Evaluation apply routes fail with one fixed diagnostic before configuration, host, executable, privilege, or process work; plan-only receipts remain | Complete exact-head validation and independent review; design durable intent, outcome readback, expiry, rollback, and reconciliation before any separate restoration proposal |
| Dashboard acceptance ([#7](https://github.com/bartytime4life/MEGALODON/issues/7)) | Loopback, read-only, bounded implementation exists | Complete privacy, browser, and operator acceptance evidence |
| Dashboard storage isolation ([#66](https://github.com/bartytime4life/MEGALODON/issues/66)) | Separate least-data reader requires an existing compatible private POSIX store with rename-resistant trusted ancestry; pins the database inode; requires SQLite to resolve the configured private path; holds a stable parent-entry generation; revalidates sidecars; uses `mode=ro` plus `query_only`; and denies non-dashboard SQL | Obtain independent review and native Windows ACL evidence; keep successful WAL coordination confined to a dedicated verified private directory |
| Ingestion atomicity ([#67](https://github.com/bartytime4life/MEGALODON/issues/67)) | Bounded run receipts and per-write rollback tests exist | Make event/detection/action/run accounting atomic and reconcile interrupted or ambiguous runs before adding durable alert lifecycle state |
| Whole-service resource bounds ([#68](https://github.com/bartytime4life/MEGALODON/issues/68)) | Detector windows, API result sets, offline inputs, and subprocess output have component limits | Prove finite long-running storage, overload, retention, and any future delivery queue behavior before claiming continuous monitoring |
| TShark compatibility ([#25](https://github.com/bartytime4life/MEGALODON/issues/25)) | Optional header-only probe exists | Pin and record a reviewed installed-tool receipt |
| Native Windows ([#27](https://github.com/bartytime4life/MEGALODON/issues/27)) | Static acceptance matrix and Linux-run unsupported-operation controls exist | Native core, NTFS ACL, loopback UI/browser, and exact-platform execution receipts |
| Retention/storage ([#28](https://github.com/bartytime4life/MEGALODON/issues/28)) | Per-write rollback regression coverage exists | Select finite policy values and validate operational failure/recovery and deletion controls |

Suricata issues [#9](https://github.com/bartytime4life/MEGALODON/issues/9)
and [#24](https://github.com/bartytime4life/MEGALODON/issues/24) closed their
record and reader **contract** gates. No runtime reader, durable importer,
installed-sensor compatibility, or response path follows from those closures.

## Windows/Linux extension: proposed controls, not completed validation

The [platform baseline](docs/platform-baseline.md) is the canonical proposed
configuration and installation guide. The review above concerns the Linux MVP
and original design findings; it is not independent Windows security approval.
The offline implementation depends on Linux privilege/capability checks,
descriptor-based file access, `/proc`, process groups, and a fixed
`/usr/bin/tshark`. Retained firewall apply routes are refusal surfaces only:
they stop with the fixed evaluation-release diagnostic before configuration,
platform/host, executable, privilege, or process work. There is no live Linux or
Windows firewall-apply backend in the evaluation-release candidate. Native Windows parity
is unproven; existing Linux checks must not be removed to advertise it.

| Boundary | Required Windows/guest control | Current status |
| --- | --- | --- |
| Local storage | Private local NTFS ACLs; reject unsafe shared/redirected locations; review database/WAL/report permissions | Proposed Windows acceptance work; POSIX modes alone are insufficient |
| Hostile input files | Reviewed handles and identity; reparse-point, device, UNC, alternate-stream and race defenses; finite limits | No native Windows offline adapter is approved |
| Analyzer execution | Fixed executable/argv, trusted configuration, bounded pipes/runtime/resources, reliable child-tree termination, no egress | A Windows executable path alone does not supply containment |
| Capture drivers | Verify maintenance, signed provenance, privileges, licensing, and explicit operator capture authority | Native Windows live capture excluded; Npcap is not an open-source baseline dependency |
| Guest networking | Validate guest/host scope and loopback behavior; no assumption of full host visibility or firewall control | WSL is development-only here, not the hostile-capture isolation baseline |
| Host response | Preserve existing firewall/endpoint protection; prove durable intent, outcome readback, expiry/recovery, reconciliation, and operator authorization separately | No Linux or Windows apply backend in the evaluation-release candidate; no services or scheduled cleanup installed |
| Sensor/file tools | Separate packet, flow, alert and file-scan semantics; allowlist fields; never import payloads or payload hashes | Suricata contract/tests only; ClamAV and osquery runtime integrations not implemented |

The read-only `megalodon capabilities` command reports fixed support states from
repository data. It deliberately does not inspect executables, versions,
drivers, services, configuration, privileges, sockets, or network reachability.
Its output cannot establish installation, provenance, compatibility, isolation,
or authorization to run an external tool.

The companion `megalodon hub-plan` command is also static and non-executing. It
maps each catalog component exactly once to a closed source kind, owner,
input/output contract, entry point, launch policy, data boundary, action
boundary, and next gate. It accepts no executable, argv, endpoint, SQL, path,
credential, or action field and performs no probe, process launch, network
request, persistence, capture, or host change. See
[the integration hub contract](docs/integration-hub.md). Runtime orchestration
remains a separate review boundary.

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
