# MEGALODON integration hub contract

Status: **implemented static plan; no general runner, scheduler, installer, or
external-tool activation**.

Document role: this file owns the closed workflow vocabulary and its execution
boundary. The platform baseline owns installation choices; the offline and
versioned contract documents own their input details. A capability status is
copied from code at command time, never upgraded by this prose.

`megalodon hub-plan` is the machine-readable coordination surface for the
separate applications and utilities used around MEGALODON. It joins the static
capability catalog to closed workflow definitions so documentation, UI work,
operator scripts, and future adapters can share one truthful vocabulary without
turning configuration or untrusted data into executable commands.

```bash
python -m megalodon hub-plan --platform linux
python -m megalodon hub-plan --platform linux --workflow offline-packet-metadata
```

The command reads repository constants only. It performs no filesystem or
executable discovery, version probe, subprocess launch, installation, network
request, capture, database write, firewall operation, or host configuration
change. Every receipt therefore reports `action_status=not_attempted` and all
three performed flags as false. An `entry_point` identifies the existing owner;
it is descriptive data, not an argv builder or authorization to run it.

## Closed workflow map

| Workflow | Utility | Current Linux relationship | Integration boundary |
| --- | --- | --- | --- |
| `core-metadata` | Python + SQLite | Implemented | Validated metadata to local audit; observe-only default |
| `offline-packet-metadata` | TShark/Wireshark | Optional implemented adapter | Fixed TShark argv and fields; private reports; no payload or live capture |
| `offline-flow-metadata` | Zeek | Optional implemented importer | Closed `conn.log` profile; external producer; flow and packet counts stay separate |
| `alert-metadata` | Suricata | Completed-file reader, durable transaction, reconciliation, and startup evidence view implemented | One completed private contract-envelope file can be validated, atomically written, and exactly reconciled; an explicit read-only dashboard startup snapshot displays bounded stored external alerts. No raw-EVE converter, watcher, dashboard control, sensor, or IPS |
| `live-metadata-capture` | Scapy | Optional | Explicit capture extra; metadata only; no crafting or injection feature |
| `time-limited-response` | nftables | Plan only | Deterministic review plan; every live-apply route is refused before host or process work |
| `manual-file-scan` | ClamAV | Manual companion | No file, hash, scan-result, removal, quarantine, or updater integration |
| `endpoint-inventory` | osquery | Proposed | No arbitrary SQL, daemon, scheduler, remote enrollment, or importer |
| `local-ai-advisory` | Qwen via local Ollama | Manual library call | One Airlock-admitted request to literal IPv4 loopback and an optional startup-supplied display receipt; no CLI invocation, traffic inspection, background analysis, tools, or action authority |
| `network-inventory-import` | Nmap | Proposed | Completed XML report import only; no scan launch, targets, scripts, banners, or network activity |
| `host-integrity-import` | OSSEC | Proposed | Completed alert import only; no agent enrollment, daemon control, configuration, or active response |
| `vulnerability-report-import` | Greenbone Community Edition | Proposed | Completed GMP report import only; no scanner, feed, target, task, or remediation control |
| `zabbix-availability-read` | Zabbix | Proposed | No endpoint, credential, client, poller, acknowledgement, or remote command |
| `nagios-availability-read` | Nagios Core | Proposed | No CGI endpoint, credential, poller, command pipe, acknowledgement, or remote command |

The Suricata record and reader contract gates are closed as prerequisites
([#9](https://github.com/bartytime4life/MEGALODON/issues/9) and
[#24](https://github.com/bartytime4life/MEGALODON/issues/24)). The Linux profile
exposes the bounded Python file-reader API, an explicit transaction for its
immutable publication, and an explicit read-only unknown-commit reconciliation
API. An optional [read-only startup projection](suricata-evidence-projection.md)
serves bounded stored external-alert evidence through the local dashboard.
Windows remains `contract_only`; no platform gains producer management, raw-EVE
conversion, background ingestion, dashboard control, or action authority.
`hub-plan` itself remains static and writes nothing.

## Threat context and SIEM/SOAR exchange

The separate [external exchange contract](external-exchange-contract.md) adds a
closed, machine-validated plan for three interoperability lanes without adding
them to the executable companion-tool catalog:

| Lane | Contract state | Boundary |
| --- | --- | --- |
| Offline threat context | Bounded reader delivered by merged PR #269 | One completed owner-private, checksum-bound, size/object/depth/time-bounded STIX 2.1 file returns immutable context and a no-authority receipt; no TAXII, persistence, pattern execution, model input, attribution, detection, or action authority |
| SIEM projection | Contract only | New local file only; bounded ECS 9.5.0 and OCSF 1.9.0 projections; no `event.original`, payload, credential, collector, or network delivery |
| SOAR handoff | Contract only | Inert local record with no destination, endpoint, credential, retry, scheduler, automation, or host action |

These are data-exchange profiles, not installed utilities, so readiness probes,
package lifecycle commands, saved console URLs, and `hub-plan` execution fields
remain unchanged. The offline reader is an explicit library call, not a feed or
background integration. SIEM projection still requires pure mapping code,
golden fixtures and private atomic publication; all runtime adoption still
requires exact-head validation, independent review, and operator acceptance.

Each capability appears exactly once. Platform support status is derived from
`megalodon.capabilities` instead of being copied into this registry. That
prevents a hub plan from upgrading `contract_only`, `manual_only`, `proposed`,
or `unsupported` software merely because it is installed or available upstream.
Npcap remains excluded from the open-source baseline and from the workflow map.

## Security basis and design consequences

The source review was refreshed on 2026-09-14. These sources guide the design;
they do not certify MEGALODON or any installed tool.

- NIST SP 800-53 Rev. 5 control CM-7 establishes least functionality as a
  configuration-management objective. MEGALODON applies that principle with a
  closed workflow/component allowlist and no arbitrary tool or command field.
- CISA Secure by Design guidance favors safe defaults and useful security
  logging. The hub is observe-only and makes status, data boundaries, action
  boundaries, and next gates explicit instead of inferring readiness.
- Python's `subprocess` security guidance warns that invoking a shell shifts
  quoting responsibility to the application. The hub starts no process; the
  existing TShark adapter remains the only native-analyzer runner and uses a
  fixed argv with `shell=False`, finite pipes, a timeout, and process cleanup.
- Wireshark publishes ongoing security advisories for malformed capture and
  dissector risks. A hub entry never makes an arbitrary capture safe; analysis
  remains non-root, local, bounded, updated, and externally contained.
- Suricata documents that EVE can emit alerts, anomalies, file information,
  metadata, and protocol-specific records. MEGALODON therefore keeps its
  Suricata relationship narrower than stock EVE: the completed-file reader
  accepts only the repository envelope, and the durable consumer and
  reconciler accept only that reader's immutable publication. Neither path
  accepts raw EVE or controls a producer.
- Zeek documents both TSV and JSON logs and their usefulness in pipelines.
  MEGALODON accepts only its versioned connection profile rather than arbitrary
  Zeek log streams.
- ClamAV documents separate engine and signature-database currency. It remains
  a manual companion; a future integration must record both and must not turn a
  scan label into proof or automatic quarantine.

Primary references:

- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST SP 800-92, Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final)
- [CISA Secure by Design](https://www.cisa.gov/securebydesign)
- [Python subprocess security considerations](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [Wireshark security advisories](https://www.wireshark.org/security/)
- [Suricata 8.0.6 EVE JSON output](https://docs.suricata.io/en/suricata-8.0.6/output/eve/eve-json-output.html)
- [Zeek log formats](https://docs.zeek.org/en/v8.0.8/log-formats.html)
- [ClamAV FreshClam guidance](https://docs.clamav.net/faq/faq-freshclam.html)

## Extension rule

A new utility does not enter the hub until one bounded change supplies:

1. a capability-catalog component with platform-specific status;
2. one workflow ID, source kind, owner, input/output contract, and entry point;
3. explicit data and action boundaries plus the next unproved gate;
4. closed-schema tests proving unique coverage and truthful status derivation;
5. a versioned adapter contract before runtime ingestion; and
6. separate approval for any sensor, scheduler, egress, privileged action, or
   remote listener.

No prompt, event, document, model output, sensor field, or future configuration
may choose an executable, argv, endpoint, credential, SQL query, firewall
target, or action. Runtime orchestration is a later, separately reviewed slice.

## Verification

From an installed checkout, compare the two static surfaces without probing or
launching any external tool:

```bash
python -m megalodon capabilities --platform linux
python -m megalodon capabilities --platform windows
python -m megalodon capabilities --platform other
python -m megalodon hub-plan --platform linux
python -m megalodon hub-plan --platform windows
```

The catalog and plan tests must continue to prove unique component/workflow
coverage, closed fields, exact status derivation, `action_status=not_attempted`,
and false performed flags. Output is descriptive evidence, not a compatibility
receipt or execution authorization.
