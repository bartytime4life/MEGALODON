# Research-backed integration direction — 2026-09-19

Status: **current recommendation plus implemented first slice**.

This record reconciles the current checkout, live GitHub project state, the
connected MEGALODON Drive blueprint, the owner-private Defense Console Site, and
primary upstream documentation. It does not authorize sensor operation,
deployment, remote access, host mutation, or release.

## Product conclusion

MEGALODON should remain a local evidence appliance with broad input coverage and
narrow authority. The strongest pattern across the project and upstream tools
is not a general plugin runner. It is:

1. an operator completes or exports evidence with the source tool;
2. MEGALODON admits one bounded, versioned, privacy-reviewed file;
3. a source-specific adapter produces immutable source-qualified evidence;
4. common projections support correlation and reporting without erasing units;
5. any persistence, network delivery, or response is a separate explicit step.

That pattern preserves the project's no-subscription, no-required-account,
metadata-only, no-runtime-egress default while still allowing the command center
to grow across network, endpoint, inventory, vulnerability, and threat-context
evidence.

## Primary-source findings

- Suricata EVE is a JSON event stream with an explicit `event_type`; alert
  records expose the tuple and a nested rule/action object. Suricata also warns
  that an alert's `action` is not necessarily the packet or flow's final verdict.
  This supports a narrow alert-file converter and MEGALODON's existing decision
  to keep producer-reported blocking non-authoritative. See the
  [Suricata 8.0 EVE alert format](https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html)
  and the [8.0.7 release record](https://suricata.io/2026/09/15/suricata-8-0-7-released/).
- Zeek can add an optional Community ID to `conn.log`, with an explicit seed.
  This supports later cross-source grouping, provided seed/profile identity and
  asymmetry remain visible and a shared ID is never treated as proof of event
  identity. See Zeek's
  [Community ID logging policy](https://docs.zeek.org/en/v7.1.1/scripts/policy/protocols/conn/community-id-logging.zeek.html).
- Nmap explicitly recommends XML for programmatic consumers because the normal
  output changes for human readability and the grepable format is deprecated.
  This supports a future completed-report importer—not a scan launcher. See
  [Nmap XML output](https://nmap.org/book/output-formats-xml-output.html).
- OCSF is vendor-neutral and designed for producers, analytics, storage, and
  data pipelines. ECS similarly exists to normalize diverse sources and
  explicitly recommends a proper-name namespace for custom fields. These
  sources support keeping MEGALODON's existing OCSF/ECS exports as projections,
  not replacing the source-specific evidence plane. See the
  [OCSF schema](https://github.com/ocsf/ocsf-schema),
  [ECS reference](https://www.elastic.co/docs/reference/ecs), and
  [ECS custom-field guidance](https://www.elastic.co/docs/reference/ecs/ecs-custom-fields-in-ecs).
- STIX 2.1 describes threat-intelligence content while TAXII 2.1 is its network
  exchange layer. That separation supports the current offline STIX reader and
  argues against adding automatic TAXII refresh until credential, freshness,
  provenance, containment, and failure policies are separately reviewed. See
  the [OASIS CTI resources](https://oasis-open.github.io/cti-documentation/resources.html)
  and [TAXII introduction](https://oasis-open.github.io/cti-documentation/taxii/intro.html).

## Integration sequence

| Order | Integration | Smallest useful delivery | Boundary |
| --- | --- | --- | --- |
| 1 | Suricata raw-EVE alerts | One checksum-bound completed 8.0.7 alert-only file becomes the existing immutable publication | No mixed firehose, payload, sensor launch, watcher, store write, or action |
| 2 | Operator-facing local exchange | Explicit CLI around the existing offline STIX reader and ECS/OCSF new-file writer | No TAXII, endpoint, credential, collector, acknowledgement, or dashboard write |
| 3 | Zeek/Suricata correlation | Preserve optional Community ID plus producer version, seed, direction, and quality | Grouping hint only; never identity, attribution, duplicate proof, or response authority |
| 4 | Nmap inventory | One private completed XML report to a closed inventory projection | No target selection, scan launch, NSE/script output, banner retention, or network activity |
| 5 | osquery inventory | One versioned allowlisted result-set import | No arbitrary SQL, daemon/schedule control, process environment, or remote enrollment |
| 6 | Vulnerability/availability evidence | Completed Greenbone report first; bounded Zabbix/Nagios reads only after credential design | No task creation, feed update, acknowledgement, command pipe, or remediation |
| 7 | TAXII and external delivery | Separate opt-in products only after provenance, credentials, egress, retry, and revocation contracts | Never required for core operation; no default background network client |

## Implemented first slice

`megalodon.offline.suricata_eve.read_completed_raw_eve` now implements order 1.
It pins `suricata-8.0.7-alert-json-v1`, requires an exact SHA-256 and closed run
identity, reuses the existing private-file/deadline boundary, refuses mixed or
expanded records, and returns the exact publication accepted by the existing
consumer. The producer contract, fixtures, limits, configuration guidance, and
negative authority are under `contracts/suricata-eve/v1/producer/`.

Optional scalar EVE provenance values are validated but deliberately not
retained in v1. This avoids silently widening the durable schema. Community ID
retention and cross-source correlation remain the separate order-3 review.

## Connected-project reconciliation

- GitHub currently shows the recovery, alert-lifecycle, and hardening work as
  the newest project changes; the eight roadmap issues still separate recovery,
  licensing, Suricata, Zeek/correlation, detector evaluation, release evidence,
  and model containment.
- The Drive blueprint's durable direction—file import first, fixed local reads
  second, active execution only as a separate control plane—matches the sources
  above and this implementation.
- The owner-private MEGALODON Defense Console is at Site version 19. It remains a
  hosted reference surface with no local telemetry connection. This repository
  change does not deploy or connect that Site.

## Non-goals

Do not turn the Apps viewer into an ingestion transport, proxy external consoles,
invent one generic event type for packets/flows/alerts/inventory, install or
launch companion products, or make cloud exchange necessary for core use. The
HUD should describe source, time range, unit, freshness, quality, and missing
coverage; it should not convert presence into health or missing evidence into a
zero.
