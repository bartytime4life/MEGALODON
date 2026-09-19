# Suricata 8.0.7 raw-EVE producer profile

Status: **implemented completed-file converter; installed-producer acceptance
remains separate**.

This profile is the only raw Suricata input accepted by
`megalodon.offline.suricata_eve.read_completed_raw_eve`. It converts one
explicitly selected, completed, owner-private alert-only EVE JSONL file into the
existing immutable `external-alert-v1` publication and
`suricata-eve-reader-receipt-v1`. That result is accepted unchanged by the
existing durable consumer.

## Pinned producer

- producer: Suricata;
- declared version: exactly `8.0.7`;
- profile: `suricata-8.0.7-alert-json-v1`;
- record unit: one EVE `event_type=alert` JSON object per physical line; and
- provenance: exact operator-supplied SHA-256 plus closed sensor, run, and
  ruleset identifiers.

The profile follows Suricata's documented common alert fields: timestamp,
event type, source/destination tuple, protocol, and the nested alert action and
rule identity. `action=blocked` remains producer-reported evidence and never
authorizes a MEGALODON action.

## Required EVE configuration boundary

Use a dedicated completed alert file, not the mixed default EVE firehose. Alert
payload, packet, and application metadata must be disabled. A representative
operator-owned configuration is:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: megalodon-alerts.json
      types:
        - alert:
            payload: no
            payload-printable: no
            packet: no
            metadata: no
```

File completion and transfer into a private operator-controlled location happen
outside MEGALODON. The converter does not rotate, tail, watch, lock, truncate,
or delete the source.

## Admission and resource bounds

- Linux, non-root, capability-free process using the main-thread deadline guard;
- absolute path, no symlink component, regular file, exactly one hard link,
  current owner, and mode `0400` or `0600`;
- exact lowercase `sha256:` digest supplied before the read;
- at most 64 MiB, 10,000 records, 64 KiB per record, four JSON container levels,
  16 MiB normalized output, and 30 elapsed seconds; and
- duplicate keys, floats/non-finite numbers, mixed event types, unknown fields,
  invalid timestamps/addresses/ports, version drift, replayed run identity, and
  source-identity changes fail closed without publishing a prefix.

Payloads, packets, packet headers, capture paths, Ethernet data, flow objects,
HTTP/DNS/TLS objects, files, arbitrary metadata, and final verdict objects are
refused rather than retained or silently reclassified. Optional scalar
`flow_id`, `pcap_cnt`, `tx_id`, `app_proto`, `direction`, `pkt_src`, and
`community_id` values are shape-checked but deliberately not retained in v1.

## Authority boundary

This slice adds no Suricata installation, service or ruleset management, scan or
sensor launch, directory watcher, scheduler, network access, database write,
dashboard refresh, SIEM delivery, alert acknowledgement, firewall action, or
automatic response. Passing fixtures proves parser behavior only; it does not
prove installed Suricata compatibility, capture completeness, rule quality,
packet-loss behavior, operational privacy, or host acceptance.
