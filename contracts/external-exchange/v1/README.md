# External exchange contract v1

This directory defines three closed exchange lanes:

1. an operator-supplied, checksummed STIX 2.1 file for offline threat context;
2. new local files containing bounded ECS 9.5.0 and OCSF 1.9.0 projections; and
3. an inert SOAR handoff that has no destination, endpoint, credentials, retry, automation, or host action.

The schema and fixtures remain static validation material. The first lane now
has a separately implemented bounded reader at `megalodon.threat_context`;
the schema itself is not runtime configuration or authorization. The reader is
not a TAXII client or threat-feed updater, and the other two lanes remain
contract-only. Nothing here is a SIEM sender, webhook, notifier, scheduler, or
SOAR executor. See
[`docs/external-exchange-contract.md`](../../../docs/external-exchange-contract.md)
and [`docs/threat-context-reader.md`](../../../docs/threat-context-reader.md)
for the trust boundary and adoption sequence.
