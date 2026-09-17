# External exchange contract v1

This directory defines three **contract-only** lanes:

1. an operator-supplied, checksummed STIX 2.1 file for offline threat context;
2. new local files containing bounded ECS 9.5.0 and OCSF 1.9.0 projections; and
3. an inert SOAR handoff that has no destination, endpoint, credentials, retry, automation, or host action.

The schema and fixtures are not a parser, exporter, TAXII client, SIEM sender,
webhook, notifier, scheduler, or SOAR executor. See
[`docs/external-exchange-contract.md`](../../../docs/external-exchange-contract.md)
for the trust boundary and adoption sequence.
