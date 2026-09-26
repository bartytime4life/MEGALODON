# Project gap review and action

Baseline observed: main `e6633884703fc297b4dbc5f2e92f4cb525716015` includes
#422's globe minute detail and #424's normal/danger meters. The separate HUD
redesign #425 at `26698c73fbc2f10759428f349bc8850b3ddcaf1a` has incorporated that
main revision. Its technical workflows, including CI/package and native browser
acceptance, completed successfully. Owner lifecycle and deployment are separate.
No open Nmap-specific GitHub issue was returned by the repository search.

## Concrete action in this change

Close one missing companion data path end to end: completed Nmap report → bounded
aggregate-only Python exporter → strict JSON admission → four inventory charts
in both HUDs. Keep one canonical packaged UI and generate the hosted mirror.
Align capability catalog, hub plan, feature coverage, Site companion description,
operator instructions and tests. Preserve traffic/globe behavior and all existing
permission boundaries. See [the versioned contract](nmap-inventory-v1.md).

## Remaining work, in order

| Gap | Next concrete slice | Completion evidence |
| --- | --- | --- |
| Hosted telemetry is manual | Design an explicitly configured, authenticated aggregate relay with freshness, outage and revocation behavior | Real local-to-hosted integration test; no raw records or implied browser access to loopback |
| Six companions lack result adapters | Select one completed-result profile for ClamAV, osquery, OSSEC, Greenbone, Zabbix or Nagios; implement a bounded reader and separate visualization | Producer fixture, malformed-input tests, provenance, units and last observation visible |
| Configuration commands are guidance | Add per-tool validate/preview commands before considering explicit configuration writers | Invalid paths/scope/credentials rejected, exact preview and rollback demonstrated |
| Presence is not operational health | Add documented version/configuration/last-result observations to each implemented integration | Stopped, stale, unavailable and partial cases distinguishable from healthy |
| Installation differs from publication | Exercise clean installed-package startup and the full import/export workflow on supported hosts | Native receipts with exact version; browser and package CI alone are insufficient |
| Inventory acceptance | Validate this narrow Nmap projection against reviewed real producer output and native shells | Independent profile/privacy review; no synthetic test promoted to deployed sensor proof |

This is not a claim that all telemetry is complete. Nmap now has a manual saved
aggregate path; it still has no scanner, polling, persistent ingestion or live
integration. Inventory does not establish threats or geographical locations.
