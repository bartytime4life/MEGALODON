# Repository, Console, and telemetry alignment — 2026-09-21

## Current source and ownership

Readback basis: GitHub `main@bdddd427df3c06e30c0d7e6e3405a0e1932fc971`
and the MEGALODON Defense Console Sites record on 2026-09-21. The repository
remains the source for product behavior and contracts. The [Drive coordination
log](https://docs.google.com/document/d/1UF6orVYABNDquqli1tjp6z5GBISQ0FJupMntml_uvrA/edit)
and [platform roadmap](https://docs.google.com/document/d/1BW_X0lU48rNobG1uzTNAEhMiRK4AHIYBxqybu1q0Eqk/edit)
are coordination records. Their dated checkpoints and proposals do not replace
the implementation, issue readback, or operator acceptance.

| Surface | Current readback | Limit |
| --- | --- | --- |
| Local PC | Merged [#323](https://github.com/bartytime4life/MEGALODON/pull/323) supplies the user-scoped Linux desktop installer and guided local checks; #325 adds follow-up readiness polish | Installing the core does not start a sensor, create telemetry, or install a companion tool |
| Hosted Console | Owner-only Sites v30 publishes stable links to the merged installer source and setup guide | It is a static, disconnected reference surface; see the [exact Site receipt](site-source-alignment.md) |
| Detector report | [#259](https://github.com/bartytime4life/MEGALODON/issues/259) is closed after scoped owner acceptance at `main@16742fed020283aafad35e30238986c851d7542a` | Synthetic report acceptance is not independent review or representative operational accuracy |
| Zeek qualification | [#258](https://github.com/bartytime4life/MEGALODON/issues/258) is closed; [#327](https://github.com/bartytime4life/MEGALODON/issues/327) now owns exact producer profile and schema-drift evidence | Community ID grouping does not qualify an installed producer or complete CLI/report integration |
| Ubuntu release packet | [#260](https://github.com/bartytime4life/MEGALODON/issues/260) remains open after #318–#322 and #324/#326 | Temporary synthetic CI recovery and self-asserted phase receipts do not supply the complete candidate packet, operator drill, artifact review, or acceptance |
| Local model | [#261](https://github.com/bartytime4life/MEGALODON/issues/261) remains open | The provider collector is unbound; model bytes, host containment, signed corpus, and independent review remain unaccepted |

The preceding [2026-09-20 alignment record](document-alignment-2026-09-20.md)
retains its original repository, Site v28, test, and Drive observations as a
historical checkpoint.

## Telemetry verification and meaning

The local HUD's Traffic view reads bounded, receipt-qualified **stored** metadata.
Its history endpoint selects a UTC range and uses exclusive event-ID paging;
the current page is fixed while newest-data polling continues. A successful
read proves that selected stored records were readable at that moment. It is
not a wire-speed measurement, sensor heartbeat, complete network-coverage
claim, or assertion that every companion tool is connected. The optional
Suricata store and offline evidence are startup snapshots with separate
provenance. The hosted Console receives none of these local API responses.

On this checkout, all **44 Site Node checks** passed, including disconnected
telemetry, rejected readiness input, and application navigation. The focused
Python traffic, history, dashboard-store, local-check, and documentation
selection passed **86 tests** on the host. The initial sandbox run refused
fixture creation with `STORAGE_PATH:UNSAFE_ANCESTOR` because its `/` ancestor
appeared owned by UID 65534; the same unchanged tests passed where `/` is
root-owned. This is synthetic contract verification. No live telemetry store or
sensor was inspected here.

For an operator check on an approved host, follow
[dashboard operations](dashboard-operations.md) and the
[HTTP contract](dashboard-http-contract.md): confirm an existing private
store, read `/api/setup` for startup source state, then compare `/api/traffic`
with its displayed provenance, last successful fetch, and returned-row limits.
Use `/api/traffic-history` only for an explicitly selected UTC range. An
unavailable or stale result must remain unavailable or stale; do not translate
it to zero traffic or healthy capture. Qualifying an installed source requires
its own producer and continuity evidence.

## Documentation rule

README, specification, security review, Wiki source, Site source, and the
specialized contracts describe the same local-versus-hosted boundary. Dated
receipts retain their original pins; this record supersedes only their
current-status summaries. No runtime code, detector threshold, data fixture,
host setting, or release authority changes through this documentation pass.
