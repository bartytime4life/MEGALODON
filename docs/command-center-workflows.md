# Command-center workflows and connection boundaries

This guide describes the local dashboard workflows in this revision. The
[specification](../SPECIFICATION.md#6-dashboard-contract) owns the product/API
contract; the [consumer state contract](ui-state-contract.md) owns reference
validation and recovery details. Implementation, passing tests, independent
review, merge, and operational acceptance remain separate states. Consult live
GitHub before deciding which delivery state applies to a candidate.

## Start with the question, not the tool

MEGALODON's command center is a local evidence-review surface. It does not turn
an installed security utility into an active integration. The interface has
three independent data paths. Investigating one does not silently open, update,
or merge another.

| Operator question | Read path | What the answer establishes | What it does not establish |
| --- | --- | --- | --- |
| Which fixed-rule findings were returned? | Bounded recent-detection SQLite projection | The returned stored fields and current client-side filters | Complete history, unique incidents, current capture health, or confirmed malice |
| What does the pinned registry contain for this value? | Manual IANA service/port or IP-protocol lookup | Context from the installed verified snapshot for the displayed exact query | Actual service identity, reputation, vulnerability, or current online registry contents |
| What did one selected offline analysis report? | Privacy-bounded startup snapshot of a completed report | Source-qualified aggregate results from that report | Live analysis, a union with the SQLite store, or visibility into every available report |

Use the section navigation or the Data connections guide to move between these
paths. Navigation only moves within the page. It does not initiate a source
import or infer a relationship between two records.

## A normal review session

Start the dashboard against an existing compatible private database using the
canonical installation and command instructions in the [README](../README.md)
and [platform baseline](platform-baseline.md). The dashboard is not a database
creation or migration command. Do not loosen storage checks to get an apparently
healthy page. A storage refusal is an operational finding to diagnose, not a
reason to run the dashboard as root or expose it through a public reverse proxy.

Read the operator trust strip before interpreting any counter. A successful
API fetch describes communication between the browser and the local service.
It does not show that Scapy is capturing, ingestion is progressing, a producer
is healthy, or the entire environment is protected. Conversely, no returned
findings is not evidence that the environment is safe.

In Recent detection triage, the search, priority, rule, and time controls operate
on the bounded returned set. The default return limit is 50 and the configured
maximum is 200. The timeline contains at most 12 bins. It is not a database-wide
query or a continuous traffic-volume chart. Preserve the distinction between
a displayed finding count and a source-qualified packet, flow, or alert count.

When a later fetch fails, previously displayed data is preserved as stale. A
first-fetch failure has no prior data to preserve. Pausing refresh does not pause
capture or ingestion. A manual refresh while paused is still a read; automatic
refresh remains paused. Changes to the returned set can clear a prior time
selection instead of silently reinterpreting that selection against new bins.

A rise in the stored high/critical counter is a difference between two successful
summary reads, not a count of unique new incidents. A decrease may reflect a
change in stored data; it does not establish that a threat was resolved. Summary
and recent rows are separate reads, not one cross-endpoint transaction. Keep
these limits with any notes made from the screen.

## Manual reference lookup

Choose the actual transport deliberately. TCP/443 and UDP/443 are distinct
queries; a familiar port number alone does not select a transport. The service
form accepts `tcp`, `udp`, `sctp`, or `dccp` plus one canonical decimal port from
0 to 65535. The protocol-number form accepts one canonical decimal integer from
0 to 255. Leading-zero values such as `00443`, signs, floating-point forms,
booleans, and out-of-range values are rejected. The existing event-limit API has
a separate contract; its permitted modest leading-zero values are not changed
by the reference form's canonical-input rule.

Each displayed result remains attached to the query echoed in its metadata.
The client checks that the response kind and query equal the submitted request,
and that the bundle ID, version, and digest agree with the successful status
read for this process. It also checks count/status/truncation consistency and
that returned record ranges include the requested value. This is a consumer
consistency check, not a substitute for the server's manifest and resource
verification or independent authentication of the local server.

The interface shows the manifest digest, source registry, registry date,
retrieval time, and retrieval basis as text. The registry address is not an
embedded remote page or an automatic lookup link. Retrieval time is a receipt
fact, not the time an endpoint was observed. The snapshot does not become newer
merely because its status was just fetched. Where a response supplies no source
provenance, the UI reports that absence rather than inventing a source or date.

Zero results means no matching registry record in the installed snapshot. It
is neither an error nor an unsafe-endpoint verdict. Several matching records
remain several records; the interface does not collapse them into one claimed
service. Reserved, unassigned, unnamed, and experimental entries remain their
record kinds. The summary uses **registry records** instead of implying that
every row is a named service registration.

For example, an operator reviewing a finding can manually look up a separately
known transport/port as background context. That does not establish that the
finding included that port, that a host runs the assigned service, or that a
particular vulnerability applies. The five-field recent-detection API does not
expose destination-port evidence for an automatic browser pivot. No hidden
evidence JSON is parsed to manufacture that relationship.

## Recover a reference failure without bypassing integrity

The **Recheck reference status** button performs one read of the existing local
status endpoint. It can recover a browser-to-service transport failure once the
service is reachable again. It does not download registry data, invalidate the
server's cache, rescan resources, repair files, or restart the process. Status
and lookup requests are mutually exclusive while either request is in flight.

An explicit recheck clears the previous selected lookup and requires a fresh
successful lookup for a result. This prevents an earlier result from appearing
to have been revalidated by a status-only request. During an ordinary lookup
failure, a prior result can remain visible, but it is marked stale and retains
its original displayed query. Invalid new input makes no request and does not
relabel that prior result as a result for the new input.

An authoritative unavailable or integrity-failure response clears old reference
context and disables lookup controls. The retry control remains available after
the request finishes. On the server, ordinary unavailability means the loader
reported its exact resource-access diagnostic. Validation failures, including
oversized resources, malformed framing/JSON, invalid records and digest/count
mismatches, are integrity failures; no partial rows are offered as a fallback.

The server loads its verified bundle once per process. A persistent load failure
normally requires the operator to diagnose access or restore an approved package
and restart the local service under normal procedures. Repeatedly pressing
recheck does not repair a cached load failure. A transient HTTP failure and an
unacceptable installed bundle are different causes and should be recorded
separately when known.

Do not remove a digest check, replace a manifest with a freshly generated
unreviewed manifest, point the loader at an arbitrary directory, or fall back to
partial shards. Reconstruct and review the approved artifact through the
[reference-data](reference-data.md) maintenance process. A useful failure report
contains commit/package identity, fixed error category, command or endpoint,
expected state, and reproduction steps—not private paths, packet contents, or
unredacted reports.

## Select and interpret an offline snapshot

Offline TShark and Zeek analysis are separately invoked workflows with their own
input, privilege, filesystem, process, and report boundaries. The dashboard can
receive one explicitly selected completed offline run at startup. Refreshing
SQLite counters or rechecking IANA status does not rerun that analysis or switch
the selected report.

Read source adapter, tool provenance, record kind, accepted record count,
relative window, and limitations together. A Zeek connection record is a flow,
not a packet. A candidate heuristic is a reason for analyst review, not an
incident state. A missing selected run, an empty complete run, and an unavailable
or invalid selected run require different interpretations. Use the
[offline-analysis guide](offline-analysis.md) for preparation and output semantics.

An invalid report may prevent dashboard startup rather than appear as a partial
summary. Do not weaken the report's private-directory, fixed-file, completeness,
source-version or count checks to make the UI load. A separate valid SQLite
ledger does not repair an invalid offline report, and an accepted offline
snapshot does not prove the SQLite writer is healthy.

## Connection and expansion matrix

| Component or source | Implementation boundary | Safe advancement before activation |
| --- | --- | --- |
| Core Python/SQLite | Operator-invoked validated metadata ingestion and a separate read projection | Test evidence, failure and retention semantics without making dashboard reads write-capable |
| IANA snapshot | Installed bounded reference resources; manual lookup and independent evaluator | Versioned provenance and consumer validation; reviewed updates remain separate from runtime reads |
| TShark | Separate bounded offline subprocess adapter | Installed-tool compatibility and process-isolation evidence on the stated platform |
| Zeek | Separate import-only connection-log adapter | Version/profile fixtures and preserved flow units; do not launch Zeek from the UI |
| Suricata | EVE record and reader contracts, not a runtime importer | Complete storage/capacity/privacy gates and one separately reviewed import slice |
| Scapy | Optional explicitly selected capture path | Separate permission, least-privilege, capacity and operator acceptance; not activated by installation |
| ClamAV | External manual tool, no MEGALODON scan-result integration | A reviewed, bounded result contract before any intake or execution |
| osquery | Proposed endpoint metadata scope | Closed field/table/query-pack contract and privacy review, not arbitrary SQL |
| Firewall | Inert planning with live application refused | Separate durable intent, reconciliation and execution authority; no browser action |
| Alert delivery | Proposed lifecycle/outbox work under issue #84 | Specifications, idempotency and failure fixtures; no notifier or provider credentials |

Static `capabilities` and `hub-plan` output describes implementation boundaries.
It is not a tool-discovery probe, an installed-version inventory, or a
connectivity/health receipt. The Drive command-center blueprint is planning
input, not evidence that its future adapters are installed or running. An
upstream product's availability never promotes a contract-only MEGALODON entry
to a tested runtime integration.

The [integration hub](integration-hub.md) remains the canonical closed workflow
vocabulary. This guide supplies operator interpretation, not another registry.
Adding a new source requires its own bounded contract, unit semantics, privacy
and failure behavior, tests and review. File import, active capture, analyzer
execution, provider access and host mutation are not interchangeable authorities.

## Troubleshooting by evidence state

| Visible situation | First interpretation | Bounded next action |
| --- | --- | --- |
| API unreachable; no prior success | No usable dashboard snapshot yet | Check the locally started service and intended loopback address; do not infer zero findings |
| Stale preserved detections | The last good view exists but refresh failed | Record last-success time and diagnose the local read path |
| Reference unavailable after transient failure | Status could not be obtained or bundle not available | Recheck status once; distinguish recovered transport from persistent package/access failure |
| Reference integrity failure | The bundle cannot be accepted as complete verified context | Stop interpreting old results; restore a reviewed package through maintenance procedures |
| No reference match | Valid query, no matching row in this snapshot | Preserve the exact query and snapshot identity; do not infer endpoint behavior |
| Offline snapshot unavailable | No accepted selected-report projection is available | Diagnose the offline report separately from SQLite and reference state |
| A tool appears in the catalog | Static capability description | Consult its implementation and acceptance status; no automatic execution is implied |

## Validation and review handoff

Use a disposable synthetic fixture, record `git rev-parse HEAD`, and keep local
source, hosted CI, browser, installed-analyzer and independent-review receipts
separate. Run the repository-native checks from the reviewed checkout root:

```bash
python -m compileall -q megalodon tests
python -m pytest tests/test_dashboard_workflow_regressions.py
python -m pytest
python -m pip check
```

These commands assume an already prepared test environment. They do not install
an analyzer, authorize real capture, prove native Windows confidentiality, or
approve a merge. Safe sample/plan CLI smokes and package checks remain in the
existing CI workflow. Review test skips individually; a skipped installed-tool
test is not compatibility evidence.

For browser acceptance, follow [the explicit procedure](ui-state-contract.md#manual-rendered-browser-procedure).
A DOM harness cannot establish visual overflow, focus behavior or screen-reader
announcements. A browser-policy refusal must remain a blocked receipt, not be
bypassed through another bind or proxy. Do not publish screenshots containing
real telemetry without a separate data-sharing decision.

The safest handoff names the exact base/head, changed paths, checks actually
executed, observed failures, unsupported claims and the next human gate. Neither
this guide nor the recovery button authorizes activation, deployment, release,
telemetry sharing or live response.

Implementation sources: [dashboard](../megalodon/dashboard.py),
[hub](../megalodon/hub.py), [reference loader](../megalodon/reference/loader.py),
[specification](../SPECIFICATION.md), and [security review](../SECURITY_REVIEW.md).
Background interpretation reference: [RFC 6335, security considerations](https://www.rfc-editor.org/rfc/rfc6335.html#section-9).
