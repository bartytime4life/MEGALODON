# HUD connectivity and realism review — 2026-09-19

This working-tree review covers the Python dashboard, traffic reader, browser
assets, fourteen-tool integration map and their documentation. It does not
certify live network coverage or installed companion applications.

## Corrected behavior

- Older time ranges previously filtered only the latest 500 candidates, so a
  stored event could be invisible when its date was selected. The new read-only
  history endpoint queries the selected UTC range and provides older/newer
  candidate pages. Empty excluded pages still have a usable cursor.
- The legacy audit view and main HUD each fetched the traffic endpoint during
  refresh. They now share one bounded request and concurrent reads of the same
  path share the in-flight request. Partial responses, oversized responses and
  transport errors do not replace a valid snapshot.
- History pages and their report previews remain fixed while latest polling
  continues. Activity detail exposes every qualified event in the selected page,
  including endpoints, exact reported bytes, source, run and record ID.
- Fetch time, latest observation, paused polling and unknown sensor health have
  separate labels. A running ingestion receipt is not treated as proof that a
  sensor is alive. Contradictory run-status/termination values are rejected by
  browser validation.
- Every app card has a local **View in HUD** entry. A configured web console
  loads explicitly into the App viewer with reload, close and external-open
  controls. Bookmark changes unload the selected frame. Native desktop tools
  explain their limitation instead of claiming a working web GUI.
- Empty DOM containers no longer render the literal text `undefined`. Repeated
  chart provenance is available in expandable details, and mobile status cards
  use less vertical space.
- README and specification claims about three tabs, 240 traffic rows, excluded
  endpoints, eight workflows and the absence of embedded app views were outdated;
  they now describe the implemented interfaces.

## Actual connectivity

The map is derived from `megalodon hub-plan --platform linux` and the owning
modules. Executable presence, static integration support, data ingestion and
the ability to open a console are separate facts.

| Component | Data path currently implemented | GUI in the HUD |
| --- | --- | --- |
| Python / SQLite | Validated metadata ingestion and a live read-only database view | The main HUD |
| Scapy | Optional, explicitly operated metadata capture writer | No native web GUI; configured companion viewer only |
| Wireshark / TShark | Bounded offline packet-metadata analysis | Wireshark is a desktop GUI; requires a separate web viewer |
| Zeek | Completed connection-log import into offline reports | Configured companion web console |
| Suricata | Completed-file reader, durable publication/reconciliation APIs, startup evidence projection | Configured alert console; no watcher or sensor control |
| nftables | Inert firewall plans; live application refused | Configured viewer; plans remain separate evidence |
| ClamAV | Manual companion; no scan-result importer | Configured viewer |
| Qwen / Ollama | Bounded optional local advisory; startup display receipt | Configured model web UI; the model/provider is not itself a GUI |
| osquery, Nmap, OSSEC, Greenbone, Zabbix, Nagios | Proposed data integrations; no implemented background ingestion or polling | Each has a viewer entry for an operator-configured web console; Nmap/Zenmap requires a separate web viewer |

Opening a console does not merge its data into the traffic store. There are no
credentials or verified console URLs in this change. The hosted reference Site
receives no feed and retains its external console links. No capture, package,
firewall, scanner, model or remote service was started during implementation.

## Limits that remain

The HUD displays metadata that a configured writer actually records. It does
not establish complete network visibility, collect packet payloads, aggregate
distributed sensors or continuously ingest every companion tool. Those require
real source configuration and additional adapters with coverage/health evidence.

History is limited to 500 event candidates and 200 linked finding candidates per
page, with a maximum 31-day selected range. Reports summarize one page. Read
budgets can reject expensive queries; narrower time ranges can reduce the work.
Pagination is not a database snapshot held across multiple requests; retention
and changed run receipts may alter subsequent reads.

Companion consoles retain their own permissions and network behavior. Some deny
framing or need a separate login window. The HUD preserves those restrictions
and offers an external-open fallback. Browser load events cannot establish
successful framing or app health. See the [MDN iframe reference](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/iframe).

## Validation evidence

Final full regression run: **2,662 passed, 1 skipped** (Python 3.12.3).
Shared Site assets: **39 Node tests passed**. Python compilation, dashboard
JavaScript syntax and diff whitespace checks passed. The repository hygiene
guard passed for 459 tracked files; that guard does not cover untracked files.
An earlier run concurrent with browser artifact creation had three Suricata
`SOURCE_CHANGED` refusals. All 25 reconciliation tests passed on an isolated
rerun, followed by the clean full run with browser fixture work stopped.

Regression coverage includes historical events outside the latest window,
associated findings, exact UTC second/microsecond boundaries, excluded candidate
pages, insertion during pagination, malformed requests, query-budget recovery,
large byte counts, response-size refusal and app frame lifecycle/navigation.

Rendered Chrome checks used isolated synthetic documentation-address metadata
and a local test console. They exercised custom history, older/newer pages,
automatic writer updates, pause/resume, failure/recovery, stable report previews,
explicit frame loading/closing, embedding refusal fallback and a 390-pixel mobile
viewport. Synthetic fixtures were never written to the project audit store.
These checks do not qualify an installed sensor, companion app or production
network connection.
