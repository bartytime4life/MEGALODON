# Visual HUD and companion setup

The local **HUD** brings the activity globe, separate traffic-volume lanes,
traffic timeline, protocol mix, endpoints, conversations, ports/flags, source
flows, coverage, finding timeline and detector/severity bars into one workspace.
**Traffic** and **Findings** retain the detailed evidence tables. Setup follows
the visual overview. The shared range governs the overview; the globe explicitly
uses its own rolling hour and selected minute. Existing same-origin read-only
`/api/traffic` and `/api/traffic-history` supply data at the configured refresh
interval (five seconds by default). No sensor is started by opening a view.

## Hosted summary workflow

The hosted Site cannot read localhost or your database. In the updated local
HUD, select **Prepare summary**, review the aggregate JSON, then **Download
summary JSON** and load that file on the hosted page. Preparation uses the
latest bounded database window, independently of the displayed time filter.
A failed refresh preserves the previous preview and its original timestamp.

Alternatively, run this in the Python environment containing this revision:

```sh
umask 077
python -m megalodon.hud_snapshot --database /absolute/path/to/megalodon.db > hud-summary.json
```

Replace the database path, then choose **Load summary JSON** in the hosted HUD.
The exporter uses the existing bounded read-only projection: at most 500 event
candidates and 200 linked finding candidates. Sample/unlinked events remain
excluded. No database is created. A missing/unavailable source exits nonzero
without writing a JSON document; shell redirection may leave an empty file.

`megalodon-hud-snapshot-v1` contains aggregate counts, reported-byte totals as
an exact decimal string, twelve equal time bins, protocol/source/severity/
detector counts, three exclusive traffic lanes, timestamps and quality flags.
It contains no IPs, ports, raw records, messages, credentials or filesystem paths.
Highest linked finding severity determines each event's lane. No finding is
not evidence of safety. Counts are metadata records, not link bandwidth.

The browser accepts at most 16 KiB of strict UTF-8 JSON, closed keys and fixed
arrays. It rejects duplicate keys, invalid/future dates, excessive nesting,
unknown quality, out-of-range counts and inconsistent totals. Values are rendered
as text. Imported data stays in memory until Clear, reload or navigation away;
there is no upload or persistent storage. Concurrent reads cannot restore a
cleared or superseded import. Failed imports preserve the previous summary and
show an error. A summary is always labeled **saved**, never live, and is an
unauthenticated self-report. The geographic reference remains unpopulated because
locations are not exported. Use the local HUD for refreshing minute rates and
optional approximate offline IP mapping.

## One setup entry point for every companion

From a reviewed checkout, use the small wrapper below. It selects that
checkout's Python environment. Replace `tshark` with a tool ID below:

```sh
./scripts/manage-companion.sh tshark plan
./scripts/manage-companion.sh tshark install
./scripts/manage-companion.sh tshark install --apply
./scripts/manage-companion.sh tshark configure
./scripts/manage-companion.sh tshark verify
./scripts/manage-companion.sh tshark uninstall
```

Installed-package users can run the equivalent `python -m megalodon.tool_setup`
in the MEGALODON Python environment. Default/plan, install and uninstall without
`--apply`, and configure only print instructions.
Configure provides tool-specific paths, settings and validation steps; it does
not write vendor configuration or guess network scope, role or credentials.
Verify performs the existing read-only executable-presence probe; it does not
establish service health or valid configuration. Python/SQLite and Scapy are
not checked by that probe. All 14 cards offer the same copyable commands.

| IDs | Installation path |
| --- | --- |
| tshark, suricata, nftables, clamav, nmap, zabbix, nagios | Existing fixed Ubuntu apt recipes; OS privilege prompt through pkexec when needed |
| scapy | Existing bounded-version pip recipe in the active Python environment |
| qwen | Existing example qwen2.5:7b download through an installed Ollama provider |
| core | Existing reviewed `scripts/install-local.sh` user installer |
| zeek, osquery, ossec, greenbone | Publisher/project guides; explicit build, repository, role or container decisions |

`install --apply` executes the same closed recipe registry as the local
installer, with a 30-minute deadline and the package manager's terminal
output. No supplied command, package or shell fragment is accepted.
Unsupported platform/guided recipes return a nonzero result. Package service
side effects and large model downloads are disclosed before execution. This
workflow never automatically starts a scan, capture or firewall rule change.

`uninstall --apply` is available for the fixed Ubuntu packages except nftables,
the active Python environment's Scapy package, and the example Qwen model.
It refuses noninteractive input and root, requires the exact tool ID typed in
the terminal, and uses package-manager review without purge or autoremove.
Generic removal is unavailable for private-prefix, vendor-repository,
container, or ambiguous multi-role installations. Use
`~/.local/bin/megalodon-manage uninstall` for the user-installed core; its
data and settings are preserved. A stopped service or removed executable does
not prove the rest of a dependency tree was removed.

## Connection coverage and failure isolation

Both UIs use `megalodon/telemetry_catalog.py` for the same 16-feature and
14-companion data map. It describes supported sources and update modes, not
observed runtime health. The local HUD additionally shows accepted traffic,
heartbeat and installer-job observations with their separate timestamps/states.
The map names each unimplemented companion data adapter explicitly.

`GET /api/hud-snapshot` is read-only, parameter-free and limited to 16 KiB.
It uses the same exporter as the CLI and inherits the local server's Host,
no-store and same-origin boundaries. The packaged validator is identical to
the hosted validator. The preview/download controls start no upload or timer.

Heartbeat and installer-status responses are handled independently. A failed
installer request disables management and shows its own unavailable state while
a valid heartbeat continues to show observed tool presence. A failed heartbeat
continues to mark tool observations stale even when installer status succeeds.

osquery, OSSEC, Greenbone, Zabbix and Nagios do not yet have their
inventory/alert/monitoring data adapters. ClamAV and Nmap have manual completed-report
aggregate importers, not live connections. Presence/process checks and manual
console links do not establish these data connections.
nftables exposes inert response-plan evidence, never live firewall telemetry.
The local **Check tool presence now** button asks the backend for a fresh
observation, bypassing its short cache. It does not start services or certify
health. Installed tool cards show a backend-supplied removal command where an
exact supported method exists; the page copies that command but never runs it.

## Completed file scan

For a separately operated completed ClamAV scan, see
[Completed scan summary](clamav-summary-v1.md). Export aggregate counts with
`python -m megalodon.clamav_summary --exit-code 0 < completed-clamscan.txt > scan-summary.json`
(substitute the recorded exit status 1 when applicable), then load that JSON
in the Completed file scan panel. It is a saved report, not a live feed.

## Completed network inventory


The local HUD and hosted overview share a Network inventory panel. Use
`python -m megalodon.nmap_inventory < completed-report.xml > inventory-summary.json`
in the installed MEGALODON environment, then load the aggregate JSON into either
panel. The [versioned profile](nmap-inventory-v1.md) explains bounds and omissions.
No scanner is installed or started. Inventory counts never change traffic rates,
finding severity or globe signals. New observations require another completed
report, export and explicit load; this is not a live Nmap connection.

## Validate core setup before startup

Run `python -m megalodon.config_check < config/settings.toml` in the installed
MEGALODON environment, substituting your settings file. It checks syntax, known
fields, typed limits and the supported dashboard binding without opening the
database or starting a program. Exit 0 means configuration only; runtime remains
unverified. See [the preflight guide](config-preflight.md). The existing
`python -m megalodon.tool_setup core configure` command also prints this step.
