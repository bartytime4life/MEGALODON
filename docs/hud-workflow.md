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

Run these in your installed MEGALODON environment (or activate the reviewed
checkout's virtual environment). Replace `tshark` with a tool ID below:

```sh
python -m megalodon.tool_setup tshark plan
python -m megalodon.tool_setup tshark install
python -m megalodon.tool_setup tshark install --apply
python -m megalodon.tool_setup tshark configure
python -m megalodon.tool_setup tshark verify
```

Default/plan, install without `--apply`, and configure only print instructions.
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

`--apply` is valid only for install. It executes the same closed recipe registry
as the local installer, with a 30-minute deadline and the package manager's
terminal output. No supplied command, package or shell fragment is accepted.
Unsupported platform/guided recipes return a nonzero result. Package service
side effects and large model downloads are disclosed before execution. This
workflow never automatically starts a scan, capture or firewall rule change.

## Connection coverage and failure isolation

Both UIs use `megalodon/telemetry_catalog.py` for the same 14-feature and
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

ClamAV, osquery, Nmap, OSSEC, Greenbone, Zabbix and Nagios do not yet have their
scan/inventory/alert/monitoring data adapters. Their presence/process checks and
manual console links must not be presented as those missing data connections.
nftables exposes inert response-plan evidence, never live firewall telemetry.
