# Live PC graphs and free local tools

Open the installed **MEGALODON** app or <http://127.0.0.1:8787/> while the
local HUD is running. **Live PC** starts collecting automatically with the HUD.
No account, additional package, data upload, API key, or separate monitoring
service is needed. The hosted Defense Console links to this local view; its
optional private hosting sign-in is separate from running MEGALODON on the PC.

## What the graphs measure

| View | Source and unit | What it tells you |
| --- | --- | --- |
| PC CPU and memory | Linux processor ticks and MemAvailable | Total computer CPU capacity used; physical memory currently in use |
| MEGALODON and companion gauges | Recognized local processes | CPU share of the entire PC and summed resident memory |
| Resources over time | Two-second observations | Whether PC and companion resource demand are rising together |
| Receive / send trend | Selected interface's byte counters | Bytes per second on one adapter, without summing VPN/bridge duplicates |
| Packet rate and errors / drops | Selected interface's counters | Packets per second and counter changes since the preceding observation |
| TCP / UDP and TCP states | Kernel socket tables | Current socket counts, established TCP sockets, listeners and TIME_WAIT |
| Remote peers | Remote IPs in socket tables | Up to ten remote addresses ranked by socket count, without reverse DNS |
| Saved traffic / protocol / conversation charts | Existing qualified metadata adapters | Recorded packet/flow observations and linked detector findings |

Network activity and CPU load appearing together does not prove that one caused
the other. Socket counts are not packet protocol shares. Interface counters do
not provide application-specific byte totals. GPU use is not currently measured.
MEGALODON keeps packet evidence, network counters, inventory and scan results in
their own units.

The first observation warms up rate measurements. Missing permissions, new
processes, restarted processes, counter resets and long sampling gaps produce
unavailable rates. Process totals are a lower bound when visibility is partial.
Summed resident memory can count shared pages more than once. Companion totals
include recognized instances started outside MEGALODON. Browsers opened by the
HUD are excluded because they can contain unrelated tabs. A process-name match is
an observation, not proof of software identity or health.

History is held in memory for this HUD session, up to 300 points (ten minutes at
two-second intervals). The browser pauses its requests when hidden; the shared
sampler continues so reopening the tab retains recent history. Pausing the view
does not stop running apps. Restarting the HUD clears this history. Process IDs,
command lines and file paths are never returned. Interface names and remote IP
addresses remain inside the loopback HUD.

## Account-free tool choices

The active catalog already excludes Greenbone, Nagios, OSSEC and Zabbix console
integrations. Retired IDs remain only where needed to discard old saved browser
preferences. No new cloud connector or signup service is introduced here.

These local editions have public downloads and can be used locally without a
vendor account. Their license terms remain those of their publishers.

| Tool | Useful data | Current connection |
| --- | --- | --- |
| Built-in Linux counters | Live resources, interface rates, sockets | Automatic with the local HUD |
| [Wireshark / TShark](https://www.wireshark.org/download.html) | Packet metadata and protocol dissection | Existing completed-capture adapter |
| [Zeek](https://zeek.org/get-zeek/) | Connection summaries | Existing completed conn.log adapter |
| [Suricata](https://suricata.io/our-story/suricata/) | Network detector alerts | Existing committed external-alert store |
| [Nmap](https://nmap.org/download.html) | Host and port-state inventory | Automatic bounded loopback scan and completed-report watcher |
| [ClamAV](https://www.clamav.net/) | Scanned files and signature matches | Automatic Downloads scan and completed-report watcher |
| [osquery](https://osquery.io/downloads) | Package inventory | Automatic bounded package count and result watcher |
| [Ollama with local Qwen](https://github.com/ollama/ollama) | Optional explanation of supported observations | Existing opt-in, loopback-only, pinned-model provider |

The catalog also retains local Python/SQLite, Scapy and nftables. A running
tool does not automatically supply packet evidence. Missing packet capture or a
missing qualified store leaves the corresponding evidence charts unavailable.
The live PC graphs remain useful independently. Qwen is not required for counter
collection and cannot select commands, execute scripts or invent missing data.

## Implementation contract

`GET /api/host-telemetry` returns `megalodon-host-telemetry-v1` only in local HUD
mode, using the existing loopback Host and optional sign-in boundaries plus
`X-Megalodon-Check: 1`. Query parameters are rejected. Cross-origin CORS access
is not enabled. This endpoint has no write or execution operation.

One background sampler is shared by all browser tabs. It reads bounded Linux
procfs counters, with at most 32 interfaces, 32,768 process directory entries,
10,000 sockets per table and ten remote peers. Each process belongs to a single
resource bucket. PID start ticks prevent reused IDs from producing false deltas.
No subprocesses, package imports, DNS lookups, external network calls, packet
captures, database writes or files are created by the sampler.

Checks: `tests/test_host_telemetry.py` verifies counter arithmetic, reset/gap
handling, process reuse, attribution, missing access, history limits and HTTP
boundaries. UI checks cover the live/paused/stale/unavailable transitions.
