# Tool heartbeat and one-click install

Start the local HUD with `python -m megalodon hud`. Every companion tool shows
a **status light** next to its name, both in **Home → Data and tools** and in
**Apps**:

| Light | Meaning |
|-------|---------|
| Green | Installed. For service tools (Suricata, Ollama, OSSEC, Greenbone, Zabbix, Nagios) the service process is also running; hover to see its uptime. |
| Amber | Installed, but the tool's expected service is not running. |
| Red   | Not installed. |
| Grey  | Unknown (for example, a non-Linux host or unreadable metadata). |

The detail line under each name shows the uptime (for example `up 3h 12m`) and
the date the tool was installed, based on the executable's change time.

## When checks run

Checks run in the background, and only when they are useful:

* once when the HUD opens;
* every 60 seconds while the HUD tab is visible (hidden tabs pause polling);
* right away when you return to the tab after more than a minute;
* every 2 seconds while an installation runs, then once more when it finishes.

The server caches each observation for 5 seconds, so extra tabs add almost no
load. A heartbeat reads file metadata and `/proc` process names and start
times. It never runs a tool, opens a network connection, or returns paths,
PIDs or command lines.

Detection covers the usual install locations that the earlier PATH-only check
missed: OSSEC in `/var/ossec/bin`, private Zeek builds in `~/.local/zeek-*`,
the Greenbone container compose project, all three Zabbix roles, and Nagios
source installs in `/usr/local/nagios`. A matching running process also counts
as installed.

## Install button

Tools with a fixed package show an **Install** button:

| Tool | What the button runs |
|------|----------------------|
| Wireshark / TShark | Ubuntu `tshark` (capture permission preseeded to **No**) |
| Suricata, nftables, ClamAV, Nmap | Ubuntu packages of the same name |
| Zabbix | Ubuntu `zabbix-agent` |
| Nagios Core | Ubuntu `nagios4` |
| Scapy | `pip install 'scapy>=2.5,<3'` into the HUD's own Python environment |
| Qwen | `ollama pull qwen2.5:7b` (after Ollama itself is installed) |

System packages run through `pkexec`, so Ubuntu shows its own password dialog.
The HUD never sees or stores the password. Some packages, such as Suricata,
ClamAV, Zabbix and Nagios, can start a service after installation. Zeek,
osquery, OSSEC and Greenbone need a vendor repository, a role choice or a
multi-service deployment, so they keep their official guide links instead.

If a computer has no graphical password agent (for example over SSH), the HUD
shows the equivalent terminal command instead of the button.

## HTTP contract

| Route | Requirement | Purpose |
|-------|-------------|---------|
| `GET /api/heartbeat` | `X-Megalodon-Check: 1`, HUD mode | `megalodon-tool-heartbeat-v1` receipt |
| `GET /api/install` | `X-Megalodon-Check: 1`, HUD mode | recipe catalog and current job status |
| `POST /api/install` | exact same-site `Origin`, `Content-Type: application/json`, `X-Megalodon-Install: 1`, body `{"tool": "<id>"}` of 64 bytes or less | starts one fixed recipe; `409` while another job runs |

The request body selects only a tool id. Package names and commands come from
the closed registry in `megalodon/tool_installer.py`. Because the POST needs a
custom header, a cross-site page would have to pass a CORS preflight first, and
this server never grants one.
