# Tool heartbeat and one-click install

Start the local HUD with `python -m megalodon hud`. Every companion tool shows
a **status light** next to its name, both in **Home → Data and tools** and in
**Apps**:

| Light | Meaning |
|-------|---------|
| Green | Installed. For service tools (Suricata, Ollama, OSSEC, Greenbone, Zabbix, Nagios) the service process is also running; hover to see its uptime. |
| Amber | Installed, but the tool's expected service is not running. For Qwen, also amber while Ollama is installed but the `qwen2.5:7b` model has not been downloaded. |
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

For Qwen, the heartbeat also checks whether the `qwen2.5:7b` model is
downloaded, by looking for Ollama's manifest file in `$OLLAMA_MODELS`,
`~/.ollama/models`, or the system service's model directory. It reads only file
metadata and never contacts the Ollama server. When the service's directory is
not readable by your user, the model status shows as unknown instead of
missing.

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

## Start service button

When a light is amber because an installed tool's service is stopped, the HUD
shows **Start service**. It runs `systemctl start` on one fixed unit per tool,
through the same `pkexec` password prompt:

| Tool | Units tried, first existing unit file wins |
|------|--------------------------------------------|
| Suricata | `suricata` |
| Qwen (Ollama) | `ollama` |
| OSSEC | `ossec`, `wazuh-agent` |
| Zabbix | `zabbix-agent2`, `zabbix-agent`, `zabbix-server` |
| Nagios Core | `nagios4`, `nagios` |

The button only starts the service; it does not enable it at boot, stop it, or
change its configuration. When no unit file is found (for example, a source
install), the HUD shows no button. When a unit exists but there is no password
prompt, it shows the `sudo systemctl start` command instead. For Qwen, Start
comes before Download, because `ollama pull` needs the server running.

## HTTP contract

| Route | Requirement | Purpose |
|-------|-------------|---------|
| `GET /api/heartbeat` | `X-Megalodon-Check: 1`, HUD mode | `megalodon-tool-heartbeat-v1` receipt |
| `GET /api/install` | `X-Megalodon-Check: 1`, HUD mode | recipe catalog and current job status |
| `POST /api/install` | exact same-site `Origin`, `Content-Type: application/json`, `X-Megalodon-Install: 1`, body `{"tool": "<id>", "action": "install" or "start"}` (action optional, defaults to install) of 96 bytes or less | starts one fixed recipe or service unit; `409` while another job runs |

The request body selects only a tool id. Package names and commands come from
the closed registry in `megalodon/tool_installer.py`. Because the POST needs a
custom header, a cross-site page would have to pass a CORS preflight first, and
this server never grants one.
