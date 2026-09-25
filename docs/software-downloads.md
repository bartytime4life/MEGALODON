# Software downloads

Start with Python and a reviewed MEGALODON checkout. Install the local desktop
application with `./scripts/install-local.sh`. Add other software only when your
chosen workflow needs it. The local HUD offers these publisher links as buttons
under **Home → Data and tools**; search or choose a workflow to narrow the list.

Links below were checked against publisher pages on 2026-09-20. They open release
pages or installation guides, so you can choose your OS and architecture without
a stale hard-coded installer URL. Upstream availability on an OS does not mean
the corresponding MEGALODON adapter supports it. Use the
[platform baseline](platform-baseline.md) for installation and acceptance details.

## Essentials

| Software | Why you need it | Official source |
| --- | --- | --- |
| Python 3.11+ | Runs the core and local HUD; use an existing compatible environment if available | [Download Python](https://www.python.org/downloads/) |
| Git | Optional once you have a checkout; obtains and maintains the source | [Download Git](https://git-scm.com/downloads/) |
| MEGALODON | Install the reviewed checkout for the current Linux user; the repository remains the source authority | [Project source](https://github.com/bartytime4life/MEGALODON) and [local install guide](local-pc-setup.md#recommended-install-for-this-user) |
| SQLite | Included in standard Python builds; the running HUD reports its version | [Python SQLite documentation](https://docs.python.org/3/library/sqlite3.html); no separate pip package |

The MEGALODON installer may download declared Python build requirements. It does
not install any companion program listed below. Once the HUD is open, its
**Install** buttons can install several of them from fixed Ubuntu or Python
packages; see [tool heartbeat and one-click install](tool-heartbeat.md). No GPU, cloud account, capture
driver or local AI model is needed to open the HUD.
For a new environment, follow the [platform setup recipe](platform-baseline.md)
instead of replacing an existing working environment.

## Capture and saved network evidence

| Software | Purpose and MEGALODON scope | Official source |
| --- | --- | --- |
| Wireshark / TShark | Inspect saved packet captures; MEGALODON's TShark adapter is Linux-only and uses its fixed reviewed system path | [Download Wireshark / TShark](https://www.wireshark.org/download.html) |
| Zeek | Produce connection logs separately, then use the Linux offline importer | [Get Zeek](https://zeek.org/get-zeek/) |
| Suricata | Produce sensor alerts separately; only the documented completed-file readers and publication contracts are admitted | [Download Suricata](https://suricata.io/download/) |
| Scapy | Optional Python capture extra for an explicitly selected Linux interface | [Install Scapy](https://scapy.readthedocs.io/en/latest/installation.html) |

MEGALODON does not start these sensors when you open the HUD or click a check.
Review the repository's capture and offline-analysis setup before using them.

## Optional explanations and response planning

| Software | Purpose and MEGALODON scope | Official source |
| --- | --- | --- |
| Ollama | Optional local model provider; finding its executable does not verify a model or provider health | [Download Ollama](https://ollama.com/download) |
| Qwen | Optional advisory model; select and verify the artifact through the documented local registry workflow | [Qwen 2.5 model catalog](https://ollama.com/library/qwen2.5) |
| nftables | Linux firewall planning; live application is refused in this evaluation release | [nftables downloads and documentation](https://netfilter.org/projects/nftables/index.html) |

Ollama and Qwen are separate downloads. A model name/tag alone is not the artifact
digest required by the [local advisory contract](local-model-advisory-contract.md).

## Separate companion applications

These are optional products in the integration catalog, not prerequisites or
automatically connected data sources. Their installers may configure services;
follow the guide for the exact product and role you choose.

| Software | What it is for | Official source |
| --- | --- | --- |
| ClamAV | Local file scanning and signatures | [Download ClamAV](https://www.clamav.net/downloads) |
| osquery | Host inventory and SQL-based endpoint queries | [Download osquery](https://github.com/osquery/osquery/releases/latest) |
| Nmap | Authorized network discovery; the HUD does not run scans | [Download Nmap](https://nmap.org/download) |
| OSSEC | Host monitoring; server and agent are different roles | [OSSEC downloads](https://www.ossec.net/ossec-downloads/) |
| Greenbone | Vulnerability management through a separate multi-service deployment | [Greenbone Community installation](https://greenbone.github.io/docs/latest/22.4/container/) |
| Zabbix | Infrastructure monitoring; select the intended server or agent | [Zabbix install selector](https://www.zabbix.com/download) |
| Nagios Core | Infrastructure monitoring with a separately configured server and plugins | [Get Nagios Core](https://www.nagios.org/projects/nagios-core/) |

After installing something, return to **Check this computer**. Presence checks
use the running server's PATH. If your installation changes PATH, restart the
HUD from the updated environment. Container/private-prefix installs may remain
outside executable discovery. A detected program still needs its own documented
configuration and data handoff.
