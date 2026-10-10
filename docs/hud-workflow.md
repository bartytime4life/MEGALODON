# Visual HUD and companion setup

The local **HUD** combines interface speeds, resources, storage coverage, the
traffic globe, local topology and endpoint details. **Findings** and retained
history provide evidence tables. **Setup** contains installation, permissions
and configuration; **Start background tools** remains in the HUD.

Live packet views are bounded recent observations. Historical dates use
`/api/traffic-history-v2` across retained segments and verified compact summaries,
with segment-qualified paging and explicit gaps. The original read interfaces
remain compatible. The globe uses its own recent observed connections; unknown
locations remain unmapped. Opening a view does not itself start a sensor.

**Findings** shows each severity as a coloured pill that also spells out the
level, and high or critical rows carry an accent edge, so the level never
depends on colour alone. Detector names, levels and IDs stay whole. On phones
each finding becomes a compact card with detector and severity on the first
line; on wider screens the table scrolls sideways with a shaded edge when
columns do not fit. A severity outside the fixed four levels is shown as
**UNKNOWN** styling with its original text.

## Visual reports and advanced exports

Open Reports for the latest saved visual report. **Make report now**, **Save
report**, and **Print / save PDF** are the primary actions. The default interval
is the preceding 24 hours; daily generation runs at 9 AM in this PC's time zone
while the local service is running. Selected dates aggregate retained segments
and verified compact summaries with explicit coverage limits. Reports remain
local and downloads reuse completed results. See
[efficient recording and reports](efficient-recording-reports.md).

Advanced exports retain CSV, JSON and the address-free HUD summary. The summary
is a compatibility export of the newest bounded window, independent of selected
historical dates. It is not a complete report and has no hosted import workflow.
The former large raw-JSON preview and hosted console are retired.

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
Verify returns the existing read-only executable-presence probe **and** the
local HUD's metadata/process heartbeat in separate JSON fields. The latter
can observe the Scapy Python module, an expected process, and the example
Qwen model manifest without executing a companion. Neither result establishes
service health, a valid configuration, version or integration. Python/SQLite
and Scapy remain `not_checked` in the executable-only `presence` field; read
the separate `heartbeat` field with its `observed_at` timestamp. All 10 cards
offer the same copyable commands.

The local HUD can prepare the exact command needed to reopen that HUD with its
existing fixed Install/Start/Open controls enabled. Expand **Authorize Install,
Start and Open** in Setup and copy the displayed command. Copying does not stop or restart
the HUD, and it does not install, start or open a companion. After running the command
in a terminal, the separate per-launch token and confirmation controls remain
required.

| IDs | Installation path |
| --- | --- |
| tshark, suricata, nftables, clamav, nmap | Existing fixed Ubuntu apt recipes; OS privilege prompt through pkexec when needed |
| scapy | Existing bounded-version pip recipe in the active Python environment |
| qwen | Existing example qwen2.5:7b download through an installed Ollama provider |
| core | Existing reviewed `scripts/install-local.sh` user installer |
| zeek, osquery | Publisher/project guides; explicit build, repository or container decisions |

`install --apply` executes the same closed recipe registry as the local
installer, with a 30-minute deadline and the package manager's terminal
output. No supplied command, package or shell fragment is accepted.
Unsupported platform/guided recipes return a nonzero result. Package service
side effects and large model downloads are disclosed before execution. This
workflow never automatically starts a scan, capture or firewall rule change.

`uninstall --apply` is available for the fixed Ubuntu packages except nftables,
the active Python environment's Scapy package, and the example Qwen model.
It refuses noninteractive input and root, requires the exact tool ID typed in
the terminal, and first runs unprivileged `apt-get -s remove` for Ubuntu
packages. It displays the current dependency removal plan and stops if the
simulation fails or its output is too large to review. After confirmation,
the package manager may show a new plan; review it again before accepting.
Removal uses no purge or autoremove.
Generic removal is unavailable for private-prefix, vendor-repository,
container, or ambiguous multi-role installations. Use
`~/.local/bin/megalodon-manage uninstall` for the user-installed core; its
data and settings are preserved. A stopped service or removed executable does
not prove the rest of a dependency tree was removed.

## Connection coverage and failure isolation

The local HUD uses `megalodon/telemetry_catalog.py` for its capability reference.
That reference describes supported sources, not runtime health. Sensors shows
current workflow observations; Setup checks executable presence, process
observations and configuration separately. A saved result is timestamped and
does not prove a collector is running now.

`GET /api/hud-snapshot` remains a read-only, parameter-free compatibility export
limited to 16 KiB. Advanced exports validates the returned summary before
download. It performs no upload and does not substitute for a date-based report.

Heartbeat and installer-status responses fail independently. A failed installer
request disables management and shows its own unavailable state; a valid
heartbeat can still show observed tool presence. A failed heartbeat marks that
observation stale even when installer status succeeds.

## Automatic endpoint observations

The configured local collectors run ClamAV over the chosen folder, Nmap over
the explicitly selected inventory target, and a fixed osquery package-count
query. They also watch their completed-report locations. Their accepted,
timestamped aggregates appear automatically; manual JSON upload is not needed.
Scan counts do not change packet rates or detector severity. Separate host
discovery supplies topology for authorized scopes selected in Setup.

The standalone [ClamAV converter](clamav-summary-v1.md) and
[Nmap converter](nmap-inventory-v1.md) remain useful CLI compatibility tools.
They convert completed reports without starting a scanner. Their outputs are
not evidence of present sensor health or full network visibility.

## Local response and configuration

The IP inspector can preview a fixed, time-limited local block. Applying it
requires the existing reviewed workflow and OS authorization, with a retained
outcome receipt. Qwen advice cannot invent or execute arbitrary commands.
Setup owns supported install, configure, verify and uninstall controls.
Unsupported installation methods provide explicit publisher guidance. Download
links open publisher pages; they do not install software by themselves.

## Validate core setup before startup

Run `python -m megalodon.config_check < config/settings.toml` in the installed
MEGALODON environment, substituting your settings file. It checks syntax, known
fields, typed limits and the supported dashboard binding without opening the
database or starting a program. Exit 0 means configuration only; runtime remains
unverified. See [the preflight guide](config-preflight.md). The existing
`python -m megalodon.tool_setup core configure` command also prints this step.
