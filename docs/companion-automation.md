# Local companion collection and report watching

The local `hud` launcher starts a bounded worker automatically. It collects a
fixed osquery DEB package count on this PC, scans loopback `127.0.0.1/32` with
Nmap when Nmap is installed, and scans the current user's real `Downloads`
folder with ClamAV when that folder and scanner exist. Collection starts when
the HUD starts and repeats hourly. Results are aggregate counts held in HUD
memory, with source and observation times shown in the panels. Unavailable
programs and rejected results have their own status; they never create sample
data. The `dashboard` CLI mode does not start default collection.

The same worker checks these optional report paths every 15 seconds:

| Producer | Completed report path |
| --- | --- |
| Nmap | `~/.local/share/megalodon/companion-reports/nmap.xml` |
| ClamAV | `~/.local/share/megalodon/companion-reports/clamscan.txt` and matching `clamscan.exit` containing `0` or `1` |
| osquery | `~/.local/share/megalodon/companion-reports/osquery.json` |

A missing report is normal; no file selection is needed. A producer should
replace its finished report atomically. The worker rejects symlinks, changing
files, oversized files, unsupported formats and failed scans. It keeps the
previous aggregate when a new result is rejected. Raw reports are not copied
into the HUD. The hosted Console cannot read local files or launch PC tools;
it links to the local HUD and has no manual upload controls for these panels.

The fixed Nmap command uses a TCP connect scan of ports 1 through 1024,
without scripts or service detection. The fixed ClamAV command scans files
read-only: it does not quarantine, remove or update signatures. The fixed
osquery query counts `deb_packages` rows without collecting package names.
Each command has a deadline and output bound. These observations do not prove
complete coverage, safety, or that an open port is a threat.

An explicit private TOML file can override the default scope and watch paths:

```toml
[collection]
interval_seconds = 3600
nmap_target = "192.168.1.0/24"
clamav_paths = ["/home/you/Downloads"]
osquery_enabled = true

[watch]
nmap_xml = "/home/you/private-reports/nmap.xml"
clamscan_text = "/home/you/private-reports/clamscan.txt"
clamscan_exit = "/home/you/private-reports/clamscan.exit"
osquery_json = "/home/you/private-reports/osquery.json"

[qwen]
advisory = true
```

Use `./scripts/start-local.sh --companion-config /absolute/private/companions.toml`
to override. The target must be one private IPv4 host or CIDR with at most
256 addresses. ClamAV accepts at most four existing non-root directories.
Do not use the example LAN range without authorization to scan it.

Qwen receives only validated aggregate counts through the separately
configured, digest-pinned local provider. It may explain the counts as an
advisory. Fixed scripts choose the commands, scopes and schedule; Qwen cannot
choose or execute them. If the provider is disabled or does not pass its
local containment check, the worker still collects counts and labels the
advisory unavailable.

Use `./scripts/start-local.sh --no-auto-companions` to turn off the default
worker for that HUD session. The flag cannot be combined with
`--companion-config`. Existing HUD processes keep their launch behavior until
restarted; the running instance is not changed by updating source files.
