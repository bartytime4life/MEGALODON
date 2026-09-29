# Local companion collection and report watching

The local HUD can update its Nmap, ClamAV and osquery panels without repeated
file selection. This is an opt-in local process. The hosted Console is a static
Site and cannot start host tools or read files from this PC. Its file inputs
remain a manual fallback; open the loopback HUD to see automatic results.

Create one private TOML file outside the repository with exact scopes. For
example, after choosing an authorized private target and scan folder:

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

Replace every example path and target with a reviewed local scope. Omit any
collection or watch key that you do not want. The watch paths refer to
completed raw reports, ideally replaced atomically by their producer. The
ClamAV exit file must contain `0` or `1` matching its report. The worker
rejects incomplete, changing, oversized and unsupported reports, preserving
the previous aggregate. A failed collector also preserves the previous result
and shows an unavailable status. No raw report is kept in the HUD.

Start a new HUD process with:

```sh
./scripts/start-local.sh --companion-config /absolute/private/companions.toml
```

Use the same explicit flag on subsequent
starts. The existing HUD must be stopped only when you are ready to switch
instances; its current sign-in password changes on restart. With no flag,
no companion scans, queries or file watches start. Collection begins once
when that configured HUD starts and repeats every `interval_seconds` (300 to
86,400). Watched files are checked every 15 seconds.

The fixed Nmap action uses TCP connect scanning of ports 1 through 1024,
without scripts or service detection. The target must be a literal IPv4 host
or CIDR inside RFC 1918 or loopback space, covering at most 256 addresses.
The fixed ClamAV action recursively scans one to four explicit existing
directories; it never removes, moves or quarantines files and never updates
signatures. The fixed osquery action counts rows in `deb_packages` and does
not collect package names. Each tool has a deadline and an output limit. The
report exporters remain the authority for counts. The scans observe their
scopes only; they are not evidence of complete coverage or safety.

Qwen is optional and requires the HUD's separately configured, digest-pinned
local AI provider. It receives only the aggregate count result and may write
an advisory explanation displayed as such. It cannot choose a command,
target, path, query, schedule, or response action. If Qwen is unavailable,
collection and report watching continue and its status is shown. The three
panels are kept separate from live traffic and detections.

To stop automatic work, stop the HUD and relaunch it without
`--companion-config`; the configuration file remains private and can be
reused. The worker stores only in-memory counts for the current HUD process.
