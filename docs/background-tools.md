# Background tools inside MEGALODON

Use **Start background tools** in the local HUD, or:

```bash
./scripts/start-support-apps.sh
```

The script can start the installed HUD user service, then invokes the same
fixed background workflow as the button. `--check` reads the latest startup
result. Normal startup never opens Wireshark, Zenmap or ClamTk windows. Those
remain explicit optional controls under Advanced in Setup. Sensors shows current
workflow status; a saved inventory result is distinct from an active feed.

| Tool | Background role |
| --- | --- |
| Python / SQLite | HUD, resource sampling, validated metadata and storage |
| dumpcap / TShark | Continuous finite capture sessions, accepted packet metadata, charts and live atlas |
| Zeek | Once-per-minute bounded connection samples, at most 10 seconds / 2,000 frames with a 256-byte snapshot |
| Suricata | Passive system sensor with installed rules; HUD reads recent EVE record counts |
| Nmap | Scheduled inventory of the configured private target; default loopback |
| ClamAV | Scheduled scan of the configured folder; separate FreshClam updater |
| osquery | Scheduled fixed installed-package query |
| Qwen / Ollama | Bounded explanations of completed aggregate collector results and selected observed IPs; operator-reviewed proposals only |
| Scapy | Alternative capture engine; not started alongside the TShark feed |
| nftables | Operator-reviewed local containment from the IP inspector; startup does not change firewall rules |

## First-time service configuration

Configure apps offers **Configure local Qwen**, **Configure Suricata**, capture
permissions and interface selection. Equivalent fixed commands:

```bash
./scripts/configure-support-apps.sh qwen_configure
./scripts/configure-support-apps.sh suricata_configure --interface enp11s0
./scripts/configure-support-apps.sh zeek_check
```

Use your selected interface. System authorization may appear once during setup.
Ollama setup restricts the shared installed service to `127.0.0.1:11434`; other
devices then cannot use it directly. It preserves existing model files and
selects an installed model matching MEGALODON's supported digest. Its owner-private
`~/.config/megalodon/qwen-profile.json` enables companion advice on later HUD
starts. Every inference still checks loopback binding and model identity. A
listener or installed model alone does not establish a completed response.

Suricata setup adds an interface-specific passive, single-worker systemd
override, creates its runtime directory, and grants this user read access to
the sensor's EVE log. Existing rules and the packaged configuration remain in
place. It does not install new rules or enable IPS/firewall actions. Overrides
are named `zz-megalodon-local.conf` (Ollama) and `zz-megalodon-passive.conf`
(Suricata) under the respective `/etc/systemd/system/*.service.d` directories.
A replaced override is preserved once as `.previous`. Removing only the named
override and reloading/restarting that service restores its other definitions;
review the earlier listener/interface configuration before doing so.

## Data and resource bounds

Zeek runs unprivileged through CLI with a private temporary HOME, using bounded
raw frames in memory and anonymous pipes. Only its connection log is enabled;
that temporary log is projected to counts and removed. Sampling gaps and short
snapshots mean incomplete flow/application coverage. Its counts never become
packet totals or admitted detector findings. A failed sample stops retries until
the operator retries background tools. Monitoring stop cancels the sampler.

Suricata summaries read at most the last 256 KiB / 1,000 complete records and
include timestamps no older than two minutes. Partial rows, stale/future records
and symlink logs are excluded. Consecutive windows overlap: do not sum them.
Zero alert records in this window does not establish no threats. This live
context is separate from the strict completed-file alert admission workflow.
Stopping HUD monitoring stops its summary reader, not the system Suricata service.

Background capture and sensor sampling resume with the HUD's saved monitoring
preference. Nmap/osquery keep their hourly schedules; ClamAV keeps its daily
schedule. Repeated starts reuse active collectors and do not duplicate GUI or
capture processes. The resource gauge includes recognized sensor/model processes;
its coverage limits remain visible.

`GET /api/support-workflows` requires the local Host/sign-in boundary and one
`X-Megalodon-Check: 1` header. It returns ten fixed tool rows with state, source
time and at most six metrics each, and performs no actions or model requests.
User-triggered fixed POST actions retain their existing Origin and nonce checks.
No new signup, remote telemetry upload, or automatic geography opt-in is added.
