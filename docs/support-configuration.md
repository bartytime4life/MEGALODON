# Configure support apps from the local HUD

At the top of **Home**, beside **Start support apps**, choose **Configure apps**.
The panel contains actual configuration and control actions. They are available
in a normal non-root Linux HUD, with the same optional sign-in as the dashboard.
The hosted Site cannot operate these controls.

The [live connection atlas](live-connection-globe.md) adds background monitoring,
directional geographic animation and a separate opt-in for automatic IP location
data. Monitoring resumes across local HUD restarts once enabled. **Disable automatic
location updates** revokes the separate online lookup opt-in without stopping
traffic capture.

## Network capture

1. Select the interface to observe. The current default-route interface is
   suggested; virtual adapters, VPNs and loopback remain separately selectable.
2. Choose **Configure capture access**. The operating system may ask for your
   password. Only the packaged, root-owned `/usr/bin/dumpcap` receives
   `cap_net_raw,cap_net_admin=ep`, with an execute/read ACL for the requesting
   user. Other-user access is removed. Wireshark, TShark, Python and the HUD
   remain ordinary user processes. Package upgrades may require repeating this
   setup. Stopping capture does not remove these permissions.
3. Choose **Start HUD traffic** to feed packet metadata to the existing traffic
   and detection charts. The session stops after 15 minutes or 50,000 frames.
   **Stop HUD capture** stops only that session and retains accepted metadata.
4. Optionally choose **Open live Wireshark** for a separate managed GUI window.
   It uses a dedicated MEGALODON profile, selected interface, no name resolution,
   no promiscuous mode, a 256-byte capture snapshot, and the same session bounds.
   **Close managed Wireshark** closes only the window created by this control.
   Wireshark maintains its own packet buffer; save any capture you want to keep
   before closing.

The HUD path streams dumpcap output through an anonymous pipe to TShark and
uses a fixed set of metadata fields. Raw capture files are not retained by the
HUD. Accepted rows pass through the existing strict TShark field parser, JSONL
validator, ingestion receipts and detection/storage service. The existing
traffic projection labels them as JSONL metadata; its conservative source and
coverage limitations still apply. Non-IP, ambiguous and malformed rows are
skipped and counted. Capture drops remain unknown. Running with zero accepted
rows means waiting for usable metadata, not a successful data connection.
No capture starts on page load or merely by opening the configuration panel.

If the HUD began without a database, its read-only reader can now open the
newly created validated store without restarting the page or changing sources.
Managed capture does not enable firewall actions. A SIGTERM service shutdown
requests bounded capture cleanup and finalizes its ingestion receipt.

## Other setup actions

| Tool | Action and scope |
| --- | --- |
| Nmap / Zenmap | Save a private IPv4 target/range of at most 256 addresses and queue the existing inventory worker. Default is loopback. Zenmap can still be opened with Start support apps. |
| ClamAV / ClamTk | Select this user's Downloads or Documents folder, save the scanner scope and queue collection. A separate button starts the installed FreshClam signature updater through system authorization. |
| osquery | Enable and queue the existing fixed DEB package count. No arbitrary SQL or enrollment. |
| Ollama / Qwen | Query the loopback model inventory. No model download, model change or execution authority is granted. Advisory requests still use their configured model/digest contract. |
| Zeek | Verify the installed executable and prepare a private workspace. Completed qualified conn.log intake remains the separate offline workflow. |
| Suricata | Run the installed configuration's native validation in a private log folder. Rules, sensor interfaces and evidence intake are not rewritten. |

Collector scopes persist in `~/.config/megalodon/support-config.json`; report
watching remains active. A scope change is refused while a collector is running.
Only the chosen collector is queued by its configuration action. Previously
configured scopes are restored when the local HUD starts again. Symlinks and
untrusted paths are refused. Existing edited Wireshark profile contents are
preserved and cause a clear setup error instead of being overwritten.

Each setup result shows its own time. A completed check or requested GUI launch
is not continuous proof that the program is running or delivering data.

## Terminal scripts

The same actions are available from the reviewed checkout:

```bash
./scripts/configure-support-apps.sh --help
./scripts/configure-support-apps.sh status
./scripts/configure-support-apps.sh capture_permissions --interface enp11s0
./scripts/configure-support-apps.sh capture_start --interface enp11s0
./scripts/configure-support-apps.sh capture_stop
./scripts/configure-support-apps.sh wireshark_open --interface enp11s0
./scripts/configure-support-apps.sh wireshark_stop
./scripts/configure-support-apps.sh nmap_configure --nmap-target 127.0.0.1/32
./scripts/configure-support-apps.sh clamav_configure --scan-folder Downloads
./scripts/configure-support-apps.sh signature_update
./scripts/configure-support-apps.sh osquery_configure
./scripts/configure-support-apps.sh qwen_check
./scripts/configure-support-apps.sh zeek_check
./scripts/configure-support-apps.sh suricata_check
```

Replace the example interface with the one selected in your HUD. These scripts
use the running local HUD; if optional sign-in is enabled, use its browser
buttons after signing in. Passwords are entered only in the OS/sign-in UI.

## Request boundary

`GET /api/support-config` requires `X-Megalodon-Check: 1` and returns bounded
settings, interfaces, action/capture results and a separate in-memory nonce.
GET never launches a tool. `POST` requires the exact same Origin, its nonce in
`X-Megalodon-Config-Token`, JSON content type and a 2–2048 byte closed body.
Each action accepts only its documented interface, private target or folder
choice. Duplicate keys/headers, encodings, query aliases, paths, commands,
services, arbitrary URLs and extra fields are rejected. Responses stay below
64 KiB. No CORS access is granted. Host and optional HTTP sign-in apply first.
