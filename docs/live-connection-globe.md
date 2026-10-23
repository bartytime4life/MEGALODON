# Live connection atlas

The local HUD's **Live connection atlas** plots recent accepted packet metadata.
Choose an interface and **Enable background monitoring**. This saves the choice
and resumes collection when the local HUD starts again. **Stop monitoring** (or
**Stop HUD capture** in Configure apps) clears automatic resumption.

## What supplies the view

- The installed dumpcap helper captures the selected interface without promiscuous
  mode. Unprivileged TShark extracts the fixed metadata fields through a pipe.
- Strict validation, existing detectors and storage run before a packet enters
  the live conversation cache. The historical traffic and finding charts continue
  to use the stored evidence. Opening a desktop app is unnecessary for this feed.
- Existing configured Nmap, ClamAV and osquery collectors are queued when monitoring
  is enabled and retain their normal schedules. Report watching continues.
- Qwen advice retains its separate loopback-listener and model-digest checks.
  An installed/running model or sensor does not establish a qualified data feed.

Each capture session stops after 15 minutes or 50,000 frames. Background mode
starts a new session after a brief gap. Each session has its own ingestion receipt.
A capture error stops automatic retries; the operator can choose **Retry
monitoring** after addressing permissions, the interface or storage. The existing
database size limit remains enforced. Stored observations are not silently deleted.

## Geographic context

**Set up IP locations** is a separate saved opt-in. It downloads the account-free
[DB-IP City Lite MMDB database](https://db-ip.com/db/download/ip-to-city-lite) from
`download.db-ip.com` and discovers this computer's public internet address through
`api64.ipify.org`. Both services see the connection's public address. Peer addresses,
packets and scan results are not uploaded. Peer locations are looked up locally.

The database is licensed under CC BY 4.0; the atlas displays DB-IP attribution.
Linux desktop installation includes the small `maxminddb` reader through the
existing `geo` package extra. Data is kept in the owner's private
`~/.local/share/megalodon/geography` directory, with a release timestamp, SHA-256
receipt and an atomic validated database replacement. Downloads are capped at
128 MiB compressed and uncompressed and use fixed HTTPS destinations.

While monitoring is enabled, the public internet location is refreshed every
10 minutes; the database is downloaded again only for a new monthly release.
**Disable automatic location updates** revokes the saved opt-in while leaving
background packet capture and the local database available. An already started
location request may finish; later monitoring restarts do not resume online
location refreshes unless you explicitly enable them again.
GET requests never perform either network action. A failed lookup clears the
internet-exit anchor rather than keeping an old marker as current.
A saved database whose build date is out of range or malformed is closed and
treated as not set up, so the HUD still starts. A database whose data section
is damaged returns no location for the affected peers instead of failing the
live or operations views.

The live atlas preserves provider coordinates instead of rounding them to 5°.
They remain approximate IP locations: an ISP gateway, VPN, proxy, anycast or cloud
network can appear far from a physical device. Missing accuracy radii are labelled
unknown. Only addresses actually assigned to the selected local interface use the
internet-exit anchor. Other private and unresolved peers remain unmapped. Existing
stored-history and CSV location contracts remain unchanged.

## Motion and freshness

Connections group the two directions of a transport tuple. Moving light indicates
observed packets in that direction; a return path is animated only after return
traffic is observed. It is not a one-dot-per-packet animation, route tracer or
latency measurement. TCP/UDP labels describe transport, not inferred applications.

Recent activity expires after 15 seconds, and rows leave the cache after 60 seconds
without another packet. TCP resets stop activity; FIN marks closing. A SYN on
a reset tuple, or a SYN without ACK on a closing tuple, starts a new row rather
than adding to the old connection's counters. This is
captured activity, not a claim that an operating-system socket is established.
At most 512 tuples are retained and 128 are returned. Truncation/eviction is
reported. Counters describe the current in-memory flow; session renewal resets them.
Sensor flow-summary baselines are also bounded at 512; the least recently
updated baseline is dropped first, so a long-lived flow that keeps reporting
retains its baseline and its later deltas still reach the timeline.

The atlas uses stable animation phases, separate land/traffic canvases, bounded
rendering, great-circle interpolation and hidden-hemisphere clipping. Pausing,
reduced motion, hidden workspaces, stale data and stopped capture suppress moving
traffic. Unmapped traffic remains visible in the connection details and counts.
The older stored globe/time sweep is available under **History**.

## Camera and workspace

The atlas occupies the full HUD width; the local-network directory has its own
workspace underneath it. **Follow activity** gently frames recent mapped
exchanges and visits different regions when activity spans the world.
**World rotation** provides a geographic overview. Dragging, arrow keys or
manual zoom gives the user control of the camera; choose Follow activity to
resume automatic framing. **Pause motion** stops camera and traffic animation.
Reduced-motion preferences keep the view static, and offscreen animation stops.

Camera position and scale are presentation choices, not measurements. The back
of a globe cannot be visible at the same time as the front. Connection details
retain the returned endpoints, including unmapped locations and paths currently
behind the globe. Automatic framing uses recent measured traffic; it does not
invent activity when the capture is stopped, unavailable or stale.

## API and terminal

`GET /api/live-connections` requires the existing local Host/sign-in boundary and
one `X-Megalodon-Check: 1` header. It rejects query parameters, starts no process,
and returns `megalodon-live-connections-v1`, capped by 128 rows and 256 KiB.
It has no cross-origin permission. Existing nonce/Origin/JSON restrictions protect
the new fixed actions on `POST /api/support-config`:

```bash
./scripts/configure-support-apps.sh geography_refresh
./scripts/configure-support-apps.sh geography_disable
./scripts/configure-support-apps.sh background_start --interface enp11s0
./scripts/configure-support-apps.sh background_stop
```

Use the actual interface selected in the HUD. Geography refresh enables the saved
online opt-in; geography disable revokes it. Background monitoring by itself does
not enable location lookups.


## Incoming-origin rings

Red animated rings mark mapped remote sources of recently observed incoming
traffic. Connections at the same approximate coordinate share a ring. Rings use
the globe's projection and animation clock, disappear with stale or stopped feeds,
and become static when motion is paused or reduced. They are traffic markers,
not attack verdicts or active network pings. Unmapped sources do not acquire a
made-up location. DB-IP locations remain approximate internet locations.

## Investigating an observed address

Select a peer in the connection roster, then choose **Investigate selected
address**. Even when the origin and location are unknown, the local note collects
retained times, connection/packet/byte counts, sent/received direction relative
to that address, protocols, TCP flags, names and ports. Missing measurements show
as unavailable. Recording sources, byte units and capture coverage accompany the
counts; a failed or stopped capture is shown explicitly. Save the note to preserve
this snapshot beyond the bounded live window.

The note also includes possible relay port associations. A WireGuard/OpenVPN/proxy-associated port is
a clue to review, not proof of installed software, a relay or a malicious actor.
The original address and person behind the connection remain unestablished.

**Save investigation note** downloads a JSON copy. For a public IP, the optional
registry link opens ARIN's search page; you enter the public IP there yourself.
The app sends no selected address to a lookup provider. Private/reserved IPs
have no public registry link. Registry allocation and approximate IP location
cannot establish a person's identity or a physical street address.

The note can help correlate separately obtained, trustworthy proxy/provider
records, but MEGALODON does not obtain those records or reconstruct hidden hops.
See the [HTTP and evidence boundaries](dashboard-http-contract.md#address-investigation-and-capture-diagnostics).
