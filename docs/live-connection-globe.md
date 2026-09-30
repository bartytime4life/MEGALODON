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
GET requests never perform either network action. A failed lookup clears the
internet-exit anchor rather than keeping an old marker as current.

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
without another packet. TCP resets stop activity; FIN marks closing. This is
captured activity, not a claim that an operating-system socket is established.
At most 512 tuples are retained and 128 are returned. Truncation/eviction is
reported. Counters describe the current in-memory flow; session renewal resets them.

The atlas uses stable animation phases, separate land/traffic canvases, bounded
rendering, great-circle interpolation and hidden-hemisphere clipping. Pausing,
reduced motion, hidden workspaces, stale data and stopped capture suppress moving
traffic. Unmapped traffic remains visible in the connection details and counts.
The older stored globe/time sweep is available under **History**.

## API and terminal

`GET /api/live-connections` requires the existing local Host/sign-in boundary and
one `X-Megalodon-Check: 1` header. It rejects query parameters, starts no process,
and returns `megalodon-live-connections-v1`, capped by 128 rows and 256 KiB.
It has no cross-origin permission. Existing nonce/Origin/JSON restrictions protect
the new fixed actions on `POST /api/support-config`:

```bash
./scripts/configure-support-apps.sh geography_refresh
./scripts/configure-support-apps.sh background_start --interface enp11s0
./scripts/configure-support-apps.sh background_stop
```

Use the actual interface selected in the HUD. The geography action enables its
saved online opt-in; background monitoring by itself does not enable it.
