# Fleet view

Each MEGALODON machine checks itself, sends signed heartbeats
(`megalodon heartbeat send`) and sends alerts to its webhook destinations.
With more than one machine, you want them in one place:
- which machines are quiet;
- which have gone silent;
- whose heartbeats were forged or replayed;
- what each has reported today.

`megalodon fleet` is that place: a collector that receives every machine's
heartbeats and alerts and shows them together.

## Setting up the collector

On the collector, enroll each machine with the key its `heartbeat init`
printed, saved in a mode-600 file:

```bash
megalodon fleet enroll web-1 --key-file web-1-heartbeat.key
```

This prints a new **alert token** for that machine, once. Only its SHA-256 is
kept, in `~/.local/share/megalodon/fleet/machines.json` (mode 600). Pass
`--sensor` when the machine's heartbeats carry a name other than the one you
enroll it under. A sensor name belongs to one machine only.

`--replace` gives a machine a new key and token, for example after it is set
up again. Its earlier heartbeats are kept, but set aside as
`heartbeats-before-TIME.jsonl`, so they are not checked against the new key.

Then run the collector:

```bash
megalodon fleet serve --listen 0.0.0.0:8650 --certificate fleet.crt --private-key fleet.key
```

It receives heartbeats at `/heartbeat` and alerts at `/alert`, and answers
nothing else. Off loopback it needs TLS, because alert tokens would otherwise
cross the network in the clear. `--plain-http` is only for running behind a
TLS proxy.

## Setting up each machine

* **Heartbeats:** point them at the collector.

  ```bash
  megalodon heartbeat init --url https://collector:8650/heartbeat
  ```

  The scheduler's `heartbeat` job sends one every 5 minutes.
* **Alerts:** add a webhook alert destination with `format = "json"`. Its
  `url_file` holds `https://collector:8650/alert`, and its `token_file` holds
  the alert token. Each file is mode 600.

Nothing is sent to the machines: the collector only listens.

## What the collector checks

* **Heartbeats** must name an enrolled machine, or they are refused (403).
  They are stored exactly as sent and checked with the same rules as
  `megalodon heartbeat monitor`:

  | Rule | Severity | When |
  | --- | --- | --- |
  | `HEARTBEAT_SILENT` | CRITICAL | The machine sent no valid heartbeat for longer than `--max-gap` (default 900 s), or never sent one |
  | `HEARTBEAT_FORGED` | CRITICAL | A heartbeat's signature does not match the machine's key. Kept and shown, and answered 401. |
  | `HEARTBEAT_REPLAYED` | HIGH | A heartbeat repeated or went back in sequence |
  | `HEARTBEAT_REPORTS_TAMPER` | HIGH | The machine's own tamper check reported findings |
  | `TAMPER_BASELINE_LOST` | HIGH | Its tamper baseline disappeared |
  | `SENSOR_STATE_CHANGED`, `HEARTBEAT_GAP` | MEDIUM | Its state digest changed, or heartbeats went missing |

  The full rules are in [tamper detection](tamper-detection.md).
* **Alerts** must carry an enrolled machine's token, or they are refused (401).
  The machine is the one the token belongs to, whatever the alert's own
  `sensor` field says. That claim is kept as `claimed_sensor`, so a mismatch
  shows.
* **Bodies** over 64 KiB are refused. Each machine's records are kept in two
  files of up to 8 MiB each: the current file and the previous one.

## The view

```bash
megalodon fleet status
```

This shows every enrolled machine:
- **its state:**
  - `ok`;
  - `attention`, for heartbeat findings or CRITICAL or HIGH alerts;
  - `silent`, when it is overdue;
- its last heartbeat and sequence number;
- its heartbeat findings;
- its alerts by severity over the last `--hours` (default 24), with the
  latest five.

It exits 1 when any machine is not `ok`, and `--alert` sends the heartbeat
findings through the collector's own alerts. Schedule it on the collector to
be told when a machine goes quiet.

`fleet serve` also shows the same view on a **separate listener**,
`--view 127.0.0.1:8651` by default, which binds to loopback only:
- at `/status`, as JSON;
- at `/`, as a page that refreshes every minute and has no scripts.

The receiving listener never shows the view. A proxy in front of it forwards
requests from loopback, and keeping the two apart means a proxy can only ever
reach the receiving side. `--view off` turns the view off. Reach it from
elsewhere through an SSH tunnel:

```bash
ssh -L 8651:127.0.0.1:8651 collector
```

`megalodon fleet remove NAME` stops accepting a machine. What it already sent
is kept.

## Limits

* **One collector.** It is not replicated; if it is down, heartbeats are
  missed and show as gaps later. Alerts the machines could not deliver are
  retried by each machine's own alert queue, within its limits.
* **Alert content is what each machine chose to send.** The destination's
  `detail` setting decides whether addresses and messages are included.
* **No user accounts.** The view is shown to the collector machine itself and
  to nobody else. Anyone who can log in there can see it.
