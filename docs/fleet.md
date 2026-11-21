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

## A second collector

One collector is one machine an intruder has to silence. A machine can report
to two or more, each kept on its own and checking for itself. A collector that
misses a heartbeat reports the gap even if the other got it.

* **Each machine names every collector.** Either give `--url` once per
  collector at `heartbeat init`, or add one later and keep the key:

  ```bash
  megalodon heartbeat add-url https://collector-2:8650/heartbeat
  ```
* **Each collector enrolls the machine with the same key file.**

  ```bash
  megalodon fleet enroll web-1 --key-file web-1-heartbeat.key
  ```

  Each collector prints its own alert token. Add a second webhook alert
  destination with that collector's `/alert` URL and token, so alerts reach
  both too.
* **Heartbeats** go to every collector, the same signed body to each.
* **Timelines and evidence go to each collector separately.** `timeline push`
  and `evidence push` keep a separate push record for each collector. They
  send each one what it does not have yet, and evidence within its own
  budget. The first collector uses the usual record file. Each added one
  uses the same name with part of its URL's SHA-256 added. So a collector
  that was down, or added later, catches up from where it stands, and the
  others are not sent anything twice.
* **The results list each collector.** `heartbeat send`, `timeline push` and
  `evidence push` list each collector with its result. One that could not be
  reached or refused is listed with its error, and the command exits
  non-zero while still sending to the rest. A destination that is only a
  heartbeat monitor and answers 404 is listed with a note, not an error.

The collectors do not talk to each other. Each holds what the machines sent
it, and `fleet status`, `fleet timeline` and `fleet evidence` on each show its
own view.

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
  | `COMMAND_LOG_ROLLED_BACK` | CRITICAL | Its [command log](command-log.md) went back to an earlier line |
  | `COMMAND_LOG_LOST`, `COMMAND_LOG_RESTARTED` | HIGH, MEDIUM | Its command log stopped being reported, or started over with a new key |

  The full rules are in [tamper detection](tamper-detection.md).
* **Alerts** must carry an enrolled machine's token, or they are refused (401).
  The machine is the one the token belongs to, whatever the alert's own
  `sensor` field says. That claim is kept as `claimed_sensor`, so a mismatch
  shows.
* **Bodies** over 64 KiB are refused, except at `/evidence`, which takes up to
  1 MiB. Each machine's heartbeats, alerts and timeline events are kept in two
  files of up to 8 MiB each: the current file and the previous one.
* **Evidence** arrives at `/evidence`: each machine's command log lines and
  evidence bundles, sent by `megalodon evidence push` and signed with its
  heartbeat key. The collector keeps the first copy of each. A line or bundle
  sent again with other content is reported as `SHIPPED_COMMANDS_REWRITTEN` or
  `SHIPPED_EVIDENCE_CHANGED`, and lines missing when later ones arrive as
  `SHIPPED_COMMANDS_GAP`. `megalodon fleet evidence` lists the copies and
  `--verify` checks them. See [evidence off the machine](evidence-shipping.md).

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

## Incidents across machines

Each machine's [incident timeline](incident-timeline.md) can be sent to the
collector. The collector joins incidents on different machines when they share
something only an intruder's activity would, seen by two machines within a
day:
- **an address:** the same outside address, or one machine reaching another;
- **a domain name that is itself the finding:** one on your watchlist, or one
  spelled the way generated names are (`OUTBOUND_TO_WATCHLISTED_NAME` and
  `OUTBOUND_TO_GENERATED_NAME`). Case and a final dot do not matter. This
  joins machines that reached the same server at different addresses;
- **a dropped tool's place:** a program or file in `/tmp`, `/var/tmp`,
  `/dev/shm` or memory (`/memfd:`) at the same path. A program on one machine
  and a file on another at that path count as the same thing, and so does a
  deleted one.

Every incident on each machine that saw it in that day is joined, not only the
most recent one. An attacker moving between machines, or working through
several, then shows up as one fleet incident. `linked_by` lists what joined
it. Addresses are listed bare, and other links say what they are, such as
`name:c2.example` or `file:/tmp/.cache/kworker`.

Names a new program reaches, and paths and accounts every machine has (such as
`/usr/bin/curl`, `/etc/passwd` or `root`), never join machines. Neither do
ports, devices or services.

On each machine:

```bash
megalodon timeline push
```

On the collector:

```bash
megalodon fleet timeline
```

```bash
megalodon fleet timeline 7d41c0
```

```bash
megalodon fleet timeline --entity address:203.0.113.9
```

* **`timeline push`** sends the events this machine has not sent yet:
  findings, decisions, actions and undos. It also sends merges: when a later
  finding makes two of the machine's incidents one, the collector joins the
  two as well, including events it received before the merge. It sends them
  in batches to
  `/events` on the collector, at the heartbeat address with `/events` in place
  of `/heartbeat` (or `--url`). Each batch is signed with the machine's
  heartbeat key, so enrolling the machine is all it needs. The
  [scheduler](scheduling.md) runs it every five minutes. A heartbeat monitor
  that is not a fleet collector answers 404, and the push then sends nothing
  and does not fail.
* **The collector checks each batch.** It must be:
  - from an enrolled machine (else 403);
  - signed with that machine's key (else 401, and nothing is kept);
  - newer than the last batch it accepted from it (a replay gets 409).

  Each event is kept once, even if a machine that lost its record of what it
  sent sends it again.
* **`fleet timeline`** lists the fleet's incidents of the last `--hours` (168
  by default), worst first. Each shows its machines and the addresses that
  joined them. With an ID, or the start of one, it tells that incident, every
  machine's events in one order. With `--entity`, it shows every incident that
  involved that entity. `--format text|json|html` and `--output FILE` (mode
  600) work as for `timeline show`.
* **The view also shows it:**
  - `/timeline` lists the incidents, as a page with no scripts;
  - `/timeline/ID` tells one;
  - `/timeline.json` gives the list as JSON.

  Like the rest of the view, these are on the loopback listener only.

## Limits

* **Collectors are not replicated.** With one collector, if it is down,
  heartbeats are missed and show as gaps later. A second collector
  ([above](#a-second-collector)) keeps its own copy. Collectors never
  merge or compare what they hold: compare `fleet status` on each. Alerts
  the machines could not deliver are retried by each machine's own alert
  queue, within its limits. Heartbeats are not retried, so a collector that
  was down shows the gap.
* **Alert content is what each machine chose to send.** The destination's
  `detail` setting decides whether addresses and messages are included.
* **No user accounts.** The view is shown to the collector machine itself and
  to nobody else. Anyone who can log in there can see it.
* **Joined by addresses, finding names and dropped tools only.** Only these
  join machines, as described above. An ordinary path or account name on two
  machines is not taken to be the same thing, and neither is a USB device: one
  without a serial number is named by its model, which identical devices
  share. A tool dropped at a different path on each machine is not joined by
  its path. File contents are not compared.
* **Timelines are only as recent as the last push.** With the scheduler, that
  is at most five minutes old. The collector keeps about 16 MiB of events per
  machine: the current file and the one before it.
